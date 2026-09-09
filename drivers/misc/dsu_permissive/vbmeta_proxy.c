// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/workqueue.h>

#include <asm/ptrace.h>

#include "dsu_detect.h"
#include "dsu_permissive.h"
#include "vbmeta_proxy.h"

#define VBMETA_SLOT_COUNT 2
#define VBMETA_RESOLVE_INTERVAL_MS 10U

/* AvbVBMetaImageHeader 的 magic 与 flags 均为固定布局。 */
#define AVB_VBMETA_MAGIC_OFFSET 0U
#define AVB_VBMETA_MAGIC_SIZE 4U
#define AVB_VBMETA_FLAGS_OFFSET 120U
#define AVB_VBMETA_HASHTREE_DISABLED_BYTE_OFFSET \
	(AVB_VBMETA_FLAGS_OFFSET + 3U)
#define AVB_VBMETA_HASHTREE_DISABLED_BYTE_MASK 0x01U

struct vbmeta_slot {
	struct file *file;
	const struct file_operations *original_ops;
	struct file_operations proxy_ops;
	struct mutex io_lock;
	bool ops_initialized;
	bool patch_allowed;
	bool bypass_rejected;
	bool header_confirmed;
	bool header_rejected;
};

static const u8 avb_magic[AVB_VBMETA_MAGIC_SIZE] = { 'A', 'V', 'B', '0' };

static const char *const vbmeta_paths[] = {
	"/dev/block/by-name/vbmeta",
	"/dev/block/by-name/vbmeta_a",
	"/dev/block/by-name/vbmeta_b",
	"/dev/block/bootdevice/by-name/vbmeta",
	"/dev/block/bootdevice/by-name/vbmeta_a",
	"/dev/block/bootdevice/by-name/vbmeta_b",
};

static struct vbmeta_slot slots[VBMETA_SLOT_COUNT];
static DEFINE_SPINLOCK(slots_lock);
static DEFINE_SPINLOCK(devices_lock);
static dev_t vbmeta_devices[ARRAY_SIZE(vbmeta_paths)];
static unsigned int vbmeta_device_count;
static struct delayed_work resolve_work;
static atomic64_t matched_files = ATOMIC64_INIT(0);
static atomic64_t patched_reads = ATOMIC64_INIT(0);
static atomic64_t proxy_errors = ATOMIC64_INIT(0);
static atomic_t patch_logged = ATOMIC_INIT(0);
static atomic_t device_logged = ATOMIC_INIT(0);
static atomic_t enforce_logged = ATOMIC_INIT(0);
static bool kprobe_registered;

static ssize_t proxy_read(struct file *file, char __user *buffer,
			  size_t count, loff_t *position);
static int proxy_release(struct inode *inode, struct file *file);

static struct vbmeta_slot *slot_from_file(struct file *file)
{
	struct vbmeta_slot *slot;

	slot = container_of(file->f_op, struct vbmeta_slot, proxy_ops);
	if (READ_ONCE(slot->file) != file)
		return NULL;
	return slot;
}

static bool add_vbmeta_device(dev_t device)
{
	unsigned long flags;
	unsigned int index;
	bool added = false;

	if (!device)
		return false;

	spin_lock_irqsave(&devices_lock, flags);
	for (index = 0; index < vbmeta_device_count; ++index) {
		if (vbmeta_devices[index] == device)
			goto out;
	}
	if (vbmeta_device_count < ARRAY_SIZE(vbmeta_devices)) {
		vbmeta_devices[vbmeta_device_count++] = device;
		added = true;
	}
out:
	spin_unlock_irqrestore(&devices_lock, flags);
	return added;
}

static void resolve_vbmeta_path(const char *name)
{
	struct inode *inode;
	struct path path;

	if (kern_path(name, LOOKUP_FOLLOW, &path))
		return;

	inode = d_inode(path.dentry);
	if (inode && S_ISBLK(inode->i_mode) && add_vbmeta_device(inode->i_rdev) &&
	    atomic_cmpxchg(&device_logged, 0, 1) == 0)
		pr_info("dsu-permissive：已定位 first-stage vbmeta 块设备\n");
	path_put(&path);
}

static void resolve_vbmeta_devices(struct work_struct *work)
{
	unsigned int index;

	(void)work;
	if (dsu_permissive_phase_get() != DSU_PHASE_WAIT_SYSTEM_INIT)
		return;

	for (index = 0; index < ARRAY_SIZE(vbmeta_paths); ++index)
		resolve_vbmeta_path(vbmeta_paths[index]);

	schedule_delayed_work(&resolve_work,
			      msecs_to_jiffies(VBMETA_RESOLVE_INTERVAL_MS));
}

static bool is_vbmeta_device(dev_t device)
{
	unsigned long flags;
	unsigned int index;
	bool matched = false;

	spin_lock_irqsave(&devices_lock, flags);
	for (index = 0; index < vbmeta_device_count; ++index) {
		if (vbmeta_devices[index] == device) {
			matched = true;
			break;
		}
	}
	spin_unlock_irqrestore(&devices_lock, flags);
	return matched;
}

static bool is_vbmeta_file(struct file *file)
{
	struct inode *inode;

	if (!file)
		return false;
	inode = file_inode(file);
	if (!inode || !S_ISBLK(inode->i_mode))
		return false;
	return is_vbmeta_device(inode->i_rdev);
}

static bool should_patch(struct vbmeta_slot *slot)
{
	if (current->pid != 1 ||
	    dsu_permissive_phase_get() != DSU_PHASE_WAIT_SYSTEM_INIT)
		return false;
	if (slot->bypass_rejected)
		return false;
	if (!slot->patch_allowed) {
		if (dsu_detect_avb_enforced()) {
			slot->bypass_rejected = true;
			atomic64_inc(&proxy_errors);
			if (atomic_cmpxchg(&enforce_logged, 0, 1) == 0)
				pr_err("dsu-permissive：检测到 DSU avb_enforce，拒绝修改 vbmeta 读取视图\n");
			return false;
		}
		slot->patch_allowed = true;
	}

	return slot->patch_allowed;
}

static bool read_contains_region(loff_t position, ssize_t read_size,
				 u64 region_offset, size_t region_size)
{
	u64 relative;

	if (position < 0 || read_size <= 0 || (u64)position > region_offset)
		return false;

	relative = region_offset - (u64)position;
	return relative <= (u64)read_size &&
	       region_size <= (u64)read_size - relative;
}

static int inspect_user_magic(struct vbmeta_slot *slot, char __user *buffer,
			      loff_t position, ssize_t read_size)
{
	u8 magic[AVB_VBMETA_MAGIC_SIZE];
	size_t relative;

	if (slot->header_confirmed || slot->header_rejected ||
	    !read_contains_region(position, read_size, AVB_VBMETA_MAGIC_OFFSET,
				  AVB_VBMETA_MAGIC_SIZE))
		return 0;

	relative = AVB_VBMETA_MAGIC_OFFSET - (size_t)position;
	if (copy_from_user(magic, buffer + relative, sizeof(magic)))
		return -EFAULT;
	if (!memcmp(magic, avb_magic, sizeof(magic)))
		slot->header_confirmed = true;
	else {
		slot->header_rejected = true;
		return -EINVAL;
	}
	return 0;
}

static int patch_user_buffer(struct vbmeta_slot *slot, char __user *buffer,
			     loff_t position, ssize_t read_size,
			     u8 *old_flags, u8 *new_flags)
{
	u8 flags_byte;
	size_t relative;
	int error;

	error = inspect_user_magic(slot, buffer, position, read_size);
	if (error || !slot->header_confirmed)
		return error;
	if (!read_contains_region(
			position, read_size,
			AVB_VBMETA_HASHTREE_DISABLED_BYTE_OFFSET, 1))
		return 0;

	relative = AVB_VBMETA_HASHTREE_DISABLED_BYTE_OFFSET -
		   (size_t)position;
	if (copy_from_user(&flags_byte, buffer + relative, 1))
		return -EFAULT;
	if (old_flags)
		*old_flags = flags_byte;
	if (flags_byte & AVB_VBMETA_HASHTREE_DISABLED_BYTE_MASK)
		return 0;
	flags_byte |= AVB_VBMETA_HASHTREE_DISABLED_BYTE_MASK;
	if (new_flags)
		*new_flags = flags_byte;
	return copy_to_user(buffer + relative, &flags_byte, 1) ? -EFAULT : 1;
}

static ssize_t read_original(struct vbmeta_slot *slot, struct file *file,
			     char __user *buffer, size_t count,
			     loff_t *position)
{
	struct iov_iter iter;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
	struct iovec iov = {
		.iov_base = buffer,
		.iov_len = count,
	};
#endif
	struct kiocb kiocb;
	ssize_t result;

	if (slot->original_ops->read)
		return slot->original_ops->read(file, buffer, count, position);
	if (!slot->original_ops->read_iter)
		return -EIO;

	/* 与内核 new_sync_read() 一致，把 vfs_read 的直缓冲区交给原 read_iter。 */
	init_sync_kiocb(&kiocb, file);
	kiocb.ki_pos = position ? *position : 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
	iov_iter_ubuf(&iter, READ, buffer, count);
#else
	iov_iter_init(&iter, READ, &iov, 1, count);
#endif
	result = slot->original_ops->read_iter(&kiocb, &iter);
	if (WARN_ON_ONCE(result == -EIOCBQUEUED)) {
		atomic64_inc(&proxy_errors);
		pr_err("dsu-permissive：vbmeta 同步读取意外进入异步队列\n");
		return -EIO;
	}
	if (position)
		*position = kiocb.ki_pos;
	return result;
}

static void record_patch(loff_t position, ssize_t read_size,
			 u8 old_flags, u8 new_flags)
{
	atomic64_inc(&patched_reads);
	if (atomic_cmpxchg(&patch_logged, 0, 1) == 0)
		pr_info("dsu-permissive：已为 PID 1 临时呈现 hashtree-disabled vbmeta（offset=%lld，count=%zd，flags=0x%02x->0x%02x）\n",
			position, read_size, old_flags, new_flags);
}

static ssize_t proxy_read(struct file *file, char __user *buffer,
			  size_t count, loff_t *position)
{
	struct vbmeta_slot *slot = slot_from_file(file);
	loff_t start;
	ssize_t result;
	int patch_result;
	u8 old_flags = 0;
	u8 new_flags = 0;

	if (!slot)
		return -EIO;

	mutex_lock(&slot->io_lock);
	if (slot->file != file || !slot->original_ops ||
	    (!slot->original_ops->read && !slot->original_ops->read_iter) ||
	    !position) {
		result = -EIO;
		goto out;
	}

	start = *position;
	result = read_original(slot, file, buffer, count, position);
	if (result <= 0 || !should_patch(slot))
		goto out;

	patch_result = patch_user_buffer(slot, buffer, start, result,
					 &old_flags, &new_flags);
	if (patch_result < 0) {
		atomic64_inc(&proxy_errors);
		pr_err("dsu-permissive：修改 vbmeta 用户态读取视图失败：%d\n",
		       patch_result);
	} else if (patch_result > 0) {
		record_patch(start, result, old_flags, new_flags);
	}
out:
	mutex_unlock(&slot->io_lock);
	return result;
}

static int proxy_release(struct inode *inode, struct file *file)
{
	struct vbmeta_slot *slot = slot_from_file(file);
	int (*original_release)(struct inode *inode, struct file *released_file);
	unsigned long flags;
	int result = 0;

	if (!slot)
		return 0;

	mutex_lock(&slot->io_lock);
	original_release = slot->original_ops ? slot->original_ops->release : NULL;
	if (original_release)
		result = original_release(inode, file);

	spin_lock_irqsave(&slots_lock, flags);
	WRITE_ONCE(slot->file, NULL);
	slot->patch_allowed = false;
	slot->bypass_rejected = false;
	slot->header_confirmed = false;
	slot->header_rejected = false;
	spin_unlock_irqrestore(&slots_lock, flags);
	mutex_unlock(&slot->io_lock);

	/* __fput() 随后通过 proxy_ops.owner 释放附加时取得的模块引用。 */
	return result;
}

static void attach_proxy(struct file *file)
{
	const struct file_operations *original_ops;
	struct vbmeta_slot *slot = NULL;
	unsigned long flags;
	bool release_module = false;
	int index;

	original_ops = READ_ONCE(file->f_op);
	if (!original_ops || original_ops->owner ||
	    (!original_ops->read && !original_ops->read_iter))
		return;

	spin_lock_irqsave(&slots_lock, flags);
	for (index = 0; index < VBMETA_SLOT_COUNT; ++index) {
		if (slots[index].file == file)
			goto out;
		if (!slot && !slots[index].file &&
		    (!slots[index].ops_initialized ||
		     slots[index].original_ops == original_ops))
			slot = &slots[index];
	}

	if (!slot || !try_module_get(THIS_MODULE))
		goto out;

	if (!slot->ops_initialized) {
		slot->original_ops = original_ops;
		memcpy(&slot->proxy_ops, original_ops,
		       sizeof(slot->proxy_ops));
		slot->proxy_ops.owner = THIS_MODULE;
		/* 仅代理 vfs_read/pread64；readv、io_uring 等路径仍用原 read_iter。 */
		slot->proxy_ops.read = proxy_read;
		slot->proxy_ops.release = proxy_release;
		slot->ops_initialized = true;
	}
	slot->patch_allowed = false;
	slot->bypass_rejected = false;
	slot->header_confirmed = false;
	slot->header_rejected = false;
	WRITE_ONCE(slot->file, file);
	smp_wmb();
	if (cmpxchg(&file->f_op, original_ops, &slot->proxy_ops) !=
	    original_ops) {
		WRITE_ONCE(slot->file, NULL);
		slot->patch_allowed = false;
		slot->bypass_rejected = false;
		slot->header_confirmed = false;
		slot->header_rejected = false;
		release_module = true;
		goto out;
	}
	atomic64_inc(&matched_files);
out:
	spin_unlock_irqrestore(&slots_lock, flags);
	if (release_module)
		module_put(THIS_MODULE);
}

static int on_vfs_read(struct kprobe *probe, struct pt_regs *registers)
{
	struct file *file;

	(void)probe;
	if (dsu_permissive_phase_get() != DSU_PHASE_WAIT_SYSTEM_INIT ||
	    current->pid != 1)
		return 0;

	file = (struct file *)registers->regs[0];
	if (is_vbmeta_file(file))
		attach_proxy(file);
	return 0;
}

NOKPROBE_SYMBOL(on_vfs_read);

static struct kprobe vfs_read_probe = {
	.symbol_name = "vfs_read",
	.pre_handler = on_vfs_read,
};

int vbmeta_proxy_register(void)
{
	unsigned long flags;
	int index;
	int error;

	if (kprobe_registered)
		return 0;

	for (index = 0; index < VBMETA_SLOT_COUNT; ++index)
		mutex_init(&slots[index].io_lock);
	spin_lock_irqsave(&devices_lock, flags);
	vbmeta_device_count = 0;
	spin_unlock_irqrestore(&devices_lock, flags);
	atomic64_set(&matched_files, 0);
	atomic64_set(&patched_reads, 0);
	atomic64_set(&proxy_errors, 0);
	atomic_set(&patch_logged, 0);
	atomic_set(&device_logged, 0);
	atomic_set(&enforce_logged, 0);
	INIT_DELAYED_WORK(&resolve_work, resolve_vbmeta_devices);

	error = register_kprobe(&vfs_read_probe);
	if (error)
		return error;

	kprobe_registered = true;
	schedule_delayed_work(&resolve_work, 0);
	return 0;
}

void vbmeta_proxy_unregister(void)
{
	if (!kprobe_registered)
		return;

	cancel_delayed_work_sync(&resolve_work);
	unregister_kprobe(&vfs_read_probe);
	kprobe_registered = false;
}

u64 vbmeta_proxy_match_count(void)
{
	return atomic64_read(&matched_files);
}

u64 vbmeta_proxy_patch_count(void)
{
	return atomic64_read(&patched_reads);
}

u64 vbmeta_proxy_error_count(void)
{
	return atomic64_read(&proxy_errors);
}
