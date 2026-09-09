// SPDX-License-Identifier: GPL-2.0
/*
 * Android first-stage AVB read-view bypass.
 *
 * This is deliberately an in-kernel, AVB-only path. It does not alter
 * SELinux boot parameters or selinuxfs/enforce, and it does not write any
 * boot-chain partition. The bypass is limited to PID 1 before its first
 * exec of /system/bin/init. Only the user buffer returned by vfs_read() is
 * changed.
 */
#include <linux/android_dsu_avb.h>
#include <linux/atomic.h>
#include <linux/blkdev.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#include <trace/events/sched.h>

#define SYSTEM_INIT_PATH "/system/bin/init"
#define VBMETA_RESOLVE_INTERVAL_MS 10U

#define AVB_VBMETA_MAGIC_OFFSET 0U
#define AVB_VBMETA_MAGIC_SIZE 4U
#define AVB_VBMETA_FLAGS_OFFSET 120U
#define AVB_VBMETA_VERIFICATION_DISABLED_BYTE_OFFSET \
	(AVB_VBMETA_FLAGS_OFFSET + 3U)
#define AVB_VBMETA_VERIFICATION_DISABLED_BYTE_MASK 0x02U

static const char *const vbmeta_paths[] = {
	"/dev/block/by-name/vbmeta",
	"/dev/block/by-name/vbmeta_a",
	"/dev/block/by-name/vbmeta_b",
	"/dev/block/bootdevice/by-name/vbmeta",
	"/dev/block/bootdevice/by-name/vbmeta_a",
	"/dev/block/bootdevice/by-name/vbmeta_b",
};

static const u8 avb_magic[AVB_VBMETA_MAGIC_SIZE] = { 'A', 'V', 'B', '0' };

static dev_t vbmeta_devices[ARRAY_SIZE(vbmeta_paths)];
static unsigned int vbmeta_device_count;
static DEFINE_SPINLOCK(vbmeta_devices_lock);
static struct delayed_work resolve_work;
static atomic_t first_stage_active = ATOMIC_INIT(1);
static atomic_t device_logged = ATOMIC_INIT(0);
static atomic_t patch_logged = ATOMIC_INIT(0);

static bool dsu_avb_first_stage_active(void)
{
	return current->pid == 1 && atomic_read(&first_stage_active);
}

bool android_dsu_avb_bootconfig_active(void)
{
	return dsu_avb_first_stage_active();
}

static bool add_vbmeta_device(dev_t device)
{
	unsigned long flags;
	unsigned int index;
	bool added = false;

	if (!device)
		return false;

	spin_lock_irqsave(&vbmeta_devices_lock, flags);
	for (index = 0; index < vbmeta_device_count; ++index) {
		if (vbmeta_devices[index] == device)
			goto out;
	}
	if (vbmeta_device_count < ARRAY_SIZE(vbmeta_devices)) {
		vbmeta_devices[vbmeta_device_count++] = device;
		added = true;
	}
out:
	spin_unlock_irqrestore(&vbmeta_devices_lock, flags);
	return added;
}

static void resolve_vbmeta_path(const char *name)
{
	struct inode *inode;
	struct path path;

	if (kern_path(name, LOOKUP_FOLLOW, &path))
		return;

	inode = d_inode(path.dentry);
	if (inode && S_ISBLK(inode->i_mode) &&
	    add_vbmeta_device(inode->i_rdev) &&
	    atomic_cmpxchg(&device_logged, 0, 1) == 0)
		pr_info("android-dsu-avb: resolved top-level vbmeta block device\n");
	path_put(&path);
}

static void resolve_vbmeta_devices(struct work_struct *work)
{
	unsigned int index;

	(void)work;
	if (!atomic_read(&first_stage_active))
		return;

	for (index = 0; index < ARRAY_SIZE(vbmeta_paths); ++index)
		resolve_vbmeta_path(vbmeta_paths[index]);

	if (atomic_read(&first_stage_active))
		schedule_delayed_work(&resolve_work,
				      msecs_to_jiffies(VBMETA_RESOLVE_INTERVAL_MS));
}

static bool is_vbmeta_device(dev_t device)
{
	unsigned long flags;
	unsigned int index;
	bool matched = false;

	spin_lock_irqsave(&vbmeta_devices_lock, flags);
	for (index = 0; index < vbmeta_device_count; ++index) {
		if (vbmeta_devices[index] == device) {
			matched = true;
			break;
		}
	}
	spin_unlock_irqrestore(&vbmeta_devices_lock, flags);
	return matched;
}

static bool is_vbmeta_file(struct file *file)
{
	struct inode *inode;

	if (!file)
		return false;
	inode = file_inode(file);
	return inode && S_ISBLK(inode->i_mode) &&
		is_vbmeta_device(inode->i_rdev);
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

void android_dsu_avb_patch_vbmeta(struct file *file, char __user *buffer,
					  loff_t position, ssize_t read_size)
{
	u8 magic[AVB_VBMETA_MAGIC_SIZE];
	u8 flags_byte;
	size_t relative;

	if (!dsu_avb_first_stage_active() || !is_vbmeta_file(file) ||
		!buffer || read_size <= 0)
		return;

	/* Validate the magic whenever this read contains the header prefix. */
	if (read_contains_region(position, read_size, AVB_VBMETA_MAGIC_OFFSET,
				AVB_VBMETA_MAGIC_SIZE)) {
		relative = AVB_VBMETA_MAGIC_OFFSET - (size_t)position;
		if (copy_from_user(magic, buffer + relative, sizeof(magic)) ||
		    memcmp(magic, avb_magic, sizeof(magic)))
			return;
	}

	if (!read_contains_region(
			position, read_size,
			AVB_VBMETA_VERIFICATION_DISABLED_BYTE_OFFSET, 1))
		return;

	relative = AVB_VBMETA_VERIFICATION_DISABLED_BYTE_OFFSET -
		   (size_t)position;
	if (copy_from_user(&flags_byte, buffer + relative, 1) ||
	    (flags_byte & AVB_VBMETA_VERIFICATION_DISABLED_BYTE_MASK))
		return;

	flags_byte |= AVB_VBMETA_VERIFICATION_DISABLED_BYTE_MASK;
	if (copy_to_user(buffer + relative, &flags_byte, 1))
		return;

	if (atomic_cmpxchg(&patch_logged, 0, 1) == 0)
		pr_info("android-dsu-avb: first-stage PID 1 vbmeta read view marked verification-disabled\n");
}

static void dsu_avb_process_exec(void *unused, struct task_struct *task,
				 pid_t old_pid, struct linux_binprm *bprm)
{
	(void)unused;
	(void)old_pid;

	if (task->pid != 1 || !bprm || !bprm->filename ||
	    strcmp(bprm->filename, SYSTEM_INIT_PATH))
		return;

	if (atomic_cmpxchg(&first_stage_active, 1, 0) == 1)
		pr_info("android-dsu-avb: first-stage AVB read-view window closed\n");
}

static int __init android_dsu_avb_init(void)
{
	int error;

	error = register_trace_sched_process_exec(dsu_avb_process_exec, NULL);
	if (error) {
		atomic_set(&first_stage_active, 0);
		pr_err("android-dsu-avb: failed to register init exec gate: %d\n",
		       error);
		return error;
	}

	INIT_DELAYED_WORK(&resolve_work, resolve_vbmeta_devices);
	schedule_delayed_work(&resolve_work, 0);
	pr_info("android-dsu-avb: built-in AVB-only bypass enabled; SELinux is untouched\n");
	return 0;
}
subsys_initcall(android_dsu_avb_init);
