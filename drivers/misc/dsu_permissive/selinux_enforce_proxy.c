// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/dcache.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/magic.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <asm/ptrace.h>

#include "dsu_detect.h"
#include "dsu_permissive.h"
#include "selinux_enforce_proxy.h"

#define SELINUX_ENFORCE_NAME "enforce"
#define SELINUX_ENFORCE_SLOT_COUNT 2

enum enforce_force_state {
	ENFORCE_FORCE_PENDING = 0,
	ENFORCE_FORCE_RUNNING,
	ENFORCE_FORCE_SUCCEEDED,
	ENFORCE_FORCE_FAILED,
};

struct selinux_enforce_slot {
	struct file *file;
	const struct file_operations *original_ops;
	/* 每个 file 需要保留原操作集，所以代理 fops 不能声明为 const。 */
	struct file_operations proxy_ops;
	struct mutex io_lock;
	bool ops_initialized;
	bool dsu_checked;
	bool dsu_active;
};

static struct selinux_enforce_slot slots[SELINUX_ENFORCE_SLOT_COUNT];
static DEFINE_SPINLOCK(slots_lock);
static atomic_t force_state = ATOMIC_INIT(ENFORCE_FORCE_PENDING);
static atomic64_t matched_files = ATOMIC64_INIT(0);
static atomic64_t forced_transitions = ATOMIC64_INIT(0);
static atomic64_t proxy_errors = ATOMIC64_INIT(0);
static bool kprobe_registered;

static ssize_t proxy_read(struct file *file, char __user *buffer,
			  size_t count, loff_t *position);
static int proxy_release(struct inode *inode, struct file *file);

static struct selinux_enforce_slot *slot_from_file(struct file *file)
{
	struct selinux_enforce_slot *slot;

	slot = container_of(file->f_op, struct selinux_enforce_slot,
			    proxy_ops);
	if (READ_ONCE(slot->file) != file)
		return NULL;
	return slot;
}

static bool is_selinux_enforce(struct file *file)
{
	struct dentry *dentry;
	struct super_block *super;

	if (!file)
		return false;

	dentry = file->f_path.dentry;
	super = file_inode(file)->i_sb;
	if (!dentry || !super || super->s_magic != SELINUX_MAGIC)
		return false;
	if (dentry->d_parent != super->s_root)
		return false;
	if (dentry->d_name.len != sizeof(SELINUX_ENFORCE_NAME) - 1)
		return false;

	return !memcmp(dentry->d_name.name, SELINUX_ENFORCE_NAME,
		       sizeof(SELINUX_ENFORCE_NAME) - 1);
}

static bool dsu_is_active(struct selinux_enforce_slot *slot)
{
	if (!slot->dsu_checked) {
		/* SELinux 只允许 DSU 启动链在 selinux_setup 窗口内切换。 */
		slot->dsu_active = dsu_detect_active();
		slot->dsu_checked = true;
	}

	return slot->dsu_active;
}

static int copy_enforcing_to_user(char __user *buffer)
{
	const char enforcing = '1';

	return copy_to_user(buffer, &enforcing, sizeof(enforcing)) ? -EFAULT : 0;
}

static int force_permissive_and_report_enforcing(
	struct selinux_enforce_slot *slot, struct file *file,
	char __user *buffer, char original_value)
{
	const char permissive = '0';
	loff_t write_position = 0;
	ssize_t written;
	int error;

	if (!slot->original_ops || !slot->original_ops->write)
		return -EOPNOTSUPP;

	if (copy_to_user(buffer, &permissive, sizeof(permissive)))
		return -EFAULT;

	/*
	 * 直接调用该 selinuxfs file 的原始 write fop。它仍会执行
	 * SECURITY__SETENFORCE 权限检查、状态页更新、通知与审计；这里不
	 * 定位 selinux_state，也不依赖其随机化布局。
	 */
	written = slot->original_ops->write(file, buffer, 1, &write_position);
	if (written != 1) {
		error = written < 0 ? (int)written : -EIO;
		if (copy_to_user(buffer, &original_value,
				 sizeof(original_value)))
			return -EFAULT;
		return error;
	}

	/*
	 * user init 以 ALLOW_PERMISSIVE_SELINUX=0 编译时会坚持 desired=true。
	 * 对这一次 security_getenforce() 报告 1，可避免它把刚完成的启动期
	 * permissive 再写回 enforcing。代理在 second_stage 前即失效。
	 */
	return copy_enforcing_to_user(buffer);
}

static ssize_t proxy_read(struct file *file, char __user *buffer,
			  size_t count, loff_t *position)
{
	struct selinux_enforce_slot *slot = slot_from_file(file);
	loff_t original_position;
	ssize_t result;
	char original_value;
	int state;
	int error;

	if (!slot)
		return -EIO;

	mutex_lock(&slot->io_lock);
	if (slot->file != file || !slot->original_ops ||
	    !slot->original_ops->read) {
		result = -EIO;
		goto out;
	}

	original_position = position ? *position : -1;
	result = slot->original_ops->read(file, buffer, count, position);
	if (result <= 0 || original_position != 0 || !count ||
	    current->pid != 1 ||
	    dsu_permissive_phase_get() != DSU_PHASE_SELINUX_SETUP_ARMED ||
	    !dsu_is_active(slot))
		goto out;

	if (copy_from_user(&original_value, buffer, sizeof(original_value))) {
		atomic64_inc(&proxy_errors);
		goto out;
	}
	if (original_value != '0' && original_value != '1') {
		atomic64_inc(&proxy_errors);
		goto out;
	}

	state = atomic_read(&force_state);
	if (state == ENFORCE_FORCE_SUCCEEDED) {
		if (copy_enforcing_to_user(buffer))
			atomic64_inc(&proxy_errors);
		goto out;
	}
	if (state != ENFORCE_FORCE_PENDING ||
	    atomic_cmpxchg(&force_state, ENFORCE_FORCE_PENDING,
			   ENFORCE_FORCE_RUNNING) != ENFORCE_FORCE_PENDING)
		goto out;

	error = force_permissive_and_report_enforcing(slot, file, buffer,
						       original_value);
	if (error) {
		atomic64_inc(&proxy_errors);
		atomic_set(&force_state, ENFORCE_FORCE_FAILED);
		pr_err("dsu-permissive：启动期 SELinux permissive 切换失败：%d\n",
		       error);
		goto out;
	}

	atomic64_inc(&forced_transitions);
	atomic_set(&force_state, ENFORCE_FORCE_SUCCEEDED);
	pr_info("dsu-permissive：已通过 SELinux 原始 enforce 接口执行一次启动期 permissive\n");
out:
	mutex_unlock(&slot->io_lock);
	return result;
}

static int proxy_release(struct inode *inode, struct file *file)
{
	struct selinux_enforce_slot *slot = slot_from_file(file);
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
	slot->dsu_checked = false;
	slot->dsu_active = false;
	spin_unlock_irqrestore(&slots_lock, flags);
	mutex_unlock(&slot->io_lock);

	/* __fput() 随后通过 proxy_ops.owner 释放附加时取得的模块引用。 */
	return result;
}

static void attach_proxy(struct file *file)
{
	const struct file_operations *original_ops;
	struct selinux_enforce_slot *slot = NULL;
	unsigned long flags;
	bool release_module = false;
	int index;

	original_ops = READ_ONCE(file->f_op);
	if (!original_ops || original_ops->owner || !original_ops->read ||
	    !original_ops->write)
		return;

	spin_lock_irqsave(&slots_lock, flags);
	for (index = 0; index < SELINUX_ENFORCE_SLOT_COUNT; ++index) {
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
		slot->proxy_ops.read = proxy_read;
		slot->proxy_ops.release = proxy_release;
		slot->ops_initialized = true;
	}
	slot->dsu_checked = false;
	slot->dsu_active = false;
	WRITE_ONCE(slot->file, file);
	/* f_op 发布后，代理回调必须能看到上面的完整槽位状态。 */
	smp_wmb();
	if (cmpxchg(&file->f_op, original_ops, &slot->proxy_ops) !=
	    original_ops) {
		WRITE_ONCE(slot->file, NULL);
		slot->dsu_checked = false;
		slot->dsu_active = false;
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

	if (dsu_permissive_phase_get() != DSU_PHASE_SELINUX_SETUP_ARMED ||
	    current->pid != 1)
		return 0;

	file = (struct file *)registers->regs[0];
	if (is_selinux_enforce(file))
		attach_proxy(file);

	return 0;
}

NOKPROBE_SYMBOL(on_vfs_read);

static struct kprobe vfs_read_probe = {
	.symbol_name = "vfs_read",
	.pre_handler = on_vfs_read,
};

int selinux_enforce_proxy_register(void)
{
	int index;
	int error;

	if (kprobe_registered)
		return 0;

	for (index = 0; index < SELINUX_ENFORCE_SLOT_COUNT; ++index)
		mutex_init(&slots[index].io_lock);

	atomic_set(&force_state, ENFORCE_FORCE_PENDING);
	atomic64_set(&matched_files, 0);
	atomic64_set(&forced_transitions, 0);
	atomic64_set(&proxy_errors, 0);
	error = register_kprobe(&vfs_read_probe);
	if (error)
		return error;

	kprobe_registered = true;
	return 0;
}

void selinux_enforce_proxy_unregister(void)
{
	if (!kprobe_registered)
		return;

	unregister_kprobe(&vfs_read_probe);
	kprobe_registered = false;
}

u64 selinux_enforce_proxy_match_count(void)
{
	return atomic64_read(&matched_files);
}

u64 selinux_enforce_proxy_force_count(void)
{
	return atomic64_read(&forced_transitions);
}

u64 selinux_enforce_proxy_error_count(void)
{
	return atomic64_read(&proxy_errors);
}
