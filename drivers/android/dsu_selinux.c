// SPDX-License-Identifier: GPL-2.0
/*
 * Android DSU first-stage SELinux permissive helper.
 *
 * The helper is built into the kernel so it is available before first-stage
 * init loads policy.  It is intentionally gated by the AOSP DSU marker and
 * by the PID 1 selinux_setup window; a normal boot never changes SELinux.
 */
#include <linux/atomic.h>
#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include <trace/events/sched.h>

#include <linux/android_dsu_selinux.h>

#define DSU_BOOTED_PATH "/metadata/gsi/dsu/booted"
#define SYSTEM_INIT_PATH "/system/bin/init"
#define SELINUX_SETUP_TIMEOUT_SECONDS 120U

enum dsu_selinux_window {
	DSU_SELINUX_WAIT_FIRST_INIT = 0,
	DSU_SELINUX_SETUP_ACTIVE,
	DSU_SELINUX_WINDOW_CLOSED,
};

enum dsu_selinux_force_state {
	DSU_SELINUX_FORCE_PENDING = 0,
	DSU_SELINUX_FORCE_RUNNING,
	DSU_SELINUX_FORCE_SUCCEEDED,
	DSU_SELINUX_FORCE_FAILED,
};

static atomic_t selinux_window =
	ATOMIC_INIT(DSU_SELINUX_WAIT_FIRST_INIT);
static atomic_t dsu_seen = ATOMIC_INIT(0);
static atomic_t force_state =
	ATOMIC_INIT(DSU_SELINUX_FORCE_PENDING);
static struct delayed_work selinux_timeout_work;

static bool dsu_booted_marker_present(void)
{
	struct path path;
	struct inode *inode;
	bool present;

	if (kern_path(DSU_BOOTED_PATH, LOOKUP_FOLLOW, &path))
		return false;

	inode = d_inode(path.dentry);
	present = inode && !S_ISDIR(inode->i_mode);
	path_put(&path);
	return present;
}

static bool dsu_selinux_active(void)
{
	if (current->pid != 1 ||
	    atomic_read(&selinux_window) != DSU_SELINUX_SETUP_ACTIVE)
		return false;

	if (!atomic_read(&dsu_seen) && dsu_booted_marker_present()) {
		if (atomic_cmpxchg(&dsu_seen, 0, 1) == 0)
			pr_info("android-dsu-selinux: DSU boot marker detected\n");
	}

	return atomic_read(&dsu_seen);
}

bool android_dsu_selinux_bootconfig_active(void)
{
	return dsu_selinux_active();
}

bool android_dsu_selinux_try_force_permissive(void)
{
	if (!dsu_selinux_active())
		return false;

	return atomic_cmpxchg(&force_state, DSU_SELINUX_FORCE_PENDING,
				      DSU_SELINUX_FORCE_RUNNING) ==
		       DSU_SELINUX_FORCE_PENDING;
}

void android_dsu_selinux_force_result(int error)
{
	if (error == -EAGAIN)
		atomic_set(&force_state, DSU_SELINUX_FORCE_PENDING);
	else if (error)
		atomic_set(&force_state, DSU_SELINUX_FORCE_FAILED);
	else
		atomic_set(&force_state, DSU_SELINUX_FORCE_SUCCEEDED);
}

bool android_dsu_selinux_report_enforcing(void)
{
	return dsu_selinux_active() &&
	       atomic_read(&force_state) == DSU_SELINUX_FORCE_SUCCEEDED;
}

static void close_selinux_window(const char *reason)
{
	if (atomic_cmpxchg(&selinux_window, DSU_SELINUX_SETUP_ACTIVE,
			   DSU_SELINUX_WINDOW_CLOSED) == DSU_SELINUX_SETUP_ACTIVE)
		pr_info("android-dsu-selinux: first-stage window closed (%s)\n",
			reason);
}

static void selinux_timeout(struct work_struct *work)
{
	(void)work;
	close_selinux_window("timeout");
}

static void dsu_selinux_process_exec(void *unused, struct task_struct *task,
				     pid_t old_pid, struct linux_binprm *bprm)
{
	(void)unused;
	(void)old_pid;

	if (task->pid != 1 || !bprm || !bprm->filename ||
	    strcmp(bprm->filename, SYSTEM_INIT_PATH))
		return;

	if (atomic_cmpxchg(&selinux_window, DSU_SELINUX_WAIT_FIRST_INIT,
			   DSU_SELINUX_SETUP_ACTIVE) == DSU_SELINUX_WAIT_FIRST_INIT) {
		atomic_set(&dsu_seen, 0);
		atomic_set(&force_state, DSU_SELINUX_FORCE_PENDING);
		pr_info("android-dsu-selinux: selinux_setup window opened\n");
		return;
	}

	close_selinux_window("second-stage init");
}

static int __init android_dsu_selinux_init(void)
{
	int error;

	INIT_DELAYED_WORK(&selinux_timeout_work, selinux_timeout);
	error = register_trace_sched_process_exec(dsu_selinux_process_exec, NULL);
	if (error) {
		pr_err("android-dsu-selinux: failed to register init exec gate: %d\n",
		       error);
		return error;
	}

	schedule_delayed_work(&selinux_timeout_work,
			      msecs_to_jiffies(SELINUX_SETUP_TIMEOUT_SECONDS * 1000U));
	pr_info("android-dsu-selinux: built-in DSU-only permissive helper enabled\n");
	return 0;
}
subsys_initcall(android_dsu_selinux_init);
