// SPDX-License-Identifier: GPL-2.0-only
#include <linux/atomic.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/workqueue.h>

#include "bootconfig_proxy.h"
#include "dsu_permissive.h"
#include "exec_gate.h"
#include "selinux_enforce_proxy.h"
#include "vbmeta_proxy.h"

#define HOOK_TIMEOUT_SECONDS 120U

static atomic_t phase = ATOMIC_INIT(DSU_PHASE_WAIT_SYSTEM_INIT);
static atomic_t stop_reason = ATOMIC_INIT(DSU_STOP_TIMEOUT);
static struct work_struct stop_work;
static struct delayed_work timeout_work;

enum dsu_permissive_phase dsu_permissive_phase_get(void)
{
	return (enum dsu_permissive_phase)atomic_read(&phase);
}

bool dsu_permissive_try_arm(void)
{
	return atomic_cmpxchg(&phase, DSU_PHASE_WAIT_SYSTEM_INIT,
			      DSU_PHASE_SELINUX_SETUP_ARMED) ==
	       DSU_PHASE_WAIT_SYSTEM_INIT;
}

static const char *stop_reason_name(enum dsu_permissive_stop_reason reason)
{
	if (reason == DSU_STOP_SECOND_STAGE)
		return "PID 1 已进入 second_stage";
	return "120 秒安全超时";
}

static void stop_hooks(struct work_struct *work)
{
	enum dsu_permissive_stop_reason reason;
	u64 bootconfig_matches;
	u64 bootconfig_injections;
	u64 vbmeta_matches;
	u64 vbmeta_patches;
	u64 vbmeta_errors;
	u64 enforce_matches;
	u64 force_count;
	u64 enforce_errors;

	(void)work;
	if (atomic_read(&phase) == DSU_PHASE_DISABLED)
		return;
	reason = (enum dsu_permissive_stop_reason)atomic_read(&stop_reason);
	cancel_delayed_work(&timeout_work);
	exec_gate_unregister();
	vbmeta_proxy_unregister();
	selinux_enforce_proxy_unregister();
	bootconfig_proxy_unregister();
	bootconfig_matches = bootconfig_proxy_match_count();
	bootconfig_injections = bootconfig_proxy_injection_count();
	vbmeta_matches = vbmeta_proxy_match_count();
	vbmeta_patches = vbmeta_proxy_patch_count();
	vbmeta_errors = vbmeta_proxy_error_count();
	enforce_matches = selinux_enforce_proxy_match_count();
	force_count = selinux_enforce_proxy_force_count();
	enforce_errors = selinux_enforce_proxy_error_count();
	atomic_set(&phase, DSU_PHASE_DISABLED);
	pr_info("dsu-permissive：Hook 已注销（%s，vbmeta 命中 %llu，修改 %llu，错误 %llu；bootconfig 命中 %llu，注入 %llu；DSU enforce 命中 %llu，切换 %llu，错误 %llu）\n",
		stop_reason_name(reason), vbmeta_matches, vbmeta_patches,
		vbmeta_errors, bootconfig_matches, bootconfig_injections,
		enforce_matches, force_count, enforce_errors);
}

void dsu_permissive_request_stop(enum dsu_permissive_stop_reason reason)
{
	int current_phase;

	current_phase = atomic_read(&phase);
	while (current_phase == DSU_PHASE_WAIT_SYSTEM_INIT ||
	       current_phase == DSU_PHASE_SELINUX_SETUP_ARMED) {
		int observed_phase;

		observed_phase = atomic_cmpxchg(&phase, current_phase,
					DSU_PHASE_DRAINING);
		if (observed_phase == current_phase) {
			atomic_set(&stop_reason, reason);
			schedule_work(&stop_work);
			return;
		}
		current_phase = observed_phase;
	}
}

static void on_timeout(struct work_struct *work)
{
	(void)work;
	dsu_permissive_request_stop(DSU_STOP_TIMEOUT);
}

static int __init dsu_permissive_init(void)
{
	int error;

	INIT_WORK(&stop_work, stop_hooks);
	INIT_DELAYED_WORK(&timeout_work, on_timeout);

	error = bootconfig_proxy_register();
	if (error) {
		pr_err("dsu-permissive：注册 bootconfig vfs_read kprobe 失败：%d\n",
		       error);
		return error;
	}

	error = vbmeta_proxy_register();
	if (error) {
		pr_err("dsu-permissive：注册 vbmeta vfs_read kprobe 失败：%d\n",
		       error);
		bootconfig_proxy_unregister();
		return error;
	}

	error = selinux_enforce_proxy_register();
	if (error) {
		pr_err("dsu-permissive：注册 SELinux enforce vfs_read kprobe 失败：%d\n",
		       error);
		vbmeta_proxy_unregister();
		bootconfig_proxy_unregister();
		return error;
	}

	error = exec_gate_register();
	if (error) {
		pr_err("dsu-permissive：注册 sched_process_exec tracepoint 失败：%d\n",
		       error);
		selinux_enforce_proxy_unregister();
		vbmeta_proxy_unregister();
		bootconfig_proxy_unregister();
		return error;
	}

	schedule_delayed_work(&timeout_work,
			      msecs_to_jiffies(HOOK_TIMEOUT_SECONDS * 1000U));
	pr_info("dsu-permissive：模块已加载；主系统/DSU 处理 AVB，仅 DSU 处理 SELinux\n");
	return 0;
}

static void __exit dsu_permissive_exit(void)
{
	/* 先关闭所有生产者的状态门，防止 cancel_work_sync() 后重新排队。 */
	atomic_set(&phase, DSU_PHASE_DISABLED);
	cancel_delayed_work_sync(&timeout_work);
	cancel_work_sync(&stop_work);
	exec_gate_unregister();
	/* 同步 tracepoint 后再捕获注销期间最后一次可能的排队。 */
	cancel_work_sync(&stop_work);
	selinux_enforce_proxy_unregister();
	vbmeta_proxy_unregister();
	bootconfig_proxy_unregister();
	pr_info("dsu-permissive：模块已卸载\n");
}

module_init(dsu_permissive_init);
module_exit(dsu_permissive_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DSU-Permissive contributors");
MODULE_DESCRIPTION("Android first-stage AVB 视图处理与 DSU 专用 SELinux permissive");
MODULE_INFO(dsu_ddk_target, DSU_DDK_TARGET);
MODULE_IMPORT_NS(ANDROID_GKI_VFS_EXPORT_ONLY);
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
MODULE_VERSION("0.7.0");
