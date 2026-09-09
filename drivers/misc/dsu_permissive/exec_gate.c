// SPDX-License-Identifier: GPL-2.0-only
#include <linux/binfmts.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/tracepoint.h>

#include "dsu_permissive.h"
#include "exec_gate.h"

#define SYSTEM_INIT_PATH "/system/bin/init"

static struct tracepoint *sched_exec_tracepoint;
static bool tracepoint_registered;

static void find_sched_exec_tracepoint(struct tracepoint *tracepoint, void *private)
{
	struct tracepoint **result = private;

	if (!strcmp(tracepoint->name, "sched_process_exec"))
		*result = tracepoint;
}

static void on_sched_process_exec(void *unused, struct task_struct *task,
				  pid_t old_pid, struct linux_binprm *bprm)
{
	enum dsu_permissive_phase phase;

	(void)unused;
	(void)old_pid;

	if (task->pid != 1 || !bprm || !bprm->filename ||
	    strcmp(bprm->filename, SYSTEM_INIT_PATH))
		return;

	phase = dsu_permissive_phase_get();
	if (phase == DSU_PHASE_WAIT_SYSTEM_INIT) {
		if (dsu_permissive_try_arm())
			pr_info("dsu-permissive：已进入 selinux_setup 观察窗口\n");
		return;
	}

	if (phase == DSU_PHASE_SELINUX_SETUP_ARMED)
		dsu_permissive_request_stop(DSU_STOP_SECOND_STAGE);
}

int exec_gate_register(void)
{
	int error;

	if (tracepoint_registered)
		return 0;

	sched_exec_tracepoint = NULL;
	for_each_kernel_tracepoint(find_sched_exec_tracepoint,
				   &sched_exec_tracepoint);
	if (!sched_exec_tracepoint)
		return -ENOENT;

	error = tracepoint_probe_register(sched_exec_tracepoint,
					  (void *)on_sched_process_exec, NULL);
	if (error) {
		sched_exec_tracepoint = NULL;
		return error;
	}

	tracepoint_registered = true;
	return 0;
}

void exec_gate_unregister(void)
{
	if (!tracepoint_registered)
		return;

	tracepoint_probe_unregister(sched_exec_tracepoint,
				    (void *)on_sched_process_exec, NULL);
	tracepoint_registered = false;
	sched_exec_tracepoint = NULL;
}
