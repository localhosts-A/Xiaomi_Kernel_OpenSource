/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DSU_PERMISSIVE_H
#define DSU_PERMISSIVE_H

#include <linux/types.h>

enum dsu_permissive_phase {
	DSU_PHASE_WAIT_SYSTEM_INIT = 0,
	DSU_PHASE_SELINUX_SETUP_ARMED,
	DSU_PHASE_DRAINING,
	DSU_PHASE_DISABLED,
};

enum dsu_permissive_stop_reason {
	DSU_STOP_SECOND_STAGE = 0,
	DSU_STOP_TIMEOUT,
};

enum dsu_permissive_phase dsu_permissive_phase_get(void);
bool dsu_permissive_try_arm(void);
void dsu_permissive_request_stop(enum dsu_permissive_stop_reason reason);

#endif
