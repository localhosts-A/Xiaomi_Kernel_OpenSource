/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DSU_PERMISSIVE_DSU_DETECT_H
#define DSU_PERMISSIVE_DSU_DETECT_H

#include <linux/types.h>

bool dsu_detect_active(void);
bool dsu_detect_avb_enforced(void);

#endif
