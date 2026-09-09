/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DSU_PERMISSIVE_BOOTCONFIG_PROXY_H
#define DSU_PERMISSIVE_BOOTCONFIG_PROXY_H

#include <linux/types.h>

int bootconfig_proxy_register(void);
void bootconfig_proxy_unregister(void);
u64 bootconfig_proxy_match_count(void);
u64 bootconfig_proxy_injection_count(void);

#endif
