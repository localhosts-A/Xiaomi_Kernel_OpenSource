/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DSU_PERMISSIVE_SELINUX_ENFORCE_PROXY_H
#define DSU_PERMISSIVE_SELINUX_ENFORCE_PROXY_H

#include <linux/types.h>

int selinux_enforce_proxy_register(void);
void selinux_enforce_proxy_unregister(void);
u64 selinux_enforce_proxy_match_count(void);
u64 selinux_enforce_proxy_force_count(void);
u64 selinux_enforce_proxy_error_count(void);

#endif
