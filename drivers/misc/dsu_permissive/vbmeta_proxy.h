/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DSU_PERMISSIVE_VBMETA_PROXY_H
#define DSU_PERMISSIVE_VBMETA_PROXY_H

#include <linux/types.h>

int vbmeta_proxy_register(void);
void vbmeta_proxy_unregister(void);
u64 vbmeta_proxy_match_count(void);
u64 vbmeta_proxy_patch_count(void);
u64 vbmeta_proxy_error_count(void);

#endif
