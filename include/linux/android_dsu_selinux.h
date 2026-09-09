/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ANDROID_DSU_SELINUX_H
#define _LINUX_ANDROID_DSU_SELINUX_H

#include <linux/kconfig.h>
#include <linux/types.h>

#if IS_ENABLED(CONFIG_ANDROID_DSU_SELINUX_PERMISSIVE)
bool android_dsu_selinux_bootconfig_active(void);
bool android_dsu_selinux_try_force_permissive(void);
void android_dsu_selinux_force_result(int error);
bool android_dsu_selinux_report_enforcing(void);
#else
static inline bool android_dsu_selinux_bootconfig_active(void)
{
	return false;
}

static inline bool android_dsu_selinux_try_force_permissive(void)
{
	return false;
}

static inline void android_dsu_selinux_force_result(int error)
{
	(void)error;
}

static inline bool android_dsu_selinux_report_enforcing(void)
{
	return false;
}
#endif

#endif /* _LINUX_ANDROID_DSU_SELINUX_H */
