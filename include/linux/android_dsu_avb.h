/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_ANDROID_DSU_AVB_H
#define _LINUX_ANDROID_DSU_AVB_H

#include <linux/compiler_types.h>
#include <linux/kconfig.h>
#include <linux/types.h>

struct file;

#if IS_ENABLED(CONFIG_ANDROID_DSU_AVB_BYPASS)
bool android_dsu_avb_bootconfig_active(void);
void android_dsu_avb_patch_vbmeta(struct file *file, char __user *buffer,
					loff_t position, ssize_t read_size);
#else
static inline bool android_dsu_avb_bootconfig_active(void)
{
	return false;
}

static inline void android_dsu_avb_patch_vbmeta(struct file *file,
						char __user *buffer,
						loff_t position,
						ssize_t read_size)
{
}
#endif

#endif /* _LINUX_ANDROID_DSU_AVB_H */
