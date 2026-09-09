// SPDX-License-Identifier: GPL-2.0-only
#include <linux/namei.h>
#include <linux/path.h>

#include "dsu_detect.h"

#define DSU_BOOTED_MARKER "/metadata/gsi/dsu/booted"
#define DSU_AVB_ENFORCE_MARKER "/metadata/gsi/dsu/avb_enforce"

static bool path_exists(const char *name)
{
	struct path path;

	if (kern_path(name, LOOKUP_FOLLOW, &path))
		return false;

	path_put(&path);
	return true;
}

bool dsu_detect_active(void)
{
	/*
	 * AOSP first-stage init 会在判断 DSU 前删除旧标记，并且只在 DSU
	 * 映射成功后重新创建该标记；这也是 IsGsiRunning() 的唯一条件。
	 */
	return path_exists(DSU_BOOTED_MARKER);
}

bool dsu_detect_avb_enforced(void)
{
	/* avb_enforce 只属于 DSU 启动链，不能阻断主系统的 AVB 处理。 */
	return dsu_detect_active() && path_exists(DSU_AVB_ENFORCE_MARKER);
}
