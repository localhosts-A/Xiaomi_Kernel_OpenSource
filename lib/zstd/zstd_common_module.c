// SPDX-License-Identifier: GPL-2.0+ OR BSD-3-Clause
/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under both the BSD-style license (found in the
 * LICENSE file in the root directory of this source tree) and the GPLv2 (found
 * in the COPYING file in the root directory of this source tree).
 * You may select, at your option, one of the above-listed licenses.
 */

#include <linux/module.h>

#define ZSTD_DEPS_NEED_MALLOC
#define ZSTD_STATIC_LINKING_ONLY
#include "common/zstd_deps.h"
#include <linux/zstd.h>
#include "common/huf.h"
#include "common/fse.h"
#include "common/zstd_internal.h"

// Export symbols shared by compress and decompress into a common module

/*
 * These were externally visible in the vendor 1.5.2 integration.  Upstream
 * 1.5.7 made them translation-unit-local helpers, so keep ABI compatibility
 * with the original exported signatures using the same implementation.
 */
void *ZSTD_customMalloc(size_t size, ZSTD_customMem customMem)
{
	if (customMem.customAlloc)
		return customMem.customAlloc(customMem.opaque, size);
	return ZSTD_malloc(size);
}

void *ZSTD_customCalloc(size_t size, ZSTD_customMem customMem)
{
	if (customMem.customAlloc) {
		void *const ptr = customMem.customAlloc(customMem.opaque, size);

		ZSTD_memset(ptr, 0, size);
		return ptr;
	}
	return ZSTD_calloc(1, size);
}

void ZSTD_customFree(void *ptr, ZSTD_customMem customMem)
{
	if (ptr != NULL) {
		if (customMem.customFree)
			customMem.customFree(customMem.opaque, ptr);
		else
			ZSTD_free(ptr);
	}
}

#undef ZSTD_isError   /* defined within zstd_internal.h */
EXPORT_SYMBOL_GPL(FSE_readNCount);
EXPORT_SYMBOL_GPL(HUF_readStats);
EXPORT_SYMBOL_GPL(HUF_readStats_wksp);
EXPORT_SYMBOL_GPL(ZSTD_isError);
EXPORT_SYMBOL_GPL(ZSTD_getErrorName);
EXPORT_SYMBOL_GPL(ZSTD_getErrorCode);
/* Keep the existing vendor-module ABI after the v1.5.7 import. */
EXPORT_SYMBOL_GPL(ZSTD_customMalloc);
EXPORT_SYMBOL_GPL(ZSTD_customCalloc);
EXPORT_SYMBOL_GPL(ZSTD_customFree);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("Zstd Common");
