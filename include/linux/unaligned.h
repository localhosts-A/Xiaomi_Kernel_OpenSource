/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __LINUX_UNALIGNED_H
#define __LINUX_UNALIGNED_H

/*
 * This vendor 6.6 tree does not carry the generic Linux unaligned wrapper
 * used by current upstream LZ4.  Keep the upstream include path while
 * delegating to the architecture implementation already used by this tree.
 */
#include <asm/unaligned.h>

#endif /* __LINUX_UNALIGNED_H */
