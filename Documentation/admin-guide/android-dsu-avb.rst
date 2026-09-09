.. SPDX-License-Identifier: GPL-2.0-only

===============================
Android first-stage AVB read view
===============================

``CONFIG_ANDROID_DSU_AVB_BYPASS`` adds an in-kernel, first-stage Android
verified-boot read view. It is intended for development kernels where the
normal system must boot with the top-level ``vbmeta`` verification disabled.
The AVB option itself does not change SELinux policy or enforcement; the
separate ``CONFIG_ANDROID_DSU_SELINUX_PERMISSIVE`` option is required for the
DSU-only SELinux development behavior.

When enabled, the helper does the following while PID 1 is still in the
first-stage window:

* adds ``androidboot.verifiedbootstate = "orange"`` to the returned
  ``/proc/bootconfig`` view;
* marks the top-level AVB ``VERIFICATION_DISABLED`` flag in reads of the
  resolved ``vbmeta``, ``vbmeta_a``, or ``vbmeta_b`` block device.

The AVB change is applied only to the user buffer returned by ``vfs_read()``.
It does not write any block device, modify the on-disk ``vbmeta`` image,
change ``androidboot.selinux``, write ``selinuxfs/enforce``, or install a
SELinux hook. The read-view window closes when PID 1 executes
``/system/bin/init``. No ``init_boot`` loader or external kernel module is
required.

When ``CONFIG_ANDROID_DSU_SELINUX_PERMISSIVE`` is also enabled, a separate
DSU-only helper detects ``/metadata/gsi/dsu/booted`` between the first and
second PID 1 executions of ``/system/bin/init``. It adds a temporary
``androidboot.selinux = "permissive"`` view and performs one native SELinux
state transition. The helper closes at second-stage init or after a safety
timeout; normal boots without the DSU marker are unchanged.

This is a deliberate change to the device trust model. A top-level ``vbmeta``
flag can affect the chained system, vendor, and odm images governed by that
metadata. It does not bypass a bootloader's verification of the kernel,
boot, or other boot-chain images before the kernel starts. The kernel option
is therefore appropriate only for images whose boot chain already permits
this development kernel to run.
