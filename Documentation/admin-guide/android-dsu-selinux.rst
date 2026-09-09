.. SPDX-License-Identifier: GPL-2.0-only

========================================
Android DSU SELinux permissive helper
========================================

``CONFIG_ANDROID_DSU_SELINUX_PERMISSIVE`` is an opt-in development feature
for Android DSU boots. It is built into the kernel and does not require an
``init_boot`` loader or an externally loaded ``.ko``.

The helper is active only when all of the following hold:

* the caller is PID 1;
* PID 1 is between its first and second execution of ``/system/bin/init``;
* ``/metadata/gsi/dsu/booted`` exists.

During that window it gives PID 1 a temporary
``androidboot.selinux = "permissive"`` bootconfig entry. On the first read
of ``/sys/fs/selinux/enforce`` it performs the transition through the native
SELinux path, including the normal permission check, audit event, status-page
update, LSM notification, and IMA measurement. For the remainder of the
window PID 1 sees ``1`` from the enforce file so a ``user`` build of init does
not immediately restore enforcing mode.

The window closes when second-stage init executes or after 120 seconds. A
normal boot without the DSU marker is not changed. After the window closes,
ordinary ``setenforce`` behavior is restored; the helper does not permanently
lock SELinux into permissive mode.

This feature intentionally weakens the SELinux trust boundary for DSU
development. It should not be enabled in a production kernel.
