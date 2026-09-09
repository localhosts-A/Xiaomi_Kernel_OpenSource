# KBUILD_EXTMOD is set when the same directory is built as a standalone DDK
# module.  In a kernel tree the Kconfig symbol decides y/m/n instead.
ifneq ($(KBUILD_EXTMOD),)
obj-m += dsu_permissive.o
else
obj-$(CONFIG_DSU_PERMISSIVE) += dsu_permissive.o
endif

dsu_permissive-y := dsu_permissive_main.o exec_gate.o bootconfig_proxy.o \
	dsu_detect.o selinux_enforce_proxy.o vbmeta_proxy.o

ifndef DSU_DDK_TARGET
DSU_DDK_TARGET := unknown
endif
ccflags-y += -DDSU_DDK_TARGET=\"$(DSU_DDK_TARGET)\"
