VBH_ROOT := $(PWD)/vbh

MODULE_NAME := hvi
MODULE_OBJECTS := setup.o vdso_protection.o vmcall.o

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-y += $(MODULE_OBJECTS)

EXTRA_CFLAGS += -g
EXTRA_CFLAGS += -I$(VBH_ROOT)/sources
