VBH_ROOT := $(PWD)/../vbh_bd

MODULE_NAME := hvi
MODULE_OBJECTS := setup.o vdso_protection.o

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-y += $(MODULE_OBJECTS)

EXTRA_CFLAGS += -g
EXTRA_CFLAGS += -I$(VBH_ROOT)/sources

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD)

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

