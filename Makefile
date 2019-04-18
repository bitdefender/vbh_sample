obj-y := vbh/sources/ hvi/

KERNEL ?= /lib/modules/$(shell uname -r)/build

all: modules

modules clean:
	make -C $(KERNEL) M=$(PWD) $@

.PHONY: all modules clean
