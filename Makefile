obj-y := vbh/sources/ hvi/

KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all: modules

modules clean:
	make -C $(KERNELDIR) M=$(PWD) $@

.PHONY: all modules clean
