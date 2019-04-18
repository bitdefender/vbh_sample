obj-y := vbh/sources/ hvi/

KERNEL ?= /lib/modules/$(shell uname -r)/build

all:
	make -C $(KERNEL) M=$(PWD)
clean:
	make -C $(KERNEL) M=$(PWD) clean

.PHONY: all clean
