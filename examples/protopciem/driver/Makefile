THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
DRIVER_DIR    := $(abspath $(dir $(THIS_MAKEFILE)))

ifneq ($(KERNELRELEASE),)

obj-m := protopciem_driver.o

else

KDIR ?= /lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(DRIVER_DIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(DRIVER_DIR) clean

.PHONY: all clean

endif
