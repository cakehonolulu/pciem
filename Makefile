KDIR ?= /lib/modules/$(shell uname -r)/build
GCC ?= gcc
PWD := $(shell pwd)

all: modules protopciem_card

modules:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel modules

protopciem_card:
	$(GCC) -Wall -Wextra -O2 -pthread -Iinclude -o userspace/protopciem_card userspace/protopciem_card.c

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel clean
	rm -f userspace/protopciem_card

.PHONY: all modules clean
