KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

CC = x86_64-linux-gnu-gcc

# Kernel modules
obj-m += pciem.o
obj-m += protopciem_driver.o

# Userspace proxy
PROXY_SRC = pciem_uproxy.c
PROXY_BIN = pciem_uproxy

all: modules proxy

modules:
	$(MAKE) -C $(KDIR) CC=$(CC) M=$(PWD) modules

proxy: $(PROXY_SRC)
	$(CC) -o $(PROXY_BIN) $(PROXY_SRC) -Wall -O2

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(PROXY_BIN)

load: modules
	sudo insmod pciem.ko

unload:
	-sudo rmmod pciem

reload: unload load

test: reload
	lspci -vvv |
grep -A 20 "1f0c:0001"
	ls -la /dev/pciem*

.PHONY: all modules proxy clean load unload reload test
