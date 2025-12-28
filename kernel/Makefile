KDIR ?= /lib/modules/$(shell uname -r)/build

ccflags-y := -I$(src)/../include -I$(src)/framework

pciem-objs := framework/pciem_framework.o \
              framework/pciem_capabilities.o \
              framework/pciem_p2p.o \
              framework/pciem_dma.o \
			  framework/pciem_bar.o \
			  framework/pciem_userspace.o

protopciem-driver-objs := driver/protopciem_driver.c

obj-m += pciem.o
obj-m += driver/protopciem_driver.o

ccflags-y += -Wall

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
