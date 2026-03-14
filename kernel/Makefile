KDIR ?= /lib/modules/$(shell uname -r)/build

ccflags-y := -I$(src)/../include -I$(src)/include

pciem-objs := framework/pciem.o \
              framework/capabilities.o \
              framework/p2p.o \
              framework/dma.o \
              framework/userspace.o \
              framework/pool.o

pciem-objs += trace/smptrace.o \
              trace/arch/x86/lib/insn.o \
              trace/arch/x86/lib/insn-eval.o \
              trace/arch/x86/lib/inat.o
ccflags-y += -I$(src)/trace/arch/x86/include/asm

obj-m += pciem.o

ccflags-y += -Wall

# Only add build rules when not invoked by kbuild
ifeq ($(KERNELRELEASE),)
all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
endif
