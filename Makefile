KDIR ?= /lib/modules/$(shell uname -r)/build
GCC ?= gcc
PWD := $(shell pwd)

THIS_MAKEFILE     := $(lastword $(MAKEFILE_LIST))
TOP_DIR           := $(abspath $(dir $(THIS_MAKEFILE)))
EXAMPLES_DIR      := $(TOP_DIR)/examples
EXAMPLE_MAKEFILES := $(wildcard $(EXAMPLES_DIR)/*/Makefile)
EXAMPLES          := $(notdir $(patsubst %/Makefile,%,$(EXAMPLE_MAKEFILES)))

all: modules examples

modules:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel modules

examples: $(EXAMPLES)

$(EXAMPLES):
	$(MAKE) -C $(EXAMPLES_DIR)/$@

clean:
	$(MAKE) -C $(KDIR) M=$(PWD)/kernel clean
	for e in $(EXAMPLES); do \
		$(MAKE) -C $(EXAMPLES_DIR)/$$e clean; \
	done

.PHONY: all modules examples clean $(EXAMPLES)
