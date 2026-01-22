THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR      := $(abspath $(dir $(THIS_MAKEFILE)))

DRIVER_DIR    := $(THIS_DIR)/driver
USERSPACE_DIR := $(THIS_DIR)/userspace

.PHONY: all driver userspace clean

all: driver userspace

driver:
	$(MAKE) -C $(DRIVER_DIR)

userspace:
	$(MAKE) -C $(USERSPACE_DIR)

clean:
	$(MAKE) -C $(DRIVER_DIR) clean
	$(MAKE) -C $(USERSPACE_DIR) clean
