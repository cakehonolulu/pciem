# SPDX-License-Identifier: MIT

THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR      := $(abspath $(dir $(THIS_MAKEFILE)))
PCIEM_ROOT    := $(THIS_DIR)/../..
UNAME_S       := $(shell uname -s)

CFLAGS := -Wall -Wextra -O2 -I$(PCIEM_ROOT)/include
LDFLAGS :=

ifeq ($(UNAME_S),Linux)
LDFLAGS += -static
endif

.PHONY: all clean

all: pciem_vroot_smoke

pciem_vroot_smoke: pciem_vroot_smoke.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f pciem_vroot_smoke
