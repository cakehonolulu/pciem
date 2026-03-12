THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CUR_DIR    := $(abspath $(dir $(THIS_MAKEFILE)))

CFLAGS := -Wall -Wextra -O2 -pthread -I$(CUR_DIR)/../../include -ggdb

CFLAGS  = -Wall -Wextra -O2 -ggdb -pthread -I../../include $(shell pkg-config --cflags libpipewire-0.3)
LDLIBS  = $(shell pkg-config --libs libpipewire-0.3) -lpthread

hda_card: hda_card.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f hda_card
