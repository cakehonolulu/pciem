THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CUR_DIR    := $(abspath $(dir $(THIS_MAKEFILE)))

CFLAGS  := -Wall -Wextra -O2 -I$(CUR_DIR)/../../include -ggdb $(shell pkg-config --cflags sdl3)
LDFLAGS := $(shell pkg-config --libs sdl3)

bochs_card: bochs_card.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f bochs_card
