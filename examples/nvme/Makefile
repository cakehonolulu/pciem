THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CUR_DIR    := $(abspath $(dir $(THIS_MAKEFILE)))

CFLAGS := -Wall -Wextra -O2 -I$(CUR_DIR)/../../include -ggdb

nvme_card: nvme_card.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f nvme_card
