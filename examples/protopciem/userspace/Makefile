THIS_MAKEFILE := $(lastword $(MAKEFILE_LIST))
CUR_DIR    := $(abspath $(dir $(THIS_MAKEFILE)))

CFLAGS := -Wall -Wextra -O2 -pthread -I$(CUR_DIR)/../../../include

protopciem_card: protopciem_card.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f protopciem_card
