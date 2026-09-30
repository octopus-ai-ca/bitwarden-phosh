CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Werror -pthread

test_nci_bridge: test_nci_bridge.c nci_bridge.c nci_bridge.h
	$(CC) $(CFLAGS) -o $@ test_nci_bridge.c nci_bridge.c

check: test_nci_bridge
	./test_nci_bridge

clean:
	rm -f test_nci_bridge

.PHONY: check clean
