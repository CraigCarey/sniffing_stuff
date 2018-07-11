CC=g++
LDLIBS= -lpcap
CXX_FLAGS=-std=c++11 -Wall -g --coverage

all: simplesniffer

simplesniffer:
	$(CC) $(CXX_FLAGS) $@.cpp -o $@ $(LDLIBS)

clean:
	rm -f simplesniffer *.d *.o *.gc*

.PHONY: all clean
