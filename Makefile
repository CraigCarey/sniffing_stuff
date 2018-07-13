CC=g++
LDLIBS= -lpcap
CXX_FLAGS=-std=c++11 -Wall -g --coverage

all: probe_req_sniffer

probe_req_sniffer: probe_req_sniffer.cpp
	$(CC) $(CXX_FLAGS) $@.cpp -o $@ $(LDLIBS)

clean:
	rm -f probe_req_sniffer *.d *.o *.gc*

.PHONY: all clean
