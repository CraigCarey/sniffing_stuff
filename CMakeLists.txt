cmake_minimum_required(VERSION 3.10)
project(probe_req_sniffer)

set(CMAKE_CXX_STANDARD 11)

add_executable(probe_req_sniffer probe_req_sniffer.cpp)
target_link_libraries(probe_req_sniffer -lpcap)
