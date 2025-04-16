cmake_minimum_required(VERSION 3.10)
project(NetReaper)

set(CMAKE_CXX_STANDARD 17)

find_package(Pcap REQUIRED)

include_directories(include)

add_executable(netreaper main.cpp src/arp_spoofer.cpp src/network_utils.cpp)
target_link_libraries(netreaper pcap)