cmake_minimum_required(VERSION 3.7)
project(mypr)

set(CMAKE_CXX_STANDARD 11)

include(FindPCAP.cmake)

set(SOURCE_FILES main.cpp)
add_executable(mypr ${SOURCE_FILES})
target_link_libraries(mypr ${PCAP_LIBRARY})