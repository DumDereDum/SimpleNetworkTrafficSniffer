cmake_minimum_required(VERSION 3.10)
project(RawSocketProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(SOURCE_FILES src/main.cpp src/sniffer.cpp)

add_executable(RawSocketProject ${SOURCE_FILES})

target_include_directories(RawSocketProject PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(RawSocketProject ws2_32)
