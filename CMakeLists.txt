cmake_minimum_required(VERSION 4.0)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")

project(yet_another_manual_map CXX ASM)

set(CMAKE_CXX_STANDARD 23)

add_executable(yet_another_manual_map srcs/main.cpp
        srcs/injector.cpp srcs/syscalls.s)
target_include_directories(yet_another_manual_map PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/includes)
