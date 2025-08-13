cmake_minimum_required(VERSION 4.0)
project(yet_another_manual_map)

set(CMAKE_CXX_STANDARD 23)

add_executable(yet_another_manual_map srcs/main.cpp
        srcs/injector.cpp)
target_include_directories(yet_another_manual_map PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/includes)
