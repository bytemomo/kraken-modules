cmake_minimum_required(VERSION 3.10)
project(ecat_inject C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

add_library(ecat_inject SHARED ecat_inject.c)
target_include_directories(ecat_inject PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../api/abi)
