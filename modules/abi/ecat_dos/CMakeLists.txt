cmake_minimum_required(VERSION 3.10)
project(ecat_dos C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

add_library(ecat_dos SHARED ecat_dos.c)
target_include_directories(ecat_dos PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../api/abi)
