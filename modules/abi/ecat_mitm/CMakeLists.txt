cmake_minimum_required(VERSION 3.10)
project(ecat_mitm C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")

add_library(ecat_mitm SHARED ecat_mitm.c)
target_include_directories(ecat_mitm PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../api/abi)
