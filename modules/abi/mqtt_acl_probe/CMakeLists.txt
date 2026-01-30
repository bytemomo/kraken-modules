cmake_minimum_required(VERSION 3.20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(mqtt_acl_probe
  VERSION 1.0.0
  LANGUAGES C
)

option(BUILD_STATIC_RUNTIME "Link the static runtime on MSVC (MT/MTd)" OFF)

add_library(mqtt_acl_probe SHARED mqtt_acl_probe.c)

target_compile_definitions(mqtt_acl_probe PRIVATE BUILDING_MQTT_ACL_PROBE)
target_include_directories(mqtt_acl_probe PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../api/abi)

set_target_properties(mqtt_acl_probe PROPERTIES
  PREFIX ""
  POSITION_INDEPENDENT_CODE ON
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  OUTPUT_NAME "mqtt_acl_probe"
  WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

if (NOT WIN32)
    set_target_properties(mqtt_acl_probe PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
  )
endif()

if (MSVC AND BUILD_STATIC_RUNTIME)
    foreach(flag_var
    CMAKE_C_FLAGS CMAKE_C_FLAGS_DEBUG CMAKE_C_FLAGS_RELEASE
    CMAKE_C_FLAGS_RELWITHDEBINFO CMAKE_C_FLAGS_MINSIZEREL
  )
        if(${flag_var} MATCHES "/MDd")
            string(REPLACE "/MDd" "/MTd" ${flag_var} "${${flag_var}}")
        elseif(${flag_var} MATCHES "/MD")
            string(REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
        endif()
    endforeach()
    target_compile_definitions(mqtt_acl_probe PRIVATE _CRT_SECURE_NO_WARNINGS=1)
endif()

message(STATUS "Building module: mqtt_acl_probe")
