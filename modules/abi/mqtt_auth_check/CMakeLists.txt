cmake_minimum_required(VERSION 3.20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(mqtt_auth_check
  VERSION 2.0.0
  LANGUAGES C
)

option(BUILD_STATIC_RUNTIME "Link the static runtime on MSVC (MT/MTd)" OFF)

# V2 API module (receives connected handle)
add_library(mqtt_auth_check SHARED mqtt_auth_check.c)

target_compile_definitions(mqtt_auth_check PRIVATE BUILDING_MQTT_AUTH_CHECK)
target_include_directories(mqtt_auth_check PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../../../api/abi)

set_target_properties(mqtt_auth_check PROPERTIES
  PREFIX ""
  POSITION_INDEPENDENT_CODE ON
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  OUTPUT_NAME "mqtt_auth_check"
  WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

if (NOT WIN32)
    set_target_properties(mqtt_auth_check PROPERTIES
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
    target_compile_definitions(mqtt_auth_check PRIVATE _CRT_SECURE_NO_WARNINGS=1)
endif()

message(STATUS "Building module: mqtt_auth_check")
