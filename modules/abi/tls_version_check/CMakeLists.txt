cmake_minimum_required(VERSION 3.20)

project(tls_version_check
  VERSION 2.0.0
  LANGUAGES C
)

option(BUILD_STATIC_RUNTIME "Link the static runtime on MSVC (MT/MTd)" OFF)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# V2 API module with TLS testing capabilities
add_library(tls_version_check SHARED tls_version_check.c)

target_compile_definitions(tls_version_check PRIVATE BUILDING_TLS_VERSION_CHECK)
target_include_directories(tls_version_check PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../api/abi
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(tls_version_check PRIVATE OpenSSL::SSL OpenSSL::Crypto)

set_target_properties(tls_version_check PROPERTIES
  PREFIX ""
  POSITION_INDEPENDENT_CODE ON
  C_STANDARD 11
  C_STANDARD_REQUIRED YES
  OUTPUT_NAME "tls_version_check"
  WINDOWS_EXPORT_ALL_SYMBOLS OFF
)

if (NOT WIN32)
    set_target_properties(tls_version_check PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
  )
endif()

if (MSVC OR MINGW)
    target_link_libraries(tls_version_check PRIVATE ws2_32)
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
    target_compile_definitions(tls_version_check PRIVATE _CRT_SECURE_NO_WARNINGS=1)
endif()

message(STATUS "Building module: tls_version_check (with OpenSSL ${OPENSSL_VERSION})")
