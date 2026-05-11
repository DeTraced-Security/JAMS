cmake_minimum_required(VERSION 3.22)
project(mailserver CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(
    -Wall -Wextra -Wpedantic
    $<$<CONFIG:Debug>:-g3>
    $<$<CONFIG:Debug>:-O0>
    $<$<CONFIG:Debug>:-fsanitize=address>
    $<$<CONFIG:Debug>:-fsanitize=undefined>
    $<$<CONFIG:Release>:-O3>
)

add_link_options(
    $<$<CONFIG:Debug>:-fsanitize=address>
    $<$<CONFIG:Debug>:-fsanitize=undefined>
)

find_package(OpenSSL REQUIRED)

find_path(LIBURING_INCLUDE_DIR liburing.h
    HINTS /usr/include /usr/local/include)

find_library(LIBURING_LIBRARY uring
    HINTS /usr/lib /usr/local/lib /usr/lib64
          /usr/lib/x86_64-linux-gnu)

if(NOT LIBURING_INCLUDE_DIR OR NOT LIBURING_LIBRARY)
    message(FATAL_ERROR "liburing not found. Install with:\n"
        "  Fedora:  sudo dnf install liburing-devel\n"
        "  Ubuntu:  sudo apt-get install liburing-dev")
endif()

message(STATUS "liburing: ${LIBURING_LIBRARY}")
message(STATUS "OpenSSL:  ${OPENSSL_VERSION}")

set(SOURCES
    src/main.cpp
    src/io/io_uring_loop.cpp
    src/smtp/smtp_session.cpp
    src/tls/tls_context.cpp
    src/tls/tls_conn.cpp
    src/storage/maildir.cpp
    src/dns/dns_message.cpp
    src/dns/dns_resolver.cpp
    src/auth/spf_checker.cpp
    src/auth/sasl.cpp
    src/auth/dmarc_checker.cpp
    src/auth/dkim_verifier.cpp
)

add_executable(mailserver ${SOURCES})

target_include_directories(mailserver PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${LIBURING_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(mailserver PRIVATE
    ${LIBURING_LIBRARY}
    OpenSSL::SSL
    OpenSSL::Crypto
)