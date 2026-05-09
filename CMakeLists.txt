cmake_minimum_required(VERSION 3.22)
project(mailserver CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (NOT CMAKE_BUILD_TYPE)
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
find_path(
    LIBURING_INCLUDE_DIR liburing.h
    HINTS /usr/include /usr/local/include    
)
find_library(
    LIBRURING_LIBRARY uring
    HINTS /usr/lib /usr/local/lib
)

if (NOT LIBURING_INCLUDE_DIR OR NOT LIBRURING_LIBRARY)
    message(FATAL_ERROR "liburing not found. Run: sudo dnf install liburing-devel")
endif()

set(SOURCES
    src/main.cpp
    src/io/io_uring_loop.cpp
    src/smtp/smtp_session.cpp
    src/tls/tls_context.cpp
    src/storage/maildir.cpp
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
