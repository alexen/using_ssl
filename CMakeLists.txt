cmake_minimum_required(VERSION 3.2)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(OPENSSL_ROOT_DIR "/usr/local/openssl")

find_package(Boost 1.54 REQUIRED)
find_package(OpenSSL 1.0.2 REQUIRED)
find_package(Threads REQUIRED)

add_subdirectory(ssl_server)
add_subdirectory(ssl_client)