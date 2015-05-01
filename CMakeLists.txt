cmake_minimum_required(VERSION 3.2)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror -Wpedantic -Wextra")

set(OPENSSL_ROOT_DIR "/usr/local/openssl")
set(BOOST_ROOT "/usr/local")

find_package(Boost 1.58 REQUIRED COMPONENTS system thread program_options)
find_package(OpenSSL 1.0.2 REQUIRED)
find_package(Threads REQUIRED)

add_subdirectory(common)
add_subdirectory(ssl_server)
add_subdirectory(ssl_client)
