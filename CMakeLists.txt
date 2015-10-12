cmake_minimum_required(VERSION 2.8)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -Werror -Wpedantic -Wextra")
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g3 -gdwarf-2")

set(OPENSSL_ROOT_DIR "/usr/local/openssl")
set(BOOST_ROOT "/usr/local")

find_package(Boost 1.57 REQUIRED COMPONENTS system thread program_options)
find_package(OpenSSL 1.0.2 REQUIRED)
find_package(Threads REQUIRED)
find_package(Doxygen 1.8)

if(DOXYGEN_FOUND)
    set(DOXYGEN_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/doxyfile)
    set(DOXYGEN_OUTPUT ${CMAKE_CACHEFILE_DIR}/doc)
    
    add_custom_command(
        OUTPUT ${DOXYGEN_OUTPUT}
        COMMAND ${CMAKE_COMMAND} -E echo_append "Building API Documentation..."
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_INPUT}
        COMMAND ${CMAKE_COMMAND} -E echo "Done."
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DEPENDS ${DOXYGEN_INPUT}
    )
    
    add_custom_target(apidoc ALL DEPENDS ${DOXYGEN_OUTPUT})
    
    add_custom_target(apidoc_forced
        COMMAND ${CMAKE_COMMAND} -E echo_append "Building API Documentation..."
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_INPUT}
        COMMAND ${CMAKE_COMMAND} -E echo "Done."
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif(DOXYGEN_FOUND)

add_subdirectory(common)
add_subdirectory(ssl_server)
add_subdirectory(ssl_client)
