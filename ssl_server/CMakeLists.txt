set(NAME ssl_server)

add_executable(${NAME}
    src/server.cpp
    src/main.cpp
)

target_link_libraries(${NAME}
    common
    ${CMAKE_THREAD_LIBS_INIT}
    ${OPENSSL_LIBRARIES}
    ${Boost_THREAD_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
)
