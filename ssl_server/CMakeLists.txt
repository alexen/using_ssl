set(NAME ssl_server)

add_executable(${NAME}
    src/server.cpp
    src/main.cpp
)

set_property(TARGET ${NAME} PROPERTY CXX_STANDARD 11)

target_link_libraries(${NAME}
    ${CMAKE_THREAD_LIBS_INIT}
    ${OPENSSL_LIBRARIES}
    ${Boost_THREAD_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
)
