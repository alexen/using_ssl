set(NAME ssl_client)

add_executable(${NAME}
    src/client.cpp
    src/main.cpp
)

set_property(TARGET ${NAME} PROPERTY CXX_STANDARD 11)

target_link_libraries(${NAME}
    common
    ${OPENSSL_LIBRARIES}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
)
