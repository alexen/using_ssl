set(NAME ssl_client)

add_executable(${NAME}
    src/client.cpp
    src/main.cpp
)

target_link_libraries(${NAME}
    common
    ${OPENSSL_LIBRARIES}
    ${Boost_SYSTEM_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
)
