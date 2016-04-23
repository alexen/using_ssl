set(NAME mail_client)

add_executable(${NAME}
    src/main.cpp
)

target_link_libraries(${NAME}
    common
    ${OPENSSL_LIBRARIES}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
)