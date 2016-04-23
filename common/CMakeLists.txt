set(NAME common)

add_library(${NAME} SHARED
    src/error.cpp
    src/init.cpp
    src/tools.cpp
    src/logger.cpp
    src/bio_tools.cpp
    src/ssl_tools.cpp
)
