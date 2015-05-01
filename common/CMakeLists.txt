set(NAME common)

add_library(${NAME} SHARED
    src/error.cpp
    src/init.cpp
    src/tools.cpp
)
