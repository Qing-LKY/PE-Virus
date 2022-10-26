include_directories(${PROJECT_SOURCE_DIR}/include)

set(SOURCE
    infect.c
)
add_executable(
    PE-Virus
    ${SOURCE}
)
