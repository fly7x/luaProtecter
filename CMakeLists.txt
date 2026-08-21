cmake_minimum_required(VERSION 3.20)

project(luaProtecter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    ${CMAKE_BINARY_DIR}/bin
)

add_executable(luaProtecter
    src/main.cpp
    src/transformer.cpp
    src/bytecode.cpp
    src/vm.cpp
)

target_include_directories(luaProtecter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Luau is included as a subdirectory.
set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)

add_subdirectory(luau)

target_link_libraries(luaProtecter
    PRIVATE
        Luau.Compiler
        Luau.VM
)

if (UNIX)
    target_link_libraries(luaProtecter
        PRIVATE
            pthread
    )
endif()

if (MSVC)
    target_compile_options(luaProtecter PRIVATE
        /W4
    )
else()
    target_compile_options(luaProtecter PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()