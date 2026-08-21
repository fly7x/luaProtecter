cmake_minimum_required(VERSION 3.20)

project(luaProtecter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------------------------------------------------
# Luau
# ------------------------------------------------------------

set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_WEB OFF CACHE BOOL "" FORCE)

add_subdirectory(luau)

# ------------------------------------------------------------
# luaProtecter
# ------------------------------------------------------------

add_executable(luaProtecter

    src/main.cpp

    src/transformer.cpp
    src/transformer.hpp

    src/bytecode.cpp
    src/bytecode.hpp

    src/vm.cpp
    src/vm.hpp
)

# ------------------------------------------------------------
# Include directories
# ------------------------------------------------------------

target_include_directories(luaProtecter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# ------------------------------------------------------------
# Luau libraries
# ------------------------------------------------------------

target_link_libraries(luaProtecter
    PRIVATE
        Luau.VM
        Luau.Compiler
        Luau.Ast
)

# ------------------------------------------------------------
# Compiler warnings
# ------------------------------------------------------------

if (MSVC)

    target_compile_options(luaProtecter
        PRIVATE
            /W4
    )

else()

    target_compile_options(luaProtecter
        PRIVATE
            -Wall
            -Wextra
            -Wpedantic
    )

endif()

# ------------------------------------------------------------
# Runtime output
# ------------------------------------------------------------

set_target_properties(luaProtecter
    PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/bin
)