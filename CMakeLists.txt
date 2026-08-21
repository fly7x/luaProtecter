cmake_minimum_required(VERSION 3.20)

project(luaProtecter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================
# Luau
# ============================================================
#
# Your repository stores Luau here:
#
#     third_party/luau/
#
# NOT:
#
#     luau/
#
# ============================================================

set(LUAU_BUILD_CLI OFF CACHE BOOL "Build Luau CLI tools" FORCE)
set(LUAU_BUILD_TESTS OFF CACHE BOOL "Build Luau tests" FORCE)
set(LUAU_BUILD_WEB OFF CACHE BOOL "Build Luau web module" FORCE)
set(LUAU_BUILD_SHARED OFF CACHE BOOL "Build Luau shared libraries" FORCE)

add_subdirectory(
    third_party/luau
)

# ============================================================
# LuaProtecter
# ============================================================

add_executable(luaProtecter

    src/main.cpp

    src/transformer.cpp
    src/transformer.hpp

    src/bytecode.cpp
    src/bytecode.hpp

    src/vm.cpp
    src/vm.hpp
)

# ============================================================
# Include directories
# ============================================================

target_include_directories(luaProtecter
    PRIVATE

    ${CMAKE_CURRENT_SOURCE_DIR}/src

    ${CMAKE_CURRENT_SOURCE_DIR}/include

    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/VM/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Compiler/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Bytecode/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Ast/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Common/include
)

# ============================================================
# Link against the REAL Luau compiler + VM
# ============================================================
#
# Luau itself defines these targets in its CMake project.
#
# Compiler:
#   Luau.Compiler
#
# Runtime VM:
#   Luau.VM
#
# ============================================================

target_link_libraries(luaProtecter
    PRIVATE

    Luau.Compiler
    Luau.VM
)

# ============================================================
# Compiler warnings
# ============================================================

if(MSVC)

    target_compile_options(
        luaProtecter
        PRIVATE
        /W4
    )

else()

    target_compile_options(
        luaProtecter
        PRIVATE

        -Wall
        -Wextra
        -Wpedantic
    )

endif()

# ============================================================
# Linux / Unix
# ============================================================

if(UNIX AND NOT APPLE)

    target_link_libraries(
        luaProtecter
        PRIVATE
        pthread
    )

endif()

# ============================================================
# Output
# ============================================================

set_target_properties(
    luaProtecter
    PROPERTIES

    RUNTIME_OUTPUT_DIRECTORY
    ${CMAKE_BINARY_DIR}/bin
)