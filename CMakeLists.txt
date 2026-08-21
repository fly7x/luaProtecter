cmake_minimum_required(VERSION 3.20)

project(luaProtecter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ============================================================
# Download Luau automatically
# ============================================================
#
# This means you DO NOT need to manually put a "luau" folder
# into your repository.
#
# CMake will download the official Luau source during configure.
#

include(FetchContent)

FetchContent_Declare(
    Luau
    GIT_REPOSITORY https://github.com/luau-lang/luau.git
    GIT_TAG master
    GIT_SHALLOW TRUE
)

# We don't need Luau's command-line tools/tests.
set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_WEB OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_SHARED OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(Luau)


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
)


# ============================================================
# Luau libraries
# ============================================================
#
# Luau's own CMake project creates these targets:
#
#   Luau.Compiler
#   Luau.VM
#
# Compiler:
#   source -> Luau bytecode
#
# VM:
#   executes Luau bytecode
#

target_link_libraries(luaProtecter
    PRIVATE

    Luau.Compiler
    Luau.VM
)


# ============================================================
# Compiler warnings
# ============================================================

if(MSVC)

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

        # Luau and some system headers can trigger these
        # without representing an actual problem in our code.
        -Wno-unused-parameter
    )

endif()


# ============================================================
# Release optimization
# ============================================================

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING
        "Build type" FORCE)
endif()


if(NOT MSVC)

    target_compile_options(luaProtecter
        PRIVATE

        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:RelWithDebInfo>:-O2>
    )

endif()


# ============================================================
# Output
# ============================================================

set_target_properties(luaProtecter
    PROPERTIES

    RUNTIME_OUTPUT_DIRECTORY
        ${CMAKE_BINARY_DIR}/bin
)