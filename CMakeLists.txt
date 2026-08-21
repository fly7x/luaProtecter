cmake_minimum_required(VERSION 3.20)

project(luaProtecter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ------------------------------------------------------------
# Luau
# ------------------------------------------------------------

add_subdirectory(luau)

# ------------------------------------------------------------
# LuaProtecter
# ------------------------------------------------------------

add_executable(luaProtecter
    src/main.cpp
    src/transformer.cpp
    src/bytecode.cpp
    src/vm.cpp
)

target_include_directories(luaProtecter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/luau/VM/include
        ${CMAKE_CURRENT_SOURCE_DIR}/luau/Compiler/include
        ${CMAKE_CURRENT_SOURCE_DIR}/luau/Common/include
)

target_link_libraries(luaProtecter
    PRIVATE
        Luau.Compiler
        Luau.VM
)

if (MSVC)
    target_compile_options(luaProtecter PRIVATE /W4)
else()
    target_compile_options(luaProtecter PRIVATE
        -Wall
        -Wextra
        -Wpedantic
    )
endif()