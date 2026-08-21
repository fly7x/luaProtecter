cmake_minimum_required(VERSION 3.20)

project(luaProtecter LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(USE_LUAU "Use embedded Luau" ON)

add_executable(luaProtecter
    src/main.cpp
    src/transformer.cpp
    src/emitter.cpp
    src/lexer.cpp
    src/obfuscation.cpp
)

target_include_directories(luaProtecter
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(USE_LUAU AND EXISTS
   "${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/CMakeLists.txt")

    message(STATUS "Luau sources found.")

    set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
    set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(LUAU_BUILD_WEB OFF CACHE BOOL "" FORCE)

    add_subdirectory(
        third_party/luau
        ${CMAKE_BINARY_DIR}/luau
    )

    target_link_libraries(luaProtecter
        PRIVATE
            Luau.Compiler
            Luau.VM
            Luau.Ast
            Luau.Common
    )

    target_compile_definitions(
        luaProtecter PRIVATE HAVE_LUAU=1
    )

else()

    message(WARNING "Luau submodule not found.")

endif()

if(UNIX)

    target_link_libraries(
        luaProtecter PRIVATE pthread
    )

endif()