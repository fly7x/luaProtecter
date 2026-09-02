cmake_minimum_required(VERSION 3.20)
project(luaProtecter LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LUAU_BUILD_CLI OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_WEB OFF CACHE BOOL "" FORCE)
set(LUAU_BUILD_SHARED OFF CACHE BOOL "" FORCE)
add_subdirectory(third_party/luau)

add_executable(luaProtecter
    src/main.cpp
    src/compiler.cpp
    src/transformer.cpp
    src/obfuscator.cpp
    src/bytecode.cpp
    src/virtualizer.cpp
    src/vm.cpp
    src/translator.cpp
)

target_include_directories(luaProtecter PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/VM/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/VM/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Compiler/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Bytecode/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Ast/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Common/include
)

target_link_libraries(luaProtecter PRIVATE Luau.Compiler Luau.VM)
if(UNIX AND NOT APPLE)
    target_link_libraries(luaProtecter PRIVATE pthread)
endif()

set_target_properties(luaProtecter PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)