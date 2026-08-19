cmake_minimum_required(VERSION 3.20)

project(luaProtecter LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(USE_LUAU "Build with Luau" ON)

add_executable(luaProtecter
    src/main.cpp
    src/transformer.cpp
    src/emitter.cpp
    src/obfuscation.cpp
)

target_include_directories(luaProtecter PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(USE_LUAU)

    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/CMakeLists.txt")
        message(FATAL_ERROR
            "Luau submodule is missing. Initialize third_party/luau first."
        )
    endif()

    message(STATUS "Adding Luau from third_party/luau")

    add_subdirectory(
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau"
        "${CMAKE_BINARY_DIR}/luau"
        EXCLUDE_FROM_ALL
    )

    if(TARGET Luau.Compiler)
        message(STATUS "Found Luau.Compiler")
        target_link_libraries(luaProtecter PRIVATE Luau.Compiler)
    else()
        message(FATAL_ERROR
            "Luau.Compiler target was not created."
        )
    endif()

    if(TARGET Luau.Ast)
        target_link_libraries(luaProtecter PRIVATE Luau.Ast)
    endif()

    if(TARGET Luau.Bytecode)
        target_link_libraries(luaProtecter PRIVATE Luau.Bytecode)
    endif()

    target_include_directories(luaProtecter PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Ast/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Compiler/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Bytecode/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/third_party/luau/Common/include"
    )

    target_compile_definitions(luaProtecter PRIVATE
        HAVE_LUAU=1
    )

endif()