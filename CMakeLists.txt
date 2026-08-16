cmake_minimum_required(VERSION 3.15)
project(luaProtecter VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(${PROJECT_SOURCE_DIR}/include)

add_executable(luaProtecter
    src/main.cpp
    src/transformer.cpp
    src/emitter.cpp
    src/obfuscation.cpp
)

option(USE_LUAU "Use embedded Luau (requires third_party/luau to be present)" ON)

if (USE_LUAU)
    if (EXISTS "${PROJECT_SOURCE_DIR}/third_party/luau/CMakeLists.txt")
        message(STATUS "Luau sources found in third_party/luau — adding subdirectory")
        # Add Luau as a subdirectory (assumes Luau provides a CMakeLists.txt)
        add_subdirectory(${PROJECT_SOURCE_DIR}/third_party/luau ${CMAKE_BINARY_DIR}/third_party/luau_build EXCLUDE_FROM_ALL)

        # If the Luau target exists, link it. The exact target name may vary depending on Luau's CMake.
        if (TARGET luau)
            target_link_libraries(luaProtecter PRIVATE luau)
            target_compile_definitions(luaProtecter PRIVATE HAVE_LUAU=1)
            target_include_directories(luaProtecter PRIVATE ${PROJECT_SOURCE_DIR}/third_party/luau/include)
        else()
            message(WARNING "Luau subdirectory added but target 'luau' not found. You may need to inspect Luau's CMake targets and adjust CMakeLists.txt accordingly.")
        endif()
    else()
        message(STATUS "third_party/luau not found; skipping Luau integration. Add Luau as submodule or place sources in third_party/luau to enable integration.")
    endif()
endif()

# Optionally link to other libraries
# target_link_libraries(luaProtecter PRIVATE <libraries>)
