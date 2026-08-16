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

# Optionally link to Luau or other third-party libraries if available
# target_link_libraries(luaProtecter PRIVATE <libraries>)
