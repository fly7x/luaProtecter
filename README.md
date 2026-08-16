# luaProtecter

Redesigned project layout: removed the standalone lexer from the default pipeline and simplified the transformer to accept raw source text. The repository now focuses on a clearer pipeline: source -> transformer -> obfuscator -> emitter.

Current layout

luaProtecter
├── src
│   ├── main.cpp
│   ├── transformer.cpp
│   ├── transformer.hpp
│   ├── obfuscation.cpp
│   ├── obfuscation.hpp
│   ├── emitter.cpp
│   └── emitter.hpp
│
├── include
│   └── protector
│       └── config.hpp
│
├── input
│   └── script.lua
│
├── output
│   └── protected.lua
│
└── third_party
    └── luau
        ← official Luau source goes here

Build

- mkdir build && cd build
- cmake ..
- cmake --build .

Run

- ./luaProtecter

Notes

- If you want to reintroduce a lexer stage, add it back and update CMakeLists.txt to include its sources.
- Add Luau as a submodule into third_party/luau if you need to integrate the Luau compiler/runtime.
