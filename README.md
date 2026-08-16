# luaProtecter

This repository includes optional integration with the Luau compiler/runtime.

Redesigned project layout

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

Building with Luau

By default the CMake option USE_LUAU is ON. CMake will look for a Luau CMakeLists.txt in third_party/luau and attempt to add it as a subdirectory.

To add Luau as a submodule and enable integration:

1. Add Luau as a git submodule:

   git submodule add https://github.com/Roblox/luau.git third_party/luau

2. Configure and build with the Luau option (default is ON):

   mkdir build && cd build
   cmake -DUSE_LUAU=ON ..
   cmake --build .

If Luau is not present, CMake will skip integration and the project will build without it.

Notes

- The CMake code attempts to link a target named `luau` if Luau's CMake adds such a target. If Luau's CMake uses a different target name, you may need to update CMakeLists.txt to match.
- You can disable attempting to use Luau by setting -DUSE_LUAU=OFF when configuring CMake.
