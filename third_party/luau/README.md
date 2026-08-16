# third_party/luau

Official Luau source goes here.

Add Luau as a submodule to this path to enable optional integration with the project build system:

  git submodule add https://github.com/Roblox/luau.git third_party/luau

After adding the submodule, run CMake from the project's build directory; the top-level CMakeLists.txt will attempt to add Luau as a subdirectory and link against it.

If Luau changes its CMake target names or layout, you may need to adjust the top-level CMakeLists.txt to link the correct target(s) and include directories.
