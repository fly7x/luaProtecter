#!/bin/sh
# helper script: add the Luau submodule and initialize it
# Run from the repository root

if [ -d "third_party/luau" ]; then
  echo "third_party/luau already exists. If it's a submodule, run: git submodule update --init --recursive"
  exit 0
fi

git submodule add https://github.com/Roblox/luau.git third_party/luau
git submodule update --init --recursive

echo "Luau submodule added. Run CMake with -DUSE_LUAU=ON to enable integration."
