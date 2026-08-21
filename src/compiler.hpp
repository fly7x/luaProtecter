#pragma once

#include "bytecode.hpp"

#include <string>

class Compiler
{
public:
    Compiler() = default;

    // Compile Luau source using the Luau compiler
    // already present in third_party/luau.
    Bytecode compile(
        const std::string& source
    ) const;
};