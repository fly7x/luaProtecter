#pragma once

#include "bytecode.hpp"

#include <string>

class Compiler
{
public:
    Compiler() = default;

    /*
     * Compile real Luau source using the Luau compiler
     * shipped in third_party/luau.
     *
     * The returned Bytecode contains REAL Luau bytecode.
     */
    Bytecode compile(
        const std::string& source
    ) const;
};