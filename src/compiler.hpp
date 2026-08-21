#pragma once

#include "bytecode.hpp"

#include <string>

class Compiler
{
public:
    Compiler() = default;

    /*
     * Compile complete Luau source using the real Luau compiler
     * contained in third_party/luau.
     *
     * This supports the Luau language rather than a homemade
     * subset such as only print().
     *
     * Throws std::runtime_error when Luau compilation fails.
     */
    Bytecode compile(
        const std::string& source
    ) const;
};