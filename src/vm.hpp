#pragma once

#include "bytecode.hpp"

#include <string>

class VM
{
public:
    VM() = default;

    /*
     * Execute REAL Luau bytecode using the Luau VM
     * contained in third_party/luau.
     */
    bool execute(
        const Bytecode& bytecode,
        std::string& output
    ) const;
};