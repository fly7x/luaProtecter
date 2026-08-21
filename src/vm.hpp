#pragma once

#include "bytecode.hpp"

#include <string>

class VM
{
public:
    VM() = default;

    /*
     * Execute protected Luau bytecode.
     *
     * The VM first restores the protected representation,
     * then executes it through the real Luau runtime.
     */
    bool execute(
        const Bytecode& bytecode,
        std::string& output
    ) const;
};