#pragma once

#include "bytecode.hpp"

#include <string>

class VM
{
public:
    VM() = default;

    /*
     * Executes protected Luau bytecode.
     *
     * The VM first validates and unwraps the protected
     * package, then passes the recovered Luau bytecode
     * to the Luau runtime.
     *
     * Returns true when execution succeeds.
     * Returns false when validation/execution fails.
     */
    bool execute(
        const Bytecode& bytecode,
        std::string& output
    ) const;
};