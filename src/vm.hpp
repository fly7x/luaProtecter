#pragma once
#include "bytecode.hpp"
#include <string>
class VM
{
public:
    VM() = default;
    /*
     * Execute real Luau bytecode produced by Compiler.
     *
     * Returns true when execution succeeds.
     * Returns false when loading or execution fails.
     *
     * output receives captured program output where applicable.
     */
    bool execute(
        const Bytecode& bytecode,
        std::string& output
    ) const;
};