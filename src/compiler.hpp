#pragma once

#include "bytecode.hpp"

#include <string>

class Compiler
{
public:
    Compiler() = default;

    /*
     * Compile supported Luau source into our custom VM
     * instruction format.
     *
     * This is NOT native Luau bytecode.
     * The resulting Bytecode is consumed by VM::execute().
     */
    Bytecode compile(
        const std::string& source
    ) const;
};