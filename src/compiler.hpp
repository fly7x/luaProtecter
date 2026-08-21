#pragma once

#include “bytecode.hpp”

#include 

class Compiler
{
public:
Compiler() = default;

/*
 * Compile Luau source into the custom VM instruction format.
 *
 * This is NOT Luau bytecode.
 * The resulting Bytecode is consumed by VM::execute().
 */
Bytecode compile(
    const std::string& source
) const;

};