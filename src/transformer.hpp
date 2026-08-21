#pragma once

#include "bytecode.hpp"

class Transformer
{
public:
    Transformer() = default;

    /*
     * Compile/protect the supplied Luau source.
     *
     * Returns the final protected representation.
     */
    Bytecode protect(
        const Bytecode& bytecode
    ) const;
};