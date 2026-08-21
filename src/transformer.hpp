#pragma once

#include "bytecode.hpp"

#include <cstdint>
#include <string>

class Transformer
{
public:
    Transformer() = default;

    /*
     * Protect compiled Luau bytecode.
     *
     * This does NOT change the Luau instruction semantics.
     * It creates a package containing protected bytecode.
     */
    Bytecode protect(
        const Bytecode& bytecode
    ) const;
};