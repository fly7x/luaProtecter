#pragma once

#include "bytecode.hpp"

class Transformer
{
public:
    Transformer() = default;

    Bytecode protect(
        const Bytecode& bytecode
    ) const;
};