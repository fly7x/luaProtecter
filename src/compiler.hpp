#pragma once

#include "bytecode.hpp"

#include <string>

class Compiler
{
public:
    Compiler() = default;

    Bytecode compile(
        const std::string& source
    ) const;
};