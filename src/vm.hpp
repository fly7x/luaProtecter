#pragma once

#include "bytecode.hpp"

#include <string>

class VM
{
public:
    VM() = default;

    bool execute(
        const Bytecode& bytecode,
        std::string& output
    ) const;
};