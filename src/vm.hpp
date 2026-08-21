#pragma once

#include "bytecode.hpp"

#include <string>

class VM
{
public:
    VM() = default;

    /*
     * Validate that the supplied payload is structurally valid
     * Luau bytecode produced by the compiler pipeline.
     *
     * This VM does not interpret arbitrary source text.
     */
    bool validate(
        const Bytecode& bytecode,
        std::string& error
    ) const;

    /*
     * Return the protected representation used by the
     * application transport layer.
     */
    std::string package(
        const Bytecode& bytecode
    ) const;
};