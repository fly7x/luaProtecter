#pragma once

#include "bytecode.hpp"

#include <string>

class VM
{
public:
    VM() = default;

    /*
     * Execute custom LVM bytecode.
     *
     * output receives everything printed by the VM.
     *
     * Returns true on success.
     * Returns false on invalid bytecode/runtime failure.
     */
    bool execute(
        const Bytecode& bytecode,
        std::string& output
    ) const;
};