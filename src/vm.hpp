#pragma once

#include "bytecode.hpp"

#include <string>

class VM
{
public:
    VM() = default;
    ~VM() = default;

    VM(const VM&) = delete;
    VM& operator=(const VM&) = delete;

    VM(VM&&) = default;
    VM& operator=(VM&&) = default;

    /*
     * Executes REAL Luau bytecode using the Luau VM
     * provided by third_party/luau.
     *
     * Returns:
     *   true  = execution succeeded
     *   false = load/runtime failure
     *
     * output contains the error when false.
     */
    bool execute(
        const Bytecode& bytecode,
        std::string& output
    ) const;
};