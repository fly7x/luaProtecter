#pragma once

#include "bytecode.hpp"

class Transformer
{
public:
    Transformer() = default;

    /*
     * Protect custom VM bytecode.
     *
     * Input:
     *     LVM1 custom bytecode
     *
     * Output:
     *     LPRO protected package
     */
    Bytecode protect(
        const Bytecode& bytecode
    );
};