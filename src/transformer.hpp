#pragma once

#include <string>

class Transformer
{
public:
    Transformer() = default;

    /*
     * Takes REAL Luau bytecode and packages it for
     * the custom VM/protection layer.
     *
     * Input:
     *     Luau bytecode
     *
     * Output:
     *     Protected custom VM package
     */
    std::string protect(
        const std::string& bytecode
    );
};