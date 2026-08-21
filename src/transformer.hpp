#pragma once

#include <string>

class Transformer
{
public:
    Transformer() = default;

    // Takes compiled Luau bytecode and returns the protected package.
    std::string protect(
        const std::string& bytecode
    );
};