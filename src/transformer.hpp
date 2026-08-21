#pragma once

#include <string>

class Transformer
{
public:
    Transformer() = default;

    // Takes valid Luau source and returns valid,
    // source-level-obfuscated Luau.
    std::string transform(
        const std::string& source
    );
};