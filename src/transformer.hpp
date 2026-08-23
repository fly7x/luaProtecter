#pragma once

#include <string>

class Transformer
{
public:
    Transformer() = default;

    /*
     * Transform Luau source into valid, obfuscated Luau source.
     *
     * The returned value is SOURCE CODE, not binary bytecode.
     */
    std::string protect(
        const std::string& source
    ) const;
};