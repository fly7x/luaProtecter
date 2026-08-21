#pragma once

#include <string>

class Transformer
{
public:
    Transformer() = default;

    /*
     * Validate/transform Luau source and return
     * valid Luau source.
     */
    std::string protect(
        const std::string& source
    ) const;
};