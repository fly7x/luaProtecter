#pragma once

#include "bytecode.hpp"

#include <cstdint>
#include <vector>

class Obfuscator
{
public:

    Obfuscator();

    /*
     * Transform Luau bytecode while preserving the
     * bytecode's original semantics.
     *
     * This layer intentionally operates on bytes instead
     * of trying to reimplement the Luau compiler.
     */
    Bytecode transform(
        const Bytecode& input
    ) const;

private:

    std::uint32_t seed_;

    static std::uint32_t mix32(
        std::uint32_t value
    );

    static std::uint8_t transformByte(
        std::uint8_t value,
        std::size_t index,
        std::uint32_t seed
    );
};