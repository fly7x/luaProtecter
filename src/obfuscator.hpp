#pragma once

#include "bytecode.hpp"

#include <cstdint>

class Obfuscator
{
public:
    Obfuscator();

    Bytecode transform(
        const Bytecode& input
    ) const;

private:
    std::uint32_t seed_;

    static std::uint32_t mix32(
        std::uint32_t value
    );

    static std::uint8_t keyByte(
        std::uint32_t seed,
        std::size_t position
    );
};