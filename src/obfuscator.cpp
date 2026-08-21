#include "obfuscator.hpp"

#include <chrono>
#include <cstdint>
#include <random>

namespace
{
    std::uint32_t generateSeed()
    {
        std::random_device rd;

        const std::uint32_t a =
            static_cast<std::uint32_t>(
                rd()
            );

        const std::uint32_t b =
            static_cast<std::uint32_t>(
                rd()
            );

        const auto now =
            static_cast<std::uint64_t>(
                std::chrono::high_resolution_clock::
                    now()
                    .time_since_epoch()
                    .count()
            );

        std::uint32_t seed =
            a ^
            (b * 0x9E3779B9u) ^
            static_cast<std::uint32_t>(
                now
            ) ^
            static_cast<std::uint32_t>(
                now >> 32
            );

        if (seed == 0)
            seed = 0xA341316Cu;

        return seed;
    }
}

Obfuscator::Obfuscator()
    : seed_(
        generateSeed()
    )
{
}

std::uint32_t Obfuscator::mix32(
    std::uint32_t value
)
{
    value ^= value >> 16;
    value *= 0x7FEB352Du;
    value ^= value >> 15;
    value *= 0x846CA68Bu;
    value ^= value >> 16;

    return value;
}

std::uint8_t Obfuscator::transformByte(
    std::uint8_t value,
    std::size_t index,
    std::uint32_t seed
)
{
    /*
     * Generate a deterministic keystream byte from:
     *
     *   package seed
     *   byte position
     *
     * This is reversible by applying the same operation
     * again.
     */
    const std::uint32_t position =
        static_cast<std::uint32_t>(
            index
        );

    std::uint32_t state =
        seed ^
        (position * 0x9E3779B9u);

    state =
        mix32(state);

    const std::uint8_t key =
        static_cast<std::uint8_t>(
            state & 0xFFu
        );

    return static_cast<std::uint8_t>(
        value ^ key
    );
}

Bytecode Obfuscator::transform(
    const Bytecode& input
) const
{
    if (input.empty())
        return {};

    const auto& source =
        input.data();

    std::vector<std::uint8_t> result;

    result.resize(
        source.size()
    );

    /*
     * XOR is deliberately applied twice:
     *
     * transform(transform(bytecode)) == bytecode
     *
     * This makes the transformation reversible.
     *
     * The important point is that this layer does not
     * pretend to be a complete VM or compiler.
     */
    for (
        std::size_t i = 0;
        i < source.size();
        ++i
    )
    {
        result[i] =
            transformByte(
                source[i],
                i,
                seed_
            );
    }

    /*
     * Preserve the existing Bytecode abstraction.
     *
     * No textual Lua is generated here.
     */
    return Bytecode(
        std::move(result)
    );
}