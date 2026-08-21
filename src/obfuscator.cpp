#include "obfuscator.hpp"

#include <chrono>
#include <cstdint>
#include <random>
#include <vector>

namespace
{
    std::uint32_t generateSeed()
    {
        std::random_device device;

        const std::uint32_t a =
            static_cast<std::uint32_t>(
                device()
            );

        const std::uint32_t b =
            static_cast<std::uint32_t>(
                device()
            );

        const std::uint64_t timestamp =
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
                timestamp
            ) ^
            static_cast<std::uint32_t>(
                timestamp >> 32
            );

        if (seed == 0)
            seed = 0xA341316Cu;

        return seed;
    }
}

Obfuscator::Obfuscator()
    : seed_(generateSeed())
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

std::uint8_t Obfuscator::keyByte(
    std::uint32_t seed,
    std::size_t position
)
{
    const std::uint32_t index =
        static_cast<std::uint32_t>(
            position
        );

    std::uint32_t state =
        seed ^
        (index * 0x9E3779B9u);

    state = mix32(state);

    return static_cast<std::uint8_t>(
        state & 0xFFu
    );
}

Bytecode Obfuscator::transform(
    const Bytecode& input
) const
{
    if (input.empty())
        return {};

    const std::vector<std::uint8_t>& source =
        input.data();

    std::vector<std::uint8_t> result;

    result.resize(
        source.size()
    );

    for (
        std::size_t i = 0;
        i < source.size();
        ++i
    )
    {
        result[i] =
            static_cast<std::uint8_t>(
                source[i] ^
                keyByte(
                    seed_,
                    i
                )
            );
    }

    return Bytecode(
        std::move(result)
    );
}