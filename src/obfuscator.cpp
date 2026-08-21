#include "obfuscator.hpp"

#include <chrono>
#include <cstdint>
#include <random>
#include <utility>
#include <vector>

namespace
{
    constexpr std::uint32_t MAGIC =
        0x31564D4Cu; // "LVM1"

    constexpr std::uint8_t VERSION = 1;

    std::uint32_t generateSeed()
    {
        std::random_device rd;

        const std::uint32_t a =
            static_cast<std::uint32_t>(rd());

        const std::uint32_t b =
            static_cast<std::uint32_t>(rd());

        const auto now =
            std::chrono::high_resolution_clock::
                now()
                .time_since_epoch()
                .count();

        std::uint64_t timestamp =
            static_cast<std::uint64_t>(now);

        std::uint32_t seed =
            a ^
            (b * 0x9E3779B9u) ^
            static_cast<std::uint32_t>(timestamp) ^
            static_cast<std::uint32_t>(timestamp >> 32);

        if (seed == 0)
            seed = 0xA341316Cu;

        return seed;
    }

    void writeU32(
        std::vector<std::uint8_t>& output,
        std::uint32_t value
    )
    {
        output.push_back(
            static_cast<std::uint8_t>(
                value
            )
        );

        output.push_back(
            static_cast<std::uint8_t>(
                value >> 8
            )
        );

        output.push_back(
            static_cast<std::uint8_t>(
                value >> 16
            )
        );

        output.push_back(
            static_cast<std::uint8_t>(
                value >> 24
            )
        );
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

    /*
     * Format:
     *
     * 00-03  MAGIC
     * 04     VERSION
     * 05-08  SEED
     * 09-0C  ORIGINAL SIZE
     * 0D...  ENCRYPTED BYTECODE
     */

    std::vector<std::uint8_t> result;

    result.reserve(
        13 + source.size()
    );

    writeU32(
        result,
        MAGIC
    );

    result.push_back(
        VERSION
    );

    writeU32(
        result,
        seed_
    );

    if (
        source.size() >
        static_cast<std::size_t>(
            UINT32_MAX
        )
    )
    {
        return {};
    }

    writeU32(
        result,
        static_cast<std::uint32_t>(
            source.size()
        )
    );

    for (
        std::size_t i = 0;
        i < source.size();
        ++i
    )
    {
        const std::uint8_t encrypted =
            static_cast<std::uint8_t>(
                source[i] ^
                keyByte(
                    seed_,
                    i
                )
            );

        result.push_back(
            encrypted
        );
    }

    return Bytecode(
        std::move(result)
    );
}