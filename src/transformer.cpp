#include "transformer.hpp"

#include <cstdint>
#include <limits>
#include <random>
#include <stdexcept>
#include <vector>

namespace
{
    constexpr std::uint32_t MAGIC =
        0x4C50524Fu; // LPRO

    constexpr std::uint8_t VERSION = 1;

    constexpr std::size_t HEADER_SIZE = 20;

    std::uint32_t random32()
    {
        static std::random_device rd;

        const std::uint32_t a =
            static_cast<std::uint32_t>(rd());

        const std::uint32_t b =
            static_cast<std::uint32_t>(rd());

        std::uint32_t value =
            a ^
            (b * 0x9E3779B9u);

        if (value == 0)
            value = 0xA341316Cu;

        return value;
    }

    void writeU32(
        std::vector<std::uint8_t>& out,
        std::uint32_t value
    )
    {
        out.push_back(
            static_cast<std::uint8_t>(
                value & 0xFFu
            )
        );

        out.push_back(
            static_cast<std::uint8_t>(
                (value >> 8) & 0xFFu
            )
        );

        out.push_back(
            static_cast<std::uint8_t>(
                (value >> 16) & 0xFFu
            )
        );

        out.push_back(
            static_cast<std::uint8_t>(
                (value >> 24) & 0xFFu
            )
        );
    }

    std::uint32_t hashBytes(
        const std::vector<std::uint8_t>& data
    )
    {
        std::uint32_t hash =
            2166136261u;

        for (std::uint8_t value : data)
        {
            hash ^= value;
            hash *= 16777619u;
        }

        return hash;
    }
}

Bytecode Transformer::protect(
    const Bytecode& bytecode
) const
{
    const auto& input =
        bytecode.data();

    if (input.empty())
    {
        throw std::runtime_error(
            "Cannot protect empty bytecode"
        );
    }

    if (
        input.size() >
        std::numeric_limits<std::uint32_t>::max()
    )
    {
        throw std::runtime_error(
            "Bytecode is too large"
        );
    }

    const std::uint8_t key =
        static_cast<std::uint8_t>(
            random32() & 0xFFu
        );

    const std::uint32_t seed =
        random32();

    std::vector<std::uint8_t> output;

    output.reserve(
        HEADER_SIZE + input.size()
    );

    /*
     * Header:
     *
     * 4  bytes MAGIC
     * 1  byte  VERSION
     * 1  byte  KEY
     * 2  bytes RESERVED
     * 4  bytes SEED
     * 4  bytes SIZE
     * 4  bytes HASH
     */

    writeU32(
        output,
        MAGIC
    );

    output.push_back(
        VERSION
    );

    output.push_back(
        key
    );

    output.push_back(0);
    output.push_back(0);

    writeU32(
        output,
        seed
    );

    writeU32(
        output,
        static_cast<std::uint32_t>(
            input.size()
        )
    );

    writeU32(
        output,
        hashBytes(input)
    );

    /*
     * Protected Luau bytecode.
     */
    for (
        std::size_t i = 0;
        i < input.size();
        ++i
    )
    {
        const std::uint32_t position =
            static_cast<std::uint32_t>(i);

        const std::uint8_t mix =
            static_cast<std::uint8_t>(
                (
                    seed ^
                    (position * 37u) ^
                    (position >> 3)
                ) & 0xFFu
            );

        output.push_back(
            static_cast<std::uint8_t>(
                input[i] ^
                key ^
                mix
            )
        );
    }

    return Bytecode(
        std::move(output)
    );
}