#include "transformer.hpp"

#include <cstdint>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    constexpr std::uint32_t MAGIC =
        0x4C50524Fu; // LPRO

    constexpr std::uint8_t VERSION =
        1;

    constexpr std::size_t HEADER_SIZE =
        20;

    std::uint32_t random32()
    {
        static std::random_device device;

        const std::uint32_t a =
            static_cast<std::uint32_t>(
                device()
            );

        const std::uint32_t b =
            static_cast<std::uint32_t>(
                device()
            );

        std::uint32_t value =
            a ^
            (
                b *
                0x9E3779B9u
            );

        if (value == 0)
            value = 0xA341316Cu;

        return value;
    }

    void writeU32(
        std::vector<std::uint8_t>& output,
        std::uint32_t value
    )
    {
        output.push_back(
            static_cast<std::uint8_t>(
                value & 0xFFu
            )
        );

        output.push_back(
            static_cast<std::uint8_t>(
                (value >> 8) & 0xFFu
            )
        );

        output.push_back(
            static_cast<std::uint8_t>(
                (value >> 16) & 0xFFu
            )
        );

        output.push_back(
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
    if (bytecode.empty())
        return {};

    const auto& input =
        bytecode.data();

    if (
        input.size() >
        static_cast<std::size_t>(
            UINT32_MAX
        )
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
        HEADER_SIZE +
        input.size()
    );

    /*
     * Header
     *
     * 00: MAGIC
     * 04: VERSION
     * 05: KEY
     * 06: RESERVED
     * 08: SEED
     * 0C: ORIGINAL SIZE
     * 10: HASH
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
     * Protected payload.
     */
    for (
        std::size_t i = 0;
        i < input.size();
        ++i
    )
    {
        const std::uint32_t position =
            static_cast<std::uint32_t>(
                i
            );

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