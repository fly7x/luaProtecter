#include "transformer.hpp"

#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace
{
    constexpr std::uint32_t MAGIC = 0x4C50524Fu; // "LPRO"
    constexpr std::uint8_t VERSION = 1;

    std::uint32_t random32()
    {
        static std::random_device rd;

        std::uint32_t a =
            static_cast<std::uint32_t>(rd());

        std::uint32_t b =
            static_cast<std::uint32_t>(rd());

        std::uint32_t value =
            a ^ (b * 0x9E3779B9u);

        if (value == 0)
            value = 0xA341316Cu;

        return value;
    }

    std::uint8_t randomKey()
    {
        std::uint8_t key =
            static_cast<std::uint8_t>(
                random32() & 0xFFu
            );

        if (key == 0)
            key = 0xA7;

        return key;
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
        const std::string& data
    )
    {
        std::uint32_t hash =
            2166136261u;

        for (unsigned char c : data)
        {
            hash ^= c;
            hash *= 16777619u;
        }

        return hash;
    }

    std::vector<std::uint8_t> protectBytecode(
        const std::string& bytecode
    )
    {
        std::vector<std::uint8_t> result;

        const std::uint8_t key =
            randomKey();

        const std::uint32_t seed =
            random32();

        const std::uint32_t checksum =
            hashBytes(bytecode);

        /*
         * Header
         *
         * [magic]
         * [version]
         * [key]
         * [reserved]
         * [seed]
         * [size]
         * [checksum]
         */

        writeU32(
            result,
            MAGIC
        );

        result.push_back(
            VERSION
        );

        result.push_back(
            key
        );

        result.push_back(0);
        result.push_back(0);

        writeU32(
            result,
            seed
        );

        writeU32(
            result,
            static_cast<std::uint32_t>(
                bytecode.size()
            )
        );

        writeU32(
            result,
            checksum
        );

        /*
         * Protect the bytecode payload.
         *
         * This is deliberately a packaging layer,
         * not a replacement Luau interpreter.
         */

        for (
            std::size_t i = 0;
            i < bytecode.size();
            ++i
        )
        {
            const std::uint8_t original =
                static_cast<std::uint8_t>(
                    static_cast<unsigned char>(
                        bytecode[i]
                    )
                );

            const std::uint8_t mix =
                static_cast<std::uint8_t>(
                    (
                        seed ^
                        static_cast<std::uint32_t>(
                            i * 37u
                        ) ^
                        static_cast<std::uint32_t>(
                            i >> 3
                        )
                    ) & 0xFFu
                );

            const std::uint8_t encoded =
                static_cast<std::uint8_t>(
                    original ^ key ^ mix
                );

            result.push_back(
                encoded
            );
        }

        return result;
    }
}

std::string Transformer::transform(
    const std::string& source
)
{
    /*
     * This function expects the caller to have already
     * compiled source with Luau::compile().
     *
     * The input here is therefore Luau bytecode,
     * not Lua source text.
     */

    if (source.empty())
        return {};

    const std::vector<std::uint8_t> protectedData =
        protectBytecode(source);

    return std::string(
        reinterpret_cast<const char*>(
            protectedData.data()
        ),
        protectedData.size()
    );
}