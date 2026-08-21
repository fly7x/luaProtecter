#include "transformer.hpp"

#include <cstdint>
#include <random>
#include <string>
#include <vector>

namespace
{
    constexpr std::uint32_t MAGIC = 0x4C50524Fu; // LPRO
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

    void writeU32(
        std::vector<std::uint8_t>& out,
        std::uint32_t value
    )
    {
        out.push_back(
            static_cast<std::uint8_t>(value)
        );

        out.push_back(
            static_cast<std::uint8_t>(value >> 8)
        );

        out.push_back(
            static_cast<std::uint8_t>(value >> 16)
        );

        out.push_back(
            static_cast<std::uint8_t>(value >> 24)
        );
    }

    std::uint32_t hashBytes(
        const std::string& data
    )
    {
        std::uint32_t hash = 2166136261u;

        for (unsigned char c : data)
        {
            hash ^= c;
            hash *= 16777619u;
        }

        return hash;
    }

    std::string protectBytecode(
        const std::string& bytecode
    )
    {
        const std::uint8_t key =
            static_cast<std::uint8_t>(
                random32() & 0xFFu
            );

        const std::uint32_t seed =
            random32();

        std::vector<std::uint8_t> result;

        writeU32(result, MAGIC);

        result.push_back(VERSION);
        result.push_back(key);
        result.push_back(0);
        result.push_back(0);

        writeU32(result, seed);

        writeU32(
            result,
            static_cast<std::uint32_t>(
                bytecode.size()
            )
        );

        writeU32(
            result,
            hashBytes(bytecode)
        );

        for (std::size_t i = 0; i < bytecode.size(); ++i)
        {
            const std::uint8_t value =
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

            result.push_back(
                static_cast<std::uint8_t>(
                    value ^ key ^ mix
                )
            );
        }

        return std::string(
            reinterpret_cast<const char*>(
                result.data()
            ),
            result.size()
        );
    }
}

std::string Transformer::protect(
    const std::string& bytecode
)
{
    if (bytecode.empty())
        return {};

    return protectBytecode(bytecode);
}