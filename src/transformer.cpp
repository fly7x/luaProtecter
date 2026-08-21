#include "transformer.hpp"

#include <cstdint>
#include <limits>
#include <random>
#include <string>
#include <vector>

namespace
{
    /*
     * ---------------------------------------------------------
     * Protected package format
     * ---------------------------------------------------------
     *
     * Offset:
     *
     * 0x00  4 bytes   MAGIC
     * 0x04  1 byte    VERSION
     * 0x05  1 byte    XOR KEY
     * 0x06  2 bytes   RESERVED
     * 0x08  4 bytes   SEED
     * 0x0C  4 bytes   ORIGINAL BYTECODE SIZE
     * 0x10  4 bytes   BYTECODE HASH
     * 0x14  N bytes   protected LVM1 bytecode
     *
     * All integer fields are little-endian.
     */

    constexpr std::uint32_t MAGIC =
        0x4C50524Fu; // LPRO

    constexpr std::uint8_t VERSION =
        1;

    constexpr std::size_t HEADER_SIZE =
        20;

    /*
     * ---------------------------------------------------------
     * Random
     * ---------------------------------------------------------
     */

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

    /*
     * ---------------------------------------------------------
     * Binary helpers
     * ---------------------------------------------------------
     */

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

    /*
     * ---------------------------------------------------------
     * Integrity hash
     * ---------------------------------------------------------
     *
     * FNV-1a 32-bit.
     */

    std::uint32_t hashBytes(
        const std::vector<std::uint8_t>& bytes
    )
    {
        std::uint32_t hash =
            2166136261u;

        for (
            const std::uint8_t value :
            bytes
        )
        {
            hash ^= value;
            hash *= 16777619u;
        }

        return hash;
    }

    /*
     * ---------------------------------------------------------
     * Protect custom bytecode
     * ---------------------------------------------------------
     */

    Bytecode protectBytecode(
        const Bytecode& bytecode
    )
    {
        const std::vector<std::uint8_t>& input =
            bytecode.data();

        if (input.empty())
            return Bytecode{};

        /*
         * The package stores the original size
         * in a uint32.
         */
        if (
            input.size() >
            static_cast<std::size_t>(
                std::numeric_limits<
                    std::uint32_t
                >::max()
            )
        )
        {
            return Bytecode{};
        }

        /*
         * Generate a different key for every package.
         */
        const std::uint8_t key =
            static_cast<std::uint8_t>(
                random32() & 0xFFu
            );

        /*
         * Generate a different mixing seed for every package.
         */
        const std::uint32_t seed =
            random32();

        std::vector<std::uint8_t> result;

        result.reserve(
            HEADER_SIZE +
            input.size()
        );

        /*
         * -----------------------------------------------------
         * Header
         * -----------------------------------------------------
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

        /*
         * Reserved.
         */
        result.push_back(0);
        result.push_back(0);

        /*
         * Seed.
         */
        writeU32(
            result,
            seed
        );

        /*
         * Original custom bytecode size.
         */
        writeU32(
            result,
            static_cast<std::uint32_t>(
                input.size()
            )
        );

        /*
         * Hash of the original LVM1 bytecode.
         */
        writeU32(
            result,
            hashBytes(input)
        );

        /*
         * -----------------------------------------------------
         * Protected payload
         * -----------------------------------------------------
         *
         * Each byte is mixed using:
         *
         *     byte ^ key ^ positionMix
         *
         * The position-dependent component prevents the
         * payload from being a simple repeated XOR stream.
         */

        for (
            std::size_t i = 0;
            i < input.size();
            ++i
        )
        {
            const std::uint8_t value =
                input[i];

            const std::uint32_t position =
                static_cast<std::uint32_t>(
                    i
                );

            const std::uint8_t mix =
                static_cast<std::uint8_t>(
                    (
                        seed ^
                        (
                            position *
                            37u
                        ) ^
                        (
                            position >>
                            3
                        )
                    ) & 0xFFu
                );

            const std::uint8_t protectedValue =
                static_cast<std::uint8_t>(
                    value ^
                    key ^
                    mix
                );

            result.push_back(
                protectedValue
            );
        }

        return Bytecode(
            std::move(result)
        );
    }
}

/*
 * -------------------------------------------------------------
 * Transformer
 * -------------------------------------------------------------
 */

Bytecode Transformer::protect(
    const Bytecode& bytecode
)
{
    if (bytecode.empty())
        return Bytecode{};

    return protectBytecode(
        bytecode
    );
}