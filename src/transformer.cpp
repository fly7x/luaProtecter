#include "transformer.hpp"

#include <cstdint>
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
     * 0x14  N bytes   protected bytecode
     *
     * All integer fields are little-endian.
     */

    constexpr std::uint32_t MAGIC =
        0x4C50524Fu; // "LPRO"

    constexpr std::uint8_t VERSION =
        1;

    constexpr std::size_t HEADER_SIZE =
        20;

    // ---------------------------------------------------------
    // Random values
    // ---------------------------------------------------------

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

    // ---------------------------------------------------------
    // Binary helpers
    // ---------------------------------------------------------

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

    // ---------------------------------------------------------
    // Hash
    // ---------------------------------------------------------

    std::uint32_t hashBytes(
        const std::string& data
    )
    {
        /*
         * FNV-1a 32-bit.
         *
         * This is used for package integrity checking.
         */
        std::uint32_t hash =
            2166136261u;

        for (unsigned char value : data)
        {
            hash ^= value;
            hash *= 16777619u;
        }

        return hash;
    }

    // ---------------------------------------------------------
    // Protected bytecode
    // ---------------------------------------------------------

    std::string protectBytecode(
        const std::string& bytecode
    )
    {
        if (bytecode.empty())
            return {};

        /*
         * Random per-package key.
         */
        const std::uint8_t key =
            static_cast<std::uint8_t>(
                random32() & 0xFFu
            );

        /*
         * Random per-package seed.
         */
        const std::uint32_t seed =
            random32();

        /*
         * Prevent integer overflow from silently producing
         * an invalid package size.
         */
        if (
            bytecode.size() >
            static_cast<std::size_t>(
                UINT32_MAX
            )
        )
        {
            return {};
        }

        std::vector<std::uint8_t> result;

        result.reserve(
            HEADER_SIZE +
            bytecode.size()
        );

        // -----------------------------------------------------
        // Header
        // -----------------------------------------------------

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
         * Reserved bytes.
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
         * Original bytecode size.
         */
        writeU32(
            result,
            static_cast<std::uint32_t>(
                bytecode.size()
            )
        );

        /*
         * Integrity hash of the original Luau bytecode.
         */
        writeU32(
            result,
            hashBytes(bytecode)
        );

        // -----------------------------------------------------
        // Protected payload
        // -----------------------------------------------------

        for (
            std::size_t i = 0;
            i < bytecode.size();
            ++i
        )
        {
            const std::uint8_t value =
                static_cast<std::uint8_t>(
                    static_cast<unsigned char>(
                        bytecode[i]
                    )
                );

            /*
             * Position-dependent mixing.
             *
             * The same key/seed is required to recover the
             * original bytecode.
             */
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

        return std::string(
            reinterpret_cast<const char*>(
                result.data()
            ),
            result.size()
        );
    }
}

// -------------------------------------------------------------
// Transformer
// -------------------------------------------------------------

std::string Transformer::protect(
    const std::string& bytecode
)
{
    if (bytecode.empty())
        return {};

    return protectBytecode(
        bytecode
    );
}