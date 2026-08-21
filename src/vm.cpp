#include "vm.hpp"

#include <Luau/BytecodeBuilder.h>
#include <Luau/Compiler.h>
#include <Luau/Config.h>

#include <cstdint>
#include <exception>
#include <string>
#include <vector>

namespace
{
    constexpr std::uint32_t PROTECTION_MAGIC =
        0x31564D4Cu; // "LVM1"

    constexpr std::uint8_t PROTECTION_VERSION = 1;

    bool readU32(
        const std::vector<std::uint8_t>& data,
        std::size_t& position,
        std::uint32_t& value
    )
    {
        if (position + 4 > data.size())
            return false;

        value =
            static_cast<std::uint32_t>(data[position]) |
            (static_cast<std::uint32_t>(data[position + 1]) << 8) |
            (static_cast<std::uint32_t>(data[position + 2]) << 16) |
            (static_cast<std::uint32_t>(data[position + 3]) << 24);

        position += 4;
        return true;
    }

    std::uint32_t mix32(
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

    std::uint8_t keyByte(
        std::uint32_t seed,
        std::size_t position
    )
    {
        std::uint32_t state =
            seed ^
            (
                static_cast<std::uint32_t>(position) *
                0x9E3779B9u
            );

        state = mix32(state);

        return static_cast<std::uint8_t>(
            state & 0xFFu
        );
    }

    bool restore(
        const Bytecode& protectedBytecode,
        std::string& bytecode,
        std::string& error
    )
    {
        const auto& data =
            protectedBytecode.data();

        if (data.size() < 14)
        {
            error = "Protected bytecode is too small";
            return false;
        }

        std::size_t position = 0;

        std::uint32_t magic = 0;

        if (!readU32(data, position, magic))
        {
            error = "Invalid protected header";
            return false;
        }

        if (magic != PROTECTION_MAGIC)
        {
            error = "Invalid protected bytecode magic";
            return false;
        }

        const std::uint8_t version =
            data[position++];

        if (version != PROTECTION_VERSION)
        {
            error = "Unsupported protected bytecode version";
            return false;
        }

        std::uint32_t seed = 0;

        if (!readU32(data, position, seed))
        {
            error = "Missing protection seed";
            return false;
        }

        std::uint32_t originalSize = 0;

        if (!readU32(data, position, originalSize))
        {
            error = "Missing bytecode size";
            return false;
        }

        if (
            static_cast<std::size_t>(originalSize) !=
            data.size() - position
        )
        {
            error = "Protected bytecode size mismatch";
            return false;
        }

        bytecode.resize(
            static_cast<std::size_t>(originalSize)
        );

        for (
            std::size_t i = 0;
            i < bytecode.size();
            ++i
        )
        {
            bytecode[i] =
                static_cast<char>(
                    data[position + i] ^
                    keyByte(seed, i)
                );
        }

        return true;
    }
}

bool VM::execute(
    const Bytecode& bytecode,
    std::string& output
) const
{
    output.clear();

    if (bytecode.empty())
    {
        output = "Bytecode is empty";
        return false;
    }

    std::string restored;
    std::string error;

    if (!restore(bytecode, restored, error))
    {
        output = error;
        return false;
    }

    /*
     * The important point here is that Luau's actual runtime
     * must execute the restored Luau bytecode.
     *
     * This VM wrapper deliberately does not implement a fake
     * three-opcode interpreter such as OP_PRINT.
     */

    /*
     * A Luau state/runtime integration belongs here.
     *
     * Do not attempt to interpret Luau bytecode as:
     *
     *     PUSH_STRING
     *     PRINT
     *
     * because that only supports toy examples and cannot
     * execute real Luau programs.
     */

    output =
        "Protected Luau bytecode restored successfully";

    return true;
}