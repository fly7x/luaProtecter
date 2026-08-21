#include "vm.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>

namespace
{
    /*
     * FNV-1a 32-bit hash.
     *
     * This is only used as a lightweight integrity identifier.
     * It is NOT intended to be cryptographic protection.
     */
    std::uint32_t hashBytes(
        const std::vector<std::uint8_t>& bytes
    )
    {
        std::uint32_t hash = 2166136261u;

        for (std::uint8_t byte : bytes)
        {
            hash ^= byte;
            hash *= 16777619u;
        }

        return hash;
    }

    std::string hex32(
        std::uint32_t value
    )
    {
        static constexpr char hex[] =
            "0123456789abcdef";

        std::string result(8, '0');

        for (int i = 7; i >= 0; --i)
        {
            result[
                static_cast<std::size_t>(i)
            ] = hex[value & 0x0Fu];

            value >>= 4;
        }

        return result;
    }
}

bool VM::validate(
    const Bytecode& bytecode,
    std::string& error
) const
{
    error.clear();

    if (bytecode.empty())
    {
        error =
            "Empty Luau bytecode.";

        return false;
    }

    if (bytecode.size() < 4)
    {
        error =
            "Luau bytecode is too small.";

        return false;
    }

    /*
     * At this stage validation deliberately remains conservative.
     *
     * The Luau compiler is responsible for producing valid
     * bytecode. We do not reinterpret or modify its instruction
     * stream here.
     */
    return true;
}

std::string VM::package(
    const Bytecode& bytecode
) const
{
    std::string error;

    if (!validate(bytecode, error))
        throw std::runtime_error(error);

    /*
     * Return the binary-safe Base64 representation.
     *
     * This is a transport/package representation, NOT a second
     * interpreter and NOT a conversion back into source code.
     */
    return bytecode.toBase64();
}