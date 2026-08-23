#include "virtualizer.hpp"

#include <algorithm>
#include <array>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>

namespace Protect
{
    namespace
    {
        constexpr std::uint64_t MASK =
            0x9e3779b97f4a7c15ULL;

        constexpr std::uint32_t MAGIC =
            0x56584c50; // PLXV

        std::uint32_t rotl(
            std::uint32_t x,
            unsigned r
        )
        {
            r &= 31;

            if (r == 0)
                return x;

            return
                (x << r) |
                (x >> (32 - r));
        }

        std::uint32_t avalanche(
            std::uint32_t x
        )
        {
            x ^= x >> 16;
            x *= 0x7feb352dU;
            x ^= x >> 15;
            x *= 0x846ca68bU;
            x ^= x >> 16;

            return x;
        }
    }

    Virtualizer::Virtualizer(
        std::uint64_t seed
    )
        : seed_(seed)
    {
        if (seed_ == 0)
            seed_ = MASK;
    }

    std::uint32_t Virtualizer::readU32(
        const std::string& data,
        std::size_t& offset
    )
    {
        if (
            offset + 4 >
            data.size()
        )
        {
            throw std::runtime_error(
                "Truncated Luau bytecode"
            );
        }

        const auto* p =
            reinterpret_cast<
                const unsigned char*
            >(
                data.data() + offset
            );

        const std::uint32_t result =
            static_cast<std::uint32_t>(p[0]) |
            (static_cast<std::uint32_t>(p[1]) << 8) |
            (static_cast<std::uint32_t>(p[2]) << 16) |
            (static_cast<std::uint32_t>(p[3]) << 24);

        offset += 4;

        return result;
    }

    std::uint8_t Virtualizer::opcode(
        std::uint32_t instruction
    )
    {
        return static_cast<std::uint8_t>(
            instruction & 0xff
        );
    }

    std::uint8_t Virtualizer::A(
        std::uint32_t instruction
    )
    {
        return static_cast<std::uint8_t>(
            (instruction >> 8) & 0xff
        );
    }

    std::uint8_t Virtualizer::B(
        std::uint32_t instruction
    )
    {
        return static_cast<std::uint8_t>(
            (instruction >> 16) & 0xff
        );
    }

    std::uint8_t Virtualizer::C(
        std::uint32_t instruction
    )
    {
        return static_cast<std::uint8_t>(
            (instruction >> 24) & 0xff
        );
    }

    std::int16_t Virtualizer::D(
        std::uint32_t instruction
    )
    {
        return static_cast<std::int16_t>(
            (instruction >> 16) & 0xffff
        );
    }

    std::int32_t Virtualizer::E(
        std::uint32_t instruction
    )
    {
        std::uint32_t value =
            (instruction >> 8) & 0x00ffffff;

        if (value & 0x00800000)
            value |= 0xff000000;

        return static_cast<std::int32_t>(
            value
        );
    }

    std::uint64_t Virtualizer::nextKey(
        std::uint64_t value
    ) const
    {
        value +=
            0x9e3779b97f4a7c15ULL;

        value ^= value >> 30;
        value *= 0xbf58476d1ce4e5b9ULL;

        value ^= value >> 27;
        value *= 0x94d049bb133111ebULL;

        value ^= value >> 31;

        return value;
    }

    std::uint32_t Virtualizer::mix(
        std::uint32_t value,
        std::uint64_t key
    ) const
    {
        std::uint32_t k =
            static_cast<std::uint32_t>(
                key
            ) ^
            static_cast<std::uint32_t>(
                key >> 32
            );

        value ^= k;
        value = rotl(value, k & 31);
        value += 0x6d2b79f5U;

        return avalanche(value);
    }

    VirtualProgram Virtualizer::virtualize(
        const std::string& bytecode,
        const Options& options
    ) const
    {
        if (bytecode.empty())
        {
            throw std::runtime_error(
                "Empty Luau bytecode"
            );
        }

        VirtualProgram program;

        program.version = 1;
        program.key = seed_;

        /*
         * The first four bytes of serialized Luau bytecode
         * are the bytecode magic.
         *
         * Do not silently interpret an arbitrary string as
         * Luau bytecode.
         */
        if (bytecode.size() < 4)
        {
            throw std::runtime_error(
                "Invalid Luau bytecode"
            );
        }

        std::size_t offset = 0;

        const std::uint32_t magic =
            readU32(
                bytecode,
                offset
            );

        /*
         * Luau's serialized bytecode starts with
         * "\x1bLua" in the current format.
         */
        if (magic != 0x61754c1b)
        {
            throw std::runtime_error(
                "Input is not serialized Luau bytecode"
            );
        }

        /*
         * The complete serialized Luau format contains
         * proto metadata and multiple variable-size
         * sections. It must be decoded according to the
         * exact Luau checkout being used.
         *
         * We deliberately do not pretend that the rest of
         * the blob is a flat instruction array.
         */
        (void)offset;

        /*
         * This backend therefore refuses to generate a
         * corrupted pseudo-program until the exact Luau
         * bytecode version/parser is wired in.
         */
        if (options.encodeInstructions)
        {
            throw std::runtime_error(
                "Luau bytecode decoder must be bound to the "
                "exact third_party/luau bytecode version"
            );
        }

        return program;
    }

    std::string Virtualizer::emitLuau(
        const VirtualProgram& program
    ) const
    {
        std::ostringstream out;

        out <<
            "-- generated LuaProtecter runtime\n"
            "local __k=" <<
            program.key <<
            "\n";

        out <<
            "local function __mix(x,k)\n"
            "    x=x~k\n"
            "    x=((x<<((k%31)+1))|(x>>"
            "(32-((k%31)+1))))\n"
            "    return x\n"
            "end\n";

        out <<
            "local function __run(p)\n"
            "    local pc=1\n"
            "    while true do\n"
            "        local i=p[pc]\n"
            "        if not i then error('VM bounds') end\n"
            "        local op=i[1]\n"
            "        if op==0 then return end\n"
            "        pc=pc+1\n"
            "    end\n"
            "end\n";

        out <<
            "return __run({})\n";

        return out.str();
    }
}