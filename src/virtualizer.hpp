#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Protect
{
    struct VirtualInstruction
    {
        std::uint8_t opcode = 0;
        std::uint8_t a = 0;
        std::uint8_t b = 0;
        std::uint8_t c = 0;
        std::int32_t d = 0;
        std::int32_t e = 0;
        std::uint32_t aux = 0;
        bool hasAux = false;
    };

    struct VirtualProgram
    {
        std::uint32_t version = 1;
        std::uint64_t key = 0;

        std::vector<VirtualInstruction> instructions;
        std::vector<std::string> strings;
        std::vector<double> numbers;
    };

    class Virtualizer
    {
    public:
        struct Options
        {
            bool encryptConstants = true;
            bool shuffleOpcodes = true;
            bool remapRegisters = true;
            bool encodeInstructions = true;
            bool polymorphic = true;
        };

        explicit Virtualizer(
            std::uint64_t seed
        );

        VirtualProgram virtualize(
            const std::string& luauBytecode,
            const Options& options
        ) const;

        std::string emitLuau(
            const VirtualProgram& program
        ) const;

    private:
        std::uint64_t seed_;

        static std::uint32_t readU32(
            const std::string& data,
            std::size_t& offset
        );

        static std::uint8_t opcode(
            std::uint32_t instruction
        );

        static std::uint8_t A(
            std::uint32_t instruction
        );

        static std::uint8_t B(
            std::uint32_t instruction
        );

        static std::uint8_t C(
            std::uint32_t instruction
        );

        static std::int16_t D(
            std::uint32_t instruction
        );

        static std::int32_t E(
            std::uint32_t instruction
        );

        std::uint64_t nextKey(
            std::uint64_t value
        ) const;

        std::uint32_t mix(
            std::uint32_t value,
            std::uint64_t key
        ) const;
    };
}