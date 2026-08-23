#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace Protected
{
    enum class ConstantType : std::uint8_t
    {
        Nil = 0,
        Boolean,
        Number,
        String,
        Integer,
        Vector,
        Unknown
    };

    struct Constant
    {
        ConstantType type = ConstantType::Unknown;

        bool booleanValue = false;
        double numberValue = 0.0;
        std::int64_t integerValue = 0;

        std::string stringValue;

        float vectorX = 0.0f;
        float vectorY = 0.0f;
        float vectorZ = 0.0f;
        float vectorW = 0.0f;
    };

    struct Instruction
    {
        std::uint8_t opcode = 0;

        std::uint8_t A = 0;
        std::uint8_t B = 0;
        std::uint8_t C = 0;

        std::int16_t D = 0;
        std::int32_t E = 0;

        bool hasAux = false;
        std::uint32_t AUX = 0;

        std::size_t wordOffset = 0;
    };

    struct Function
    {
        std::uint32_t id = 0;

        std::uint8_t maxStackSize = 0;
        std::uint8_t numParams = 0;

        bool isVararg = false;

        std::vector<Constant> constants;
        std::vector<Instruction> instructions;

        std::vector<Function> children;
    };

    struct Program
    {
        std::uint8_t bytecodeVersion = 0;
        std::uint8_t typesVersion = 0;

        Function main;

        std::vector<std::uint8_t> original;
    };
}

class Bytecode
{
public:
    Bytecode() = default;

    bool parse(
        const std::vector<std::uint8_t>& data,
        Protected::Program& program,
        std::string& error
    ) const;

private:
    static bool readU8(
        const std::vector<std::uint8_t>& data,
        std::size_t& position,
        std::uint8_t& value
    );

    static bool readU32(
        const std::vector<std::uint8_t>& data,
        std::size_t& position,
        std::uint32_t& value
    );

    static bool readU64(
        const std::vector<std::uint8_t>& data,
        std::size_t& position,
        std::uint64_t& value
    );

    static bool readString(
        const std::vector<std::uint8_t>& data,
        std::size_t& position,
        std::string& value
    );

    static bool readInstruction(
        const std::vector<std::uint8_t>& data,
        std::size_t& position,
        Protected::Instruction& instruction,
        std::string& error
    );

    static std::string constantTypeName(
        std::uint8_t type
    );
};