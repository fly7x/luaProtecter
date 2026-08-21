#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace LuaProtecter
{
    /*
     * Internal VM bytecode representation.
     *
     * The bytecode is deliberately kept independent from Luau's
     * native bytecode format. The transformer produces this format,
     * while vm.cpp consumes it.
     */

    using Word = std::uint32_t;
    using Index = std::uint32_t;

    enum class OpCode : std::uint8_t
    {
        Nop = 0,

        /*
         * Constants / registers
         */
        LoadNil,
        LoadBool,
        LoadNumber,
        LoadString,
        Move,

        /*
         * Globals / tables
         */
        GetGlobal,
        SetGlobal,
        GetTable,
        SetTable,

        /*
         * Arithmetic
         */
        Add,
        Sub,
        Mul,
        Div,
        Mod,
        Pow,
        Neg,

        /*
         * Comparisons
         */
        Equal,
        NotEqual,
        Less,
        LessEqual,
        Greater,
        GreaterEqual,

        /*
         * Logical
         */
        Not,
        Test,

        /*
         * Control flow
         */
        Jump,
        JumpIfFalse,
        JumpIfTrue,

        /*
         * Functions
         */
        NewClosure,
        Call,
        Return,

        /*
         * Miscellaneous
         */
        Concat,

        /*
         * VM termination.
         */
        Halt
    };

    /*
     * One VM instruction.
     *
     * The VM uses registers rather than exposing the original
     * Luau source structure directly.
     */
    struct Instruction
    {
        OpCode op = OpCode::Nop;

        std::uint8_t a = 0;
        std::uint8_t b = 0;
        std::uint8_t c = 0;

        std::int32_t aux = 0;

        Instruction() = default;

        Instruction(
            OpCode opcode,
            std::uint8_t regA,
            std::uint8_t regB = 0,
            std::uint8_t regC = 0,
            std::int32_t extra = 0
        )
            : op(opcode),
              a(regA),
              b(regB),
              c(regC),
              aux(extra)
        {
        }
    };

    enum class ConstantType : std::uint8_t
    {
        Nil = 0,
        Boolean,
        Number,
        String
    };

    struct Constant
    {
        ConstantType type = ConstantType::Nil;

        bool booleanValue = false;

        double numberValue = 0.0;

        std::string stringValue;

        static Constant nil()
        {
            return {};
        }

        static Constant boolean(bool value)
        {
            Constant result;

            result.type = ConstantType::Boolean;
            result.booleanValue = value;

            return result;
        }

        static Constant number(double value)
        {
            Constant result;

            result.type = ConstantType::Number;
            result.numberValue = value;

            return result;
        }

        static Constant string(const std::string& value)
        {
            Constant result;

            result.type = ConstantType::String;
            result.stringValue = value;

            return result;
        }
    };

    /*
     * A VM function/prototype.
     *
     * Functions can contain their own instruction stream and
     * constants, allowing nested functions to be represented.
     */
    struct Prototype
    {
        std::vector<Instruction> code;

        std::vector<Constant> constants;

        std::vector<Prototype> children;

        std::uint32_t registerCount = 0;

        std::uint32_t parameterCount = 0;

        std::uint32_t upvalueCount = 0;

        bool isVararg = false;
    };

    /*
     * Complete protected program.
     */
    struct Program
    {
        Prototype main;

        /*
         * Version allows the generated VM to reject bytecode
         * produced by an incompatible compiler.
         */
        std::uint32_t version = 1;

        /*
         * Runtime-specific seed. This is NOT intended to be a
         * cryptographic secret; it allows the bytecode encoding
         * layer to produce different representations.
         */
        std::uint32_t seed = 0;
    };

    /*
     * Bytecode serialization.
     *
     * bytecode.cpp will implement these functions.
     */
    std::vector<std::uint8_t> serialize(
        const Program& program
    );

    bool deserialize(
        const std::vector<std::uint8_t>& data,
        Program& program
    );

    /*
     * Utility helpers.
     */
    const char* opcodeName(
        OpCode opcode
    );

    bool isValidOpcode(
        std::uint8_t opcode
    );

    std::uint32_t opcodeCount();
}