#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace LuaProtecter
{
    enum class OpCode : std::uint8_t
    {
        Nop = 0,

        PushString,
        PushNumber,

        GetGlobal,
        SetGlobal,

        Add,
        Sub,
        Mul,
        Div,

        Call,
        Return,

        Pop,

        Jump,
        JumpIfFalse,

        Halt
    };

    struct Instruction
    {
        std::uint32_t opcode = 0;
        std::uint32_t a = 0;
        std::uint32_t b = 0;
        std::uint32_t c = 0;
    };

    struct Constant
    {
        enum class Type
        {
            String,
            Number
        };

        Type type = Type::String;

        std::string stringValue;
        double numberValue = 0.0;
    };

    struct Program
    {
        std::vector<Instruction> code;
        std::vector<Constant> constants;

        std::uint32_t seed = 0;
    };

    class VM
    {
    public:
        VM() = default;

        /*
         * Execute a compiled program.
         *
         * The VM is intentionally separated from the transformer:
         *
         *     source
         *        ↓
         *     Transformer
         *        ↓
         *     Program
         *        ↓
         *     VM
         */
        bool execute(
            const Program& program
        );

    private:
        struct Value
        {
            enum class Type
            {
                Nil,
                Number,
                String
            };

            Type type = Type::Nil;

            double number = 0.0;
            std::string string;
        };

        std::vector<Value> stack;

        std::size_t stackBase = 0;

        std::size_t programCounter = 0;

        bool halted = false;

        Value pop();

        void push(
            Value value
        );

        Value constantToValue(
            const Constant& constant
        ) const;

        static std::uint32_t decodeOpcode(
            std::uint32_t encoded,
            std::uint32_t seed
        );

        bool executeInstruction(
            const Instruction& instruction,
            const Program& program
        );
    };
}