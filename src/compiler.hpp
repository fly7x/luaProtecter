#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class VMOpcode : std::uint8_t
{
    NOP = 0,

    PUSH_NIL,
    PUSH_BOOL,
    PUSH_NUMBER,
    PUSH_STRING,

    GET_GLOBAL,
    SET_GLOBAL,

    ADD,
    SUB,
    MUL,
    DIV,

    NEG,
    NOT,

    POP,

    CALL,
    RETURN
};

struct VMInstruction
{
    VMOpcode opcode = VMOpcode::NOP;

    std::int32_t operandA = 0;
    std::int32_t operandB = 0;

    double number = 0.0;

    std::string text;
};

class Compiler
{
public:
    Compiler() = default;

    /*
     * Compile valid Luau source into our custom VM
     * instruction representation.
     */
    bool compile(
        const std::string& source,
        std::vector<VMInstruction>& output,
        std::string& error
    );

    /*
     * Serialize the instruction stream into a binary
     * representation suitable for Transformer::protect().
     */
    std::string serialize(
        const std::vector<VMInstruction>& instructions
    ) const;

private:
    bool compileStatement(
        const std::string& statement,
        std::vector<VMInstruction>& output,
        std::string& error
    );

    bool compileExpression(
        const std::string& expression,
        std::vector<VMInstruction>& output,
        std::string& error
    );
};