#include "compiler.hpp"

#include <Luau/Compiler.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <stdexcept>

namespace
{
    std::string trim(
        const std::string& value
    )
    {
        std::size_t start = 0;

        while (
            start < value.size() &&
            std::isspace(
                static_cast<unsigned char>(
                    value[start]
                )
            )
        )
        {
            ++start;
        }

        std::size_t end = value.size();

        while (
            end > start &&
            std::isspace(
                static_cast<unsigned char>(
                    value[end - 1]
                )
            )
        )
        {
            --end;
        }

        return value.substr(
            start,
            end - start
        );
    }

    bool isIdentifier(
        const std::string& value
    )
    {
        if (value.empty())
            return false;

        if (
            !std::isalpha(
                static_cast<unsigned char>(
                    value[0]
                )
            ) &&
            value[0] != '_'
        )
        {
            return false;
        }

        for (std::size_t i = 1; i < value.size(); ++i)
        {
            const unsigned char c =
                static_cast<unsigned char>(
                    value[i]
                );

            if (
                !std::isalnum(c) &&
                c != '_'
            )
            {
                return false;
            }
        }

        return true;
    }

    bool parseBoolean(
        const std::string& value,
        bool& result
    )
    {
        if (value == "true")
        {
            result = true;
            return true;
        }

        if (value == "false")
        {
            result = false;
            return true;
        }

        return false;
    }

    bool parseNumber(
        const std::string& value,
        double& result
    )
    {
        if (value.empty())
            return false;

        char* end = nullptr;

        result =
            std::strtod(
                value.c_str(),
                &end
            );

        if (end == value.c_str())
            return false;

        while (
            *end != '\0' &&
            std::isspace(
                static_cast<unsigned char>(
                    *end
                )
            )
        )
        {
            ++end;
        }

        return *end == '\0';
    }

    bool parseString(
        const std::string& value,
        std::string& result
    )
    {
        if (value.size() < 2)
            return false;

        const char quote = value.front();

        if (
            quote != '"' &&
            quote != '\''
        )
        {
            return false;
        }

        if (value.back() != quote)
            return false;

        result.clear();

        bool escaped = false;

        for (
            std::size_t i = 1;
            i + 1 < value.size();
            ++i
        )
        {
            const char c = value[i];

            if (escaped)
            {
                switch (c)
                {
                    case 'n':
                        result += '\n';
                        break;

                    case 'r':
                        result += '\r';
                        break;

                    case 't':
                        result += '\t';
                        break;

                    case '\\':
                        result += '\\';
                        break;

                    case '"':
                        result += '"';
                        break;

                    case '\'':
                        result += '\'';
                        break;

                    default:
                        result += c;
                        break;
                }

                escaped = false;
                continue;
            }

            if (c == '\\')
            {
                escaped = true;
                continue;
            }

            result += c;
        }

        return !escaped;
    }

    void writeU8(
        std::string& output,
        std::uint8_t value
    )
    {
        output.push_back(
            static_cast<char>(value)
        );
    }

    void writeU32(
        std::string& output,
        std::uint32_t value
    )
    {
        output.push_back(
            static_cast<char>(
                value & 0xFF
            )
        );

        output.push_back(
            static_cast<char>(
                (value >> 8) & 0xFF
            )
        );

        output.push_back(
            static_cast<char>(
                (value >> 16) & 0xFF
            )
        );

        output.push_back(
            static_cast<char>(
                (value >> 24) & 0xFF
            )
        );
    }

    void writeI32(
        std::string& output,
        std::int32_t value
    )
    {
        writeU32(
            output,
            static_cast<std::uint32_t>(
                value
            )
        );
    }

    void writeDouble(
        std::string& output,
        double value
    )
    {
        static_assert(
            sizeof(double) == sizeof(std::uint64_t),
            "Unexpected double size"
        );

        std::uint64_t bits = 0;

        std::memcpy(
            &bits,
            &value,
            sizeof(bits)
        );

        for (int i = 0; i < 8; ++i)
        {
            writeU8(
                output,
                static_cast<std::uint8_t>(
                    (bits >> (i * 8)) & 0xFF
                )
            );
        }
    }

    void writeString(
        std::string& output,
        const std::string& value
    )
    {
        writeU32(
            output,
            static_cast<std::uint32_t>(
                value.size()
            )
        );

        output.append(value);
    }

    /*
     * Find an operator outside quoted strings.
     */
    std::size_t findOperator(
        const std::string& expression,
        char wanted
    )
    {
        bool singleQuote = false;
        bool doubleQuote = false;
        bool escaped = false;

        int depth = 0;

        for (
            std::size_t i = 0;
            i < expression.size();
            ++i
        )
        {
            const char c = expression[i];

            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (
                singleQuote ||
                doubleQuote
            )
            {
                if (c == '\\')
                {
                    escaped = true;
                    continue;
                }

                if (
                    singleQuote &&
                    c == '\''
                )
                {
                    singleQuote = false;
                }

                if (
                    doubleQuote &&
                    c == '"'
                )
                {
                    doubleQuote = false;
                }

                continue;
            }

            if (c == '\'')
            {
                singleQuote = true;
                continue;
            }

            if (c == '"')
            {
                doubleQuote = true;
                continue;
            }

            if (c == '(')
            {
                ++depth;
                continue;
            }

            if (c == ')')
            {
                --depth;
                continue;
            }

            if (
                depth == 0 &&
                c == wanted
            )
            {
                return i;
            }
        }

        return std::string::npos;
    }

    VMOpcode arithmeticOpcode(
        char op
    )
    {
        switch (op)
        {
            case '+':
                return VMOpcode::ADD;

            case '-':
                return VMOpcode::SUB;

            case '*':
                return VMOpcode::MUL;

            case '/':
                return VMOpcode::DIV;

            default:
                return VMOpcode::NOP;
        }
    }
}

bool Compiler::compile(
    const std::string& source,
    std::vector<VMInstruction>& output,
    std::string& error
)
{
    output.clear();
    error.clear();

    if (source.empty())
    {
        error = "Source cannot be empty";
        return false;
    }

    /*
     * First validate the source with the actual Luau
     * compiler. This prevents our small custom compiler
     * from accepting malformed Luau.
     */
    try
    {
        const std::string bytecode =
            Luau::compile(source);

        if (bytecode.empty())
        {
            error =
                "Luau compiler rejected the source";

            return false;
        }
    }
    catch (
        const std::exception& exception
    )
    {
        error =
            std::string(
                "Luau validation failed: "
            ) +
            exception.what();

        return false;
    }

    /*
     * This first compiler intentionally handles a
     * small, deterministic subset.
     *
     * We expand the instruction set later rather than
     * pretending arbitrary Luau can already be represented.
     */

    std::stringstream stream(source);

    std::string line;

    while (
        std::getline(
            stream,
            line
        )
    )
    {
        line = trim(line);

        if (line.empty())
            continue;

        /*
         * Ignore ordinary Lua comments.
         */
        if (
            line.size() >= 2 &&
            line[0] == '-' &&
            line[1] == '-'
        )
        {
            continue;
        }

        /*
         * Remove a trailing semicolon.
         */
        if (
            !line.empty() &&
            line.back() == ';'
        )
        {
            line.pop_back();
            line = trim(line);
        }

        if (!compileStatement(
                line,
                output,
                error
            ))
        {
            return false;
        }
    }

    output.push_back(
        VMInstruction{
            VMOpcode::RETURN
        }
    );

    return true;
}

bool Compiler::compileStatement(
    const std::string& statement,
    std::vector<VMInstruction>& output,
    std::string& error
)
{
    const std::string code =
        trim(statement);

    if (code.empty())
        return true;

    /*
     * print(...)
     *
     * We represent this as a global function call.
     */
    if (
        code.size() >= 6 &&
        code.compare(
            0,
            6,
            "print("
        ) == 0 &&
        code.back() == ')'
    )
    {
        const std::string argument =
            trim(
                code.substr(
                    6,
                    code.size() - 7
                )
            );

        if (!compileExpression(
                argument,
                output,
                error
            ))
        {
            return false;
        }

        VMInstruction getPrint;

        getPrint.opcode =
            VMOpcode::GET_GLOBAL;

        getPrint.text =
            "print";

        output.push_back(
            getPrint
        );

        /*
         * Stack arrangement expected by the VM:
         *
         * function
         * argument
         *
         * The exact calling convention can be finalized
         * when vm.cpp is updated.
         */
        VMInstruction call;

        call.opcode =
            VMOpcode::CALL;

        call.operandA = 1;

        output.push_back(
            call
        );

        return true;
    }

    /*
     * local x = expression
     */
    if (
        code.size() >= 6 &&
        code.compare(
            0,
            6,
            "local "
        ) == 0
    )
    {
        const std::string declaration =
            trim(
                code.substr(6)
            );

        const std::size_t equals =
            findOperator(
                declaration,
                '='
            );

        if (
            equals == std::string::npos
        )
        {
            error =
                "Local declaration requires '='";

            return false;
        }

        const std::string name =
            trim(
                declaration.substr(
                    0,
                    equals
                )
            );

        const std::string expression =
            trim(
                declaration.substr(
                    equals + 1
                )
            );

        if (!isIdentifier(name))
        {
            error =
                "Invalid local identifier: " +
                name;

            return false;
        }

        if (!compileExpression(
                expression,
                output,
                error
            ))
        {
            return false;
        }

        VMInstruction instruction;

        instruction.opcode =
            VMOpcode::SET_GLOBAL;

        instruction.text =
            name;

        output.push_back(
            instruction
        );

        return true;
    }

    /*
     * x = expression
     */
    {
        const std::size_t equals =
            findOperator(
                code,
                '='
            );

        if (
            equals != std::string::npos
        )
        {
            const std::string name =
                trim(
                    code.substr(
                        0,
                        equals
                    )
                );

            const std::string expression =
                trim(
                    code.substr(
                        equals + 1
                    )
                );

            if (!isIdentifier(name))
            {
                error =
                    "Invalid assignment target: " +
                    name;

                return false;
            }

            if (!compileExpression(
                    expression,
                    output,
                    error
                ))
            {
                return false;
            }

            VMInstruction instruction;

            instruction.opcode =
                VMOpcode::SET_GLOBAL;

            instruction.text =
                name;

            output.push_back(
                instruction
            );

            return true;
        }
    }

    /*
     * return expression
     */
    if (
        code == "return"
    )
    {
        output.push_back(
            VMInstruction{
                VMOpcode::RETURN
            }
        );

        return true;
    }

    if (
        code.size() > 7 &&
        code.compare(
            0,
            7,
            "return "
        ) == 0
    )
    {
        const std::string expression =
            trim(
                code.substr(7)
            );

        if (!compileExpression(
                expression,
                output,
                error
            ))
        {
            return false;
        }

        output.push_back(
            VMInstruction{
                VMOpcode::RETURN
            }
        );

        return true;
    }

    /*
     * Standalone expression.
     */
    return compileExpression(
        code,
        output,
        error
    );
}

bool Compiler::compileExpression(
    const std::string& expression,
    std::vector<VMInstruction>& output,
    std::string& error
)
{
    const std::string value =
        trim(expression);

    if (value.empty())
    {
        error =
            "Empty expression";

        return false;
    }

    /*
     * Parenthesized expression.
     */
    if (
        value.size() >= 2 &&
        value.front() == '(' &&
        value.back() == ')'
    )
    {
        return compileExpression(
            value.substr(
                1,
                value.size() - 2
            ),
            output,
            error
        );
    }

    /*
     * nil
     */
    if (value == "nil")
    {
        output.push_back(
            VMInstruction{
                VMOpcode::PUSH_NIL
            }
        );

        return true;
    }

    /*
     * booleans
     */
    bool booleanValue = false;

    if (
        parseBoolean(
            value,
            booleanValue
        )
    )
    {
        VMInstruction instruction;

        instruction.opcode =
            VMOpcode::PUSH_BOOL;

        instruction.operandA =
            booleanValue ? 1 : 0;

        output.push_back(
            instruction
        );

        return true;
    }

    /*
     * strings
     */
    std::string stringValue;

    if (
        parseString(
            value,
            stringValue
        )
    )
    {
        VMInstruction instruction;

        instruction.opcode =
            VMOpcode::PUSH_STRING;

        instruction.text =
            stringValue;

        output.push_back(
            instruction
        );

        return true;
    }

    /*
     * number
     */
    double numberValue = 0.0;

    if (
        parseNumber(
            value,
            numberValue
        )
    )
    {
        VMInstruction instruction;

        instruction.opcode =
            VMOpcode::PUSH_NUMBER;

        instruction.number =
            numberValue;

        output.push_back(
            instruction
        );

        return true;
    }

    /*
     * Unary minus.
     */
    if (
        value.size() > 1 &&
        value.front() == '-'
    )
    {
        if (!compileExpression(
                value.substr(1),
                output,
                error
            ))
        {
            return false;
        }

        output.push_back(
            VMInstruction{
                VMOpcode::NEG
            }
        );

        return true;
    }

    /*
     * Unary not.
     */
    if (
        value.size() > 4 &&
        value.compare(
            0,
            4,
            "not "
        ) == 0
    )
    {
        if (!compileExpression(
                value.substr(4),
                output,
                error
            ))
        {
            return false;
        }

        output.push_back(
            VMInstruction{
                VMOpcode::NOT
            }
        );

        return true;
    }

    /*
     * Arithmetic.
     *
     * We intentionally search from the right so
     * expressions such as:
     *
     * 1 + 2 * 3
     *
     * can later be improved into a proper precedence
     * parser without changing the VM format.
     */
    for (
        const char operatorCharacter :
        {'+', '-', '*', '/'}
    )
    {
        const std::size_t position =
            findOperator(
                value,
                operatorCharacter
            );

        if (
            position != std::string::npos &&
            position > 0 &&
            position + 1 < value.size()
        )
        {
            const VMOpcode opcode =
                arithmeticOpcode(
                    operatorCharacter
                );

            if (
                opcode == VMOpcode::NOP
            )
            {
                continue;
            }

            if (!compileExpression(
                    value.substr(
                        0,
                        position
                    ),
                    output,
                    error
                ))
            {
                return false;
            }

            if (!compileExpression(
                    value.substr(
                        position + 1
                    ),
                    output,
                    error
                ))
            {
                return false;
            }

            output.push_back(
                VMInstruction{
                    opcode
                }
            );

            return true;
        }
    }

    /*
     * Global lookup.
     */
    if (isIdentifier(value))
    {
        VMInstruction instruction;

        instruction.opcode =
            VMOpcode::GET_GLOBAL;

        instruction.text =
            value;

        output.push_back(
            instruction
        );

        return true;
    }

    error =
        "Unsupported expression: " +
        value;

    return false;
}

std::string Compiler::serialize(
    const std::vector<VMInstruction>& instructions
) const
{
    /*
     * Binary format:
     *
     * Header:
     *   "CVMI"
     *   version u8
     *   instruction count u32
     *
     * Each instruction:
     *   opcode      u8
     *   operandA    i32
     *   operandB    i32
     *   number      f64
     *   textLength  u32
     *   text        bytes
     */

    std::string output;

    output.reserve(
        instructions.size() * 32
    );

    output.append("CVMI", 4);

    writeU8(
        output,
        1
    );

    writeU32(
        output,
        static_cast<std::uint32_t>(
            instructions.size()
        )
    );

    for (
        const VMInstruction& instruction :
        instructions
    )
    {
        writeU8(
            output,
            static_cast<std::uint8_t>(
                instruction.opcode
            )
        );

        writeI32(
            output,
            instruction.operandA
        );

        writeI32(
            output,
            instruction.operandB
        );

        writeDouble(
            output,
            instruction.number
        );

        writeString(
            output,
            instruction.text
        );
    }

    return output;
}