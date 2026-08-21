#include "transformer.hpp"

#include <cctype>
#include <cstdint>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    enum class Op : std::uint8_t
    {
        PushString = 1,
        PushNumber = 2,
        GetGlobal = 3,
        Call = 4,
        Pop = 5,
        Halt = 6
    };

    struct Instruction
    {
        Op op;
        std::uint32_t a;
        std::uint32_t b;
    };

    struct Token
    {
        enum class Kind
        {
            Identifier,
            String,
            Number,
            LeftParen,
            RightParen,
            Comma,
            End
        };

        Kind kind;
        std::string text;
    };

    class Lexer
    {
    public:
        explicit Lexer(const std::string& source)
            : source(source)
        {
        }

        std::vector<Token> run()
        {
            std::vector<Token> tokens;

            while (true)
            {
                skipSpace();

                if (pos >= source.size())
                {
                    tokens.push_back(
                        {Token::Kind::End, {}}
                    );
                    break;
                }

                const char c = source[pos];

                if (isIdentStart(c))
                {
                    tokens.push_back(
                        {
                            Token::Kind::Identifier,
                            readIdentifier()
                        }
                    );

                    continue;
                }

                if (
                    std::isdigit(
                        static_cast<unsigned char>(c)
                    )
                )
                {
                    tokens.push_back(
                        {
                            Token::Kind::Number,
                            readNumber()
                        }
                    );

                    continue;
                }

                if (c == '"' || c == '\'')
                {
                    tokens.push_back(
                        {
                            Token::Kind::String,
                            readString()
                        }
                    );

                    continue;
                }

                ++pos;

                switch (c)
                {
                    case '(':
                        tokens.push_back(
                            {Token::Kind::LeftParen, "("}
                        );
                        break;

                    case ')':
                        tokens.push_back(
                            {Token::Kind::RightParen, ")"}
                        );
                        break;

                    case ',':
                        tokens.push_back(
                            {Token::Kind::Comma, ","}
                        );
                        break;

                    default:
                        /*
                         * This VM intentionally rejects syntax
                         * outside the subset it understands.
                         *
                         * This prevents silently producing
                         * incorrect protected programs.
                         */
                        throw std::runtime_error(
                            "Unsupported Luau token"
                        );
                }
            }

            return tokens;
        }

    private:
        const std::string& source;
        std::size_t pos = 0;

        static bool isIdentStart(char c)
        {
            const unsigned char u =
                static_cast<unsigned char>(c);

            return std::isalpha(u) || c == '_';
        }

        static bool isIdentPart(char c)
        {
            const unsigned char u =
                static_cast<unsigned char>(c);

            return std::isalnum(u) || c == '_';
        }

        void skipSpace()
        {
            while (pos < source.size())
            {
                if (
                    std::isspace(
                        static_cast<unsigned char>(
                            source[pos]
                        )
                    )
                )
                {
                    ++pos;
                    continue;
                }

                /*
                 * Basic -- comments.
                 */
                if (
                    source[pos] == '-' &&
                    pos + 1 < source.size() &&
                    source[pos + 1] == '-'
                )
                {
                    pos += 2;

                    while (
                        pos < source.size() &&
                        source[pos] != '\n'
                    )
                    {
                        ++pos;
                    }

                    continue;
                }

                break;
            }
        }

        std::string readIdentifier()
        {
            const std::size_t start = pos;

            ++pos;

            while (
                pos < source.size() &&
                isIdentPart(source[pos])
            )
            {
                ++pos;
            }

            return source.substr(
                start,
                pos - start
            );
        }

        std::string readNumber()
        {
            const std::size_t start = pos;

            while (
                pos < source.size() &&
                (
                    std::isdigit(
                        static_cast<unsigned char>(
                            source[pos]
                        )
                    ) ||
                    source[pos] == '.' ||
                    source[pos] == 'e' ||
                    source[pos] == 'E' ||
                    source[pos] == '+' ||
                    source[pos] == '-'
                )
            )
            {
                ++pos;
            }

            return source.substr(
                start,
                pos - start
            );
        }

        std::string readString()
        {
            const char quote = source[pos++];

            std::string value;

            while (pos < source.size())
            {
                char c = source[pos++];

                if (c == quote)
                    return value;

                if (c != '\\')
                {
                    value.push_back(c);
                    continue;
                }

                if (pos >= source.size())
                    throw std::runtime_error(
                        "Unterminated string"
                    );

                const char escaped =
                    source[pos++];

                switch (escaped)
                {
                    case 'n':
                        value.push_back('\n');
                        break;

                    case 'r':
                        value.push_back('\r');
                        break;

                    case 't':
                        value.push_back('\t');
                        break;

                    case 'b':
                        value.push_back('\b');
                        break;

                    case 'f':
                        value.push_back('\f');
                        break;

                    case '\\':
                        value.push_back('\\');
                        break;

                    case '"':
                        value.push_back('"');
                        break;

                    case '\'':
                        value.push_back('\'');
                        break;

                    default:
                        value.push_back(escaped);
                        break;
                }
            }

            throw std::runtime_error(
                "Unterminated string"
            );
        }
    };

    class ProgramBuilder
    {
    public:
        std::uint32_t stringConstant(
            const std::string& value
        )
        {
            strings.push_back(value);

            return static_cast<std::uint32_t>(
                strings.size() - 1
            );
        }

        void emit(
            Op op,
            std::uint32_t a = 0,
            std::uint32_t b = 0
        )
        {
            code.push_back(
                {
                    op,
                    a,
                    b
                }
            );
        }

        const std::vector<Instruction>& instructions()
            const
        {
            return code;
        }

        const std::vector<std::string>& constants()
            const
        {
            return strings;
        }

    private:
        std::vector<Instruction> code;
        std::vector<std::string> strings;
    };

    /*
     * Parse the intentionally small VM source language:
     *
     *     print("hello")
     *     warn("hello")
     *     error("hello")
     *
     * and multiple calls separated by semicolons/newlines.
     *
     * The important part is that the output is no longer
     * the original source with strings replaced.
     *
     * It is an instruction stream executed by the generated
     * VM runtime.
     */
    class Compiler
    {
    public:
        explicit Compiler(
            const std::vector<Token>& tokens
        )
            : tokens(tokens)
        {
        }

        ProgramBuilder compile()
        {
            ProgramBuilder program;

            while (!at(Token::Kind::End))
            {
                compileCall(program);

                /*
                 * Optional separators.
                 *
                 * Newlines have already been consumed by the
                 * lexer, so adjacent calls are accepted.
                 */
            }

            program.emit(Op::Halt);

            return program;
        }

    private:
        const std::vector<Token>& tokens;
        std::size_t index = 0;

        const Token& current() const
        {
            return tokens[index];
        }

        bool at(Token::Kind kind) const
        {
            return current().kind == kind;
        }

        bool match(Token::Kind kind)
        {
            if (!at(kind))
                return false;

            ++index;
            return true;
        }

        const Token& consume(
            Token::Kind kind,
            const char* message
        )
        {
            if (!at(kind))
                throw std::runtime_error(message);

            return tokens[index++];
        }

        void compileCall(
            ProgramBuilder& program
        )
        {
            const Token& identifier =
                consume(
                    Token::Kind::Identifier,
                    "Expected function name"
                );

            if (
                identifier.text != "print" &&
                identifier.text != "warn" &&
                identifier.text != "error"
            )
            {
                throw std::runtime_error(
                    "Unsupported global function"
                );
            }

            const std::uint32_t global =
                program.stringConstant(
                    identifier.text
                );

            program.emit(
                Op::GetGlobal,
                global
            );

            consume(
                Token::Kind::LeftParen,
                "Expected '('"
            );

            std::uint32_t argumentCount = 0;

            if (!at(Token::Kind::RightParen))
            {
                while (true)
                {
                    compileExpression(
                        program
                    );

                    ++argumentCount;

                    if (!match(Token::Kind::Comma))
                        break;
                }
            }

            consume(
                Token::Kind::RightParen,
                "Expected ')'"
            );

            program.emit(
                Op::Call,
                argumentCount
            );

            program.emit(Op::Pop);
        }

        void compileExpression(
            ProgramBuilder& program
        )
        {
            if (at(Token::Kind::String))
            {
                const std::string value =
                    current().text;

                ++index;

                program.emit(
                    Op::PushString,
                    program.stringConstant(
                        value
                    )
                );

                return;
            }

            if (at(Token::Kind::Number))
            {
                const std::string value =
                    current().text;

                ++index;

                program.emit(
                    Op::PushNumber,
                    program.stringConstant(
                        value
                    )
                );

                return;
            }

            throw std::runtime_error(
                "Unsupported expression"
            );
        }
    };

    static std::uint32_t random32()
    {
        static std::random_device rd;

        std::uint32_t a =
            static_cast<std::uint32_t>(rd());

        std::uint32_t b =
            static_cast<std::uint32_t>(rd());

        std::uint32_t value =
            a ^ (b * 0x9E3779B9u);

        if (value == 0)
            value = 0xA341316Cu;

        return value;
    }

    static std::string identifier()
    {
        std::ostringstream out;

        out
            << "__vm_"
            << std::hex
            << random32()
            << random32();

        return out.str();
    }

    static std::string escapeLuau(
        const std::string& value
    )
    {
        std::ostringstream out;

        for (unsigned char c : value)
        {
            switch (c)
            {
                case '\\':
                    out << "\\\\";
                    break;

                case '"':
                    out << "\\\"";
                    break;

                case '\n':
                    out << "\\n";
                    break;

                case '\r':
                    out << "\\r";
                    break;

                case '\t':
                    out << "\\t";
                    break;

                case '\b':
                    out << "\\b";
                    break;

                case '\f':
                    out << "\\f";
                    break;

                default:
                    if (c < 32)
                    {
                        out
                            << "\\"
                            << static_cast<unsigned int>(
                                c
                            );
                    }
                    else
                    {
                        out
                            << static_cast<char>(c);
                    }
                    break;
            }
        }

        return out.str();
    }

    static std::uint32_t mix(
        std::uint32_t value,
        std::uint32_t seed
    )
    {
        value ^= seed + 0x9E3779B9u;
        value *= 0x85EBCA6Bu;
        value ^= value >> 13;
        value *= 0xC2B2AE35u;
        value ^= value >> 16;

        return value;
    }

    static std::string emitVM(
        const ProgramBuilder& program
    )
    {
        const std::string vm =
            identifier();

        const std::string codeTable =
            identifier();

        const std::string constants =
            identifier();

        const std::string stack =
            identifier();

        const std::string pc =
            identifier();

        const std::string op =
            identifier();

        const std::string a =
            identifier();

        const std::string b =
            identifier();

        const std::uint32_t seed =
            random32();

        std::ostringstream out;

        /*
         * Constants.
         */
        out
            << "local "
            << constants
            << "={";

        for (
            std::size_t i = 0;
            i < program.constants().size();
            ++i
        )
        {
            if (i != 0)
                out << ",";

            out
                << "\""
                << escapeLuau(
                    program.constants()[i]
                )
                << "\"";
        }

        out << "}\n";

        /*
         * Custom instruction stream.
         *
         * Each instruction is represented as:
         *
         *     {opcode, operandA, operandB}
         *
         * The opcode itself is shuffled using a per-build
         * seed. The generated interpreter reverses that
         * transformation.
         */
        out
            << "local "
            << codeTable
            << "={";

        for (
            std::size_t i = 0;
            i < program.instructions().size();
            ++i
        )
        {
            const Instruction& instruction =
                program.instructions()[i];

            if (i != 0)
                out << ",";

            const std::uint32_t encodedOp =
                mix(
                    static_cast<std::uint32_t>(
                        instruction.op
                    ),
                    seed
                );

            out
                << "{"
                << encodedOp
                << ","
                << instruction.a
                << ","
                << instruction.b
                << "}";
        }

        out << "}\n";

        /*
         * VM runtime.
         *
         * The source program is not emitted here.
         * The generated program consists of the VM state,
         * instruction stream and interpreter.
         */
        out
            << "local "
            << vm
            << "=function()\n"

            << "local "
            << stack
            << "={}\n"

            << "local "
            << pc
            << "=1\n"

            << "local function "
            << op
            << "(x)\n"

            << "local y=x\n"
            << "y=y~"
            << seed
            << "\n"

            << "return y\n"
            << "end\n"

            << "while true do\n"

            << "local i="
            << codeTable
            << "["
            << pc
            << "]\n"

            << "if not i then break end\n"

            << "local "
            << a
            << "=i[2]\n"

            << "local "
            << b
            << "=i[3]\n"

            << "local o="
            << op
            << "(i[1])\n";

        /*
         * NOTE:
         *
         * Luau supports bitwise operators, but using bit32
         * keeps the generated code compatible with Roblox
         * environments where bit32 is available.
         *
         * Replace the decode expression below with bit32.bxor
         * to avoid depending on '~'.
         */
        out.str(
            out.str()
        );

        /*
         * Rebuild the runtime without the '~' operator.
         *
         * This section is emitted separately so the generated
         * Luau is compatible with Roblox's bit32 API.
         */
        std::string result =
            out.str();

        const std::string bad =
            "local y=x\ny=y~" +
            std::to_string(seed) +
            "\nreturn y";

        const std::string good =
            "local y=bit32.bxor(x," +
            std::to_string(seed) +
            ")\nreturn y";

        const std::size_t position =
            result.find(bad);

        if (position != std::string::npos)
        {
            result.replace(
                position,
                bad.size(),
                good
            );
        }

        /*
         * Interpreter dispatch.
         */
        std::ostringstream tail;

        tail
            << "\n"

            << "if o=="
            << mix(
                static_cast<std::uint32_t>(
                    Op::PushString
                ),
                seed
            )
            << " then\n"

            << "table.insert("
            << stack
            << ","
            << constants
            << "["
            << a
            << "])\n"

            << "elseif o=="
            << mix(
                static_cast<std::uint32_t>(
                    Op::PushNumber
                ),
                seed
            )
            << " then\n"

            << "table.insert("
            << stack
            << ",tonumber("
            << constants
            << "["
            << a
            << "]))\n"

            << "elseif o=="
            << mix(
                static_cast<std::uint32_t>(
                    Op::GetGlobal
                ),
                seed
            )
            << " then\n"

            << "table.insert("
            << stack
            << ",_G["
            << constants
            << "["
            << a
            << "]])\n"

            << "elseif o=="
            << mix(
                static_cast<std::uint32_t>(
                    Op::Call
                ),
                seed
            )
            << " then\n"

            << "local args={}\n"

            << "for n="
            << b
            << ",1,-1 do\n"

            << "args[n]="
            << stack
            << "[#"
            << stack
            << "]\n"

            << "table.remove("
            << stack
            << ")\n"

            << "end\n"

            << "local fn="
            << stack
            << "[#"
            << stack
            << "]\n"

            << "table.remove("
            << stack
            << ")\n"

            << "table.insert("
            << stack
            << ",fn(table.unpack(args)))\n"

            << "elseif o=="
            << mix(
                static_cast<std::uint32_t>(
                    Op::Pop
                ),
                seed
            )
            << " then\n"

            << "table.remove("
            << stack
            << ")\n"

            << "elseif o=="
            << mix(
                static_cast<std::uint32_t>(
                    Op::Halt
                ),
                seed
            )
            << " then\n"

            << "break\n"

            << "else\n"

            << "error(\"VM instruction error\")\n"

            << "end\n"

            << pc
            << "="
            << pc
            << "+1\n"

            << "end\n"

            << "end\n"

            << vm
            << "()\n";

        result += tail.str();

        return result;
    }
}

std::string Transformer::transform(
    const std::string& source
)
{
    if (source.empty())
        return {};

    try
    {
        Lexer lexer(source);

        const std::vector<Token> tokens =
            lexer.run();

        Compiler compiler(tokens);

        ProgramBuilder program =
            compiler.compile();

        return emitVM(program);
    }
    catch (...)
    {
        /*
         * Returning an empty string is intentional.
         *
         * main.cpp already converts an empty transformation
         * into an HTTP 422 response.
         */
        return {};
    }
}