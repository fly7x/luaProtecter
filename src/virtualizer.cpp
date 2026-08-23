#include "virtualizer.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <random>
#include <sstream>
#include <stdexcept>
#include <unordered_set>

namespace
{
    bool isIdentifierStart(char c)
    {
        return
            std::isalpha(
                static_cast<unsigned char>(c)
            ) ||
            c == '_';
    }

    bool isIdentifierPart(char c)
    {
        return
            std::isalnum(
                static_cast<unsigned char>(c)
            ) ||
            c == '_';
    }

    bool isKeyword(const std::string& s)
    {
        static const std::unordered_set<std::string>
            keywords =
        {
            "and",
            "break",
            "do",
            "else",
            "elseif",
            "end",
            "false",
            "for",
            "function",
            "if",
            "in",
            "local",
            "nil",
            "not",
            "or",
            "repeat",
            "return",
            "then",
            "true",
            "until",
            "while",
            "continue",

            "type",
            "export",
            "typeof"
        };

        return keywords.count(s) != 0;
    }

    std::string escapeLuauString(
        const std::string& input
    )
    {
        std::string out;

        for (unsigned char c : input)
        {
            switch (c)
            {
                case '\\':
                    out += "\\\\";
                    break;

                case '"':
                    out += "\\\"";
                    break;

                case '\n':
                    out += "\\n";
                    break;

                case '\r':
                    out += "\\r";
                    break;

                case '\t':
                    out += "\\t";
                    break;

                default:
                    out += static_cast<char>(c);
                    break;
            }
        }

        return out;
    }
}

Virtualizer::Virtualizer(
    std::uint64_t seedValue
)
    : seed(seedValue)
{
}

std::uint64_t Virtualizer::nextRandom()
{
    /*
     * xorshift64*
     *
     * Fast deterministic PRNG used only to make
     * generated identifiers/opcodes differ between builds.
     */
    std::uint64_t x = seed;

    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;

    seed = x;

    return x * 2685821657736338717ULL;
}

std::string Virtualizer::identifier()
{
    static constexpr char alphabet[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    const std::size_t length =
        7 +
        static_cast<std::size_t>(
            nextRandom() % 7
        );

    std::string result;

    result.reserve(length);

    result +=
        alphabet[
            nextRandom() %
            (sizeof(alphabet) - 1)
        ];

    for (std::size_t i = 1; i < length; ++i)
    {
        result +=
            alphabet[
                nextRandom() %
                (sizeof(alphabet) - 1)
            ];
    }

    if (isKeyword(result))
        return identifier();

    return result;
}

std::string Virtualizer::encodeString(
    const std::string& value
)
{
    /*
     * Store the characters as arithmetic expressions
     * rather than leaving the original literal visible.
     *
     * Example:
     *
     * "abc"
     *
     * becomes something conceptually equivalent to:
     *
     * string.char(...)
     */
    std::ostringstream out;

    out << "string.char(";

    for (std::size_t i = 0;
         i < value.size();
         ++i)
    {
        if (i != 0)
            out << ",";

        const unsigned int character =
            static_cast<unsigned int>(
                static_cast<unsigned char>(
                    value[i]
                )
            );

        const unsigned int mask =
            1 +
            static_cast<unsigned int>(
                nextRandom() % 251
            );

        const unsigned int encoded =
            character ^ mask;

        out
            << "("
            << encoded
            << "^"
            << mask
            << ")";
    }

    out << ")";

    return out.str();
}

std::string Virtualizer::encodeNumber(
    const std::string& value
)
{
    /*
     * Only transform plain integer literals.
     */
    if (value.empty())
        return value;

    for (char c : value)
    {
        if (!std::isdigit(
                static_cast<unsigned char>(c)
            ))
        {
            return value;
        }
    }

    try
    {
        const long long original =
            std::stoll(value);

        const long long mask =
            3 +
            static_cast<long long>(
                nextRandom() % 997
            );

        const long long encoded =
            original + mask;

        return
            "(" +
            std::to_string(encoded) +
            "-" +
            std::to_string(mask) +
            ")";
    }
    catch (...)
    {
        return value;
    }
}

std::vector<std::string>
Virtualizer::buildInstructions(
    const std::string& source
)
{
    /*
     * This stage deliberately keeps the original
     * semantics intact.
     *
     * Each source fragment becomes a VM instruction.
     *
     * The generated dispatcher later executes these
     * fragments in sequence.
     */

    std::vector<std::string> instructions;

    std::string current;

    char quote = 0;
    bool escaped = false;

    int depth = 0;

    for (std::size_t i = 0;
         i < source.size();
         ++i)
    {
        const char c = source[i];

        /*
         * Preserve strings as atomic fragments.
         */
        if (quote != 0)
        {
            current += c;

            if (escaped)
            {
                escaped = false;
                continue;
            }

            if (c == '\\')
            {
                escaped = true;
                continue;
            }

            if (c == quote)
                quote = 0;

            continue;
        }

        if (c == '"' || c == '\'')
        {
            quote = c;
            current += c;
            continue;
        }

        if (c == '(' ||
            c == '{' ||
            c == '[')
        {
            ++depth;
            current += c;
            continue;
        }

        if (c == ')' ||
            c == '}' ||
            c == ']')
        {
            if (depth > 0)
                --depth;

            current += c;
            continue;
        }

        /*
         * Split on statement boundaries only when we're
         * not inside an expression.
         */
        if (
            c == '\n' &&
            depth == 0
        )
        {
            if (!current.empty())
            {
                instructions.push_back(
                    current
                );

                current.clear();
            }

            continue;
        }

        current += c;
    }

    if (!current.empty())
        instructions.push_back(current);

    /*
     * Remove completely empty instructions.
     */
    instructions.erase(
        std::remove_if(
            instructions.begin(),
            instructions.end(),
            [](const std::string& value)
            {
                return std::all_of(
                    value.begin(),
                    value.end(),
                    [](char c)
                    {
                        return std::isspace(
                            static_cast<unsigned char>(
                                c
                            )
                        );
                    }
                );
            }
        ),
        instructions.end()
    );

    return instructions;
}

std::string Virtualizer::generateDispatcher(
    const std::vector<std::string>& instructions
)
{
    const std::string vm =
        identifier();

    const std::string state =
        identifier();

    const std::string table =
        identifier();

    const std::string handler =
        identifier();

    const std::string dispatch =
        identifier();

    const std::string value =
        identifier();

    std::ostringstream out;

    /*
     * Generated VM state.
     */
    out
        << "local "
        << vm
        << "={}\n";

    /*
     * Instruction table.
     *
     * Each entry contains a state and a function.
     */
    out
        << "local "
        << table
        << "={}\n";

    /*
     * Randomized state IDs.
     */
    std::vector<std::uint64_t> states;

    states.reserve(
        instructions.size()
    );

    for (std::size_t i = 0;
         i < instructions.size();
         ++i)
    {
        std::uint64_t id =
            nextRandom();

        id =
            (id % 900000) +
            100000;

        states.push_back(id);
    }

    /*
     * Generate handlers.
     */
    for (std::size_t i = 0;
         i < instructions.size();
         ++i)
    {
        const std::string handlerName =
            identifier();

        out
            << "local "
            << handlerName
            << "=function()\n";

        out
            << instructions[i]
            << "\n";

        if (
            i + 1 <
            instructions.size()
        )
        {
            out
                << vm
                << "."
                << state
                << "="
                << states[i + 1]
                << "\n";
        }
        else
        {
            out
                << vm
                << "."
                << state
                << "=nil\n";
        }

        out
            << "end\n";

        out
            << table
            << "["
            << states[i]
            << "]="
            << handlerName
            << "\n";
    }

    if (instructions.empty())
    {
        return {};
    }

    /*
     * Initial state.
     */
    out
        << vm
        << "."
        << state
        << "="
        << states.front()
        << "\n";

    /*
     * Dispatcher.
     */
    out
        << "while "
        << vm
        << "."
        << state
        << "~=nil do\n";

    out
        << "local "
        << handler
        << "="
        << table
        << "["
        << vm
        << "."
        << state
        << "]\n";

    out
        << "if "
        << handler
        << "==nil then break end\n";

    out
        << handler
        << "()\n";

    out
        << "end\n";

    return out.str();
}

std::string Virtualizer::generate(
    const std::string& source,
    const Options& options
)
{
    if (source.empty())
        throw std::runtime_error(
            "Cannot virtualize empty source"
        );

    /*
     * Build the VM instruction representation.
     */
    const std::vector<std::string> instructions =
        buildInstructions(source);

    if (!options.virtualize)
        return source;

    /*
     * Emit the generated Luau dispatcher.
     */
    return generateDispatcher(
        instructions
    );
}