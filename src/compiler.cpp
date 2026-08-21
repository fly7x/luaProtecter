#include “compiler.hpp”

#include 
#include 
#include 
#include 

namespace
{
/*
* ———————————————————
* Custom VM instruction set
* ———————————————————
*
* These values belong ONLY to our VM.
*
* 0x01 = HALT
* 0x02 = PUSH_STRING
* 0x03 = PRINT
*
* The VM must use exactly the same definitions.
*/

constexpr std::uint8_t OP_HALT        = 0x01;
constexpr std::uint8_t OP_PUSH_STRING  = 0x02;
constexpr std::uint8_t OP_PRINT        = 0x03;
/*
 * Custom bytecode header.
 *
 * "LVM1"
 */
constexpr std::uint8_t MAGIC_0 = 'L';
constexpr std::uint8_t MAGIC_1 = 'V';
constexpr std::uint8_t MAGIC_2 = 'M';
constexpr std::uint8_t MAGIC_3 = '1';
constexpr std::uint8_t VERSION = 1;
class Builder
{
public:
    std::vector<std::uint8_t> bytes;
    void u8(std::uint8_t value)
    {
        bytes.push_back(value);
    }
    void u32(std::uint32_t value)
    {
        bytes.push_back(
            static_cast<std::uint8_t>(
                value & 0xFFu
            )
        );
        bytes.push_back(
            static_cast<std::uint8_t>(
                (value >> 8) & 0xFFu
            )
        );
        bytes.push_back(
            static_cast<std::uint8_t>(
                (value >> 16) & 0xFFu
            )
        );
        bytes.push_back(
            static_cast<std::uint8_t>(
                (value >> 24) & 0xFFu
            )
        );
    }
    void string(const std::string& value)
    {
        if (
            value.size() >
            0xFFFFFFFFull
        )
        {
            throw std::runtime_error(
                "String is too large"
            );
        }
        u32(
            static_cast<std::uint32_t>(
                value.size()
            )
        );
        bytes.insert(
            bytes.end(),
            value.begin(),
            value.end()
        );
    }
};
/*
 * Skip whitespace.
 */
std::size_t skipWhitespace(
    const std::string& source,
    std::size_t position
)
{
    while (
        position < source.size()
    )
    {
        const char c =
            source[position];
        if (
            c == ' ' ||
            c == '\t' ||
            c == '\r' ||
            c == '\n'
        )
        {
            ++position;
            continue;
        }
        break;
    }
    return position;
}
/*
 * Read a quoted Luau string.
 *
 * Supports:
 *
 * "hello"
 * 'hello'
 *
 * and basic escapes:
 *
 * \n
 * \r
 * \t
 * \\
 * \"
 * \'
 */
std::string readString(
    const std::string& source,
    std::size_t& position
)
{
    if (
        position >= source.size()
    )
    {
        throw std::runtime_error(
            "Expected string"
        );
    }
    const char quote =
        source[position];
    if (
        quote != '"' &&
        quote != '\''
    )
    {
        throw std::runtime_error(
            "Expected quoted string"
        );
    }
    ++position;
    std::string result;
    while (
        position < source.size()
    )
    {
        const char c =
            source[position++];
        if (c == quote)
            return result;
        if (c != '\\')
        {
            result += c;
            continue;
        }
        if (
            position >= source.size()
        )
        {
            throw std::runtime_error(
                "Unterminated escape sequence"
            );
        }
        const char escaped =
            source[position++];
        switch (escaped)
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
                /*
                 * Preserve unknown Luau escapes
                 * instead of silently deleting them.
                 */
                result += '\\';
                result += escaped;
                break;
        }
    }
    throw std::runtime_error(
        "Unterminated string literal"
    );
}
/*
 * Read an identifier.
 */
std::string readIdentifier(
    const std::string& source,
    std::size_t& position
)
{
    const std::size_t start =
        position;
    if (
        position >= source.size()
    )
    {
        return {};
    }
    const auto isStart =
        [](char c)
        {
            return
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                c == '_';
        };
    const auto isPart =
        [](char c)
        {
            return
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '_';
        };
    if (!isStart(source[position]))
        return {};
    ++position;
    while (
        position < source.size() &&
        isPart(source[position])
    )
    {
        ++position;
    }
    return source.substr(
        start,
        position - start
    );
}
/*
 * Expect a specific character.
 */
void expect(
    const std::string& source,
    std::size_t& position,
    char expected
)
{
    position =
        skipWhitespace(
            source,
            position
        );
    if (
        position >= source.size() ||
        source[position] != expected
    )
    {
        throw std::runtime_error(
            std::string(
                "Expected '"
            ) +
            expected +
            "'"
        );
    }
    ++position;
}
/*
 * Remove Lua/Luau line comments.
 *
 * This intentionally handles only normal
 * -- comments. Long-bracket comments are
 * handled later when the parser is expanded.
 */
std::string stripComments(
    const std::string& source
)
{
    std::string result;
    result.reserve(
        source.size()
    );
    bool inString = false;
    char stringQuote = 0;
    bool escaped = false;
    for (
        std::size_t i = 0;
        i < source.size();
        ++i
    )
    {
        const char c =
            source[i];
        if (inString)
        {
            result += c;
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
            if (c == stringQuote)
            {
                inString = false;
                stringQuote = 0;
            }
            continue;
        }
        if (
            c == '"' ||
            c == '\''
        )
        {
            inString = true;
            stringQuote = c;
            result += c;
            continue;
        }
        if (
            c == '-' &&
            i + 1 < source.size() &&
            source[i + 1] == '-'
        )
        {
            ++i;
            while (
                i + 1 < source.size() &&
                source[i + 1] != '\n'
            )
            {
                ++i;
            }
            result += '\n';
            continue;
        }
        result += c;
    }
    return result;
}
/*
 * Compile:
 *
 * print("hello")
 *
 * into:
 *
 * PUSH_STRING "hello"
 * PRINT
 */
void compilePrint(
    const std::string& source,
    std::size_t& position,
    Builder& builder
)
{
    const std::string identifier =
        readIdentifier(
            source,
            position
        );
    if (identifier != "print")
    {
        throw std::runtime_error(
            "Expected print"
        );
    }
    position =
        skipWhitespace(
            source,
            position
        );
    expect(
        source,
        position,
        '('
    );
    position =
        skipWhitespace(
            source,
            position
        );
    if (
        position >= source.size()
    )
    {
        throw std::runtime_error(
            "Expected print argument"
        );
    }
    const char first =
        source[position];
    if (
        first != '"' &&
        first != '\''
    )
    {
        throw std::runtime_error(
            "Custom compiler currently "
            "supports string arguments "
            "for print()"
        );
    }
    const std::string value =
        readString(
            source,
            position
        );
    position =
        skipWhitespace(
            source,
            position
        );
    expect(
        source,
        position,
        ')'
    );
    builder.u8(
        OP_PUSH_STRING
    );
    builder.string(
        value
    );
    builder.u8(
        OP_PRINT
    );
}

}

Bytecode Compiler::compile(
const std::string& source
) const
{
if (source.empty())
{
throw std::runtime_error(
“Source cannot be empty”
);
}

const std::string cleaned =
    stripComments(
        source
    );
Builder builder;
/*
 * Header:
 *
 * LVM1
 * version
 */
builder.u8(MAGIC_0);
builder.u8(MAGIC_1);
builder.u8(MAGIC_2);
builder.u8(MAGIC_3);
builder.u8(VERSION);
std::size_t position = 0;
while (true)
{
    position =
        skipWhitespace(
            cleaned,
            position
        );
    if (
        position >= cleaned.size()
    )
    {
        break;
    }
    /*
     * A semicolon is optional.
     */
    if (cleaned[position] == ';')
    {
        ++position;
        continue;
    }
    /*
     * The first supported statement is:
     *
     * print("...")
     */
    const std::size_t statementStart =
        position;
    const std::string identifier =
        readIdentifier(
            cleaned,
            position
        );
    position =
        statementStart;
    if (identifier == "print")
    {
        compilePrint(
            cleaned,
            position,
            builder
        );
    }
    else
    {
        throw std::runtime_error(
            "Unsupported Luau statement: " +
            (
                identifier.empty()
                    ? std::string("<unknown>")
                    : identifier
            )
        );
    }
    position =
        skipWhitespace(
            cleaned,
            position
        );
    /*
     * Allow:
     *
     * print("a")
     * print("b")
     *
     * and:
     *
     * print("a"); print("b")
     */
    if (
        position < cleaned.size() &&
        cleaned[position] == ';'
    )
    {
        ++position;
    }
}
/*
 * Every valid program ends with HALT.
 */
builder.u8(
    OP_HALT
);
return Bytecode(
    std::move(
        builder.bytes
    )
);

}