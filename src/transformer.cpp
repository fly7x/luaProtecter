#include "transformer.hpp"

#include <cctype>
#include <cstdint>
#include <random>
#include <sstream>
#include <string>
#include <vector>

namespace
{
    struct Token
    {
        enum class Kind
        {
            Normal,
            String,
            LongString,
            Comment,
            Whitespace
        };

        Kind kind;
        std::string text;
    };

    bool isIdentStart(char c)
    {
        const unsigned char u =
            static_cast<unsigned char>(c);

        return std::isalpha(u) || c == '_';
    }

    bool isIdentPart(char c)
    {
        const unsigned char u =
            static_cast<unsigned char>(c);

        return std::isalnum(u) || c == '_';
    }

    std::uint32_t random32()
    {
        std::random_device rd;

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

    std::string makeName()
    {
        static std::uint64_t counter = 0;

        ++counter;

        std::ostringstream out;

        out << "__lp_"
            << std::hex
            << random32()
            << random32()
            << counter;

        return out.str();
    }

    std::string escapeLuau(
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

                default:
                    if (c < 32)
                    {
                        out << "\\"
                            << static_cast<int>(c);
                    }
                    else
                    {
                        out << static_cast<char>(c);
                    }

                    break;
            }
        }

        return out.str();
    }

    std::string decodeQuotedString(
        const std::string& token
    )
    {
        if (token.size() < 2)
            return {};

        const char quote =
            token.front();

        if (
            (quote != '"' && quote != '\'') ||
            token.back() != quote
        )
        {
            return {};
        }

        std::string result;

        for (
            std::size_t i = 1;
            i + 1 < token.size();
            ++i
        )
        {
            char c = token[i];

            if (c != '\\')
            {
                result.push_back(c);
                continue;
            }

            if (i + 1 >= token.size() - 1)
                break;

            char n = token[++i];

            switch (n)
            {
                case 'n':
                    result.push_back('\n');
                    break;

                case 'r':
                    result.push_back('\r');
                    break;

                case 't':
                    result.push_back('\t');
                    break;

                case 'b':
                    result.push_back('\b');
                    break;

                case 'f':
                    result.push_back('\f');
                    break;

                case '\\':
                    result.push_back('\\');
                    break;

                case '"':
                    result.push_back('"');
                    break;

                case '\'':
                    result.push_back('\'');
                    break;

                default:
                    /*
                     * Preserve unknown escapes.
                     */
                    result.push_back(n);
                    break;
            }
        }

        return result;
    }

    std::vector<Token> lex(
        const std::string& source
    )
    {
        std::vector<Token> result;

        std::size_t i = 0;

        while (i < source.size())
        {
            const char c = source[i];

            /*
             * Whitespace
             */
            if (
                std::isspace(
                    static_cast<unsigned char>(c)
                )
            )
            {
                std::size_t start = i;

                while (
                    i < source.size() &&
                    std::isspace(
                        static_cast<unsigned char>(
                            source[i]
                        )
                    )
                )
                {
                    ++i;
                }

                result.push_back(
                {
                    Token::Kind::Whitespace,
                    source.substr(
                        start,
                        i - start
                    )
                });

                continue;
            }

            /*
             * Single-line / long comments
             */
            if (
                c == '-' &&
                i + 1 < source.size() &&
                source[i + 1] == '-'
            )
            {
                std::size_t start = i;

                i += 2;

                /*
                 * Long comment.
                 */
                if (
                    i + 1 < source.size() &&
                    source[i] == '[' &&
                    source[i + 1] == '['
                )
                {
                    i += 2;

                    while (
                        i + 1 < source.size() &&
                        !(
                            source[i] == ']' &&
                            source[i + 1] == ']'
                        )
                    )
                    {
                        ++i;
                    }

                    if (i + 1 < source.size())
                        i += 2;
                }
                else
                {
                    while (
                        i < source.size() &&
                        source[i] != '\n'
                    )
                    {
                        ++i;
                    }
                }

                result.push_back(
                {
                    Token::Kind::Comment,
                    source.substr(
                        start,
                        i - start
                    )
                });

                continue;
            }

            /*
             * Quoted strings.
             */
            if (
                c == '"' ||
                c == '\''
            )
            {
                const char quote = c;

                std::size_t start = i;

                ++i;

                bool escaped = false;

                while (i < source.size())
                {
                    const char current =
                        source[i++];

                    if (escaped)
                    {
                        escaped = false;
                        continue;
                    }

                    if (current == '\\')
                    {
                        escaped = true;
                        continue;
                    }

                    if (current == quote)
                        break;
                }

                result.push_back(
                {
                    Token::Kind::String,
                    source.substr(
                        start,
                        i - start
                    )
                });

                continue;
            }

            /*
             * Long strings.
             */
            if (
                c == '[' &&
                i + 1 < source.size() &&
                source[i + 1] == '['
            )
            {
                std::size_t start = i;

                i += 2;

                while (
                    i + 1 < source.size() &&
                    !(
                        source[i] == ']' &&
                        source[i + 1] == ']'
                    )
                )
                {
                    ++i;
                }

                if (i + 1 < source.size())
                    i += 2;

                result.push_back(
                {
                    Token::Kind::LongString,
                    source.substr(
                        start,
                        i - start
                    )
                });

                continue;
            }

            /*
             * Normal token.
             *
             * We deliberately keep normal tokens intact.
             * This avoids accidentally changing Roblox
             * member names, globals, types, attributes,
             * userdata constructors, etc.
             */
            std::size_t start = i;

            ++i;

            /*
             * Consume until something that definitely starts
             * another lexical construct.
             */
            while (i < source.size())
            {
                const char n = source[i];

                if (
                    std::isspace(
                        static_cast<unsigned char>(n)
                    )
                )
                {
                    break;
                }

                if (
                    n == '"' ||
                    n == '\''
                )
                {
                    break;
                }

                if (
                    n == '-' &&
                    i + 1 < source.size() &&
                    source[i + 1] == '-'
                )
                {
                    break;
                }

                if (
                    n == '[' &&
                    i + 1 < source.size() &&
                    source[i + 1] == '['
                )
                {
                    break;
                }

                ++i;
            }

            result.push_back(
            {
                Token::Kind::Normal,
                source.substr(
                    start,
                    i - start
                )
            });
        }

        return result;
    }

    std::string encodeString(
        const std::string& value,
        std::uint8_t key,
        const std::string& decoder
    )
    {
        std::ostringstream out;

        out
            << decoder
            << "({";

        for (
            std::size_t i = 0;
            i < value.size();
            ++i
        )
        {
            const std::uint8_t byte =
                static_cast<std::uint8_t>(
                    static_cast<unsigned char>(
                        value[i]
                    )
                );

            const std::uint8_t mix =
                static_cast<std::uint8_t>(
                    (i * 37u + 19u) & 0xFFu
                );

            const std::uint8_t encoded =
                static_cast<std::uint8_t>(
                    byte ^ key ^ mix
                );

            if (i != 0)
                out << ",";

            out << static_cast<unsigned int>(
                encoded
            );
        }

        out
            << "},"
            << static_cast<unsigned int>(key)
            << ")";

        return out.str();
    }

    std::string buildDecoder(
        const std::string& name
    )
    {
        std::ostringstream out;

        /*
         * IMPORTANT:
         *
         * Luau does NOT use the Lua 5.3 "~" operator.
         *
         * Roblox/Luau provides bit32.bxor().
         */

        out
            << "local "
            << name
            << "=function(t,k)"
            << "local r={}"
            << "for i=1,#t do"
            << "local m=(i-1)*37+19"
            << "m=m%256"
            << "r[i]=string.char(bit32.bxor(t[i],k,m))"
            << "end"
            << "return table.concat(r)"
            << "end";

        return out.str();
    }

    bool shouldEncode(
        const std::string& value
    )
    {
        /*
         * Avoid turning tiny directive-like strings into
         * runtime expressions.
         */
        if (value.empty())
            return false;

        return true;
    }
}

std::string Transformer::transform(
    const std::string& source
)
{
    if (source.empty())
        return {};

    const std::vector<Token> tokens =
        lex(source);

    const std::string decoder =
        makeName();

    std::ostringstream output;

    /*
     * Decoder is generated once per output.
     */
    output
        << buildDecoder(decoder)
        << "\n";

    /*
     * Add a harmless runtime value.
     *
     * No "~" operator is used anywhere.
     */
    const std::string guard =
        makeName();

    output
        << "local "
        << guard
        << "=bit32.band(1,1)"
        << "\n";

    std::size_t stringIndex = 0;

    for (const Token& token : tokens)
    {
        if (
            token.kind !=
            Token::Kind::String
        )
        {
            /*
             * Long strings, comments, whitespace and ordinary
             * source are copied exactly.
             */
            output << token.text;
            continue;
        }

        const std::string decoded =
            decodeQuotedString(
                token.text
            );

        if (
            !shouldEncode(decoded)
        )
        {
            output << token.text;
            continue;
        }

        ++stringIndex;

        /*
         * Every string gets its own key.
         */
        const std::uint8_t key =
            static_cast<std::uint8_t>(
                (
                    random32() ^
                    static_cast<std::uint32_t>(
                        stringIndex * 73u
                    )
                ) & 0xFFu
            );

        output
            << encodeString(
                decoded,
                key,
                decoder
            );
    }

    return output.str();
}