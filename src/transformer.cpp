#include "transformer.hpp"

#include <cctype>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
    struct Token
    {
        enum class Kind
        {
            Identifier,
            Number,
            String,
            LongString,
            Comment,
            Symbol,
            Whitespace,
            Other
        };

        Kind kind;
        std::string text;
    };

    bool isIdentifierStart(char c)
    {
        unsigned char u =
            static_cast<unsigned char>(c);

        return std::isalpha(u) || c == '_';
    }

    bool isIdentifierPart(char c)
    {
        unsigned char u =
            static_cast<unsigned char>(c);

        return std::isalnum(u) || c == '_';
    }

    bool isKeyword(const std::string& s)
    {
        static const std::unordered_set<std::string> keywords =
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
            "export"
        };

        return keywords.find(s) != keywords.end();
    }

    bool isProtectedName(const std::string& s)
    {
        static const std::unordered_set<std::string> names =
        {
            "game",
            "workspace",
            "script",
            "shared",
            "self",
            "_ENV",
            "_G",

            "print",
            "warn",
            "error",
            "assert",
            "pcall",
            "xpcall",
            "require",
            "pairs",
            "ipairs",
            "next",
            "select",
            "unpack",

            "type",
            "typeof",
            "tostring",
            "tonumber",

            "rawget",
            "rawset",
            "rawequal",
            "rawlen",
            "setmetatable",
            "getmetatable",

            "string",
            "table",
            "math",
            "coroutine",
            "task",
            "os",
            "debug",

            "Instance",
            "Enum",
            "Vector2",
            "Vector2int16",
            "Vector3",
            "Vector3int16",
            "CFrame",
            "Color3",
            "BrickColor",
            "UDim",
            "UDim2",
            "Ray",
            "RaycastParams",
            "Region3",

            "GetService",
            "WaitForChild",
            "FindFirstChild",
            "FindFirstChildOfClass",
            "FindFirstChildWhichIsA",
            "GetChildren",
            "GetDescendants",
            "IsA",
            "Clone",
            "Destroy",

            "Connect",
            "Once",
            "Fire",
            "FireServer",
            "InvokeServer"
        };

        return names.find(s) != names.end();
    }

    std::string makeIdentifier(
        unsigned int index
    )
    {
        static const char alphabet[] =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        constexpr unsigned int alphabetSize =
            sizeof(alphabet) - 1;

        std::string result = "__";

        do
        {
            result.push_back(
                alphabet[index % alphabetSize]
            );

            index /= alphabetSize;
        }
        while (index != 0);

        return result;
    }

    std::uint32_t randomKey()
    {
        std::random_device rd;

        std::uint32_t a =
            static_cast<std::uint32_t>(rd());

        std::uint32_t b =
            static_cast<std::uint32_t>(rd());

        std::uint32_t key =
            a ^
            (b * 0x9E3779B9u) ^
            0xA53C9E17u;

        if (key == 0)
            key = 0x6D2B79F5u;

        return key;
    }

    std::string randomHex()
    {
        std::random_device rd;

        std::uint64_t a =
            (static_cast<std::uint64_t>(rd()) << 32) ^
            static_cast<std::uint64_t>(rd());

        std::uint64_t b =
            (static_cast<std::uint64_t>(rd()) << 32) ^
            static_cast<std::uint64_t>(rd());

        std::uint64_t value =
            a ^ b ^ 0x9E3779B97F4A7C15ULL;

        std::ostringstream out;

        out << std::hex
            << value;

        return out.str();
    }

    std::string escapeLuauString(
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
                {
                    if (c < 32 || c >= 127)
                    {
                        out
                            << "\\"
                            << std::oct
                            << std::setw(3)
                            << std::setfill('0')
                            << static_cast<unsigned int>(c)
                            << std::dec;
                    }
                    else
                    {
                        out <<
                            static_cast<char>(c);
                    }

                    break;
                }
            }
        }

        return out.str();
    }

    std::vector<Token> lex(
        const std::string& source
    )
    {
        std::vector<Token> tokens;

        std::size_t i = 0;

        while (i < source.size())
        {
            const char c =
                source[i];

            /*
             * Whitespace
             */
            if (std::isspace(
                    static_cast<unsigned char>(c)))
            {
                std::size_t start = i;

                ++i;

                while (
                    i < source.size() &&
                    std::isspace(
                        static_cast<unsigned char>(
                            source[i]))
                )
                {
                    ++i;
                }

                tokens.push_back(
                {
                    Token::Kind::Whitespace,
                    source.substr(
                        start,
                        i - start)
                });

                continue;
            }

            /*
             * Comments
             */
            if (
                c == '-' &&
                i + 1 < source.size() &&
                source[i + 1] == '-'
            )
            {
                /*
                 * Long comment.
                 */
                if (
                    i + 3 < source.size() &&
                    source[i + 2] == '[' &&
                    source[i + 3] == '['
                )
                {
                    std::size_t start = i;

                    i += 4;

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

                    tokens.push_back(
                    {
                        Token::Kind::Comment,
                        source.substr(
                            start,
                            i - start)
                    });

                    continue;
                }

                std::size_t start = i;

                i += 2;

                while (
                    i < source.size() &&
                    source[i] != '\n'
                )
                {
                    ++i;
                }

                tokens.push_back(
                {
                    Token::Kind::Comment,
                    source.substr(
                        start,
                        i - start)
                });

                continue;
            }

            /*
             * Quoted strings.
             */
            if (c == '"' || c == '\'')
            {
                const char quote = c;

                std::size_t start = i;

                ++i;

                bool escaped = false;

                while (i < source.size())
                {
                    const char current =
                        source[i];

                    ++i;

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

                tokens.push_back(
                {
                    Token::Kind::String,
                    source.substr(
                        start,
                        i - start)
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

                tokens.push_back(
                {
                    Token::Kind::LongString,
                    source.substr(
                        start,
                        i - start)
                });

                continue;
            }

            /*
             * Identifiers.
             */
            if (isIdentifierStart(c))
            {
                std::size_t start = i;

                ++i;

                while (
                    i < source.size() &&
                    isIdentifierPart(source[i])
                )
                {
                    ++i;
                }

                tokens.push_back(
                {
                    Token::Kind::Identifier,
                    source.substr(
                        start,
                        i - start)
                });

                continue;
            }

            /*
             * Numbers.
             */
            if (
                std::isdigit(
                    static_cast<unsigned char>(c)) ||
                (
                    c == '.' &&
                    i + 1 < source.size() &&
                    std::isdigit(
                        static_cast<unsigned char>(
                            source[i + 1]))
                )
            )
            {
                std::size_t start = i;

                ++i;

                while (i < source.size())
                {
                    const char n =
                        source[i];

                    if (
                        std::isdigit(
                            static_cast<unsigned char>(n)) ||
                        std::isalpha(
                            static_cast<unsigned char>(n)) ||
                        n == '.' ||
                        n == '_' ||
                        n == '+' ||
                        n == '-'
                    )
                    {
                        ++i;
                    }
                    else
                    {
                        break;
                    }
                }

                tokens.push_back(
                {
                    Token::Kind::Number,
                    source.substr(
                        start,
                        i - start)
                });

                continue;
            }

            /*
             * Multi-character operators.
             */
            static const char* operators[] =
            {
                "...",
                "..=",
                "...",
                "==",
                "~=",
                "<=",
                ">=",
                "::",
                "//",
                "+=",
                "-=",
                "*=",
                "/=",
                "%=",
                "^=",
                ".."
            };

            bool matched = false;

            for (
                const char* op :
                operators
            )
            {
                const std::size_t length =
                    std::strlen(op);

                if (
                    i + length <= source.size() &&
                    source.compare(
                        i,
                        length,
                        op) == 0
                )
                {
                    tokens.push_back(
                    {
                        Token::Kind::Symbol,
                        std::string(op)
                    });

                    i += length;

                    matched = true;

                    break;
                }
            }

            if (matched)
                continue;

            /*
             * Single-character symbol.
             */
            tokens.push_back(
            {
                Token::Kind::Symbol,
                std::string(1, c)
            });

            ++i;
        }

        return tokens;
    }

    std::string decodeStringLiteral(
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

            const char next =
                token[++i];

            switch (next)
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
                     * Keep unknown Luau escapes intact.
                     */
                    result.push_back(next);
                    break;
            }
        }

        return result;
    }

    bool previousIsMemberAccess(
        const std::vector<Token>& tokens,
        std::size_t index
    )
    {
        if (index == 0)
            return false;

        std::size_t p = index;

        while (p > 0)
        {
            --p;

            if (
                tokens[p].kind ==
                Token::Kind::Whitespace
            )
            {
                continue;
            }

            return
                tokens[p].text == "." ||
                tokens[p].text == ":";
        }

        return false;
    }

    void renameLocals(
        std::vector<Token>& tokens
    )
    {
        std::unordered_map<
            std::string,
            std::string
        > replacements;

        unsigned int counter = 0;

        /*
         * Find explicit local declarations.
         */
        for (
            std::size_t i = 0;
            i < tokens.size();
            ++i
        )
        {
            if (
                tokens[i].kind !=
                Token::Kind::Identifier ||
                tokens[i].text != "local"
            )
            {
                continue;
            }

            std::size_t j = i + 1;

            while (j < tokens.size())
            {
                while (
                    j < tokens.size() &&
                    tokens[j].kind ==
                        Token::Kind::Whitespace
                )
                {
                    ++j;
                }

                if (
                    j >= tokens.size() ||
                    tokens[j].kind !=
                        Token::Kind::Identifier
                )
                {
                    break;
                }

                const std::string original =
                    tokens[j].text;

                if (
                    isKeyword(original) ||
                    isProtectedName(original) ||
                    previousIsMemberAccess(
                        tokens,
                        j)
                )
                {
                    break;
                }

                if (
                    replacements.find(original) ==
                    replacements.end()
                )
                {
                    replacements.emplace(
                        original,
                        makeIdentifier(
                            counter++)
                    );
                }

                tokens[j].text =
                    replacements[original];

                ++j;

                while (
                    j < tokens.size() &&
                    tokens[j].kind ==
                        Token::Kind::Whitespace
                )
                {
                    ++j;
                }

                if (
                    j < tokens.size() &&
                    tokens[j].text == ","
                )
                {
                    ++j;
                    continue;
                }

                break;
            }
        }

        /*
         * Replace references.
         */
        for (
            std::size_t i = 0;
            i < tokens.size();
            ++i
        )
        {
            if (
                tokens[i].kind !=
                Token::Kind::Identifier
            )
            {
                continue;
            }

            if (
                isKeyword(tokens[i].text)
            )
            {
                continue;
            }

            if (
                previousIsMemberAccess(
                    tokens,
                    i)
            )
            {
                continue;
            }

            auto found =
                replacements.find(
                    tokens[i].text);

            if (
                found !=
                replacements.end()
            )
            {
                tokens[i].text =
                    found->second;
            }
        }
    }

    std::string makeEncodedString(
        const std::string& value,
        std::uint32_t key,
        const std::string& decoder
    )
    {
        std::ostringstream out;

        out << decoder << "({";

        for (
            std::size_t i = 0;
            i < value.size();
            ++i
        )
        {
            const std::uint32_t byte =
                static_cast<unsigned char>(
                    value[i]);

            const std::uint32_t mixed =
                byte ^
                key ^
                (
                    static_cast<std::uint32_t>(
                        i * 131u) &
                    0xFFu
                );

            if (i != 0)
                out << ',';

            out << mixed;
        }

        out << "})";

        return out.str();
    }

    void encodeStrings(
        std::vector<Token>& tokens,
        std::uint32_t key,
        const std::string& decoder
    )
    {
        for (
            std::size_t i = 0;
            i < tokens.size();
            ++i
        )
        {
            if (
                tokens[i].kind !=
                Token::Kind::String
            )
            {
                continue;
            }

            /*
             * Do not touch strings used as
             * member/index names.
             *
             * Example:
             *
             * object["Name"]
             *
             * remains unchanged.
             */
            if (
                i > 0 &&
                previousIsMemberAccess(
                    tokens,
                    i)
            )
            {
                continue;
            }

            const std::string decoded =
                decodeStringLiteral(
                    tokens[i].text);

            /*
             * Empty strings are perfectly valid.
             */
            if (
                decoded.empty() &&
                tokens[i].text != "\"\"" &&
                tokens[i].text != "''"
            )
            {
                continue;
            }

            tokens[i].text =
                makeEncodedString(
                    decoded,
                    key,
                    decoder);

            tokens[i].kind =
                Token::Kind::Other;
        }
    }

    void transformSimpleNumbers(
        std::vector<Token>& tokens,
        std::uint32_t key
    )
    {
        for (
            Token& token :
            tokens
        )
        {
            if (
                token.kind !=
                Token::Kind::Number
            )
            {
                continue;
            }

            /*
             * Only transform simple integer
             * literals. This avoids changing
             * floating-point semantics.
             */
            bool integer = true;

            for (char c : token.text)
            {
                if (
                    !std::isdigit(
                        static_cast<unsigned char>(
                            c))
                )
                {
                    integer = false;
                    break;
                }
            }

            if (!integer)
                continue;

            try
            {
                long long value =
                    std::stoll(
                        token.text);

                /*
                 * Keep zero and very large values
                 * untouched.
                 */
                if (
                    value == 0 ||
                    value > 1000000
                )
                {
                    continue;
                }

                const std::uint32_t salt =
                    key ^
                    (
                        static_cast<
                            std::uint32_t>(
                                value) *
                        0x45D9F3Bu
                    );

                const long long encoded =
                    value ^
                    static_cast<long long>(
                        salt);

                std::ostringstream out;

                out
                    << "("
                    << encoded
                    << "~"
                    << static_cast<
                        unsigned long long>(
                            salt)
                    << ")";

                token.text =
                    out.str();

                token.kind =
                    Token::Kind::Other;
            }
            catch (...)
            {
                /*
                 * Leave unusual values alone.
                 */
            }
        }
    }

    std::string buildDecoder(
        std::uint32_t key,
        const std::string& decoder
    )
    {
        std::ostringstream out;

        out
            << "local function "
            << decoder
            << "(t)"
            << "local s=\"\";"
            << "for i=1,#t do "
            << "local v=t[i];"
            << "v=v~"
            << key
            << ";"
            << "v=v~((i-1)*131%256);"
            << "s=s..string.char(v);"
            << "end;"
            << "return s;"
            << "end;";

        return out.str();
    }

    std::string rebuild(
        const std::vector<Token>& tokens
    )
    {
        std::string result;

        Token::Kind previousKind =
            Token::Kind::Other;

        std::string previousText;

        for (
            const Token& token :
            tokens
        )
        {
            /*
             * Remove whitespace.
             */
            if (
                token.kind ==
                Token::Kind::Whitespace
            )
            {
                /*
                 * We decide later whether a
                 * separating space is necessary.
                 */
                continue;
            }

            /*
             * Remove comments.
             */
            if (
                token.kind ==
                Token::Kind::Comment
            )
            {
                continue;
            }

            if (!result.empty())
            {
                const char previous =
                    result.back();

                const char current =
                    token.text.empty()
                        ? '\0'
                        : token.text.front();

                /*
                 * Identifiers/numbers must be
                 * separated when adjacent.
                 */
                if (
                    isIdentifierPart(previous) &&
                    isIdentifierPart(current)
                )
                {
                    result.push_back(' ');
                }

                /*
                 * Prevent accidental -- comment
                 * formation.
                 */
                if (
                    previous == '-' &&
                    current == '-'
                )
                {
                    result.push_back(' ');
                }
            }

            result += token.text;

            previousKind =
                token.kind;

            previousText =
                token.text;
        }

        (void)previousKind;
        (void)previousText;

        return result;
    }
}

std::string Transformer::transform(
    const std::string& source
)
{
    if (source.empty())
        return {};

    /*
     * This implementation deliberately does
     * not depend on Luau's Parser/Compiler
     * headers. The backend can therefore
     * compile independently of changes in the
     * Luau API.
     */

    std::vector<Token> tokens =
        lex(source);

    if (tokens.empty())
        return {};

    const std::uint32_t key =
        randomKey();

    const std::string decoder =
        "__lp_" + randomHex();

    /*
     * Pass 1:
     * Conservative local renaming.
     */
    renameLocals(tokens);

    /*
     * Pass 2:
     * Runtime string encoding.
     */
    encodeStrings(
        tokens,
        key,
        decoder
    );

    /*
     * Pass 3:
     * Simple integer transformation.
     */
    transformSimpleNumbers(
        tokens,
        key
    );

    /*
     * Pass 4:
     * Remove comments and unnecessary
     * whitespace.
     */
    std::string body =
        rebuild(tokens);

    if (body.empty())
        return {};

    /*
     * Runtime decoder must appear before
     * encoded literals are executed.
     */
    const std::string runtime =
        buildDecoder(
            key,
            decoder
        );

    /*
     * A small opaque-looking runtime guard.
     * It does not affect program behavior.
     */
    const std::string guard =
        "local __lp_guard=(function()"
        "local a=17;"
        "local b=31;"
        "local c=a*7+b;"
        "return c-c;"
        "end)();";

    std::string output;

    output.reserve(
        runtime.size() +
        guard.size() +
        body.size() +
        16
    );

    output += runtime;
    output += guard;
    output += body;

    return output;
}