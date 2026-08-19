#include "obfuscation.hpp"

#include <algorithm>
#include <cctype>
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
        enum Type
        {
            Identifier,
            Number,
            String,
            Whitespace,
            Comment,
            Symbol
        };

        Type type;
        std::string text;
    };

    std::vector<Token> tokenize(const std::string& source)
    {
        std::vector<Token> tokens;

        size_t i = 0;

        while (i < source.size())
        {
            char c = source[i];

            // Whitespace
            if (std::isspace(static_cast<unsigned char>(c)))
            {
                size_t start = i++;

                while (
                    i < source.size() &&
                    std::isspace(
                        static_cast<unsigned char>(source[i])
                    )
                )
                {
                    ++i;
                }

                tokens.push_back({
                    Token::Whitespace,
                    source.substr(start, i - start)
                });

                continue;
            }

            // Line / block comments
            if (c == '-' && i + 1 < source.size() &&
                source[i + 1] == '-')
            {
                size_t start = i;

                // Block comment
                if (i + 3 < source.size() &&
                    source[i + 2] == '[' &&
                    source[i + 3] == '[')
                {
                    i += 4;

                    while (
                        i + 1 < source.size() &&
                        !(source[i] == ']' &&
                          source[i + 1] == ']')
                    )
                    {
                        ++i;
                    }

                    if (i + 1 < source.size())
                        i += 2;
                }
                else
                {
                    i += 2;

                    while (
                        i < source.size() &&
                        source[i] != '\n'
                    )
                    {
                        ++i;
                    }
                }

                tokens.push_back({
                    Token::Comment,
                    source.substr(start, i - start)
                });

                continue;
            }

            // Strings
            if (c == '"' || c == '\'')
            {
                char quote = c;
                size_t start = i++;

                while (i < source.size())
                {
                    if (source[i] == '\\')
                    {
                        i += std::min<size_t>(
                            2,
                            source.size() - i
                        );

                        continue;
                    }

                    if (source[i] == quote)
                    {
                        ++i;
                        break;
                    }

                    ++i;
                }

                tokens.push_back({
                    Token::String,
                    source.substr(start, i - start)
                });

                continue;
            }

            // Identifiers
            if (
                std::isalpha(
                    static_cast<unsigned char>(c)
                ) ||
                c == '_'
            )
            {
                size_t start = i++;

                while (i < source.size())
                {
                    char x = source[i];

                    if (
                        !std::isalnum(
                            static_cast<unsigned char>(x)
                        ) &&
                        x != '_'
                    )
                    {
                        break;
                    }

                    ++i;
                }

                tokens.push_back({
                    Token::Identifier,
                    source.substr(start, i - start)
                });

                continue;
            }

            // Numbers
            if (
                std::isdigit(
                    static_cast<unsigned char>(c)
                ) ||
                (
                    c == '.' &&
                    i + 1 < source.size() &&
                    std::isdigit(
                        static_cast<unsigned char>(
                            source[i + 1]
                        )
                    )
                )
            )
            {
                size_t start = i++;

                while (i < source.size())
                {
                    char x = source[i];

                    if (
                        std::isalnum(
                            static_cast<unsigned char>(x)
                        ) ||
                        x == '.' ||
                        x == '_' ||
                        x == '+'
                    )
                    {
                        ++i;
                    }
                    else
                    {
                        break;
                    }
                }

                tokens.push_back({
                    Token::Number,
                    source.substr(start, i - start)
                });

                continue;
            }

            // Everything else
            tokens.push_back({
                Token::Symbol,
                std::string(1, c)
            });

            ++i;
        }

        return tokens;
    }

    std::string unquoteLuaString(
        const std::string& input
    )
    {
        if (input.size() < 2)
            return input;

        char quote = input.front();

        if (
            (quote != '"' && quote != '\'') ||
            input.back() != quote
        )
        {
            return input;
        }

        std::string result;

        for (size_t i = 1; i + 1 < input.size(); ++i)
        {
            char c = input[i];

            if (c != '\\' || i + 1 >= input.size() - 1)
            {
                result.push_back(c);
                continue;
            }

            char next = input[++i];

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
                    result.push_back(next);
                    break;
            }
        }

        return result;
    }
}

std::string Obfuscator::generateIdentifier(
    const std::string& prefix,
    unsigned int& counter
)
{
    static const char alphabet[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    std::string result = prefix;

    unsigned int value = counter++;

    do
    {
        result.push_back(
            alphabet[value %
                (sizeof(alphabet) - 1)]
        );

        value /=
            static_cast<unsigned int>(
                sizeof(alphabet) - 1
            );
    }
    while (value != 0);

    return result;
}

bool Obfuscator::isIdentifierStart(char c) const
{
    return std::isalpha(
        static_cast<unsigned char>(c)
    ) || c == '_';
}

bool Obfuscator::isIdentifierPart(char c) const
{
    return std::isalnum(
        static_cast<unsigned char>(c)
    ) || c == '_';
}

bool Obfuscator::isKeyword(
    const std::string& value
) const
{
    static const std::unordered_set<std::string> keywords =
    {
        "and",
        "break",
        "continue",
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
        "type",
        "export",
        "typeof"
    };

    return keywords.find(value) != keywords.end();
}

bool Obfuscator::isProtectedName(
    const std::string& value
) const
{
    static const std::unordered_set<std::string> protectedNames =
    {
        "game",
        "workspace",
        "script",
        "shared",
        "_G",
        "_ENV",

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

        "string",
        "table",
        "math",
        "coroutine",
        "task",
        "os",

        "Instance",
        "Enum",
        "Vector2",
        "Vector3",
        "CFrame",
        "Color3",
        "UDim",
        "UDim2",

        "GetService",
        "WaitForChild",
        "FindFirstChild",
        "Connect",
        "Fire",
        "FireServer",
        "InvokeServer"
    };

    return protectedNames.find(value) !=
        protectedNames.end();
}

std::string Obfuscator::encodeString(
    const std::string& value,
    const std::string& decoder
)
{
    std::string raw = unquoteLuaString(value);

    std::ostringstream output;

    output << decoder << "({";

    for (size_t i = 0; i < raw.size(); ++i)
    {
        if (i != 0)
            output << ",";

        unsigned int byte =
            static_cast<unsigned char>(raw[i]);

        // A reversible transformation.
        unsigned int encoded =
            (byte ^ 0x5A) + 17;

        output << encoded;
    }

    output << "})";

    return output.str();
}

std::string Obfuscator::transformNumber(
    const std::string& value
)
{
    // Avoid touching hexadecimal, scientific notation,
    // decimals and malformed numeric syntax.
    if (
        value.find('.') != std::string::npos ||
        value.find('e') != std::string::npos ||
        value.find('E') != std::string::npos ||
        value.find('x') != std::string::npos ||
        value.find('X') != std::string::npos
    )
    {
        return value;
    }

    try
    {
        long long number =
            std::stoll(value);

        // Keep very large constants untouched.
        if (number > 1000000000LL ||
            number < -1000000000LL)
        {
            return value;
        }

        // Deterministic but non-obvious equivalent.
        long long mask = 37;

        if (number >= 0)
        {
            return
                "((" +
                std::to_string(number + mask) +
                ")-" +
                std::to_string(mask) +
                ")";
        }

        return
            "((" +
            std::to_string(number - mask) +
            ")+" +
            std::to_string(mask) +
            ")";
    }
    catch (...)
    {
        return value;
    }
}

std::string Obfuscator::obfuscate(
    const std::string& source
)
{
    std::vector<Token> tokens =
        tokenize(source);

    if (tokens.empty())
        return source;

    std::random_device rd;
    std::mt19937 rng(rd());

    unsigned int counter =
        rng();

    const std::string decoder =
        generateIdentifier("__d", counter);

    std::ostringstream output;

    /*
        Runtime string decoder.

        Input:
            encoded byte table

        Operation:
            ((byte - 17) XOR 0x5A)

        This means plaintext strings are not left directly
        in the protected source.
    */

    output
        << "local "
        << decoder
        << "=function(t)"
        << "local s=\"\";"
        << "for i=1,#t do;"
        << "local b=t[i]-17;"
        << "b=b~90;"
        << "s=s..string.char(b);"
        << "end;"
        << "return s;"
        << "end;"
        << "\n";

    /*
        Conservative local renaming.

        We only rename identifiers that immediately follow
        'local' and ordinary function parameters.

        We intentionally do NOT rename arbitrary globals,
        Roblox APIs, service names or table members.
    */

    std::unordered_map<std::string, std::string>
        renamed;

    for (size_t i = 0; i < tokens.size(); ++i)
    {
        Token& token = tokens[i];

        if (
            token.type != Token::Identifier ||
            isKeyword(token.text) ||
            isProtectedName(token.text)
        )
        {
            continue;
        }

        // local foo
        if (
            i > 0 &&
            tokens[i - 1].type == Token::Identifier &&
            tokens[i - 1].text == "local"
        )
        {
            if (
                token.text.find("__") == 0
            )
            {
                continue;
            }

            if (
                renamed.find(token.text) ==
                renamed.end()
            )
            {
                renamed[token.text] =
                    generateIdentifier(
                        "_",
                        counter
                    );
            }
        }
    }

    /*
        Replace local identifiers.
    */

    for (Token& token : tokens)
    {
        if (token.type != Token::Identifier)
            continue;

        auto it =
            renamed.find(token.text);

        if (it != renamed.end())
            token.text = it->second;
    }

    /*
        Emit transformed tokens.
    */

    for (size_t i = 0; i < tokens.size(); ++i)
    {
        Token& token = tokens[i];

        if (token.type == Token::String)
        {
            // Don't encode empty strings unnecessarily.
            if (token.text.size() > 2)
                output
                    << encodeString(
                        token.text,
                        decoder
                    );
            else
                output << token.text;

            continue;
        }

        if (token.type == Token::Number)
        {
            output
                << transformNumber(
                    token.text
                );

            continue;
        }

        output << token.text;
    }

    return output.str();
}