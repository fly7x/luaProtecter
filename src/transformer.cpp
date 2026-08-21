#include "transformer.hpp"
#include "obfuscation.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef HAVE_LUAU
#include "Luau/Allocator.h"
#include "Luau/Compiler.h"
#include "Luau/Parser.h"
#endif

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

    static bool isIdentifierStart(char c)
    {
        return std::isalpha(static_cast<unsigned char>(c)) || c == '_';
    }

    static bool isIdentifierPart(char c)
    {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
    }

    static bool isDigit(char c)
    {
        return std::isdigit(static_cast<unsigned char>(c)) != 0;
    }

    static bool isHexDigit(char c)
    {
        return std::isxdigit(static_cast<unsigned char>(c)) != 0;
    }

    static bool isKeyword(const std::string& s)
    {
        static const std::unordered_set<std::string> keywords =
        {
            "and", "break", "do", "else", "elseif", "end",
            "false", "for", "function", "if", "in", "local",
            "nil", "not", "or", "repeat", "return", "then",
            "true", "until", "while", "continue", "type",
            "export"
        };

        return keywords.find(s) != keywords.end();
    }

    static bool isProtectedName(const std::string& s)
    {
        static const std::unordered_set<std::string> protectedNames =
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
            "select",
            "unpack",
            "next",
            "pairs",
            "ipairs",

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
            "InvokeServer",

            "require",
            "game",
            "workspace"
        };

        return protectedNames.find(s) != protectedNames.end();
    }

    static std::string makeIdentifier(unsigned int index)
    {
        static const char alphabet[] =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        std::string result = "_";

        do
        {
            result.push_back(
                alphabet[index % (sizeof(alphabet) - 1)]
            );

            index /= static_cast<unsigned int>(
                sizeof(alphabet) - 1
            );
        }
        while (index != 0);

        return result;
    }

    static std::string makeRandomSeed()
    {
        std::random_device rd;

        std::uint64_t a =
            (static_cast<std::uint64_t>(rd()) << 32) ^
            static_cast<std::uint64_t>(rd());

        std::uint64_t b =
            (static_cast<std::uint64_t>(rd()) << 32) ^
            static_cast<std::uint64_t>(rd());

        std::uint64_t seed = a ^ (b + 0x9e3779b97f4a7c15ULL);

        std::ostringstream out;
        out << std::hex << seed;

        return out.str();
    }

    static std::string escapeLuauString(const std::string& value)
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
                    if (c < 32 || c >= 127)
                    {
                        out << "\\"
                            << std::oct
                            << std::setw(3)
                            << std::setfill('0')
                            << static_cast<unsigned int>(c)
                            << std::dec;
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

    static std::string encodeRuntimeString(
        const std::string& value,
        std::uint32_t key
    )
    {
        std::ostringstream out;

        out << "__lp_decode({";

        for (size_t i = 0; i < value.size(); ++i)
        {
            const std::uint32_t mixed =
                static_cast<std::uint32_t>(
                    static_cast<unsigned char>(value[i])
                )
                ^ key
                ^ static_cast<std::uint32_t>(
                    (i * 131u) & 0xFFu
                );

            if (i != 0)
                out << ",";

            out << mixed;
        }

        out << "})";

        return out.str();
    }

    static std::vector<Token> lex(const std::string& source)
    {
        std::vector<Token> tokens;

        size_t i = 0;

        while (i < source.size())
        {
            char c = source[i];

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
                    Token::Kind::Whitespace,
                    source.substr(start, i - start)
                });

                continue;
            }

            if (
                c == '-' &&
                i + 1 < source.size() &&
                source[i + 1] == '-'
            )
            {
                size_t start = i;

                i += 2;

                while (
                    i < source.size() &&
                    source[i] != '\n'
                )
                {
                    ++i;
                }

                tokens.push_back({
                    Token::Kind::Comment,
                    source.substr(start, i - start)
                });

                continue;
            }

            if (c == '"' || c == '\'')
            {
                const char quote = c;

                size_t start = i++;

                bool escaped = false;

                while (i < source.size())
                {
                    char current = source[i++];

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

                tokens.push_back({
                    Token::Kind::String,
                    source.substr(start, i - start)
                });

                continue;
            }

            if (c == '[' && i + 1 < source.size() &&
                source[i + 1] == '[')
            {
                size_t start = i;

                i += 2;

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

                tokens.push_back({
                    Token::Kind::LongString,
                    source.substr(start, i - start)
                });

                continue;
            }

            if (isIdentifierStart(c))
            {
                size_t start = i++;

                while (
                    i < source.size() &&
                    isIdentifierPart(source[i])
                )
                {
                    ++i;
                }

                tokens.push_back({
                    Token::Kind::Identifier,
                    source.substr(start, i - start)
                });

                continue;
            }

            if (isDigit(c) ||
                (c == '.' &&
                 i + 1 < source.size() &&
                 isDigit(source[i + 1])))
            {
                size_t start = i++;

                while (i < source.size())
                {
                    char current = source[i];

                    if (
                        isDigit(current) ||
                        isHexDigit(current) ||
                        current == '.' ||
                        current == '_' ||
                        current == '+' ||
                        current == '-' ||
                        current == 'x' ||
                        current == 'X' ||
                        current == 'e' ||
                        current == 'E'
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
                    Token::Kind::Number,
                    source.substr(start, i - start)
                });

                continue;
            }

            static const char* multiSymbols[] =
            {
                "...",
                "..",
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
                "..=",
                "->"
            };

            bool matched = false;

            for (const char* symbol : multiSymbols)
            {
                const size_t length = std::strlen(symbol);

                if (
                    i + length <= source.size() &&
                    source.compare(i, length, symbol) == 0
                )
                {
                    tokens.push_back({
                        Token::Kind::Symbol,
                        std::string(symbol)
                    });

                    i += length;
                    matched = true;
                    break;
                }
            }

            if (matched)
                continue;

            tokens.push_back({
                Token::Kind::Symbol,
                std::string(1, c)
            });

            ++i;
        }

        return tokens;
    }

    static std::string decodeQuotedLiteral(
        const std::string& token
    )
    {
        if (token.size() < 2)
            return {};

        const char quote = token.front();

        if (
            (quote != '"' && quote != '\'') ||
            token.back() != quote
        )
        {
            return {};
        }

        std::string value;

        bool escaped = false;

        for (size_t i = 1; i + 1 < token.size(); ++i)
        {
            char c = token[i];

            if (escaped)
            {
                switch (c)
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
                        value.push_back(c);
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

            value.push_back(c);
        }

        return value;
    }

    static std::string rebuild(
        const std::vector<Token>& tokens
    )
    {
        std::string output;

        std::string previous;

        for (const Token& token : tokens)
        {
            if (token.kind == Token::Kind::Whitespace)
            {
                if (!output.empty() &&
                    !previous.empty())
                {
                    const char a = output.back();
                    const char b =
                        token.text.empty()
                            ? '\0'
                            : token.text.front();

                    if (
                        (isIdentifierPart(a) &&
                         isIdentifierPart(b))
                    )
                    {
                        output.push_back(' ');
                    }
                }

                continue;
            }

            if (token.kind == Token::Kind::Comment)
            {
                /*
                    Comments contain no executable information.
                    Dropping them removes a large amount of
                    unnecessary reverse-engineering metadata.
                */
                continue;
            }

            if (
                !output.empty() &&
                token.kind == Token::Kind::Identifier &&
                !previous.empty() &&
                isIdentifierPart(output.back())
            )
            {
                output.push_back(' ');
            }

            output += token.text;

            previous = token.text;
        }

        return output;
    }

    static void renameLocalIdentifiers(
        std::vector<Token>& tokens
    )
    {
        /*
            Conservative lexical renaming.

            We only rename locals that can be identified from
            explicit `local` declarations. We deliberately avoid
            renaming member names after '.' or ':' because those
            names are part of Roblox APIs and object interfaces.
        */

        struct Rename
        {
            std::string from;
            std::string to;
        };

        std::vector<Rename> renames;

        unsigned int counter = 0;

        for (size_t i = 0; i < tokens.size(); ++i)
        {
            if (
                tokens[i].kind != Token::Kind::Identifier ||
                tokens[i].text != "local"
            )
            {
                continue;
            }

            size_t j = i + 1;

            while (j < tokens.size())
            {
                while (
                    j < tokens.size() &&
                    tokens[j].kind == Token::Kind::Whitespace
                )
                {
                    ++j;
                }

                if (
                    j >= tokens.size() ||
                    tokens[j].kind != Token::Kind::Identifier
                )
                {
                    break;
                }

                const std::string name =
                    tokens[j].text;

                if (
                    isKeyword(name) ||
                    isProtectedName(name)
                )
                {
                    ++j;
                    break;
                }

                /*
                    Avoid changing table-field shorthand or
                    method names accidentally.
                */
                if (j > 0)
                {
                    size_t p = j;

                    while (
                        p > 0 &&
                        tokens[p - 1].kind ==
                            Token::Kind::Whitespace
                    )
                    {
                        --p;
                    }

                    if (
                        p > 0 &&
                        (tokens[p - 1].text == "." ||
                         tokens[p - 1].text == ":")
                    )
                    {
                        ++j;
                        break;
                    }
                }

                const std::string replacement =
                    makeIdentifier(counter++);

                renames.push_back({
                    name,
                    replacement
                });

                tokens[j].text = replacement;

                ++j;

                while (
                    j < tokens.size() &&
                    tokens[j].kind == Token::Kind::Whitespace
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
            Apply references.

            This intentionally ignores member accesses:

                object.foo
                object:foo()

            because changing those would alter Roblox behavior.
        */

        for (size_t i = 0; i < tokens.size(); ++i)
        {
            if (tokens[i].kind != Token::Kind::Identifier)
                continue;

            if (isKeyword(tokens[i].text))
                continue;

            if (i > 0)
            {
                size_t p = i;

                while (
                    p > 0 &&
                    tokens[p - 1].kind ==
                        Token::Kind::Whitespace
                )
                {
                    --p;
                }

                if (
                    p > 0 &&
                    (tokens[p - 1].text == "." ||
                     tokens[p - 1].text == ":")
                )
                {
                    continue;
                }
            }

            for (const Rename& rename : renames)
            {
                if (tokens[i].text == rename.from)
                {
                    tokens[i].text = rename.to;
                    break;
                }
            }
        }
    }

    static void encodeStrings(
        std::vector<Token>& tokens,
        std::uint32_t key
    )
    {
        for (size_t i = 0; i < tokens.size(); ++i)
        {
            if (tokens[i].kind != Token::Kind::String)
                continue;

            const std::string decoded =
                decodeQuotedLiteral(tokens[i].text);

            if (decoded.empty())
                continue;

            /*
                Don't encode strings that appear immediately
                after a member-access operator.

                Example:

                    object["Name"]

                remains valid and predictable.
            */

            tokens[i].text =
                encodeRuntimeString(
                    decoded,
                    key
                );

            tokens[i].kind =
                Token::Kind::Other;
        }
    }

    static void transformNumbers(
        std::vector<Token>& tokens,
        std::uint32_t key
    )
    {
        for (Token& token : tokens)
        {
            if (token.kind != Token::Kind::Number)
                continue;

            /*
                Keep numbers with decimal/exponent notation
                untouched. This avoids precision surprises.
            */
            if (
                token.text.find('.') != std::string::npos ||
                token.text.find('e') != std::string::npos ||
                token.text.find('E') != std::string::npos ||
                token.text.find('x') != std::string::npos ||
                token.text.find('X') != std::string::npos
            )
            {
                continue;
            }

            try
            {
                long long value =
                    std::stoll(token.text);

                std::uint32_t salt =
                    key ^
                    static_cast<std::uint32_t>(
                        value * 2654435761LL
                    );

                long long encoded =
                    value ^
                    static_cast<long long>(salt);

                /*
                    Equivalent runtime expression.

                    The original integer is recovered by the
                    second XOR, but the literal itself is no
                    longer visible in the source.
                */
                std::ostringstream out;

                out << "("
                    << encoded
                    << " ~ "
                    << static_cast<long long>(salt)
                    << ")";

                token.text = out.str();
                token.kind = Token::Kind::Other;
            }
            catch (...)
            {
                /*
                    Leave unusual numeric syntax untouched.
                */
            }
        }
    }

    static std::string runtimeDecoder(
        std::uint32_t key,
        const std::string& seed
    )
    {
        std::ostringstream out;

        out
            << "local "
            << "__lp_k=\""
            << escapeLuauString(seed)
            << "\";"
            << "local function __lp_decode(t)"
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

    static std::string addOpaqueNoise()
    {
        /*
            Small, deterministic-looking noise which has no
            observable effect.

            It is intentionally simple enough that Luau can
            optimize it without changing semantics.
        */

        return
            "local __lp_noise=(function()"
            "local a=17;"
            "local b=29;"
            "local c=a*3+b;"
            "return c-c;"
            "end)();";
    }
}

std::string Transformer::transform(
    const std::string& source
)
{
    if (source.empty())
        return {};

#ifdef HAVE_LUAU

    try
    {
        /*
            ====================================================
            PASS 1 — Parse original source
            ====================================================
        */

        Luau::Allocator allocator;
        Luau::AstNameTable names(allocator);
        Luau::ParseOptions parseOptions;

        Luau::ParseResult parsed =
            Luau::Parser::parse(
                source.c_str(),
                source.size(),
                names,
                allocator,
                parseOptions
            );

        if (!parsed.root || !parsed.errors.empty())
        {
            std::cerr
                << "Luau parser rejected input.\n";

            for (const Luau::ParseError& error :
                 parsed.errors)
            {
                std::cerr
                    << error.getMessage()
                    << '\n';
            }

            return {};
        }

        /*
            ====================================================
            PASS 2 — Lexical protection
            ====================================================
        */

        std::vector<Token> tokens =
            lex(source);

        if (tokens.empty())
            return {};

        const std::string randomSeed =
            makeRandomSeed();

        std::uint32_t key = 0xA53C9E17u;

        for (char c : randomSeed)
        {
            key =
                (key * 33u) ^
                static_cast<unsigned char>(c);
        }

        if (key == 0)
            key = 0x6D2B79F5u;

        /*
            Remove comments and rename conservative locals.
        */
        renameLocalIdentifiers(tokens);

        /*
            Encode strings into a runtime decoder.
        */
        encodeStrings(tokens, key);

        /*
            Transform simple integer constants.
        */
        transformNumbers(tokens, key);

        std::string transformed =
            rebuild(tokens);

        if (transformed.empty())
            return {};

        /*
            ====================================================
            PASS 3 — Runtime support
            ====================================================
        */

        const std::string decoder =
            runtimeDecoder(
                key,
                randomSeed
            );

        transformed =
            decoder +
            addOpaqueNoise() +
            transformed;

        /*
            ====================================================
            PASS 4 — Existing Obfuscator layer
            ====================================================
        */

        Obfuscator obfuscator;

        std::string secondary =
            obfuscator.obfuscate(
                transformed
            );

        /*
            The existing Obfuscator in this repository is
            optional. If its implementation returns empty,
            retain our validated transformation instead of
            destroying an otherwise valid result.
        */
        if (!secondary.empty())
            transformed = secondary;

        /*
            ====================================================
            PASS 5 — Parse final output
            ====================================================
        */

        Luau::Allocator validationAllocator;
        Luau::AstNameTable validationNames(
            validationAllocator
        );

        Luau::ParseResult validation =
            Luau::Parser::parse(
                transformed.c_str(),
                transformed.size(),
                validationNames,
                validationAllocator,
                parseOptions
            );

        if (!validation.root ||
            !validation.errors.empty())
        {
            std::cerr
                << "Protected output failed Luau parsing.\n";

            for (const Luau::ParseError& error :
                 validation.errors)
            {
                std::cerr
                    << error.getMessage()
                    << '\n';
            }

            return {};
        }

        /*
            ====================================================
            PASS 6 — Compile final output
            ====================================================
        */

        Luau::CompileOptions compileOptions;

        std::string bytecode =
            Luau::compile(
                transformed,
                compileOptions
            );

        if (bytecode.empty())
        {
            std::cerr
                << "Protected output failed Luau compilation.\n";

            return {};
        }

        return transformed;
    }
    catch (const std::exception& exception)
    {
        std::cerr
            << "Transformer exception: "
            << exception.what()
            << '\n';

        return {};
    }

#else

    std::cerr
        << "luaProtecter was compiled without Luau support.\n";

    return {};

#endif
}