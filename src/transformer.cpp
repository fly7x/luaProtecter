#include "transformer.hpp"

#include <cctype>
#include <cstdint>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace
{
    /*
     * ---------------------------------------------------------
     * Random identifier generation
     * ---------------------------------------------------------
     */

    class Random
    {
    public:
        Random()
            : engine(
                std::random_device{}()
            )
        {
        }

        std::uint32_t u32()
        {
            return engine();
        }

        char letter()
        {
            static constexpr char letters[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            return letters[
                engine() %
                (sizeof(letters) - 1)
            ];
        }

        char identifierChar()
        {
            static constexpr char chars[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "0123456789";

            return chars[
                engine() %
                (sizeof(chars) - 1)
            ];
        }

    private:
        std::mt19937 engine;
    };

    /*
     * ---------------------------------------------------------
     * Luau keywords
     * ---------------------------------------------------------
     */

    bool isKeyword(
        const std::string& value
    )
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

        return keywords.find(value) != keywords.end();
    }

    bool isIdentifierStart(
        char c
    )
    {
        return
            std::isalpha(
                static_cast<unsigned char>(c)
            ) ||
            c == '_';
    }

    bool isIdentifierPart(
        char c
    )
    {
        return
            std::isalnum(
                static_cast<unsigned char>(c)
            ) ||
            c == '_';
    }

    /*
     * ---------------------------------------------------------
     * Identifier generator
     * ---------------------------------------------------------
     */

    std::string makeIdentifier(
        Random& random,
        std::unordered_set<std::string>& used
    )
    {
        for (;;)
        {
            std::string result;

            result += random.letter();

            const std::size_t length =
                7 + (random.u32() % 10);

            for (std::size_t i = 1; i < length; ++i)
                result += random.identifierChar();

            if (
                !isKeyword(result) &&
                used.insert(result).second
            )
            {
                return result;
            }
        }
    }

    /*
     * ---------------------------------------------------------
     * Lexer
     *
     * This deliberately does NOT use regex replacement.
     *
     * Strings/comments are copied without touching their
     * contents, preventing accidental replacements inside:
     *
     *     "local player"
     *     -- local player
     *     [[ local player ]]
     * ---------------------------------------------------------
     */

    enum class TokenType
    {
        Identifier,
        Number,
        String,
        LongString,
        Comment,
        Symbol,
        Whitespace
    };

    struct Token
    {
        TokenType type;
        std::string text;
    };

    bool startsLongString(
        const std::string& source,
        std::size_t position
    )
    {
        return
            position + 1 < source.size() &&
            source[position] == '[' &&
            source[position + 1] == '[';
    }

    std::size_t consumeLongString(
        const std::string& source,
        std::size_t position
    )
    {
        const std::size_t end =
            source.find(
                "]]",
                position + 2
            );

        if (end == std::string::npos)
            return source.size();

        return end + 2;
    }

    std::size_t consumeQuotedString(
        const std::string& source,
        std::size_t position
    )
    {
        const char quote =
            source[position];

        std::size_t i =
            position + 1;

        while (i < source.size())
        {
            if (source[i] == '\\')
            {
                if (i + 1 < source.size())
                    i += 2;
                else
                    ++i;

                continue;
            }

            if (source[i] == quote)
                return i + 1;

            ++i;
        }

        return source.size();
    }

    std::vector<Token> tokenize(
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
            if (
                std::isspace(
                    static_cast<unsigned char>(c)
                )
            )
            {
                const std::size_t start = i;

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

                tokens.push_back(
                    {
                        TokenType::Whitespace,
                        source.substr(
                            start,
                            i - start
                        )
                    }
                );

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
                const std::size_t start = i;

                i += 2;

                /*
                 * Long comment.
                 */
                if (
                    i < source.size() &&
                    source[i] == '[' &&
                    i + 1 < source.size() &&
                    source[i + 1] == '['
                )
                {
                    i =
                        consumeLongString(
                            source,
                            i
                        );
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

                tokens.push_back(
                    {
                        TokenType::Comment,
                        source.substr(
                            start,
                            i - start
                        )
                    }
                );

                continue;
            }

            /*
             * Long strings.
             */
            if (startsLongString(source, i))
            {
                const std::size_t start = i;

                i =
                    consumeLongString(
                        source,
                        i
                    );

                tokens.push_back(
                    {
                        TokenType::LongString,
                        source.substr(
                            start,
                            i - start
                        )
                    }
                );

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
                const std::size_t start = i;

                i =
                    consumeQuotedString(
                        source,
                        i
                    );

                tokens.push_back(
                    {
                        TokenType::String,
                        source.substr(
                            start,
                            i - start
                        )
                    }
                );

                continue;
            }

            /*
             * Identifiers.
             */
            if (isIdentifierStart(c))
            {
                const std::size_t start = i;

                ++i;

                while (
                    i < source.size() &&
                    isIdentifierPart(
                        source[i]
                    )
                )
                {
                    ++i;
                }

                tokens.push_back(
                    {
                        TokenType::Identifier,
                        source.substr(
                            start,
                            i - start
                        )
                    }
                );

                continue;
            }

            /*
             * Numbers.
             *
             * We keep the entire numeric literal together.
             */
            if (
                std::isdigit(
                    static_cast<unsigned char>(c)
                )
            )
            {
                const std::size_t start = i;

                ++i;

                while (
                    i < source.size()
                )
                {
                    const char n =
                        source[i];

                    if (
                        std::isalnum(
                            static_cast<unsigned char>(
                                n
                            )
                        ) ||
                        n == '.' ||
                        n == '_'
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
                        TokenType::Number,
                        source.substr(
                            start,
                            i - start
                        )
                    }
                );

                continue;
            }

            /*
             * Multi-character Luau operators.
             */
            static constexpr const char* operators[] =
            {
                "...",
                "..=",
                "==",
                "~=",
                "<=",
                ">=",
                "//",
                "->",
                "+=",
                "-=",
                "*=",
                "/=",
                "%=",
                "^=",
                "&=",
                "|=",
                "<<",
                ">>",
                "::"
            };

            bool foundOperator = false;

            for (const char* op : operators)
            {
                const std::size_t length =
                    std::char_traits<char>::length(op);

                if (
                    i + length <= source.size() &&
                    source.compare(
                        i,
                        length,
                        op
                    ) == 0
                )
                {
                    tokens.push_back(
                        {
                            TokenType::Symbol,
                            std::string(
                                op,
                                length
                            )
                        }
                    );

                    i += length;

                    foundOperator = true;
                    break;
                }
            }

            if (foundOperator)
                continue;

            /*
             * Single-character symbol.
             */
            tokens.push_back(
                {
                    TokenType::Symbol,
                    std::string(
                        1,
                        c
                    )
                }
            );

            ++i;
        }

        return tokens;
    }

    /*
     * ---------------------------------------------------------
     * String escaping
     *
     * Converts ordinary quoted strings into numeric escapes.
     *
     * Example:
     *
     *     "Hello"
     *
     * becomes something similar to:
     *
     *     "\72\101\108\108\111"
     *
     * This remains valid Luau source.
     * ---------------------------------------------------------
     */

    std::string encodeString(
        const std::string& token
    )
    {
        if (token.size() < 2)
            return token;

        const char quote =
            token.front();

        if (
            quote != '"' &&
            quote != '\''
        )
        {
            return token;
        }

        if (token.back() != quote)
            return token;

        std::string result;

        result += '"';

        /*
         * We intentionally decode only simple source characters
         * here. Existing escape sequences are retained so we
         * don't change semantics accidentally.
         */
        for (
            std::size_t i = 1;
            i + 1 < token.size();
            ++i
        )
        {
            const unsigned char c =
                static_cast<unsigned char>(
                    token[i]
                );

            if (c == '\\')
            {
                /*
                 * Preserve an existing escape sequence.
                 */
                result += '\\';

                if (i + 1 < token.size() - 1)
                {
                    result += token[i + 1];
                    ++i;
                }

                continue;
            }

            /*
             * Keep quotes safe.
             */
            if (c == '"')
            {
                result += "\\\"";
                continue;
            }

            /*
             * Numeric escape.
             */
            result += '\\';

            result +=
                std::to_string(
                    static_cast<unsigned int>(c)
                );
        }

        result += '"';

        return result;
    }

    /*
     * ---------------------------------------------------------
     * Identifier renaming
     *
     * This pass deliberately focuses on identifiers that are
     * declared with "local".
     *
     * It does not blindly replace every occurrence of a word.
     * That would break table fields and globals.
     * ---------------------------------------------------------
     */

    struct RenameState
    {
        std::unordered_map<std::string, std::string> names;
        std::unordered_set<std::string> generated;
        Random random;
    };

    bool isLocalDeclaration(
        const std::vector<Token>& tokens,
        std::size_t index
    )
    {
        if (
            index >= tokens.size() ||
            tokens[index].type != TokenType::Identifier ||
            tokens[index].text != "local"
        )
        {
            return false;
        }

        return true;
    }

    bool isDeclarationIdentifier(
        const std::vector<Token>& tokens,
        std::size_t index
    )
    {
        if (index == 0)
            return false;

        if (
            tokens[index - 1].type !=
            TokenType::Identifier
        )
        {
            return false;
        }

        return
            tokens[index - 1].text ==
            "local";
    }

    /*
     * Determine whether an identifier is obviously being used
     * as a property/table key rather than a variable.
     *
     * We don't rename:
     *
     *     object.name
     *     object:name
     *     ["name"]
     */
    bool isPropertyName(
        const std::vector<Token>& tokens,
        std::size_t index
    )
    {
        if (index == 0)
            return false;

        std::size_t previous = index;

        while (previous > 0)
        {
            --previous;

            if (
                tokens[previous].type ==
                TokenType::Whitespace
            )
            {
                continue;
            }

            if (
                tokens[previous].type ==
                TokenType::Comment
            )
            {
                continue;
            }

            return
                tokens[previous].text == "." ||
                tokens[previous].text == ":";
        }

        return false;
    }

    void collectLocalNames(
        const std::vector<Token>& tokens,
        RenameState& state
    )
    {
        for (
            std::size_t i = 0;
            i < tokens.size();
            ++i
        )
        {
            if (!isLocalDeclaration(tokens, i))
                continue;

            std::size_t j = i + 1;

            while (j < tokens.size())
            {
                if (
                    tokens[j].type ==
                    TokenType::Whitespace
                )
                {
                    ++j;
                    continue;
                }

                if (
                    tokens[j].type ==
                    TokenType::Comment
                )
                {
                    ++j;
                    continue;
                }

                /*
                 * A local function declaration:
                 *
                 * local function foo(...)
                 */
                if (
                    tokens[j].type ==
                    TokenType::Identifier &&
                    tokens[j].text ==
                    "function"
                )
                {
                    ++j;

                    while (
                        j < tokens.size() &&
                        tokens[j].type ==
                        TokenType::Whitespace
                    )
                    {
                        ++j;
                    }

                    if (
                        j < tokens.size() &&
                        tokens[j].type ==
                        TokenType::Identifier
                    )
                    {
                        const std::string oldName =
                            tokens[j].text;

                        if (
                            !isKeyword(oldName) &&
                            state.names.find(oldName) ==
                                state.names.end()
                        )
                        {
                            state.names[oldName] =
                                makeIdentifier(
                                    state.random,
                                    state.generated
                                );
                        }
                    }

                    break;
                }

                /*
                 * Normal local declaration.
                 *
                 * local foo, bar, baz = ...
                 */
                if (
                    tokens[j].type !=
                    TokenType::Identifier
                )
                {
                    break;
                }

                const std::string name =
                    tokens[j].text;

                if (
                    !isKeyword(name) &&
                    state.names.find(name) ==
                        state.names.end()
                )
                {
                    state.names[name] =
                        makeIdentifier(
                            state.random,
                            state.generated
                        );
                }

                ++j;

                /*
                 * Continue through comma-separated
                 * declarations.
                 */
                while (
                    j < tokens.size() &&
                    tokens[j].type ==
                    TokenType::Whitespace
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
    }

    std::string rebuild(
        const std::vector<Token>& tokens
    )
    {
        RenameState state;

        collectLocalNames(
            tokens,
            state
        );

        std::ostringstream output;

        for (
            std::size_t i = 0;
            i < tokens.size();
            ++i
        )
        {
            const Token& token =
                tokens[i];

            /*
             * Remove comments completely.
             */
            if (
                token.type ==
                TokenType::Comment
            )
            {
                /*
                 * Preserve a newline if the comment contained
                 * one so tokens don't accidentally merge.
                 */
                if (
                    token.text.find('\n') !=
                    std::string::npos
                )
                {
                    output << '\n';
                }

                continue;
            }

            /*
             * Collapse whitespace later.
             */
            if (
                token.type ==
                TokenType::Whitespace
            )
            {
                /*
                 * Keep at most one separator.
                 */
                if (
                    output.tellp() > 0
                )
                {
                    output << ' ';
                }

                continue;
            }

            /*
             * Encode strings.
             */
            if (
                token.type ==
                TokenType::String
            )
            {
                output <<
                    encodeString(
                        token.text
                    );

                continue;
            }

            /*
             * Long strings remain untouched.
             */
            if (
                token.type ==
                TokenType::LongString
            )
            {
                output <<
                    token.text;

                continue;
            }

            /*
             * Rename local identifiers.
             */
            if (
                token.type ==
                TokenType::Identifier &&
                !isKeyword(token.text) &&
                !isPropertyName(tokens, i)
            )
            {
                const auto found =
                    state.names.find(
                        token.text
                    );

                if (
                    found !=
                    state.names.end()
                )
                {
                    output <<
                        found->second;

                    continue;
                }
            }

            output <<
                token.text;
        }

        return output.str();
    }

    /*
     * ---------------------------------------------------------
     * A tiny amount of harmless constant transformation.
     *
     * We intentionally don't rewrite arbitrary expressions.
     * The goal is to preserve Luau semantics.
     * ---------------------------------------------------------
     */

    std::string addHeader(
        const std::string& source,
        Random& random
    )
    {
        std::ostringstream output;

        const std::string marker =
            makeIdentifier(
                random,
                *new std::unordered_set<std::string>()
            );

        /*
         * Use a local that is optimized away by Luau.
         *
         * The generated identifier itself is randomized.
         */
        output
            << "local "
            << marker
            << "=nil\n";

        output << source;

        return output.str();
    }
}

/*
 * -------------------------------------------------------------
 * Transformer
 * -------------------------------------------------------------
 */

std::string Transformer::transform(
    const std::string& source
)
{
    if (source.empty())
        return {};

    const std::vector<Token> tokens =
        tokenize(source);

    if (tokens.empty())
        return {};

    std::string result =
        rebuild(tokens);

    /*
     * Avoid the unnecessary generated header for very small
     * scripts. The actual source transformations above are
     * sufficient.
     */
    if (result.empty())
        return {};

    return result;
}