#include "obfuscator.hpp"

#include <cctype>
#include <cstdint>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>

namespace
{
    class Scanner
    {
    public:
        explicit Scanner(const std::string& input)
            : source(input)
        {
        }

        std::string run()
        {
            std::string result;
            result.reserve(source.size());

            while (position < source.size())
            {
                const char c = source[position];

                // Quoted strings
                if (c == '"' || c == '\'')
                {
                    result += readString();
                    continue;
                }

                // Long bracket strings/comments are preserved.
                if (c == '[' && position + 1 < source.size() &&
                    source[position + 1] == '[')
                {
                    result += readLongBracket();
                    continue;
                }

                // Line comment
                if (c == '-' &&
                    position + 1 < source.size() &&
                    source[position + 1] == '-')
                {
                    skipComment();
                    continue;
                }

                result += c;
                ++position;
            }

            return result;
        }

    private:
        const std::string& source;
        std::size_t position = 0;

        std::string readString()
        {
            const char quote = source[position++];

            std::string result;
            result += quote;

            bool escaped = false;

            while (position < source.size())
            {
                const char c = source[position++];
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

                if (c == quote)
                    break;
            }

            return result;
        }

        std::string readLongBracket()
        {
            const std::size_t start = position;

            position += 2;

            while (position + 1 < source.size())
            {
                if (source[position] == ']' &&
                    source[position + 1] == ']')
                {
                    position += 2;
                    break;
                }

                ++position;
            }

            return source.substr(
                start,
                position - start
            );
        }

        void skipComment()
        {
            position += 2;

            while (position < source.size() &&
                   source[position] != '\n')
            {
                ++position;
            }

            if (position < source.size())
                ++position;
        }
    };

    std::string encodeString(
        const std::string& value
    )
    {
        std::ostringstream output;

        output << '"';

        for (unsigned char c : value)
        {
            switch (c)
            {
                case '\n':
                    output << "\\n";
                    break;

                case '\r':
                    output << "\\r";
                    break;

                case '\t':
                    output << "\\t";
                    break;

                case '\\':
                    output << "\\\\";
                    break;

                case '"':
                    output << "\\\"";
                    break;

                default:
                    /*
                     * Keep printable UTF-8 bytes intact.
                     *
                     * ASCII control characters are emitted
                     * numerically so the resulting source
                     * remains readable by Luau.
                     */
                    if (c < 32 || c == 127)
                    {
                        output << '\\';

                        output << static_cast<unsigned int>(c);
                    }
                    else
                    {
                        output << static_cast<char>(c);
                    }

                    break;
            }
        }

        output << '"';

        return output.str();
    }

    std::string transformStringLiterals(
        const std::string& source
    )
    {
        std::string result;
        result.reserve(source.size());

        std::size_t position = 0;

        while (position < source.size())
        {
            const char c = source[position];

            // Preserve comments.
            if (c == '-' &&
                position + 1 < source.size() &&
                source[position + 1] == '-')
            {
                const std::size_t start = position;

                position += 2;

                while (position < source.size() &&
                       source[position] != '\n')
                {
                    ++position;
                }

                result += source.substr(
                    start,
                    position - start
                );

                continue;
            }

            // Preserve long strings.
            if (c == '[' &&
                position + 1 < source.size() &&
                source[position + 1] == '[')
            {
                const std::size_t start = position;

                position += 2;

                while (position + 1 < source.size())
                {
                    if (source[position] == ']' &&
                        source[position + 1] == ']')
                    {
                        position += 2;
                        break;
                    }

                    ++position;
                }

                result += source.substr(
                    start,
                    position - start
                );

                continue;
            }

            // Transform quoted strings.
            if (c == '"' || c == '\'')
            {
                const char quote = c;

                ++position;

                std::string value;

                bool escaped = false;

                while (position < source.size())
                {
                    const char current =
                        source[position++];

                    if (escaped)
                    {
                        switch (current)
                        {
                            case 'n':
                                value += '\n';
                                break;

                            case 'r':
                                value += '\r';
                                break;

                            case 't':
                                value += '\t';
                                break;

                            case '\\':
                                value += '\\';
                                break;

                            case '"':
                                value += '"';
                                break;

                            case '\'':
                                value += '\'';
                                break;

                            default:
                                /*
                                 * Unknown escape:
                                 * preserve it literally.
                                 */
                                value += '\\';
                                value += current;
                                break;
                        }

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

                    value += current;
                }

                result += encodeString(value);

                continue;
            }

            result += c;
            ++position;
        }

        return result;
    }

    std::string removeComments(
        const std::string& source
    )
    {
        Scanner scanner(source);
        return scanner.run();
    }

    std::string collapseWhitespace(
        const std::string& source
    )
    {
        std::string result;
        result.reserve(source.size());

        bool whitespace = false;

        std::size_t position = 0;

        while (position < source.size())
        {
            const char c = source[position];

            if (c == '"' || c == '\'')
            {
                if (whitespace && !result.empty())
                {
                    result += ' ';
                    whitespace = false;
                }

                const char quote = c;

                result += quote;
                ++position;

                bool escaped = false;

                while (position < source.size())
                {
                    const char current =
                        source[position++];

                    result += current;

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

                continue;
            }

            if (std::isspace(
                    static_cast<unsigned char>(c)))
            {
                whitespace = true;
                ++position;
                continue;
            }

            if (whitespace && !result.empty())
                result += ' ';

            whitespace = false;

            result += c;
            ++position;
        }

        return result;
    }
}

std::string Obfuscator::obfuscateStrings(
    const std::string& source
) const
{
    return transformStringLiterals(source);
}

std::string Obfuscator::minify(
    const std::string& source
) const
{
    return collapseWhitespace(
        removeComments(source)
    );
}

std::string Obfuscator::transform(
    const std::string& source
) const
{
    if (source.empty())
        throw std::runtime_error(
            "Cannot obfuscate empty source"
        );

    /*
     * Keep this conservative:
     *
     * 1. Remove ordinary comments.
     * 2. Rewrite quoted string literals.
     * 3. Collapse unnecessary whitespace.
     *
     * We intentionally do NOT blindly rename identifiers
     * with regex because that can change Luau semantics.
     */
    const std::string withoutComments =
        removeComments(source);

    const std::string stringsTransformed =
        obfuscateStrings(withoutComments);

    return minify(stringsTransformed);
}