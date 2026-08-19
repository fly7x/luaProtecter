#include "emitter.hpp"

#include <string>

std::string Emitter::emit(
    const std::string& source
)
{
    /*
        The transformation stage already emits valid Luau.

        Keep this class as the final output boundary so that
        additional formatting/minification can be added later
        without changing main.cpp.
    */

    std::string result;

    result.reserve(source.size());

    for (size_t i = 0; i < source.size(); ++i)
    {
        char c = source[i];

        // Normalize CRLF -> LF.
        if (c == '\r')
        {
            if (
                i + 1 < source.size() &&
                source[i + 1] == '\n'
            )
            {
                continue;
            }

            result.push_back('\n');
            continue;
        }

        result.push_back(c);
    }

    return result;
}