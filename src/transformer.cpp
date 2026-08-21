#include "transformer.hpp"
#include "obfuscator.hpp"

#include <stdexcept>
#include <string>

std::string Transformer::protect(
    const std::string& source
) const
{
    if (source.empty())
    {
        throw std::runtime_error(
            "Source cannot be empty"
        );
    }

    Obfuscator obfuscator;

    const std::string result =
        obfuscator.transform(source);

    if (result.empty())
    {
        throw std::runtime_error(
            "Obfuscator produced empty output"
        );
    }

    return result;
}