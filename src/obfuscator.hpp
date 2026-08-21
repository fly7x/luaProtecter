#pragma once

#include <string>

class Obfuscator
{
public:
    Obfuscator() = default;

    std::string transform(
        const std::string& source
    ) const;

private:
    std::string obfuscateStrings(
        const std::string& source
    ) const;

    std::string renameLocals(
        const std::string& source
    ) const;

    std::string minify(
        const std::string& source
    ) const;
};