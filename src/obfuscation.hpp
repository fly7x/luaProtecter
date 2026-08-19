#pragma once

#include <string>

class Obfuscator
{
public:
    std::string obfuscate(const std::string& source);

private:
    std::string generateIdentifier(
        const std::string& prefix,
        unsigned int& counter
    );

    std::string encodeString(
        const std::string& value,
        const std::string& decoder
    );

    std::string transformNumber(
        const std::string& value
    );

    bool isIdentifierStart(char c) const;
    bool isIdentifierPart(char c) const;
    bool isKeyword(const std::string& value) const;
    bool isProtectedName(const std::string& value) const;
};