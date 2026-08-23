#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class Compiler
{
public:
    struct Result
    {
        bool success = false;
        std::vector<std::uint8_t> bytecode;
        std::string error;
    };

    Compiler() = default;

    Result compile(
        const std::string& source
    ) const;

private:
    static std::string decodeCompileError(
        const std::vector<std::uint8_t>& bytecode
    );
};