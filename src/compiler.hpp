#pragma once

#include <vector>
#include <string>
#include <cstdint>

class Compiler {
public:
    struct Result {
        bool success = false;
        std::vector<uint8_t> bytecode;
        std::string error;
    };
    
    Compiler() = default;
    Result compile(const std::string& source) const;
    
private:
    static std::string decodeCompileError(const std::vector<uint8_t>& bytecode);
};