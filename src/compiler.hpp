#pragma once

#include "bytecode.hpp"
#include <string>

class Compiler {
public:
    struct Result {
        bool success = false;
        Bytecode bytecode;
        std::string error;
    };
    
    Compiler() = default;
    Result compile(const std::string& source) const;
};