#pragma once

#include <string>

class VM
{
public:
    VM();

    // Compile Luau source into Luau bytecode.
    bool compile(
        const std::string& source,
        std::string& bytecode,
        std::string& error
    );

    // Execute normal Luau source using the embedded Luau runtime.
    bool execute(
        const std::string& source,
        std::string& output,
        std::string& error
    );
};