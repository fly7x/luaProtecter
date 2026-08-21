#pragma once

#include <string>

class VM
{
public:
    VM();

    bool execute(
        const std::string& source,
        std::string& output
    );
};