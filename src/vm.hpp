#pragma once

#include <string>

class VM
{
public:
    VM();
    ~VM();

    VM(const VM&) = delete;
    VM& operator=(const VM&) = delete;

    // Compile and execute Luau source.
    // Returns true when execution succeeds.
    bool execute(
        const std::string& source,
        std::string& error
    );

private:
    struct State;
    State* state_;
};