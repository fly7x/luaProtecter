#include "vm.hpp"

#include <Luau/Compiler.h>

#include <string>

VM::VM()
{
}

bool VM::execute(
    const std::string& source,
    std::string& output
)
{
    output.clear();

    if (source.empty())
        return true;

    Luau::CompileOptions options;

    // Compile using the Luau compiler bundled in
    // third_party/luau.
    const std::string bytecode = Luau::compile(
        source,
        options,
        Luau::ParseOptions{},
        nullptr
    );

    // Luau reports compilation errors as a bytecode string
    // beginning with "-- " in this API.
    if (bytecode.empty())
    {
        output = "Luau compilation failed";
        return false;
    }

    output = bytecode;

    return true;
}