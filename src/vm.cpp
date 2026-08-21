#include "vm.hpp"

#include <Luau/Compiler.h>
#include <Luau/BytecodeBuilder.h>
#include <Luau/BytecodeUtils.h>

#include <string>

VM::VM()
{
}

bool VM::compile(
    const std::string& source,
    std::string& bytecode,
    std::string& error
)
{
    bytecode.clear();
    error.clear();

    if (source.empty())
    {
        error = "Source is empty";
        return false;
    }

    Luau::CompileOptions options;

    bytecode = Luau::compile(
        source,
        options,
        Luau::ParseOptions{},
        nullptr
    );

    if (bytecode.empty())
    {
        error = "Luau compilation failed";
        return false;
    }

    /*
     * Luau's compiler returns diagnostics as a textual
     * error string beginning with "-- ".
     */
    if (
        bytecode.size() >= 3 &&
        bytecode[0] == '-' &&
        bytecode[1] == '-' &&
        bytecode[2] == ' '
    )
    {
        error = bytecode;
        bytecode.clear();
        return false;
    }

    return true;
}

bool VM::execute(
    const std::string& source,
    std::string& output,
    std::string& error
)
{
    output.clear();
    error.clear();

    std::string bytecode;

    if (!compile(source, bytecode, error))
        return false;

    /*
     * IMPORTANT:
     *
     * This function currently only verifies compilation.
     *
     * Actual execution requires creating a Luau lua_State,
     * loading the compiled bytecode with Luau's runtime API,
     * and calling the resulting closure.
     *
     * Do NOT attempt to execute the binary by passing it to
     * a source parser.
     */

    output = bytecode;

    return true;
}