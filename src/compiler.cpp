#include "compiler.hpp"

#include <luacode.h>

#include <cstdlib>
#include <stdexcept>
#include <string>

Bytecode Compiler::compile(
    const std::string& source
) const
{
    if (source.empty())
    {
        throw std::runtime_error(
            "Source cannot be empty"
        );
    }

    std::size_t bytecodeSize = 0;

    lua_CompileOptions options{};

    char* compiled =
        luau_compile(
            source.data(),
            source.size(),
            &options,
            &bytecodeSize
        );

    if (!compiled)
    {
        throw std::runtime_error(
            "Luau compilation failed"
        );
    }

    std::string result(
        compiled,
        bytecodeSize
    );

    std::free(compiled);

    /*
     * Luau encodes compilation errors into the
     * returned bytecode payload rather than
     * returning nullptr for every source error.
     *
     * The Luau VM's luau_load() is the authoritative
     * validation/loading step.
     */

    return Bytecode(result);
}