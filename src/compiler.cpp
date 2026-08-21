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
            "Luau source cannot be empty"
        );
    }

    size_t bytecodeSize = 0;

    char* compiled =
        luau_compile(
            source.data(),
            source.size(),
            nullptr,
            &bytecodeSize
        );

    if (!compiled)
    {
        throw std::runtime_error(
            "Luau compiler returned null"
        );
    }

    std::string result(
        compiled,
        bytecodeSize
    );

    std::free(compiled);

    if (result.empty())
    {
        throw std::runtime_error(
            "Luau compiler produced empty bytecode"
        );
    }

    return Bytecode(
        std::move(result)
    );
}