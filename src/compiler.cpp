#include "compiler.hpp"

#include <Luau/Compiler.h>
#include <luacode.h>

#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    /*
     * Convert Luau's compiler output into our Bytecode
     * container.
     *
     * Luau returns a malloc'ed buffer which must be released
     * with free().
     */
    Bytecode makeBytecode(
        const char* data,
        std::size_t size
    )
    {
        if (data == nullptr)
        {
            throw std::runtime_error(
                "Luau compiler returned null bytecode"
            );
        }

        if (size == 0)
        {
            throw std::runtime_error(
                "Luau compiler returned empty bytecode"
            );
        }

        std::vector<std::uint8_t> bytes(
            reinterpret_cast<const std::uint8_t*>(data),
            reinterpret_cast<const std::uint8_t*>(data) + size
        );

        return Bytecode(
            std::move(bytes)
        );
    }
}

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

    /*
     * Use Luau's actual compiler.
     *
     * We intentionally do not implement our own parser here.
     */
    Luau::CompileOptions options = {};

    /*
     * Optimization:
     *
     * 0 = disabled
     * 1 = normal
     * 2 = aggressive
     *
     * Start at 2 for the protection pipeline.
     */
    options.optimizationLevel = 2;

    /*
     * Debug information:
     *
     * 0 = minimal
     * 1 = normal
     * 2 = detailed
     *
     * Minimal debug information is preferable for a
     * protection/production build.
     */
    options.debugLevel = 0;

    /*
     * We don't request type information from the compiler
     * output here.
     */
    options.typeInfoLevel = 0;

    std::size_t bytecodeSize = 0;

    char* compiled =
        luau_compile(
            source.data(),
            source.size(),
            reinterpret_cast<lua_CompileOptions*>(
                &options
            ),
            &bytecodeSize
        );

    if (compiled == nullptr)
    {
        throw std::runtime_error(
            "Luau compiler failed to allocate bytecode"
        );
    }

    try
    {
        Bytecode result =
            makeBytecode(
                compiled,
                bytecodeSize
            );

        std::free(compiled);

        return result;
    }
    catch (...)
    {
        std::free(compiled);
        throw;
    }
}