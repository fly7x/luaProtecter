#include "transformer.hpp"

#include <luacode.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace
{
    /*
     * Compile source using the official Luau compiler.
     *
     * We deliberately do NOT:
     *
     *   - tokenize the source ourselves
     *   - rewrite strings
     *   - invent Luau instructions
     *   - generate a fake interpreter
     *
     * Luau itself is responsible for parsing and compiling
     * the source.
     */

    std::string compileLuau(
        const std::string& source
    )
    {
        if (source.empty())
            throw std::runtime_error(
                "Source code is empty"
            );

        lua_CompileOptions options{};

        /*
         * Maximum optimization level supported by the
         * current public compiler API.
         *
         * Higher optimization can make the resulting
         * bytecode less directly representative of the
         * original source.
         */
        options.optimizationLevel = 2;

        /*
         * Do not retain debugger-oriented information such
         * as local/upvalue names.
         */
        options.debugLevel = 0;

        /*
         * Normal compiler configuration.
         */
        options.typeInfoLevel = 0;
        options.coverageLevel = 0;
        options.vectorLib = nullptr;
        options.vectorCtor = nullptr;

        std::size_t bytecodeSize = 0;

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
                "Luau compiler returned a null bytecode buffer"
            );
        }

        if (bytecodeSize == 0)
        {
            std::free(compiled);

            throw std::runtime_error(
                "Luau compiler produced empty bytecode"
            );
        }

        /*
         * luau_compile() allocates the returned buffer.
         * Copy it into a C++ string before freeing it.
         */
        std::string result(
            compiled,
            bytecodeSize
        );

        std::free(compiled);

        return result;
    }
}

std::string Transformer::transform(
    const std::string& source
)
{
    return compileLuau(source);
}