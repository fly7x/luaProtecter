#include "compiler.hpp"

#include "luacode.h"

#include <cstdlib>
#include <cstring>

Compiler::Result Compiler::compile(
    const std::string& source
) const
{
    Result result;

    if (source.empty())
    {
        result.error = "Source is empty";
        return result;
    }

    lua_CompileOptions options{};

    /*
     * Optimization level 2 gives Luau its stronger
     * compiler optimizations.
     */
    options.optimizationLevel = 2;

    /*
     * Don't retain unnecessary debugging information.
     *
     * This is important for protection because debug
     * information can expose names and source locations.
     */
    options.debugLevel = 0;

    /*
     * Type information isn't needed for the protected
     * runtime representation.
     */
    options.typeInfoLevel = 0;

    options.coverageLevel = 0;

    options.vectorLib = nullptr;
    options.vectorCtor = nullptr;
    options.vectorType = nullptr;

    options.vectorPrecision = 0;

    options.mutableGlobals = nullptr;
    options.userdataTypes = nullptr;
    options.librariesWithKnownMembers = nullptr;

    options.libraryMemberTypeCb = nullptr;
    options.libraryMemberConstantCb = nullptr;

    options.disabledBuiltins = nullptr;

    size_t bytecodeSize = 0;

    char* compiled = luau_compile(
        source.data(),
        source.size(),
        &options,
        &bytecodeSize
    );

    if (compiled == nullptr)
    {
        result.error =
            "Luau compiler returned null";

        return result;
    }

    if (bytecodeSize == 0)
    {
        std::free(compiled);

        result.error =
            "Luau compiler returned empty bytecode";

        return result;
    }

    result.bytecode.resize(
        bytecodeSize
    );

    std::memcpy(
        result.bytecode.data(),
        compiled,
        bytecodeSize
    );

    std::free(compiled);

    /*
     * Luau encodes compilation errors into the resulting
     * bytecode rather than necessarily returning null.
     *
     * A valid Luau binary starts with its bytecode header.
     */
    if (
        result.bytecode.size() < 4 ||
        result.bytecode[0] != 'L' ||
        result.bytecode[1] != 'B' ||
        result.bytecode[2] != 'C'
    )
    {
        result.error =
            decodeCompileError(
                result.bytecode
            );

        result.bytecode.clear();

        return result;
    }

    result.success = true;

    return result;
}

std::string Compiler::decodeCompileError(
    const std::vector<std::uint8_t>& bytecode
)
{
    /*
     * Luau's compiler can return an encoded error
     * instead of normal bytecode.
     *
     * Don't blindly expose arbitrary binary data.
     */
    if (bytecode.empty())
        return "Luau compilation failed";

    std::string message;

    message.reserve(
        bytecode.size()
    );

    for (std::uint8_t c : bytecode)
    {
        /*
         * Keep printable ASCII characters.
         */
        if (
            c >= 32 &&
            c <= 126
        )
        {
            message.push_back(
                static_cast<char>(c)
            );
        }
    }

    if (message.empty())
    {
        return "Luau compilation failed";
    }

    return message;
}