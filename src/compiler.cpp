#include "compiler.hpp"

#include <Luau/Compiler.h>

#include <stdexcept>
#include <string>
#include <vector>

Bytecode Compiler::compile(
    const std::string& source
) const
{
    if (source.empty())
        throw std::runtime_error(
            "Source is empty"
        );

    Luau::CompileOptions options;

    /*
     * Use the real Luau compiler.
     *
     * Luau::compile() returns the actual Luau
     * bytecode produced from the source.
     */
    const std::string compiled =
        Luau::compile(
            source,
            options
        );

    if (compiled.empty())
    {
        throw std::runtime_error(
            "Luau compiler returned empty bytecode"
        );
    }

    std::vector<std::uint8_t> bytes;

    bytes.reserve(
        compiled.size()
    );

    for (unsigned char c : compiled)
    {
        bytes.push_back(c);
    }

    return Bytecode(
        std::move(bytes)
    );
}