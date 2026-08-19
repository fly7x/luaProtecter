#include "transformer.hpp"
#include "obfuscation.hpp"

#include <iostream>

#ifdef HAVE_LUAU
#include "Luau/Compiler.h"
#endif

std::string Transformer::transform(const std::string& source)
{
    if (source.empty())
        return source;

#ifdef HAVE_LUAU
    try
    {
        Luau::CompileOptions options;

        // First make sure the ORIGINAL source is valid Luau.
        const std::string originalBytecode =
            Luau::compile(source, options);

        if (originalBytecode.empty())
        {
            std::cerr << "Input is not valid Luau.\n";
            return {};
        }

        Obfuscator obfuscator;
        std::string result = obfuscator.obfuscate(source);

        if (result.empty())
            return {};

        // Critical safety check:
        // never output something that Luau cannot compile.
        const std::string protectedBytecode =
            Luau::compile(result, options);

        if (protectedBytecode.empty())
        {
            std::cerr
                << "Protected output failed Luau validation.\n";

            return {};
        }

        return result;
    }
    catch (const std::exception& e)
    {
        std::cerr
            << "Luau transformation error: "
            << e.what()
            << '\n';

        return {};
    }
#else
    std::cerr
        << "luaProtecter was built without Luau support.\n";

    return source;
#endif
}