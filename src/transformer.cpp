cat > src/transformer.cpp <<'EOF'
#include "transformer.hpp"

#include <iostream>
#include <string>

#ifdef HAVE_LUAU

#include "Luau/Compiler.h"

#endif

std::string Transformer::transform(const std::string& source)
{
#ifdef HAVE_LUAU

    if (source.empty())
        return source;

    Luau::CompileOptions options;

    std::string bytecode;

    try
    {
        bytecode = Luau::compile(source, options);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Luau compilation failed: "
                  << e.what() << '\n';

        return {};
    }

    if (bytecode.empty())
    {
        std::cerr << "Luau returned empty bytecode\n";
        return {};
    }

    /*
        The first stage deliberately preserves the original source.

        This gives us a verified Luau-backed pipeline:

            source
               ↓
        Luau compiler
               ↓
          valid bytecode
               ↓
        protected output

        The transformation layer can now be expanded without
        sacrificing syntax compatibility.
    */

    return source;

#else

    std::cerr <<
        "luaProtecter was built without Luau support.\n";

    return source;

#endif
}
EOF