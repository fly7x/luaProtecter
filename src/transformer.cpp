#include "transformer.hpp"

#include "obfuscator.hpp"

Bytecode Transformer::protect(
    const Bytecode& bytecode
) const
{
    if (bytecode.empty())
        return {};

    /*
     * Pass the real Luau bytecode through the
     * existing obfuscation layer.
     */
    Obfuscator obfuscator;

    return obfuscator.transform(
        bytecode
    );
}