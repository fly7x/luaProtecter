#include "transformer.hpp"
#include "obfuscation.hpp"

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#ifdef HAVE_LUAU

#include "Luau/Allocator.h"
#include "Luau/Ast.h"
#include "Luau/Compiler.h"
#include "Luau/Parser.h"
#include "Luau/PrettyPrinter.h"

namespace
{
    class LocalRenamer final : public Luau::AstVisitor
    {
    public:
        LocalRenamer(Luau::AstNameTable& names)
            : names(names)
        {
        }

        bool visit(Luau::AstStatLocal* node) override
        {
            for (size_t i = 0; i < node->vars.size; ++i)
                rename(node->vars.data[i]);

            return true;
        }

        bool visit(Luau::AstStatLocalFunction* node) override
        {
            rename(node->name);
            return true;
        }

        bool visit(Luau::AstStatFor* node) override
        {
            rename(node->var);
            return true;
        }

        bool visit(Luau::AstStatForIn* node) override
        {
            for (size_t i = 0; i < node->vars.size; ++i)
                rename(node->vars.data[i]);

            return true;
        }

        bool visit(Luau::AstExprFunction* node) override
        {
            for (size_t i = 0; i < node->args.size; ++i)
                rename(node->args.data[i]);

            return true;
        }

    private:
        Luau::AstNameTable& names;
        unsigned int counter = 0;

        static bool protectedName(const char* name)
        {
            if (!name)
                return true;

            static const char* protectedNames[] =
            {
                "game",
                "workspace",
                "script",
                "shared",

                "print",
                "warn",
                "error",
                "assert",
                "pcall",
                "xpcall",
                "require",

                "pairs",
                "ipairs",
                "next",
                "select",
                "unpack",

                "type",
                "typeof",
                "tostring",
                "tonumber",

                "string",
                "table",
                "math",
                "coroutine",
                "task",
                "os",

                "Instance",
                "Enum",
                "Vector2",
                "Vector3",
                "Vector3int16",
                "CFrame",
                "Color3",
                "UDim",
                "UDim2",
                "Ray",
                "RaycastParams",

                "GetService",
                "WaitForChild",
                "FindFirstChild",
                "FindFirstChildOfClass",
                "Connect",
                "Once",
                "Fire",
                "FireServer",
                "InvokeServer",

                nullptr
            };

            for (size_t i = 0; protectedNames[i]; ++i)
            {
                if (std::string(name) == protectedNames[i])
                    return true;
            }

            return false;
        }

        std::string makeName()
        {
            std::ostringstream out;

            out << "_";

            unsigned int value = counter++;

            static const char alphabet[] =
                "abcdefghijklmnopqrstuvwxyz"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            do
            {
                out <<
                    alphabet[
                        value %
                        (sizeof(alphabet) - 1)
                    ];

                value /=
                    static_cast<unsigned int>(
                        sizeof(alphabet) - 1
                    );
            }
            while (value != 0);

            return out.str();
        }

        void rename(Luau::AstLocal* local)
        {
            if (!local || !local->name.value)
                return;

            /*
                Don't touch intentionally special names.
            */
            if (protectedName(local->name.value))
                return;

            /*
                Keep exported locals readable because renaming
                exported declarations can change their public API.
            */
            if (local->isExported)
                return;

            const std::string generated = makeName();

            local->name =
                names.getOrAdd(
                    generated.c_str()
                );
        }
    };
}

#endif

std::string Transformer::transform(
    const std::string& source
)
{
    if (source.empty())
        return {};

#ifdef HAVE_LUAU

    try
    {
        /*
            ------------------------------
            1. Parse original source
            ------------------------------
        */

        Luau::Allocator allocator;
        Luau::AstNameTable names(allocator);

        Luau::ParseOptions parseOptions;

        Luau::ParseResult parsed =
            Luau::Parser::parse(
                source.c_str(),
                source.size(),
                names,
                allocator,
                parseOptions
            );

        if (!parsed.root || !parsed.errors.empty())
        {
            std::cerr
                << "Luau parser rejected input.\n";

            for (const Luau::ParseError& error :
                 parsed.errors)
            {
                std::cerr
                    << error.getMessage()
                    << '\n';
            }

            return {};
        }

        /*
            ------------------------------
            2. Rename locals through AST
            ------------------------------

            This is deliberately AST based.

            That means:

                local foo = 1
                print(foo)

            becomes something like:

                local _a = 1
                print(_a)

            while:

                object.foo

            remains:

                object.foo

            This avoids the dangerous global token replacement
            approach used by the old implementation.
        */

        LocalRenamer renamer(names);
        parsed.root->visit(&renamer);

        /*
            ------------------------------
            3. Convert AST back to Luau
            ------------------------------
        */

        std::string transformed =
            Luau::prettyPrint(
                *parsed.root
            );

        if (transformed.empty())
        {
            std::cerr
                << "Luau pretty printer produced empty output.\n";

            return {};
        }

        /*
            ------------------------------
            4. Additional protection pass
            ------------------------------

            Strings/constants are handled after the AST
            transformation so we don't accidentally alter
            Roblox member names or local references.
        */

        Obfuscator obfuscator;

        transformed =
            obfuscator.obfuscate(
                transformed
            );

        if (transformed.empty())
            return {};

        /*
            ------------------------------
            5. Parse protected result again
            ------------------------------
        */

        Luau::Allocator validationAllocator;
        Luau::AstNameTable validationNames(
            validationAllocator
        );

        Luau::ParseResult validation =
            Luau::Parser::parse(
                transformed.c_str(),
                transformed.size(),
                validationNames,
                validationAllocator,
                parseOptions
            );

        if (!validation.root ||
            !validation.errors.empty())
        {
            std::cerr
                << "Protected output failed Luau parsing.\n";

            for (const Luau::ParseError& error :
                 validation.errors)
            {
                std::cerr
                    << error.getMessage()
                    << '\n';
            }

            return {};
        }

        /*
            ------------------------------
            6. Compile validation
            ------------------------------
        */

        Luau::CompileOptions compileOptions;

        std::string bytecode =
            Luau::compile(
                transformed,
                compileOptions
            );

        if (bytecode.empty())
        {
            std::cerr
                << "Protected output failed Luau compilation.\n";

            return {};
        }

        /*
            Only return code that successfully survived:

                source
                  ↓
                parser
                  ↓
                AST transform
                  ↓
                pretty printer
                  ↓
                protection pass
                  ↓
                parser
                  ↓
                compiler
        */

        return transformed;
    }
    catch (const std::exception& exception)
    {
        std::cerr
            << "Transformer exception: "
            << exception.what()
            << '\n';

        return {};
    }

#else

    std::cerr
        << "luaProtecter was compiled without Luau support.\n";

    return {};

#endif
}