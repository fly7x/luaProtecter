#include "transformer.hpp"
#include "obfuscation.hpp"
#include "emitter.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

static constexpr const char* INPUT_FILE =
    "input/script.lua";

static constexpr const char* OUTPUT_FILE =
    "output/protected.lua";

int main()
{
    std::ifstream input(
        INPUT_FILE,
        std::ios::in
    );

    if (!input)
    {
        std::cerr
            << "Failed to open "
            << INPUT_FILE
            << '\n';

        return 1;
    }

    std::string source(
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    );

    input.close();

    if (source.empty())
    {
        std::cerr
            << "Input source is empty.\n";

        return 1;
    }

    Transformer transformer;

    std::string transformed =
        transformer.transform(source);

    if (transformed.empty())
    {
        std::cerr
            << "Transformation failed.\n";

        return 2;
    }

    /*
        Transformer performs the actual protection.

        Obfuscator remains as the dedicated protection
        component so future protection passes can be
        separated cleanly.
    */

    Obfuscator obfuscator;

    std::string protectedSource =
        obfuscator.obfuscate(transformed);

    if (protectedSource.empty())
    {
        std::cerr
            << "Obfuscation failed.\n";

        return 3;
    }

    Emitter emitter;

    std::string output =
        emitter.emit(protectedSource);

    if (output.empty())
    {
        std::cerr
            << "Emitter produced empty output.\n";

        return 4;
    }

    std::ofstream file(
        OUTPUT_FILE,
        std::ios::out |
        std::ios::trunc
    );

    if (!file)
    {
        std::cerr
            << "Failed to create "
            << OUTPUT_FILE
            << '\n';

        return 5;
    }

    file << output;
    file.close();

    std::cout
        << "Protected output written to "
        << OUTPUT_FILE
        << '\n';

    return 0;
}