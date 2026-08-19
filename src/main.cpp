cat > src/main.cpp <<'EOF'
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
    std::ifstream input(INPUT_FILE);

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

    Transformer transformer;

    std::string transformed =
        transformer.transform(source);

    if (transformed.empty() && !source.empty())
    {
        std::cerr
            << "Transformation failed.\n";

        return 2;
    }

    Obfuscator obfuscator;

    std::string protectedSource =
        obfuscator.obfuscate(transformed);

    Emitter emitter;

    std::string output =
        emitter.emit(protectedSource);

    std::ofstream file(OUTPUT_FILE);

    if (!file)
    {
        std::cerr
            << "Failed to create "
            << OUTPUT_FILE
            << '\n';

        return 3;
    }

    file << output;

    std::cout
        << "Protected output written to "
        << OUTPUT_FILE
        << '\n';

    return 0;
}
EOF