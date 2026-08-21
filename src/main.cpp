#include "transformer.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main()
{
    std::ifstream input("input/script.lua", std::ios::binary);

    if (!input)
    {
        std::cerr << "Failed to open input/script.lua\n";
        return 1;
    }

    std::string source{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    };

    if (source.empty())
    {
        std::cerr << "Input script is empty.\n";
        return 1;
    }

    Transformer transformer;

    std::string protectedSource = transformer.transform(source);

    std::ofstream output(
        "output/protected.lua",
        std::ios::binary
    );

    if (!output)
    {
        std::cerr << "Failed to open output/protected.lua\n";
        return 1;
    }

    output << protectedSource;

    if (!output)
    {
        std::cerr << "Failed to write protected output.\n";
        return 1;
    }

    std::cout << "Protected output written to: output/protected.lua\n";

    return 0;
}