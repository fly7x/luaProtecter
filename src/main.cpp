#include "transformer.hpp"
#include "obfuscation.hpp"
#include "emitter.hpp"
#include "protector/config.hpp"

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

int main()
{
    const std::string inputPath = protector::DEFAULT_INPUT;
    const std::string outputPath = protector::DEFAULT_OUTPUT;

    std::ifstream input(inputPath, std::ios::binary);

    if (!input)
    {
        std::cerr << "Failed to open input file: " << inputPath << '\n';
        return 1;
    }

    // Use braces here so the compiler cannot interpret this as
    // a function declaration.
    const std::string source{
        std::istreambuf_iterator<char>(input),
        std::istreambuf_iterator<char>()
    };

    if (source.empty())
    {
        std::cerr << "Input file is empty: " << inputPath << '\n';
        return 1;
    }

    Transformer transformer;
    Obfuscator obfuscator;
    Emitter emitter;

    std::string transformed = transformer.transform(source);
    std::string obfuscated = obfuscator.obfuscate(transformed);
    std::string output = emitter.emit(obfuscated);

    std::ofstream out(outputPath, std::ios::binary);

    if (!out)
    {
        std::cerr << "Failed to open output file: " << outputPath << '\n';
        return 1;
    }

    out.write(output.data(), static_cast<std::streamsize>(output.size()));

    if (!out)
    {
        std::cerr << "Failed while writing output file: " << outputPath << '\n';
        return 1;
    }

    std::cout << "Protected output written to: "
              << outputPath << '\n';

    return 0;
}