#include <iostream>
#include <fstream>
#include <string>

#include "protector/config.hpp"
#include "transformer.hpp"
#include "emitter.hpp"
#include "obfuscation.hpp"

int main(int argc, char** argv) {
    // Simple hardcoded input/output paths for the skeleton
    std::string inputPath = protector::DEFAULT_INPUT;
    std::string outputPath = protector::DEFAULT_OUTPUT;

    std::ifstream in(inputPath);
    if (!in) {
        std::cerr << "Failed to open input file: " << inputPath << "\n";
        return 1;
    }

    std::string source((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    // Transformer -> Obfuscator -> Emitter (stubs)
    Transformer transformer;
    std::string transformed = transformer.transform(source);

    Obfuscator obf;
    std::string obfuscated = obf.obfuscate(transformed);

    Emitter emitter;
    std::string output = emitter.emit(obfuscated);

    std::ofstream out(outputPath);
    if (!out) {
        std::cerr << "Failed to open output file: " << outputPath << "\n";
        return 1;
    }
    out << output;
    out.close();

    std::cout << "Protected output written to: " << outputPath << "\n";
    return 0;
}
