#include "obfuscation.hpp"

std::string Obfuscator::obfuscate(const std::string& input) {
    // Very small placeholder obfuscation: reverse the string
    std::string out(input.rbegin(), input.rend());
    return out;
}
