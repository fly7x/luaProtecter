#include "transformer.hpp"

#include <vector>
#include <string>

std::string Transformer::transform(const std::vector<std::string>& tokens) {
    // Placeholder: join tokens with a single space
    std::string out;
    for (size_t i = 0; i < tokens.size(); ++i) {
        out += tokens[i];
        if (i + 1 < tokens.size()) out += ' ';
    }
    return out;
}
