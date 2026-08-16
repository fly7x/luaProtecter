#include "lexer.hpp"

#include <vector>

std::vector<std::string> Lexer::tokenize(const std::string& src) {
    // Very small placeholder tokenizer: split on whitespace
    std::vector<std::string> tokens;
    std::string cur;
    for (char c : src) {
        if (isspace(static_cast<unsigned char>(c))) {
            if (!cur.empty()) {
                tokens.push_back(cur);
                cur.clear();
            }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) tokens.push_back(cur);
    return tokens;
}
