#pragma once

#include <string>
#include <vector>

class Transformer {
public:
    // Transform token stream back into source or intermediate representation
    std::string transform(const std::vector<std::string>& tokens);
};
