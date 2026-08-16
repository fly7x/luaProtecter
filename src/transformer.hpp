#pragma once

#include <string>

class Transformer {
public:
    // Transform raw source text into an intermediate representation or transformed source
    // For the skeleton this takes the full source as input.
    std::string transform(const std::string& src);
};
