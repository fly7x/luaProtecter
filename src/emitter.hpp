#pragma once

#include <string>

class Emitter {
public:
    // Produce final Lua output from obfuscated/intermediate representation
    std::string emit(const std::string& obfuscated);
};
