#include "emitter.hpp"

std::string Emitter::emit(const std::string& obfuscated) {
    // Placeholder emitter: return the input wrapped with a comment header
    std::string out = "-- Protected by luaProtecter (placeholder)\n";
    out += obfuscated;
    return out;
}
