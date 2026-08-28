#pragma once

#include "bytecode.hpp"
#include <cstdint>

class Obfuscator {
public:
    Obfuscator();
    explicit Obfuscator(uint32_t seed);
    
    // Encrypts bytecode with XOR and applies simple scrambling
    Bytecode obfuscate(const Bytecode& input) const;
    
    uint32_t seed() const { return seed_; }
    
private:
    uint32_t seed_;
    
    static uint32_t mix32(uint32_t value);
    static uint8_t keyByte(uint32_t seed, size_t position);
    static void writeU32(std::vector<uint8_t>& output, uint32_t value);
};