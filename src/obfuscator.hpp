#pragma once

#include "bytecode.hpp"
#include <cstdint>
#include <random>
#include <chrono>

class Obfuscator {
public:
    Obfuscator();
    explicit Obfuscator(uint32_t seed);
    
    Bytecode transform(const Bytecode& input) const;
    
private:
    uint32_t seed_;
    
    static uint32_t mix32(uint32_t value);
    static uint8_t keyByte(uint32_t seed, size_t position);
    static void writeU32(std::vector<uint8_t>& output, uint32_t value);
};