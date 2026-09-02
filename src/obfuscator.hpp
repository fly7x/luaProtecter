#pragma once

#include "bytecode.hpp"
#include <cstdint>
#include <vector>

class Obfuscator {
public:
    Obfuscator();
    explicit Obfuscator(uint32_t seed);

    Bytecode obfuscate(const Bytecode& input) const;
    uint32_t seed() const { return seed_; }

private:
    uint32_t seed_;
    static uint32_t mix32(uint32_t x);
    static void encryptBlock(std::vector<uint8_t>& data, uint32_t seed);
};