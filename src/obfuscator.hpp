#pragma once
#include "bytecode.hpp"
#include <cstdint>
#include <vector>
#include <string>

class Obfuscator {
public:
    struct Options {
        bool encryptConstants = true;
        bool shuffleOpcodes   = true;
        bool remapRegisters   = true;
        uint32_t seed         = 0;
    };

    Obfuscator();
    explicit Obfuscator(uint32_t seed);

    Bytecode obfuscate(const Bytecode& input, const Options& opts = {}) const;
    uint32_t seed() const { return seed_; }

private:
    uint32_t seed_;

    static uint32_t mix32(uint32_t x);
    static uint32_t nextKey(uint32_t& state);
    static void encryptBlock(std::vector<uint8_t>& data, uint32_t seed);
    static std::vector<uint8_t> packHeader(uint32_t seed, uint32_t originalSize);
};