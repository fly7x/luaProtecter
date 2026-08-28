#include "obfuscator.hpp"
#include <random>
#include <chrono>
#include <cstring>
#include <limits>

namespace {
    constexpr uint32_t MAGIC = 0x31564D4Cu; // "LVM1"
    constexpr uint8_t VERSION = 1;
    
    uint32_t generateSeed() {
        std::random_device rd;
        uint32_t a = static_cast<uint32_t>(rd());
        uint32_t b = static_cast<uint32_t>(rd());
        auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        uint64_t ts = static_cast<uint64_t>(now);
        uint32_t seed = a ^ (b * 0x9E3779B9u) ^ static_cast<uint32_t>(ts) ^ static_cast<uint32_t>(ts >> 32);
        if (seed == 0) seed = 0xA341316Cu;
        return seed;
    }
}

Obfuscator::Obfuscator() : seed_(generateSeed()) {}
Obfuscator::Obfuscator(uint32_t seed) : seed_(seed) { if (seed_ == 0) seed_ = generateSeed(); }

uint32_t Obfuscator::mix32(uint32_t value) {
    value ^= value >> 16;
    value *= 0x7FEB352Du;
    value ^= value >> 15;
    value *= 0x846CA68Bu;
    value ^= value >> 16;
    return value;
}

uint8_t Obfuscator::keyByte(uint32_t seed, size_t position) {
    uint32_t index = static_cast<uint32_t>(position);
    uint32_t state = seed ^ (index * 0x9E3779B9u);
    state = mix32(state);
    return static_cast<uint8_t>(state & 0xFFu);
}

void Obfuscator::writeU32(std::vector<uint8_t>& output, uint32_t value) {
    output.push_back(static_cast<uint8_t>(value));
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value >> 16));
    output.push_back(static_cast<uint8_t>(value >> 24));
}

Bytecode Obfuscator::obfuscate(const Bytecode& input) const {
    if (input.empty()) return Bytecode();
    const auto& src = input.data();
    
    // Format: MAGIC (4) + VERSION (1) + SEED (4) + ORIG_SIZE (4) + ENCRYPTED_DATA
    std::vector<uint8_t> result;
    result.reserve(13 + src.size());
    
    writeU32(result, MAGIC);
    result.push_back(VERSION);
    writeU32(result, seed_);
    if (src.size() > static_cast<size_t>(UINT32_MAX)) return Bytecode();
    writeU32(result, static_cast<uint32_t>(src.size()));
    
    for (size_t i = 0; i < src.size(); ++i) {
        uint8_t encrypted = static_cast<uint8_t>(src[i] ^ keyByte(seed_, i));
        result.push_back(encrypted);
    }
    
    return Bytecode(std::move(result));
}