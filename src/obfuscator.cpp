#include "obfuscator.hpp"
#include <cstring>
#include <limits>

namespace {
    constexpr uint32_t MAGIC = 0x31564D4Cu; // "LVM1"
    constexpr uint8_t VERSION = 1;
    
    uint32_t generateSeed() {
        std::random_device rd;
        uint32_t a = static_cast<uint32_t>(rd());
        uint32_t b = static_cast<uint32_t>(rd());
        
        auto now = std::chrono::high_resolution_clock::now()
            .time_since_epoch()
            .count();
        uint64_t timestamp = static_cast<uint64_t>(now);
        
        uint32_t seed = a ^ (b * 0x9E3779B9u) ^ 
                        static_cast<uint32_t>(timestamp) ^ 
                        static_cast<uint32_t>(timestamp >> 32);
        
        if (seed == 0) seed = 0xA341316Cu;
        return seed;
    }
}

Obfuscator::Obfuscator() : seed_(generateSeed()) {}

Obfuscator::Obfuscator(uint32_t seed) : seed_(seed) {
    if (seed_ == 0) seed_ = generateSeed();
}

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

Bytecode Obfuscator::transform(const Bytecode& input) const {
    if (input.empty()) return Bytecode();
    
    const std::vector<uint8_t>& source = input.data();
    
    // Format:
    // 00-03 MAGIC
    // 04    VERSION
    // 05-08 SEED
    // 09-0C ORIGINAL SIZE
    // 0D... ENCRYPTED BYTECODE
    
    std::vector<uint8_t> result;
    result.reserve(13 + source.size());
    
    writeU32(result, MAGIC);
    result.push_back(VERSION);
    writeU32(result, seed_);
    
    if (source.size() > static_cast<size_t>(UINT32_MAX)) {
        return Bytecode(); // Too large
    }
    
    writeU32(result, static_cast<uint32_t>(source.size()));
    
    for (size_t i = 0; i < source.size(); ++i) {
        uint8_t encrypted = static_cast<uint8_t>(source[i] ^ keyByte(seed_, i));
        result.push_back(encrypted);
    }
    
    return Bytecode(std::move(result));
}