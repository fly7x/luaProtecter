#include "obfuscator.hpp"
#include <chrono>
#include <random>

namespace {
constexpr uint32_t MAGIC = 0x4C50524Fu;
constexpr uint8_t VERSION = 2;
}

Obfuscator::Obfuscator() {
    std::random_device rd;
    seed_ = rd() ^ uint32_t(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    if (!seed_) seed_ = 0xA341316C;
}

Obfuscator::Obfuscator(uint32_t seed) : seed_(seed ? seed : 0xA341316C) {}

uint32_t Obfuscator::mix32(uint32_t x) { return x; }

void Obfuscator::encryptBlock(std::vector<uint8_t>& data, uint32_t seed) {
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t k = uint8_t(seed >> ((i & 3) * 8));
        k = uint8_t(k ^ uint8_t(i * 131u + 17u) ^ uint8_t(seed));
        data[i] = uint8_t(data[i] ^ k);
    }
}

Bytecode Obfuscator::obfuscate(const Bytecode& input) const {
    if (input.empty()) return Bytecode();
    std::vector<uint8_t> payload = input.data();
    uint32_t originalSize = uint32_t(payload.size());
    encryptBlock(payload, seed_);
    std::vector<uint8_t> out;
    auto w8 = [&](uint8_t v) { out.push_back(v); };
    auto w32 = [&](uint32_t v) {
        out.push_back(uint8_t(v));
        out.push_back(uint8_t(v >> 8));
        out.push_back(uint8_t(v >> 16));
        out.push_back(uint8_t(v >> 24));
    };
    w32(MAGIC);
    w8(VERSION);
    w8(0); w8(0); w8(0);
    w32(seed_);
    w32(originalSize);
    out.insert(out.end(), payload.begin(), payload.end());
    return Bytecode(std::move(out));
}