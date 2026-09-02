#include "obfuscator.hpp"
#include <random>
#include <chrono>
#include <cstring>

namespace {
    constexpr uint32_t MAGIC = 0x4C50524Fu; // "LPRO"
    constexpr uint8_t  VERSION = 2;
}

Obfuscator::Obfuscator() : seed_(0) {
    std::random_device rd;
    seed_ = rd() ^ static_cast<uint32_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count());
    if (seed_ == 0) seed_ = 0xA341316C;
}

Obfuscator::Obfuscator(uint32_t seed) : seed_(seed ? seed : 0xA341316C) {}

uint32_t Obfuscator::mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352D;
    x ^= x >> 15;
    x *= 0x846CA68B;
    x ^= x >> 16;
    return x;
}

uint32_t Obfuscator::nextKey(uint32_t& state) {
    state = mix32(state + 0x9E3779B9u);
    return state;
}

void Obfuscator::encryptBlock(std::vector<uint8_t>& data, uint32_t seed) {
    uint32_t state = seed;
    for (size_t i = 0; i < data.size(); ++i) {
        uint32_t k = nextKey(state);
        // Extra mixing based on position
        k ^= static_cast<uint32_t>(i * 0x85EBCA77u);
        k = mix32(k);
        data[i] ^= static_cast<uint8_t>(k);
        data[i] ^= static_cast<uint8_t>(k >> 8);
        data[i] ^= static_cast<uint8_t>(k >> 16);
    }
}

std::vector<uint8_t> Obfuscator::packHeader(uint32_t seed, uint32_t originalSize) {
    std::vector<uint8_t> header;
    header.reserve(16);

    auto writeU32 = [&](uint32_t v) {
        header.push_back(v & 0xFF);
        header.push_back((v >> 8) & 0xFF);
        header.push_back((v >> 16) & 0xFF);
        header.push_back((v >> 24) & 0xFF);
    };

    writeU32(MAGIC);
    header.push_back(VERSION);
    header.push_back(0); // reserved
    header.push_back(0);
    header.push_back(0);
    writeU32(seed);
    writeU32(originalSize);

    return header;
}

Bytecode Obfuscator::obfuscate(const Bytecode& input, const Options& opts) const {
    if (input.empty()) return Bytecode();

    std::vector<uint8_t> data = input.data();
    uint32_t originalSize = static_cast<uint32_t>(data.size());

    // Strong encryption
    encryptBlock(data, seed_);

    // Pack header + encrypted payload
    auto header = packHeader(seed_, originalSize);
    header.insert(header.end(), data.begin(), data.end());

    return Bytecode(std::move(header));
}