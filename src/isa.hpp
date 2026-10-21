#pragma once

#include <array>
#include <cstdint>
#include <random>
#include <vector>

namespace Protect {

inline constexpr uint32_t FLY_MAGIC = 0x33594C46u; // 'F''L''Y''3'
inline constexpr uint32_t LPR2_MAGIC = 0x3252504Cu;

enum Op : int {
    OP_MOVE = 0,
    OP_LOADK = 1,
    OP_LOADNIL = 2,
    OP_LOADBOOL = 3,
    OP_ADD = 4,
    OP_SUB = 5,
    OP_MUL = 6,
    OP_DIV = 7,
    OP_MOD = 8,
    OP_POW = 9,
    OP_UNM = 10,
    OP_NOT = 11,
    OP_LEN = 12,
    OP_CONCAT = 13,
    OP_JMP = 14,
    OP_TEST = 15,
    OP_TESTN = 16,
    OP_EQ = 17,
    OP_LT = 18,
    OP_LE = 19,
    OP_GETGLOBAL = 20,
    OP_SETGLOBAL = 21,
    OP_GETTABLE = 22,
    OP_SETTABLE = 23,
    OP_GETTABLEKS = 24,
    OP_SETTABLEKS = 25,
    OP_NEWTABLE = 26,
    OP_CALL = 27,
    OP_RETURN = 28,
    OP_FORLOOP = 29,
    OP_FORPREP = 30,
    OP_CLOSURE = 31,
    OP_VARARG = 32,
    OP_NAMECALL = 33,
    OP_GETUPVAL = 34,
    OP_SETUPVAL = 35,
    OP_SETLIST = 36,
    OP_FORGLOOP = 37,
    OP_CAPTURE = 38,
    OP_AND = 39,
    OP_OR = 40,
    OP_GETTABUP = 41,
    OP_SETTABUP = 42,
    OP_IDIV = 43,
    OP_EQK = 44,
    COUNT = 45
};

inline uint32_t mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
}

// map_[logical] = physical byte  (size == Op::COUNT)
inline std::array<uint8_t, static_cast<size_t>(Op::COUNT)> makeOpcodeMap(uint32_t seed) {
    std::array<uint8_t, 256> pool{};
    for (int i = 0; i < 256; ++i)
        pool[static_cast<size_t>(i)] = static_cast<uint8_t>(i);

    std::mt19937 rng(seed ^ 0xA5A5A5A5u);
    for (int i = 255; i > 0; --i) {
        std::uniform_int_distribution<int> dist(0, i);
        int j = dist(rng);
        std::swap(pool[static_cast<size_t>(i)], pool[static_cast<size_t>(j)]);
    }

    std::array<uint8_t, static_cast<size_t>(Op::COUNT)> map{};
    for (int logical = 0; logical < Op::COUNT; ++logical)
        map[static_cast<size_t>(logical)] = pool[static_cast<size_t>(logical)];
    return map;
}

inline uint32_t packABC(uint8_t op, uint8_t a, uint8_t b, uint8_t c) {
    return uint32_t(op) | (uint32_t(a) << 8) | (uint32_t(b) << 16) | (uint32_t(c) << 24);
}

inline uint32_t packAD(uint8_t op, uint8_t a, int16_t d) {
    return uint32_t(op) | (uint32_t(a) << 8) | (uint32_t(uint16_t(d)) << 16);
}

inline uint32_t rotateLeft(uint32_t w, uint32_t r) {
    r &= 31u;
    if (r == 0) return w;
    return (w << r) | (w >> (32u - r));
}

inline uint32_t rotateRight(uint32_t w, uint32_t r) {
    r &= 31u;
    if (r == 0) return w;
    return (w >> r) | (w << (32u - r));
}

inline uint32_t insnRotateAmount(uint32_t bseed) {
    return ((bseed >> 3) & 7u) + 1u;
}

inline uint32_t sealKey(uint32_t bseed, uint32_t index) {
    uint32_t k = bseed ^ (index * 0x9E3779B9u);
    k ^= (k << 13);
    k ^= (k >> 17);
    k ^= (k << 5);
    return k;
}

inline uint32_t sealInsn(uint32_t word, uint32_t bseed, uint32_t index) {
    uint32_t w = word ^ sealKey(bseed, index);
    return rotateLeft(w, insnRotateAmount(bseed));
}

inline uint32_t unsealInsn(uint32_t word, uint32_t bseed, uint32_t index) {
    uint32_t w = rotateRight(word, insnRotateAmount(bseed));
    return w ^ sealKey(bseed, index);
}

inline void sealStringBytes(std::vector<uint8_t>& bytes, uint32_t bseed) {
    for (size_t j = 0; j < bytes.size(); ++j) {
        uint8_t k1 = uint8_t((bseed + uint32_t(j) * 13u) & 0xFFu);
        uint8_t k2 = uint8_t(((bseed >> 8) + uint32_t(j) * 37u + 91u) & 0xFFu);
        bytes[j] = uint8_t(bytes[j] ^ k1 ^ k2);
    }
}

} // namespace Protect

// ---- translator.cpp / translator.hpp compatibility (no Protect:: prefix needed) ----
using Protect::Op;
using Protect::FLY_MAGIC;
using Protect::LPR2_MAGIC;
using Protect::mix32;
using Protect::makeOpcodeMap;
using Protect::packABC;
using Protect::packAD;
using Protect::sealInsn;
using Protect::unsealInsn;
using Protect::sealStringBytes;
using Protect::insnRotateAmount;
using Protect::sealKey;