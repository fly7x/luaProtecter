#pragma once

#include <array>
#include <cstdint>
#include <random>
#include <vector>

namespace Protect {

inline constexpr uint32_t FLY_MAGIC = 0x33594C46u;
inline constexpr uint32_t LPR2_MAGIC = 0x3252504Cu;

// Names MUST match translator.cpp (Op::LOADK, Op::NAMECALL, ...)
enum Op : int {
    MOVE = 0,
    LOADK = 1,
    LOADNIL = 2,
    LOADBOOL = 3,
    ADD = 4,
    SUB = 5,
    MUL = 6,
    DIV = 7,
    MOD = 8,
    POW = 9,
    UNM = 10,
    NOT = 11,
    LEN = 12,
    CONCAT = 13,
    JMP = 14,
    JMPIF = 15,
    JMPIFNOT = 16,
    EQ = 17,
    LT = 18,
    LE = 19,
    GETGLOBAL = 20,
    SETGLOBAL = 21,
    GETTABLE = 22,
    SETTABLE = 23,
    GETTABLEKS = 24,
    SETTABLEKS = 25,
    NEWTABLE = 26,
    CALL = 27,
    RETURN = 28,
    FORLOOP = 29,
    FORPREP = 30,
    CLOSURE = 31,
    VARARG = 32,
    NAMECALL = 33,
    GETUPVAL = 34,
    SETUPVAL = 35,
    SETLIST = 36,
    FORGLOOP = 37,
    CAPTURE = 38,
    AND = 39,
    OR = 40,
    GETTABLEN = 41,
    SETTABLEN = 42,
    IDIV = 43,
    EQK = 44,
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

// So translator.cpp can use Op::NAMECALL, mix32, sealInsn without Protect::
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