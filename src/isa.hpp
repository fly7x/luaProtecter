#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <string>

namespace Protect {

constexpr uint32_t FLY_MAGIC  = 0x33594C46u; // 'FLY3' LE
constexpr uint32_t LPR2_MAGIC = 0x3252504Cu; // 'LPR2' LE

enum class Op : uint8_t {
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
    JUNK = 45,
    SUPER_GETK = 46,
    SUPER_CALLK = 47,
    COUNT = 48
};

inline uint32_t packABC(uint8_t op, uint8_t a, uint8_t b, uint8_t c) {
    return uint32_t(op) | (uint32_t(a) << 8) | (uint32_t(b) << 16) | (uint32_t(c) << 24);
}

inline uint32_t packAD(uint8_t op, uint8_t a, int16_t d) {
    return uint32_t(op) | (uint32_t(a) << 8) | (uint32_t(uint16_t(d)) << 16);
}

inline uint32_t mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
}

inline uint32_t sealInsn(uint32_t insn, uint32_t seed, uint32_t index) {
    uint32_t k = seed ^ (index * 0x9E3779B9u);
    k ^= (k << 13);
    k ^= (k >> 17);
    k ^= (k << 5);
    uint32_t w = insn ^ k;
    uint32_t r = ((seed >> 3) & 7u) + 1u;
    return (w << r) | (w >> (32u - r));
}

inline void sealStringBytes(std::vector<uint8_t>& bytes, uint32_t seed) {
    for (size_t j = 0; j < bytes.size(); ++j) {
        uint8_t k1 = uint8_t((seed + uint32_t(j) * 13u) & 255u);
        uint8_t k2 = uint8_t(((seed >> 8) + uint32_t(j) * 37u + 91u) & 255u);
        bytes[j] = uint8_t(bytes[j] ^ k1 ^ k2);
    }
}

inline std::array<uint8_t, size_t(Op::COUNT)> makeOpcodeMap(uint32_t seed) {
    std::array<uint8_t, size_t(Op::COUNT)> map{};
    for (size_t i = 0; i < map.size(); ++i)
        map[i] = uint8_t(i);

    uint32_t s = seed ? seed : 0xA341316Cu;
    for (size_t i = map.size(); i > 1; --i) {
        s = mix32(s + uint32_t(i) * 0x9E3779B9u);
        size_t j = size_t(s % i);
        uint8_t tmp = map[i - 1];
        map[i - 1] = map[j];
        map[j] = tmp;
    }
    return map;
}

struct FlyConstant {
    enum Type : uint8_t { NIL = 0, BOOL = 1, NUMBER = 2, STRING = 3 };
    Type type = NIL;
    bool b = false;
    double n = 0;
    std::string s;
};

struct FlyProto {
    uint8_t maxstack = 8;
    uint8_t numparams = 0;
    uint8_t nups = 0;
    uint8_t isvararg = 0;
    std::vector<uint32_t> code;
    std::vector<FlyConstant> constants;
    std::vector<uint32_t> childProtos;
};

} // namespace Protect