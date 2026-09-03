#pragma once

#include <array>
#include <cstdint>
#include <numeric>
#include <random>
#include <algorithm>

enum class Op : uint8_t {
    MOVE = 0,
    LOADK,
    LOADNIL,
    LOADBOOL,
    ADD,
    SUB,
    MUL,
    DIV,
    MOD,
    POW,
    UNM,
    NOT,
    LEN,
    CONCAT,
    JMP,
    JMPIF,
    JMPIFNOT,
    EQ,
    LT,
    LE,
    GETGLOBAL,
    SETGLOBAL,
    GETTABLE,
    SETTABLE,
    GETTABLEKS,
    SETTABLEKS,
    NEWTABLE,
    CALL,
    RETURN,
    FORLOOP,
    FORPREP,
    CLOSURE,
    VARARG,
    NAMECALL,
    GETUPVAL,
    SETUPVAL,
    SETLIST,
    COUNT
};

inline std::array<uint8_t, static_cast<size_t>(Op::COUNT)>
makeOpcodeMap(uint32_t seed) {
    std::array<uint8_t, static_cast<size_t>(Op::COUNT)> map{};
    std::array<uint8_t, 240> pool{};
    std::iota(pool.begin(), pool.end(), static_cast<uint8_t>(1));
    std::mt19937 rng(seed ^ 0xA5A5A5A5u);
    std::shuffle(pool.begin(), pool.end(), rng);
    for (size_t i = 0; i < map.size(); ++i)
        map[i] = pool[i];
    return map;
}

inline uint32_t packABC(uint8_t op, uint8_t a, uint8_t b, uint8_t c) {
    return uint32_t(op) | (uint32_t(a) << 8) | (uint32_t(b) << 16) | (uint32_t(c) << 24);
}

inline uint32_t packAD(uint8_t op, uint8_t a, int16_t d) {
    return uint32_t(op) | (uint32_t(a) << 8) | (uint32_t(uint16_t(d)) << 16);
}

inline uint8_t  insnOp(uint32_t insn) { return uint8_t(insn & 0xFF); }
inline uint8_t  insnA(uint32_t insn)  { return uint8_t((insn >> 8) & 0xFF); }
inline uint8_t  insnB(uint32_t insn)  { return uint8_t((insn >> 16) & 0xFF); }
inline uint8_t  insnC(uint32_t insn)  { return uint8_t((insn >> 24) & 0xFF); }
inline int16_t  insnD(uint32_t insn)  { return int16_t(insn >> 16); }