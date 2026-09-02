#pragma once

#include "bytecode.hpp"
#include <string>
#include <cstdint>
#include <array>
#include <vector>
#include <random>

namespace Protect {

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
    EQ,
    LT,
    LE,
    CALL,
    RETURN,
    FORLOOP,
    FORPREP,
    TFORCALL,
    TFORLOOP,
    SETLIST,
    CLOSURE,
    VARARG,
    COUNT
};

class Virtualizer {
public:
    struct Options {
        bool encryptConstants   = true;
        bool shuffleOpcodes     = true;
        bool remapRegisters     = true;
        bool encodeInstructions = true;
        bool polymorphic        = true;
        bool antiDebug          = true;
        bool controlFlowFlatten = true;
    };

    explicit Virtualizer(uint64_t seed);

    std::string emitVirtualizedScript(const Bytecode& obfuscatedBytecode,
                                      const Options& options) const;

private:
    uint64_t seed_;
    mutable std::mt19937 rng_;

    uint32_t nextU32() const;
    std::string ident(const char* prefix) const;
    std::array<uint8_t, static_cast<size_t>(Op::COUNT)> buildOpcodeMap() const;
    std::string bytecodeToLuaTable(const std::vector<uint8_t>& data) const;
    std::string generateDecryptor(const std::string& fnName) const;
    std::string generateAntiDebug(const std::string& fnName) const;
    std::string generateInterpreter(const std::string& bcVar,
                                    const std::string& seedVar,
                                    const std::string& decryptFn,
                                    const std::string& antiFn,
                                    const Options& options) const;
};

} // namespace Protect