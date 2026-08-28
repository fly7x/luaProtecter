#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace Protect {

struct VirtualInstruction {
    uint8_t opcode = 0;
    uint8_t a = 0;
    uint8_t b = 0;
    uint8_t c = 0;
    int32_t d = 0;
    int32_t e = 0;
    uint32_t aux = 0;
    bool hasAux = false;
};

struct VirtualProgram {
    uint32_t version = 1;
    uint64_t key = 0;
    std::vector<VirtualInstruction> instructions;
    std::vector<std::string> strings;
    std::vector<double> numbers;
};

class Virtualizer {
public:
    struct Options {
        bool encryptConstants = true;
        bool shuffleOpcodes = true;
        bool remapRegisters = true;
        bool encodeInstructions = true;
        bool polymorphic = true;
    };
    
    explicit Virtualizer(uint64_t seed);
    
    VirtualProgram virtualize(const std::string& luauBytecode, const Options& options) const;
    std::string emitLuau(const VirtualProgram& program) const;
    
private:
    uint64_t seed_;
    
    static uint32_t readU32(const std::string& data, size_t& offset);
    static uint8_t opcode(uint32_t instruction);
    static uint8_t A(uint32_t instruction);
    static uint8_t B(uint32_t instruction);
    static uint8_t C(uint32_t instruction);
    static int16_t D(uint32_t instruction);
    static int32_t E(uint32_t instruction);
    
    uint64_t nextKey(uint64_t value) const;
    uint32_t mix(uint32_t value, uint64_t key) const;
};

} // namespace Protect