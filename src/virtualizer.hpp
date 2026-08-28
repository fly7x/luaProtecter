#pragma once

#include "bytecode.hpp"
#include <string>
#include <vector>
#include <cstdint>

namespace Protect {

struct VirtualInstruction {
    uint8_t opcode;
    uint8_t a, b, c;
    int32_t d;
    uint32_t aux;
    bool hasAux;
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
    
    // Generate a Luau script that contains the VM and the encrypted bytecode
    // The VM will decrypt and execute the bytecode at runtime.
    std::string emitVirtualizedScript(const Bytecode& obfuscatedBytecode, 
                                      const Options& options) const;
    
private:
    uint64_t seed_;
    
    // Helper to generate a random-looking key from seed
    uint64_t nextKey() const;
    
    // Convert bytecode to a Lua string literal (hex or escaped)
    std::string bytecodeToLuaString(const std::vector<uint8_t>& data) const;
};

} // namespace Protect