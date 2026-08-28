#pragma once

#include "bytecode.hpp"
#include <string>
#include <cstdint>

namespace Protect {

class Virtualizer {
public:
    struct Options {
        bool encryptConstants = true;
        bool shuffleOpcodes = true;
        bool remapRegisters = true;
        bool encodeInstructions = true;
        bool polymorphic = true;
        bool antiDebug = true;
        bool controlFlowFlatten = true;
    };

    explicit Virtualizer(uint64_t seed);

    // Generate a self-contained Luau script that decrypts and executes the obfuscated bytecode
    // through a custom VM loader with anti-analysis measures.
    std::string emitVirtualizedScript(const Bytecode& obfuscatedBytecode,
                                      const Options& options) const;

private:
    uint64_t seed_;

    // Helper: convert bytecode to a Lua string literal (hex escaped)
    std::string bytecodeToLuaString(const std::vector<uint8_t>& data) const;

    // Generate a random-looking name for the VM table
    std::string generateVMName() const;

    // Generate a random-looking function name
    std::string generateFuncName() const;

    // Produce a Lua function that implements control flow flattening around the decryption + load
    std::string generateFlattenedLoader(const std::string& decryptedVar,
                                        const std::string& loadCall) const;
};

} // namespace Protect