#pragma once

#include "bytecode.hpp"
#include <string>
#include <cstdint>
#include <vector>

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
        bool useCustomOpcodes = true;  // if false, use standard Luau opcodes
    };

    explicit Virtualizer(uint64_t seed);

    // Generate a self-contained Luau script that decrypts the bytecode and interprets it
    std::string emitVirtualizedScript(const Bytecode& obfuscatedBytecode,
                                      const Options& options) const;

private:
    uint64_t seed_;

    // Convert bytecode to a Lua table of instruction words
    std::string bytecodeToLuaTable(const std::vector<uint8_t>& data) const;

    // Generate a random-looking name for the VM table
    std::string generateVMName() const;

    // Generate the interpreter loop as a string
    std::string generateInterpreter(const std::string& bytecodeTableVar,
                                    const std::string& seedVar,
                                    bool antiDebug) const;

    // Generate anti-debug code (if enabled)
    std::string generateAntiDebug() const;

    // Generate decryption function (same as before)
    std::string generateDecryptor() const;
};

} // namespace Protect