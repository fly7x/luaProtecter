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

    // Generate a self-contained Luau script with VM interpreter
    std::string emitVirtualizedScript(const Bytecode& obfuscatedBytecode,
                                      const Options& options) const;

private:
    uint64_t seed_;

    std::string bytecodeToLuaTable(const std::vector<uint8_t>& data) const;
    std::string generateVMName() const;
    std::string generateAntiDebug() const;
    std::string generateDecryptor() const;
    std::string generateInterpreter(const std::string& bytecodeTableVar,
                                    const std::string& seedVar,
                                    bool antiDebug) const;
};

} // namespace Protect