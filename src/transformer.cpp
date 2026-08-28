#include "transformer.hpp"
#include "compiler.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"
#include <stdexcept>
#include <sstream>
#include <regex>

Transformer::Transformer() : seed_(generateSeed()) {}
Transformer::Transformer(uint64_t seed) : seed_(seed) { if (seed_ == 0) seed_ = generateSeed(); }

uint64_t Transformer::generateSeed() const {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return static_cast<uint64_t>(now) ^ 0x9E3779B97F4A7C15ULL;
}

std::string Transformer::protect(const std::string& source) const {
    Options defaultOpts;
    return protect(source, defaultOpts);
}

std::string Transformer::protect(const std::string& source, const Options& options) const {
    // Step 1: Compile source to Luau bytecode
    Compiler compiler;
    auto compileResult = compiler.compile(source);
    if (!compileResult.success) {
        throw std::runtime_error("Compilation failed: " + compileResult.error);
    }
    
    // Step 2: Obfuscate (encrypt) the bytecode
    Obfuscator obfuscator(static_cast<uint32_t>(options.seed));
    Bytecode encrypted = obfuscator.obfuscate(compileResult.bytecode);
    
    // Step 3: Virtualize – generate VM wrapper that decrypts and executes
    Protect::Virtualizer virtualizer(options.seed);
    Protect::Virtualizer::Options vmOpts;
    vmOpts.encryptConstants = true;
    vmOpts.shuffleOpcodes = true;
    vmOpts.remapRegisters = true;
    vmOpts.polymorphic = options.polymorphic;
    
    std::string virtualizedScript = virtualizer.emitVirtualizedScript(encrypted, vmOpts);
    
    return virtualizedScript;
}