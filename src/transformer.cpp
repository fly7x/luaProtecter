#include "transformer.hpp"
#include "compiler.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"
#include <regex>
#include <sstream>

Transformer::Transformer() : seed_(generateSeed()) {}

Transformer::Transformer(uint64_t seed) : seed_(seed) {
    if (seed_ == 0) seed_ = generateSeed();
}

uint64_t Transformer::generateSeed() const {
    auto now = std::chrono::high_resolution_clock::now()
        .time_since_epoch()
        .count();
    return static_cast<uint64_t>(now) ^ 0x9E3779B97F4A7C15ULL;
}

std::string Transformer::validateLuau(const std::string& source) const {
    // Basic validation - check for obvious syntax issues
    if (source.empty()) {
        throw std::runtime_error("Source code is empty");
    }
    
    // Check for balanced parentheses, brackets, etc.
    int parens = 0, braces = 0, brackets = 0;
    bool inString = false;
    char stringChar = 0;
    
    for (char c : source) {
        if (inString) {
            if (c == '\\') {
                // Skip escaped character
                continue;
            }
            if (c == stringChar) {
                inString = false;
            }
            continue;
        }
        
        switch (c) {
            case '"': case '\'':
                inString = true;
                stringChar = c;
                break;
            case '(': parens++; break;
            case ')': parens--; break;
            case '{': braces++; break;
            case '}': braces--; break;
            case '[': brackets++; break;
            case ']': brackets--; break;
        }
    }
    
    if (parens != 0 || braces != 0 || brackets != 0) {
        throw std::runtime_error("Unbalanced parentheses, braces, or brackets");
    }
    
    return source;
}

std::string Transformer::normalize(const std::string& source) const {
    std::string result = source;
    
    // Remove comments (basic)
    std::regex commentPattern("--[^\n]*");
    result = std::regex_replace(result, commentPattern, "");
    
    // Normalize whitespace (basic)
    std::regex multiSpace("\\s+");
    result = std::regex_replace(result, multiSpace, " ");
    
    return result;
}

std::string Transformer::protect(const std::string& source) const {
    Options defaultOptions;
    return protect(source, defaultOptions);
}

std::string Transformer::protect(const std::string& source, const Options& options) const {
    // Validate input
    std::string validated = validateLuau(source);
    
    // Normalize
    std::string normalized = options.removeComments ? normalize(validated) : validated;
    
    // Apply transformations
    return transform(normalized, options);
}

std::string Transformer::transform(const std::string& source, const Options& options) const {
    // Step 1: Compile to bytecode
    Compiler compiler;
    Compiler::Result compileResult = compiler.compile(source);
    
    if (!compileResult.success) {
        throw std::runtime_error("Compilation failed: " + compileResult.error);
    }
    
    // Step 2: Obfuscate bytecode
    Obfuscator obfuscator(static_cast<uint32_t>(options.seed));
    Bytecode obfuscated = obfuscator.transform(
        Bytecode(std::move(compileResult.bytecode))
    );
    
    // Step 3: Virtualize if requested
    if (options.virtualize) {
        Protect::Virtualizer virtualizer(options.seed);
        Protect::Virtualizer::Options vmOptions;
        vmOptions.encryptConstants = true;
        vmOptions.shuffleOpcodes = true;
        vmOptions.remapRegisters = true;
        vmOptions.encodeInstructions = true;
        vmOptions.polymorphic = options.polymorphic;
        
        Protect::VirtualProgram program = virtualizer.virtualize(
            obfuscated.toString(),
            vmOptions
        );
        
        return virtualizer.emitLuau(program);
    }
    
    // Fallback: return as bytecode string
    return obfuscated.toString();
}