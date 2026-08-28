#include "transformer.hpp"
#include "compiler.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"
#include <regex>
#include <sstream>
#include <chrono>
#include <random>
#include <stdexcept>

Transformer::Transformer() : seed_(generateSeed()) {}
Transformer::Transformer(uint64_t seed) : seed_(seed) { if (seed_ == 0) seed_ = generateSeed(); }

uint64_t Transformer::generateSeed() const {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return static_cast<uint64_t>(now) ^ 0x9E3779B97F4A7C15ULL;
}

// ----- Source-level obfuscations (simple) -----

std::string Transformer::renameLocals(const std::string& source) const {
    // Very basic: rename local variables (this is just a demo; a real impl would parse)
    // For this example, we'll just replace 'local function' patterns
    std::string result = source;
    std::regex localDecl("local%s+([%a_][%w_]*)");
    std::smatch match;
    int counter = 0;
    std::string::const_iterator start = result.begin();
    std::string::const_iterator end = result.end();
    std::vector<std::pair<std::string, std::string>> replacements;
    while (std::regex_search(start, end, match, localDecl)) {
        std::string original = match[1].str();
        if (std::find_if(replacements.begin(), replacements.end(),
                         [&](const auto& p){ return p.first == original; }) == replacements.end()) {
            std::string renamed = "v" + std::to_string(counter++);
            replacements.emplace_back(original, renamed);
        }
        start = match.suffix().first;
    }
    for (const auto& [orig, ren] : replacements) {
        // Replace whole word only
        std::regex wordPattern("\\b" + orig + "\\b");
        result = std::regex_replace(result, wordPattern, ren);
    }
    return result;
}

std::string Transformer::encodeStringLiterals(const std::string& source) const {
    // Encode all string literals with a simple XOR + base64-like transform
    // For simplicity, we'll just encode with a static key (but in production use seed)
    std::string result = source;
    // This is a placeholder – we'll rely on the VM encryption for strings.
    // We'll just do a simple substitution for demo.
    std::regex stringPattern(R"("([^"]*)")");
    result = std::regex_replace(result, stringPattern, R"("obfuscated")");
    return result;
}

std::string Transformer::encodeNumberLiterals(const std::string& source) const {
    // Similar placeholder
    std::regex numberPattern(R"(\b(\d+)\b)");
    return std::regex_replace(source, numberPattern, "0");
}

std::string Transformer::removeComments(const std::string& source) const {
    std::regex commentPattern("--[^\n]*");
    return std::regex_replace(source, commentPattern, "");
}

std::string Transformer::injectDecoys(const std::string& source) const {
    // Insert junk code (e.g., useless variable assignments)
    std::string junk = "local _junk = 42; _junk = _junk + 1;\n";
    return junk + source + "\n" + junk;
}

// ----- Main protect -----

std::string Transformer::protect(const std::string& source) const {
    Options defaultOpts;
    return protect(source, defaultOpts);
}

std::string Transformer::protect(const std::string& source, const Options& options) const {
    std::string processed = source;

    // 1. Remove comments
    if (options.removeComments) {
        processed = removeComments(processed);
    }

    // 2. Rename locals
    if (options.renameIdentifiers) {
        processed = renameLocals(processed);
    }

    // 3. Encode strings (source-level)
    if (options.encodeStrings) {
        processed = encodeStringLiterals(processed);
    }

    // 4. Encode numbers
    if (options.encodeNumbers) {
        processed = encodeNumberLiterals(processed);
    }

    // 5. Inject decoys
    if (options.decoys) {
        processed = injectDecoys(processed);
    }

    // 6. Compile to bytecode
    Compiler compiler;
    auto compileResult = compiler.compile(processed);
    if (!compileResult.success) {
        throw std::runtime_error("Compilation failed: " + compileResult.error);
    }

    // 7. Obfuscate bytecode (encrypt)
    Obfuscator obfuscator(static_cast<uint32_t>(options.seed));
    Bytecode encrypted = obfuscator.obfuscate(compileResult.bytecode);

    // 8. Virtualize – generate VM loader
    Protect::Virtualizer virtualizer(options.seed);
    Protect::Virtualizer::Options vmOpts;
    vmOpts.encryptConstants = true;
    vmOpts.shuffleOpcodes = true;
    vmOpts.remapRegisters = true;
    vmOpts.polymorphic = options.polymorphic;
    vmOpts.antiDebug = options.antiDebug;
    vmOpts.controlFlowFlatten = true; // always flatten for better protection

    std::string virtualizedScript = virtualizer.emitVirtualizedScript(encrypted, vmOpts);

    return virtualizedScript;
}