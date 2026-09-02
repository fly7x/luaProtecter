#include "transformer.hpp"
#include "compiler.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"
#include <regex>
#include <sstream>
#include <chrono>
#include <stdexcept>

Transformer::Transformer() : seed_(generateSeed()) {}
Transformer::Transformer(uint64_t seed) : seed_(seed) { if (seed_ == 0) seed_ = generateSeed(); }

uint64_t Transformer::generateSeed() const {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return static_cast<uint64_t>(now) ^ 0x9E3779B97F4A7C15ULL;
}

// ---------- Source-level obfuscations (simple) ----------
std::string Transformer::renameLocals(const std::string& source) const {
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
        std::regex wordPattern("\\b" + orig + "\\b");
        result = std::regex_replace(result, wordPattern, ren);
    }
    return result;
}

std::string Transformer::encodeStringLiterals(const std::string& source) const {
    // Placeholder – we rely on VM encryption
    return source;
}

std::string Transformer::encodeNumberLiterals(const std::string& source) const {
    return source;
}

std::string Transformer::removeComments(const std::string& source) const {
    std::regex commentPattern("--[^\n]*");
    return std::regex_replace(source, commentPattern, "");
}

std::string Transformer::injectDecoys(const std::string& source) const {
    std::string junk = "local _junk = 42; _junk = _junk + 1;\n";
    return junk + source + "\n" + junk;
}

// ---------- Main protect ----------
std::string Transformer::protect(const std::string& source) const {
    Options defaultOpts;
    return protect(source, defaultOpts);
}

std::string Transformer::protect(const std::string& source, const Options& options) const {
    std::string processed = source;

    if (options.removeComments) processed = removeComments(processed);
    if (options.renameIdentifiers) processed = renameLocals(processed);
    if (options.encodeStrings) processed = encodeStringLiterals(processed);
    if (options.encodeNumbers) processed = encodeNumberLiterals(processed);
    if (options.decoys) processed = injectDecoys(processed);

    Compiler compiler;
    auto compileResult = compiler.compile(processed);
    if (!compileResult.success) {
        throw std::runtime_error("Compilation failed: " + compileResult.error);
    }

    Obfuscator obfuscator(static_cast<uint32_t>(options.seed));
    Bytecode encrypted = obfuscator.obfuscate(compileResult.bytecode);

    Protect::Virtualizer virtualizer(options.seed);
    Protect::Virtualizer::Options vmOpts;
    vmOpts.encryptConstants = true;
    vmOpts.shuffleOpcodes = true;
    vmOpts.remapRegisters = true;
    vmOpts.polymorphic = options.polymorphic;
    vmOpts.antiDebug = options.antiDebug;
    vmOpts.controlFlowFlatten = true;

    std::string virtualizedScript = virtualizer.emitVirtualizedScript(encrypted, vmOpts);
    return virtualizedScript;
}