#include "transformer.hpp"
#include "compiler.hpp"
#include "obfuscator.hpp"
#include "translator.hpp"
#include "virtualizer.hpp"
#include <chrono>
#include <regex>
#include <stdexcept>
#include <algorithm>

Transformer::Transformer() : seed_(generateSeed()) {}
Transformer::Transformer(uint64_t seed) : seed_(seed ? seed : generateSeed()) {}

uint64_t Transformer::generateSeed() const {
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    return uint64_t(now) ^ 0x9E3779B97F4A7C15ULL;
}

std::string Transformer::renameLocals(const std::string& source) const {
    std::string result = source;
    std::regex localDecl("local%s+([A-Za-z_][A-Za-z0-9_]*)");
    std::smatch match;
    int counter = 0;
    std::string::const_iterator start = result.begin();
    std::string::const_iterator end = result.end();
    std::vector<std::pair<std::string, std::string>> replacements;
    while (std::regex_search(start, end, match, localDecl)) {
        std::string original = match[1].str();
        bool seen = false;
        for (auto& p : replacements) if (p.first == original) seen = true;
        if (!seen) replacements.emplace_back(original, "v" + std::to_string(counter++));
        start = match.suffix().first;
    }
    for (const auto& [orig, ren] : replacements) {
        std::regex wordPattern(std::string("\\b") + orig + "\\b");
        result = std::regex_replace(result, wordPattern, ren);
    }
    return result;
}

std::string Transformer::encodeStringLiterals(const std::string& source) const { return source; }
std::string Transformer::encodeNumberLiterals(const std::string& source) const { return source; }

std::string Transformer::removeComments(const std::string& source) const {
    std::regex commentPattern("--[^\\n]*");
    return std::regex_replace(source, commentPattern, "");
}

std::string Transformer::injectDecoys(const std::string& source) const {
    return source;
}

std::string Transformer::protect(const std::string& source) const {
    Options opts;
    return protect(source, opts);
}

std::string Transformer::protect(const std::string& source, const Options& options) const {
    std::string processed = source;
    if (options.removeComments) processed = removeComments(processed);
    if (options.renameIdentifiers) processed = renameLocals(processed);

    Compiler compiler;
    auto compiled = compiler.compile(processed);
    if (!compiled.success)
        throw std::runtime_error("Compilation failed: " + compiled.error);

    uint32_t seed = uint32_t(options.seed ? options.seed : seed_);

    Translator translator(seed);
    auto translated = translator.translate(compiled.bytecode);
    if (!translated.success)
        throw std::runtime_error("Translate failed: " + translated.error);

    Obfuscator obfuscator(seed);
    Bytecode encrypted = obfuscator.obfuscate(translated.encoded);

    Protect::Virtualizer virtualizer(seed);
    Protect::Virtualizer::Options vmOpts;
    vmOpts.antiDebug = options.antiDebug;
    vmOpts.polymorphic = options.polymorphic;
    return virtualizer.emitVirtualizedScript(encrypted, vmOpts);
}