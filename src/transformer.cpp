#include "transformer.hpp"
#include "compiler.hpp"
#include "translator.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"

#include <chrono>
#include <random>
#include <stdexcept>
#include <sstream>
#include <cstdint>

Transformer::Transformer() : seed_(0) {}
Transformer::Transformer(uint64_t seed) : seed_(seed) {}

uint64_t Transformer::generateSeed() const {
    if (seed_) return seed_;
    std::random_device rd;
    uint64_t s = (uint64_t(rd()) << 32) ^ uint64_t(rd());
    s ^= uint64_t(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    if (!s) s = 0xA341316C9E3779B9ULL;
    return s;
}

std::string Transformer::removeComments(const std::string& source) const {
    std::string out;
    out.reserve(source.size());
    bool inStr = false;
    char quote = 0;
    bool esc = false;
    for (size_t i = 0; i < source.size(); ++i) {
        char c = source[i];
        if (inStr) {
            out += c;
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == quote) inStr = false;
            continue;
        }
        if (c == '"' || c == '\'') {
            inStr = true;
            quote = c;
            out += c;
            continue;
        }
        if (c == '-' && i + 1 < source.size() && source[i + 1] == '-') {
            if (i + 3 < source.size() && source[i + 2] == '[' && source[i + 3] == '[') {
                i += 3;
                while (i + 1 < source.size() && !(source[i] == ']' && source[i + 1] == ']'))
                    ++i;
                if (i + 1 < source.size()) ++i;
                continue;
            }
            while (i < source.size() && source[i] != '\n') ++i;
            if (i < source.size()) out += '\n';
            continue;
        }
        out += c;
    }
    return out;
}

std::string Transformer::emitHybrid(const std::string& source, uint32_t seed) const {
    // keep your existing hybrid-vm emitter if you still use mode hybrid;
    // main product path is full VM below.
    (void)source;
    (void)seed;
    return "error('hybrid disabled; use vm mode')\n";
}

std::string Transformer::protect(const std::string& source) const {
    Options opts;
    return protect(source, opts);
}

std::string Transformer::protect(const std::string& source, const Options& options) const {
    if (source.empty())
        throw std::runtime_error("empty source");

    // ONE seed for Translator + Obfuscator + Virtualizer (critical for inv)
    uint32_t seed = options.polymorphic
        ? uint32_t(generateSeed())
        : (options.seed ? uint32_t(options.seed) : 0xA341316Cu);
    if (!seed) seed = 0xA341316C;

    std::string processed = source;
    if (options.removeComments)
        processed = removeComments(processed);

    // hybrid only if explicitly requested
    if (options.wholeScriptEncrypt && !options.virtualize)
        return emitHybrid(processed, seed);

    Compiler compiler;
    auto compiled = compiler.compile(processed);
    if (!compiled.success)
        throw std::runtime_error(std::string("Compilation failed: ") + compiled.error);

    Translator translator(seed);
    auto translated = translator.translate(compiled.bytecode);
    if (!translated.success)
        throw std::runtime_error(std::string("Translate failed: ") + translated.error);

    Obfuscator obfuscator(seed);
    Bytecode sealed = obfuscator.obfuscate(translated.encoded);

    Protect::Virtualizer::Options vopts;
    vopts.heads = (options.vmHeads <= 1) ? 1 : 2;
    vopts.watchdog = true;

    Protect::Virtualizer virtualizer(seed);
    return virtualizer.emitVirtualizedScript(sealed, vopts);
}