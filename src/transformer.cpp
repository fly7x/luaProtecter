#include "transformer.hpp"
#include "compiler.hpp"
#include "translator.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"

#include <chrono>
#include <random>
#include <stdexcept>
#include <sstream>
#include <vector>
#include <cstdint>

Transformer::Transformer() : seed_(0) {}
Transformer::Transformer(uint64_t seed) : seed_(seed) {}

uint64_t Transformer::generateSeed() const {
    if (seed_)
        return seed_;
    std::random_device rd;
    uint64_t s = (uint64_t(rd()) << 32) ^ uint64_t(rd());
    s ^= uint64_t(std::chrono::high_resolution_clock::now().time_since_epoch().count());
    if (!s)
        s = 0xA341316C9E3779B9ULL;
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
            if (esc)
                esc = false;
            else if (c == '\\')
                esc = true;
            else if (c == quote)
                inStr = false;
            continue;
        }
        if (c == '"' || c == '\'') {
            inStr = true;
            quote = c;
            out += c;
            continue;
        }
        if (c == '-' && i + 1 < source.size() && source[i + 1] == '-') {
            // long comment --[[ ... ]]
            if (i + 3 < source.size() && source[i + 2] == '[' && source[i + 3] == '[') {
                i += 3;
                while (i + 1 < source.size() && !(source[i] == ']' && source[i + 1] == ']'))
                    ++i;
                if (i + 1 < source.size())
                    ++i;
                continue;
            }
            // line comment
            while (i < source.size() && source[i] != '\n')
                ++i;
            if (i < source.size())
                out += '\n';
            continue;
        }
        out += c;
    }
    return out;
}

std::string Transformer::emitHybrid(const std::string& source, uint32_t seed) const {
    // Multi-pass XOR, L/R split, checksum, sealed loader — no long-lived plaintext
    std::vector<uint8_t> plain(source.begin(), source.end());
    std::vector<uint8_t> enc(plain.size());
    uint32_t s1 = seed;
    uint32_t s2 = seed ^ 0xA5A5A5A5u;
    uint32_t sum = 0;
    for (size_t i = 0; i < plain.size(); ++i) {
        uint8_t k1 = uint8_t((s1 + uint32_t(i) * 131u + 17u) & 0xFFu);
        uint8_t k2 = uint8_t((s2 + uint32_t(i) * 47u + 91u) & 0xFFu);
        enc[i] = uint8_t(plain[i] ^ k1 ^ k2);
        sum += enc[i];
    }

    size_t mid = enc.size() / 2;
    std::ostringstream o;

    o << "--[[\n";
    o << "  ╔══════════════════════════════════════════╗\n";
    o << "  ║          FŁÝ  ·  FLYX  Protection         ║\n";
    o << "  ║     Hybrid  ·  multi-pass  ·  sealed      ║\n";
    o << "  ╚══════════════════════════════════════════╝\n";
    o << "]]\n";

    o << "local L={";
    for (size_t i = 0; i < mid; ++i) {
        if (i)
            o << ",";
        if ((i % 16) == 0)
            o << "\n";
        o << int(enc[i]);
    }
    o << "}\n";

    o << "local R={";
    for (size_t i = mid; i < enc.size(); ++i) {
        if (i > mid)
            o << ",";
        if (((i - mid) % 16) == 0)
            o << "\n";
        o << int(enc[i]);
    }
    o << "}\n";

    o << "local function _go()\n";
    o << "local B={}\n";
    o << "for i=1,#L do B[i]=L[i] end\n";
    o << "for i=1,#R do B[#L+i]=R[i] end\n";
    o << "do local s=0 for i=1,#B do s+=B[i] end if s~=" << sum << " then return end end\n";
    o << "L,R=nil,nil\n";
    o << "local a=" << s1 << " local b=" << s2 << "\n";
    o << "local function d()\n";
    o << "local o={}\n";
    o << "for i=1,#B do\n";
    o << "local k1=bit32.band(a+(i-1)*131+17,255)\n";
    o << "local k2=bit32.band(b+(i-1)*47+91,255)\n";
    o << "o[i]=string.char(bit32.band(bit32.bxor(B[i],k1,k2),255))\n";
    o << "end\n";
    o << "return table.concat(o)\n";
    o << "end\n";
    o << "local src=d()\n";
    o << "B,d,a,b=nil,nil,nil,nil\n";
    o << "local ld=loadstring or load\n";
    o << "if type(ld)~=\"function\" then error(\"x\") end\n";
    o << "local fn,e=ld(src)\n";
    o << "src=nil\n";
    o << "if not fn then error(tostring(e)) end\n";
    o << "return fn()\n";
    o << "end\n";
    o << "return _go()\n";

    return o.str();
}

std::string Transformer::protect(const std::string& source) const {
    Options opts;
    return protect(source, opts);
}

std::string Transformer::protect(const std::string& source, const Options& options) const {
    if (source.empty())
        throw std::runtime_error("empty source");

    uint32_t seed = options.polymorphic
        ? uint32_t(generateSeed())
        : (options.seed ? uint32_t(options.seed) : 0xA341316Cu);
    if (!seed)
        seed = 0xA341316C;

    std::string processed = source;
    if (options.removeComments)
        processed = removeComments(processed);

    // Hybrid path: native Luau + multi-pass encrypted payload
    if (options.wholeScriptEncrypt || !options.virtualize)
        return emitHybrid(processed, seed);

    // VM path: compile → translate → obfuscate blob → virtualizer (1 or 2 heads)
    Compiler compiler;
    auto compiled = compiler.compile(processed);
    if (!compiled.success)
        throw std::runtime_error(std::string("Compilation failed: ") + compiled.error);

    Translator translator(seed);
    auto translated = translator.translate(compiled.bytecode);
    if (!translated.success)
        throw std::runtime_error(std::string("Translate failed: ") + translated.error);

    Obfuscator obfuscator(seed);
    Bytecode encrypted = obfuscator.obfuscate(translated.encoded);

    Protect::Virtualizer::Options vopts;
    vopts.heads = (options.vmHeads <= 1) ? 1 : 2;
    vopts.watchdog = true;

    Protect::Virtualizer virtualizer(seed);
    return virtualizer.emitVirtualizedScript(encrypted, vopts);
}