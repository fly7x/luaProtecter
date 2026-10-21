#include "transformer.hpp"
#include "compiler.hpp"
#include "translator.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"
#include "isa.hpp"

#include <chrono>
#include <random>
#include <stdexcept>
#include <sstream>
#include <cstdint>
#include <vector>
#include <string>
#include <cstdio>

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

static std::string flyBanner(const char* modeLine) {
    std::ostringstream o;
    o << "--[[\n";
    o << "  ╔══════════════════════════════════════════╗\n";
    o << "  ║          FŁÝ  ·  FLYX  Protection         ║\n";
    o << "  ║  " << modeLine << "\n";
    o << "  ╚══════════════════════════════════════════╝\n";
    o << "]]\n";
    return o.str();
}

std::string Transformer::emitHybrid(const std::string& source, uint32_t seed) const {
    std::vector<uint8_t> plain(source.begin(), source.end());

    uint32_t s1 = seed;
    for (size_t i = 0; i < plain.size(); ++i) {
        s1 = mix32(s1 + uint32_t(i) + 0x9E3779B9u);
        uint8_t k = uint8_t(s1 ^ (s1 >> 8) ^ uint8_t(i * 131u + 17u));
        plain[i] = uint8_t(plain[i] ^ k);
    }
    uint32_t s2 = seed ^ 0xC2B2AE35u;
    for (size_t i = plain.size(); i-- > 0; ) {
        s2 = mix32(s2 + uint32_t(i) * 0x85EBCA6Bu);
        uint8_t k = uint8_t(s2 ^ (s2 >> 16) ^ uint8_t(i * 47u + 91u));
        plain[i] = uint8_t(plain[i] ^ k);
    }

    uint32_t sum = 0;
    for (uint8_t b : plain) sum += b;

    uint32_t psum = 0;
    for (size_t i = 0; i < source.size(); ++i)
        psum = (psum + uint8_t(source[i]) * (1u + uint32_t(i % 7))) & 0xFFFFFFFFu;

    size_t n = plain.size();
    size_t n1 = n / 3, n2 = n / 3, n3 = n - n1 - n2;

    auto hid = [&](uint32_t tag) {
        uint32_t h = mix32(seed ^ tag ^ 0x811C9DC5u);
        char buf[16];
        std::snprintf(buf, sizeof(buf), "_%x", h & 0xFFFFFFu);
        return std::string(buf);
    };
    std::string A = hid(1), B = hid(2), C = hid(3), go = hid(4);

    std::ostringstream o;
    o << flyBanner("Hybrid  ·  multi-pass  ·  sealed      ");

    auto emitChunk = [&](const std::string& name, size_t off, size_t len) {
        o << "local " << name << "={";
        for (size_t i = 0; i < len; ++i) {
            if (i) o << ",";
            if (i && (i % 18) == 0) o << "\n";
            o << int(plain[off + i]);
        }
        o << "}\n";
    };
    emitChunk(A, 0, n1);
    emitChunk(B, n1, n2);
    emitChunk(C, n1 + n2, n3);

    o << "local K={" << seed << "," << (seed ^ 0xC2B2AE35u) << "," << psum << "," << sum << "}\n";
    o << "local function " << go << "()\n";
    o << "local sealed={}\n";
    o << "for i=1,#" << A << " do sealed[#sealed+1]=" << A << "[i] end\n";
    o << "for i=1,#" << B << " do sealed[#sealed+1]=" << B << "[i] end\n";
    o << "for i=1,#" << C << " do sealed[#sealed+1]=" << C << "[i] end\n";
    o << "do local s=0 for i=1,#sealed do s+=sealed[i] end if s~=K[4] then return end end\n";
    o << A << "," << B << "," << C << "=nil,nil,nil\n";
    o << "local function mix(x)\n";
    o << "x=bit32.bxor(x,bit32.rshift(x,16)) x=bit32.band(x*0x7FEB352D,0xFFFFFFFF)\n";
    o << "x=bit32.bxor(x,bit32.rshift(x,15)) x=bit32.band(x*0x846CA68B,0xFFFFFFFF)\n";
    o << "x=bit32.bxor(x,bit32.rshift(x,16)) return x end\n";
    o << "local function decBytes(chunk)\n";
    o << "local o={} for i=1,#chunk do o[i]=chunk[i] end\n";
    o << "local s=K[2]\n";
    o << "for i=#o,1,-1 do\n";
    o << "s=mix(s+i*0x85EBCA6B)\n";
    o << "local k=bit32.band(bit32.bxor(s,bit32.rshift(s,16),i*47+91),255)\n";
    o << "o[i]=bit32.band(bit32.bxor(o[i],k),255)\n";
    o << "end\n";
    o << "s=K[1]\n";
    o << "for i=1,#o do\n";
    o << "s=mix(s+i-1+0x9E3779B9)\n";
    o << "local k=bit32.band(bit32.bxor(s,bit32.rshift(s,8),i*131+17),255)\n";
    o << "o[i]=bit32.band(bit32.bxor(o[i],k),255)\n";
    o << "end\n";
    o << "local t={} for i=1,#o do t[i]=string.char(o[i]) end return table.concat(t)\n";
    o << "end\n";
    o << "local src=decBytes(sealed) sealed=nil\n";
    o << "local function psum(s)\n";
    o << "local sum=0 for i=1,#s do sum=bit32.band(sum+string.byte(s,i)*(1+(i-1)%7),0xFFFFFFFF) end return sum\n";
    o << "end\n";
    o << "if psum(src)~=K[3] then return end\n";
    o << "local ld=loadstring or load\n";
    o << "if type(ld)~=\"function\" then error(\"x\") end\n";
    o << "local fn,err=ld(src) src=nil\n";
    o << "if not fn then error(tostring(err)) end\n";
    o << "return fn()\n";
    o << "end\n";
    o << "return " << go << "()\n";
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
    if (!seed) seed = 0xA341316C;

    std::string processed = source;
    if (options.removeComments)
        processed = removeComments(processed);

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
    vopts.strictEnv = options.strictEnv;
    vopts.safeParse = options.safeParse;
    vopts.dense = true;

    Protect::Virtualizer virtualizer(seed);
    return virtualizer.emitVirtualizedScript(sealed, vopts);
}