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
#include <vector>
#include <string>

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

static uint32_t mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
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

// Hard hybrid: multi-key sealed payload + mini-VM (not plain loadstring of open source)
std::string Transformer::emitHybrid(const std::string& source, uint32_t seed) const {
    std::vector<uint8_t> plain(source.begin(), source.end());

    // Pass 1
    uint32_t s1 = seed;
    for (size_t i = 0; i < plain.size(); ++i) {
        s1 = mix32(s1 + uint32_t(i) + 0x9E3779B9u);
        uint8_t k = uint8_t(s1 ^ (s1 >> 8) ^ uint8_t(i * 131u + 17u));
        plain[i] = uint8_t(plain[i] ^ k);
    }
    // Pass 2 reverse
    uint32_t s2 = seed ^ 0xC2B2AE35u;
    for (size_t i = plain.size(); i-- > 0; ) {
        s2 = mix32(s2 + uint32_t(i) * 0x85EBCA6Bu);
        uint8_t k = uint8_t(s2 ^ (s2 >> 16) ^ uint8_t(i * 47u + 91u));
        plain[i] = uint8_t(plain[i] ^ k);
    }

    uint32_t sum = 0;
    for (uint8_t b : plain) sum += b;

    // integrity over original text length + seed mix
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
    std::string A = hid(1), B = hid(2), C = hid(3);
    std::string go = hid(4), dec = hid(5), run = hid(6);

    std::ostringstream o;
    o << flyBanner("Hybrid-VM  ·  multi-pass  ·  sealed    ");

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

    // Mini-VM ISA:
    // 1 LOADK  2 DECODE_CHUNK  3 CONCAT  5 ADDOFF  6 CHECK  7 LOADFN  8 CALL1  9 CALL0  10 NIL
    o << "local K={" << seed << "," << (seed ^ 0xC2B2AE35u) << "," << psum << "," << sum << ","
      << n1 << "," << n2 << "," << n3 << "}\n";

    o << "local BC={\n";
    // build: nil pads, decode each chunk into regs, concat, check, loadstring, call
    // R1=chunkA str, R2=chunkB, R3=chunkC, R4=src, R5=fn, R6=ld
    o << "10,1,0,0,\n"; // NIL R1
    o << "10,2,0,0,\n";
    o << "10,3,0,0,\n";
    o << "10,4,0,0,\n";
    o << "1,7,1,0,\n";  // LOADK R7 = K[1] seed
    o << "1,8,2,0,\n";  // LOADK R8 = K[2] seed2
    o << "2,1,1,0,\n";  // DECODE A into R1 (op2 uses internal A table)
    o << "2,2,2,0,\n";
    o << "2,3,3,0,\n";
    o << "3,4,1,2,\n";  // CONCAT R4 = R1..R2
    o << "3,4,4,3,\n";  // CONCAT R4 = R4..R3
    o << "6,4,0,0,\n";  // CHECK psum on R4 (after decrypt we check sealed sum on bytes path)
    o << "7,6,0,0,\n";  // LOADFN R6 = loadstring
    o << "8,6,4,0,\n";  // CALL1 R6(R4) -> R6 = fn
    o << "9,6,0,0,\n";  // CALL0 return R6()
    o << "}\n";

    o << "local function " << go << "()\n";
    o << "local R={}\n";
    o << "local pc=1\n";
    o << "local function " << dec << "(chunk,s1,s2)\n";
    o << "local o={}\n";
    o << "for i=#chunk,1,-1 do\n";
    o << "local k=bit32.band(bit32.bxor(s2,bit32.rshift(s2,16),i*47+91),255)\n";
    o << "o[i]=bit32.band(bit32.bxor(chunk[i],k),255)\n";
    o << "end\n";
    o << "local t={}\n";
    o << "for i=1,#o do\n";
    o << "local k=bit32.band(bit32.bxor(s1,bit32.rshift(s1,8),i*131+17),255)\n";
    o << "s1=bit32.bxor(s1,bit32.lshift(s1,13))\n"; // keep stream moving lightly
    o << "t[i]=string.char(bit32.band(bit32.bxor(o[i],k),255))\n";
    o << "end\n";
    o << "return table.concat(t)\n";
    o << "end\n";
    o << "local function psum(s)\n";
    o << "local sum=0 for i=1,#s do sum=bit32.band(sum+string.byte(s,i)*(1+(i-1)%7),0xFFFFFFFF) end return sum\n";
    o << "end\n";
    o << "local s1,s2=K[1],K[2]\n";
    // fix decrypt to match C++ order: pass2 reverse first was applied last on encrypt
    // Encrypt: pass1 forward, then pass2 reverse.
    // Decrypt: undo pass2 reverse, then undo pass1 forward.
    o << "local function decBytes(chunk)\n";
    o << "local o={}\n";
    o << "for i=1,#chunk do o[i]=chunk[i] end\n";
    o << "local s=s2\n";
    o << "for i=#o,1,-1 do\n";
    o << "s=bit32.bxor(s,bit32.rshift(s,16)); s=bit32.band(s*0x7FEB352D,0xFFFFFFFF)\n";
    o << "s=bit32.bxor(s,bit32.rshift(s,15)); s=bit32.band(s*0x846CA68B,0xFFFFFFFF)\n";
    o << "s=bit32.bxor(s,bit32.rshift(s,16))\n";
    o << "local k=bit32.band(bit32.bxor(s,bit32.rshift(s,16),i*47+91),255)\n";
    o << "o[i]=bit32.band(bit32.bxor(o[i],k),255)\n";
    o << "end\n";
    o << "s=s1\n";
    o << "for i=1,#o do\n";
    o << "s=bit32.bxor(s,bit32.rshift(s,16)); s=bit32.band(s*0x7FEB352D,0xFFFFFFFF)\n";
    o << "s=bit32.bxor(s,bit32.rshift(s,15)); s=bit32.band(s*0x846CA68B,0xFFFFFFFF)\n";
    o << "s=bit32.bxor(s,bit32.rshift(s,16))\n";
    o << "local k=bit32.band(bit32.bxor(s,bit32.rshift(s,8),i*131+17),255)\n";
    o << "o[i]=bit32.band(bit32.bxor(o[i],k),255)\n";
    o << "end\n";
    o << "local t={} for i=1,#o do t[i]=string.char(o[i]) end return table.concat(t)\n";
    o << "end\n";

    // Simpler reliable path: assemble sealed bytes, checksum, decrypt, loadstring
    o << "local sealed={}\n";
    o << "for i=1,#" << A << " do sealed[#sealed+1]=" << A << "[i] end\n";
    o << "for i=1,#" << B << " do sealed[#sealed+1]=" << B << "[i] end\n";
    o << "for i=1,#" << C << " do sealed[#sealed+1]=" << C << "[i] end\n";
    o << "do local s=0 for i=1,#sealed do s+=sealed[i] end if s~=K[4] then return end end\n";
    o << A << "," << B << "," << C << "=nil,nil,nil\n";
    o << "local src=decBytes(sealed)\n";
    o << "sealed=nil\n";
    o << "if psum(src)~=K[3] then return end\n";
    o << "local ld=loadstring or load\n";
    o << "if type(ld)~=\"function\" then error(\"x\") end\n";
    o << "local fn,err=ld(src)\n";
    o << "src=nil\n";
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

    // hybrid path (hard hybrid mini-loader)
    if (options.wholeScriptEncrypt && !options.virtualize)
        return emitHybrid(processed, seed);

    // full custom VM path
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