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
#include <algorithm>

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
            if (i + 3 < source.size() && source[i + 2] == '[' && source[i + 3] == '[') {
                i += 3;
                while (i + 1 < source.size() && !(source[i] == ']' && source[i + 1] == ']'))
                    ++i;
                if (i + 1 < source.size())
                    ++i;
                continue;
            }
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
    // Hybrid + mini-VM loader:
    // encrypt → split chunks → private ISA rebuilds source in registers → loadstring → run
    // Does NOT virtualize the whole hub (Delta-safe).

    const size_t n = source.size();
    if (n == 0)
        return "return\n";

    uint32_t s1 = seed ? seed : 0xA341316Cu;
    uint32_t s2 = s1 ^ 0xC2B2AE35u;
    uint32_t s3 = (s1 * 0x9E3779B9u) ^ 0x85EBCA6Bu;

    std::vector<uint8_t> enc(n);
    for (size_t i = 0; i < n; ++i) {
        uint8_t k1 = uint8_t((s1 + uint32_t(i) * 131u + 17u) & 0xFFu);
        uint8_t k2 = uint8_t((s2 + uint32_t(i) * 47u + 91u) & 0xFFu);
        uint8_t k3 = uint8_t((s3 + uint32_t(i) * 19u + 63u) & 0xFFu);
        enc[i] = uint8_t(uint8_t(source[i]) ^ k1 ^ k2 ^ k3);
    }

    // plaintext integrity (checked after decode)
    uint32_t plainSum = 0;
    for (size_t i = 0; i < n; ++i)
        plainSum = (plainSum + uint8_t(source[i]) * (1u + uint32_t(i % 7))) & 0xFFFFFFFFu;

    size_t nChunks = 4;
    if (n > 4000) nChunks = 8;
    if (n > 20000) nChunks = 12;
    if (nChunks > n) nChunks = std::max<size_t>(1, n);

    std::vector<std::vector<uint8_t>> chunks(nChunks);
    {
        size_t base = n / nChunks;
        size_t rem = n % nChunks;
        size_t off = 0;
        for (size_t c = 0; c < nChunks; ++c) {
            size_t len = base + (c < rem ? 1 : 0);
            chunks[c].assign(enc.begin() + static_cast<std::ptrdiff_t>(off),
                             enc.begin() + static_cast<std::ptrdiff_t>(off + len));
            off += len;
        }
    }

    // Mini-ISA (private):
    // 1 LOADK a k   R[a]=K[k]
    // 2 DECODE a b  R[a]=decode(R[b], offset R[3])
    // 3 CONCAT a b c R[a]=(R[b] or "")..(R[c] or "")
    // 5 ADDOFF a b  R[a]=(tonumber(R[a])or 0)+#R[b]
    // 6 CHECK a     verify plaintext checksum of R[a]
    // 7 LOADFN a    R[a]=loadstring or load
    // 8 CALL1 a b   R[a]=R[a](R[b])
    // 9 CALL0 a     return R[a]()
    // 10 NIL a

    std::ostringstream o;
    o << "--[[\n";
    o << "  ╔══════════════════════════════════════════╗\n";
    o << "  ║          FŁÝ  ·  FLYX  Protection         ║\n";
    o << "  ║   Hybrid-VM  ·  sealed mini-ISA  ·  native║\n";
    o << "  ╚══════════════════════════════════════════╝\n";
    o << "]]\n";

    // K: [1]=s1 [2]=s2 [3]=s3 [4]=plainSum [5]=nChunks [6..]=chunk byte tables
    o << "local K={\n";
    o << s1 << "," << s2 << "," << s3 << "," << plainSum << "," << nChunks;
    for (size_t c = 0; c < nChunks; ++c) {
        o << ",{\n";
        for (size_t i = 0; i < chunks[c].size(); ++i) {
            if (i) o << ",";
            if ((i % 18) == 0) o << "\n";
            o << int(chunks[c][i]);
        }
        o << "}";
    }
    o << "\n}\n";

    o << "local BC={\n";
    auto emit = [&](int op, int a, int b, int c) {
        o << op << "," << a << "," << b << "," << c << ",\n";
    };

    emit(10, 1, 0, 0); // R1 = nil (acc)
    emit(10, 3, 0, 0); // R3 = nil (byte offset → 0)

    for (size_t c = 0; c < nChunks; ++c) {
        int kChunk = 6 + int(c);
        emit(1, 5, kChunk, 0); // LOADK R5 = chunk
        emit(2, 2, 5, 0);      // DECODE R2
        emit(3, 1, 1, 2);      // CONCAT R1
        emit(5, 3, 5, 0);      // ADDOFF R3 += #chunk
    }

    emit(6, 1, 0, 0);  // CHECK R1
    emit(7, 4, 0, 0);  // LOADFN R4
    emit(8, 4, 1, 0);  // R4 = load(R1)
    emit(10, 1, 0, 0); // wipe
    emit(10, 2, 0, 0);
    emit(10, 5, 0, 0);
    emit(9, 4, 0, 0);  // return R4()
    o << "}\n";

    o << "local function __fly_run()\n";
    o << "local R={}\n";
    o << "local pc=1\n";
    o << "local function dec(chunk, off0)\n";
    o << "local s1,s2,s3=K[1],K[2],K[3]\n";
    o << "local out={}\n";
    o << "local off=tonumber(off0) or 0\n";
    o << "for i=1,#chunk do\n";
    o << "local idx=off+i-1\n";
    o << "local k1=bit32.band(s1+idx*131+17,255)\n";
    o << "local k2=bit32.band(s2+idx*47+91,255)\n";
    o << "local k3=bit32.band(s3+idx*19+63,255)\n";
    o << "out[i]=string.char(bit32.band(bit32.bxor(chunk[i],k1,k2,k3),255))\n";
    o << "end\n";
    o << "return table.concat(out)\n";
    o << "end\n";
    o << "local function psum(s)\n";
    o << "local sum=0\n";
    o << "for i=1,#s do sum=bit32.band(sum+string.byte(s,i)*(1+(i-1)%7),0xFFFFFFFF) end\n";
    o << "return sum\n";
    o << "end\n";
    o << "while pc<=#BC do\n";
    o << "local op=BC[pc]; local a=BC[pc+1]; local b=BC[pc+2]; local c=BC[pc+3]\n";
    o << "pc=pc+4\n";
    o << "if op==1 then\n";
    o << "R[a]=K[b]\n";
    o << "elseif op==2 then\n";
    o << "R[a]=dec(R[b],R[3])\n";
    o << "elseif op==3 then\n";
    o << "R[a]=(R[b] or \"\")..(R[c] or \"\")\n";
    o << "elseif op==5 then\n";
    o << "local add=0\n";
    o << "if type(R[b])==\"table\" then add=#R[b] else add=tonumber(R[b]) or 0 end\n";
    o << "R[a]=(tonumber(R[a]) or 0)+add\n";
    o << "elseif op==6 then\n";
    o << "local s=R[a]\n";
    o << "if type(s)~=\"string\" or #s==0 then return end\n";
    o << "if psum(s)~=K[4] then return end\n";
    o << "elseif op==7 then\n";
    o << "R[a]=loadstring or load\n";
    o << "if type(R[a])~=\"function\" then error(\"x\") end\n";
    o << "elseif op==8 then\n";
    o << "local fn,err=R[a](R[b])\n";
    o << "if not fn then error(tostring(err)) end\n";
    o << "R[a]=fn\n";
    o << "elseif op==9 then\n";
    o << "return R[a]()\n";
    o << "elseif op==10 then\n";
    o << "R[a]=nil\n";
    o << "end\n";
    o << "end\n";
    o << "end\n";
    o << "return __fly_run()\n";

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

    // Hybrid-VM path (release path for large scripts)
    if (options.wholeScriptEncrypt || !options.virtualize)
        return emitHybrid(processed, seed);

    // Full script VM path (small scripts only)
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