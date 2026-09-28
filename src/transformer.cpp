#include "transformer.hpp"
#include "compiler.hpp"

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

std::string Transformer::emitLoadstringBootstrap(const std::string& payload, uint32_t seed) const {
    // XOR payload bytes
    std::vector<uint8_t> enc;
    enc.reserve(payload.size());
    for (size_t i = 0; i < payload.size(); ++i) {
        uint8_t k = uint8_t((seed + uint32_t(i) * 131u + 17u) & 0xFFu);
        enc.push_back(uint8_t(payload[i]) ^ k);
    }

    uint32_t sum = 0;
    for (uint8_t b : enc)
        sum += b;

    std::ostringstream bytes;
    bytes << "{";
    for (size_t i = 0; i < enc.size(); ++i) {
        if (i) bytes << ",";
        if ((i % 16) == 0) bytes << "\n";
        bytes << int(enc[i]);
    }
    bytes << "}";

    std::ostringstream o;
    o << "--!nocheck\n";
    o << "--[[\n";
    o << "  ╔══════════════════════════════════════════╗\n";
    o << "  ║     Protected by FŁÝ / FLYX Obfuscator   ║\n";
    o << "  ║   Hybrid · encrypted payload · native    ║\n";
    o << "  ╚══════════════════════════════════════════╝\n";
    o << "]]\n";
    o << "local _B=" << bytes.str() << "\n";
    o << "do local s=0 for i=1,#_B do s+=_B[i] end if s~=" << sum << " then return end end\n";
    o << "local _s=" << seed << "\n";
    o << "local function _dec()\n";
    o << "local o={}\n";
    o << "for i=1,#_B do\n";
    o << "local k=bit32.band(_s+(i-1)*131+17,255)\n";
    o << "o[i]=string.char(bit32.band(bit32.bxor(_B[i],k),255))\n";
    o << "end\n";
    o << "return table.concat(o)\n";
    o << "end\n";
    o << "local _src=_dec()\n";
    o << "_B,_dec=nil,nil\n";
    // Executor-safe load
    o << "local _ld=loadstring or load\n";
    o << "if type(_ld)~=\"function\" then error(\"no loadstring\") end\n";
    o << "local _fn,err=_ld(_src)\n";
    o << "_src=nil\n";
    o << "if not _fn then error(tostring(err)) end\n";
    o << "return _fn()\n";
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

    std::string payload = source;
    if (options.removeComments)
        payload = removeComments(payload);

    // Soften _G writes for stricter sandboxes (still mainly for executors)
    // Users can keep source as-is; bootstrap doesn't change payload semantics.

    if (options.wholeScriptEncrypt) {
        // Validate payload is valid Luau before encrypting
        Compiler compiler;
        auto compiled = compiler.compile(payload);
        if (!compiled.success)
            throw std::runtime_error(std::string("Compile failed: ") + compiled.error);
        return emitLoadstringBootstrap(payload, seed);
    }

    throw std::runtime_error("wholeScriptEncrypt must be true for hybrid protection");
}