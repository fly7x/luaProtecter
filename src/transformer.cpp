#include "transformer.hpp"
#include "compiler.hpp"
#include "translator.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"

#include <chrono>
#include <random>
#include <stdexcept>
#include <sstream>

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

std::string Transformer::encodeStringLiterals(const std::string& source, uint32_t seed) const {
    auto xorKey = [&](size_t i) -> uint8_t {
        return uint8_t((seed + uint32_t(i) * 131u + 17u) & 0xFFu);
    };

    std::string body;
    body.reserve(source.size() * 2);
    bool inStr = false;
    char quote = 0;
    std::string current;

    auto flushString = [&]() {
        body += "FLYS({";
        for (size_t i = 0; i < current.size(); ++i) {
            if (i) body += ',';
            body += std::to_string(int(uint8_t(current[i]) ^ xorKey(i)));
        }
        body += "})";
    };

    for (size_t i = 0; i < source.size(); ++i) {
        char c = source[i];
        if (inStr) {
            if (c == '\\' && i + 1 < source.size()) {
                char n = source[i + 1];
                if (n == 'n') { current.push_back('\n'); ++i; continue; }
                if (n == 't') { current.push_back('\t'); ++i; continue; }
                if (n == 'r') { current.push_back('\r'); ++i; continue; }
                if (n == '\\' || n == '"' || n == '\'') { current.push_back(n); ++i; continue; }
            }
            if (c == quote) {
                flushString();
                inStr = false;
                current.clear();
                continue;
            }
            current.push_back(c);
            continue;
        }
        if (c == '"' || c == '\'') {
            inStr = true;
            quote = c;
            current.clear();
            continue;
        }
        body += c;
    }

    std::ostringstream out;
    out << "local function FLYS(t)\n";
    out << "local s=" << seed << "\n";
    out << "local o={}\n";
    out << "for i=1,#t do\n";
    out << "local k=bit32.band(s+(i-1)*131+17,255)\n";
    out << "o[i]=string.char(bit32.band(bit32.bxor(t[i],k),255))\n";
    out << "end\n";
    out << "return table.concat(o)\n";
    out << "end\n";
    out << body;
    return out.str();
}

std::string Transformer::injectDecoys(const std::string& source, uint32_t seed) const {
    uint32_t a = seed % 9973u;
    uint32_t b = (seed >> 8) % 7919u;
    std::ostringstream j;
    j << "do local _a=" << a << " local _b=" << b << "\n";
    j << "if _a*_a<0 then error(\"x\") end\n";
    j << "if (_a+_b)*(_a-_b)~=(_a*_a-_b*_b) then return end end\n";
    return j.str() + source;
}

std::string Transformer::injectAntiDebug(const std::string& source, uint32_t seed) const {
    (void)seed;
    std::ostringstream a;
    a << "do local _t=os.clock() local _n=0 for _i=1,40 do _n+=_i end\n";
    a << "if os.clock()-_t>3 then return end if _n~=820 then return end end\n";
    return a.str() + source;
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
    if (options.encodeStrings)
        processed = encodeStringLiterals(processed, seed);
    if (options.decoys)
        processed = injectDecoys(processed, seed);
    if (options.antiDebug)
        processed = injectAntiDebug(processed, seed);

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
    Protect::Virtualizer virtualizer(seed);
    return virtualizer.emitVirtualizedScript(encrypted, vopts);
}