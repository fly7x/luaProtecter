#include "transformer.hpp"
#include "ast_pipeline.hpp"
#include "compiler.hpp"
#include "translator.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"

#include <chrono>
#include <random>
#include <stdexcept>
#include <sstream>
#include <cctype>

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
            if (i)
                body += ',';
            uint8_t b = uint8_t(current[i]) ^ xorKey(i);
            body += std::to_string(int(b));
        }
        body += "})";
    };

    for (size_t i = 0; i < source.size(); ++i) {
        char c = source[i];
        if (inStr) {
            if (c == '\\' && i + 1 < source.size()) {
                char n = source[i + 1];
                if (n == 'n') {
                    current.push_back('\n');
                    ++i;
                    continue;
                }
                if (n == 't') {
                    current.push_back('\t');
                    ++i;
                    continue;
                }
                if (n == 'r') {
                    current.push_back('\r');
                    ++i;
                    continue;
                }
                if (n == '\\' || n == '"' || n == '\'') {
                    current.push_back(n);
                    ++i;
                    continue;
                }
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
    std::ostringstream junk;
    uint32_t a = seed % 9973u;
    uint32_t b = (seed >> 8) % 7919u;
    junk << "do\n";
    junk << "local _a=" << a << " local _b=" << b << "\n";
    junk << "local _c=_a*_a-_b*_b\n";
    junk << "if _a*_a<0 then error(\"x\") end\n";
    junk << "if (_a+_b)*(_a-_b)~=_c then return end\n";
    junk << "local function _d(_) return _ end\n";
    junk << "if _d(0)~=0 then return end\n";
    junk << "end\n";
    return junk.str() + source;
}

std::string Transformer::injectAntiDebug(const std::string& source, uint32_t seed) const {
    std::ostringstream ad;
    ad << "do\n";
    ad << "local _t=os.clock()\n";
    ad << "local _n=0 for _i=1,40 do _n+=_i end\n";
    ad << "if os.clock()-_t>3 then return end\n";
    ad << "if _n~=820 then return end\n";
    ad << "end\n";
    (void)seed;
    return ad.str() + source;
}

std::string Transformer::wrapOpaqueShell(const std::string& source, uint32_t seed) const {
    // Always-true predicate; body is the real script
    uint32_t x = (seed % 1000) + 3;
    std::ostringstream o;
    o << "do\n";
    o << "local _x=" << x << "\n";
    o << "if (_x*_x)>=0 then\n";
    o << source;
    if (!source.empty() && source.back() != '\n')
        o << "\n";
    o << "end\n";
    o << "end\n";
    return o.str();
}

std::string Transformer::emitNativeProtected(const std::string& source, uint32_t seed, const Options& options) const {
    std::string body = source;

    if (options.encodeStrings)
        body = encodeStringLiterals(body, seed);

    if (options.decoys)
        body = injectDecoys(body, seed);

    if (options.antiDebug)
        body = injectAntiDebug(body, seed);

    if (options.wrapOpaque)
        body = wrapOpaqueShell(body, seed);

    // Validate still compiles as real Luau
    Compiler compiler;
    auto compiled = compiler.compile(body);
    if (!compiled.success)
        throw std::runtime_error(std::string("Native protect compile failed: ") + compiled.error);

    std::ostringstream out;
    out << "--!nocheck\n";
    out << "--[[\n";
    out << "  ╔══════════════════════════════════════════╗\n";
    out << "  ║     Protected by FŁÝ / FLYX Obfuscator   ║\n";
    out << "  ║   Hybrid · native Luau · max layers      ║\n";
    out << "  ╚══════════════════════════════════════════╝\n";
    out << "]]\n";
    out << body;
    if (!body.empty() && body.back() != '\n')
        out << "\n";
    return out.str();
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

    // ── PRIMARY: hybrid native (reliable + layered security) ──
    if (options.useAstPipeline && !options.virtualize) {
        // Optional parse gate
        Protect::AstOptions aopts;
        aopts.validateCompile = true;
        aopts.addBanner = false;
        auto gate = Protect::astPassThrough(processed, aopts);
        if (!gate.success)
            throw std::runtime_error(gate.error);

        return emitNativeProtected(processed, seed, options);
    }

    // ── OPTIONAL: full VM (off by default — fails often) ──
    if (options.virtualize) {
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

    return emitNativeProtected(processed, seed, options);
}