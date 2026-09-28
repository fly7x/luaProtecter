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
#include <vector>
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

// Encrypt "..." and '...' into FLYS({bytes}) calls; inject decoder once.
std::string Transformer::encodeStringLiterals(const std::string& source, uint32_t seed) const {
    auto xorKey = [&](size_t i) -> uint8_t {
        return uint8_t((seed + i * 131u + 17u) & 0xFFu);
    };

    std::string body;
    body.reserve(source.size() * 2);
    bool inStr = false;
    char quote = 0;
    bool esc = false;
    std::string current;

    auto flushString = [&]() {
        if (current.empty() && quote) {
            body += "FLYS({})";
            return;
        }
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
            if (esc) {
                current.push_back(c);
                esc = false;
                continue;
            }
            if (c == '\\') {
                // keep escape semantics in decrypted string
                if (i + 1 < source.size()) {
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
                current.push_back(c);
                continue;
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
    junk << "do\n";
    junk << "local _a=" << (seed % 9973) << "\n";
    junk << "local _b=" << ((seed >> 8) % 7919) << "\n";
    junk << "if _a*_a<0 then\n";
    junk << "error(FLYS and FLYS({1,2,3}) or \"x\")\n";
    junk << "end\n";
    junk << "if (_a+_b)*(_a-_b)~=(_a*_a-_b*_b) then\n";
    junk << "return nil\n";
    junk << "end\n";
    junk << "end\n";
    return junk.str() + source;
}

std::string Transformer::injectAntiDebug(const std::string& source, uint32_t seed) const {
    std::ostringstream ad;
    ad << "do\n";
    ad << "local _t=os.clock()\n";
    ad << "local _n=0\n";
    ad << "for _i=1,50 do _n=_n+_i end\n";
    ad << "if os.clock()-_t>2.5 then return end\n";
    ad << "if _n~=" << (50 * 51 / 2) << " then return end\n";
    ad << "end\n";
    (void)seed;
    return ad.str() + source;
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

    // Optional light AST path (not max security)
    if (options.useAstPipeline && !options.virtualize) {
        Protect::AstOptions aopts;
        aopts.validateCompile = true;
        aopts.addBanner = true;
        auto result = Protect::astPassThrough(processed, aopts);
        if (!result.success)
            throw std::runtime_error(result.error);
        return result.code;
    }

    // ── MAX SECURITY LAYERS ──
    if (options.encodeStrings)
        processed = encodeStringLiterals(processed, seed);

    if (options.decoys)
        processed = injectDecoys(processed, seed);

    if (options.antiDebug)
        processed = injectAntiDebug(processed, seed);

    // Compile → private ISA → encrypt → VM
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