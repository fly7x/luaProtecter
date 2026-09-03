#include "transformer.hpp"
#include "compiler.hpp"
#include "translator.hpp"
#include "obfuscator.hpp"
#include "virtualizer.hpp"
#include <regex>
#include <unordered_set>
#include <chrono>
#include <random>

static bool isReserved(const std::string& name) {
    static const std::unordered_set<std::string> words = {
        "and","break","do","else","elseif","end","false","for","function",
        "if","in","local","nil","not","or","repeat","return","then","true",
        "until","while","continue","export","type"
    };
    return words.count(name) != 0;
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
                while (i + 1 < source.size() && !(source[i] == ']' && source[i + 1] == ']')) ++i;
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

std::string Transformer::renameLocals(const std::string& source) const {
    // Do not rewrite source with regex. Virtualization already remaps the ISA.
    // The old regex turned `local function fly` into `local v0 fly` and broke compile.
    return source;
}

std::string Transformer::protect(const std::string& source, const Options& options) const {
    std::string processed = source;
    if (options.removeComments)
        processed = removeComments(processed);

    uint32_t seed = 0;
    if (options.polymorphic) {
        std::random_device rd;
        seed = rd() ^ uint32_t(std::chrono::high_resolution_clock::now().time_since_epoch().count());
        if (!seed) seed = 0xA341316C;
    } else {
        seed = 0xA341316C;
    }

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