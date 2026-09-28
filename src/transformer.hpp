#pragma once

#include <string>
#include <cstdint>

class Transformer {
public:
    struct Options {
        bool removeComments = true;
        bool polymorphic = true;
        // Whole-script encrypt + load (real hybrid protection)
        bool wholeScriptEncrypt = true;
        // Light extras inside payload before encrypt
        bool encodeStrings = false;
        bool decoys = false;
        bool antiDebug = false;
        bool wrapOpaque = false;
        bool virtualize = false;  // keep off
        uint64_t seed = 0;
    };

    Transformer();
    explicit Transformer(uint64_t seed);

    std::string protect(const std::string& source) const;
    std::string protect(const std::string& source, const Options& options) const;

private:
    uint64_t seed_;
    uint64_t generateSeed() const;
    std::string removeComments(const std::string& source) const;
    std::string emitLoadstringBootstrap(const std::string& payload, uint32_t seed) const;
};