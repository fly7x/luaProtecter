#pragma once

#include <string>
#include <cstdint>

class Transformer {
public:
    struct Options {
        bool removeComments = true;
        bool encodeStrings = false;   // off until print works
        bool encodeNumbers = false;
        bool decoys = false;
        bool antiDebug = false;
        bool polymorphic = true;
        bool virtualize = true;       // double-head VM ON
        bool wholeScriptEncrypt = false;
        bool useAstPipeline = false;
        bool renameIdentifiers = false;
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
    std::string encodeStringLiterals(const std::string& source, uint32_t seed) const;
};