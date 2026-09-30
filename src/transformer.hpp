#pragma once

#include <string>
#include <cstdint>

class Transformer {
public:
    struct Options {
        bool removeComments = true;
        bool encodeStrings = false;
        bool encodeNumbers = false;
        bool decoys = false;
        bool antiDebug = false;
        bool polymorphic = true;
        bool virtualize = true;          // heavy VM
        bool wholeScriptEncrypt = false; // hybrid
        bool tripleHead = false;         // max VM shell
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
    std::string emitHybrid(const std::string& source, uint32_t seed) const;
};