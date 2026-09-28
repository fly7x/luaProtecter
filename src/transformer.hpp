#pragma once

#include <string>
#include <cstdint>

class Transformer {
public:
    struct Options {
        bool renameIdentifiers = false;
        bool encodeStrings = false;
        bool encodeNumbers = false;
        bool removeComments = true;
        bool useAstPipeline = true;   // primary path
        bool virtualize = false;      // legacy VM path (off)
        bool polymorphic = true;
        bool decoys = false;
        bool antiDebug = false;
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
};