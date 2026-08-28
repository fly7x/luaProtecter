#pragma once

#include <string>
#include <cstdint>

class Transformer {
public:
    struct Options {
        bool renameIdentifiers = true;
        bool encodeStrings = true;
        bool encodeNumbers = true;
        bool removeComments = true;
        bool virtualize = true;
        bool polymorphic = true;
        bool decoys = true;
        bool antiDebug = true;
        uint64_t seed = 0;  // 0 = generate fresh
    };

    Transformer();
    explicit Transformer(uint64_t seed);

    // Main entry: protects a Luau source string
    std::string protect(const std::string& source) const;
    std::string protect(const std::string& source, const Options& options) const;

private:
    uint64_t seed_;

    uint64_t generateSeed() const;

    // Source-level obfuscations
    std::string renameLocals(const std::string& source) const;
    std::string encodeStringLiterals(const std::string& source) const;
    std::string encodeNumberLiterals(const std::string& source) const;
    std::string removeComments(const std::string& source) const;
    std::string injectDecoys(const std::string& source) const;
};