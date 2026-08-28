#pragma once

#include "virtualizer.hpp"
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
        uint64_t seed = 0;  // 0 means generate fresh
    };
    
    Transformer();
    explicit Transformer(uint64_t seed);
    
    // Transform valid Luau source into protected Roblox-compatible Luau source
    std::string protect(const std::string& source) const;
    std::string protect(const std::string& source, const Options& options) const;
    
private:
    uint64_t seed_;
    
    uint64_t generateSeed() const;
    std::string validateLuau(const std::string& source) const;
    std::string normalize(const std::string& source) const;
    std::string transform(const std::string& source, const Options& options) const;
};