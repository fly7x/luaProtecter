#pragma once

#include <string>
#include <cstdint>

class Transformer {
public:
    struct Options {
        // Hybrid defaults: native Luau, layered security, no VM
        bool removeComments = true;
        bool encodeStrings = true;
        bool encodeNumbers = true;
        bool decoys = true;
        bool antiDebug = true;
        bool wrapOpaque = true;
        bool polymorphic = true;
        bool useAstPipeline = true;   // native path ON
        bool virtualize = false;      // VM OFF (unreliable)
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
    std::string injectDecoys(const std::string& source, uint32_t seed) const;
    std::string injectAntiDebug(const std::string& source, uint32_t seed) const;
    std::string wrapOpaqueShell(const std::string& source, uint32_t seed) const;
    std::string emitNativeProtected(const std::string& body, uint32_t seed) const;
};