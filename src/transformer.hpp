#pragma once

#include "virtualizer.hpp"

#include <cstdint>
#include <string>

class Transformer
{
public:
    struct Options
    {
        bool renameIdentifiers = true;
        bool encodeStrings = true;
        bool encodeNumbers = true;
        bool removeComments = true;

        bool virtualize = true;
        bool polymorphic = true;
        bool decoys = true;

        /*
         * Seed of 0 means generate a fresh seed.
         */
        std::uint64_t seed = 0;
    };

    Transformer();

    explicit Transformer(
        std::uint64_t seed
    );

    /*
     * Transform valid Luau source into generated
     * Roblox-compatible Luau source.
     */
    std::string protect(
        const std::string& source
    ) const;

    /*
     * Same operation with explicit options.
     */
    std::string protect(
        const std::string& source,
        const Options& options
    ) const;

private:
    std::uint64_t seed_;

    std::uint64_t generateSeed() const;

    std::string validateLuau(
        const std::string& source
    ) const;

    std::string normalize(
        const std::string& source
    ) const;

    std::string transform(
        const std::string& source,
        const Options& options
    ) const;
};