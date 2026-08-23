#pragma once

#include <cstdint>
#include <string>
#include <vector>

class Virtualizer
{
public:
    struct Options
    {
        bool renameIdentifiers = true;
        bool encodeStrings = true;
        bool encodeNumbers = true;
        bool removeComments = true;

        /*
         * Generate a Luau dispatcher around the protected
         * representation.
         */
        bool virtualize = true;

        /*
         * Randomize the generated VM every build.
         */
        bool polymorphic = true;

        /*
         * Add harmless decoy VM instructions.
         */
        bool decoys = true;
    };

    explicit Virtualizer(
        std::uint64_t seed
    );

    std::string generate(
        const std::string& source,
        const Options& options = {}
    );

private:
    std::uint64_t seed;

    std::uint64_t nextRandom();

    std::string identifier();

    std::string encodeString(
        const std::string& value
    );

    std::string encodeNumber(
        const std::string& value
    );

    std::string generateDispatcher(
        const std::vector<std::string>& instructions
    );

    std::vector<std::string> buildInstructions(
        const std::string& source
    );
};