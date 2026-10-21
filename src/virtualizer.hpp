#pragma once
#include "bytecode.hpp"
#include <string>
#include <cstdint>

namespace Protect {

class Virtualizer {
public:
    struct Options {
        int heads = 1;
        bool watchdog = true;
        bool strictEnv = true;
        bool safeParse = true;
        bool dense = true; // minified / anti-lift layout
    };

    explicit Virtualizer(uint32_t seed = 0);
    std::string emitVirtualizedScript(const Bytecode& encryptedBlob) const;
    std::string emitVirtualizedScript(const Bytecode& encryptedBlob, const Options& options) const;

private:
    uint32_t seed_;
};

} // namespace Protect