#pragma once

#include "bytecode.hpp"
#include <string>
#include <cstdint>

namespace Protect {

class Virtualizer {
public:
    struct Options {
        int heads = 1;          // 1 = single, 2 = outer shell
        bool watchdog = true;
        bool strictEnv = true;  // no open _G / RealG fallback
        bool safeParse = true;  // bounds + index checks
    };

    explicit Virtualizer(uint32_t seed = 0);

    std::string emitVirtualizedScript(const Bytecode& encryptedBlob) const;
    std::string emitVirtualizedScript(const Bytecode& encryptedBlob,
                                      const Options& options) const;

private:
    uint32_t seed_;
};

} // namespace Protect