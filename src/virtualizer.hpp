#pragma once

#include "bytecode.hpp"
#include <string>
#include <cstdint>

namespace Protect {

class Virtualizer {
public:
    struct Options {
        int heads = 1;      // 1 = single fast VM, 2 = outer decrypt shell + same VM
        bool watchdog = true;
    };

    explicit Virtualizer(uint32_t seed = 0);

    std::string emitVirtualizedScript(const Bytecode& encryptedBlob,
                                      const Options& options = {}) const;

private:
    uint32_t seed_;
};

} // namespace Protect