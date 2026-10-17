#pragma once

#include "bytecode.hpp"
#include <string>
#include <cstdint>

namespace Protect {

class Virtualizer {
public:
    struct Options {
        int heads = 1;       // 1 = fast single VM, 2 = outer decrypt + same VM
        bool watchdog = true;
    };

    explicit Virtualizer(uint32_t seed = 0);

    // no default-arg on const ref (fixes the build error)
    std::string emitVirtualizedScript(const Bytecode& encryptedBlob) const;
    std::string emitVirtualizedScript(const Bytecode& encryptedBlob,
                                      const Options& options) const;

private:
    uint32_t seed_;
};

} // namespace Protect