#pragma once

#include "bytecode.hpp"
#include "isa.hpp"
#include <string>
#include <cstdint>
#include <vector>

namespace Protect {

class Virtualizer {
public:
    struct Options {
        int heads = 2;      // 1 = single VM, 2 = outer+inner
        bool watchdog = true;
    };

    explicit Virtualizer(uint64_t seed = 0);

    std::string emitVirtualizedScript(const Bytecode& encrypted) const;
    std::string emitVirtualizedScript(const Bytecode& encrypted,
                                      const Options& options) const;

private:
    uint64_t seed_;
    uint32_t seed32() const { return uint32_t(seed_ ^ (seed_ >> 32)); }
    std::string bytesToLuaTable(const std::vector<uint8_t>& data) const;
};

} // namespace Protect