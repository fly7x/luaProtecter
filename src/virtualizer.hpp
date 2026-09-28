#pragma once

#include "bytecode.hpp"
#include "isa.hpp"
#include <cstdint>
#include <string>

namespace Protect {

class Virtualizer {
public:
    struct Options {
        bool polymorphic = true;
        bool antiDebug = true;
    };

    explicit Virtualizer(uint64_t seed);
    std::string emitVirtualizedScript(const Bytecode& encrypted, const Options& options) const;

private:
    uint64_t seed_;
    uint32_t seed32() const { return uint32_t(seed_); }
    std::string ident(const char* prefix, uint32_t n) const;
    std::string bytesToLuaTable(const std::vector<uint8_t>& data) const;
};

} // namespace Protect