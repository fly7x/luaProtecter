#pragma once

#include <cstdint>
#include <vector>

namespace Protect {
    class VirtualMachine {
    public:
        VirtualMachine() = default;
        bool loadBytecode(const std::vector<uint8_t>& bytecode);
        int run();
    private:
        std::vector<uint8_t> bytecode_;
    };
}