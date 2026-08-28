#include "vm.hpp"

namespace Protect {
    bool VirtualMachine::loadBytecode(const std::vector<uint8_t>& bytecode) {
        bytecode_ = bytecode;
        return !bytecode_.empty();
    }

    int VirtualMachine::run() {
        // Placeholder for future advanced VM interpreter
        // (Currently we use the loadstring approach in Virtualizer)
        return 0;
    }
}