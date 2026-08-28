#include "virtualizer.hpp"
#include <algorithm>
#include <random>
#include <sstream>
#include <stdexcept>

namespace Protect {

namespace {
    constexpr uint64_t MASK = 0x9e3779b97f4a7c15ULL;
    constexpr uint32_t MAGIC = 0x56584c50; // PLXV
    
    uint32_t rotl(uint32_t x, unsigned r) {
        r &= 31;
        if (r == 0) return x;
        return (x << r) | (x >> (32 - r));
    }
    
    uint32_t avalanche(uint32_t x) {
        x ^= x >> 16;
        x *= 0x7feb352dU;
        x ^= x >> 15;
        x *= 0x846ca68bU;
        x ^= x >> 16;
        return x;
    }
}

Virtualizer::Virtualizer(uint64_t seed) : seed_(seed) {
    if (seed_ == 0) seed_ = MASK;
}

uint32_t Virtualizer::readU32(const std::string& data, size_t& offset) {
    if (offset + 4 > data.size()) {
        throw std::runtime_error("Truncated Luau bytecode");
    }
    const auto* p = reinterpret_cast<const unsigned char*>(data.data() + offset);
    uint32_t result = static_cast<uint32_t>(p[0]) |
                     (static_cast<uint32_t>(p[1]) << 8) |
                     (static_cast<uint32_t>(p[2]) << 16) |
                     (static_cast<uint32_t>(p[3]) << 24);
    offset += 4;
    return result;
}

uint8_t Virtualizer::opcode(uint32_t instruction) {
    return static_cast<uint8_t>(instruction & 0xff);
}

uint8_t Virtualizer::A(uint32_t instruction) {
    return static_cast<uint8_t>((instruction >> 8) & 0xff);
}

uint8_t Virtualizer::B(uint32_t instruction) {
    return static_cast<uint8_t>((instruction >> 16) & 0xff);
}

uint8_t Virtualizer::C(uint32_t instruction) {
    return static_cast<uint8_t>((instruction >> 24) & 0xff);
}

int16_t Virtualizer::D(uint32_t instruction) {
    return static_cast<int16_t>((instruction >> 16) & 0xffff);
}

int32_t Virtualizer::E(uint32_t instruction) {
    uint32_t value = (instruction >> 8) & 0x00ffffff;
    if (value & 0x00800000) value |= 0xff000000;
    return static_cast<int32_t>(value);
}

uint64_t Virtualizer::nextKey(uint64_t value) const {
    value += 0x9e3779b97f4a7c15ULL;
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value;
}

uint32_t Virtualizer::mix(uint32_t value, uint64_t key) const {
    uint32_t k = static_cast<uint32_t>(key) ^ static_cast<uint32_t>(key >> 32);
    value ^= k;
    value = rotl(value, k & 31);
    value += 0x6d2b79f5U;
    return avalanche(value);
}

VirtualProgram Virtualizer::virtualize(const std::string& bytecode, const Options& options) const {
    if (bytecode.empty()) {
        throw std::runtime_error("Empty Luau bytecode");
    }
    
    VirtualProgram program;
    program.version = 1;
    program.key = seed_;
    
    // Check magic
    if (bytecode.size() < 4) {
        throw std::runtime_error("Bytecode too small");
    }
    
    // Parse bytecode header
    size_t offset = 0;
    uint32_t magic = readU32(bytecode, offset);
    if (magic != 0x4C554143) { // 'LUAC'
        throw std::runtime_error("Invalid Luau bytecode magic");
    }
    
    // Skip version and other header fields
    offset += 12; // Skip version, format, etc.
    
    // Parse instructions until end
    while (offset < bytecode.size()) {
        if (offset + 4 > bytecode.size()) break;
        
        uint32_t inst = readU32(bytecode, offset);
        VirtualInstruction vi;
        vi.opcode = opcode(inst);
        vi.a = A(inst);
        vi.b = B(inst);
        vi.c = C(inst);
        vi.d = D(inst);
        vi.e = E(inst);
        
        // Check for aux
        if (vi.opcode == 0x27 || vi.opcode == 0x28) { // LOADK, LOADN
            vi.hasAux = true;
            vi.aux = readU32(bytecode, offset);
        }
        
        program.instructions.push_back(vi);
    }
    
    // Apply transformations
    if (options.shuffleOpcodes) {
        // Scramble opcodes with a simple mapping
        std::vector<uint8_t> opcodeMap(256);
        for (int i = 0; i < 256; i++) opcodeMap[i] = i;
        std::shuffle(opcodeMap.begin(), opcodeMap.end(), 
            std::mt19937(static_cast<unsigned>(seed_)));
        
        for (auto& inst : program.instructions) {
            inst.opcode = opcodeMap[inst.opcode];
        }
    }
    
    if (options.remapRegisters) {
        // Simple register remapping
        std::vector<uint8_t> regMap(256);
        for (int i = 0; i < 256; i++) regMap[i] = i;
        std::shuffle(regMap.begin(), regMap.end(),
            std::mt19937(static_cast<unsigned>(seed_ >> 32)));
        
        for (auto& inst : program.instructions) {
            inst.a = regMap[inst.a];
            inst.b = regMap[inst.b];
            inst.c = regMap[inst.c];
        }
    }
    
    return program;
}

std::string Virtualizer::emitLuau(const VirtualProgram& program) const {
    std::stringstream ss;
    
    // Emit VM runtime
    ss << R"(-- Virtualized by LuaProtecter
local _vm = {}
_vm._state = 0
_vm._regs = {}
_vm._stack = {}
_vm._key = )" << program.key << R"(

local function _decode(v)
    return v ~ _vm._key
end

local _dispatch = {
)";
    
    // Emit dispatch table
    for (size_t i = 0; i < program.instructions.size(); i++) {
        const auto& inst = program.instructions[i];
        ss << "    [" << i << "] = function()\n";
        ss << "        local op = " << static_cast<int>(inst.opcode) << "\n";
        ss << "        local a = " << static_cast<int>(inst.a) << "\n";
        ss << "        local b = " << static_cast<int>(inst.b) << "\n";
        ss << "        local c = " << static_cast<int>(inst.c) << "\n";
        ss << "        -- Virtual instruction handler\n";
        ss << "        _vm._regs[a] = (_vm._regs[b] or 0) + (_vm._regs[c] or 0)\n";
        ss << "    end,\n";
    }
    
    ss << R"(}

-- Execution loop
local _pc = 0
local _instructions = {)";
    
    for (size_t i = 0; i < program.instructions.size(); i++) {
        ss << i << ",";
    }
    
    ss << R"(}

while _pc < #_instructions do
    local idx = _instructions[_pc + 1]
    if _dispatch[idx] then
        _dispatch[idx]()
    end
    _pc = _pc + 1
end

return _vm
)";
    
    return ss.str();
}

} // namespace Protect