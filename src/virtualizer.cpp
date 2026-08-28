#include "virtualizer.hpp"
#include <sstream>
#include <iomanip>
#include <random>

namespace Protect {

Virtualizer::Virtualizer(uint64_t seed) : seed_(seed) {
    if (seed_ == 0) seed_ = 0x9E3779B97F4A7C15ULL;
}

uint64_t Virtualizer::nextKey() const {
    uint64_t key = seed_;
    key ^= key >> 30;
    key *= 0xBF58476D1CE4E5B9ULL;
    key ^= key >> 27;
    key *= 0x94D049BB133111EBULL;
    key ^= key >> 31;
    return key;
}

std::string Virtualizer::bytecodeToLuaString(const std::vector<uint8_t>& data) const {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << '"';
    for (uint8_t b : data) {
        ss << "\\x" << std::setw(2) << static_cast<int>(b);
    }
    ss << '"';
    return ss.str();
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& obfuscatedBytecode,
                                               const Options& options) const {
    const auto& data = obfuscatedBytecode.data();
    if (data.empty()) {
        return "-- No bytecode to virtualize";
    }
    
    std::stringstream script;
    
    // Generate a unique VM name to avoid collisions
    uint64_t vmSeed = nextKey();
    std::string vmName = "_vm_" + std::to_string(vmSeed & 0xFFFF);
    
    // ----- Emit the VM loader -----
    script << "local " << vmName << " = {}\n";
    script << vmName << ".seed = " << seed_ << "\n";
    script << vmName << ".bytecode = " << bytecodeToLuaString(data) << "\n";
    
    // Decryption function
    script << "local function _decrypt(data, seed)\n";
    script << "    local result = {}\n";
    script << "    for i = 1, #data do\n";
    script << "        local b = string.byte(data, i)\n";
    script << "        local key = seed\n";
    script << "        key = key ~ (key >> 16)\n";
    script << "        key = key * 0x7FEB352D\n";
    script << "        key = key ~ (key >> 15)\n";
    script << "        key = key * 0x846CA68B\n";
    script << "        key = key ~ (key >> 16)\n";
    script << "        local idx = i - 1\n";
    script << "        local k = seed ~ (idx * 0x9E3779B9)\n";
    script << "        k = k ~ (k >> 16) * 0x7FEB352D\n";
    script << "        k = k ~ (k >> 15) * 0x846CA68B\n";
    script << "        k = k ~ (k >> 16)\n";
    script << "        result[i] = b ~ (k & 0xFF)\n";
    script << "    end\n";
    script << "    return string.char(table.unpack(result))\n";
    script << "end\n";
    
    script << "local bytecode = _decrypt(" << vmName << ".bytecode, " << vmName << ".seed)\n";
    
    // ----- Execute the bytecode using Luau's loadstring -----
    // We can't directly run arbitrary bytecode from within Luau, but we can load it.
    // However, loadstring expects a string of source code, not bytecode.
    // So we need to save the decrypted bytecode to a temporary file? No.
    // Instead, we need to compile the decrypted bytecode using Luau's loadstring? 
    // Actually, loadstring can take bytecode if it's a valid Luau bytecode chunk.
    // But the bytecode we have is the original Luau bytecode that was encrypted.
    // After decryption, we can load it with loadstring (which accepts bytecode).
    // However, loadstring expects the bytecode to be in a specific format (with header).
    // Our encrypted blob included the header (since we encrypted the whole bytecode).
    // So after decryption, we get the original Luau bytecode.
    // We can then call loadstring(bytecode) to get the function.
    // This is exactly how Luraph works.
    
    script << "local chunk = loadstring(bytecode)\n";
    script << "if chunk then\n";
    script << "    chunk()\n";
    script << "else\n";
    script << "    error('Failed to load virtualized bytecode')\n";
    script << "end\n";
    
    // Wrap in a function to hide globals, and return it
    std::stringstream finalScript;
    finalScript << "return function()\n";
    finalScript << script.str();
    finalScript << "end\n";
    
    return finalScript.str();
}

} // namespace Protect