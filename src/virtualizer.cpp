#include "virtualizer.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>

namespace Protect {

Virtualizer::Virtualizer(uint64_t seed) : seed_(seed) {
    if (seed_ == 0) seed_ = 0x9E3779B97F4A7C15ULL;
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

std::string Virtualizer::generateVMName() const {
    // Create a unique, random-looking name
    uint64_t r = seed_ ^ 0x9e3779b97f4a7c15ULL;
    r ^= r >> 30;
    r *= 0xbf58476d1ce4e5b9ULL;
    r ^= r >> 27;
    r *= 0x94d049bb133111ebULL;
    r ^= r >> 31;
    std::stringstream ss;
    ss << "_vm" << std::hex << (r & 0xFFFFFFFF);
    return ss.str();
}

std::string Virtualizer::generateFuncName() const {
    uint64_t r = seed_ ^ 0x123456789abcdefULL;
    r ^= r >> 33;
    r *= 0xff51afd7ed558ccdULL;
    r ^= r >> 33;
    r *= 0xc4ceb9fe1a85ec53ULL;
    r ^= r >> 33;
    std::stringstream ss;
    ss << "_f" << std::hex << (r & 0xFFFFFFFF);
    return ss.str();
}

std::string Virtualizer::generateFlattenedLoader(const std::string& decryptedVar,
                                                 const std::string& loadCall) const {
    // Creates a control-flow flattened wrapper around the loadcall
    // using a dispatch table and a state variable.
    std::stringstream ss;
    ss << "local _state = 0\n";
    ss << "local _dispatch = {\n";
    ss << "  [0] = function()\n";
    ss << "    local chunk = " << loadCall << "\n";
    ss << "    if chunk then\n";
    ss << "      _state = 1\n";
    ss << "    else\n";
    ss << "      _state = -1\n";
    ss << "    end\n";
    ss << "  end,\n";
    ss << "  [1] = function()\n";
    ss << "    chunk()\n";
    ss << "    _state = -1\n";
    ss << "  end,\n";
    ss << "}\n";
    ss << "while _state ~= -1 do\n";
    ss << "  _dispatch[_state]()\n";
    ss << "end\n";
    return ss.str();
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& obfuscatedBytecode,
                                               const Options& options) const {
    const auto& data = obfuscatedBytecode.data();
    if (data.empty()) {
        return "-- No bytecode to virtualize";
    }

    std::string vmName = generateVMName();
    std::string decryptFunc = generateFuncName();
    std::string bytecodeVar = generateFuncName();

    std::stringstream script;

    // ----- 1. Anti-debug preamble (if enabled) -----
    if (options.antiDebug) {
        script << "local function _antiDebug()\n";
        script << "  if debug and debug.getinfo then\n";
        script << "    local info = debug.getinfo(2)\n";
        script << "    if info and info.name == 'debug' then\n";
        script << "      error('Debugger detected', 2)\n";
        script << "    end\n";
        script << "  end\n";
        script << "  local t1 = os.clock()\n";
        script << "  local t2 = os.clock()\n";
        script << "  if (t2 - t1) > 0.001 then\n";
        script << "    error('Timing anomaly')\n";
        script << "  end\n";
        script << "end\n";
        script << "_antiDebug()\n";
    }

    // ----- 2. Decryption function -----
    script << "local function " << decryptFunc << "(data, seed)\n";
    script << "  local result = {}\n";
    script << "  for i = 1, #data do\n";
    script << "    local b = string.byte(data, i)\n";
    script << "    local key = seed\n";
    script << "    key = key ~ (key >> 16)\n";
    script << "    key = key * 0x7FEB352D\n";
    script << "    key = key ~ (key >> 15)\n";
    script << "    key = key * 0x846CA68B\n";
    script << "    key = key ~ (key >> 16)\n";
    script << "    local idx = i - 1\n";
    script << "    local k = seed ~ (idx * 0x9E3779B9)\n";
    script << "    k = k ~ (k >> 16) * 0x7FEB352D\n";
    script << "    k = k ~ (k >> 15) * 0x846CA68B\n";
    script << "    k = k ~ (k >> 16)\n";
    script << "    result[i] = b ~ (k & 0xFF)\n";
    script << "  end\n";
    script << "  return string.char(table.unpack(result))\n";
    script << "end\n";

    // ----- 3. Encrypted bytecode as literal -----
    script << "local " << bytecodeVar << " = " << bytecodeToLuaString(data) << "\n";

    // ----- 4. Decrypt and execute -----
    script << "local decrypted = " << decryptFunc << "(" << bytecodeVar << ", " << seed_ << ")\n";

    // ----- 5. Load and run (with optional control flow flattening) -----
    if (options.controlFlowFlatten) {
        script << generateFlattenedLoader("decrypted", "loadstring(decrypted)");
    } else {
        script << "local chunk = loadstring(decrypted)\n";
        script << "if chunk then chunk() else error('Failed to load') end\n";
    }

    // ----- 6. Polymorphic: wrap in a function to hide globals -----
    std::stringstream finalScript;
    finalScript << "return function()\n";
    finalScript << script.str();
    finalScript << "end\n";

    // Optionally add junk code if decoys enabled (handled in Transformer)
    return finalScript.str();
}

} // namespace Protect