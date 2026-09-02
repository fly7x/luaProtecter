#include "virtualizer.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>

namespace Protect {

Virtualizer::Virtualizer(uint64_t seed) : seed_(seed) {
    if (seed_ == 0) seed_ = 0x9E3779B97F4A7C15ULL;
}

std::string Virtualizer::bytecodeToLuaTable(const std::vector<uint8_t>& data) const {
    std::stringstream ss;
    ss << "{";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) ss << ",";
        ss << static_cast<int>(data[i]);
    }
    ss << "}";
    return ss.str();
}

std::string Virtualizer::generateVMName() const {
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

std::string Virtualizer::generateAntiDebug() const {
    return R"(
local function _antiDebug()
    if debug and debug.getinfo then
        local info = debug.getinfo(2)
        if info and info.name == 'debug' then
            error('Debugger detected', 2)
        end
    end
    local t1 = os.clock()
    local t2 = os.clock()
    if (t2 - t1) > 0.001 then
        error('Timing anomaly')
    end
end
)";
}

std::string Virtualizer::generateDecryptor() const {
    return R"(
local function _decrypt(data, seed)
    local result = {}
    for i = 1, #data do
        local b = data[i]
        local key = seed
        key = key ~ (key >> 16)
        key = key * 0x7FEB352D
        key = key ~ (key >> 15)
        key = key * 0x846CA68B
        key = key ~ (key >> 16)
        local idx = i - 1
        local k = seed ~ (idx * 0x9E3779B9)
        k = k ~ (k >> 16) * 0x7FEB352D
        k = k ~ (k >> 15) * 0x846CA68B
        k = k ~ (k >> 16)
        result[i] = b ~ (k & 0xFF)
    end
    return result
end
)";
}

std::string Virtualizer::generateInterpreter(const std::string& bytecodeTableVar,
                                             const std::string& seedVar,
                                             bool antiDebug) const {
    std::stringstream code;

    code << "local pc = 1\n";
    code << "local reg = {}\n";
    code << "local stack = {}\n";
    code << "local top = 0\n";
    code << "local bc = " << bytecodeTableVar << "\n";

    code << "bc = _decrypt(bc, " << seedVar << ")\n";

    if (antiDebug) {
        code << "_antiDebug()\n";
    }

    // Flattened dispatch loop
    code << "local state = 0\n";
    code << "local dispatch = {\n";
    code << "  [0] = function()\n";
    code << "    while pc <= #bc do\n";
    code << "      local inst = bc[pc]\n";
    code << "      local op = inst & 0xFF\n";
    code << "      local a = (inst >> 8) & 0xFF\n";
    code << "      local b = (inst >> 16) & 0xFF\n";
    code << "      local c = (inst >> 24) & 0xFF\n";
    code << "      local d = (inst >> 16) & 0xFFFF\n";
    code << "      local e = (inst >> 8) & 0xFFFFFF\n";
    code << "      if e & 0x800000 then e = e - 0x1000000 end\n";

    // Opcode handlers (expanded list)
    code << R"(
      if op == 0x01 then -- MOVE
        reg[a] = reg[b]
      elseif op == 0x02 then -- LOADK
        local k = bc[pc+1]
        reg[a] = k
        pc = pc + 1
      elseif op == 0x03 then -- LOADNIL
        for i = a, b do reg[i] = nil end
      elseif op == 0x04 then -- LOADBOOL
        reg[a] = (b ~= 0)
      elseif op == 0x05 then -- ADD
        reg[a] = reg[b] + reg[c]
      elseif op == 0x06 then -- SUB
        reg[a] = reg[b] - reg[c]
      elseif op == 0x07 then -- MUL
        reg[a] = reg[b] * reg[c]
      elseif op == 0x08 then -- DIV
        reg[a] = reg[b] / reg[c]
      elseif op == 0x09 then -- MOD
        reg[a] = reg[b] % reg[c]
      elseif op == 0x0A then -- POW
        reg[a] = reg[b] ^ reg[c]
      elseif op == 0x0B then -- UNM
        reg[a] = -reg[b]
      elseif op == 0x0C then -- NOT
        reg[a] = not reg[b]
      elseif op == 0x0D then -- LEN
        reg[a] = #reg[b]
      elseif op == 0x0E then -- CONCAT
        local s = ''
        for i = b, c do s = s .. reg[i] end
        reg[a] = s
      elseif op == 0x0F then -- JMP
        pc = pc + d
      elseif op == 0x10 then -- EQ
        if (reg[b] == reg[c]) == (a ~= 0) then
          pc = pc + d
        end
      elseif op == 0x11 then -- LT
        if (reg[b] < reg[c]) == (a ~= 0) then
          pc = pc + d
        end
      elseif op == 0x12 then -- LE
        if (reg[b] <= reg[c]) == (a ~= 0) then
          pc = pc + d
        end
      elseif op == 0x13 then -- CALL
        local func = reg[a]
        local nargs = b - 1
        local nresults = c - 1
        local args = {}
        for i = 1, nargs do args[i] = reg[a + i] end
        local results = { func(table.unpack(args)) }
        for i = 1, nresults do reg[a + i - 1] = results[i] end
        if nresults == 0 then top = #results end
      elseif op == 0x14 then -- RETURN
        local n = b - 1
        local ret = {}
        for i = 1, n do ret[i] = reg[a + i - 1] end
        return table.unpack(ret)
      else
        -- Unknown opcode – skip
      end
)";
    code << "      pc = pc + 1\n";
    code << "    end\n";
    code << "  end,\n";
    code << "}\n";
    code << "dispatch[0]()\n";

    return code.str();
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& obfuscatedBytecode,
                                               const Options& options) const {
    const auto& data = obfuscatedBytecode.data();
    if (data.empty()) {
        return "-- No bytecode to virtualize";
    }

    std::string vmName = generateVMName();
    std::string bytecodeVar = vmName + "_bc";   // FIXED: use + not ..
    std::string seedVar = std::to_string(seed_);

    std::stringstream script;

    if (options.antiDebug) {
        script << generateAntiDebug();
    }
    script << generateDecryptor();
    script << "local " << bytecodeVar << " = " << bytecodeToLuaTable(data) << "\n";
    script << generateInterpreter(bytecodeVar, seedVar, options.antiDebug);

    std::stringstream finalScript;
    finalScript << "return function()\n";
    finalScript << script.str();
    finalScript << "end\n";
    return finalScript.str();
}

} // namespace Protect