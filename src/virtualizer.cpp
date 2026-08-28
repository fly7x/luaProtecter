#include "virtualizer.hpp"
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>

namespace Protect {

Virtualizer::Virtualizer(uint64_t seed) : seed_(seed) {
    if (seed_ == 0) seed_ = 0x9E3779B97F4A7C15ULL;
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

    // ----- VM state -----
    code << "local pc = 1\n";
    code << "local reg = {}\n";
    code << "local stack = {}\n";
    code << "local top = 0\n";
    code << "local bc = " << bytecodeTableVar << "\n";

    // ----- Decrypt bytecode in place -----
    code << "bc = _decrypt(bc, " << seedVar << ")\n";

    // ----- Anti-debug hook -----
    if (antiDebug) {
        code << "_antiDebug()\n";
    }

    // ----- The main loop (flattened for obfuscation) -----
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

    // ----- Opcode dispatch (big if-elseif chain) -----
    // We'll include handlers for the most common Luau opcodes.
    // This is a subset – you can expand it.
    code << "      if op == 0x01 then -- MOVE\n";
    code << "        reg[a] = reg[b]\n";
    code << "      elseif op == 0x02 then -- LOADK\n";
    code << "        local k = bc[pc+1]\n";
    code << "        reg[a] = k\n";
    code << "        pc = pc + 1\n";
    code << "      elseif op == 0x03 then -- LOADNIL\n";
    code << "        for i = a, b do reg[i] = nil end\n";
    code << "      elseif op == 0x04 then -- LOADBOOL\n";
    code << "        reg[a] = (b ~= 0)\n";
    code << "      elseif op == 0x05 then -- ADD\n";
    code << "        reg[a] = reg[b] + reg[c]\n";
    code << "      elseif op == 0x06 then -- SUB\n";
    code << "        reg[a] = reg[b] - reg[c]\n";
    code << "      elseif op == 0x07 then -- MUL\n";
    code << "        reg[a] = reg[b] * reg[c]\n";
    code << "      elseif op == 0x08 then -- DIV\n";
    code << "        reg[a] = reg[b] / reg[c]\n";
    code << "      elseif op == 0x09 then -- MOD\n";
    code << "        reg[a] = reg[b] % reg[c]\n";
    code << "      elseif op == 0x0A then -- POW\n";
    code << "        reg[a] = reg[b] ^ reg[c]\n";
    code << "      elseif op == 0x0B then -- UNM\n";
    code << "        reg[a] = -reg[b]\n";
    code << "      elseif op == 0x0C then -- NOT\n";
    code << "        reg[a] = not reg[b]\n";
    code << "      elseif op == 0x0D then -- LEN\n";
    code << "        reg[a] = #reg[b]\n";
    code << "      elseif op == 0x0E then -- CONCAT\n";
    code << "        local s = ''\n";
    code << "        for i = b, c do s = s .. reg[i] end\n";
    code << "        reg[a] = s\n";
    code << "      elseif op == 0x0F then -- JMP\n";
    code << "        pc = pc + d\n";
    code << "      elseif op == 0x10 then -- EQ\n";
    code << "        if (reg[b] == reg[c]) == (a ~= 0) then\n";
    code << "          pc = pc + d\n";
    code << "        end\n";
    code << "      elseif op == 0x11 then -- LT\n";
    code << "        if (reg[b] < reg[c]) == (a ~= 0) then\n";
    code << "          pc = pc + d\n";
    code << "        end\n";
    code << "      elseif op == 0x12 then -- LE\n";
    code << "        if (reg[b] <= reg[c]) == (a ~= 0) then\n";
    code << "          pc = pc + d\n";
    code << "        end\n";
    code << "      elseif op == 0x13 then -- CALL\n";
    code << "        local func = reg[a]\n";
    code << "        local nargs = b - 1\n";
    code << "        local nresults = c - 1\n";
    code << "        local args = {}\n";
    code << "        for i = 1, nargs do args[i] = reg[a + i] end\n";
    code << "        local results = { func(table.unpack(args)) }\n";
    code << "        for i = 1, nresults do reg[a + i - 1] = results[i] end\n";
    code << "        if nresults == 0 then top = #results end\n";
    code << "      elseif op == 0x14 then -- RETURN\n";
    code << "        local n = b - 1\n";
    code << "        local ret = {}\n";
    code << "        for i = 1, n do ret[i] = reg[a + i - 1] end\n";
    code << "        return table.unpack(ret)\n";
    code << "      else\n";
    code << "        -- Unknown opcode – skip\n";
    code << "      end\n";
    code << "      pc = pc + 1\n";
    code << "    end\n";
    code << "  end,\n";
    code << "}\n";

    // ----- Execute dispatch[0] -----
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
    std::string bytecodeVar = vmName .. "_bc";
    std::string seedVar = std::to_string(seed_);

    std::stringstream script;

    // 1. Anti-debug
    if (options.antiDebug) {
        script << generateAntiDebug();
    }

    // 2. Decryptor
    script << generateDecryptor();

    // 3. Bytecode as table
    script << "local " << bytecodeVar << " = " << bytecodeToLuaTable(data) << "\n";

    // 4. The interpreter
    script << generateInterpreter(bytecodeVar, seedVar, options.antiDebug);

    // 5. Wrap in a function to hide globals
    std::stringstream finalScript;
    finalScript << "return function()\n";
    finalScript << script.str();
    finalScript << "end\n";

    return finalScript.str();
}

} // namespace Protect