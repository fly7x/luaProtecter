#include "virtualizer.hpp"
#include <sstream>
#include <iomanip>

namespace Protect {

Virtualizer::Virtualizer(uint64_t seed) : seed_(seed ? seed : 0x9E3779B97F4A7C15ULL),
                                          rng_(static_cast<uint32_t>(seed_ ^ (seed_ >> 32))) {}

uint32_t Virtualizer::nextU32() const {
    return rng_();
}

std::string Virtualizer::ident(const char* prefix) const {
    std::stringstream ss;
    ss << prefix << "_" << std::hex << (nextU32() & 0xFFFFF);
    return ss.str();
}

std::array<uint8_t, static_cast<size_t>(Op::COUNT)> Virtualizer::buildOpcodeMap() const {
    std::array<uint8_t, static_cast<size_t>(Op::COUNT)> map{};
    std::vector<uint8_t> ids;
    for (int i = 1; i <= 240; ++i) ids.push_back(static_cast<uint8_t>(i));
    std::shuffle(ids.begin(), ids.end(), rng_);
    for (size_t i = 0; i < map.size(); ++i) map[i] = ids[i];
    return map;
}

std::string Virtualizer::bytecodeToLuaTable(const std::vector<uint8_t>& data) const {
    std::stringstream ss;
    ss << "{";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i) ss << ",";
        if ((i % 24) == 0) ss << "\n";
        ss << static_cast<int>(data[i]);
    }
    ss << "}";
    return ss.str();
}

std::string Virtualizer::generateDecryptor(const std::string& fnName) const {
    return
        "local function " + fnName + "(data, seed)\n"
        "  local out = {}\n"
        "  local state = seed\n"
        "  local function mix(x)\n"
        "    x = x ~ (x >> 16)\n"
        "    x = (x * 0x7FEB352D) % 4294967296\n"
        "    x = x ~ (x >> 15)\n"
        "    x = (x * 0x846CA68B) % 4294967296\n"
        "    return x ~ (x >> 16)\n"
        "  end\n"
        "  for i = 1, #data do\n"
        "    state = mix(state + 0x9E3779B9)\n"
        "    local k = mix(state ~ ((i-1) * 0x85EBCA77))\n"
        "    out[i] = data[i] ~ (k & 255) ~ ((k >> 8) & 255) ~ ((k >> 16) & 255)\n"
        "  end\n"
        "  return out\n"
        "end\n";
}

std::string Virtualizer::generateAntiDebug(const std::string& fnName) const {
    return
        "local function " + fnName + "()\n"
        "  if debug and type(debug.getinfo) == 'function' then\n"
        "    local ok, info = pcall(debug.getinfo, 2, 'Snl')\n"
        "    if ok and info and (info.what == 'C' or info.namewhat == 'hook') then\n"
        "      error('protected', 0)\n"
        "    end\n"
        "  end\n"
        "  local a = os.clock()\n"
        "  local s = 0\n"
        "  for i = 1, 64 do s = s + i end\n"
        "  local b = os.clock()\n"
        "  if (b - a) > 0.05 then error('protected', 0) end\n"
        "end\n";
}

std::string Virtualizer::generateInterpreter(const std::string& bcVar,
                                             const std::string& seedVar,
                                             const std::string& decryptFn,
                                             const std::string& antiFn,
                                             const Options& options) const {
    auto op = buildOpcodeMap();
    auto nMOVE     = std::to_string(op[static_cast<size_t>(Op::MOVE)]);
    auto nLOADK    = std::to_string(op[static_cast<size_t>(Op::LOADK)]);
    auto nLOADNIL  = std::to_string(op[static_cast<size_t>(Op::LOADNIL)]);
    auto nLOADBOOL = std::to_string(op[static_cast<size_t>(Op::LOADBOOL)]);
    auto nADD      = std::to_string(op[static_cast<size_t>(Op::ADD)]);
    auto nSUB      = std::to_string(op[static_cast<size_t>(Op::SUB)]);
    auto nMUL      = std::to_string(op[static_cast<size_t>(Op::MUL)]);
    auto nDIV      = std::to_string(op[static_cast<size_t>(Op::DIV)]);
    auto nMOD      = std::to_string(op[static_cast<size_t>(Op::MOD)]);
    auto nPOW      = std::to_string(op[static_cast<size_t>(Op::POW)]);
    auto nUNM      = std::to_string(op[static_cast<size_t>(Op::UNM)]);
    auto nNOT      = std::to_string(op[static_cast<size_t>(Op::NOT)]);
    auto nLEN      = std::to_string(op[static_cast<size_t>(Op::LEN)]);
    auto nCONCAT   = std::to_string(op[static_cast<size_t>(Op::CONCAT)]);
    auto nJMP      = std::to_string(op[static_cast<size_t>(Op::JMP)]);
    auto nEQ       = std::to_string(op[static_cast<size_t>(Op::EQ)]);
    auto nLT       = std::to_string(op[static_cast<size_t>(Op::LT)]);
    auto nLE       = std::to_string(op[static_cast<size_t>(Op::LE)]);
    auto nCALL     = std::to_string(op[static_cast<size_t>(Op::CALL)]);
    auto nRETURN   = std::to_string(op[static_cast<size_t>(Op::RETURN)]);
    auto nFORLOOP  = std::to_string(op[static_cast<size_t>(Op::FORLOOP)]);
    auto nFORPREP  = std::to_string(op[static_cast<size_t>(Op::FORPREP)]);
    auto nTFORCALL = std::to_string(op[static_cast<size_t>(Op::TFORCALL)]);
    auto nTFORLOOP = std::to_string(op[static_cast<size_t>(Op::TFORLOOP)]);
    auto nSETLIST  = std::to_string(op[static_cast<size_t>(Op::SETLIST)]);
    auto nCLOSURE  = std::to_string(op[static_cast<size_t>(Op::CLOSURE)]);
    auto nVARARG   = std::to_string(op[static_cast<size_t>(Op::VARARG)]);

    std::string pc   = ident("pc");
    std::string reg  = ident("r");
    std::string st   = ident("s");
    std::string top  = ident("t");
    std::string inst = ident("i");
    std::string code = ident("op");
    std::string a    = ident("a");
    std::string b    = ident("b");
    std::string c    = ident("c");
    std::string d    = ident("d");
    std::string state= ident("st");
    std::string pred = std::to_string((nextU32() % 7) + 3);

    std::stringstream ss;
    ss << "local " << pc << ", " << reg << ", " << st << ", " << top << " = 1, {}, {}, 0\n";
    ss << "local " << bcVar << " = " << decryptFn << "(" << bcVar << ", " << seedVar << ")\n";
    if (options.antiDebug) ss << antiFn << "()\n";

    ss << "local " << state << " = 1\n";
    ss << "while " << state << " ~= 0 do\n";
    ss << "  if " << state << " == 1 then\n";
    ss << "    if (" << pred << " * " << pred << ") < 0 then " << state << " = 99 else " << state << " = 2 end\n";
    ss << "  elseif " << state << " == 2 then\n";
    ss << "    while " << pc << " <= #" << bcVar << " do\n";
    ss << "      local " << inst << " = " << bcVar << "[" << pc << "]\n";
    ss << "      local " << code << " = " << inst << " & 255\n";
    ss << "      local " << a << " = (" << inst << " >> 8) & 255\n";
    ss << "      local " << b << " = (" << inst << " >> 16) & 255\n";
    ss << "      local " << c << " = (" << inst << " >> 24) & 255\n";
    ss << "      local " << d << " = (" << inst << " >> 16) & 65535\n";

    ss << "      if " << code << " == " << nMOVE << " then " << reg << "[" << a << "] = " << reg << "[" << b << "]\n";
    ss << "      elseif " << code << " == " << nLOADK << " then " << reg << "[" << a << "] = " << bcVar << "[" << pc << "+1]; " << pc << " = " << pc << " + 1\n";
    ss << "      elseif " << code << " == " << nLOADNIL << " then for i=" << a << "," << b << " do " << reg << "[i]=nil end\n";
    ss << "      elseif " << code << " == " << nLOADBOOL << " then " << reg << "[" << a << "] = (" << b << " ~= 0)\n";
    ss << "      elseif " << code << " == " << nADD << " then " << reg << "[" << a << "] = " << reg << "[" << b << "] + " << reg << "[" << c << "]\n";
    ss << "      elseif " << code << " == " << nSUB << " then " << reg << "[" << a << "] = " << reg << "[" << b << "] - " << reg << "[" << c << "]\n";
    ss << "      elseif " << code << " == " << nMUL << " then " << reg << "[" << a << "] = " << reg << "[" << b << "] * " << reg << "[" << c << "]\n";
    ss << "      elseif " << code << " == " << nDIV << " then " << reg << "[" << a << "] = " << reg << "[" << b << "] / " << reg << "[" << c << "]\n";
    ss << "      elseif " << code << " == " << nMOD << " then " << reg << "[" << a << "] = " << reg << "[" << b << "] % " << reg << "[" << c << "]\n";
    ss << "      elseif " << code << " == " << nPOW << " then " << reg << "[" << a << "] = " << reg << "[" << b << "] ^ " << reg << "[" << c << "]\n";
    ss << "      elseif " << code << " == " << nUNM << " then " << reg << "[" << a << "] = -" << reg << "[" << b << "]\n";
    ss << "      elseif " << code << " == " << nNOT << " then " << reg << "[" << a << "] = not " << reg << "[" << b << "]\n";
    ss << "      elseif " << code << " == " << nLEN << " then " << reg << "[" << a << "] = #" << reg << "[" << b << "]\n";
    ss << "      elseif " << code << " == " << nCONCAT << " then\n";
    ss << "        local s=''; for i=" << b << "," << c << " do s=s.." << reg << "[i] end; " << reg << "[" << a << "]=s\n";
    ss << "      elseif " << code << " == " << nJMP << " then " << pc << " = " << pc << " + " << d << "\n";
    ss << "      elseif " << code << " == " << nEQ << " then if (" << reg << "[" << b << "]==" << reg << "[" << c << "])==(" << a << "~=0) then " << pc << "=" << pc << "+" << d << " end\n";
    ss << "      elseif " << code << " == " << nLT << " then if (" << reg << "[" << b << "]<" << reg << "[" << c << "])==(" << a << "~=0) then " << pc << "=" << pc << "+" << d << " end\n";
    ss << "      elseif " << code << " == " << nLE << " then if (" << reg << "[" << b << "]<=" << reg << "[" << c << "])==(" << a << "~=0) then " << pc << "=" << pc << "+" << d << " end\n";
    ss << "      elseif " << code << " == " << nCALL << " then\n";
    ss << "        local f=" << reg << "[" << a << "]; local n=" << b << "-1; local m=" << c << "-1; local args={}\n";
    ss << "        for i=1,n do args[i]=" << reg << "[" << a << "+i] end\n";
    ss << "        local res={f(table.unpack(args))}\n";
    ss << "        for i=1,m do " << reg << "[" << a << "+i-1]=res[i] end\n";
    ss << "      elseif " << code << " == " << nRETURN << " then\n";
    ss << "        local n=" << b << "-1; local ret={}\n";
    ss << "        for i=1,n do ret[i]=" << reg << "[" << a << "+i-1] end\n";
    ss << "        return table.unpack(ret)\n";
    ss << "      elseif " << code << " == " << nFORLOOP << " then\n";
    ss << "        local idx=" << reg << "[" << a << "]; local lim=" << reg << "[" << a << "+1]; local step=" << reg << "[" << a << "+2]\n";
    ss << "        if (step>0 and idx<=lim) or (step<0 and idx>=lim) then " << reg << "[" << a << "]=idx+step; " << pc << "=" << pc << "+" << d << " end\n";
    ss << "      elseif " << code << " == " << nFORPREP << " then " << reg << "[" << a << "]=" << reg << "[" << a << "]-" << reg << "[" << a << "+1]; " << pc << "=" << pc << "+" << d << "\n";
    ss << "      elseif " << code << " == " << nTFORCALL << " then\n";
    ss << "        local f=" << reg << "[" << a << "]; local args={}\n";
    ss << "        for i=1," << b << " do args[i]=" << reg << "[" << a << "+i] end\n";
    ss << "        local res={f(table.unpack(args))}\n";
    ss << "        for i=1,#res do " << reg << "[" << a << "+i-1]=res[i] end\n";
    ss << "      elseif " << code << " == " << nTFORLOOP << " then " << reg << "[" << a << "]=" << reg << "[" << a << "]+1; " << pc << "=" << pc << "+" << d << "\n";
    ss << "      elseif " << code << " == " << nSETLIST << " then\n";
    ss << "        for i=1," << c << " do " << reg << "[" << a << "][" << b << "+i-1]=" << reg << "[" << a << "+i] end\n";
    ss << "      elseif " << code << " == " << nCLOSURE << " then " << reg << "[" << a << "]=function() end; " << pc << "=" << pc << "+1\n";
    ss << "      elseif " << code << " == " << nVARARG << " then\n";
    ss << "        local n=" << b << "-1; for i=1,n do " << reg << "[" << a << "+i-1]=" << st << "[" << top << "+i] end\n";
    ss << "      end\n";
    ss << "      " << pc << " = " << pc << " + 1\n";
    ss << "    end\n";
    ss << "    " << state << " = 0\n";
    ss << "  else\n";
    ss << "    " << state << " = 0\n";
    ss << "  end\n";
    ss << "end\n";
    return ss.str();
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& obfuscatedBytecode,
                                               const Options& options) const {
    const auto& data = obfuscatedBytecode.data();
    if (data.empty()) return "-- empty\nreturn function() end\n";

    std::string decryptFn = ident("_d");
    std::string antiFn    = ident("_ad");
    std::string bcVar     = ident("_bc");
    std::string seedVar   = std::to_string(static_cast<uint32_t>(seed_));

    std::stringstream script;
    if (options.antiDebug) script << generateAntiDebug(antiFn);
    script << generateDecryptor(decryptFn);
    script << "local " << bcVar << " = " << bytecodeToLuaTable(data) << "\n";
    script << generateInterpreter(bcVar, seedVar, decryptFn, antiFn, options);

    std::stringstream out;
    out << "return (function()\n" << script.str() << "end)()\n";
    return out.str();
}

} // namespace Protect