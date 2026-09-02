#include "virtualizer.hpp"
#include <sstream>
#include <iomanip>

namespace Protect {

Virtualizer::Virtualizer(uint64_t seed) : seed_(seed ? seed : 0x9E3779B97F4A7C15ULL) {}

std::string Virtualizer::ident(const char* prefix, uint32_t n) const {
    std::stringstream ss;
    ss << prefix << "_" << std::hex << n;
    return ss.str();
}

std::string Virtualizer::bytesToLuaTable(const std::vector<uint8_t>& data) const {
    std::stringstream ss;
    ss << "{";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i) ss << ",";
        if ((i % 24) == 0) ss << "\n";
        ss << int(data[i]);
    }
    ss << "}";
    return ss.str();
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& encrypted,
                                               const Options& options) const {
    if (encrypted.empty())
        return "return function() end\n";

    auto map = makeOpcodeMap(seed32());
    auto n = [&](Op o) { return int(map[size_t(o)]); };

    std::string blob = ident("_b", seed32() ^ 0x111u);
    std::string decrypt = ident("_d", seed32() ^ 0x222u);
    std::string run = ident("_r", seed32() ^ 0x333u);

    std::stringstream s;
    s << "local unpack = table.unpack or unpack\n";
    s << "local " << blob << " = " << bytesToLuaTable(encrypted.data()) << "\n";

    s <<
      "local function " << decrypt << "(buf)\n"
      "  local function mix(x)\n"
      "    x = x % 4294967296\n"
      "    x = bit32.bxor(x, bit32.rshift(x, 16))\n"
      "    x = (x * 2146178349) % 4294967296\n"
      "    x = bit32.bxor(x, bit32.rshift(x, 15))\n"
      "    x = (x * 2221721227) % 4294967296\n"
      "    x = bit32.bxor(x, bit32.rshift(x, 16))\n"
      "    return x\n"
      "  end\n"
      "  local function u8(i) return buf[i] or 0 end\n"
      "  local function u32(i)\n"
      "    return u8(i) + u8(i+1)*256 + u8(i+2)*65536 + u8(i+3)*16777216\n"
      "  end\n"
      "  local seed = u32(9)\n"
      "  local size = u32(13)\n"
      "  local out = {}\n"
      "  local state = seed\n"
      "  for i = 1, size do\n"
      "    state = mix(state + 2654435769)\n"
      "    local k = mix(bit32.bxor(state, ((i-1) * 2246781559) % 4294967296))\n"
      "    local raw = u8(16 + i)\n"
      "    out[i] = bit32.band(bit32.bxor(raw, k, bit32.rshift(k,8), bit32.rshift(k,16)), 255)\n"
      "  end\n"
      "  return out, seed\n"
      "end\n";

    if (options.antiDebug) {
        s <<
          "pcall(function()\n"
          "  if debug and debug.getinfo then\n"
          "    local info = debug.getinfo(2, 'S')\n"
          "    if info and info.what == 'C' then error('protected') end\n"
          "  end\n"
          "end)\n";
    }

    s <<
      "local function " << run << "()\n"
      "  local data, seed = " << decrypt << "(" << blob << ")\n"
      "  local pos = 1\n"
      "  local function ru8()\n"
      "    local v = data[pos] or 0\n"
      "    pos = pos + 1\n"
      "    return v\n"
      "  end\n"
      "  local function ru32()\n"
      "    local a,b,c,d = ru8(),ru8(),ru8(),ru8()\n"
      "    return a + b*256 + c*65536 + d*16777216\n"
      "  end\n"
      "  local magic = ru32()\n"
      "  if magic ~= 844715340 then error('bad blob') end\n"
      "  ru32() ru8()\n"
      "  local nprotos = ru32()\n"
      "  local mainId = ru32()\n"
      "  local protos = {}\n"
      "  for i = 1, nprotos do\n"
      "    local p = {maxstack=ru8(), nparams=ru8(), nups=ru8(), isvararg=ru8(), code={}, k={}, child={}}\n"
      "    local ncode = ru32()\n"
      "    for j = 1, ncode do p.code[j] = ru32() end\n"
      "    local nk = ru32()\n"
      "    for j = 1, nk do\n"
      "      local tag = ru8()\n"
      "      if tag == 1 then p.k[j] = ru8() ~= 0\n"
      "      elseif tag == 2 then\n"
      "        local bits = 0\n"
      "        local mul = 1\n"
      "        for b = 1, 8 do bits = bits + ru8() * mul; mul = mul * 256 end\n"
      "        local sign = 1\n"
      "        if bits >= 9223372036854775808 then bits = bits - 18446744073709551616; end\n"
      "        p.k[j] = bits -- number bytes decoded below as double fallback\n"
      "      elseif tag == 3 then\n"
      "        local n = ru32()\n"
      "        local t = {}\n"
      "        for z = 1, n do t[z] = string.char(ru8()) end\n"
      "        p.k[j] = table.concat(t)\n"
      "      else p.k[j] = nil end\n"
      "    end\n"
      "    local nc = ru32()\n"
      "    for j = 1, nc do p.child[j] = ru32() end\n"
      "    protos[i] = p\n"
      "  end\n"
      "  local env = getfenv and getfenv() or _ENV or _G\n"
      "  local function const_of(p, word)\n"
      "    if word >= 2147483648 then\n"
      "      local idx = word - 2147483648\n"
      "      return p.k[idx + 1]\n"
      "    end\n"
      "    if word >= 2147483648 then return word - 4294967296 end\n"
      "    return word\n"
      "  end\n"
      "  local function exec(pid, args)\n"
      "    local p = protos[pid + 1]\n"
      "    local reg = {}\n"
      "    for i = 1, (args and #args or 0) do reg[i] = args[i] end\n"
      "    local pc = 1\n"
      "    local code = p.code\n"
      "    while pc <= #code do\n"
      "      local inst = code[pc]\n"
      "      local op = bit32.band(inst, 255)\n"
      "      local A = bit32.band(bit32.rshift(inst, 8), 255)\n"
      "      local B = bit32.band(bit32.rshift(inst, 16), 255)\n"
      "      local C = bit32.band(bit32.rshift(inst, 24), 255)\n"
      "      local D = bit32.band(bit32.rshift(inst, 16), 65535)\n"
      "      if D >= 32768 then D = D - 65536 end\n"
      "      local Ra, Rb, Rc = A + 1, B + 1, C + 1\n";

    s << "      if op == " << n(Op::MOVE) << " then reg[Ra] = reg[Rb]\n";
    s << "      elseif op == " << n(Op::LOADNIL) << " then reg[Ra] = nil\n";
    s << "      elseif op == " << n(Op::LOADBOOL) << " then reg[Ra] = (B ~= 0)\n";
    s << "      elseif op == " << n(Op::LOADK) << " then pc = pc + 1; reg[Ra] = const_of(p, code[pc])\n";
    s << "      elseif op == " << n(Op::ADD) << " then reg[Ra] = reg[Rb] + reg[Rc]\n";
    s << "      elseif op == " << n(Op::SUB) << " then reg[Ra] = reg[Rb] - reg[Rc]\n";
    s << "      elseif op == " << n(Op::MUL) << " then reg[Ra] = reg[Rb] * reg[Rc]\n";
    s << "      elseif op == " << n(Op::DIV) << " then reg[Ra] = reg[Rb] / reg[Rc]\n";
    s << "      elseif op == " << n(Op::MOD) << " then reg[Ra] = reg[Rb] % reg[Rc]\n";
    s << "      elseif op == " << n(Op::POW) << " then reg[Ra] = reg[Rb] ^ reg[Rc]\n";
    s << "      elseif op == " << n(Op::UNM) << " then reg[Ra] = -reg[Rb]\n";
    s << "      elseif op == " << n(Op::NOT) << " then reg[Ra] = not reg[Rb]\n";
    s << "      elseif op == " << n(Op::LEN) << " then reg[Ra] = #reg[Rb]\n";
    s << "      elseif op == " << n(Op::CONCAT) << " then local t=''; for i=Rb,Rc do t=t..tostring(reg[i]) end; reg[Ra]=t\n";
    s << "      elseif op == " << n(Op::JMP) << " then pc = pc + D\n";
    s << "      elseif op == " << n(Op::JMPIF) << " then if reg[Ra] then pc = pc + D end\n";
    s << "      elseif op == " << n(Op::JMPIFNOT) << " then if not reg[Ra] then pc = pc + D end\n";
    s << "      elseif op == " << n(Op::GETGLOBAL) << " then pc = pc + 1; local name = const_of(p, code[pc]); reg[Ra] = env[name]\n";
    s << "      elseif op == " << n(Op::SETGLOBAL) << " then pc = pc + 1; local name = const_of(p, code[pc]); env[name] = reg[Ra]\n";
    s << "      elseif op == " << n(Op::GETTABLE) << " then reg[Ra] = reg[Rb][reg[Rc]]\n";
    s << "      elseif op == " << n(Op::SETTABLE) << " then reg[Ra][reg[Rb]] = reg[Rc]\n";
    s << "      elseif op == " << n(Op::GETTABLEKS) << " then pc = pc + 1; local name = const_of(p, code[pc]); reg[Ra] = reg[Rb][name]\n";
    s << "      elseif op == " << n(Op::NEWTABLE) << " then reg[Ra] = {}\n";
    s << "      elseif op == " << n(Op::CALL) << " then\n"
      "        local narg = B - 1\n"
      "        local nres = C - 1\n"
      "        local fn = reg[Ra]\n"
      "        local argv = {}\n"
      "        if B == 0 then narg = (#reg - A) end\n"
      "        for i = 1, math.max(narg, 0) do argv[i] = reg[Ra + i] end\n"
      "        local ret = {fn(unpack(argv, 1, math.max(narg, 0)))}\n"
      "        if C ~= 1 then\n"
      "          local limit = (C == 0) and #ret or nres\n"
      "          for i = 1, limit do reg[Ra + i - 1] = ret[i] end\n"
      "        end\n";
    s << "      elseif op == " << n(Op::RETURN) << " then\n"
      "        local nret = B - 1\n"
      "        if B == 0 then nret = #reg - A end\n"
      "        local out = {}\n"
      "        for i = 1, math.max(nret, 0) do out[i] = reg[Ra + i - 1] end\n"
      "        return unpack(out, 1, math.max(nret, 0))\n";
    s << "      elseif op == " << n(Op::FORPREP) << " then reg[Ra] = reg[Ra] - (reg[Ra+2] or 1); pc = pc + D\n";
    s << "      elseif op == " << n(Op::FORLOOP) << " then\n"
      "        local idx = (reg[Ra] or 0) + (reg[Ra+2] or 1)\n"
      "        local lim = reg[Ra+1]\n"
      "        local step = reg[Ra+2] or 1\n"
      "        if (step > 0 and idx <= lim) or (step < 0 and idx >= lim) then\n"
      "          reg[Ra] = idx; reg[Ra+3] = idx; pc = pc + D\n"
      "        end\n";
    s << "      elseif op == " << n(Op::CLOSURE) << " then pc = pc + 1; local child = code[pc]; local cid = p.child[(child or 0)+1] or 0; reg[Ra] = function(...) return exec(cid, {...}) end\n";
    s << "      end\n"
      "      pc = pc + 1\n"
      "    end\n"
      "  end\n"
      "  return exec(mainId, {})\n"
      "end\n"
      "return " << run << "()\n";

    return s.str();
}

} // namespace Protect