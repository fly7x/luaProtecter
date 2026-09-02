#include "virtualizer.hpp"
#include <sstream>

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
                                               const Options&) const {
    if (encrypted.empty())
        return "return nil\n";

    auto map = makeOpcodeMap(seed32());
    auto n = [&](Op o) { return int(map[size_t(o)]); };

    std::stringstream s;
    s << "--!nocheck\n";
    s << "-- FLY obfuscator | Roblox Luau VM\n";
    s << "local bit32 = bit32\n";
    s << "local unpack = table.unpack\n";
    s << "local ENV = {}\n";
    s << "ENV.print = print\n";
    s << "ENV.warn = warn\n";
    s << "ENV.pairs = pairs\n";
    s << "ENV.ipairs = ipairs\n";
    s << "ENV.type = type\n";
    s << "ENV.tostring = tostring\n";
    s << "ENV.tonumber = tonumber\n";
    s << "ENV.pcall = pcall\n";
    s << "ENV.error = error\n";
    s << "ENV.select = select\n";
    s << "ENV.table = table\n";
    s << "ENV.string = string\n";
    s << "ENV.math = math\n";
    s << "ENV.bit32 = bit32\n";
    s << "setmetatable(ENV, {__index = function(_, k) return rawget(_G, k) end})\n";
    s << "local B = " << bytesToLuaTable(encrypted.data()) << "\n";

    s << R"LUAU(
local function dec(buf)
	local function u8(i) return buf[i] or 0 end
	local function u32(i)
		return u8(i) + u8(i+1)*256 + u8(i+2)*65536 + u8(i+3)*16777216
	end
	local seed = u32(9)
	local size = u32(13)
	local out = {}
	for i = 1, size do
		out[i] = bit32.band(bit32.bxor(u8(16 + i), bit32.band(seed + (i - 1), 255)), 255)
	end
	return out
end
local data = dec(B)
local pos = 1
local function ru8()
	local v = data[pos] or 0
	pos += 1
	return v
end
local function ru32()
	return ru8() + ru8()*256 + ru8()*65536 + ru8()*16777216
end
local magic = ru32()
if magic ~= 0x3252504C then
	error("bad blob " .. tostring(magic))
end
ru32()
ru8()
local nprotos = ru32()
local mainId = ru32()
local protos = {}
for i = 1, nprotos do
	local p = {code = {}, k = {}, child = {}}
	p.maxstack, p.nparams, p.nups, p.isvararg = ru8(), ru8(), ru8(), ru8()
	local ncode = ru32()
	for j = 1, ncode do
		p.code[j] = ru32()
	end
	local nk = ru32()
	for j = 1, nk do
		local tag = ru8()
		if tag == 1 then
			p.k[j] = ru8() ~= 0
		elseif tag == 2 then
			local bytes = string.char(ru8(), ru8(), ru8(), ru8(), ru8(), ru8(), ru8(), ru8())
			p.k[j] = string.unpack("<d", bytes)
		elseif tag == 3 then
			local n = ru32()
			local t = {}
			for z = 1, n do
				t[z] = string.char(ru8())
			end
			p.k[j] = table.concat(t)
		else
			p.k[j] = nil
		end
	end
	local nc = ru32()
	for j = 1, nc do
		p.child[j] = ru32()
	end
	protos[i] = p
end
local function kn(p, word)
	if word >= 2147483648 then
		return p.k[(word - 2147483648) + 1]
	end
	return word
end
local function exec(pid, args)
	local p = protos[pid + 1]
	if not p then
		error("bad proto")
	end
	local reg = {}
	if args then
		for i = 1, #args do
			reg[i] = args[i]
		end
	end
	local pc = 1
	local code = p.code
	while pc <= #code do
		local inst = code[pc]
		local op = bit32.band(inst, 255)
		local A = bit32.band(bit32.rshift(inst, 8), 255)
		local B = bit32.band(bit32.rshift(inst, 16), 255)
		local C = bit32.band(bit32.rshift(inst, 24), 255)
		local D = bit32.band(bit32.rshift(inst, 16), 65535)
		if D >= 32768 then
			D -= 65536
		end
		local Ra, Rb, Rc = A + 1, B + 1, C + 1
)LUAU";

    s << "		if op == " << n(Op::MOVE) << " then reg[Ra] = reg[Rb]\n";
    s << "		elseif op == " << n(Op::LOADNIL) << " then reg[Ra] = nil\n";
    s << "		elseif op == " << n(Op::LOADBOOL) << " then reg[Ra] = B ~= 0\n";
    s << "		elseif op == " << n(Op::LOADK) << " then pc += 1; reg[Ra] = kn(p, code[pc])\n";
    s << "		elseif op == " << n(Op::ADD) << " then reg[Ra] = reg[Rb] + reg[Rc]\n";
    s << "		elseif op == " << n(Op::SUB) << " then reg[Ra] = reg[Rb] - reg[Rc]\n";
    s << "		elseif op == " << n(Op::MUL) << " then reg[Ra] = reg[Rb] * reg[Rc]\n";
    s << "		elseif op == " << n(Op::DIV) << " then reg[Ra] = reg[Rb] / reg[Rc]\n";
    s << "		elseif op == " << n(Op::MOD) << " then reg[Ra] = reg[Rb] % reg[Rc]\n";
    s << "		elseif op == " << n(Op::POW) << " then reg[Ra] = reg[Rb] ^ reg[Rc]\n";
    s << "		elseif op == " << n(Op::UNM) << " then reg[Ra] = -reg[Rb]\n";
    s << "		elseif op == " << n(Op::NOT) << " then reg[Ra] = not reg[Rb]\n";
    s << "		elseif op == " << n(Op::LEN) << " then reg[Ra] = #reg[Rb]\n";
    s << "		elseif op == " << n(Op::CONCAT) << " then\n";
    s << "			local t = \"\"\n";
    s << "			for i = Rb, Rc do t ..= tostring(reg[i]) end\n";
    s << "			reg[Ra] = t\n";
    s << "		elseif op == " << n(Op::JMP) << " then pc += D\n";
    s << "		elseif op == " << n(Op::JMPIF) << " then if reg[Ra] then pc += D end\n";
    s << "		elseif op == " << n(Op::JMPIFNOT) << " then if not reg[Ra] then pc += D end\n";
    s << "		elseif op == " << n(Op::GETGLOBAL) << " then pc += 1; reg[Ra] = ENV[kn(p, code[pc])]\n";
    s << "		elseif op == " << n(Op::SETGLOBAL) << " then pc += 1; ENV[kn(p, code[pc])] = reg[Ra]\n";
    s << "		elseif op == " << n(Op::GETTABLE) << " then reg[Ra] = reg[Rb][reg[Rc]]\n";
    s << "		elseif op == " << n(Op::SETTABLE) << " then reg[Ra][reg[Rb]] = reg[Rc]\n";
    s << "		elseif op == " << n(Op::GETTABLEKS) << " then pc += 1; reg[Ra] = reg[Rb][kn(p, code[pc])]\n";
    s << "		elseif op == " << n(Op::NEWTABLE) << " then reg[Ra] = {}\n";
    s << "		elseif op == " << n(Op::CALL) << " then\n";
    s << "			local narg = if B == 0 then (#reg - A) else (B - 1)\n";
    s << "			local fn = reg[Ra]\n";
    s << "			local argv = {}\n";
    s << "			for i = 1, math.max(narg, 0) do argv[i] = reg[Ra + i] end\n";
    s << "			local ret = {fn(unpack(argv, 1, math.max(narg, 0)))}\n";
    s << "			if C ~= 1 then\n";
    s << "				local limit = if C == 0 then #ret else (C - 1)\n";
    s << "				for i = 1, limit do reg[Ra + i - 1] = ret[i] end\n";
    s << "			end\n";
    s << "		elseif op == " << n(Op::RETURN) << " then\n";
    s << "			local nret = if B == 0 then (#reg - A) else (B - 1)\n";
    s << "			local out = {}\n";
    s << "			for i = 1, math.max(nret, 0) do out[i] = reg[Ra + i - 1] end\n";
    s << "			return unpack(out, 1, math.max(nret, 0))\n";
    s << "		elseif op == " << n(Op::FORPREP) << " then\n";
    s << "			reg[Ra] = (reg[Ra] or 0) - (reg[Ra+2] or 1)\n";
    s << "			pc += D\n";
    s << "		elseif op == " << n(Op::FORLOOP) << " then\n";
    s << "			local step = reg[Ra+2] or 1\n";
    s << "			local idx = (reg[Ra] or 0) + step\n";
    s << "			local lim = reg[Ra+1]\n";
    s << "			if (step > 0 and idx <= lim) or (step < 0 and idx >= lim) then\n";
    s << "				reg[Ra] = idx; reg[Ra+3] = idx; pc += D\n";
    s << "			end\n";
    s << "		elseif op == " << n(Op::CLOSURE) << " then\n";
    s << "			pc += 1\n";
    s << "			local child = code[pc] or 0\n";
    s << "			local cid = p.child[child + 1] or 0\n";
    s << "			reg[Ra] = function(...)\n";
    s << "				return exec(cid, {...})\n";
    s << "			end\n";
    s << "		end\n";
    s << "		pc += 1\n";
    s << "	end\n";
    s << "end\n";
    s << "return exec(mainId)\n";
    return s.str();
}

} // namespace Protect