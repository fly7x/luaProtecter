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
        if ((i % 18) == 0) ss << "\n";
        ss << int(data[i]);
    }
    ss << "}";
    return ss.str();
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& encrypted,
                                               const Options&) const {
    if (encrypted.empty()) return "return nil\n";

    auto map = makeOpcodeMap(seed32());
    auto n = [&](Op o) { return int(map[size_t(o)]); };
    uint32_t sid = seed32();

    std::string a = ident("a", sid ^ 0x1111);
    std::string b = ident("b", sid ^ 0x2222);
    std::string d = ident("d", sid ^ 0x3333);
    std::string p_ = ident("p", sid ^ 0x4444);
    std::string r_ = ident("r", sid ^ 0x5555);
    std::string e_ = ident("e", sid ^ 0x6666);
    std::string k_ = ident("k", sid ^ 0x7777);
    std::string x_ = ident("x", sid ^ 0x8888);
    std::string h_ = ident("h", sid ^ 0x9999);

    std::stringstream s;
    s << "--!nocheck\n";
    s << "local " << a << "=" << bytesToLuaTable(encrypted.data()) << "\n";
    s << "local function " << b << "(n,i)\n";
    s << "	return n[i] or 0\n";
    s << "end\n";
    s << "local function " << d << "(buf)\n";
    s << "	local function u8(i) return buf[i] or 0 end\n";
    s << "	local function u32(i) return u8(i)+u8(i+1)*256+u8(i+2)*65536+u8(i+3)*16777216 end\n";
    s << "	local seed=u32(9)\n";
    s << "	local size=u32(13)\n";
    s << "	local out={}\n";
    s << "	for i=1,size do\n";
    s << "		local k=bit32.band(bit32.rshift(seed, bit32.band(i-1,3)*8),255)\n";
    s << "		k=bit32.band(bit32.bxor(k, bit32.band((i-1)*131+17,255), bit32.band(seed,255)),255)\n";
    s << "		out[i]=bit32.band(bit32.bxor(u8(16+i),k),255)\n";
    s << "	end\n";
    s << "	return out,seed\n";
    s << "end\n";
    s << "local " << x_ << ",_s=" << d << "(" << a << ")\n";
    s << "local _i=1\n";
    s << "local function _u8() local v=" << x_ << "[_i] or 0; _i+=1; return v end\n";
    s << "local function _u32() return _u8()+_u8()*256+_u8()*65536+_u8()*16777216 end\n";
    s << "if _u32()~=0x3252504C then error(\"x\") end\n";
    s << "local _ks=_u32()\n";
    s << "_u8()\n";
    s << "local _np=_u32()\n";
    s << "local _mid=_u32()\n";
    s << "local " << p_ << "={}\n";
    s << "for i=1,_np do\n";
    s << "	local p={c={},k={},h={}}\n";
    s << "	p.m,p.a,p.u,p.v=_u8(),_u8(),_u8(),_u8()\n";
    s << "	local nc=_u32()\n";
    s << "	for j=1,nc do p.c[j]=_u32() end\n";
    s << "	local nk=_u32()\n";
    s << "	for j=1,nk do\n";
    s << "		local tag=_u8()\n";
    s << "		if tag==1 then p.k[j]=_u8()~=0\n";
    s << "		elseif tag==2 then\n";
    s << "			p.k[j]=string.unpack(\"<d\", string.char(_u8(),_u8(),_u8(),_u8(),_u8(),_u8(),_u8(),_u8()))\n";
    s << "		elseif tag==3 then\n";
    s << "			local n=_u32(); local t={}\n";
    s << "			for z=1,n do t[z]=string.char(bit32.band(bit32.bxor(_u8(), bit32.band(_ks+(z-1)*13,255)),255)) end\n";
    s << "			p.k[j]=table.concat(t)\n";
    s << "		else p.k[j]=nil end\n";
    s << "	end\n";
    s << "	local nh=_u32()\n";
    s << "	for j=1,nh do p.h[j]=_u32() end\n";
    s << "	" << p_ << "[i]=p\n";
    s << "end\n";
    s << "local " << e_ << "={}\n";
    s << "local function _nm(t) local o={} for i=1,#t do o[i]=string.char(bit32.bxor(t[i],91)) end return table.concat(o) end\n";
    s << e_ << "[_nm({43,25,18,22,15})]=print\n"; // print xor 91
    s << e_ << "[_nm({44,26,27,22})]=warn\n";
    s << "setmetatable(" << e_ << ",{__index=function(_,k) return rawget(_G,k) end})\n";
    s << "local function " << k_ << "(p,w)\n";
    s << "	if w>=2147483648 then return p.k[(w-2147483648)+1] end\n";
    s << "	return w\n";
    s << "end\n";
    s << "local " << h_ << "={}\n";

    auto bind = [&](Op o, const std::string& body) {
        s << h_ << "[" << n(o) << "]=function(p,reg,A,B,C,D,pc,code)\n" << body << "\nend\n";
    };

    bind(Op::MOVE, "reg[A+1]=reg[B+1]; return pc");
    bind(Op::LOADNIL, "reg[A+1]=nil; return pc");
    bind(Op::LOADBOOL, "reg[A+1]=B~=0; return pc");
    bind(Op::LOADK, "pc+=1; reg[A+1]=" + k_ + "(p,code[pc]); return pc");
    bind(Op::ADD, "reg[A+1]=reg[B+1]+reg[C+1]; return pc");
    bind(Op::SUB, "reg[A+1]=reg[B+1]-reg[C+1]; return pc");
    bind(Op::MUL, "reg[A+1]=reg[B+1]*reg[C+1]; return pc");
    bind(Op::DIV, "reg[A+1]=reg[B+1]/reg[C+1]; return pc");
    bind(Op::MOD, "reg[A+1]=reg[B+1]%reg[C+1]; return pc");
    bind(Op::POW, "reg[A+1]=reg[B+1]^reg[C+1]; return pc");
    bind(Op::UNM, "reg[A+1]=-reg[B+1]; return pc");
    bind(Op::NOT, "reg[A+1]=not reg[B+1]; return pc");
    bind(Op::LEN, "reg[A+1]=#reg[B+1]; return pc");
    bind(Op::CONCAT,
         "local t=\"\" for i=B+1,C+1 do t..=tostring(reg[i]) end; reg[A+1]=t; return pc");
    bind(Op::JMP, "return pc+D");
    bind(Op::JMPIF, "if reg[A+1] then return pc+D end; return pc");
    bind(Op::JMPIFNOT, "if not reg[A+1] then return pc+D end; return pc");
    bind(Op::GETGLOBAL, "pc+=1; reg[A+1]=" + e_ + "[" + k_ + "(p,code[pc])]; return pc");
    bind(Op::SETGLOBAL, "pc+=1; " + e_ + "[" + k_ + "(p,code[pc])]=reg[A+1]; return pc");
    bind(Op::GETTABLE, "reg[A+1]=reg[B+1][reg[C+1]]; return pc");
    bind(Op::SETTABLE, "reg[A+1][reg[B+1]]=reg[C+1]; return pc");
    bind(Op::GETTABLEKS, "pc+=1; reg[A+1]=reg[B+1][" + k_ + "(p,code[pc])]; return pc");
    bind(Op::NEWTABLE, "reg[A+1]={}; return pc");
    bind(Op::CALL,
         "local narg=if B==0 then (#reg-A) else (B-1)\n"
         "local fn=reg[A+1]\n"
         "local argv={}\n"
         "for i=1,math.max(narg,0) do argv[i]=reg[A+1+i] end\n"
         "local ret={fn(table.unpack(argv,1,math.max(narg,0)))}\n"
         "if C~=1 then local limit=if C==0 then #ret else (C-1)\n"
         "for i=1,limit do reg[A+i]=ret[i] end end\n"
         "return pc");
    bind(Op::RETURN,
         "local nret=if B==0 then (#reg-A) else (B-1)\n"
         "local out={}\n"
         "for i=1,math.max(nret,0) do out[i]=reg[A+i] end\n"
         "return pc, table.unpack(out,1,math.max(nret,0))");
    bind(Op::FORPREP, "reg[A+1]=(reg[A+1] or 0)-(reg[A+3] or 1); return pc+D");
    bind(Op::FORLOOP,
         "local step=reg[A+3] or 1\n"
         "local idx=(reg[A+1] or 0)+step\n"
         "local lim=reg[A+2]\n"
         "if (step>0 and idx<=lim) or (step<0 and idx>=lim) then\n"
         "reg[A+1]=idx; reg[A+4]=idx; return pc+D end\n"
         "return pc");
    bind(Op::CLOSURE,
         "pc+=1\n"
         "local child=code[pc] or 0\n"
         "local cid=p.h[child+1] or 0\n"
         "reg[A+1]=function(...)\n"
         "return " + r_ + "(cid,{...})\n"
         "end\n"
         "return pc");

    // junk handlers so the table is not only real ops
    s << "for z=0,239 do if not " << h_ << "[z] then " << h_ << "[z]=function(_,reg,A) reg[A+1]=reg[A+1] return 0 end end end\n";

    s << "function " << r_ << "(pid,args)\n";
    s << "	local p=" << p_ << "[pid+1]\n";
    s << "	if not p then error(\"p\") end\n";
    s << "	local reg={}\n";
    s << "	if args then for i=1,#args do reg[i]=args[i] end end\n";
    s << "	local pc=1\n";
    s << "	local code=p.c\n";
    s << "	while pc<=#code do\n";
    s << "		local inst=code[pc]\n";
    s << "		local op=bit32.band(inst,255)\n";
    s << "		local A=bit32.band(bit32.rshift(inst,8),255)\n";
    s << "		local B=bit32.band(bit32.rshift(inst,16),255)\n";
    s << "		local C=bit32.band(bit32.rshift(inst,24),255)\n";
    s << "		local D=bit32.band(bit32.rshift(inst,16),65535)\n";
    s << "		if D>=32768 then D-=65536 end\n";
    s << "		local h=" << h_ << "[op]\n";
    s << "		local npc,a,b,c,d,e=h(p,reg,A,B,C,D,pc,code)\n";
    s << "		if npc==nil then pc+=1 else\n";
    s << "			if a~=nil or b~=nil or c~=nil then return a,b,c,d,e end\n";
    s << "			pc=npc+1\n";
    s << "		end\n";
    s << "	end\n";
    s << "end\n";
    s << "return " << r_ << "(_mid)\n";
    return s.str();
}

} // namespace Protect