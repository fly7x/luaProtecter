#include "virtualizer.hpp"
#include <sstream>

namespace Protect {

Virtualizer::Virtualizer(uint64_t seed) : seed_(seed ? seed : 0x9E3779B97F4A7C15ULL) {}

std::string Virtualizer::ident(const char* prefix, uint32_t n) const {
    std::stringstream ss;
    ss << prefix << std::hex << n;
    return ss.str();
}

std::string Virtualizer::bytesToLuaTable(const std::vector<uint8_t>& data) const {
    std::stringstream ss;
    ss << "{";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i) ss << ",";
        if ((i % 16) == 0) ss << "\n";
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

    uint32_t sum = 0;
    for (uint8_t b : encrypted.data())
        sum += b;

    uint32_t sid = seed32();
    std::string A = ident("_A", sid ^ 0x11u);
    std::string B = ident("_B", sid ^ 0x22u);
    std::string C = ident("_C", sid ^ 0x33u);
    std::string D = ident("_D", sid ^ 0x44u);
    std::string E = ident("_E", sid ^ 0x55u);
    std::string F = ident("_F", sid ^ 0x66u);
    std::string G = ident("_G", sid ^ 0x77u);
    std::string H = ident("_H", sid ^ 0x88u);
    std::string I = ident("_I", sid ^ 0x99u);
    std::string J = ident("_J", sid ^ 0xAAu);

    std::stringstream s;
    s << "--!nocheck\n";

    // dead noise tables (never read for real control)
    s << "local " << A << "={";
    for (int i = 0; i < 32; ++i) {
        if (i) s << ",";
        s << ((sid >> (i % 24)) ^ (i * 17));
    }
    s << "}\n";
    s << "local " << B << "=function(x) return bit32.bxor(x or 0," << (sid & 255) << ") end\n";
    s << "local " << C << "=0\n";
    s << "for i=1,#" << A << " do " << C << "=bit32.band(" << C << "+" << A << "[i],65535) end\n";
    s << "if " << C << "==999999 then error(\"dead\") end\n";

    s << "local _B=" << bytesToLuaTable(encrypted.data()) << "\n";
    s << "do local s=0 for i=1,#_B do s+=_B[i] end if s~=" << sum << " then error(\"t\") end end\n";
    s << "pcall(function() local d=debug if d and d.info and d.info(1,\"s\")==\"[C]\" then end end)\n";

    // opaque predicate helpers (always true / always false in practice)
    s << "local function " << D << "(x)\n";
    s << "  x=bit32.band(x or 0,255)\n";
    s << "  return bit32.band(x*x-x,1)==0 or x==x\n";
    s << "end\n";
    s << "local function " << E << "(x)\n";
    s << "  return bit32.band((x or 0)+1,0)==2\n"; // always false
    s << "end\n";

    s << "local function _dec(buf)\n";
    s << "local function u8(i) return buf[i] or 0 end\n";
    s << "local function u32(i) return u8(i)+u8(i+1)*256+u8(i+2)*65536+u8(i+3)*16777216 end\n";
    s << "local seed=u32(9) local size=u32(13) local out={}\n";
    s << "if " << E << "(seed) then for i=1,size do out[i]=0 end return out end\n";
    s << "for i=1,size do\n";
    s << "local k=bit32.band(bit32.rshift(seed,bit32.band(i-1,3)*8),255)\n";
    s << "k=bit32.band(bit32.bxor(k,bit32.band((i-1)*131+17,255),bit32.band(seed,255)),255)\n";
    s << "out[i]=bit32.band(bit32.bxor(u8(16+i),k),255)\n";
    s << "if " << E << "(i) then out[i]=bit32.bxor(out[i],1) end\n";
    s << "end return out end\n";

    s << "local data=_dec(_B) local pos=1\n";
    s << "local function ru8() local v=data[pos] or 0 pos+=1 return v end\n";
    s << "local function ru32() return ru8()+ru8()*256+ru8()*65536+ru8()*16777216 end\n";
    s << "if not " << D << "(1) then error(\"o\") end\n";
    s << "if ru32()~=0x3252504C then error(\"x\") end\n";
    s << "local ks=ru32() ru8() local nprotos=ru32() local mainId=ru32() local protos={}\n";

    // decoy proto path (never taken)
    s << "if " << E << "(nprotos) then protos[1]={code={0},k={},child={}} end\n";

    s << "for i=1,nprotos do local p={code={},k={},child={}}\n";
    s << "p.maxstack,p.nparams,p.nups,p.isvararg=ru8(),ru8(),ru8(),ru8()\n";
    s << "local ncode=ru32() for j=1,ncode do p.code[j]=ru32() end\n";
    s << "local nk=ru32() for j=1,nk do local tag=ru8()\n";
    s << "if tag==1 then p.k[j]=ru8()~=0\n";
    s << "elseif tag==2 then p.k[j]=string.unpack(\"<d\",string.char(ru8(),ru8(),ru8(),ru8(),ru8(),ru8(),ru8(),ru8()))\n";
    s << "elseif tag==3 then local n=ru32() local t={} for z=1,n do t[z]=string.char(bit32.band(bit32.bxor(ru8(),bit32.band(ks+(z-1)*13,255)),255)) end p.k[j]=table.concat(t)\n";
    s << "else p.k[j]=nil end end\n";
    s << "local nc=ru32() for j=1,nc do p.child[j]=ru32() end protos[i]=p end\n";

    s << "local function nm(t) local o={} for i=1,#t do o[i]=string.char(bit32.bxor(t[i],91)) end return table.concat(o) end\n";
    s << "local ENV={} ENV[nm({43,25,18,21,15})]=print\n";
    s << "setmetatable(ENV,{__index=function(_,k) return rawget(_G,k) end})\n";
    s << "local function kn(p,word) if word>=2147483648 then return p.k[(word-2147483648)+1] end return word end\n";

    // decoy handlers (never matched by real remapped ops in practice, but present)
    s << "local " << F << "={}\n";
    for (int i = 0; i < 12; ++i) {
        int fake = int((sid + i * 37) % 240);
        s << F << "[" << fake << "]=function(reg,A) reg[A+1]=reg[A+1] end\n";
    }

    s << "local function exec(pid,args)\n";
    s << "local p=protos[pid+1] if not p then error(\"p\") end local reg={} if args then for i=1,#args do reg[i]=args[i] end end\n";
    s << "local pc=1 local code=p.code local " << G << "=0\n";
    s << "while pc<=#code do\n";
    s << "local inst=code[pc]\n";
    s << "local op=bit32.band(inst,255) local A=bit32.band(bit32.rshift(inst,8),255)\n";
    s << "local B=bit32.band(bit32.rshift(inst,16),255) local C=bit32.band(bit32.rshift(inst,24),255)\n";
    s << "local D=bit32.band(bit32.rshift(inst,16),65535) if D>=32768 then D-=65536 end\n";
    s << "local Ra,Rb,Rc=A+1,B+1,C+1\n";
    s << G << "=bit32.band(" << G << "+op,65535)\n";
    s << "if " << E << "(" << G << ") then " << F << "[op](reg,A) end\n";

    // real dispatch (same semantics as working build)
    s << "if op==" << n(Op::MOVE) << " then reg[Ra]=reg[Rb]\n";
    s << "elseif op==" << n(Op::LOADNIL) << " then reg[Ra]=nil\n";
    s << "elseif op==" << n(Op::LOADBOOL) << " then reg[Ra]=B~=0\n";
    s << "elseif op==" << n(Op::LOADK) << " then pc+=1 reg[Ra]=kn(p,code[pc])\n";
    s << "elseif op==" << n(Op::ADD) << " then reg[Ra]=reg[Rb]+reg[Rc]\n";
    s << "elseif op==" << n(Op::SUB) << " then reg[Ra]=reg[Rb]-reg[Rc]\n";
    s << "elseif op==" << n(Op::MUL) << " then reg[Ra]=reg[Rb]*reg[Rc]\n";
    s << "elseif op==" << n(Op::DIV) << " then reg[Ra]=reg[Rb]/reg[Rc]\n";
    s << "elseif op==" << n(Op::MOD) << " then reg[Ra]=reg[Rb]%reg[Rc]\n";
    s << "elseif op==" << n(Op::POW) << " then reg[Ra]=reg[Rb]^reg[Rc]\n";
    s << "elseif op==" << n(Op::UNM) << " then reg[Ra]=-reg[Rb]\n";
    s << "elseif op==" << n(Op::NOT) << " then reg[Ra]=not reg[Rb]\n";
    s << "elseif op==" << n(Op::LEN) << " then reg[Ra]=#reg[Rb]\n";
    s << "elseif op==" << n(Op::CONCAT) << " then local t=\"\" for i=Rb,Rc do t..=tostring(reg[i]) end reg[Ra]=t\n";
    s << "elseif op==" << n(Op::JMP) << " then pc+=D\n";
    s << "elseif op==" << n(Op::JMPIF) << " then if reg[Ra] then pc+=D end\n";
    s << "elseif op==" << n(Op::JMPIFNOT) << " then if not reg[Ra] then pc+=D end\n";
    s << "elseif op==" << n(Op::GETGLOBAL) << " then pc+=1 reg[Ra]=ENV[kn(p,code[pc])]\n";
    s << "elseif op==" << n(Op::SETGLOBAL) << " then pc+=1 ENV[kn(p,code[pc])]=reg[Ra]\n";
    s << "elseif op==" << n(Op::GETTABLE) << " then reg[Ra]=reg[Rb][reg[Rc]]\n";
    s << "elseif op==" << n(Op::SETTABLE) << " then reg[Ra][reg[Rb]]=reg[Rc]\n";
    s << "elseif op==" << n(Op::GETTABLEKS) << " then pc+=1 reg[Ra]=reg[Rb][kn(p,code[pc])]\n";
    s << "elseif op==" << n(Op::NEWTABLE) << " then reg[Ra]={}\n";
    s << "elseif op==" << n(Op::CALL) << " then local narg=if B==0 then (#reg-A) else (B-1) local fn=reg[Ra] local argv={} for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end local ret={fn(table.unpack(argv,1,math.max(narg,0)))} if C~=1 then local limit=if C==0 then #ret else (C-1) for i=1,limit do reg[Ra+i-1]=ret[i] end end\n";
    s << "elseif op==" << n(Op::RETURN) << " then local nret=if B==0 then (#reg-A) else (B-1) local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end return table.unpack(out,1,math.max(nret,0))\n";
    s << "elseif op==" << n(Op::FORPREP) << " then reg[Ra]=(reg[Ra] or 0)-(reg[Ra+2] or 1) pc+=D\n";
    s << "elseif op==" << n(Op::FORLOOP) << " then local step=reg[Ra+2] or 1 local idx=(reg[Ra] or 0)+step local lim=reg[Ra+1] if (step>0 and idx<=lim) or (step<0 and idx>=lim) then reg[Ra]=idx reg[Ra+3]=idx pc+=D end\n";
    s << "elseif op==" << n(Op::CLOSURE) << " then pc+=1 local child=code[pc] or 0 local cid=p.child[child+1] or 0 reg[Ra]=function(...) return exec(cid,{...}) end\n";
    // extra dead elseif noise
    s << "elseif " << E << "(op) then reg[Ra]=reg[Ra]\n";
    s << "elseif op==999 then error(\"deadop\")\n";
    s << "end\n";
    s << "if " << E << "(pc) then pc=pc end\n";
    s << "pc+=1 end end\n";
    s << "if " << E << "(mainId) then return nil end\n";
    s << "return exec(mainId)\n";
    return s.str();
}

} // namespace Protect