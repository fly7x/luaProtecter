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
        if ((i % 14) == 0) ss << "\n";
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
    uint32_t sid = seed32();
    uint32_t sum = 0;
    for (uint8_t b : encrypted.data())
        sum += b;

    const std::vector<uint8_t>& raw = encrypted.data();
    size_t mid = raw.empty() ? 0 : raw.size() / 2;
    std::vector<uint8_t> left(raw.begin(), raw.begin() + mid);
    std::vector<uint8_t> right(raw.begin() + mid, raw.end());

    auto exprOp = [&](Op o) {
        int v = n(o);
        int a = (v ^ int(sid & 63)) & 255;
        int b = v ^ a;
        std::stringstream e;
        e << "bit32.bxor(" << a << "," << b << ")";
        return e.str();
    };

    std::stringstream s;
    s << "--!nocheck\n";
    s << "local L=" << bytesToLuaTable(left) << "\n";
    s << "local R=" << bytesToLuaTable(right) << "\n";
    s << "local _B={}\n";
    s << "for i=1,#L do _B[i]=L[i] end\n";
    s << "for i=1,#R do _B[#L+i]=R[i] end\n";
    s << "do local s=0 for i=1,#_B do s+=_B[i] end if s~=" << sum << " then error(\"t\") end end\n";

    s << "local function dec(buf)\n";
    s << "local function u8(i) return buf[i] or 0 end\n";
    s << "local function u32(i) return u8(i)+u8(i+1)*256+u8(i+2)*65536+u8(i+3)*16777216 end\n";
    s << "local seed=u32(9) local size=u32(13) local out={}\n";
    s << "for i=1,size do\n";
    s << "local k=bit32.band(bit32.rshift(seed,bit32.band(i-1,3)*8),255)\n";
    s << "k=bit32.band(bit32.bxor(k,bit32.band((i-1)*131+17,255),bit32.band(seed,255)),255)\n";
    s << "out[i]=bit32.band(bit32.bxor(u8(16+i),k),255)\n";
    s << "end return out end\n";

    s << "local data=dec(_B) local pos=1\n";
    s << "local function ru8() local v=data[pos] or 0 pos+=1 return v end\n";
    s << "local function ru32() return ru8()+ru8()*256+ru8()*65536+ru8()*16777216 end\n";
    s << "if ru32()~=0x3252504C then error(\"x\") end\n";
    s << "local ks=ru32() ru8() local nprotos=ru32() local mainId=ru32()\n";
    s << "local P={}\n";
    s << "for i=1,nprotos do\n";
    s << "local p={c={},z={},t={},ch={}}\n";
    s << "p.m,p.a,p.u,p.v=ru8(),ru8(),ru8(),ru8()\n";
    s << "local ncode=ru32() for j=1,ncode do p.c[j]=ru32() end\n";
    s << "local nk=ru32() for j=1,nk do local tag=ru8() p.t[j]=tag\n";
    s << "if tag==1 then p.z[j]=ru8()~=0\n";
    s << "elseif tag==2 then p.z[j]=string.unpack(\"<d\",string.char(ru8(),ru8(),ru8(),ru8(),ru8(),ru8(),ru8(),ru8()))\n";
    s << "elseif tag==3 then local n=ru32() local raw={} for z=1,n do raw[z]=ru8() end p.z[j]=raw\n";
    s << "else p.z[j]=nil end end\n";
    s << "local nc=ru32() for j=1,nc do p.ch[j]=ru32() end P[i]=p end\n";

    s << "local function S(raw)\n";
    s << "if type(raw)~=\"table\" then return raw end\n";
    s << "local o={} for i=1,#raw do o[i]=string.char(bit32.band(bit32.bxor(raw[i],bit32.band(ks+(i-1)*13,255)),255)) end\n";
    s << "return table.concat(o)\n";
    s << "end\n";
    s << "local function kn(p,word)\n";
    s << "if word>=2147483648 then\n";
    s << "local i=(word-2147483648)+1\n";
    s << "if p.t[i]==3 then p.z[i]=S(p.z[i]) p.t[i]=0 end\n";
    s << "return p.z[i]\n";
    s << "end\n";
    s << "return word\n";
    s << "end\n";

    s << "local E={}\n";
    s << "do local n={} local raw={43,25,18,21,15}\n";
    s << "for i=1,#raw do n[i]=string.char(bit32.bxor(raw[i],91)) end\n";
    s << "E[table.concat(n)]=print\n";
    s << "end\n";
    s << "setmetatable(E,{__index=function(_,k) return rawget(_G,k) end})\n";

    s << "local M=" << exprOp(Op::MOVE) << "\n";
    s << "local NI=" << exprOp(Op::LOADNIL) << "\n";
    s << "local LB=" << exprOp(Op::LOADBOOL) << "\n";
    s << "local LK=" << exprOp(Op::LOADK) << "\n";
    s << "local AD=" << exprOp(Op::ADD) << "\n";
    s << "local SU=" << exprOp(Op::SUB) << "\n";
    s << "local MU=" << exprOp(Op::MUL) << "\n";
    s << "local DV=" << exprOp(Op::DIV) << "\n";
    s << "local MD=" << exprOp(Op::MOD) << "\n";
    s << "local PW=" << exprOp(Op::POW) << "\n";
    s << "local UN=" << exprOp(Op::UNM) << "\n";
    s << "local NT=" << exprOp(Op::NOT) << "\n";
    s << "local LN=" << exprOp(Op::LEN) << "\n";
    s << "local CC=" << exprOp(Op::CONCAT) << "\n";
    s << "local JM=" << exprOp(Op::JMP) << "\n";
    s << "local JI=" << exprOp(Op::JMPIF) << "\n";
    s << "local JN=" << exprOp(Op::JMPIFNOT) << "\n";
    s << "local GG=" << exprOp(Op::GETGLOBAL) << "\n";
    s << "local SG=" << exprOp(Op::SETGLOBAL) << "\n";
    s << "local GT=" << exprOp(Op::GETTABLE) << "\n";
    s << "local ST=" << exprOp(Op::SETTABLE) << "\n";
    s << "local GK=" << exprOp(Op::GETTABLEKS) << "\n";
    s << "local TB=" << exprOp(Op::NEWTABLE) << "\n";
    s << "local CA=" << exprOp(Op::CALL) << "\n";
    s << "local RT=" << exprOp(Op::RETURN) << "\n";
    s << "local FP=" << exprOp(Op::FORPREP) << "\n";
    s << "local FL=" << exprOp(Op::FORLOOP) << "\n";
    s << "local CL=" << exprOp(Op::CLOSURE) << "\n";

    s << "local function stepA(op,p,reg,A,B,C,D,pc,code)\n";
    s << "local Ra,Rb,Rc=A+1,B+1,C+1\n";
    s << "if op==M then reg[Ra]=reg[Rb] return pc,0 end\n";
    s << "if op==NI then reg[Ra]=nil return pc,0 end\n";
    s << "if op==LB then reg[Ra]=B~=0 return pc,0 end\n";
    s << "if op==LK then pc+=1 reg[Ra]=kn(p,code[pc]) return pc,0 end\n";
    s << "if op==AD then reg[Ra]=reg[Rb]+reg[Rc] return pc,0 end\n";
    s << "if op==SU then reg[Ra]=reg[Rb]-reg[Rc] return pc,0 end\n";
    s << "if op==MU then reg[Ra]=reg[Rb]*reg[Rc] return pc,0 end\n";
    s << "if op==DV then reg[Ra]=reg[Rb]/reg[Rc] return pc,0 end\n";
    s << "return pc,1\n";
    s << "end\n";

    s << "local function stepB(op,p,reg,A,B,C,D,pc,code)\n";
    s << "local Ra,Rb,Rc=A+1,B+1,C+1\n";
    s << "if op==MD then reg[Ra]=reg[Rb]%reg[Rc] return pc,0 end\n";
    s << "if op==PW then reg[Ra]=reg[Rb]^reg[Rc] return pc,0 end\n";
    s << "if op==UN then reg[Ra]=-reg[Rb] return pc,0 end\n";
    s << "if op==NT then reg[Ra]=not reg[Rb] return pc,0 end\n";
    s << "if op==LN then reg[Ra]=#reg[Rb] return pc,0 end\n";
    s << "if op==CC then local t=\"\" for i=Rb,Rc do t..=tostring(reg[i]) end reg[Ra]=t return pc,0 end\n";
    s << "if op==JM then return pc+D,0 end\n";
    s << "if op==JI then if reg[Ra] then pc+=D end return pc,0 end\n";
    s << "if op==JN then if not reg[Ra] then pc+=D end return pc,0 end\n";
    s << "return pc,1\n";
    s << "end\n";

    s << "local function stepC(op,p,reg,A,B,C,D,pc,code,run)\n";
    s << "local Ra,Rb,Rc=A+1,B+1,C+1\n";
    s << "if op==GG then pc+=1 reg[Ra]=E[kn(p,code[pc])] return pc,0 end\n";
    s << "if op==SG then pc+=1 E[kn(p,code[pc])]=reg[Ra] return pc,0 end\n";
    s << "if op==GT then reg[Ra]=reg[Rb][reg[Rc]] return pc,0 end\n";
    s << "if op==ST then reg[Ra][reg[Rb]]=reg[Rc] return pc,0 end\n";
    s << "if op==GK then pc+=1 reg[Ra]=reg[Rb][kn(p,code[pc])] return pc,0 end\n";
    s << "if op==TB then reg[Ra]={} return pc,0 end\n";
    s << "if op==CA then local narg=if B==0 then (#reg-A) else (B-1) local fn=reg[Ra] local argv={} for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end local ret={fn(table.unpack(argv,1,math.max(narg,0)))} if C~=1 then local limit=if C==0 then #ret else (C-1) for i=1,limit do reg[Ra+i-1]=ret[i] end end return pc,0 end\n";
    s << "if op==RT then local nret=if B==0 then (#reg-A) else (B-1) local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end return pc,2,out,nret end\n";
    s << "if op==FP then reg[Ra]=(reg[Ra] or 0)-(reg[Ra+2] or 1) return pc+D,0 end\n";
    s << "if op==FL then local step=reg[Ra+2] or 1 local idx=(reg[Ra] or 0)+step local lim=reg[Ra+1] if (step>0 and idx<=lim) or (step<0 and idx>=lim) then reg[Ra]=idx reg[Ra+3]=idx return pc+D,0 end return pc,0 end\n";
    s << "if op==CL then pc+=1 local child=code[pc] or 0 local cid=p.ch[child+1] or 0 reg[Ra]=function(...) return run(cid,{...}) end return pc,0 end\n";
    s << "return pc,1\n";
    s << "end\n";

    s << "local function run(pid,args)\n";
    s << "local p=P[pid+1] if not p then error(\"p\") end\n";
    s << "local reg={} if args then for i=1,#args do reg[i]=args[i] end end\n";
    s << "local pc=1 local code=p.c\n";
    s << "while pc<=#code do\n";
    s << "local inst=code[pc]\n";
    s << "local op=bit32.band(inst,255)\n";
    s << "local A=bit32.band(bit32.rshift(inst,8),255)\n";
    s << "local B=bit32.band(bit32.rshift(inst,16),255)\n";
    s << "local C=bit32.band(bit32.rshift(inst,24),255)\n";
    s << "local D=bit32.band(bit32.rshift(inst,16),65535) if D>=32768 then D-=65536 end\n";
    s << "local npc,st,out,nret=stepA(op,p,reg,A,B,C,D,pc,code)\n";
    s << "if st==1 then npc,st,out,nret=stepB(op,p,reg,A,B,C,D,npc,code) end\n";
    s << "if st==1 then npc,st,out,nret=stepC(op,p,reg,A,B,C,D,npc,code,run) end\n";
    s << "if st==2 then return table.unpack(out,1,nret) end\n";
    s << "pc=npc+1\n";
    s << "end\n";
    s << "end\n";
    s << "return run(mainId)\n";
    return s.str();
}

} // namespace Protect