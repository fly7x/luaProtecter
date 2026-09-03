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
    s << "local G=_G\n";
    s << "pcall(function() if getfenv then G=getfenv() or G end end)\n";
    s << "local E=setmetatable({},{__index=function(_,k)\n";
    s << "local v=rawget(G,k) if v~=nil then return v end\n";
    s << "if k==\"game\" then return game end\n";
    s << "if k==\"workspace\" then return workspace end\n";
    s << "if k==\"script\" then return script end\n";
    s << "if k==\"Enum\" then return Enum end\n";
    s << "if k==\"Instance\" then return Instance end\n";
    s << "if k==\"Color3\" then return Color3 end\n";
    s << "if k==\"UDim2\" then return UDim2 end\n";
    s << "if k==\"UDim\" then return UDim end\n";
    s << "if k==\"Vector2\" then return Vector2 end\n";
    s << "if k==\"Vector3\" then return Vector3 end\n";
    s << "if k==\"CFrame\" then return CFrame end\n";
    s << "if k==\"ColorSequence\" then return ColorSequence end\n";
    s << "if k==\"ColorSequenceKeypoint\" then return ColorSequenceKeypoint end\n";
    s << "if k==\"task\" then return task end\n";
    s << "if k==\"tick\" then return tick end\n";
    s << "if k==\"time\" then return time end\n";
    s << "if k==\"typeof\" then return typeof end\n";
    s << "if k==\"pairs\" then return pairs end\n";
    s << "if k==\"ipairs\" then return ipairs end\n";
    s << "if k==\"pcall\" then return pcall end\n";
    s << "if k==\"print\" then return print end\n";
    s << "if k==\"warn\" then return warn end\n";
    s << "if k==\"error\" then return error end\n";
    s << "if k==\"tostring\" then return tostring end\n";
    s << "if k==\"tonumber\" then return tonumber end\n";
    s << "if k==\"type\" then return type end\n";
    s << "if k==\"select\" then return select end\n";
    s << "if k==\"unpack\" then return table.unpack end\n";
    s << "if k==\"table\" then return table end\n";
    s << "if k==\"string\" then return string end\n";
    s << "if k==\"math\" then return math end\n";
    s << "if k==\"bit32\" then return bit32 end\n";
    s << "return rawget(_G,k)\n";
    s << "end})\n";

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
    s << "local SK=" << exprOp(Op::SETTABLEKS) << "\n";
    s << "local TB=" << exprOp(Op::NEWTABLE) << "\n";
    s << "local CA=" << exprOp(Op::CALL) << "\n";
    s << "local RT=" << exprOp(Op::RETURN) << "\n";
    s << "local FP=" << exprOp(Op::FORPREP) << "\n";
    s << "local FL=" << exprOp(Op::FORLOOP) << "\n";
    s << "local CL=" << exprOp(Op::CLOSURE) << "\n";
    s << "local NC=" << exprOp(Op::NAMECALL) << "\n";
    s << "local GU=" << exprOp(Op::GETUPVAL) << "\n";
    s << "local SUU=" << exprOp(Op::SETUPVAL) << "\n";
    s << "local SL=" << exprOp(Op::SETLIST) << "\n";

    s << "local function run(pid,args,ups)\n";
    s << "local p=P[pid+1] if not p then error(\"p\") end\n";
    s << "local reg={} if args then for i=1,#args do reg[i]=args[i] end end\n";
    s << "ups=ups or {}\n";
    s << "local pc=1 local code=p.c\n";
    s << "while pc<=#code do\n";
    s << "local inst=code[pc]\n";
    s << "local op=bit32.band(inst,255)\n";
    s << "local A=bit32.band(bit32.rshift(inst,8),255)\n";
    s << "local B=bit32.band(bit32.rshift(inst,16),255)\n";
    s << "local C=bit32.band(bit32.rshift(inst,24),255)\n";
    s << "local D=bit32.band(bit32.rshift(inst,16),65535) if D>=32768 then D-=65536 end\n";
    s << "local Ra,Rb,Rc=A+1,B+1,C+1\n";
    s << "if op==" << n(Op::MOVE) << " then reg[Ra]=reg[Rb]\n";
    s << "elseif op==" << n(Op::LOADNIL) << " then reg[Ra]=nil\n";
    s << "elseif op==" << n(Op::LOADBOOL) << " then reg[Ra]=B~=0\n";
    s << "elseif op==" << n(Op::LOADK) << " then pc+=1 reg[Ra]=kn(p,code[pc])\n";
    s << "elseif op==" << n(Op::ADD) << " then reg[Ra]=(reg[Rb] or 0)+(reg[Rc] or 0)\n";
    s << "elseif op==" << n(Op::SUB) << " then reg[Ra]=(reg[Rb] or 0)-(reg[Rc] or 0)\n";
    s << "elseif op==" << n(Op::MUL) << " then reg[Ra]=(reg[Rb] or 0)*(reg[Rc] or 0)\n";
    s << "elseif op==" << n(Op::DIV) << " then reg[Ra]=(reg[Rb] or 1)/(reg[Rc] or 1)\n";
    s << "elseif op==" << n(Op::MOD) << " then reg[Ra]=(reg[Rb] or 0)%(reg[Rc] or 1)\n";
    s << "elseif op==" << n(Op::POW) << " then reg[Ra]=(reg[Rb] or 0)^(reg[Rc] or 1)\n";
    s << "elseif op==" << n(Op::UNM) << " then reg[Ra]=-(reg[Rb] or 0)\n";
    s << "elseif op==" << n(Op::NOT) << " then reg[Ra]=not reg[Rb]\n";
    s << "elseif op==" << n(Op::LEN) << " then reg[Ra]=#(reg[Rb] or \"\")\n";
    s << "elseif op==" << n(Op::CONCAT) << " then local t=\"\" for i=Rb,Rc do t..=tostring(reg[i]) end reg[Ra]=t\n";
    s << "elseif op==" << n(Op::JMP) << " then pc+=D\n";
    s << "elseif op==" << n(Op::JMPIF) << " then if reg[Ra] then pc+=D end\n";
    s << "elseif op==" << n(Op::JMPIFNOT) << " then if not reg[Ra] then pc+=D end\n";
    s << "elseif op==" << n(Op::GETGLOBAL) << " then pc+=1 reg[Ra]=E[kn(p,code[pc])]\n";
    s << "elseif op==" << n(Op::SETGLOBAL) << " then pc+=1 E[kn(p,code[pc])]=reg[Ra]\n";
    s << "elseif op==" << n(Op::GETTABLE) << " then reg[Ra]=reg[Rb][reg[Rc]]\n";
    s << "elseif op==" << n(Op::SETTABLE) << " then reg[Ra][reg[Rb]]=reg[Rc]\n";
    s << "elseif op==" << n(Op::GETTABLEKS) << " then pc+=1 reg[Ra]=reg[Rb][kn(p,code[pc])]\n";
    s << "elseif op==" << n(Op::SETTABLEKS) << " then pc+=1 reg[Rb][kn(p,code[pc])]=reg[Ra]\n";
    s << "elseif op==" << n(Op::NEWTABLE) << " then reg[Ra]={}\n";
    s << "elseif op==" << n(Op::NAMECALL) << " then pc+=1 local key=kn(p,code[pc]) local obj=reg[Rb] reg[Ra+1]=obj local m=obj and obj[key] reg[Ra]=m\n";
    s << "elseif op==" << n(Op::GETUPVAL) << " then reg[Ra]=ups[Rb]\n";
    s << "elseif op==" << n(Op::SETUPVAL) << " then ups[Rb]=reg[Ra]\n";
    s << "elseif op==" << n(Op::SETLIST) << " then local t=reg[Ra] local n=if C==0 then (#reg-A) else (C-1) for i=1,n do t[i]=reg[Ra+i] end\n";
    s << "elseif op==" << n(Op::CALL) << " then local narg=if B==0 then (#reg-A) else (B-1) local fn=reg[Ra] local argv={} for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end local ret={fn(table.unpack(argv,1,math.max(narg,0)))} if C~=1 then local limit=if C==0 then #ret else (C-1) for i=1,limit do reg[Ra+i-1]=ret[i] end end\n";
    s << "elseif op==" << n(Op::RETURN) << " then local nret=if B==0 then (#reg-A) else (B-1) local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end return table.unpack(out,1,math.max(nret,0))\n";
    s << "elseif op==" << n(Op::FORPREP) << " then reg[Ra]=(reg[Ra] or 0)-(reg[Ra+2] or 1) pc+=D\n";
    s << "elseif op==" << n(Op::FORLOOP) << " then local step=reg[Ra+2] or 1 local idx=(reg[Ra] or 0)+step local lim=reg[Ra+1] if (step>0 and idx<=lim) or (step<0 and idx>=lim) then reg[Ra]=idx reg[Ra+3]=idx pc+=D end\n";
    s << "elseif op==" << n(Op::CLOSURE) << " then pc+=1 local child=code[pc] or 0 local cid=p.ch[child+1] or 0 reg[Ra]=function(...) return run(cid,{...},reg) end\n";
    s << "end pc+=1 end end\n";
    s << "return run(mainId)\n";
    return s.str();
}

} // namespace Protect