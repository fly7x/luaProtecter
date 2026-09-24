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

    uint32_t sum = 0;
    for (uint8_t b : encrypted.data())
        sum += b;

    const std::vector<uint8_t>& raw = encrypted.data();
    size_t mid = raw.empty() ? 0 : raw.size() / 2;
    std::vector<uint8_t> left(raw.begin(), raw.begin() + mid);
    std::vector<uint8_t> right(raw.begin() + mid, raw.end());

    std::stringstream s;
    s << "--!nocheck\n";
    s << "--[[\n";
    s << "  ╔══════════════════════════════════════════╗\n";
    s << "  ║     Protected by FŁÝ / FLYX Obfuscator   ║\n";
    s << "  ║   Dual-VM · Clyde CALL/top · keep private ║\n";
    s << "  ╚══════════════════════════════════════════╝\n";
    s << "]]\n";

    s << "local L=" << bytesToLuaTable(left) << "\n";
    s << "local R=" << bytesToLuaTable(right) << "\n";
    s << "local _B={}\n";
    s << "for i=1,#L do _B[i]=L[i] end\n";
    s << "for i=1,#R do _B[#L+i]=R[i] end\n";
    s << "do local s=0 for i=1,#_B do s+=_B[i] end if s~=" << sum << " then error(\"t\") end end\n";
    s << "L,R=nil,nil\n";

    s << "local function dec(buf)\n";
    s << "local function u8(i) return buf[i] or 0 end\n";
    s << "local function u32(i) return u8(i)+u8(i+1)*256+u8(i+2)*65536+u8(i+3)*16777216 end\n";
    s << "local seed=u32(9) local size=u32(13) local out={}\n";
    s << "for i=1,size do\n";
    s << "local k=bit32.band(bit32.rshift(seed,bit32.band(i-1,3)*8),255)\n";
    s << "k=bit32.band(bit32.bxor(k,bit32.band((i-1)*131+17,255),bit32.band(seed,255)),255)\n";
    s << "out[i]=bit32.band(bit32.bxor(u8(16+i),k),255)\n";
    s << "end return out end\n";

    s << "local data=dec(_B) _B=nil\n";
    s << "local pos=1\n";
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
    s << "data,pos,ru8,ru32=nil,nil,nil,nil\n";

    s << "local function S(raw)\n";
    s << "if type(raw)~=\"table\" then return raw end\n";
    s << "local o={} for i=1,#raw do o[i]=string.char(bit32.band(bit32.bxor(raw[i],bit32.band(ks+(i-1)*13,255)),255)) end\n";
    s << "return table.concat(o)\n";
    s << "end\n";
    s << "for i=1,#P do local p=P[i] for j=1,#p.t do if p.t[j]==3 then p.z[j]=S(p.z[j]) p.t[j]=0 end end end\n";
    s << "S=nil\n";

    s << "local function kn(p,word)\n";
    s << "if type(word)~=\"number\" then return word end\n";
    s << "if word>=2147483648 then\n";
    s << "local i=(word-2147483648)+1\n";
    s << "if p.t[i]~=nil then return p.z[i] end\n";
    s << "return word-4294967296\n";
    s << "end\n";
    s << "return word\n";
    s << "end\n";

    s << "local G={\n";
    s << "game=game,workspace=workspace,Workspace=workspace,script=script,\n";
    s << "Enum=Enum,Instance=Instance,Color3=Color3,UDim2=UDim2,UDim=UDim,\n";
    s << "Vector2=Vector2,Vector3=Vector3,CFrame=CFrame,Rect=Rect,Region3=Region3,\n";
    s << "BrickColor=BrickColor,Ray=Ray,RaycastParams=RaycastParams,OverlapParams=OverlapParams,\n";
    s << "ColorSequence=ColorSequence,ColorSequenceKeypoint=ColorSequenceKeypoint,\n";
    s << "NumberSequence=NumberSequence,NumberSequenceKeypoint=NumberSequenceKeypoint,\n";
    s << "NumberRange=NumberRange,TweenInfo=TweenInfo,PathWaypoint=PathWaypoint,\n";
    s << "PhysicalProperties=PhysicalProperties,Faces=Faces,Axes=Axes,\n";
    s << "task=task,tick=tick,time=time,os=os,typeof=typeof,\n";
    s << "pairs=pairs,ipairs=ipairs,next=next,pcall=pcall,xpcall=xpcall,\n";
    s << "print=print,warn=warn,error=error,tostring=tostring,tonumber=tonumber,\n";
    s << "type=type,select=select,unpack=table.unpack,table=table,string=string,\n";
    s << "math=math,bit32=bit32,buffer=buffer,utf8=utf8,coroutine=coroutine,\n";
    s << "require=require,shared=shared,setfenv=setfenv,getfenv=getfenv,\n";
    s << "setmetatable=setmetatable,getmetatable=getmetatable,\n";
    s << "rawget=rawget,rawset=rawset,rawequal=rawequal,rawlen=rawlen,\n";
    s << "newproxy=newproxy,\n";
    s << "}\n";
    s << "pcall(function() G.setclipboard=setclipboard end)\n";

    s << "local RealG=_G\n";
    s << "pcall(function() if getfenv then local e=getfenv() if type(e)==\"table\" then RealG=e end end end)\n";
    s << "if type(RealG)~=\"table\" then RealG=_G end\n";
    s << "G._G=RealG G._ENV=RealG\n";
    s << "local E=setmetatable({},{__index=function(_,k)\n";
    s << "local v=G[k] if v~=nil then return v end\n";
    s << "v=rawget(RealG,k) if v~=nil then return v end\n";
    s << "return rawget(_G,k)\n";
    s << "end,__newindex=function(_,k,v) RealG[k]=v G[k]=v end})\n";

    s << "local CAP=" << n(Op::CAPTURE) << "\n";
    s << "local tpack=table.pack\n";
    s << "local tunpack=table.unpack\n";

    s << "local function filterSeqTable(t, wantType)\n";
    s << "if type(t)~=\"table\" then return t end\n";
    s << "local out={}\n";
    s << "for i=1,64 do\n";
    s << "local v=t[i]\n";
    s << "if v==nil then break end\n";
    s << "if typeof(v)==wantType then out[#out+1]=v end\n";
    s << "end\n";
    s << "return #out>0 and out or t\n";
    s << "end\n";

    s << "local function run(pid,args,ups)\n";
    s << "local p=P[pid+1] if not p then error(\"p\") end\n";
    s << "local reg={} local top=0\n";
    s << "if args then for i=1,#args do reg[i]=args[i] if i>top then top=i end end end\n";
    s << "ups=ups or {}\n";
    s << "local function setR(i,v)\n";
    s << "reg[i]=v\n";
    s << "if i>top then top=i end\n";
    s << "end\n";
    s << "local pc=1 local code=p.c\n";
    s << "while pc<=#code do\n";
    s << "local inst=code[pc]\n";
    s << "local op=bit32.band(inst,255)\n";
    s << "local A=bit32.band(bit32.rshift(inst,8),255)\n";
    s << "local B=bit32.band(bit32.rshift(inst,16),255)\n";
    s << "local C=bit32.band(bit32.rshift(inst,24),255)\n";
    s << "local D=bit32.band(bit32.rshift(inst,16),65535) if D>=32768 then D-=65536 end\n";
    s << "local Ra,Rb,Rc=A+1,B+1,C+1\n";

    s << "if op==" << n(Op::MOVE) << " then setR(Ra,reg[Rb])\n";
    s << "elseif op==" << n(Op::LOADNIL) << " then setR(Ra,nil)\n";
    s << "elseif op==" << n(Op::LOADBOOL) << " then setR(Ra,B~=0)\n";
    s << "elseif op==" << n(Op::LOADK) << " then pc+=1 setR(Ra,kn(p,code[pc]))\n";
    s << "elseif op==" << n(Op::ADD) << " then local ok,res=pcall(function() return reg[Rb]+reg[Rc] end) setR(Ra,ok and res or nil)\n";
    s << "elseif op==" << n(Op::SUB) << " then local ok,res=pcall(function() return reg[Rb]-reg[Rc] end) setR(Ra,ok and res or nil)\n";
    s << "elseif op==" << n(Op::MUL) << " then local ok,res=pcall(function() return reg[Rb]*reg[Rc] end) setR(Ra,ok and res or nil)\n";
    s << "elseif op==" << n(Op::DIV) << " then local ok,res=pcall(function() return reg[Rb]/reg[Rc] end) setR(Ra,ok and res or nil)\n";
    s << "elseif op==" << n(Op::MOD) << " then local ok,res=pcall(function() return reg[Rb]%reg[Rc] end) setR(Ra,ok and res or nil)\n";
    s << "elseif op==" << n(Op::POW) << " then local ok,res=pcall(function() return reg[Rb]^reg[Rc] end) setR(Ra,ok and res or nil)\n";
    s << "elseif op==" << n(Op::IDIV) << " then local ok,res=pcall(function() return math.floor(reg[Rb]/reg[Rc]) end) setR(Ra,ok and res or nil)\n";
    s << "elseif op==" << n(Op::UNM) << " then local ok,res=pcall(function() return -reg[Rb] end) setR(Ra,ok and res or nil)\n";
    s << "elseif op==" << n(Op::NOT) << " then setR(Ra,not reg[Rb])\n";
    s << "elseif op==" << n(Op::LEN) << " then local ok,res=pcall(function() return #reg[Rb] end) setR(Ra,ok and res or 0)\n";
    s << "elseif op==" << n(Op::CONCAT) << " then local t=\"\" for i=Rb,Rc do t..=tostring(reg[i]) end setR(Ra,t)\n";
    s << "elseif op==" << n(Op::AND) << " then if reg[Rb] then setR(Ra,reg[Rc]) else setR(Ra,reg[Rb]) end\n";
    s << "elseif op==" << n(Op::OR) << " then if reg[Rb] then setR(Ra,reg[Rb]) else setR(Ra,reg[Rc]) end\n";
    s << "elseif op==" << n(Op::JMP) << " then pc+=D\n";
    s << "elseif op==" << n(Op::JMPIF) << " then if reg[Ra] then pc+=D end\n";
    s << "elseif op==" << n(Op::JMPIFNOT) << " then if not reg[Ra] then pc+=D end\n";
    s << "elseif op==" << n(Op::EQ) << " then if not (reg[Ra]==reg[Rb]) then pc+=1 end\n";
    s << "elseif op==" << n(Op::LT) << " then if not (reg[Ra]<reg[Rb]) then pc+=1 end\n";
    s << "elseif op==" << n(Op::LE) << " then if not (reg[Ra]<=reg[Rb]) then pc+=1 end\n";
    s << "elseif op==" << n(Op::GETGLOBAL) << " then pc+=1 setR(Ra,E[kn(p,code[pc])])\n";
    s << "elseif op==" << n(Op::SETGLOBAL) << " then pc+=1 local key=kn(p,code[pc]) E[key]=reg[Ra] RealG[key]=reg[Ra] G[key]=reg[Ra]\n";
    s << "elseif op==" << n(Op::GETTABLE) << " then local t=reg[Rb] setR(Ra,t~=nil and t[reg[Rc]] or nil)\n";
    s << "elseif op==" << n(Op::SETTABLE) << " then local t=reg[Rb] if t~=nil then t[reg[Rc]]=reg[Ra] end\n";
    s << "elseif op==" << n(Op::GETTABLEKS) << " then pc+=1 local t=reg[Rb] local key=kn(p,code[pc]) setR(Ra,t~=nil and t[key] or nil)\n";
    s << "elseif op==" << n(Op::SETTABLEKS) << " then pc+=1 local t=reg[Rb] local key=kn(p,code[pc]) if t~=nil then t[key]=reg[Ra] end\n";
    s << "elseif op==" << n(Op::GETTABLEN) << " then local t=reg[Rb] setR(Ra,t~=nil and t[C+1] or nil)\n";
    s << "elseif op==" << n(Op::SETTABLEN) << " then local t=reg[Rb] if t~=nil then t[C+1]=reg[Ra] end\n";
    s << "elseif op==" << n(Op::NEWTABLE) << " then setR(Ra,{})\n";
    s << "elseif op==" << n(Op::NAMECALL) << " then\n";
    s << "pc+=1 local key=kn(p,code[pc]) local obj=reg[Rb]\n";
    s << "setR(Ra+1,obj)\n";
    s << "setR(Ra,obj~=nil and obj[key] or nil)\n";
    s << "if top<Ra+1 then top=Ra+1 end\n";
    s << "elseif op==" << n(Op::GETUPVAL) << " then setR(Ra,ups[B+1])\n";
    s << "elseif op==" << n(Op::SETUPVAL) << " then ups[B+1]=reg[Ra]\n";

    s << "elseif op==" << n(Op::SETLIST) << " then\n";
    s << "pc+=1\n";
    s << "local start=code[pc] or 1\n";
    s << "local t=reg[Ra]\n";
    s << "local n=B\n";
    s << "if n==0 then n=math.max(0,top-Ra) end\n";
    s << "if type(t)==\"table\" then for i=1,n do t[start+i-1]=reg[Ra+i] end end\n";

    // ── CALL: Clyde-style (table.pack + top shrink) ──
    s << "elseif op==" << n(Op::CALL) << " then\n";
    s << "local fn=reg[Ra]\n";
    s << "local r\n";
    s << "if type(fn)~=\"function\" then\n";
    s << "local a1,a2,a3=reg[Ra+1],reg[Ra+2],reg[Ra+3]\n";
    s << "if type(a1)==\"number\" and type(a2)==\"number\" and type(a3)==\"number\" then\n";
    s << "local x,lo,hi=a1,a2,a3\n";
    s << "if x<lo then x=lo elseif x>hi then x=hi end\n";
    s << "r=tpack(x)\n";
    s << "elseif type(a1)==\"number\" and (B==0 or B<=2) then\n";
    s << "r=tpack(math.floor(a1))\n";
    s << "else\n";
    s << "error(\"bad call \"..tostring(fn)..\" at pc \"..tostring(pc)..\" pid \"..tostring(pid))\n";
    s << "end\n";
    s << "else\n";
    s << "if B==1 then\n";
    s << "r=tpack(fn())\n";
    s << "elseif B==2 then\n";
    s << "r=tpack(fn(reg[Ra+1]))\n";
    s << "elseif B==3 then\n";
    s << "r=tpack(fn(reg[Ra+1],reg[Ra+2]))\n";
    s << "elseif B==4 then\n";
    s << "r=tpack(fn(reg[Ra+1],reg[Ra+2],reg[Ra+3]))\n";
    s << "elseif B==0 then\n";
    s << "local hi=top\n";
    s << "if hi<Ra then hi=Ra end\n";
    s << "r=tpack(fn(tunpack(reg,Ra+1,hi)))\n";
    s << "else\n";
    s << "r=tpack(fn(tunpack(reg,Ra+1,Ra+(B-1))))\n";
    s << "end\n";
    s << "if r.n>=1 and type(r[1])==\"table\" then\n";
    s << "local filtered=filterSeqTable(r[1],\"ColorSequenceKeypoint\")\n";
    s << "if filtered==r[1] then filtered=filterSeqTable(r[1],\"NumberSequenceKeypoint\") end\n";
    s << "end\n";
    s << "end\n";
    // store results + ALWAYS shrink/set top (Clyde pattern)
    s << "if C==0 then\n";
    s << "for i=1,r.n do setR(Ra+i-1,r[i]) end\n";
    s << "top=Ra+r.n-1\n";
    s << "if top<Ra-1 then top=math.max(0,Ra-1) end\n";
    s << "elseif C==1 then\n";
    s << "top=math.max(0,Ra-1)\n";
    s << "else\n";
    s << "for i=1,C-1 do setR(Ra+i-1,r[i]) end\n";
    s << "top=Ra+(C-1)-1\n";
    s << "end\n";

    s << "elseif op==" << n(Op::RETURN) << " then\n";
    s << "if B==0 then return tunpack(reg,Ra,top)\n";
    s << "elseif B==1 then return\n";
    s << "else return tunpack(reg,Ra,Ra+(B-1)-1) end\n";

    s << "elseif op==" << n(Op::FORPREP) << " then if type(reg[Ra])==\"number\" then setR(Ra,(reg[Ra] or 0)-(reg[Ra+2] or 1)) end pc+=D\n";
    s << "elseif op==" << n(Op::FORLOOP) << " then if type(reg[Ra])==\"number\" then local step=reg[Ra+2] or 1 local idx=(reg[Ra] or 0)+step local lim=reg[Ra+1] if (step>0 and idx<=lim) or (step<0 and idx>=lim) then setR(Ra,idx) setR(Ra+3,idx) pc+=D end end\n";
    s << "elseif op==" << n(Op::FORGLOOP) << " then local it,state,ctl=reg[Ra],reg[Ra+1],reg[Ra+2] if type(it)==\"function\" then local res=tpack(it(state,ctl)) if res[1]~=nil then setR(Ra+2,res[1]) for i=1,res.n do setR(Ra+2+i,res[i]) end pc+=D end end\n";

    s << "elseif op==" << n(Op::CLOSURE) << " then\n";
    s << "pc+=1\n";
    s << "local child=code[pc] or 0\n";
    s << "local cid=p.ch[child+1] or 0\n";
    s << "local parentReg,parentUps=reg,ups\n";
    s << "local stored={}\n";
    s << "for i=1,64 do stored[i]=parentReg[i] end\n";
    s << "for i=1,64 do if stored[i]==nil then stored[i]=parentUps[i] end end\n";
    s << "local ui=1\n";
    s << "while pc+1<=#code do\n";
    s << "local nextInst=code[pc+1]\n";
    s << "local nextOp=bit32.band(nextInst,255)\n";
    s << "if nextOp~=CAP then break end\n";
    s << "pc+=1\n";
    s << "local ca=bit32.band(bit32.rshift(nextInst,8),255)\n";
    s << "local cb=bit32.band(bit32.rshift(nextInst,16),255)\n";
    s << "local v=nil\n";
    s << "if ca==2 then v=parentUps[cb+1]\n";
    s << "elseif ca<=1 then v=parentReg[cb+1] end\n";
    s << "if v~=nil then stored[ui]=v end\n";
    s << "ui+=1\n";
    s << "if ui>64 then break end\n";
    s << "end\n";
    s << "setR(Ra,function(...) return run(cid,{...},stored) end)\n";
    s << "elseif op==" << n(Op::CAPTURE) << " then\n";
    s << "end\n";
    s << "pc+=1\n";
    s << "end\n";
    s << "end\n";
    s << "return run(mainId)\n";
    return s.str();
}

} // namespace Protect