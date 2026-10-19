#include "virtualizer.hpp"
#include "isa.hpp"

#include <sstream>
#include <vector>
#include <cstdint>
#include <array>

namespace Protect {

Virtualizer::Virtualizer(uint32_t seed) : seed_(seed ? seed : 0xA341316Cu) {}

static std::vector<uint8_t> xorBlob(const std::vector<uint8_t>& in, uint32_t seed) {
    std::vector<uint8_t> out(in.size());
    for (size_t i = 0; i < in.size(); ++i) {
        uint8_t k = uint8_t((seed + uint32_t(i) * 131u + 17u) & 0xFFu);
        out[i] = uint8_t(in[i] ^ k);
    }
    return out;
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& encryptedBlob) const {
    return emitVirtualizedScript(encryptedBlob, Options{});
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& encryptedBlob,
                                               const Options& options) const {
    const auto& raw = encryptedBlob.data();
    if (raw.empty())
        return "error(\"empty blob\")\n";

    uint32_t s = seed_;
    std::vector<uint8_t> bytes = xorBlob(raw, s);
    uint32_t sum = 0;
    for (uint8_t b : bytes)
        sum += b;

    size_t mid = bytes.size() / 2;
    int heads = (options.heads <= 1) ? 1 : 2;
    bool watchdog = options.watchdog;

    // map[logical Op] = raw byte  → inv[raw] = logical
    auto map = makeOpcodeMap(s);
    std::array<int, 256> inv{};
    for (int i = 0; i < 256; ++i)
        inv[i] = -1;
    for (size_t logical = 0; logical < map.size(); ++logical) {
        inv[map[logical]] = int(logical);
    }

    std::ostringstream o;

    o << "--[[\n";
    o << "  ╔══════════════════════════════════════════╗\n";
    o << "  ║          FŁÝ  ·  FLYX  Protection         ║\n";
    o << "  ║   Fast-VM  ·  private ISA  ·  sealed      ║\n";
    o << "  ╚══════════════════════════════════════════╝\n";
    o << "]]\n";

    o << "local L={";
    for (size_t i = 0; i < mid; ++i) {
        if (i) o << ",";
        if ((i % 16) == 0) o << "\n";
        o << int(bytes[i]);
    }
    o << "}\nlocal R={";
    for (size_t i = mid; i < bytes.size(); ++i) {
        if (i > mid) o << ",";
        if (((i - mid) % 16) == 0) o << "\n";
        o << int(bytes[i]);
    }
    o << "}\n";

    o << "local function dec()\n";
    o << "local B={} for i=1,#L do B[i]=L[i] end for i=1,#R do B[#L+i]=R[i] end\n";
    o << "do local s=0 for i=1,#B do s+=B[i] end if s~=" << sum << " then error(\"bad sum\") end end\n";
    o << "local seed=" << s << "\n";
    o << "local o={} for i=1,#B do\n";
    o << "local k=bit32.band(seed+(i-1)*131+17,255)\n";
    o << "o[i]=bit32.band(bit32.bxor(B[i],k),255)\n";
    o << "end L,R,B=nil,nil,nil return o end\n";

    o << "local function build(buf)\n";
    o << "local p=1\n";
    o << "local function u8() local v=buf[p] p+=1 return v end\n";
    o << "local function u32() local a=u8() local b=u8() local c=u8() local d=u8()\n";
    o << "return a+b*256+c*65536+d*16777216 end\n";
    o << "local magic=u32() if magic~=0x3252504C then error(\"bad magic\") end\n";
    o << "local bseed=u32() local ver=u8() local nproto=u32() local mainId=u32()\n";
    o << "local P={}\n";
    o << "for pi=1,nproto do\n";
    o << "local maxstack=u8() local nparam=u8() local nups=u8() local isva=u8()\n";
    o << "local ncode=u32() local code={}\n";
    o << "for i=1,ncode do code[i]=u32() end\n";
    o << "local nk=u32() local K={}\n";
    o << "for i=1,nk do\n";
    o << "local t=u8()\n";
    o << "if t==0 then K[i]=nil\n";
    o << "elseif t==1 then K[i]=(u8()~=0)\n";
    o << "elseif t==2 then\n";
    o << "local b0,b1,b2,b3,b4,b5,b6,b7=u8(),u8(),u8(),u8(),u8(),u8(),u8(),u8()\n";
    o << "local ok,num=pcall(function()\n";
    o << "return string.unpack(\"<d\", string.char(b0,b1,b2,b3,b4,b5,b6,b7))\n";
    o << "end)\n";
    o << "K[i]=ok and num or 0\n";
    o << "elseif t==3 then\n";
    o << "local len=u32() local chars={}\n";
    o << "for j=1,len do\n";
    o << "local ch=u8() local key=bit32.band(bseed+(j-1)*13,255)\n";
    o << "chars[j]=string.char(bit32.band(bit32.bxor(ch,key),255))\n";
    o << "end K[i]=table.concat(chars)\n";
    o << "else K[i]=nil end end\n";
    o << "local nc=u32() local ch={}\n";
    o << "for i=1,nc do ch[i]=u32() end\n";
    o << "P[pi]={a=nparam,c=code,k=K,ch=ch,va=isva~=0,ms=maxstack}\n";
    o << "end\n";
    o << "return P,mainId,bseed end\n";

    // inv[0..255] from C++ makeOpcodeMap(seed_) — 0-based logical Op
    o << "local inv={";
    for (int i = 0; i < 256; ++i) {
        if (i) o << ",";
        if ((i % 16) == 0) o << "\n";
        o << inv[i];
    }
    o << "}\n";

    // ---- run() : Op enum matches isa.hpp ----
    // 0 MOVE 1 LOADK 2 LOADNIL 3 LOADBOOL 4 ADD 5 SUB 6 MUL 7 DIV 8 MOD 9 POW
    // 10 UNM 11 NOT 12 LEN 13 CONCAT 14 JMP 15 JMPIF 16 JMPIFNOT 17 EQ 18 LT 19 LE
    // 20 GETGLOBAL 21 SETGLOBAL 22 GETTABLE 23 SETTABLE 24 GETTABLEKS 25 SETTABLEKS
    // 26 NEWTABLE 27 CALL 28 RETURN 29 FORLOOP 30 FORPREP 31 CLOSURE 32 VARARG
    // 33 NAMECALL 34 GETUPVAL 35 SETUPVAL 36 SETLIST 37 FORGLOOP 38 CAPTURE
    // 39 AND 40 OR 41 GETTABLEN 42 SETTABLEN 43 IDIV 44 JUMPXEQ

    o << "local function run(P, mainId, inv, seed)\n";
    o << "local CAP=38\n"; // Op::CAPTURE
    o << "local G={}\n";
    o << "G.print=print G.warn=warn G.error=error G.pcall=pcall G.xpcall=xpcall\n";
    o << "G.typeof=typeof G.type=type G.tostring=tostring G.tonumber=tonumber\n";
    o << "G.pairs=pairs G.ipairs=ipairs G.next=next G.select=select G.unpack=unpack or table.unpack\n";
    o << "G.rawget=rawget G.rawset=rawset G.rawequal=rawequal G.rawlen=rawlen\n";
    o << "G.setmetatable=setmetatable G.getmetatable=getmetatable\n";
    o << "G.bit32=bit32 G.math=math G.string=string G.table=table G.task=task G.utf8=utf8\n";
    o << "G.game=game G.workspace=workspace G.Workspace=workspace G.script=script\n";
    o << "G.Vector2=Vector2 G.Vector3=Vector3 G.CFrame=CFrame G.UDim=UDim G.UDim2=UDim2\n";
    o << "G.Color3=Color3 G.ColorSequence=ColorSequence G.ColorSequenceKeypoint=ColorSequenceKeypoint\n";
    o << "G.NumberSequence=NumberSequence G.NumberSequenceKeypoint=NumberSequenceKeypoint\n";
    o << "G.NumberRange=NumberRange G.Rect=Rect G.Region3=Region3 G.Ray=Ray\n";
    o << "G.BrickColor=BrickColor G.Enum=Enum G.Instance=Instance G.TweenInfo=TweenInfo\n";
    o << "G.os=os G.tick=tick G.time=time G.DateTime=DateTime\n";
    o << "pcall(function() G.Players=game:GetService(\"Players\") end)\n";
    o << "pcall(function() G.RunService=game:GetService(\"RunService\") end)\n";
    o << "pcall(function() G.ReplicatedStorage=game:GetService(\"ReplicatedStorage\") end)\n";
    o << "pcall(function() G.TweenService=game:GetService(\"TweenService\") end)\n";
    o << "pcall(function() G.UserInputService=game:GetService(\"UserInputService\") end)\n";
    o << "pcall(function() G.CoreGui=game:GetService(\"CoreGui\") end)\n";
    o << "pcall(function() G.HttpService=game:GetService(\"HttpService\") end)\n";
    o << "pcall(function() G.CollectionService=game:GetService(\"CollectionService\") end)\n";
    o << "pcall(function() G.ProximityPromptService=game:GetService(\"ProximityPromptService\") end)\n";
    o << "pcall(function() G.GuiService=game:GetService(\"GuiService\") end)\n";
    o << "pcall(function() G.Lighting=game:GetService(\"Lighting\") end)\n";
    o << "pcall(function() G.Debris=game:GetService(\"Debris\") end)\n";
    o << "local RealG=type(_G)==\"table\" and _G or {}\n";
    o << "pcall(function() if getfenv then local e=getfenv(0) if type(e)==\"table\" then RealG=e end end end)\n";
    o << "G._G=RealG G._ENV=RealG\n";
    o << "local E=setmetatable({},{__index=function(_,k)\n";
    o << "local v=rawget(G,k) if v~=nil then return v end\n";
    o << "local ok,r=pcall(function() return RealG[k] end) if ok and r~=nil then return r end\n";
    o << "ok,r=pcall(function() return _G[k] end) if ok then return r end return nil\n";
    o << "end,__newindex=function(_,k,v) rawset(G,k,v) pcall(function() RealG[k]=v end) end})\n";

    o << "local CSNew,NSNew\n";
    o << "pcall(function() CSNew=ColorSequence.new end)\n";
    o << "pcall(function() NSNew=NumberSequence.new end)\n";
    o << "local function onlyKeypoints(t, kind)\n";
    o << "if type(t)~=\"table\" then return t end local out={}\n";
    o << "for i=1,64 do local v=rawget(t,i) if v==nil then break end if typeof(v)==kind then out[#out+1]=v end end\n";
    o << "return #out>0 and out or t end\n";

    o << "local function kn(proto, word)\n";
    o << "if bit32.band(word,0x80000000)~=0 then\n";
    o << "local idx=bit32.band(word,0x7FFFFFFF)+1 return proto.k[idx]\n";
    o << "end\n";
    o << "return word end\n";

    o << "local function exec(pid, args, ups)\n";
    o << "local proto=P[pid+1] if not proto then error(\"bad proto\") end\n";
    o << "local reg={} local top=0\n";
    o << "local nparam=proto.a or 0 local varargs={}\n";
    o << "if args then\n";
    o << "for i=1,nparam do reg[i]=args[i] top=i end\n";
    o << "for i=nparam+1,#args do varargs[#varargs+1]=args[i] end end\n";
    o << "ups=ups or {}\n";
    o << "local function setR(i,v) reg[i]=v if i>top then top=i end end\n";
    o << "local function uvget(i) local u=ups[i] if type(u)==\"table\" and rawget(u,\"__box\")==true then return u[1] end return u end\n";
    o << "local function uvset(i,v) local u=ups[i] if type(u)==\"table\" and rawget(u,\"__box\")==true then u[1]=v else ups[i]=v end end\n";
    o << "local pc=1 local code=proto.c local steps=0\n";
    o << "local lim=" << (watchdog ? "12000000" : "1e15") << "\n";

    o << "while pc<=#code do\n";
    o << "steps+=1 if steps>lim then error(\"watchdog\") end\n";
    o << "local inst=code[pc]\n";
    o << "local rawop=bit32.band(inst,255)\n";
    o << "local op=inv[rawop]\n";
    o << "if op==nil or op<0 then error(\"bad raw op \"..tostring(rawop)..\" pc=\"..pc) end\n";
    o << "local A=bit32.band(bit32.rshift(inst,8),255)\n";
    o << "local B=bit32.band(bit32.rshift(inst,16),255)\n";
    o << "local C=bit32.band(bit32.rshift(inst,24),255)\n";
    o << "local D=bit32.band(bit32.rshift(inst,16),65535) if D>=32768 then D-=65536 end\n";
    o << "local Ra,Rb,Rc=A+1,B+1,C+1\n";

    o << "if op==0 then setR(Ra,reg[Rb])\n";                          // MOVE
    o << "elseif op==1 then pc+=1 setR(Ra,kn(proto,code[pc]))\n";     // LOADK
    o << "elseif op==2 then setR(Ra,nil)\n";                         // LOADNIL
    o << "elseif op==3 then setR(Ra,B~=0)\n";                        // LOADBOOL
    o << "elseif op==4 then setR(Ra,(reg[Rb] or 0)+(reg[Rc] or 0))\n";
    o << "elseif op==5 then setR(Ra,(reg[Rb] or 0)-(reg[Rc] or 0))\n";
    o << "elseif op==6 then setR(Ra,(reg[Rb] or 0)*(reg[Rc] or 0))\n";
    o << "elseif op==7 then setR(Ra,(reg[Rb] or 0)/(reg[Rc] or 1))\n";
    o << "elseif op==8 then setR(Ra,(reg[Rb] or 0)%(reg[Rc] or 1))\n";
    o << "elseif op==9 then setR(Ra,(reg[Rb] or 0)^(reg[Rc] or 1))\n";
    o << "elseif op==10 then setR(Ra,-(reg[Rb] or 0))\n";
    o << "elseif op==11 then setR(Ra,not reg[Rb])\n";
    o << "elseif op==12 then local t=reg[Rb] setR(Ra,type(t)==\"table\" and #t or (type(t)==\"string\" and #t or 0))\n";
    o << "elseif op==13 then local t=\"\" for i=Rb,Rc do t..=tostring(reg[i] or \"\") end setR(Ra,t)\n";
    o << "elseif op==14 then pc+=D\n";
    o << "elseif op==15 then if reg[Ra] then pc+=D end\n";
    o << "elseif op==16 then if not reg[Ra] then pc+=D end\n";
    o << "elseif op==17 then local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end\n";
    o << "elseif op==18 then local ok=(reg[Ra] or 0)<(reg[Rb] or 0) if C~=0 then ok=not ok end if not ok then pc+=1 end\n";
    o << "elseif op==19 then local ok=(reg[Ra] or 0)<=(reg[Rb] or 0) if C~=0 then ok=not ok end if not ok then pc+=1 end\n";
    o << "elseif op==20 then pc+=1 setR(Ra,E[kn(proto,code[pc])])\n";
    o << "elseif op==21 then pc+=1 E[kn(proto,code[pc])]=reg[Ra]\n";
    o << "elseif op==22 then local t=reg[Rb] setR(Ra,t and t[reg[Rc]] or nil)\n";
    o << "elseif op==23 then local t=reg[Rb] if t then t[reg[Rc]]=reg[Ra] end\n";
    o << "elseif op==24 then pc+=1 local t=reg[Rb] local key=kn(proto,code[pc]) setR(Ra,t and t[key] or nil)\n";
    o << "elseif op==25 then pc+=1 local t=reg[Rb] local key=kn(proto,code[pc]) if t then t[key]=reg[Ra] end\n";
    o << "elseif op==26 then setR(Ra,{})\n";
    o << "elseif op==41 then local t=reg[Rb] setR(Ra,t and t[C+1] or nil)\n";
    o << "elseif op==42 then local t=reg[Rb] if t then t[C+1]=reg[Ra] end\n";
    o << "elseif op==34 then setR(Ra,uvget(B+1))\n";
    o << "elseif op==35 then uvset(B+1,reg[Ra])\n";
    o << "elseif op==39 then if reg[Rb] then setR(Ra,reg[Rc]) else setR(Ra,reg[Rb]) end\n";
    o << "elseif op==40 then if reg[Rb] then setR(Ra,reg[Rb]) else setR(Ra,reg[Rc]) end\n";
    o << "elseif op==43 then setR(Ra,math.floor((reg[Rb] or 0)/(reg[Rc] or 1)))\n";

    o << "elseif op==33 then\n"; // NAMECALL
    o << "pc+=1 local key=kn(proto,code[pc]) local obj=reg[Rb]\n";
    o << "setR(Ra+1,obj) setR(Ra,obj and obj[key] or nil)\n";
    o << "if top<Ra+1 then top=Ra+1 end\n";

    o << "elseif op==36 then\n"; // SETLIST
    o << "pc+=1 local start=code[pc] or 1 if type(start)~=\"number\" or start<1 then start=1 end\n";
    o << "local t=reg[Ra] local cnt=B if cnt==0 then cnt=math.max(0,top-Ra) end\n";
    o << "if type(t)==\"table\" then for i=1,cnt do rawset(t,start+i-1,reg[Ra+i]) end end\n";

    o << "elseif op==32 then\n"; // VARARG
    o << "if B==0 then for i=1,#varargs do setR(Ra+i-1,varargs[i]) end top=Ra+#varargs-1 if top<0 then top=0 end\n";
    o << "elseif B==1 then top=math.max(0,Ra-1)\n";
    o << "else local n=B-1 for i=1,n do setR(Ra+i-1,varargs[i]) end top=Ra+n-1 end\n";

    o << "elseif op==27 then\n"; // CALL
    o << "local narg if B==0 then narg=math.max(0,top-Ra) if narg>24 then narg=24 end else narg=B-1 end\n";
    o << "local fn=reg[Ra] local argv={} for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end\n";
    o << "if type(fn)==\"function\" and narg>=1 and type(argv[1])==\"table\" then\n";
    o << "if CSNew and fn==CSNew then argv[1]=onlyKeypoints(argv[1],\"ColorSequenceKeypoint\")\n";
    o << "elseif NSNew and fn==NSNew then argv[1]=onlyKeypoints(argv[1],\"NumberSequenceKeypoint\") end end\n";
    o << "if type(fn)~=\"function\" then error(\"bad call\") end\n";
    o << "local ok,ret=pcall(function() return table.pack(fn(table.unpack(argv,1,math.max(narg,0)))) end)\n";
    o << "if not ok then error(tostring(ret)) end\n";
    o << "if C==0 then for i=1,ret.n do setR(Ra+i-1,ret[i]) end top=Ra+math.max(ret.n,0)-1 if top<0 then top=0 end\n";
    o << "elseif C==1 then top=math.max(0,Ra-1)\n";
    o << "else for i=1,C-1 do setR(Ra+i-1,ret[i]) end top=Ra+(C-1)-1 end\n";

    o << "elseif op==28 then\n"; // RETURN
    o << "local nret=if B==0 then math.max(0,top-Ra+1) else (B-1)\n";
    o << "local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end\n";
    o << "return table.unpack(out,1,math.max(nret,0))\n";

    o << "elseif op==30 then\n"; // FORPREP
    o << "local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1 local idx=tonumber(reg[Ra+2]) or 0\n";
    o << "if (step>=0 and idx>limit) or (step<0 and idx<limit) then pc+=D else setR(Ra+3,idx) end\n";
    o << "elseif op==29 then\n"; // FORLOOP
    o << "local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1\n";
    o << "local idx=(tonumber(reg[Ra+2]) or 0)+step setR(Ra+2,idx)\n";
    o << "if (step>=0 and idx<=limit) or (step<0 and idx>=limit) then setR(Ra+3,idx) pc+=D end\n";

    o << "elseif op==37 then\n"; // FORGLOOP
    o << "local it,state,ctl=reg[Ra],reg[Ra+1],reg[Ra+2]\n";
    o << "if type(it)==\"function\" then\n";
    o << "local ok,res=pcall(function() return table.pack(it(state,ctl)) end)\n";
    o << "if ok and res[1]~=nil then setR(Ra+2,res[1]) for i=1,res.n do setR(Ra+2+i,res[i]) end pc+=D end end\n";

    o << "elseif op==31 then\n"; // CLOSURE
    o << "pc+=1 local child=code[pc] or 0 local cid=proto.ch[child+1] or 0\n";
    o << "local parentReg,parentUps=reg,ups\n";
    o << "if not parentReg.__boxes then parentReg.__boxes={} end local boxes=parentReg.__boxes\n";
    o << "local stored={} local ui=1\n";
    o << "while pc+1<=#code do\n";
    o << "local nextInst=code[pc+1] local rop=bit32.band(nextInst,255)\n";
    o << "local lop=inv[rop]\n";
    o << "if lop~=CAP then break end\n";
    o << "pc+=1\n";
    o << "local ca=bit32.band(bit32.rshift(nextInst,8),255)\n";
    o << "local cb=bit32.band(bit32.rshift(nextInst,16),255)\n";
    o << "if ca==2 then stored[ui]=parentUps[cb+1]\n";
    o << "elseif ca==1 then\n";
    o << "if not boxes[cb] then boxes[cb]={__box=true,parentReg[cb+1]} end stored[ui]=boxes[cb]\n";
    o << "else stored[ui]=parentReg[cb+1] end\n";
    o << "ui+=1 if ui>128 then break end end\n";
    o << "setR(Ra,function(...) return exec(cid,{...},stored) end)\n";

    o << "elseif op==38 then end\n"; // CAPTURE no-op alone
    o << "elseif op==44 then\n"; // JUMPXEQ — treat as EQ + skip helper
    o << "local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end\n";
    o << "else error(\"bad op \"..tostring(op)..\" pc=\"..pc) end\n";
    o << "pc+=1 end end\n";

    o << "return exec(mainId) end\n";

    if (heads == 2) {
        o << "local function __outer()\n";
        o << "local buf=dec()\n";
        o << "local P,mainId,bseed=build(buf)\n";
        o << "return run(P,mainId,inv,bseed)\n";
        o << "end\nreturn __outer()\n";
    } else {
        o << "local buf=dec()\n";
        o << "local P,mainId,bseed=build(buf)\n";
        o << "return run(P,mainId,inv,bseed)\n";
    }

    return o.str();
}

} // namespace Protect