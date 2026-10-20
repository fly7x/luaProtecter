#include "virtualizer.hpp"
#include "isa.hpp"

#include <sstream>
#include <vector>
#include <cstdint>
#include <array>
#include <cstring>

namespace Protect {

Virtualizer::Virtualizer(uint32_t seed) : seed_(seed ? seed : 0xA341316Cu) {}

static uint32_t mix32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7FEB352Du;
    x ^= x >> 15;
    x *= 0x846CA68Bu;
    x ^= x >> 16;
    return x;
}

// Undo Obfuscator::encryptBlock (pass2 then pass1)
static void decryptBlock(std::vector<uint8_t>& data, uint32_t seed) {
    uint32_t s = seed ^ 0xC2B2AE35u;
    for (size_t i = data.size(); i-- > 0; ) {
        s = mix32(s + uint32_t(i) * 0x85EBCA6Bu);
        uint8_t k = uint8_t(s ^ (s >> 16) ^ uint8_t(i * 47u + 91u));
        data[i] = uint8_t(data[i] ^ k);
    }
    s = seed;
    for (size_t i = 0; i < data.size(); ++i) {
        s = mix32(s + uint32_t(i) + 0x9E3779B9u);
        uint8_t k = uint8_t(s ^ (s >> 8) ^ uint8_t(i * 131u + 17u));
        data[i] = uint8_t(data[i] ^ k);
    }
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& encryptedBlob) const {
    return emitVirtualizedScript(encryptedBlob, Options{});
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& encryptedBlob,
                                               const Options& options) const {
    const auto& rawIn = encryptedBlob.data();
    if (rawIn.empty())
        return "error(\"empty\")\n";

    // Strip obfuscator header if present (MAGIC + ver + seed + size + payload)
    std::vector<uint8_t> raw = rawIn;
    uint32_t outerSeed = seed_;
    if (raw.size() >= 16) {
        uint32_t mag = uint32_t(raw[0]) | (uint32_t(raw[1]) << 8) |
                       (uint32_t(raw[2]) << 16) | (uint32_t(raw[3]) << 24);
        if (mag == FLY_MAGIC || mag == 0x4C50524Fu) {
            outerSeed = uint32_t(raw[8]) | (uint32_t(raw[9]) << 8) |
                        (uint32_t(raw[10]) << 16) | (uint32_t(raw[11]) << 24);
            uint32_t osz = uint32_t(raw[12]) | (uint32_t(raw[13]) << 8) |
                           (uint32_t(raw[14]) << 16) | (uint32_t(raw[15]) << 24);
            if (16 + osz <= raw.size()) {
                std::vector<uint8_t> payload(raw.begin() + 16, raw.begin() + 16 + osz);
                decryptBlock(payload, outerSeed);
                raw = std::move(payload);
            }
        }
    }

    // Optional light seal of whole LPR/FLY blob for split transport
    uint32_t s = seed_;
    std::vector<uint8_t> bytes = raw;
    uint32_t sum = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        uint8_t k = uint8_t((s + uint32_t(i) * 131u + 17u) & 0xFFu);
        bytes[i] = uint8_t(bytes[i] ^ k);
        sum += bytes[i];
    }

    size_t n = bytes.size();
    size_t n1 = n / 3;
    size_t n2 = n / 3;
    size_t n3 = n - n1 - n2;
    int heads = (options.heads <= 1) ? 1 : 2;
    bool watchdog = options.watchdog;

    auto map = makeOpcodeMap(s);
    std::array<int, 256> invtbl{};
    for (int i = 0; i < 256; ++i) invtbl[i] = -1;
    for (size_t logical = 0; logical < map.size(); ++logical)
        invtbl[map[logical]] = int(logical);

    // Scrambled identifiers from seed
    auto id = [&](const char* tag) {
        uint32_t h = s ^ 0x811C9DC5u;
        for (const char* p = tag; *p; ++p) h = (h ^ uint8_t(*p)) * 0x01000193u;
        std::ostringstream ss;
        ss << "_" << std::hex << (h & 0xFFFFFFu);
        return ss.str();
    };
    std::string nDec = id("dec"), nBuild = id("build"), nRun = id("run");
    std::string nExec = id("exec"), nKn = id("kn"), nE = id("E");

    std::ostringstream o;
    o << "--[[\n";
    o << "  ╔══════════════════════════════════════════╗\n";
    o << "  ║          FŁÝ  ·  FLYX  Protection         ║\n";
    o << "  ║   FLY3  ·  sealed ISA  ·  private         ║\n";
    o << "  ╚══════════════════════════════════════════╝\n";
    o << "]]\n";

    auto emitChunk = [&](const char* name, size_t off, size_t len) {
        o << "local " << name << "={";
        for (size_t i = 0; i < len; ++i) {
            if (i) o << ",";
            if ((i % 16) == 0) o << "\n";
            o << int(bytes[off + i]);
        }
        o << "}\n";
    };
    emitChunk("A", 0, n1);
    emitChunk("B", n1, n2);
    emitChunk("C", n1 + n2, n3);

    o << "local function " << nDec << "()\n";
    o << "local t={} local n=0\n";
    o << "for i=1,#A do n+=1 t[n]=A[i] end\n";
    o << "for i=1,#B do n+=1 t[n]=B[i] end\n";
    o << "for i=1,#C do n+=1 t[n]=C[i] end\n";
    o << "do local s=0 for i=1,#t do s+=t[i] end if s~=" << sum << " then error(\"x\") end end\n";
    o << "local seed=" << s << "\n";
    o << "local o={} for i=1,#t do\n";
    o << "local k=bit32.band(seed+(i-1)*131+17,255)\n";
    o << "o[i]=bit32.band(bit32.bxor(t[i],k),255)\n";
    o << "end A,B,C,t=nil,nil,nil,nil return o end\n";

    o << "local function " << nBuild << "(buf)\n";
    o << "local p=1\n";
    o << "local function u8() local v=buf[p] p+=1 return v end\n";
    o << "local function u32() local a=u8() local b=u8() local c=u8() local d=u8()\n";
    o << "return a+b*256+c*65536+d*16777216 end\n";
    o << "local magic=u32()\n";
    o << "if magic~=" << FLY_MAGIC << " and magic~=0x3252504C then error(\"x\") end\n";
    o << "local bseed=u32() local ver=u8() local nproto=u32() local mainId=u32()\n";
    o << "local P={}\n";
    o << "for pi=1,nproto do\n";
    o << "local maxstack=u8() local nparam=u8() local nups=u8() local isva=u8()\n";
    o << "local ncode=u32() local code={}\n";
    o << "for i=1,ncode do\n";
    o << "local w=u32()\n";
    // unsealInsn in Lua
    o << "local r=bit32.band(bseed,7)+1\n";
    o << "w=bit32.bor(bit32.rshift(w,r),bit32.lshift(w,32-r))\n";
    o << "local k=bit32.bxor(bseed,(i-1)*0x9E3779B9)\n";
    o << "k=bit32.bxor(k,bit32.lshift(k,13)) k=bit32.bxor(k,bit32.rshift(k,17)) k=bit32.bxor(k,bit32.lshift(k,5))\n";
    o << "code[i]=bit32.bxor(w,k)\n";
    o << "end\n";
    o << "local nk=u32() local K={}\n";
    o << "for i=1,nk do\n";
    o << "local ty=u8()\n";
    o << "if ty==0 then K[i]=nil\n";
    o << "elseif ty==1 then K[i]=(u8()~=0)\n";
    o << "elseif ty==2 then\n";
    o << "local b0,b1,b2,b3,b4,b5,b6,b7=u8(),u8(),u8(),u8(),u8(),u8(),u8(),u8()\n";
    o << "local ok,num=pcall(function() return string.unpack(\"<d\",string.char(b0,b1,b2,b3,b4,b5,b6,b7)) end)\n";
    o << "K[i]=ok and num or 0\n";
    o << "elseif ty==3 then\n";
    o << "local len=u32() local chars={}\n";
    o << "for j=1,len do\n";
    o << "local ch=u8()\n";
    o << "local k1=bit32.band(bseed+(j-1)*13,255)\n";
    o << "local k2=bit32.band(bit32.rshift(bseed,8)+(j-1)*37+91,255)\n";
    o << "chars[j]=string.char(bit32.band(bit32.bxor(ch,k1,k2),255))\n";
    o << "end K[i]=table.concat(chars)\n";
    o << "else K[i]=nil end end\n";
    o << "local nc=u32() local ch={}\n";
    o << "for i=1,nc do ch[i]=u32() end\n";
    o << "local csum=0 for i=1,#code do csum=bit32.bxor(csum,code[i]) end\n";
    o << "P[pi]={a=nparam,c=code,k=K,ch=ch,va=isva~=0,ms=maxstack,cs=csum}\n";
    o << "end\n";
    o << "return P,mainId,bseed end\n";

    o << "local inv={";
    for (int i = 0; i < 256; ++i) {
        if (i) o << ",";
        if ((i % 16) == 0) o << "\n";
        o << invtbl[i];
    }
    o << "}\n";

    o << "local function " << nRun << "(P, mainId, inv, seed)\n";
    o << "local CAP=38\n";
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
    o << "local " << nE << "=setmetatable({},{__index=function(_,k)\n";
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

    o << "local function " << nKn << "(proto, word)\n";
    o << "if bit32.band(word,0x80000000)~=0 then\n";
    o << "local idx=bit32.band(word,0x7FFFFFFF)+1 return proto.k[idx]\n";
    o << "end return word end\n";

    o << "local function " << nExec << "(pid, args, ups)\n";
    o << "local proto=P[pid+1] if not proto then error(\"x\") end\n";
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
    o << "local tickchk=0\n";

    o << "while pc<=#code do\n";
    o << "steps+=1 if steps>lim then error(\"x\") end\n";
    o << "tickchk+=1\n";
    o << "if tickchk>=2048 then\n";
    o << "tickchk=0 local cs=0 for i=1,#code do cs=bit32.bxor(cs,code[i]) end\n";
    o << "if cs~=proto.cs then error(\"x\") end end\n";
    o << "local inst=code[pc]\n";
    o << "local rawop=bit32.band(inst,255)\n";
    o << "local op=inv[rawop]\n";
    o << "if op==nil or op<0 then error(\"x\") end\n";
    o << "local A=bit32.band(bit32.rshift(inst,8),255)\n";
    o << "local B=bit32.band(bit32.rshift(inst,16),255)\n";
    o << "local C=bit32.band(bit32.rshift(inst,24),255)\n";
    o << "local D=bit32.band(bit32.rshift(inst,16),65535) if D>=32768 then D-=65536 end\n";
    o << "local Ra,Rb,Rc=A+1,B+1,C+1\n";

    // Op handlers match isa.hpp enum
    o << "if op==0 then setR(Ra,reg[Rb])\n";
    o << "elseif op==1 then pc+=1 setR(Ra," << nKn << "(proto,code[pc]))\n";
    o << "elseif op==2 then setR(Ra,nil)\n";
    o << "elseif op==3 then setR(Ra,B~=0)\n";
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
    o << "elseif op==20 then pc+=1 setR(Ra," << nE << "[" << nKn << "(proto,code[pc])])\n";
    o << "elseif op==21 then pc+=1 " << nE << "[" << nKn << "(proto,code[pc])]=reg[Ra]\n";
    o << "elseif op==22 then local t=reg[Rb] setR(Ra,t and t[reg[Rc]] or nil)\n";
    o << "elseif op==23 then local t=reg[Rb] if t then t[reg[Rc]]=reg[Ra] end\n";
    o << "elseif op==24 then pc+=1 local t=reg[Rb] local key=" << nKn << "(proto,code[pc]) setR(Ra,t and t[key] or nil)\n";
    o << "elseif op==25 then pc+=1 local t=reg[Rb] local key=" << nKn << "(proto,code[pc]) if t then t[key]=reg[Ra] end\n";
    o << "elseif op==26 then setR(Ra,{})\n";
    o << "elseif op==41 then local t=reg[Rb] setR(Ra,t and t[C+1] or nil)\n";
    o << "elseif op==42 then local t=reg[Rb] if t then t[C+1]=reg[Ra] end\n";
    o << "elseif op==34 then setR(Ra,uvget(B+1))\n";
    o << "elseif op==35 then uvset(B+1,reg[Ra])\n";
    o << "elseif op==39 then if reg[Rb] then setR(Ra,reg[Rc]) else setR(Ra,reg[Rb]) end\n";
    o << "elseif op==40 then if reg[Rb] then setR(Ra,reg[Rb]) else setR(Ra,reg[Rc]) end\n";
    o << "elseif op==43 then setR(Ra,math.floor((reg[Rb] or 0)/(reg[Rc] or 1)))\n";
    o << "elseif op==33 then\n";
    o << "pc+=1 local key=" << nKn << "(proto,code[pc]) local obj=reg[Rb]\n";
    o << "setR(Ra+1,obj) setR(Ra,obj and obj[key] or nil)\n";
    o << "if top<Ra+1 then top=Ra+1 end\n";
    o << "elseif op==36 then\n";
    o << "pc+=1 local start=code[pc] or 1 if type(start)~=\"number\" or start<1 then start=1 end\n";
    o << "local t=reg[Ra] local cnt=B if cnt==0 then cnt=math.max(0,top-Ra) end\n";
    o << "if type(t)==\"table\" then for i=1,cnt do rawset(t,start+i-1,reg[Ra+i]) end end\n";
    o << "elseif op==32 then\n";
    o << "if B==0 then for i=1,#varargs do setR(Ra+i-1,varargs[i]) end top=Ra+#varargs-1 if top<0 then top=0 end\n";
    o << "elseif B==1 then top=math.max(0,Ra-1)\n";
    o << "else local n=B-1 for i=1,n do setR(Ra+i-1,varargs[i]) end top=Ra+n-1 end\n";
    o << "elseif op==27 then\n";
    o << "local narg if B==0 then narg=math.max(0,top-Ra) if narg>24 then narg=24 end else narg=B-1 end\n";
    o << "local fn=reg[Ra] local argv={} for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end\n";
    o << "if type(fn)==\"function\" and narg>=1 and type(argv[1])==\"table\" then\n";
    o << "if CSNew and fn==CSNew then argv[1]=onlyKeypoints(argv[1],\"ColorSequenceKeypoint\")\n";
    o << "elseif NSNew and fn==NSNew then argv[1]=onlyKeypoints(argv[1],\"NumberSequenceKeypoint\") end end\n";
    o << "if type(fn)~=\"function\" then error(\"x\") end\n";
    o << "local ok,ret=pcall(function() return table.pack(fn(table.unpack(argv,1,math.max(narg,0)))) end)\n";
    o << "if not ok then error(tostring(ret)) end\n";
    o << "if C==0 then for i=1,ret.n do setR(Ra+i-1,ret[i]) end top=Ra+math.max(ret.n,0)-1 if top<0 then top=0 end\n";
    o << "elseif C==1 then top=math.max(0,Ra-1)\n";
    o << "else for i=1,C-1 do setR(Ra+i-1,ret[i]) end top=Ra+(C-1)-1 end\n";
    o << "elseif op==28 then\n";
    o << "local nret=if B==0 then math.max(0,top-Ra+1) else (B-1)\n";
    o << "local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end\n";
    o << "return table.unpack(out,1,math.max(nret,0))\n";
    o << "elseif op==30 then\n";
    o << "local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1 local idx=tonumber(reg[Ra+2]) or 0\n";
    o << "if (step>=0 and idx>limit) or (step<0 and idx<limit) then pc+=D else setR(Ra+3,idx) end\n";
    o << "elseif op==29 then\n";
    o << "local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1\n";
    o << "local idx=(tonumber(reg[Ra+2]) or 0)+step setR(Ra+2,idx)\n";
    o << "if (step>=0 and idx<=limit) or (step<0 and idx>=limit) then setR(Ra+3,idx) pc+=D end\n";
    o << "elseif op==37 then\n";
    o << "local it,state,ctl=reg[Ra],reg[Ra+1],reg[Ra+2]\n";
    o << "if type(it)==\"function\" then\n";
    o << "local ok,res=pcall(function() return table.pack(it(state,ctl)) end)\n";
    o << "if ok and res[1]~=nil then setR(Ra+2,res[1]) for i=1,res.n do setR(Ra+2+i,res[i]) end pc+=D end end\n";
    o << "elseif op==31 then\n";
    o << "pc+=1 local child=code[pc] or 0 local cid=proto.ch[child+1] or 0\n";
    o << "local parentReg,parentUps=reg,ups\n";
    o << "if not parentReg.__boxes then parentReg.__boxes={} end local boxes=parentReg.__boxes\n";
    o << "local stored={} local ui=1\n";
    o << "while pc+1<=#code do\n";
    o << "local nextInst=code[pc+1] local rop=bit32.band(nextInst,255)\n";
    o << "if inv[rop]~=CAP then break end\n";
    o << "pc+=1\n";
    o << "local ca=bit32.band(bit32.rshift(nextInst,8),255)\n";
    o << "local cb=bit32.band(bit32.rshift(nextInst,16),255)\n";
    o << "if ca==2 then stored[ui]=parentUps[cb+1]\n";
    o << "elseif ca==1 then\n";
    o << "if not boxes[cb] then boxes[cb]={__box=true,parentReg[cb+1]} end stored[ui]=boxes[cb]\n";
    o << "else stored[ui]=parentReg[cb+1] end\n";
    o << "ui+=1 if ui>128 then break end end\n";
    o << "setR(Ra,function(...) return " << nExec << "(cid,{...},stored) end)\n";
    o << "elseif op==38 then end\n";
    o << "elseif op==44 then\n";
    o << "local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end\n";
    o << "else error(\"x\") end\n";
    o << "pc+=1 end end\n";
    o << "return " << nExec << "(mainId) end\n";

    if (heads == 2) {
        o << "local function __o()\n";
        o << "local buf=" << nDec << "()\n";
        o << "local P,mainId,bseed=" << nBuild << "(buf)\n";
        o << "return " << nRun << "(P,mainId,inv,bseed)\n";
        o << "end\nreturn __o()\n";
    } else {
        o << "local buf=" << nDec << "()\n";
        o << "local P,mainId,bseed=" << nBuild << "(buf)\n";
        o << "return " << nRun << "(P,mainId,inv,bseed)\n";
    }

    return o.str();
}

} // namespace Protect