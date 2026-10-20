#include "virtualizer.hpp"
#include "isa.hpp"

#include <sstream>
#include <vector>
#include <cstdint>
#include <array>
#include <cstdio>

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
    Options o;
    o.strictEnv = true;
    o.safeParse = true;
    return emitVirtualizedScript(encryptedBlob, o);
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& encryptedBlob,
                                               const Options& options) const {
    const auto& rawIn = encryptedBlob.data();
    if (rawIn.empty()) return "error(\"x\")\n";

    std::vector<uint8_t> raw = rawIn;
    if (raw.size() >= 16) {
        uint32_t mag = uint32_t(raw[0]) | (uint32_t(raw[1]) << 8) |
                       (uint32_t(raw[2]) << 16) | (uint32_t(raw[3]) << 24);
        if (mag == FLY_MAGIC || mag == 0x4C50524Fu) {
            uint32_t outerSeed = uint32_t(raw[8]) | (uint32_t(raw[9]) << 8) |
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

    uint32_t s = seed_;
    std::vector<uint8_t> bytes = raw;
    uint32_t st = mix32(s ^ 0xA5A5A5A5u);
    uint32_t sum = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        uint8_t k = uint8_t(st ^ (st >> 8) ^ (st >> 16));
        uint8_t c = uint8_t(bytes[i] ^ k);
        bytes[i] = c;
        st = mix32(st + uint32_t(c) + uint32_t(i) * 0x9E3779B9u + 17u);
        sum = (sum + c + ((sum << 3) & 0xFFFFFFFFu)) ^ (sum >> 5);
    }

    size_t n = bytes.size();
    size_t n1 = n / 3, n2 = n / 3, n3 = n - n1 - n2;
    int heads = (options.heads <= 1) ? 1 : 2;
    bool watchdog = options.watchdog;
    bool strictEnv = options.strictEnv;
    bool safeParse = options.safeParse;

    auto map = makeOpcodeMap(s);
    std::array<int, 256> invtbl{};
    for (int i = 0; i < 256; ++i) invtbl[i] = -1;
    for (size_t logical = 0; logical < map.size(); ++logical)
        invtbl[map[logical]] = int(logical);

    uint32_t bound = mix32(s ^ sum ^ 0xC0DEC0DEu);
    uint32_t invSeal = mix32(bound ^ 0xD00DFEED);
    std::array<int, 256> invEnc{};
    for (int i = 0; i < 256; ++i)
        invEnc[i] = int(uint32_t(invtbl[i] + 1) ^ (invSeal + uint32_t(i) * 17u));

    auto hid = [&](uint32_t tag) {
        uint32_t h = mix32(s ^ sum ^ tag ^ 0x811C9DC5u);
        char buf[16];
        std::snprintf(buf, sizeof(buf), "_%x", h & 0xFFFFFFu);
        return std::string(buf);
    };
    const std::string A = hid(1), B = hid(2), C = hid(3);
    const std::string nBoot = hid(5), nGo = hid(7), nX = hid(8);
    const std::string nE = hid(10), nG = hid(11);
    const std::string q0 = hid(20), q1 = hid(21), q2 = hid(22), q3 = hid(23);
    const std::string vSum = hid(30), vSeed = hid(31), vIsk = hid(32);

    std::ostringstream o;
    o << "--[[\n  ╔══════════════════════════════════════════╗\n"
         "  ║          FŁÝ  ·  FLYX  Protection         ║\n"
         "  ║   Fast-VM  ·  FLY3  ·  safe-parse        ║\n"
         "  ╚══════════════════════════════════════════╝\n]]\n";

    auto emitArr = [&](const std::string& name, size_t off, size_t len) {
        o << "local " << name << "={";
        for (size_t i = 0; i < len; ++i) {
            if (i) o << ",";
            if (i && (i % 24) == 0) o << "\n";
            o << int(bytes[off + i]);
        }
        o << "}\n";
    };
    emitArr(A, 0, n1);
    emitArr(B, n1, n2);
    emitArr(C, n1 + n2, n3);

    o << "local " << q0 << "={";
    for (int i = 0; i < 64; ++i) { if (i) o << ","; o << invEnc[i]; }
    o << "}\nlocal " << q1 << "={";
    for (int i = 64; i < 128; ++i) { if (i > 64) o << ","; o << invEnc[i]; }
    o << "}\nlocal " << q2 << "={";
    for (int i = 128; i < 192; ++i) { if (i > 128) o << ","; o << invEnc[i]; }
    o << "}\nlocal " << q3 << "={";
    for (int i = 192; i < 256; ++i) { if (i > 192) o << ","; o << invEnc[i]; }
    o << "}\n";
    o << "local " << vSum << "=" << sum << " local " << vSeed << "=" << s
      << " local " << vIsk << "=" << invSeal << "\n";

    // --- BOOT with safe-parse caps ---
    o << "local function " << nBoot << "()\n";
    o << "local e={} local n=0\n";
    o << "for i=1,#" << A << " do n+=1 e[n]=" << A << "[i] end\n";
    o << "for i=1,#" << B << " do n+=1 e[n]=" << B << "[i] end\n";
    o << "for i=1,#" << C << " do n+=1 e[n]=" << C << "[i] end\n";
    o << A << "," << B << "," << C << "=nil,nil,nil\n";
    o << "local a=0\n";
    o << "for i=1,#e do local c=e[i] a=bit32.bxor(a+c+bit32.band(bit32.lshift(a,3),0xFFFFFFFF),bit32.rshift(a,5)) end\n";
    o << "if a~=" << vSum << " then error(\"x\") end\n";
    o << "local sd=" << vSeed << "\n";
    o << "local st=bit32.bxor(sd,0xA5A5A5A5)\n";
    o << "st=bit32.bxor(st,bit32.rshift(st,16)) st=bit32.band(st*0x7FEB352D,0xFFFFFFFF)\n";
    o << "st=bit32.bxor(st,bit32.rshift(st,15)) st=bit32.band(st*0x846CA68B,0xFFFFFFFF)\n";
    o << "st=bit32.bxor(st,bit32.rshift(st,16))\n";
    o << "local t={}\n";
    o << "for i=1,#e do\n";
    o << "local k=bit32.band(bit32.bxor(st,bit32.rshift(st,8),bit32.rshift(st,16)),255)\n";
    o << "local c=e[i] t[i]=bit32.band(bit32.bxor(c,k),255)\n";
    o << "st=st+c+(i-1)*0x9E3779B9+17\n";
    o << "st=bit32.bxor(st,bit32.rshift(st,16)) st=bit32.band(st*0x7FEB352D,0xFFFFFFFF)\n";
    o << "st=bit32.bxor(st,bit32.rshift(st,15)) st=bit32.band(st*0x846CA68B,0xFFFFFFFF)\n";
    o << "st=bit32.bxor(st,bit32.rshift(st,16))\n";
    o << "end e=nil\n";
    o << "local p=1\n";
    o << "local function u8()\n";
    if (safeParse) o << "if p>#t then error(\"x\") end\n";
    o << "local v=t[p] p+=1 return v end\n";
    o << "local function u32() return u8()+u8()*256+u8()*65536+u8()*16777216 end\n";
    o << "local magic=u32()\n";
    o << "local bs=bit32.bxor(sd," << vSum << ",0xC0DEC0DE)\n";
    o << "bs=bit32.bxor(bs,bit32.rshift(bs,16)) bs=bit32.band(bs*0x7FEB352D,0xFFFFFFFF)\n";
    o << "bs=bit32.bxor(bs,bit32.rshift(bs,15)) bs=bit32.band(bs*0x846CA68B,0xFFFFFFFF)\n";
    o << "bs=bit32.bxor(bs,bit32.rshift(bs,16))\n";
    o << "local mm=bit32.bxor(bs,0xBADC0FFE)\n";
    o << "mm=bit32.bxor(mm,bit32.rshift(mm,16)) mm=bit32.band(mm*0x7FEB352D,0xFFFFFFFF)\n";
    o << "mm=bit32.bxor(mm,bit32.rshift(mm,15)) mm=bit32.band(mm*0x846CA68B,0xFFFFFFFF)\n";
    o << "mm=bit32.bxor(mm,bit32.rshift(mm,16))\n";
    o << "if bit32.bxor(magic,mm)~=bit32.bxor(" << FLY_MAGIC << ",mm) and bit32.bxor(magic,mm)~=bit32.bxor(0x3252504C,mm) then error(\"x\") end\n";
    o << "local bseed=u32() local ver=u8() local nproto=u32() local mainId=u32()\n";
    if (safeParse) {
        o << "if nproto<1 or nproto>512 then error(\"x\") end\n";
        o << "if mainId>=nproto then error(\"x\") end\n";
    }
    o << "local P={}\n";
    o << "for pi=1,nproto do\n";
    o << "local ms=u8() local np=u8() local nu=u8() local iv=u8() if iv~=0 then iv=1 end\n";
    if (safeParse) {
        o << "if ms>250 or np>200 or nu>128 then error(\"x\") end\n";
    }
    o << "local ncode=u32()\n";
    if (safeParse) o << "if ncode<1 or ncode>250000 then error(\"x\") end\n";
    o << "local code={}\n";
    o << "for i=1,ncode do\n";
    o << "local w=u32()\n";
    o << "local r=bit32.band(bseed,7)+1\n";
    o << "w=bit32.bor(bit32.rshift(w,r),bit32.lshift(w,32-r))\n";
    o << "local k=bit32.bxor(bseed,(i-1)*0x9E3779B9)\n";
    o << "k=bit32.bxor(k,bit32.lshift(k,13)) k=bit32.bxor(k,bit32.rshift(k,17)) k=bit32.bxor(k,bit32.lshift(k,5))\n";
    o << "code[i]=bit32.bxor(w,k)\n";
    o << "end\n";
    o << "local nk=u32()\n";
    if (safeParse) o << "if nk>10000 then error(\"x\") end\n";
    o << "local K={}\n";
    o << "for i=1,nk do\n";
    o << "local ty=u8()\n";
    o << "if ty==0 then K[i]=nil\n";
    o << "elseif ty==1 then K[i]=(u8()~=0)\n";
    o << "elseif ty==2 then\n";
    o << "local b0,b1,b2,b3,b4,b5,b6,b7=u8(),u8(),u8(),u8(),u8(),u8(),u8(),u8()\n";
    o << "local ok,num=pcall(function() return string.unpack(\"<d\",string.char(b0,b1,b2,b3,b4,b5,b6,b7)) end)\n";
    o << "K[i]=ok and num or 0\n";
    o << "elseif ty==3 then\n";
    o << "local len=u32()\n";
    if (safeParse) o << "if len>100000 then error(\"x\") end\n";
    o << "local bb={} for j=1,len do bb[j]=u8() end\n";
    o << "K[i]={__s=1,b=bb}\n";
    o << "else K[i]=nil end\n";
    o << "end\n";
    o << "local nc=u32()\n";
    if (safeParse) o << "if nc>512 then error(\"x\") end\n";
    o << "local ch={} for i=1,nc do ch[i]=u32()\n";
    if (safeParse) o << "if ch[i]>=nproto then error(\"x\") end\n";
    o << "end\n";
    o << "local csum=0 for i=1,#code do csum=bit32.bxor(csum,code[i]) end\n";
    o << "P[pi]={a=np,c=code,k=K,ch=ch,va=iv~=0,ms=ms,cs=csum,bs=bseed,nk=nk}\n";
    o << "end\n";
    o << "t=nil\n";
    o << "local inv={} local isk=" << vIsk << "\n";
    o << "for i=0,63 do inv[i]=bit32.bxor(" << q0 << "[i+1],isk+i*17)-1 end\n";
    o << "for i=64,127 do inv[i]=bit32.bxor(" << q1 << "[i-63],isk+i*17)-1 end\n";
    o << "for i=128,191 do inv[i]=bit32.bxor(" << q2 << "[i-127],isk+i*17)-1 end\n";
    o << "for i=192,255 do inv[i]=bit32.bxor(" << q3 << "[i-191],isk+i*17)-1 end\n";
    o << q0 << "," << q1 << "," << q2 << "," << q3 << "=nil,nil,nil,nil\n";
    o << "return P,mainId,inv\n";
    o << "end\n";

    // --- RUN: strict env + operand checks ---
    o << "local function " << nGo << "(P,mainId,inv)\n";
    o << "local CAP=38\n";
    o << "local " << nG << "={}\n";
    o << "local G=" << nG << "\n";
    o << "G.print=print G.warn=warn G.error=error G.pcall=pcall G.xpcall=xpcall\n";
    o << "G.typeof=typeof G.type=type G.tostring=tostring G.tonumber=tonumber\n";
    o << "G.pairs=pairs G.ipairs=ipairs G.next=next G.select=select\n";
    o << "G.unpack=unpack or table.unpack\n";
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

    if (strictEnv) {
        // Fixed env only — no _G / RealG fallthrough (Claude high priority)
        o << "local " << nE << "=setmetatable({},{__index=function(_,k) return rawget(G,k) end,"
             "__newindex=function(_,k,v) rawset(G,k,v) end})\n";
    } else {
        o << "local RealG=type(_G)==\"table\" and _G or {}\n";
        o << "pcall(function() if getfenv then local e=getfenv(0) if type(e)==\"table\" then RealG=e end end end)\n";
        o << "G._G=RealG G._ENV=RealG\n";
        o << "local " << nE << "=setmetatable({},{__index=function(_,k)\n";
        o << "local v=rawget(G,k) if v~=nil then return v end\n";
        o << "local ok,r=pcall(function() return RealG[k] end) if ok and r~=nil then return r end\n";
        o << "ok,r=pcall(function() return _G[k] end) if ok then return r end return nil end,\n";
        o << "__newindex=function(_,k,v) rawset(G,k,v) end})\n";
    }

    o << "local CSNew,NSNew\n";
    o << "pcall(function() CSNew=ColorSequence.new end)\n";
    o << "pcall(function() NSNew=NumberSequence.new end)\n";
    o << "local function okp(t,kind)\n";
    o << "if type(t)~=\"table\" then return t end local o={}\n";
    o << "for i=1,64 do local v=rawget(t,i) if v==nil then break end if typeof(v)==kind then o[#o+1]=v end end\n";
    o << "return #o>0 and o or t end\n";

    o << "local function openc(cell,bs)\n";
    o << "if type(cell)~=\"table\" or cell.__s~=1 then return cell end\n";
    o << "local bb=cell.b if not bb then return \"\" end\n";
    o << "local c={}\n";
    o << "for j=1,#bb do\n";
    o << "local ch=bb[j]\n";
    o << "local k1=bit32.band(bs+(j-1)*13,255)\n";
    o << "local k2=bit32.band(bit32.rshift(bs,8)+(j-1)*37+91,255)\n";
    o << "c[j]=string.char(bit32.band(bit32.bxor(ch,k1,k2),255))\n";
    o << "end return table.concat(c) end\n";

    o << "local function kn(proto,word)\n";
    o << "if bit32.band(word,0x80000000)~=0 then\n";
    o << "local idx=bit32.band(word,0x7FFFFFFF)+1\n";
    if (safeParse) o << "if idx<1 or idx>(proto.nk or #proto.k) then error(\"x\") end\n";
    o << "return openc(proto.k[idx],proto.bs or 0)\n";
    o << "end return word end\n";

    o << "local function " << nX << "(pid,args,ups)\n";
    if (safeParse) o << "if type(pid)~=\"number\" or pid<0 or pid>=#P then error(\"x\") end\n";
    o << "local proto=P[pid+1] if not proto then error(\"x\") end\n";
    o << "local reg={} local top=0 local nparam=proto.a or 0 local varargs={}\n";
    o << "local maxr=(proto.ms or 32)+8\n";
    o << "if args then for i=1,nparam do reg[i]=args[i] top=i end\n";
    o << "for i=nparam+1,#args do varargs[#varargs+1]=args[i] end end\n";
    o << "ups=ups or {}\n";
    o << "local function setR(i,v)\n";
    if (safeParse) o << "if i<1 or i>maxr then error(\"x\") end\n";
    o << "reg[i]=v if i>top then top=i end end\n";
    o << "local function uvget(i) local u=ups[i] if type(u)==\"table\" and rawget(u,\"__box\")==true then return u[1] end return u end\n";
    o << "local function uvset(i,v) local u=ups[i] if type(u)==\"table\" and rawget(u,\"__box\")==true then u[1]=v else ups[i]=v end end\n";
    o << "local pc,code,steps,lim,tickchk=1,proto.c,0," << (watchdog ? "8000000" : "1e15") << ",0\n";
    o << "local H={}\n";
    o << "H[0]=function(A,B,C,D,Ra,Rb) setR(Ra,reg[Rb]) end\n";
    o << "H[1]=function(A,B,C,D,Ra) pc+=1 if pc>#code then error(\"x\") end setR(Ra,kn(proto,code[pc])) end\n";
    o << "H[2]=function(A,B,C,D,Ra) setR(Ra,nil) end\n";
    o << "H[3]=function(A,B,C,D,Ra) setR(Ra,B~=0) end\n";
    o << "H[4]=function(A,B,C,D,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)+(reg[Rc] or 0)) end\n";
    o << "H[5]=function(A,B,C,D,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)-(reg[Rc] or 0)) end\n";
    o << "H[6]=function(A,B,C,D,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)*(reg[Rc] or 0)) end\n";
    o << "H[7]=function(A,B,C,D,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)/(reg[Rc] or 1)) end\n";
    o << "H[8]=function(A,B,C,D,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)%(reg[Rc] or 1)) end\n";
    o << "H[9]=function(A,B,C,D,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)^(reg[Rc] or 1)) end\n";
    o << "H[10]=function(A,B,C,D,Ra,Rb) setR(Ra,-(reg[Rb] or 0)) end\n";
    o << "H[11]=function(A,B,C,D,Ra,Rb) setR(Ra,not reg[Rb]) end\n";
    o << "H[12]=function(A,B,C,D,Ra,Rb) local t=reg[Rb] setR(Ra,type(t)==\"table\" and #t or (type(t)==\"string\" and #t or 0)) end\n";
    o << "H[13]=function(A,B,C,D,Ra,Rb,Rc) local t=\"\" for i=Rb,Rc do t..=tostring(reg[i] or \"\") end setR(Ra,t) end\n";
    o << "H[14]=function(A,B,C,D) pc+=D end\n";
    o << "H[15]=function(A,B,C,D,Ra) if reg[Ra] then pc+=D end end\n";
    o << "H[16]=function(A,B,C,D,Ra) if not reg[Ra] then pc+=D end end\n";
    o << "H[17]=function(A,B,C,D,Ra,Rb) local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end end\n";
    o << "H[18]=function(A,B,C,D,Ra,Rb) local ok=(reg[Ra] or 0)<(reg[Rb] or 0) if C~=0 then ok=not ok end if not ok then pc+=1 end end\n";
    o << "H[19]=function(A,B,C,D,Ra,Rb) local ok=(reg[Ra] or 0)<=(reg[Rb] or 0) if C~=0 then ok=not ok end if not ok then pc+=1 end end\n";
    o << "H[20]=function(A,B,C,D,Ra) pc+=1 if pc>#code then error(\"x\") end setR(Ra," << nE << "[kn(proto,code[pc])]) end\n";
    o << "H[21]=function(A,B,C,D,Ra) pc+=1 if pc>#code then error(\"x\") end " << nE << "[kn(proto,code[pc])]=reg[Ra] end\n";
    o << "H[22]=function(A,B,C,D,Ra,Rb,Rc) local t=reg[Rb] setR(Ra,t and t[reg[Rc]] or nil) end\n";
    o << "H[23]=function(A,B,C,D,Ra,Rb,Rc) local t=reg[Rb] if t then t[reg[Rc]]=reg[Ra] end end\n";
    o << "H[24]=function(A,B,C,D,Ra,Rb) pc+=1 if pc>#code then error(\"x\") end local t=reg[Rb] local key=kn(proto,code[pc]) setR(Ra,t and t[key] or nil) end\n";
    o << "H[25]=function(A,B,C,D,Ra,Rb) pc+=1 if pc>#code then error(\"x\") end local t=reg[Rb] local key=kn(proto,code[pc]) if t then t[key]=reg[Ra] end end\n";
    o << "H[26]=function(A,B,C,D,Ra) setR(Ra,{}) end\n";
    o << "H[41]=function(A,B,C,D,Ra,Rb) local t=reg[Rb] setR(Ra,t and t[C+1] or nil) end\n";
    o << "H[42]=function(A,B,C,D,Ra,Rb) local t=reg[Rb] if t then t[C+1]=reg[Ra] end end\n";
    o << "H[34]=function(A,B) setR(A+1,uvget(B+1)) end\n";
    o << "H[35]=function(A,B) uvset(B+1,reg[A+1]) end\n";
    o << "H[39]=function(A,B,C,D,Ra,Rb,Rc) if reg[Rb] then setR(Ra,reg[Rc]) else setR(Ra,reg[Rb]) end end\n";
    o << "H[40]=function(A,B,C,D,Ra,Rb,Rc) if reg[Rb] then setR(Ra,reg[Rb]) else setR(Ra,reg[Rc]) end end\n";
    o << "H[43]=function(A,B,C,D,Ra,Rb,Rc) setR(Ra,math.floor((reg[Rb] or 0)/(reg[Rc] or 1))) end\n";
    o << "H[33]=function(A,B,C,D,Ra,Rb) pc+=1 if pc>#code then error(\"x\") end local key=kn(proto,code[pc]) local obj=reg[Rb] setR(Ra+1,obj) setR(Ra,obj and obj[key] or nil) if top<Ra+1 then top=Ra+1 end end\n";
    o << "H[36]=function(A,B,C,D,Ra) pc+=1 if pc>#code then error(\"x\") end local start=code[pc] or 1 if type(start)~=\"number\" or start<1 then start=1 end local t=reg[Ra] local cnt=B if cnt==0 then cnt=math.max(0,top-Ra) end if type(t)==\"table\" then for i=1,cnt do rawset(t,start+i-1,reg[Ra+i]) end end end\n";
    o << "H[32]=function(A,B,C,D,Ra) if B==0 then for i=1,#varargs do setR(Ra+i-1,varargs[i]) end top=Ra+#varargs-1 if top<0 then top=0 end elseif B==1 then top=math.max(0,Ra-1) else local n=B-1 for i=1,n do setR(Ra+i-1,varargs[i]) end top=Ra+n-1 end end\n";
    o << "H[27]=function(A,B,C,D,Ra)\n";
    o << "local narg if B==0 then narg=math.max(0,top-Ra) if narg>24 then narg=24 end else narg=B-1 end\n";
    o << "local fn=reg[Ra] local argv={} for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end\n";
    o << "if type(fn)==\"function\" and narg>=1 and type(argv[1])==\"table\" then\n";
    o << "if CSNew and fn==CSNew then argv[1]=okp(argv[1],\"ColorSequenceKeypoint\")\n";
    o << "elseif NSNew and fn==NSNew then argv[1]=okp(argv[1],\"NumberSequenceKeypoint\") end end\n";
    o << "if type(fn)~=\"function\" then error(\"x\") end\n";
    o << "local ok,ret=pcall(function() return table.pack(fn(table.unpack(argv,1,math.max(narg,0)))) end)\n";
    o << "if not ok then error(tostring(ret)) end\n";
    o << "if C==0 then for i=1,ret.n do setR(Ra+i-1,ret[i]) end top=Ra+math.max(ret.n,0)-1 if top<0 then top=0 end\n";
    o << "elseif C==1 then top=math.max(0,Ra-1) else for i=1,C-1 do setR(Ra+i-1,ret[i]) end top=Ra+(C-1)-1 end end\n";
    o << "H[28]=function(A,B,C,D,Ra) local nret=if B==0 then math.max(0,top-Ra+1) else (B-1) local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end return true,table.pack(table.unpack(out,1,math.max(nret,0))) end\n";
    o << "H[30]=function(A,B,C,D,Ra) local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1 local idx=tonumber(reg[Ra+2]) or 0 if (step>=0 and idx>limit) or (step<0 and idx<limit) then pc+=D else setR(Ra+3,idx) end end\n";
    o << "H[29]=function(A,B,C,D,Ra) local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1 local idx=(tonumber(reg[Ra+2]) or 0)+step setR(Ra+2,idx) if (step>=0 and idx<=limit) or (step<0 and idx>=limit) then setR(Ra+3,idx) pc+=D end end\n";
    o << "H[37]=function(A,B,C,D,Ra) local it,state,ctl=reg[Ra],reg[Ra+1],reg[Ra+2] if type(it)==\"function\" then local ok,res=pcall(function() return table.pack(it(state,ctl)) end) if ok and res[1]~=nil then setR(Ra+2,res[1]) for i=1,res.n do setR(Ra+2+i,res[i]) end pc+=D end end end\n";
    o << "H[31]=function(A,B,C,D,Ra)\n";
    o << "pc+=1 if pc>#code then error(\"x\") end local child=code[pc] or 0\n";
    o << "local cid=proto.ch[child+1] or 0\n";
    if (safeParse) o << "if cid<0 or cid>=#P then error(\"x\") end\n";
    o << "local parentReg,parentUps=reg,ups\n";
    o << "if not parentReg.__boxes then parentReg.__boxes={} end local boxes=parentReg.__boxes\n";
    o << "local stored={} local ui=1\n";
    o << "while pc+1<=#code do\n";
    o << "local ni=code[pc+1] if inv[bit32.band(ni,255)]~=CAP then break end pc+=1\n";
    o << "local ca=bit32.band(bit32.rshift(ni,8),255) local cb=bit32.band(bit32.rshift(ni,16),255)\n";
    o << "if ca==2 then stored[ui]=parentUps[cb+1]\n";
    o << "elseif ca==1 then if not boxes[cb] then boxes[cb]={__box=true,parentReg[cb+1]} end stored[ui]=boxes[cb]\n";
    o << "else stored[ui]=parentReg[cb+1] end ui+=1 if ui>128 then break end end\n";
    o << "setR(Ra,function(...) return " << nX << "(cid,{...},stored) end) end\n";
    o << "H[38]=function() end\n";
    o << "H[44]=function(A,B,C,D,Ra,Rb) local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end end\n";

    o << "while pc<=#code do\n";
    o << "steps+=1 if steps>lim then error(\"x\") end\n";
    o << "tickchk+=1 if tickchk>=1536 then tickchk=0 local cs=0 for i=1,#code do cs=bit32.bxor(cs,code[i]) end if cs~=proto.cs then error(\"x\") end end\n";
    o << "local inst=code[pc]\n";
    o << "local op=inv[bit32.band(inst,255)]\n";
    o << "if op==nil or op<0 then error(\"x\") end\n";
    o << "local A=bit32.band(bit32.rshift(inst,8),255)\n";
    o << "local B=bit32.band(bit32.rshift(inst,16),255)\n";
    o << "local C=bit32.band(bit32.rshift(inst,24),255)\n";
    o << "local D=bit32.band(bit32.rshift(inst,16),65535) if D>=32768 then D-=65536 end\n";
    o << "local Ra,Rb,Rc=A+1,B+1,C+1\n";
    o << "local h=H[op] if not h then error(\"x\") end\n";
    o << "local done,pack=h(A,B,C,D,Ra,Rb,Rc)\n";
    o << "if done then return table.unpack(pack,1,pack.n) end\n";
    o << "pc+=1\n";
    o << "end end\n";
    o << "return " << nX << "(mainId)\n";
    o << "end\n";

    if (heads == 2)
        o << "return (function() local P,mainId,inv=" << nBoot << "() return " << nGo << "(P,mainId,inv) end)()\n";
    else
        o << "local P,mainId,inv=" << nBoot << "() return " << nGo << "(P,mainId,inv)\n";

    return o.str();
}

} // namespace Protect