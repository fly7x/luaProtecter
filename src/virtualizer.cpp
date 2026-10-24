#include "virtualizer.hpp"
#include "isa.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <vector>

namespace Protect {

Virtualizer::Virtualizer(uint32_t seed) : seed_(seed ? seed : 0xA341316Cu) {}

static void decryptBlock(std::vector<uint8_t>& data, uint32_t seed) {
    uint32_t s = seed ^ 0xC2B2AE35u;
    for (size_t i = data.size(); i-- > 0;) {
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
    o.strictEnv = false;
    o.safeParse = true;
    o.dense = true;
    o.watchdog = true;
    o.heads = 2;
    return emitVirtualizedScript(encryptedBlob, o);
}

std::string Virtualizer::emitVirtualizedScript(const Bytecode& encryptedBlob,
                                               const Options& options) const {
    const auto& rawIn = encryptedBlob.data();
    if (rawIn.empty())
        return "return\n";

    std::vector<uint8_t> raw = rawIn;
    if (raw.size() >= 16) {
        uint32_t mag = uint32_t(raw[0]) | (uint32_t(raw[1]) << 8) |
                       (uint32_t(raw[2]) << 16) | (uint32_t(raw[3]) << 24);
        if (mag == FLY_MAGIC || mag == LPR2_MAGIC) {
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

    uint32_t sum2 = 0x811C9DC5u;
    for (size_t i = 0; i < bytes.size(); ++i) {
        sum2 ^= uint32_t(bytes[i]) + uint32_t(i) * 0x01000193u;
        sum2 = mix32(sum2);
    }

    uint32_t fakeSum = mix32(sum ^ 0xBADF00Du);
    uint32_t fakeSum2 = mix32(sum2 ^ 0xC0FFEE);

    size_t n = bytes.size();
    size_t n1 = n / 4, n2 = n / 4, n3 = n / 4, n4 = n - n1 - n2 - n3;

    int heads = (options.heads <= 1) ? 1 : 2;
    bool watchdog = options.watchdog;

    auto map = makeOpcodeMap(s);
    std::array<int, 256> invtbl{};
    for (int i = 0; i < 256; ++i)
        invtbl[static_cast<size_t>(i)] = -1;
    for (size_t logical = 0; logical < map.size(); ++logical)
        invtbl[map[logical]] = int(logical);

    uint32_t bound = mix32(s ^ sum ^ 0xC0DEC0DEu);
    uint32_t invSeal = mix32(bound ^ 0xD00DFEED);
    std::array<int, 256> invEnc{};
    for (int i = 0; i < 256; ++i)
        invEnc[static_cast<size_t>(i)] =
            int(uint32_t(invtbl[static_cast<size_t>(i)] + 1) ^ (invSeal + uint32_t(i) * 17u));

    auto hid = [&](uint32_t tag) {
        uint32_t h = mix32(s ^ sum ^ tag ^ 0x811C9DC5u);
        char buf[16];
        std::snprintf(buf, sizeof(buf), "_%x", h & 0xFFFFFFu);
        return std::string(buf);
    };

    const std::string A = hid(1), B = hid(2), C = hid(3), D = hid(4);
    const std::string Dx = hid(5), Dy = hid(6);
    const std::string nQ0 = hid(20), nQ1 = hid(21), nQ2 = hid(22), nQ3 = hid(23);
    const std::string nSum = hid(30), nSeed = hid(31), nIsk = hid(32), nSum2 = hid(33);
    const std::string nFake1 = hid(34), nFake2 = hid(35);
    const std::string nJoin = hid(40), nDec = hid(41), nParse = hid(42);
    const std::string nEnv = hid(50), nOpen = hid(52), nKn = hid(53);
    const std::string nX = hid(60), nMain = hid(61);
    const std::string nGate = hid(71), nPoison = hid(72), nRT = hid(73);
    const std::string nWm = hid(90);

    uint32_t gateXor = s ^ 0x51EED;
    uint32_t gateArg = s ^ sum;
    uint32_t gateExpect = mix32(gateArg ^ gateXor) & 255u;
    uint32_t buildId = mix32(s ^ sum ^ 0xF1F0F1F0u);

    std::ostringstream o;

    o << "--[[\n"
         "  ╔══════════════════════════════════════════╗\n"
         "  ║          FŁÝ  ·  FLYX  Protection         ║\n"
         "  ║   Custom VM  ·  sealed ISA  ·  dual-head  ║\n"
         "  ║   Build " << std::hex << (buildId & 0xFFFFFFFFu) << std::dec
      << "  ·  do not redistribute      ║\n"
         "  ╚══════════════════════════════════════════╝\n"
         "]]\n";

    o << "local function umul32(a,b)\n"
         "local aL=bit32.band(a,0xFFFF) local aH=bit32.rshift(a,16)\n"
         "local bL=bit32.band(b,0xFFFF) local bH=bit32.rshift(b,16)\n"
         "local lo=aL*bL local mid=aL*bH+aH*bL\n"
         "return bit32.band(lo+bit32.lshift(bit32.band(mid,0xFFFF),16),0xFFFFFFFF)\n"
         "end\n"
         "local function mix32(x)\n"
         "x=bit32.bxor(x,bit32.rshift(x,16))\n"
         "x=umul32(x,0x7FEB352D)\n"
         "x=bit32.bxor(x,bit32.rshift(x,15))\n"
         "x=umul32(x,0x846CA68B)\n"
         "x=bit32.bxor(x,bit32.rshift(x,16))\n"
         "return x\n"
         "end\n";

    o << "local function " << nPoison << "()\n"
         "local t={} for i=1,16 do t[i]=mix32(" << s << "+i)%256 end return t\n"
         "end\n";

    o << "local " << nRT << "=(function()\n"
         "local r=" << (s & 0xFFFF) << "\n"
         "pcall(function() if tick then r=bit32.bxor(r,bit32.band(math.floor(tick()*1e6),0xFFFF)) end end)\n"
         "return bit32.band(r,0xFFFF)\n"
         "end)()\n";

    auto emitArr = [&](const std::string& name, size_t off, size_t len) {
        o << "local " << name << "={";
        for (size_t i = 0; i < len; ++i) {
            if (i) o << ",";
            if (i && (i % 32) == 0) o << "\n";
            o << int(bytes[off + i]);
        }
        o << "}\n";
    };
    auto emitDecoy = [&](const std::string& name, size_t len, uint32_t tag) {
        o << "local " << name << "={";
        for (size_t i = 0; i < len; ++i) {
            if (i) o << ",";
            o << int(mix32(tag + uint32_t(i) * 0x9E3779B9u) & 255u);
        }
        o << "}\n";
    };

    emitArr(A, 0, n1);
    emitDecoy(Dx, (n1 > 8 ? n1 / 2 : 8), s ^ 0x1111);
    emitArr(B, n1, n2);
    emitDecoy(Dy, (n2 > 8 ? n2 / 2 : 8), s ^ 0x2222);
    emitArr(C, n1 + n2, n3);
    emitArr(D, n1 + n2 + n3, n4);

    auto emitInvSlice = [&](const std::string& name, int start) {
        o << "local " << name << "={";
        for (int i = 0; i < 64; ++i) {
            if (i) o << ",";
            o << invEnc[static_cast<size_t>(start + i)];
        }
        o << "}\n";
    };
    emitInvSlice(nQ0, 0);
    emitInvSlice(nQ1, 64);
    emitInvSlice(nQ2, 128);
    emitInvSlice(nQ3, 192);

    o << "local " << nSum << "=" << sum
      << " local " << nSum2 << "=" << sum2
      << " local " << nFake1 << "=" << fakeSum
      << " local " << nFake2 << "=" << fakeSum2
      << " local " << nSeed << "=" << s
      << " local " << nIsk << "=" << invSeal
      << " local " << nWm << "=" << buildId << "\n";

    o << "local function " << nGate << "(x)\n"
         "local v=mix32(bit32.bxor(x or 0," << gateXor << "))\n"
         "return bit32.band(v,255)==" << gateExpect << "\n"
         "end\n";

    o << "local function " << nJoin << "()\n"
         "if not " << nGate << "(" << gateArg << ") then return " << nPoison << "() end\n"
         "local e={} local n=0\n"
         "for i=1,#" << A << " do n+=1 e[n]=" << A << "[i] end\n"
         "for i=1,#" << B << " do n+=1 e[n]=" << B << "[i] end\n"
         "for i=1,#" << C << " do n+=1 e[n]=" << C << "[i] end\n"
         "for i=1,#" << D << " do n+=1 e[n]=" << D << "[i] end\n"
      << A << "," << B << "," << C << "," << D << "=nil,nil,nil,nil\n"
         "local a=0\n"
         "for i=1,#e do local c=e[i] a=bit32.bxor(a+c+bit32.band(bit32.lshift(a,3),0xFFFFFFFF),bit32.rshift(a,5)) end\n"
         "if a~=" << nSum << " then for i=1,#e do e[i]=bit32.band(bit32.bxor(e[i]," << (s & 255) << "),255) end end\n"
         "local b=0x811C9DC5\n"
         "for i=1,#e do b=bit32.bxor(b,e[i]+(i-1)*0x01000193) b=mix32(b) end\n"
         "if b~=" << nSum2 << " then for i=1,#e do e[i]=bit32.band(e[i]+i,255) end end\n"
         "if a==" << nFake1 << " or b==" << nFake2 << " then return " << nPoison << "() end\n"
         "return e\n"
         "end\n";

    o << "local function " << nDec << "(e)\n"
         "if type(e)~=\"table\" or #e<16 then return " << nPoison << "() end\n"
         "local sd=" << nSeed << " local st=mix32(bit32.bxor(sd,0xA5A5A5A5)) local t={}\n"
         "for i=1,#e do\n"
         "local k=bit32.band(bit32.bxor(st,bit32.rshift(st,8),bit32.rshift(st,16)),255)\n"
         "local c=e[i] t[i]=bit32.band(bit32.bxor(c,k),255)\n"
         "st=mix32(st+c+(i-1)*0x9E3779B9+17)\n"
         "end return t\n"
         "end\n";

    o << "local function " << nParse << "(t)\n"
         "if type(t)~=\"table\" then return nil,0,{} end\n"
         "local p=1\n"
         "local function u8() if p>#t then return 0 end local v=t[p] or 0 p+=1 return v end\n"
         "local function u32() return u8()+u8()*256+u8()*65536+u8()*16777216 end\n"
         "local magic=u32()\n"
         "local sd=" << nSeed << " local sm=" << nSum << "\n"
         "local bs=mix32(bit32.bxor(sd,sm,0xC0DEC0DE))\n"
         "local mm=mix32(bit32.bxor(bs,0xBADC0FFE))\n"
         "if bit32.bxor(magic,mm)~=bit32.bxor(" << FLY_MAGIC << ",mm) and bit32.bxor(magic,mm)~=bit32.bxor(" << LPR2_MAGIC
      << ",mm) then return nil,0,{} end\n"
         "local bseed=u32() local ver=u8() local nproto=u32() local mainId=u32()\n"
         "if nproto<1 or nproto>512 or mainId>=nproto then return nil,0,{} end\n"
         "local P={}\n"
         "for pi=1,nproto do\n"
         "local ms=u8() local np=u8() local nu=u8() local iv=u8() if iv~=0 then iv=1 end\n"
         "local ncode=u32()\n"
         "if ncode<1 or ncode>250000 then return nil,0,{} end\n"
         "local code={}\n"
         "for i=1,ncode do\n"
         "local w=u32()\n"
         "local r=bit32.band(bit32.rshift(bseed,3),7)+1\n"
         "w=bit32.bor(bit32.rshift(w,r),bit32.lshift(w,32-r))\n"
         "local k=bit32.bxor(bseed,(i-1)*0x9E3779B9)\n"
         "k=bit32.bxor(k,bit32.lshift(k,13))\n"
         "k=bit32.bxor(k,bit32.rshift(k,17))\n"
         "k=bit32.bxor(k,bit32.lshift(k,5))\n"
         "code[i]=bit32.bxor(w,k)\n"
         "end\n"
         "local nk=u32()\n"
         "if nk>10000 then return nil,0,{} end\n"
         "local K={}\n"
         "for i=1,nk do\n"
         "local ty=u8()\n"
         "if ty==0 then K[i]=nil\n"
         "elseif ty==1 then K[i]=(u8()~=0)\n"
         "elseif ty==2 then\n"
         "local b0,b1,b2,b3,b4,b5,b6,b7=u8(),u8(),u8(),u8(),u8(),u8(),u8(),u8()\n"
         "local ok,num=pcall(function() return string.unpack(\"<d\",string.char(b0,b1,b2,b3,b4,b5,b6,b7)) end)\n"
         "K[i]=ok and num or 0\n"
         "elseif ty==3 then\n"
         "local len=u32()\n"
         "if len>100000 then return nil,0,{} end\n"
         "local bb={} for j=1,len do bb[j]=u8() end\n"
         "K[i]={__s=1,b=bb}\n"
         "else K[i]=nil end\n"
         "end\n"
         "local nc=u32()\n"
         "if nc>512 then return nil,0,{} end\n"
         "local ch={} for i=1,nc do ch[i]=u32() if ch[i]>=nproto then return nil,0,{} end end\n"
         "local csum=0 for i=1,#code do csum=bit32.bxor(csum,code[i]) end\n"
         "P[pi]={a=np,c=code,k=K,ch=ch,va=iv~=0,ms=ms,cs=csum,bs=bseed,nk=nk}\n"
         "end\n"
         "local inv={} local isk=" << nIsk << "\n"
         "for i=0,63 do inv[i]=bit32.bxor(" << nQ0 << "[i+1],isk+i*17)-1 end\n"
         "for i=64,127 do inv[i]=bit32.bxor(" << nQ1 << "[i-63],isk+i*17)-1 end\n"
         "for i=128,191 do inv[i]=bit32.bxor(" << nQ2 << "[i-127],isk+i*17)-1 end\n"
         "for i=192,255 do inv[i]=bit32.bxor(" << nQ3 << "[i-191],isk+i*17)-1 end\n"
      << nQ0 << "," << nQ1 << "," << nQ2 << "," << nQ3 << "=nil,nil,nil,nil\n"
         "return P,mainId,inv\n"
         "end\n";

    o << "local function " << nEnv << "()\n"
         "local G={}\n"
         "G.print=print G.warn=warn G.error=error G.pcall=pcall G.xpcall=xpcall\n"
         "G.typeof=typeof G.type=type G.tostring=tostring G.tonumber=tonumber\n"
         "G.pairs=pairs G.ipairs=ipairs G.next=next G.select=select\n"
         "G.unpack=unpack or table.unpack\n"
         "G.rawget=rawget G.rawset=rawset G.rawequal=rawequal G.rawlen=rawlen\n"
         "G.setmetatable=setmetatable G.getmetatable=getmetatable\n"
         "G.bit32=bit32 G.math=math G.string=string G.table=table G.task=task G.utf8=utf8\n"
         "G.coroutine=coroutine G.os=os G.tick=tick G.time=time G.DateTime=DateTime\n"
         "G.game=game G.workspace=workspace G.Workspace=workspace G.script=script\n"
         "G.Vector2=Vector2 G.Vector3=Vector3 G.CFrame=CFrame G.UDim=UDim G.UDim2=UDim2\n"
         "G.Color3=Color3 G.ColorSequence=ColorSequence G.ColorSequenceKeypoint=ColorSequenceKeypoint\n"
         "G.NumberSequence=NumberSequence G.NumberSequenceKeypoint=NumberSequenceKeypoint\n"
         "G.NumberRange=NumberRange G.Rect=Rect G.Region3=Region3 G.Ray=Ray\n"
         "G.BrickColor=BrickColor G.Enum=Enum G.Instance=Instance G.TweenInfo=TweenInfo\n"
         "G.Random=Random G.require=require G.shared=shared\n"
         "G.loadstring=loadstring or load G.load=load or loadstring\n"
         "pcall(function() G.Players=game:GetService(\"Players\") end)\n"
         "pcall(function() G.RunService=game:GetService(\"RunService\") end)\n"
         "pcall(function() G.ReplicatedStorage=game:GetService(\"ReplicatedStorage\") end)\n"
         "pcall(function() G.TweenService=game:GetService(\"TweenService\") end)\n"
         "pcall(function() G.UserInputService=game:GetService(\"UserInputService\") end)\n"
         "pcall(function() G.CoreGui=game:GetService(\"CoreGui\") end)\n"
         "pcall(function() G.HttpService=game:GetService(\"HttpService\") end)\n"
         "pcall(function() G.CollectionService=game:GetService(\"CollectionService\") end)\n"
         "pcall(function() G.Lighting=game:GetService(\"Lighting\") end)\n"
         "pcall(function() G.Debris=game:GetService(\"Debris\") end)\n"
         "pcall(function()\n"
         "local eg=nil\n"
         "if getgenv then eg=getgenv() end\n"
         "if type(eg)~=\"table\" and getfenv then eg=getfenv(0) end\n"
         "if type(eg)~=\"table\" then eg=_G end\n"
         "if type(eg)==\"table\" then for k,v in pairs(eg) do if rawget(G,k)==nil then rawset(G,k,v) end end end\n"
         "end)\n"
         "pcall(function() if setclipboard then G.setclipboard=setclipboard end end)\n"
         "pcall(function() if getgenv then G.getgenv=getgenv end end)\n"
         "G._G=G G._ENV=G\n"
         "local RealG=type(_G)==\"table\" and _G or {}\n"
         "pcall(function() if getgenv then local e=getgenv() if type(e)==\"table\" then RealG=e end end end)\n"
         "return setmetatable({},{__index=function(_,k)\n"
         "local v=rawget(G,k) if v~=nil then return v end\n"
         "local ok,r=pcall(function() return RealG[k] end) if ok and r~=nil then return r end\n"
         "ok,r=pcall(function() return _G[k] end) if ok then return r end return nil end,\n"
         "__newindex=function(_,k,v) rawset(G,k,v) pcall(function() RealG[k]=v end) end})\nend\n";

    o << "local function " << nOpen << "(cell,bs)\n"
         "if type(cell)~=\"table\" or cell.__s~=1 then return cell end\n"
         "local bb=cell.b if not bb then return \"\" end\n"
         "local c={}\n"
         "for j=1,#bb do\n"
         "local ch=bb[j]\n"
         "local k1=bit32.band(bs+(j-1)*13,255)\n"
         "local k2=bit32.band(bit32.rshift(bs,8)+(j-1)*37+91,255)\n"
         "c[j]=string.char(bit32.band(bit32.bxor(ch,k1,k2),255))\n"
         "end return table.concat(c)\n"
         "end\n";

    o << "local function " << nKn << "(proto,word)\n"
         "if type(word)~=\"number\" then return word end\n"
         "if bit32.band(word,0x80000000)==0 then return word end\n"
         "local raw=bit32.band(word,0x7FFFFFFF)\n"
         "local nK=proto.nk or (proto.k and #proto.k) or 0\n"
         "if raw>=nK then return nil end\n"
         "return " << nOpen << "(proto.k[raw+1],proto.bs or 0)\n"
         "end\n";

    o << "local function " << nX << "(P,inv,E,pid,args,ups)\n"
         "local CAP=38\n"
         "if type(P)~=\"table\" or type(pid)~=\"number\" or pid<0 or pid>=#P then return end\n"
         "local proto=P[pid+1] if not proto then return end\n"
         "local reg={} local top=0 local nparam=proto.a or 0 local varargs={}\n"
         "local maxr=(proto.ms or 32)+8\n"
         "if args then for i=1,nparam do reg[i]=args[i] top=i end\n"
         "for i=nparam+1,#args do varargs[#varargs+1]=args[i] end end\n"
         "ups=ups or {}\n"
         "local function setR(i,v)\n"
         "if i<1 or i>maxr then return end\n"
         "reg[i]=v if i>top then top=i end\n"
         "local bx=reg.__boxes if bx and bx[i] then bx[i][1]=v end\n"
         "end\n"
         "local function uvget(i)\n"
         "local u=ups[i]\n"
         "if type(u)==\"table\" and rawget(u,\"__box\")==true then return u[1] end\n"
         "return u\n"
         "end\n"
         "local function uvset(i,v)\n"
         "local u=ups[i]\n"
         "if type(u)==\"table\" and rawget(u,\"__box\")==true then\n"
         "u[1]=v\n"
         "if type(u.__reg)==\"table\" and type(u.__idx)==\"number\" then\n"
         "u.__reg[u.__idx]=v\n"
         "local pbx=u.__reg.__boxes\n"
         "if pbx and pbx[u.__idx] then pbx[u.__idx][1]=v end\n"
         "end\n"
         "else ups[i]=v end\n"
         "end\n"
         "local pc,code,steps,lim,tickchk=1,proto.c,0," << (watchdog ? "50000000" : "1e15") << ",0\n"
         "local CSNew,NSNew\n"
         "pcall(function() CSNew=ColorSequence.new end)\n"
         "pcall(function() NSNew=NumberSequence.new end)\n"
         "local function okp(t,kind)\n"
         "if type(t)~=\"table\" then return t end local o={}\n"
         "for i=1,64 do local v=rawget(t,i) if v==nil then break end if typeof(v)==kind then o[#o+1]=v end end\n"
         "return #o>0 and o or t end\n"
         "local Z={}\n"
         "Z[0]=function(A,B,C,Dd,Ra,Rb) setR(Ra,reg[Rb]) end\n"
         "Z[1]=function(A,B,C,Dd,Ra) pc+=1 if pc>#code then return end setR(Ra," << nKn << "(proto,code[pc])) end\n"
         "Z[2]=function(A,B,C,Dd,Ra) setR(Ra,nil) end\n"
         "Z[3]=function(A,B,C,Dd,Ra) setR(Ra,B~=0) end\n"
         "Z[4]=function(A,B,C,Dd,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)+(reg[Rc] or 0)) end\n"
         "Z[5]=function(A,B,C,Dd,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)-(reg[Rc] or 0)) end\n"
         "Z[6]=function(A,B,C,Dd,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)*(reg[Rc] or 0)) end\n"
         "Z[7]=function(A,B,C,Dd,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)/(reg[Rc] or 1)) end\n"
         "Z[8]=function(A,B,C,Dd,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)%(reg[Rc] or 1)) end\n"
         "Z[9]=function(A,B,C,Dd,Ra,Rb,Rc) setR(Ra,(reg[Rb] or 0)^(reg[Rc] or 1)) end\n"
         "Z[10]=function(A,B,C,Dd,Ra,Rb) setR(Ra,-(reg[Rb] or 0)) end\n"
         "Z[11]=function(A,B,C,Dd,Ra,Rb) setR(Ra,not reg[Rb]) end\n"
         "Z[12]=function(A,B,C,Dd,Ra,Rb) local t=reg[Rb] setR(Ra,type(t)==\"table\" and #t or (type(t)==\"string\" and #t or 0)) end\n"
         "Z[13]=function(A,B,C,Dd,Ra,Rb,Rc) local t=\"\" for i=Rb,Rc do t..=tostring(reg[i] or \"\") end setR(Ra,t) end\n"
         "Z[14]=function(A,B,C,Dd) pc+=Dd end\n"
         "Z[15]=function(A,B,C,Dd,Ra) if reg[Ra] then pc+=Dd end end\n"
         "Z[16]=function(A,B,C,Dd,Ra) if not reg[Ra] then pc+=Dd end end\n"
         "Z[17]=function(A,B,C,Dd,Ra,Rb) local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end end\n"
         "Z[18]=function(A,B,C,Dd,Ra,Rb) local ok=(reg[Ra] or 0)<(reg[Rb] or 0) if C~=0 then ok=not ok end if not ok then pc+=1 end end\n"
         "Z[19]=function(A,B,C,Dd,Ra,Rb) local ok=(reg[Ra] or 0)<=(reg[Rb] or 0) if C~=0 then ok=not ok end if not ok then pc+=1 end end\n"
         "Z[20]=function(A,B,C,Dd,Ra) pc+=1 if pc>#code then return end setR(Ra,E[" << nKn << "(proto,code[pc])]) end\n"
         "Z[21]=function(A,B,C,Dd,Ra) pc+=1 if pc>#code then return end E[" << nKn << "(proto,code[pc])]=reg[Ra] end\n"
         "Z[22]=function(A,B,C,Dd,Ra,Rb,Rc) local t=reg[Rb] setR(Ra,t and t[reg[Rc]] or nil) end\n"
         "Z[23]=function(A,B,C,Dd,Ra,Rb,Rc) local t=reg[Rb] if t then t[reg[Rc]]=reg[Ra] end end\n"
         "Z[24]=function(A,B,C,Dd,Ra,Rb) pc+=1 if pc>#code then return end local t=reg[Rb] local key=" << nKn << "(proto,code[pc]) setR(Ra,t and t[key] or nil) end\n"
         "Z[25]=function(A,B,C,Dd,Ra,Rb) pc+=1 if pc>#code then return end local t=reg[Rb] local key=" << nKn << "(proto,code[pc]) if t then t[key]=reg[Ra] end end\n"
         "Z[26]=function(A,B,C,Dd,Ra) setR(Ra,{}) end\n"
         "Z[41]=function(A,B,C,Dd,Ra,Rb) local t=reg[Rb] setR(Ra,t and t[C+1] or nil) end\n"
         "Z[42]=function(A,B,C,Dd,Ra,Rb) local t=reg[Rb] if t then t[C+1]=reg[Ra] end end\n"
         "Z[34]=function(A,B) setR(A+1,uvget(B+1)) end\n"
         "Z[35]=function(A,B) uvset(B+1,reg[A+1]) end\n"
         "Z[39]=function(A,B,C,Dd,Ra,Rb,Rc) if reg[Rb] then setR(Ra,reg[Rc]) else setR(Ra,reg[Rb]) end end\n"
         "Z[40]=function(A,B,C,Dd,Ra,Rb,Rc) if reg[Rb] then setR(Ra,reg[Rb]) else setR(Ra,reg[Rc]) end end\n"
         "Z[43]=function(A,B,C,Dd,Ra,Rb,Rc) setR(Ra,math.floor((reg[Rb] or 0)/(reg[Rc] or 1))) end\n"
         "Z[33]=function(A,B,C,Dd,Ra,Rb) pc+=1 if pc>#code then return end local key=" << nKn << "(proto,code[pc]) local obj=reg[Rb] setR(Ra+1,obj) setR(Ra,obj and obj[key] or nil) if top<Ra+1 then top=Ra+1 end end\n"
         "Z[36]=function(A,B,C,Dd,Ra) pc+=1 if pc>#code then return end local start=code[pc] or 1 if type(start)~=\"number\" or start<1 then start=1 end local t=reg[Ra] local cnt=B if cnt==0 then cnt=math.max(0,top-Ra) end if type(t)==\"table\" then for i=1,cnt do rawset(t,start+i-1,reg[Ra+i]) end end end\n"
         "Z[32]=function(A,B,C,Dd,Ra) if B==0 then for i=1,#varargs do setR(Ra+i-1,varargs[i]) end top=Ra+#varargs-1 if top<0 then top=0 end elseif B==1 then top=math.max(0,Ra-1) else local n=B-1 for i=1,n do setR(Ra+i-1,varargs[i]) end top=Ra+n-1 end end\n"
         "Z[27]=function(A,B,C,Dd,Ra)\n"
         "local narg if B==0 then narg=math.max(0,top-Ra) if narg>48 then narg=48 end else narg=B-1 end\n"
         "local fn=reg[Ra] local argv={} for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end\n"
         "if type(fn)==\"function\" and narg>=1 and type(argv[1])==\"table\" then\n"
         "if CSNew and fn==CSNew then argv[1]=okp(argv[1],\"ColorSequenceKeypoint\")\n"
         "elseif NSNew and fn==NSNew then argv[1]=okp(argv[1],\"NumberSequenceKeypoint\") end end\n"
         "if type(fn)~=\"function\" then return end\n"
         "local ok,ret=pcall(function() return table.pack(fn(table.unpack(argv,1,math.max(narg,0)))) end)\n"
         "if not ok then return end\n"
         "if C==0 then for i=1,ret.n do setR(Ra+i-1,ret[i]) end top=Ra+math.max(ret.n,0)-1 if top<0 then top=0 end\n"
         "elseif C==1 then top=math.max(0,Ra-1) else for i=1,C-1 do setR(Ra+i-1,ret[i]) end top=Ra+(C-1)-1 end end\n"
         "Z[28]=function(A,B,C,Dd,Ra) local nret=if B==0 then math.max(0,top-Ra+1) else (B-1) local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end return true,table.pack(table.unpack(out,1,math.max(nret,0))) end\n"
         "Z[30]=function(A,B,C,Dd,Ra) local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1 local idx=tonumber(reg[Ra+2]) or 0 if (step>=0 and idx>limit) or (step<0 and idx<limit) then pc+=Dd else setR(Ra+3,idx) end end\n"
         "Z[29]=function(A,B,C,Dd,Ra) local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1 local idx=(tonumber(reg[Ra+2]) or 0)+step setR(Ra+2,idx) if (step>=0 and idx<=limit) or (step<0 and idx>=limit) then setR(Ra+3,idx) pc+=Dd end end\n"
         // FORGLOOP: table-first ipairs (R[A+1]=table, R[A+2]=index, vars at A+3/A+4)
         "Z[37]=function(A,B,C,Dd,Ra)\n"
         "local gen,state,idx=reg[Ra],reg[Ra+1],reg[Ra+2]\n"
         "if type(state)==\"table\" then\n"
         "local n=tonumber(idx) or 0\n"
         "n=n+1\n"
         "local v=state[n]\n"
         "if v==nil then return end\n"
         "setR(Ra+2,n)\n"
         "setR(Ra+3,n)\n"
         "setR(Ra+4,v)\n"
         "if top<Ra+4 then top=Ra+4 end\n"
         "pc+=Dd\n"
         "return\n"
         "end\n"
         "if type(gen)==\"table\" then\n"
         "local ok,g,s,c=pcall(pairs,gen)\n"
         "if not ok or type(g)~=\"function\" then return end\n"
         "setR(Ra,g) setR(Ra+1,s) setR(Ra+2,c)\n"
         "gen,state,idx=g,s,c\n"
         "end\n"
         "if type(gen)~=\"function\" then return end\n"
         "if idx==nil then idx=0 end\n"
         "local ok,r1,r2,r3,r4=pcall(function() return gen(state,idx) end)\n"
         "if not ok or r1==nil then return end\n"
         "setR(Ra+3,r1)\n"
         "setR(Ra+4,r2)\n"
         "setR(Ra+5,r3)\n"
         "setR(Ra+6,r4)\n"
         "setR(Ra+2,r1)\n"
         "if top<Ra+6 then top=Ra+6 end\n"
         "pc+=Dd\n"
         "end\n"
         "Z[31]=function(A,B,C,Dd,Ra)\n"
         "pc+=1 if pc>#code then return end local child=code[pc] or 0\n"
         "local cid=proto.ch[child+1] or 0\n"
         "if cid<0 or cid>=#P then return end\n"
         "local parentReg,parentUps=reg,ups\n"
         "if not parentReg.__boxes then parentReg.__boxes={} end\n"
         "local stored={} local ui=1\n"
         "while pc+1<=#code do\n"
         "local ni=code[pc+1] if inv[bit32.band(ni,255)]~=CAP then break end pc+=1\n"
         "local ca=bit32.band(bit32.rshift(ni,8),255) local cb=bit32.band(bit32.rshift(ni,16),255)\n"
         "if ca==2 then stored[ui]=parentUps[cb+1]\n"
         "elseif ca==1 then\n"
         "local idx=cb+1 local box=parentReg.__boxes[idx]\n"
         "if not box then box={__box=true,parentReg[idx],__reg=parentReg,__idx=idx} parentReg.__boxes[idx]=box end\n"
         "stored[ui]=box\n"
         "else stored[ui]=parentReg[cb+1] end\n"
         "ui+=1 if ui>128 then break end end\n"
         "setR(Ra,function(...) return " << nX << "(P,inv,E,cid,{...},stored) end) end\n"
         "Z[38]=function() end\n"
         "Z[44]=function(A,B,C,Dd,Ra,Rb) local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end end\n"
         "Z[45]=function() end\n"
         "Z[46]=function(A,B,C,Dd,Ra) pc+=1 if pc>#code then return end setR(Ra,E[" << nKn << "(proto,code[pc])]) end\n"
         "Z[47]=function(A,B,C,Dd,Ra,Rb) local fn=reg[Ra] if type(fn)~=\"function\" then return end local ok,ret=pcall(fn,reg[Rb]) if not ok then return end if C~=0 then setR(Ra,ret) end end\n"
         "while pc<=#code do\n"
         "steps+=1 if steps>lim then return end\n"
         "tickchk+=1 if tickchk>=4096 then tickchk=0 local cs=0 for i=1,#code do cs=bit32.bxor(cs,code[i]) end if cs~=proto.cs then return end end\n"
         "local inst=code[pc]\n"
         "local op=inv[bit32.band(inst,255)]\n"
         "if op==nil or op<0 then return end\n"
         "local A=bit32.band(bit32.rshift(inst,8),255)\n"
         "local B=bit32.band(bit32.rshift(inst,16),255)\n"
         "local C=bit32.band(bit32.rshift(inst,24),255)\n"
         "local Dd=bit32.band(bit32.rshift(inst,16),65535) if Dd>=32768 then Dd-=65536 end\n"
         "local Ra,Rb,Rc=A+1,B+1,C+1\n"
         "local h=Z[op] if not h then return end\n"
         "local done,pack=h(A,B,C,Dd,Ra,Rb,Rc)\n"
         "if done then return table.unpack(pack,1,pack.n) end\n"
         "pc+=1\n"
         "end\n"
         "end\n";

    o << "local function " << nMain << "()\n"
         "local e=" << nJoin << "()\n"
         "local t=" << nDec << "(e) e=nil\n"
         "if type(t)~=\"table\" then return end\n"
         "local P,mainId,inv=" << nParse << "(t) t=nil\n"
         "if type(P)~=\"table\" then return end\n"
         "local E=" << nEnv << "()\n"
         "return " << nX << "(P,inv,E,mainId)\n"
         "end\n";

    if (heads == 2)
        o << "return (function() return " << nMain << "() end)()\n";
    else
        o << "return " << nMain << "()\n";

    return o.str();
}

} // namespace Protect