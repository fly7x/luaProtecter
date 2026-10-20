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
    return emitVirtualizedScript(encryptedBlob, Options{});
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

    // --- chained transport seal (Claude: not pure linear) ---
    // state depends on previous plaintext/ciphertext mix + seed
    std::vector<uint8_t> bytes = raw;
    uint32_t st = mix32(s ^ 0xA5A5A5A5u);
    uint32_t sum = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        st = mix32(st + uint32_t(bytes[i]) + uint32_t(i) * 0x9E3779B9u + 17u);
        uint8_t k = uint8_t(st ^ (st >> 8) ^ (st >> 16));
        bytes[i] = uint8_t(bytes[i] ^ k);
        sum = (sum + bytes[i] + (sum << 3)) ^ (sum >> 5); // stronger integrity mix
    }

    // key material bound to sum so patching checksum without fixing stream fails
    const uint32_t boundSeed = mix32(s ^ sum ^ 0xC0DEC0DEu);

    size_t n = bytes.size();
    size_t n1 = n / 3, n2 = n / 3, n3 = n - n1 - n2;
    int heads = (options.heads <= 1) ? 1 : 2;
    bool watchdog = options.watchdog;

    auto map = makeOpcodeMap(s);
    std::array<int, 256> invtbl{};
    for (int i = 0; i < 256; ++i) invtbl[i] = -1;
    for (size_t logical = 0; logical < map.size(); ++logical)
        invtbl[map[logical]] = int(logical);

    // inv seal also bound to sum
    const uint32_t invSeal = mix32(boundSeed ^ 0xD00DFEED);
    std::array<int, 256> invEnc{};
    for (int i = 0; i < 256; ++i)
        invEnc[i] = int(uint32_t(invtbl[i] + 1) ^ (invSeal + uint32_t(i) * 17u));

    const uint32_t magicMask = mix32(boundSeed ^ 0xBADC0FFEu);
    const uint32_t magicEnc = FLY_MAGIC ^ magicMask;
    const uint32_t magicEncOld = 0x3252504Cu ^ magicMask;

    auto hid = [&](uint32_t tag) {
        uint32_t h = mix32(s ^ tag ^ sum ^ 0x811C9DC5u);
        char buf[16];
        std::snprintf(buf, sizeof(buf), "_%x", h & 0xFFFFFFu);
        return std::string(buf);
    };
    const std::string A = hid(1), B = hid(2), C = hid(3);
    const std::string nBoot = hid(5), nGo = hid(7), nX = hid(8);
    const std::string nOpen = hid(12), nE = hid(10), nG = hid(11);

    std::ostringstream o;
    o << "--[[\n  ╔══════════════════════════════════════════╗\n"
         "  ║          FŁÝ  ·  FLYX  Protection         ║\n"
         "  ║   Fast-VM  ·  FLY3  ·  bound-seal        ║\n"
         "  ╚══════════════════════════════════════════╝\n]]\n";

    auto emitArr = [&](const std::string& name, size_t off, size_t len) {
        o << "local " << name << "={";
        for (size_t i = 0; i < len; ++i) {
            if (i) o << ",";
            if (i && (i % 20) == 0) o << "\n";
            o << int(bytes[off + i]);
        }
        o << "}\n";
    };
    emitArr(A, 0, n1);
    emitArr(B, n1, n2);
    emitArr(C, n1 + n2, n3);

    o << "local _ie={";
    for (int i = 0; i < 256; ++i) {
        if (i) o << ",";
        if ((i % 20) == 0) o << "\n";
        o << invEnc[i];
    }
    o << "}\n";
    o << "local _isk=" << invSeal << " local _mm=" << magicMask
      << " local _me=" << magicEnc << " local _me2=" << magicEncOld
      << " local _sum=" << sum << " local _seed=" << s
      << " local _bs=" << boundSeed << "\n";

    // chained unseal: must recompute same sum; sum folds into later steps
    o << "local function " << nBoot << "()\n"
         "local enc={} local n=0\n"
         "for i=1,#" << A << " do n+=1 enc[n]=" << A << "[i] end\n"
         "for i=1,#" << B << " do n+=1 enc[n]=" << B << "[i] end\n"
         "for i=1,#" << C << " do n+=1 enc[n]=" << C << "[i] end\n"
      << A << "," << B << "," << C << "=nil,nil,nil\n"
         "local acc=0 for i=1,#enc do acc=(acc+enc[i]+bit32.lshift(acc,3)) bit32.bxor(acc,bit32.rshift(acc,5)) end\n"
         // Luau needs proper assignment for acc — fix:
         ;

    // Fix acc loop properly for Luau
    // Rewrite boot more carefully in the stream:

    o.str("");
    o.clear();
    o << "--[[\n  ╔══════════════════════════════════════════╗\n"
         "  ║          FŁÝ  ·  FLYX  Protection         ║\n"
         "  ║   Fast-VM  ·  FLY3  ·  bound-seal        ║\n"
         "  ╚══════════════════════════════════════════╝\n]]\n";
    emitArr(A, 0, n1);
    emitArr(B, n1, n2);
    emitArr(C, n1 + n2, n3);
    o << "local _ie={";
    for (int i = 0; i < 256; ++i) {
        if (i) o << ",";
        if ((i % 20) == 0) o << "\n";
        o << invEnc[i];
    }
    o << "}\nlocal _isk=" << invSeal << " local _mm=" << magicMask
      << " local _me=" << magicEnc << " local _me2=" << magicEncOld
      << " local _sum=" << sum << " local _seed=" << s << "\n";

    // C++-side chained seal must be reversible. Implement matching unseal:
    // For encrypt we used: st = mix(st + bytes[i] + i*const + 17); k = f(st); out = in ^ k
    // Problem: encrypt used plaintext in state before xor — classic CFB-ish.
    // For decrypt: need same order with ciphertext feedback OR plaintext feedback carefully.
    //
    // Encrypt (as written):
    //   st = mix(st + plaintext[i] + i*C + 17); k=f(st); cipher[i]=plain[i]^k
    // Decrypt must recover plain first — chicken and egg.
    //
    // FIX: use ciphertext-feedback for seal:
    //   k = f(st); c = p ^ k; st = mix(st + c + i*C + 17)
    // Decrypt:
    //   k = f(st); p = c ^ k; st = mix(st + c + i*C + 17)

    // Re-seal bytes with CFB-style so runtime can decrypt
    bytes = raw;
    st = mix32(s ^ 0xA5A5A5A5u);
    sum = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        uint8_t k = uint8_t(st ^ (st >> 8) ^ (st >> 16));
        uint8_t c = uint8_t(bytes[i] ^ k);
        bytes[i] = c;
        st = mix32(st + uint32_t(c) + uint32_t(i) * 0x9E3779B9u + 17u);
        sum = (sum + c + ((sum << 3) & 0xFFFFFFFFu)) ^ (sum >> 5);
    }
    // recompute bound materials with new sum
    const uint32_t boundSeed2 = mix32(s ^ sum ^ 0xC0DEC0DEu);
    const uint32_t invSeal2 = mix32(boundSeed2 ^ 0xD00DFEED);
    for (int i = 0; i < 256; ++i)
        invEnc[i] = int(uint32_t(invtbl[i] + 1) ^ (invSeal2 + uint32_t(i) * 17u));
    const uint32_t magicMask2 = mix32(boundSeed2 ^ 0xBADC0FFEu);
    const uint32_t magicEnc2 = FLY_MAGIC ^ magicMask2;
    const uint32_t magicEncOld2 = 0x3252504Cu ^ magicMask2;

    o.str("");
    o.clear();
    o << "--[[\n  ╔══════════════════════════════════════════╗\n"
         "  ║          FŁÝ  ·  FLYX  Protection         ║\n"
         "  ║   Fast-VM  ·  FLY3  ·  bound-seal        ║\n"
         "  ╚══════════════════════════════════════════╝\n]]\n";
    emitArr(A, 0, n1);
    emitArr(B, n1, n2);
    emitArr(C, n1 + n2, n3);
    o << "local _ie={";
    for (int i = 0; i < 256; ++i) {
        if (i) o << ",";
        if ((i % 20) == 0) o << "\n";
        o << invEnc[i];
    }
    o << "}\nlocal _isk=" << invSeal2 << " local _mm=" << magicMask2
      << " local _me=" << magicEnc2 << " local _me2=" << magicEncOld2
      << " local _sum=" << sum << " local _seed=" << s << "\n";

    // mix32 in Luau (same as C++)
    o << "local function _mx(x)x=bit32.bxor(x,bit32.rshift(x,16))x=bit32.band(x*0x7FEB352D,0xFFFFFFFF)"
         "x=bit32.bxor(x,bit32.rshift(x,15))x=bit32.band(x*0x846CA68B,0xFFFFFFFF)"
         "x=bit32.bxor(x,bit32.rshift(x,16))return x end\n";

    o << "local function " << nBoot << "()\n"
         "local enc={}local n=0\n"
         "for i=1,#" << A << " do n+=1 enc[n]=" << A << "[i] end\n"
         "for i=1,#" << B << " do n+=1 enc[n]=" << B << "[i] end\n"
         "for i=1,#" << C << " do n+=1 enc[n]=" << C << "[i] end\n"
      << A << "," << B << "," << C << "=nil,nil,nil\n"
         "local acc=0\n"
         "for i=1,#enc do local c=enc[i] acc=bit32.bxor(acc+c+bit32.band(bit32.lshift(acc,3),0xFFFFFFFF),bit32.rshift(acc,5)) end\n"
         "if acc~=_sum then error(\"x\") end\n"
         // bound seed from sum — if someone patches _sum without re-sealing, inv/magic break
         "local bs=_mx(bit32.bxor(_seed,_sum,0xC0DEC0DE))\n"
         "local st=_mx(bit32.bxor(_seed,0xA5A5A5A5))\n"
         "local t={}\n"
         "for i=1,#enc do\n"
         "local k=bit32.band(bit32.bxor(st,bit32.rshift(st,8),bit32.rshift(st,16)),255)\n"
         "local c=enc[i]\n"
         "t[i]=bit32.band(bit32.bxor(c,k),255)\n"
         "st=_mx(st+c+(i-1)*0x9E3779B9+17)\n"
         "end\n"
         "enc=nil\n"
         "local p=1 local function u8()local v=t[p]p+=1 return v end\n"
         "local function u32()local a=u8()local b=u8()local c=u8()local d=u8()return a+b*256+c*65536+d*16777216 end\n"
         "local magic=u32()\n"
         "local mm=_mx(bit32.bxor(bs,0xBADC0FFE))\n"
         "if bit32.bxor(magic,mm)~=bit32.bxor(" << FLY_MAGIC << ",mm) and bit32.bxor(magic,mm)~=bit32.bxor(0x3252504C,mm) then error(\"x\") end\n"
         "local bseed=u32()local ver=u8()local nproto=u32()local mainId=u32()local P={}\n"
         "for pi=1,nproto do\n"
         "local ms=u8()local np=u8()local nu=u8()local iv=u8()if iv~=0 then iv=1 end\n"
         "local ncode=u32()local code={}\n"
         "for i=1,ncode do\n"
         "local w=u32()local r=bit32.band(bseed,7)+1\n"
         "w=bit32.bor(bit32.rshift(w,r),bit32.lshift(w,32-r))\n"
         "local k=bit32.bxor(bseed,(i-1)*0x9E3779B9)\n"
         "k=bit32.bxor(k,bit32.lshift(k,13))k=bit32.bxor(k,bit32.rshift(k,17))k=bit32.bxor(k,bit32.lshift(k,5))\n"
         "code[i]=bit32.bxor(w,k)\n"
         "end\n"
         "local nk=u32()local K={}\n"
         "for i=1,nk do local ty=u8()\n"
         "if ty==0 then K[i]=nil\n"
         "elseif ty==1 then K[i]=(u8()~=0)\n"
         "elseif ty==2 then\n"
         "local b0,b1,b2,b3,b4,b5,b6,b7=u8(),u8(),u8(),u8(),u8(),u8(),u8(),u8()\n"
         "local ok,num=pcall(function()return string.unpack(\"<d\",string.char(b0,b1,b2,b3,b4,b5,b6,b7))end)\n"
         "K[i]=ok and num or 0\n"
         "elseif ty==3 then local len=u32()local bb={}for j=1,len do bb[j]=u8()end K[i]={__s=1,b=bb}\n"
         "else K[i]=nil end end\n"
         "local nc=u32()local ch={}for i=1,nc do ch[i]=u32()end\n"
         "local csum=0 for i=1,#code do csum=bit32.bxor(csum,code[i])end\n"
         "P[pi]={a=np,c=code,k=K,ch=ch,va=iv~=0,ms=ms,cs=csum,bs=bseed}\n"
         "end\n"
         "t=nil\n"
         // rebuild inv with bound seed so _isk in file must match sum-derived seal
         "local isk=_mx(bit32.bxor(bs,0xD00DFEED))\n"
         "local inv={}\n"
         "for i=0,255 do inv[i]=bit32.bxor(_ie[i+1],isk+i*17)-1 end\n"
         "_ie=nil\n"
         "return P,mainId,bseed,inv end\n";

    o << "local function " << nGo << "(P,mainId,inv)\n"
         "local CAP=38\n"
         "local " << nG << "={print=print,warn=warn,error=error,pcall=pcall,xpcall=xpcall,typeof=typeof,type=type,"
         "tostring=tostring,tonumber=tonumber,pairs=pairs,ipairs=ipairs,next=next,select=select,"
         "unpack=unpack or table.unpack,rawget=rawget,rawset=rawset,rawequal=rawequal,rawlen=rawlen,"
         "setmetatable=setmetatable,getmetatable=getmetatable,bit32=bit32,math=math,string=string,table=table,"
         "task=task,utf8=utf8,game=game,workspace=workspace,Workspace=workspace,script=script,"
         "Vector2=Vector2,Vector3=Vector3,CFrame=CFrame,UDim=UDim,UDim2=UDim2,Color3=Color3,"
         "ColorSequence=ColorSequence,ColorSequenceKeypoint=ColorSequenceKeypoint,"
         "NumberSequence=NumberSequence,NumberSequenceKeypoint=NumberSequenceKeypoint,"
         "NumberRange=NumberRange,Rect=Rect,Region3=Region3,Ray=Ray,BrickColor=BrickColor,"
         "Enum=Enum,Instance=Instance,TweenInfo=TweenInfo,os=os,tick=tick,time=time,DateTime=DateTime}\n"
         "pcall(function()" << nG << ".Players=game:GetService(\"Players\")end)\n"
         "pcall(function()" << nG << ".RunService=game:GetService(\"RunService\")end)\n"
         "pcall(function()" << nG << ".ReplicatedStorage=game:GetService(\"ReplicatedStorage\")end)\n"
         "pcall(function()" << nG << ".TweenService=game:GetService(\"TweenService\")end)\n"
         "pcall(function()" << nG << ".UserInputService=game:GetService(\"UserInputService\")end)\n"
         "pcall(function()" << nG << ".CoreGui=game:GetService(\"CoreGui\")end)\n"
         "pcall(function()" << nG << ".HttpService=game:GetService(\"HttpService\")end)\n"
         "pcall(function()" << nG << ".CollectionService=game:GetService(\"CollectionService\")end)\n"
         "pcall(function()" << nG << ".ProximityPromptService=game:GetService(\"ProximityPromptService\")end)\n"
         "pcall(function()" << nG << ".GuiService=game:GetService(\"GuiService\")end)\n"
         "pcall(function()" << nG << ".Lighting=game:GetService(\"Lighting\")end)\n"
         "pcall(function()" << nG << ".Debris=game:GetService(\"Debris\")end)\n"
         "local RealG=type(_G)==\"table\"and _G or{}\n"
         "pcall(function()if getfenv then local e=getfenv(0)if type(e)==\"table\"then RealG=e end end end)\n"
      << nG << "._G=RealG " << nG << "._ENV=RealG\n"
         "local " << nE << "=setmetatable({},{__index=function(_,k)local v=rawget(" << nG << ",k)if v~=nil then return v end "
         "local ok,r=pcall(function()return RealG[k]end)if ok and r~=nil then return r end "
         "ok,r=pcall(function()return _G[k]end)if ok then return r end return nil end,"
         "__newindex=function(_,k,v)rawset(" << nG << ",k,v)pcall(function()RealG[k]=v end)end})\n"
         "local CSNew,NSNew pcall(function()CSNew=ColorSequence.new end)pcall(function()NSNew=NumberSequence.new end)\n"
         "local function okp(t,kind)if type(t)~=\"table\"then return t end local o={}for i=1,64 do local v=rawget(t,i)if v==nil then break end if typeof(v)==kind then o[#o+1]=v end end return #o>0 and o or t end\n";

    // NO string cache (__c) — decrypt every time, discard (Claude #5)
    o << "local function " << nOpen << "(cell,bs)\n"
         "if type(cell)~=\"table\"or cell.__s~=1 then return cell end\n"
         "local bb=cell.b if not bb then return \"\" end\n"
         "local c={}\n"
         "for j=1,#bb do\n"
         "local ch=bb[j]\n"
         "local k1=bit32.band(bs+(j-1)*13,255)\n"
         "local k2=bit32.band(bit32.rshift(bs,8)+(j-1)*37+91,255)\n"
         "c[j]=string.char(bit32.band(bit32.bxor(ch,k1,k2),255))\n"
         "end\n"
         "return table.concat(c)\n"
         "end\n";

    o << "local function kn(proto,word)\n"
         "if bit32.band(word,0x80000000)~=0 then\n"
         "return " << nOpen << "(proto.k[bit32.band(word,0x7FFFFFFF)+1],proto.bs or 0)\n"
         "end return word end\n";

    o << "local function " << nX << "(pid,args,ups)\n"
         "local proto=P[pid+1]if not proto then error(\"x\")end\n"
         "local reg={}local top=0 local nparam=proto.a or 0 local varargs={}\n"
         "if args then for i=1,nparam do reg[i]=args[i]top=i end for i=nparam+1,#args do varargs[#varargs+1]=args[i]end end\n"
         "ups=ups or{}\n"
         "local function setR(i,v)reg[i]=v if i>top then top=i end end\n"
         "local function uvget(i)local u=ups[i]if type(u)==\"table\"and rawget(u,\"__box\")==true then return u[1]end return u end\n"
         "local function uvset(i,v)local u=ups[i]if type(u)==\"table\"and rawget(u,\"__box\")==true then u[1]=v else ups[i]=v end end\n"
         "local pc,code,steps,lim,tickchk=1,proto.c,0," << (watchdog ? "12e6" : "1e15") << ",0\n"
         "local H={}\n"
         "H[0]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,reg[Rb])end\n"
         "H[1]=function(A,B,C,D,Ra)pc+=1 setR(Ra,kn(proto,code[pc]))end\n"
         "H[2]=function(A,B,C,D,Ra)setR(Ra,nil)end\n"
         "H[3]=function(A,B,C,D,Ra)setR(Ra,B~=0)end\n"
         "H[4]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)+(reg[Rc]or 0))end\n"
         "H[5]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)-(reg[Rc]or 0))end\n"
         "H[6]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)*(reg[Rc]or 0))end\n"
         "H[7]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)/(reg[Rc]or 1))end\n"
         "H[8]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)%(reg[Rc]or 1))end\n"
         "H[9]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)^(reg[Rc]or 1))end\n"
         "H[10]=function(A,B,C,D,Ra,Rb)setR(Ra,-(reg[Rb]or 0))end\n"
         "H[11]=function(A,B,C,D,Ra,Rb)setR(Ra,not reg[Rb])end\n"
         "H[12]=function(A,B,C,D,Ra,Rb)local t=reg[Rb]setR(Ra,type(t)==\"table\"and #t or(type(t)==\"string\"and #t or 0))end\n"
         "H[13]=function(A,B,C,D,Ra,Rb,Rc)local t=\"\"for i=Rb,Rc do t..=tostring(reg[i]or\"\")end setR(Ra,t)end\n"
         "H[14]=function(A,B,C,D)pc+=D end\n"
         "H[15]=function(A,B,C,D,Ra)if reg[Ra]then pc+=D end end\n"
         "H[16]=function(A,B,C,D,Ra)if not reg[Ra]then pc+=D end end\n"
         "H[17]=function(A,B,C,D,Ra,Rb)local ok=(reg[Ra]==reg[Rb])if C~=0 then ok=not ok end if not ok then pc+=1 end end\n"
         "H[18]=function(A,B,C,D,Ra,Rb)local ok=(reg[Ra]or 0)<(reg[Rb]or 0)if C~=0 then ok=not ok end if not ok then pc+=1 end end\n"
         "H[19]=function(A,B,C,D,Ra,Rb)local ok=(reg[Ra]or 0)<=(reg[Rb]or 0)if C~=0 then ok=not ok end if not ok then pc+=1 end end\n"
         "H[20]=function(A,B,C,D,Ra)pc+=1 setR(Ra," << nE << "[kn(proto,code[pc])])end\n"
         "H[21]=function(A,B,C,D,Ra)pc+=1 " << nE << "[kn(proto,code[pc])]=reg[Ra]end\n"
         "H[22]=function(A,B,C,D,Ra,Rb,Rc)local t=reg[Rb]setR(Ra,t and t[reg[Rc]]or nil)end\n"
         "H[23]=function(A,B,C,D,Ra,Rb,Rc)local t=reg[Rb]if t then t[reg[Rc]]=reg[Ra]end end\n"
         "H[24]=function(A,B,C,D,Ra,Rb)pc+=1 local t=reg[Rb]local key=kn(proto,code[pc])setR(Ra,t and t[key]or nil)end\n"
         "H[25]=function(A,B,C,D,Ra,Rb)pc+=1 local t=reg[Rb]local key=kn(proto,code[pc])if t then t[key]=reg[Ra]end end\n"
         "H[26]=function(A,B,C,D,Ra)setR(Ra,{})end\n"
         "H[41]=function(A,B,C,D,Ra,Rb)local t=reg[Rb]setR(Ra,t and t[C+1]or nil)end\n"
         "H[42]=function(A,B,C,D,Ra,Rb)local t=reg[Rb]if t then t[C+1]=reg[Ra]end end\n"
         "H[34]=function(A,B)setR(A+1,uvget(B+1))end\n"
         "H[35]=function(A,B)uvset(B+1,reg[A+1])end\n"
         "H[39]=function(A,B,C,D,Ra,Rb,Rc)if reg[Rb]then setR(Ra,reg[Rc])else setR(Ra,reg[Rb])end end\n"
         "H[40]=function(A,B,C,D,Ra,Rb,Rc)if reg[Rb]then setR(Ra,reg[Rb])else setR(Ra,reg[Rc])end end\n"
         "H[43]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,math.floor((reg[Rb]or 0)/(reg[Rc]or 1)))end\n"
         "H[33]=function(A,B,C,D,Ra,Rb)pc+=1 local key=kn(proto,code[pc])local obj=reg[Rb]setR(Ra+1,obj)setR(Ra,obj and obj[key]or nil)if top<Ra+1 then top=Ra+1 end end\n"
         "H[36]=function(A,B,C,D,Ra)pc+=1 local start=code[pc]or 1 if type(start)~=\"number\"or start<1 then start=1 end local t=reg[Ra]local cnt=B if cnt==0 then cnt=math.max(0,top-Ra)end if type(t)==\"table\"then for i=1,cnt do rawset(t,start+i-1,reg[Ra+i])end end end\n"
         "H[32]=function(A,B,C,D,Ra)if B==0 then for i=1,#varargs do setR(Ra+i-1,varargs[i])end top=Ra+#varargs-1 if top<0 then top=0 end elseif B==1 then top=math.max(0,Ra-1)else local n=B-1 for i=1,n do setR(Ra+i-1,varargs[i])end top=Ra+n-1 end end\n"
         "H[27]=function(A,B,C,D,Ra)local narg if B==0 then narg=math.max(0,top-Ra)if narg>24 then narg=24 end else narg=B-1 end local fn=reg[Ra]local argv={}for i=1,math.max(narg,0)do argv[i]=reg[Ra+i]end "
         "if type(fn)==\"function\"and narg>=1 and type(argv[1])==\"table\"then if CSNew and fn==CSNew then argv[1]=okp(argv[1],\"ColorSequenceKeypoint\")elseif NSNew and fn==NSNew then argv[1]=okp(argv[1],\"NumberSequenceKeypoint\")end end "
         "if type(fn)~=\"function\"then error(\"x\")end local ok,ret=pcall(function()return table.pack(fn(table.unpack(argv,1,math.max(narg,0))))end)if not ok then error(tostring(ret))end "
         "if C==0 then for i=1,ret.n do setR(Ra+i-1,ret[i])end top=Ra+math.max(ret.n,0)-1 if top<0 then top=0 end elseif C==1 then top=math.max(0,Ra-1)else for i=1,C-1 do setR(Ra+i-1,ret[i])end top=Ra+(C-1)-1 end end\n"
         "H[28]=function(A,B,C,D,Ra)local nret=if B==0 then math.max(0,top-Ra+1)else(B-1)local out={}for i=1,math.max(nret,0)do out[i]=reg[Ra+i-1]end return true,table.pack(table.unpack(out,1,math.max(nret,0)))end\n"
         "H[30]=function(A,B,C,D,Ra)local limit=tonumber(reg[Ra])or 0 local step=tonumber(reg[Ra+1])or 1 local idx=tonumber(reg[Ra+2])or 0 if(step>=0 and idx>limit)or(step<0 and idx<limit)then pc+=D else setR(Ra+3,idx)end end\n"
         "H[29]=function(A,B,C,D,Ra)local limit=tonumber(reg[Ra])or 0 local step=tonumber(reg[Ra+1])or 1 local idx=(tonumber(reg[Ra+2])or 0)+step setR(Ra+2,idx)if(step>=0 and idx<=limit)or(step<0 and idx>=limit)then setR(Ra+3,idx)pc+=D end end\n"
         "H[37]=function(A,B,C,D,Ra)local it,state,ctl=reg[Ra],reg[Ra+1],reg[Ra+2]if type(it)==\"function\"then local ok,res=pcall(function()return table.pack(it(state,ctl))end)if ok and res[1]~=nil then setR(Ra+2,res[1])for i=1,res.n do setR(Ra+2+i,res[i])end pc+=D end end end\n"
         "H[31]=function(A,B,C,D,Ra)pc+=1 local child=code[pc]or 0 local cid=proto.ch[child+1]or 0 local parentReg,parentUps=reg,ups if not parentReg.__boxes then parentReg.__boxes={}end local boxes=parentReg.__boxes local stored={}local ui=1 "
         "while pc+1<=#code do local ni=code[pc+1]local rop=bit32.band(ni,255)if inv[rop]~=CAP then break end pc+=1 local ca=bit32.band(bit32.rshift(ni,8),255)local cb=bit32.band(bit32.rshift(ni,16),255)"
         "if ca==2 then stored[ui]=parentUps[cb+1]elseif ca==1 then if not boxes[cb]then boxes[cb]={__box=true,parentReg[cb+1]}end stored[ui]=boxes[cb]else stored[ui]=parentReg[cb+1]end ui+=1 if ui>128 then break end end "
         "setR(Ra,function(...)return " << nX << "(cid,{...},stored)end)end\n"
         "H[38]=function()end\n"
         "H[44]=function(A,B,C,D,Ra,Rb)local ok=(reg[Ra]==reg[Rb])if C~=0 then ok=not ok end if not ok then pc+=1 end end\n"
         // dead handlers (noise)
         "H[50]=function()end H[51]=function()error(\"x\")end H[52]=function()end\n";

    o << "while pc<=#code do\n"
         "steps+=1 if steps>lim then error(\"x\")end\n"
         "tickchk+=1 if tickchk>=1536 then tickchk=0 local cs=0 for i=1,#code do cs=bit32.bxor(cs,code[i])end if cs~=proto.cs then error(\"x\")end end\n"
         "local inst=code[pc]local rawop=bit32.band(inst,255)local op=inv[rawop]\n"
         "if op==nil or op<0 then error(\"x\")end\n"
         "local A=bit32.band(bit32.rshift(inst,8),255)local B=bit32.band(bit32.rshift(inst,16),255)\n"
         "local C=bit32.band(bit32.rshift(inst,24),255)\n"
         "local D=bit32.band(bit32.rshift(inst,16),65535)if D>=32768 then D-=65536 end\n"
         "local Ra,Rb,Rc=A+1,B+1,C+1\n"
         "local h=H[op]if not h then error(\"x\")end\n"
         "local done,pack=h(A,B,C,D,Ra,Rb,Rc)\n"
         "if done then return table.unpack(pack,1,pack.n)end\n"
         "pc+=1\n"
         "end end\n"
         "return " << nX << "(mainId)end\n";

    if (heads == 2)
        o << "return(function()local P,mainId,bseed,inv=" << nBoot << "()return " << nGo << "(P,mainId,inv)end)()\n";
    else
        o << "local P,mainId,bseed,inv=" << nBoot << "()return " << nGo << "(P,mainId,inv)\n";

    return o.str();
}

} // namespace Protect