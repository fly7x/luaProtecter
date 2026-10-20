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

// multi-round string seal (encode side helper — must match runtime open)
static void sealStringBytes(std::vector<uint8_t>& b, uint32_t bseed, uint32_t idx) {
    uint32_t st = mix32(bseed ^ (idx * 0x9E3779B9u) ^ 0x51EDC0DEu);
    for (int round = 0; round < 3; ++round) {
        for (size_t j = 0; j < b.size(); ++j) {
            st = mix32(st + uint32_t(b[j]) + uint32_t(j) + uint32_t(round) * 17u);
            uint8_t k = uint8_t(st ^ (st >> 7) ^ (st >> 15) ^ uint8_t((j + 1) * (round + 3)));
            b[j] = uint8_t(b[j] ^ k);
        }
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

    // CFB-style transport
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

    // split inv into 4 slices so one IE= array isn't trivial
    std::ostringstream o;
    o << "--[[\n  ╔══════════════════════════════════════════╗\n"
         "  ║          FŁÝ  ·  FLYX  Protection         ║\n"
         "  ║   Fast-VM  ·  FLY3  ·  anti-lift         ║\n"
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

    // four inv fragments
    o << "local " << hid(20) << "={";
    for (int i = 0; i < 64; ++i) { if (i) o << ","; o << invEnc[i]; }
    o << "}\nlocal " << hid(21) << "={";
    for (int i = 64; i < 128; ++i) { if (i > 64) o << ","; o << invEnc[i]; }
    o << "}\nlocal " << hid(22) << "={";
    for (int i = 128; i < 192; ++i) { if (i > 128) o << ","; o << invEnc[i]; }
    o << "}\nlocal " << hid(23) << "={";
    for (int i = 192; i < 256; ++i) { if (i > 192) o << ","; o << invEnc[i]; }
    o << "}\n";

    // scatter constants (not SUM= SEED=)
    o << "local " << hid(30) << "=" << sum << "\n";
    o << "local " << hid(31) << "=" << s << "\n";
    o << "local " << hid(32) << "=" << invSeal << "\n";

    const std::string q0 = hid(20), q1 = hid(21), q2 = hid(22), q3 = hid(23);
    const std::string vSum = hid(30), vSeed = hid(31), vIsk = hid(32);

    // boot: inlined mix (no function named mx), CFB unseal, rebuild inv from 4 slices
    o << "local function " << nBoot << "()"
         "local e={}local n=0 "
         "for i=1,#" << A << " do n+=1 e[n]=" << A << "[i]end "
         "for i=1,#" << B << " do n+=1 e[n]=" << B << "[i]end "
         "for i=1,#" << C << " do n+=1 e[n]=" << C << "[i]end "
      << A << "," << B << "," << C << "=nil,nil,nil "
         "local a=0 for i=1,#e do local c=e[i] a=bit32.bxor(a+c+bit32.band(bit32.lshift(a,3),0xFFFFFFFF),bit32.rshift(a,5))end "
         "if a~=" << vSum << " then error(\"x\")end "
         "local sd=" << vSeed << " "
         "local st=bit32.bxor(sd,0xA5A5A5A5) "
         "st=bit32.bxor(st,bit32.rshift(st,16))st=bit32.band(st*0x7FEB352D,0xFFFFFFFF)"
         "st=bit32.bxor(st,bit32.rshift(st,15))st=bit32.band(st*0x846CA68B,0xFFFFFFFF)st=bit32.bxor(st,bit32.rshift(st,16)) "
         "local t={} "
         "for i=1,#e do "
         "local k=bit32.band(bit32.bxor(st,bit32.rshift(st,8),bit32.rshift(st,16)),255) "
         "local c=e[i] t[i]=bit32.band(bit32.bxor(c,k),255) "
         "st=st+c+(i-1)*0x9E3779B9+17 "
         "st=bit32.bxor(st,bit32.rshift(st,16))st=bit32.band(st*0x7FEB352D,0xFFFFFFFF)"
         "st=bit32.bxor(st,bit32.rshift(st,15))st=bit32.band(st*0x846CA68B,0xFFFFFFFF)st=bit32.bxor(st,bit32.rshift(st,16)) "
         "end e=nil "
         "local p=1 local function u8()local v=t[p]p+=1 return v end "
         "local function u32()local a=u8()local b=u8()local c=u8()local d=u8()return a+b*256+c*65536+d*16777216 end "
         "local magic=u32() "
         "local bs=bit32.bxor(sd," << vSum << ",0xC0DEC0DE) "
         "bs=bit32.bxor(bs,bit32.rshift(bs,16))bs=bit32.band(bs*0x7FEB352D,0xFFFFFFFF)"
         "bs=bit32.bxor(bs,bit32.rshift(bs,15))bs=bit32.band(bs*0x846CA68B,0xFFFFFFFF)bs=bit32.bxor(bs,bit32.rshift(bs,16)) "
         "local mm=bit32.bxor(bs,0xBADC0FFE) "
         "mm=bit32.bxor(mm,bit32.rshift(mm,16))mm=bit32.band(mm*0x7FEB352D,0xFFFFFFFF)"
         "mm=bit32.bxor(mm,bit32.rshift(mm,15))mm=bit32.band(mm*0x846CA68B,0xFFFFFFFF)mm=bit32.bxor(mm,bit32.rshift(mm,16)) "
         "if bit32.bxor(magic,mm)~=bit32.bxor(" << FLY_MAGIC << ",mm)and bit32.bxor(magic,mm)~=bit32.bxor(0x3252504C,mm)then error(\"x\")end "
         "local bseed=u32()local ver=u8()local nproto=u32()local mainId=u32()local P={} "
         "for pi=1,nproto do "
         "local ms=u8()local np=u8()local nu=u8()local iv=u8()if iv~=0 then iv=1 end "
         "local ncode=u32()local code={} "
         "for i=1,ncode do local w=u32()local r=bit32.band(bseed,7)+1 "
         "w=bit32.bor(bit32.rshift(w,r),bit32.lshift(w,32-r)) "
         "local k=bit32.bxor(bseed,(i-1)*0x9E3779B9) "
         "k=bit32.bxor(k,bit32.lshift(k,13))k=bit32.bxor(k,bit32.rshift(k,17))k=bit32.bxor(k,bit32.lshift(k,5)) "
         "code[i]=bit32.bxor(w,k)end "
         "local nk=u32()local K={} "
         "for i=1,nk do local ty=u8() "
         "if ty==0 then K[i]=nil "
         "elseif ty==1 then K[i]=(u8()~=0) "
         "elseif ty==2 then local b0,b1,b2,b3,b4,b5,b6,b7=u8(),u8(),u8(),u8(),u8(),u8(),u8(),u8() "
         "local ok,num=pcall(function()return string.unpack(\"<d\",string.char(b0,b1,b2,b3,b4,b5,b6,b7))end)K[i]=ok and num or 0 "
         "elseif ty==3 then local len=u32()local bb={}for j=1,len do bb[j]=u8()end K[i]={__s=1,b=bb,i=i} "
         "else K[i]=nil end end "
         "local nc=u32()local ch={}for i=1,nc do ch[i]=u32()end "
         "local csum=0 for i=1,#code do csum=bit32.bxor(csum,code[i])end "
         "P[pi]={a=np,c=code,k=K,ch=ch,va=iv~=0,ms=ms,cs=csum,bs=bseed}end "
         "t=nil "
         "local inv={}local isk=" << vIsk << " "
         "for i=0,63 do inv[i]=bit32.bxor(" << q0 << "[i+1],isk+i*17)-1 end "
         "for i=64,127 do inv[i]=bit32.bxor(" << q1 << "[i-63],isk+i*17)-1 end "
         "for i=128,191 do inv[i]=bit32.bxor(" << q2 << "[i-127],isk+i*17)-1 end "
         "for i=192,255 do inv[i]=bit32.bxor(" << q3 << "[i-191],isk+i*17)-1 end "
      << q0 << "," << q1 << "," << q2 << "," << q3 << "=nil,nil,nil,nil "
         "return P,mainId,inv end\n";

    // multi-round string open (matches heavier seal — NOTE: translator still dual-XOR today;
    // until translator is updated, keep compatible dual path OR update both)
    // For now keep dual-XOR compatible with current translator encodeCustom, but denser:
    o << "local function " << nGo << "(P,mainId,inv)"
         "local CAP=38 "
         "local " << nG << "={print=print,warn=warn,error=error,pcall=pcall,xpcall=xpcall,typeof=typeof,type=type,"
         "tostring=tostring,tonumber=tonumber,pairs=pairs,ipairs=ipairs,next=next,select=select,"
         "unpack=unpack or table.unpack,rawget=rawget,rawset=rawset,rawequal=rawequal,rawlen=rawlen,"
         "setmetatable=setmetatable,getmetatable=getmetatable,bit32=bit32,math=math,string=string,table=table,"
         "task=task,utf8=utf8,game=game,workspace=workspace,Workspace=workspace,script=script,"
         "Vector2=Vector2,Vector3=Vector3,CFrame=CFrame,UDim=UDim,UDim2=UDim2,Color3=Color3,"
         "ColorSequence=ColorSequence,ColorSequenceKeypoint=ColorSequenceKeypoint,"
         "NumberSequence=NumberSequence,NumberSequenceKeypoint=NumberSequenceKeypoint,"
         "NumberRange=NumberRange,Rect=Rect,Region3=Region3,Ray=Ray,BrickColor=BrickColor,"
         "Enum=Enum,Instance=Instance,TweenInfo=TweenInfo,os=os,tick=tick,time=time,DateTime=DateTime} "
         "pcall(function()" << nG << ".Players=game:GetService(\"Players\")end)"
         "pcall(function()" << nG << ".RunService=game:GetService(\"RunService\")end)"
         "pcall(function()" << nG << ".ReplicatedStorage=game:GetService(\"ReplicatedStorage\")end)"
         "pcall(function()" << nG << ".TweenService=game:GetService(\"TweenService\")end)"
         "pcall(function()" << nG << ".UserInputService=game:GetService(\"UserInputService\")end)"
         "pcall(function()" << nG << ".CoreGui=game:GetService(\"CoreGui\")end)"
         "pcall(function()" << nG << ".HttpService=game:GetService(\"HttpService\")end)"
         "pcall(function()" << nG << ".CollectionService=game:GetService(\"CollectionService\")end)"
         "pcall(function()" << nG << ".Lighting=game:GetService(\"Lighting\")end)"
         "pcall(function()" << nG << ".Debris=game:GetService(\"Debris\")end)"
         "local RealG=type(_G)==\"table\"and _G or{} "
         "pcall(function()if getfenv then local e=getfenv(0)if type(e)==\"table\"then RealG=e end end end) "
      << nG << "._G=RealG " << nG << "._ENV=RealG "
         "local " << nE << "=setmetatable({},{__index=function(_,k)local v=rawget(" << nG << ",k)if v~=nil then return v end "
         "local ok,r=pcall(function()return RealG[k]end)if ok and r~=nil then return r end "
         "ok,r=pcall(function()return _G[k]end)if ok then return r end return nil end,"
         "__newindex=function(_,k,v)rawset(" << nG << ",k,v)pcall(function()RealG[k]=v end)end}) "
         "local CSNew,NSNew pcall(function()CSNew=ColorSequence.new end)pcall(function()NSNew=NumberSequence.new end) "
         "local function okp(t,kind)if type(t)~=\"table\"then return t end local o={}for i=1,64 do local v=rawget(t,i)if v==nil then break end if typeof(v)==kind then o[#o+1]=v end end return #o>0 and o or t end ";

    // string open: dual-XOR (translator compatible) + bind cs into key stream so wrong csum → garbage strings
    o << "local function openc(cell,bs,cs)"
         "if type(cell)~=\"table\"or cell.__s~=1 then return cell end "
         "local bb=cell.b if not bb then return\"\"end "
         "local c={}local base=bit32.bxor(bs,cs or 0) "
         "for j=1,#bb do "
         "local ch=bb[j] "
         "local k1=bit32.band(base+(j-1)*13,255) "
         "local k2=bit32.band(bit32.rshift(base,8)+(j-1)*37+91,255) "
         "c[j]=string.char(bit32.band(bit32.bxor(ch,k1,k2),255))end "
         "return table.concat(c)end "
         "local function kn(proto,word)"
         "if bit32.band(word,0x80000000)~=0 then "
         "return openc(proto.k[bit32.band(word,0x7FFFFFFF)+1],proto.bs or 0,proto.cs or 0)end "
         "return word end ";

    // IMPORTANT: translator still encrypts with bseed only (not cs).
    // So for compatibility use bs only in openc until translator is updated:
    // Override: openc uses bs only for now so print still works
    // Re-emit kn with bs only:
    // (patch) use proto.bs only in open to match current encodeCustom

    // Actually fix: use bs only so we don't break constants
    // User said constants work - keep dual key on bseed only

    // Re-do openc without cs in key for compatibility:
    // I'll emit the compatible version in the stream by replacing - the previous openc with cs would break.
    // Simpler: document that translator must use same formula.

    // For THIS file use bseed-only open (current translator):
    // Remove cs from key — already wrote cs version. Emit fix:

    // Override kn to not use cs in key:
    o << "openc=function(cell,bs)if type(cell)~=\"table\"or cell.__s~=1 then return cell end "
         "local bb=cell.b if not bb then return\"\"end local c={} "
         "for j=1,#bb do local ch=bb[j] "
         "local k1=bit32.band(bs+(j-1)*13,255) "
         "local k2=bit32.band(bit32.rshift(bs,8)+(j-1)*37+91,255) "
         "c[j]=string.char(bit32.band(bit32.bxor(ch,k1,k2),255))end return table.concat(c)end "
         "kn=function(proto,word)if bit32.band(word,0x80000000)~=0 then "
         "return openc(proto.k[bit32.band(word,0x7FFFFFFF)+1],proto.bs or 0)end return word end ";

    o << "local function " << nX << "(pid,args,ups)"
         "local proto=P[pid+1]if not proto then error(\"x\")end "
         "local reg={}local top=0 local nparam=proto.a or 0 local varargs={} "
         "if args then for i=1,nparam do reg[i]=args[i]top=i end for i=nparam+1,#args do varargs[#varargs+1]=args[i]end end "
         "ups=ups or{} "
         "local function setR(i,v)reg[i]=v if i>top then top=i end end "
         "local function uvget(i)local u=ups[i]if type(u)==\"table\"and rawget(u,\"__box\")==true then return u[1]end return u end "
         "local function uvset(i,v)local u=ups[i]if type(u)==\"table\"and rawget(u,\"__box\")==true then u[1]=v else ups[i]=v end end "
         "local pc,code,steps,lim,tickchk=1,proto.c,0," << (watchdog ? "12e6" : "1e15") << ",0 "
         "local H={} "
         "H[0]=function(A,B,C,D,Ra,Rb)setR(Ra,reg[Rb])end "
         "H[1]=function(A,B,C,D,Ra)pc+=1 setR(Ra,kn(proto,code[pc]))end "
         "H[2]=function(A,B,C,D,Ra)setR(Ra,nil)end "
         "H[3]=function(A,B,C,D,Ra)setR(Ra,B~=0)end "
         "H[4]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)+(reg[Rc]or 0))end "
         "H[5]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)-(reg[Rc]or 0))end "
         "H[6]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)*(reg[Rc]or 0))end "
         "H[7]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)/(reg[Rc]or 1))end "
         "H[8]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)%(reg[Rc]or 1))end "
         "H[9]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,(reg[Rb]or 0)^(reg[Rc]or 1))end "
         "H[10]=function(A,B,C,D,Ra,Rb)setR(Ra,-(reg[Rb]or 0))end "
         "H[11]=function(A,B,C,D,Ra,Rb)setR(Ra,not reg[Rb])end "
         "H[12]=function(A,B,C,D,Ra,Rb)local t=reg[Rb]setR(Ra,type(t)==\"table\"and #t or(type(t)==\"string\"and #t or 0))end "
         "H[13]=function(A,B,C,D,Ra,Rb,Rc)local t=\"\"for i=Rb,Rc do t..=tostring(reg[i]or\"\")end setR(Ra,t)end "
         "H[14]=function(A,B,C,D)pc+=D end "
         "H[15]=function(A,B,C,D,Ra)if reg[Ra]then pc+=D end end "
         "H[16]=function(A,B,C,D,Ra)if not reg[Ra]then pc+=D end end "
         "H[17]=function(A,B,C,D,Ra,Rb)local ok=(reg[Ra]==reg[Rb])if C~=0 then ok=not ok end if not ok then pc+=1 end end "
         "H[18]=function(A,B,C,D,Ra,Rb)local ok=(reg[Ra]or 0)<(reg[Rb]or 0)if C~=0 then ok=not ok end if not ok then pc+=1 end end "
         "H[19]=function(A,B,C,D,Ra,Rb)local ok=(reg[Ra]or 0)<=(reg[Rb]or 0)if C~=0 then ok=not ok end if not ok then pc+=1 end end "
         "H[20]=function(A,B,C,D,Ra)pc+=1 setR(Ra," << nE << "[kn(proto,code[pc])])end "
         "H[21]=function(A,B,C,D,Ra)pc+=1 " << nE << "[kn(proto,code[pc])]=reg[Ra]end "
         "H[22]=function(A,B,C,D,Ra,Rb,Rc)local t=reg[Rb]setR(Ra,t and t[reg[Rc]]or nil)end "
         "H[23]=function(A,B,C,D,Ra,Rb,Rc)local t=reg[Rb]if t then t[reg[Rc]]=reg[Ra]end end "
         "H[24]=function(A,B,C,D,Ra,Rb)pc+=1 local t=reg[Rb]local key=kn(proto,code[pc])setR(Ra,t and t[key]or nil)end "
         "H[25]=function(A,B,C,D,Ra,Rb)pc+=1 local t=reg[Rb]local key=kn(proto,code[pc])if t then t[key]=reg[Ra]end end "
         "H[26]=function(A,B,C,D,Ra)setR(Ra,{})end "
         "H[41]=function(A,B,C,D,Ra,Rb)local t=reg[Rb]setR(Ra,t and t[C+1]or nil)end "
         "H[42]=function(A,B,C,D,Ra,Rb)local t=reg[Rb]if t then t[C+1]=reg[Ra]end end "
         "H[34]=function(A,B)setR(A+1,uvget(B+1))end "
         "H[35]=function(A,B)uvset(B+1,reg[A+1])end "
         "H[39]=function(A,B,C,D,Ra,Rb,Rc)if reg[Rb]then setR(Ra,reg[Rc])else setR(Ra,reg[Rb])end end "
         "H[40]=function(A,B,C,D,Ra,Rb,Rc)if reg[Rb]then setR(Ra,reg[Rb])else setR(Ra,reg[Rc])end end "
         "H[43]=function(A,B,C,D,Ra,Rb,Rc)setR(Ra,math.floor((reg[Rb]or 0)/(reg[Rc]or 1)))end "
         "H[33]=function(A,B,C,D,Ra,Rb)pc+=1 local key=kn(proto,code[pc])local obj=reg[Rb]setR(Ra+1,obj)setR(Ra,obj and obj[key]or nil)if top<Ra+1 then top=Ra+1 end end "
         "H[36]=function(A,B,C,D,Ra)pc+=1 local start=code[pc]or 1 if type(start)~=\"number\"or start<1 then start=1 end local t=reg[Ra]local cnt=B if cnt==0 then cnt=math.max(0,top-Ra)end if type(t)==\"table\"then for i=1,cnt do rawset(t,start+i-1,reg[Ra+i])end end end "
         "H[32]=function(A,B,C,D,Ra)if B==0 then for i=1,#varargs do setR(Ra+i-1,varargs[i])end top=Ra+#varargs-1 if top<0 then top=0 end elseif B==1 then top=math.max(0,Ra-1)else local n=B-1 for i=1,n do setR(Ra+i-1,varargs[i])end top=Ra+n-1 end end "
         "H[27]=function(A,B,C,D,Ra)local narg if B==0 then narg=math.max(0,top-Ra)if narg>24 then narg=24 end else narg=B-1 end local fn=reg[Ra]local argv={}for i=1,math.max(narg,0)do argv[i]=reg[Ra+i]end "
         "if type(fn)==\"function\"and narg>=1 and type(argv[1])==\"table\"then if CSNew and fn==CSNew then argv[1]=okp(argv[1],\"ColorSequenceKeypoint\")elseif NSNew and fn==NSNew then argv[1]=okp(argv[1],\"NumberSequenceKeypoint\")end end "
         "if type(fn)~=\"function\"then error(\"x\")end local ok,ret=pcall(function()return table.pack(fn(table.unpack(argv,1,math.max(narg,0))))end)if not ok then error(tostring(ret))end "
         "if C==0 then for i=1,ret.n do setR(Ra+i-1,ret[i])end top=Ra+math.max(ret.n,0)-1 if top<0 then top=0 end elseif C==1 then top=math.max(0,Ra-1)else for i=1,C-1 do setR(Ra+i-1,ret[i])end top=Ra+(C-1)-1 end end "
         "H[28]=function(A,B,C,D,Ra)local nret=if B==0 then math.max(0,top-Ra+1)else(B-1)local out={}for i=1,math.max(nret,0)do out[i]=reg[Ra+i-1]end return true,table.pack(table.unpack(out,1,math.max(nret,0)))end "
         "H[30]=function(A,B,C,D,Ra)local limit=tonumber(reg[Ra])or 0 local step=tonumber(reg[Ra+1])or 1 local idx=tonumber(reg[Ra+2])or 0 if(step>=0 and idx>limit)or(step<0 and idx<limit)then pc+=D else setR(Ra+3,idx)end end "
         "H[29]=function(A,B,C,D,Ra)local limit=tonumber(reg[Ra])or 0 local step=tonumber(reg[Ra+1])or 1 local idx=(tonumber(reg[Ra+2])or 0)+step setR(Ra+2,idx)if(step>=0 and idx<=limit)or(step<0 and idx>=limit)then setR(Ra+3,idx)pc+=D end end "
         "H[37]=function(A,B,C,D,Ra)local it,state,ctl=reg[Ra],reg[Ra+1],reg[Ra+2]if type(it)==\"function\"then local ok,res=pcall(function()return table.pack(it(state,ctl))end)if ok and res[1]~=nil then setR(Ra+2,res[1])for i=1,res.n do setR(Ra+2+i,res[i])end pc+=D end end end "
         "H[31]=function(A,B,C,D,Ra)pc+=1 local child=code[pc]or 0 local cid=proto.ch[child+1]or 0 local parentReg,parentUps=reg,ups if not parentReg.__boxes then parentReg.__boxes={}end local boxes=parentReg.__boxes local stored={}local ui=1 "
         "while pc+1<=#code do local ni=code[pc+1]if inv[bit32.band(ni,255)]~=CAP then break end pc+=1 local ca=bit32.band(bit32.rshift(ni,8),255)local cb=bit32.band(bit32.rshift(ni,16),255)"
         "if ca==2 then stored[ui]=parentUps[cb+1]elseif ca==1 then if not boxes[cb]then boxes[cb]={__box=true,parentReg[cb+1]}end stored[ui]=boxes[cb]else stored[ui]=parentReg[cb+1]end ui+=1 if ui>128 then break end end "
         "setR(Ra,function(...)return " << nX << "(cid,{...},stored)end)end "
         "H[38]=function()end H[44]=function(A,B,C,D,Ra,Rb)local ok=(reg[Ra]==reg[Rb])if C~=0 then ok=not ok end if not ok then pc+=1 end end "
         "H[50]=function()end H[51]=function()error(\"x\")end "
         "while pc<=#code do steps+=1 if steps>lim then error(\"x\")end "
         "tickchk+=1 if tickchk>=1536 then tickchk=0 local cs=0 for i=1,#code do cs=bit32.bxor(cs,code[i])end if cs~=proto.cs then error(\"x\")end end "
         "local inst=code[pc]local op=inv[bit32.band(inst,255)]if op==nil or op<0 then error(\"x\")end "
         "local A=bit32.band(bit32.rshift(inst,8),255)local B=bit32.band(bit32.rshift(inst,16),255)local C=bit32.band(bit32.rshift(inst,24),255) "
         "local D=bit32.band(bit32.rshift(inst,16),65535)if D>=32768 then D-=65536 end "
         "local Ra,Rb,Rc=A+1,B+1,C+1 local h=H[op]if not h then error(\"x\")end "
         "local done,pack=h(A,B,C,D,Ra,Rb,Rc)if done then return table.unpack(pack,1,pack.n)end pc+=1 end end "
         "return " << nX << "(mainId)end\n";

    if (heads == 2)
        o << "return(function()local P,mainId,inv=" << nBoot << "()return " << nGo << "(P,mainId,inv)end)()\n";
    else
        o << "local P,mainId,inv=" << nBoot << "()return " << nGo << "(P,mainId,inv)\n";

    return o.str();
}

} // namespace Protect