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
        return "error('e')\n";

    std::vector<uint8_t> raw = rawIn;
    if (raw.size() >= 16) {
        uint32_t mag = uint32_t(raw[0]) | (uint32_t(raw[1]) << 8) |
                       (uint32_t(raw[2]) << 16) | (uint32_t(raw[3]) << 24);
        if (mag == FLY_MAGIC || mag == 0x4C50524Fu || mag == 0x4C50524Fu) {
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
    uint32_t sum = 0;
    for (size_t i = 0; i < bytes.size(); ++i) {
        uint8_t k = uint8_t((s + uint32_t(i) * 131u + 17u) & 0xFFu);
        bytes[i] = uint8_t(bytes[i] ^ k);
        sum += bytes[i];
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

    auto hid = [&](uint32_t tag) -> std::string {
        uint32_t h = mix32(s ^ tag ^ 0x811C9DC5u);
        char buf[16];
        std::snprintf(buf, sizeof(buf), "_%x", h & 0xFFFFFFu);
        return buf;
    };
    const std::string n0 = hid(1), n1s = hid(2), n2s = hid(3), n3s = hid(4);
    const std::string nD = hid(5), nB = hid(6), nR = hid(7), nX = hid(8);
    const std::string nK = hid(9), nE = hid(10), nG = hid(11);

    std::ostringstream o;
    // dense: almost no whitespace / comments
    o << "local " << n1s << "={";
    for (size_t i = 0; i < n1; ++i) { if (i) o << ","; o << int(bytes[i]); }
    o << "}local " << n2s << "={";
    for (size_t i = 0; i < n2; ++i) { if (i) o << ","; o << int(bytes[n1 + i]); }
    o << "}local " << n3s << "={";
    for (size_t i = 0; i < n3; ++i) { if (i) o << ","; o << int(bytes[n1 + n2 + i]); }
    o << "}";

    o << "local function " << nD << "()local t={}local n=0 for i=1,#" << n1s
      << " do n+=1 t[n]=" << n1s << "[i]end for i=1,#" << n2s << " do n+=1 t[n]="
      << n2s << "[i]end for i=1,#" << n3s << " do n+=1 t[n]=" << n3s
      << "[i]end do local s=0 for i=1,#t do s+=t[i]end if s~=" << sum
      << " then error('e')end end local seed=" << s
      << " local o={} for i=1,#t do local k=bit32.band(seed+(i-1)*131+17,255)"
         " o[i]=bit32.band(bit32.bxor(t[i],k),255)end "
      << n1s << "," << n2s << "," << n3s << ",t=nil,nil,nil,nil return o end";

    o << "local function " << nB << "(buf)local p=1 local function u8()local v=buf[p]p+=1 return v end "
         "local function u32()local a=u8()local b=u8()local c=u8()local d=u8()return a+b*256+c*65536+d*16777216 end "
         "local magic=u32() if magic~=" << FLY_MAGIC << " and magic~=0x3252504C then error('e')end "
         "local bseed=u32() local ver=u8() local nproto=u32() local mainId=u32() local P={} "
         "for pi=1,nproto do local ms=u8() local np=u8() local nu=u8() local iv=u8() "
         "local ncode=u32() local code={} "
         "for i=1,ncode do local w=u32() local r=bit32.band(bseed,7)+1 "
         "w=bit32.bor(bit32.rshift(w,r),bit32.lshift(w,32-r)) "
         "local k=bit32.bxor(bseed,(i-1)*0x9E3779B9) "
         "k=bit32.bxor(k,bit32.lshift(k,13))k=bit32.bxor(k,bit32.rshift(k,17))k=bit32.bxor(k,bit32.lshift(k,5)) "
         "code[i]=bit32.bxor(w,k) end "
         "local nk=u32() local K={} for i=1,nk do local ty=u8() "
         "if ty==0 then K[i]=nil elseif ty==1 then K[i]=(u8()~=0) elseif ty==2 then "
         "local b0,b1,b2,b3,b4,b5,b6,b7=u8(),u8(),u8(),u8(),u8(),u8(),u8(),u8() "
         "local ok,num=pcall(function()return string.unpack('<d',string.char(b0,b1,b2,b3,b4,b5,b6,b7))end) "
         "K[i]=ok and num or 0 elseif ty==3 then local len=u32() local chars={} "
         "for j=1,len do local ch=u8() local k1=bit32.band(bseed+(j-1)*13,255) "
         "local k2=bit32.band(bit32.rshift(bseed,8)+(j-1)*37+91,255) "
         "chars[j]=string.char(bit32.band(bit32.bxor(ch,k1,k2),255)) end K[i]=table.concat(chars) "
         "else K[i]=nil end end local nc=u32() local ch={} for i=1,nc do ch[i]=u32() end "
         "local csum=0 for i=1,#code do csum=bit32.bxor(csum,code[i]) end "
         "P[pi]={a=np,c=code,k=K,ch=ch,va=iv~=0,ms=ms,cs=csum} end return P,mainId,bseed end";

    o << "local inv={";
    for (int i = 0; i < 256; ++i) {
        if (i) o << ",";
        o << invtbl[i];
    }
    o << "}";

    // environment + exec (compact)
    o << "local function " << nR << "(P,mainId,inv,seed)local CAP=38 "
         "local " << nG << "={print=print,warn=warn,error=error,pcall=pcall,xpcall=xpcall,"
         "typeof=typeof,type=type,tostring=tostring,tonumber=tonumber,pairs=pairs,ipairs=ipairs,"
         "next=next,select=select,unpack=unpack or table.unpack,rawget=rawget,rawset=rawset,"
         "rawequal=rawequal,rawlen=rawlen,setmetatable=setmetatable,getmetatable=getmetatable,"
         "bit32=bit32,math=math,string=string,table=table,task=task,utf8=utf8,game=game,"
         "workspace=workspace,Workspace=workspace,script=script,Vector2=Vector2,Vector3=Vector3,"
         "CFrame=CFrame,UDim=UDim,UDim2=UDim2,Color3=Color3,ColorSequence=ColorSequence,"
         "ColorSequenceKeypoint=ColorSequenceKeypoint,NumberSequence=NumberSequence,"
         "NumberSequenceKeypoint=NumberSequenceKeypoint,NumberRange=NumberRange,Rect=Rect,"
         "Region3=Region3,Ray=Ray,BrickColor=BrickColor,Enum=Enum,Instance=Instance,"
         "TweenInfo=TweenInfo,os=os,tick=tick,time=time,DateTime=DateTime}"
         "pcall(function() " << nG << ".Players=game:GetService('Players') end)"
         "pcall(function() " << nG << ".RunService=game:GetService('RunService') end)"
         "pcall(function() " << nG << ".ReplicatedStorage=game:GetService('ReplicatedStorage') end)"
         "pcall(function() " << nG << ".TweenService=game:GetService('TweenService') end)"
         "pcall(function() " << nG << ".UserInputService=game:GetService('UserInputService') end)"
         "pcall(function() " << nG << ".CoreGui=game:GetService('CoreGui') end)"
         "pcall(function() " << nG << ".HttpService=game:GetService('HttpService') end)"
         "pcall(function() " << nG << ".CollectionService=game:GetService('CollectionService') end)"
         "pcall(function() " << nG << ".ProximityPromptService=game:GetService('ProximityPromptService') end)"
         "pcall(function() " << nG << ".GuiService=game:GetService('GuiService') end)"
         "pcall(function() " << nG << ".Lighting=game:GetService('Lighting') end)"
         "pcall(function() " << nG << ".Debris=game:GetService('Debris') end)"
         "local RealG=type(_G)=='table' and _G or {}"
         "pcall(function() if getfenv then local e=getfenv(0) if type(e)=='table' then RealG=e end end end)"
         << nG << "._G=RealG " << nG << "._ENV=RealG "
         "local " << nE << "=setmetatable({},{__index=function(_,k) local v=rawget(" << nG
      << ",k) if v~=nil then return v end local ok,r=pcall(function() return RealG[k] end) "
         "if ok and r~=nil then return r end ok,r=pcall(function() return _G[k] end) if ok then return r end return nil end,"
         "__newindex=function(_,k,v) rawset(" << nG << ",k,v) pcall(function() RealG[k]=v end) end})"
         "local CSNew,NSNew pcall(function() CSNew=ColorSequence.new end) pcall(function() NSNew=NumberSequence.new end)"
         "local function okp(t,kind) if type(t)~='table' then return t end local o={} "
         "for i=1,64 do local v=rawget(t,i) if v==nil then break end if typeof(v)==kind then o[#o+1]=v end end "
         "return #o>0 and o or t end"
         "local function " << nK << "(proto,word) if bit32.band(word,0x80000000)~=0 then "
         "return proto.k[bit32.band(word,0x7FFFFFFF)+1] end return word end";

    o << "local function " << nX << "(pid,args,ups)"
         "local proto=P[pid+1] if not proto then error('e') end local reg={} local top=0 "
         "local nparam=proto.a or 0 local varargs={} if args then for i=1,nparam do reg[i]=args[i] top=i end "
         "for i=nparam+1,#args do varargs[#varargs+1]=args[i] end end ups=ups or {} "
         "local function setR(i,v) reg[i]=v if i>top then top=i end end "
         "local function uvget(i) local u=ups[i] if type(u)=='table' and rawget(u,'__box')==true then return u[1] end return u end "
         "local function uvset(i,v) local u=ups[i] if type(u)=='table' and rawget(u,'__box')==true then u[1]=v else ups[i]=v end end "
         "local pc=1 local code=proto.c local steps=0 local lim="
      << (watchdog ? "12e6" : "1e15")
      << " local tickchk=0 "
         "while pc<=#code do steps+=1 if steps>lim then error('e') end tickchk+=1 "
         "if tickchk>=2048 then tickchk=0 local cs=0 for i=1,#code do cs=bit32.bxor(cs,code[i]) end "
         "if cs~=proto.cs then error('e') end end "
         "local inst=code[pc] local rawop=bit32.band(inst,255) local op=inv[rawop] "
         "if op==nil or op<0 then error('e') end "
         "local A=bit32.band(bit32.rshift(inst,8),255) local B=bit32.band(bit32.rshift(inst,16),255) "
         "local C=bit32.band(bit32.rshift(inst,24),255) "
         "local D=bit32.band(bit32.rshift(inst,16),65535) if D>=32768 then D-=65536 end "
         "local Ra,Rb,Rc=A+1,B+1,C+1 ";

    // compact op dispatch (isa.hpp order)
    o << "if op==0 then setR(Ra,reg[Rb])"
         " elseif op==1 then pc+=1 setR(Ra," << nK << "(proto,code[pc]))"
         " elseif op==2 then setR(Ra,nil)"
         " elseif op==3 then setR(Ra,B~=0)"
         " elseif op==4 then setR(Ra,(reg[Rb] or 0)+(reg[Rc] or 0))"
         " elseif op==5 then setR(Ra,(reg[Rb] or 0)-(reg[Rc] or 0))"
         " elseif op==6 then setR(Ra,(reg[Rb] or 0)*(reg[Rc] or 0))"
         " elseif op==7 then setR(Ra,(reg[Rb] or 0)/(reg[Rc] or 1))"
         " elseif op==8 then setR(Ra,(reg[Rb] or 0)%(reg[Rc] or 1))"
         " elseif op==9 then setR(Ra,(reg[Rb] or 0)^(reg[Rc] or 1))"
         " elseif op==10 then setR(Ra,-(reg[Rb] or 0))"
         " elseif op==11 then setR(Ra,not reg[Rb])"
         " elseif op==12 then local t=reg[Rb] setR(Ra,type(t)=='table' and #t or (type(t)=='string' and #t or 0))"
         " elseif op==13 then local t='' for i=Rb,Rc do t..=tostring(reg[i] or '') end setR(Ra,t)"
         " elseif op==14 then pc+=D"
         " elseif op==15 then if reg[Ra] then pc+=D end"
         " elseif op==16 then if not reg[Ra] then pc+=D end"
         " elseif op==17 then local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end"
         " elseif op==18 then local ok=(reg[Ra] or 0)<(reg[Rb] or 0) if C~=0 then ok=not ok end if not ok then pc+=1 end"
         " elseif op==19 then local ok=(reg[Ra] or 0)<=(reg[Rb] or 0) if C~=0 then ok=not ok end if not ok then pc+=1 end"
         " elseif op==20 then pc+=1 setR(Ra," << nE << "[" << nK << "(proto,code[pc])])"
         " elseif op==21 then pc+=1 " << nE << "[" << nK << "(proto,code[pc])]=reg[Ra]"
         " elseif op==22 then local t=reg[Rb] setR(Ra,t and t[reg[Rc]] or nil)"
         " elseif op==23 then local t=reg[Rb] if t then t[reg[Rc]]=reg[Ra] end"
         " elseif op==24 then pc+=1 local t=reg[Rb] local key=" << nK << "(proto,code[pc]) setR(Ra,t and t[key] or nil)"
         " elseif op==25 then pc+=1 local t=reg[Rb] local key=" << nK << "(proto,code[pc]) if t then t[key]=reg[Ra] end"
         " elseif op==26 then setR(Ra,{})"
         " elseif op==41 then local t=reg[Rb] setR(Ra,t and t[C+1] or nil)"
         " elseif op==42 then local t=reg[Rb] if t then t[C+1]=reg[Ra] end"
         " elseif op==34 then setR(Ra,uvget(B+1))"
         " elseif op==35 then uvset(B+1,reg[Ra])"
         " elseif op==39 then if reg[Rb] then setR(Ra,reg[Rc]) else setR(Ra,reg[Rb]) end"
         " elseif op==40 then if reg[Rb] then setR(Ra,reg[Rb]) else setR(Ra,reg[Rc]) end"
         " elseif op==43 then setR(Ra,math.floor((reg[Rb] or 0)/(reg[Rc] or 1)))"
         " elseif op==33 then pc+=1 local key=" << nK << "(proto,code[pc]) local obj=reg[Rb] "
         "setR(Ra+1,obj) setR(Ra,obj and obj[key] or nil) if top<Ra+1 then top=Ra+1 end"
         " elseif op==36 then pc+=1 local start=code[pc] or 1 if type(start)~='number' or start<1 then start=1 end "
         "local t=reg[Ra] local cnt=B if cnt==0 then cnt=math.max(0,top-Ra) end "
         "if type(t)=='table' then for i=1,cnt do rawset(t,start+i-1,reg[Ra+i]) end end"
         " elseif op==32 then if B==0 then for i=1,#varargs do setR(Ra+i-1,varargs[i]) end "
         "top=Ra+#varargs-1 if top<0 then top=0 end elseif B==1 then top=math.max(0,Ra-1) "
         "else local n=B-1 for i=1,n do setR(Ra+i-1,varargs[i]) end top=Ra+n-1 end"
         " elseif op==27 then local narg if B==0 then narg=math.max(0,top-Ra) if narg>24 then narg=24 end else narg=B-1 end "
         "local fn=reg[Ra] local argv={} for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end "
         "if type(fn)=='function' and narg>=1 and type(argv[1])=='table' then "
         "if CSNew and fn==CSNew then argv[1]=okp(argv[1],'ColorSequenceKeypoint') "
         "elseif NSNew and fn==NSNew then argv[1]=okp(argv[1],'NumberSequenceKeypoint') end end "
         "if type(fn)~='function' then error('e') end "
         "local ok,ret=pcall(function() return table.pack(fn(table.unpack(argv,1,math.max(narg,0)))) end) "
         "if not ok then error(tostring(ret)) end "
         "if C==0 then for i=1,ret.n do setR(Ra+i-1,ret[i]) end top=Ra+math.max(ret.n,0)-1 if top<0 then top=0 end "
         "elseif C==1 then top=math.max(0,Ra-1) else for i=1,C-1 do setR(Ra+i-1,ret[i]) end top=Ra+(C-1)-1 end"
         " elseif op==28 then local nret=if B==0 then math.max(0,top-Ra+1) else (B-1) "
         "local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end return table.unpack(out,1,math.max(nret,0))"
         " elseif op==30 then local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1 "
         "local idx=tonumber(reg[Ra+2]) or 0 if (step>=0 and idx>limit) or (step<0 and idx<limit) then pc+=D else setR(Ra+3,idx) end"
         " elseif op==29 then local limit=tonumber(reg[Ra]) or 0 local step=tonumber(reg[Ra+1]) or 1 "
         "local idx=(tonumber(reg[Ra+2]) or 0)+step setR(Ra+2,idx) "
         "if (step>=0 and idx<=limit) or (step<0 and idx>=limit) then setR(Ra+3,idx) pc+=D end"
         " elseif op==37 then local it,state,ctl=reg[Ra],reg[Ra+1],reg[Ra+2] "
         "if type(it)=='function' then local ok,res=pcall(function() return table.pack(it(state,ctl)) end) "
         "if ok and res[1]~=nil then setR(Ra+2,res[1]) for i=1,res.n do setR(Ra+2+i,res[i]) end pc+=D end end"
         " elseif op==31 then pc+=1 local child=code[pc] or 0 local cid=proto.ch[child+1] or 0 "
         "local parentReg,parentUps=reg,ups if not parentReg.__boxes then parentReg.__boxes={} end local boxes=parentReg.__boxes "
         "local stored={} local ui=1 while pc+1<=#code do local nextInst=code[pc+1] local rop=bit32.band(nextInst,255) "
         "if inv[rop]~=CAP then break end pc+=1 local ca=bit32.band(bit32.rshift(nextInst,8),255) "
         "local cb=bit32.band(bit32.rshift(nextInst,16),255) if ca==2 then stored[ui]=parentUps[cb+1] "
         "elseif ca==1 then if not boxes[cb] then boxes[cb]={__box=true,parentReg[cb+1]} end stored[ui]=boxes[cb] "
         "else stored[ui]=parentReg[cb+1] end ui+=1 if ui>128 then break end end "
         "setR(Ra,function(...) return " << nX << "(cid,{...},stored) end)"
         " elseif op==38 then "
         " elseif op==44 then local ok=(reg[Ra]==reg[Rb]) if C~=0 then ok=not ok end if not ok then pc+=1 end"
         " else error('e') end pc+=1 end end return " << nX << "(mainId) end";

    if (heads == 2) {
        o << "return (function() local buf=" << nD << "() local P,mainId,bseed=" << nB
          << "(buf) return " << nR << "(P,mainId,inv,bseed) end)()";
    } else {
        o << "local buf=" << nD << "() local P,mainId,bseed=" << nB << "(buf) return "
          << nR << "(P,mainId,inv,bseed)";
    }

    return o.str();
}

} // namespace Protect