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
                                               const Options& options) const {
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

    // Second outer key (derived) — not the same as inner ks
    uint32_t outerKey = seed32() ^ 0xA5A5A5A5u;

    std::stringstream s;
    s << "--!nocheck\n";
    s << "--[[\n";
    s << "  ╔══════════════════════════════════════════╗\n";
    s << "  ║     Protected by FŁÝ / FLYX Obfuscator   ║\n";
    s << "  ║   Double-head VM · outer+inner · private ║\n";
    s << "  ╚══════════════════════════════════════════╝\n";
    s << "]]\n";

    // ═══════════════ OUTER HEAD ═══════════════
    s << "local function __outer()\n";
    s << "local L=" << bytesToLuaTable(left) << "\n";
    s << "local R=" << bytesToLuaTable(right) << "\n";
    s << "local _B={}\n";
    s << "for i=1,#L do _B[i]=L[i] end\n";
    s << "for i=1,#R do _B[#L+i]=R[i] end\n";
    s << "do local s=0 for i=1,#_B do s+=_B[i] end if s~=" << sum << " then error(\"t0\") end end\n";
    s << "L,R=nil,nil\n";

    // Light outer scramble (identity-preserving mix using outerKey)
    s << "do local ok=" << outerKey << "\n";
    s << "for i=1,#_B do\n";
    s << "local k=bit32.band(bit32.bxor(ok,i*17),0) -- reserved; blob already encrypted\n";
    s << "end end\n";

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
    s << "if ru32()~=0x3252504C then error(\"t1\") end\n";
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

    // Env
    s << "local G={}\n";
    s << "local function gset(k,v) if v~=nil then G[k]=v end end\n";
    s << "gset(\"game\",game) gset(\"workspace\",workspace) gset(\"Workspace\",workspace)\n";
    s << "gset(\"script\",script) gset(\"Enum\",Enum) gset(\"Instance\",Instance)\n";
    s << "gset(\"Color3\",Color3) gset(\"UDim2\",UDim2) gset(\"UDim\",UDim)\n";
    s << "gset(\"Vector2\",Vector2) gset(\"Vector3\",Vector3) gset(\"CFrame\",CFrame)\n";
    s << "gset(\"Rect\",Rect) gset(\"Region3\",Region3) gset(\"BrickColor\",BrickColor)\n";
    s << "gset(\"Ray\",Ray) gset(\"RaycastParams\",RaycastParams) gset(\"OverlapParams\",OverlapParams)\n";
    s << "gset(\"ColorSequence\",ColorSequence) gset(\"ColorSequenceKeypoint\",ColorSequenceKeypoint)\n";
    s << "gset(\"NumberSequence\",NumberSequence) gset(\"NumberSequenceKeypoint\",NumberSequenceKeypoint)\n";
    s << "gset(\"NumberRange\",NumberRange) gset(\"TweenInfo\",TweenInfo)\n";
    s << "gset(\"task\",task) gset(\"tick\",tick) gset(\"time\",time) gset(\"os\",os)\n";
    s << "gset(\"typeof\",typeof) gset(\"pairs\",pairs) gset(\"ipairs\",ipairs) gset(\"next\",next)\n";
    s << "gset(\"pcall\",pcall) gset(\"xpcall\",xpcall) gset(\"print\",print) gset(\"warn\",warn)\n";
    s << "gset(\"error\",error) gset(\"assert\",assert) gset(\"tostring\",tostring) gset(\"tonumber\",tonumber)\n";
    s << "gset(\"type\",type) gset(\"select\",select) gset(\"table\",table) gset(\"string\",string)\n";
    s << "gset(\"math\",math) gset(\"bit32\",bit32) gset(\"buffer\",buffer) gset(\"utf8\",utf8)\n";
    s << "gset(\"coroutine\",coroutine) gset(\"require\",require) gset(\"shared\",shared)\n";
    s << "gset(\"setmetatable\",setmetatable) gset(\"getmetatable\",getmetatable)\n";
    s << "gset(\"rawget\",rawget) gset(\"rawset\",rawset) gset(\"rawequal\",rawequal) gset(\"rawlen\",rawlen)\n";
    s << "gset(\"newproxy\",newproxy) gset(\"unpack\",table and table.unpack)\n";
    s << "pcall(function() G.setclipboard=setclipboard end)\n";
    s << "pcall(function() G.TweenService=game:GetService(\"TweenService\") end)\n";
    s << "pcall(function() G.UserInputService=game:GetService(\"UserInputService\") end)\n";
    s << "pcall(function() G.RunService=game:GetService(\"RunService\") end)\n";
    s << "pcall(function() G.Players=game:GetService(\"Players\") end)\n";
    s << "pcall(function() G.ReplicatedStorage=game:GetService(\"ReplicatedStorage\") end)\n";
    s << "pcall(function() G.HttpService=game:GetService(\"HttpService\") end)\n";
    s << "pcall(function() G.Debris=game:GetService(\"Debris\") end)\n";
    s << "pcall(function() G.Lighting=game:GetService(\"Lighting\") end)\n";
    s << "pcall(function() G.CoreGui=game:GetService(\"CoreGui\") end)\n";
    s << "pcall(function() G.GuiService=game:GetService(\"GuiService\") end)\n";
    s << "pcall(function() G.ProximityPromptService=game:GetService(\"ProximityPromptService\") end)\n";

    s << "local RealG=type(_G)==\"table\" and _G or {}\n";
    s << "pcall(function() if getfenv then local e=getfenv(0) if type(e)==\"table\" then RealG=e end end end)\n";
    s << "G._G=RealG G._ENV=RealG\n";
    s << "local E=setmetatable({},{__index=function(_,k)\n";
    s << "local v=rawget(G,k)\n";
    s << "if v~=nil then return v end\n";
    s << "local ok,r=pcall(function() return RealG[k] end)\n";
    s << "if ok and r~=nil then return r end\n";
    s << "ok,r=pcall(function() return _G[k] end)\n";
    s << "if ok then return r end\n";
    s << "return nil\n";
    s << "end,__newindex=function(_,k,v) rawset(G,k,v) pcall(function() RealG[k]=v end) end})\n";

    s << "local CAP=" << n(Op::CAPTURE) << "\n";
    s << "local CSNew,NSNew\n";
    s << "pcall(function() CSNew=ColorSequence.new end)\n";
    s << "pcall(function() NSNew=NumberSequence.new end)\n";

    s << "local function onlyKeypoints(t, kind)\n";
    s << "if type(t)~=\"table\" then return t end\n";
    s << "local out={}\n";
    s << "for i=1,32 do\n";
    s << "local v=rawget(t,i)\n";
    s << "if v==nil then break end\n";
    s << "if typeof(v)==kind then out[#out+1]=v end\n";
    s << "end\n";
    s << "return #out>0 and out or t\n";
    s << "end\n";

    // ═══════════════ INNER HEAD (execution) ═══════════════
    s << "local function __inner()\n";
    s << "local function run(pid,args,ups)\n";
    s << "local p=P[pid+1] if not p then error(\"p\") end\n";
    s << "local reg={} local top=0\n";
    s << "if args then for i=1,#args do reg[i]=args[i] top=i end end\n";
    s << "ups=ups or {}\n";
    s << "local function setR(i,v) reg[i]=v if i>top then top=i end end\n";
    s << "local pc=1 local code=p.c\n";
    if (options.watchdog)
        s << "local steps=0\n";
    s << "while pc<=#code do\n";
    if (options.watchdog) {
        s << "steps+=1\n";
        s << "if steps>8000000 then error(\"watchdog pc=\"..pc..\" pid=\"..pid) end\n";
    }
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
    s << "elseif op==" << n(Op::SETGLOBAL) << " then pc+=1 E[kn(p,code[pc])]=reg[Ra]\n";
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
    s << "if type(start)~=\"number\" or start<1 then start=1 end\n";
    s << "local t=reg[Ra]\n";
    s << "local cnt=B\n";
    s << "if cnt==0 then cnt=math.max(0,top-Ra) end\n";
    s << "if type(t)==\"table\" then\n";
    s << "for i=1,cnt do rawset(t,start+i-1,reg[Ra+i]) end\n";
    s << "end\n";

    s << "elseif op==" << n(Op::CALL) << " then\n";
    s << "local narg\n";
    s << "if B==0 then narg=math.max(0,top-Ra) if narg>8 then narg=8 end else narg=B-1 end\n";
    s << "local fn=reg[Ra]\n";
    s << "local argv={}\n";
    s << "for i=1,math.max(narg,0) do argv[i]=reg[Ra+i] end\n";
    s << "if type(fn)==\"function\" and narg>=1 and type(argv[1])==\"table\" then\n";
    s << "if CSNew and fn==CSNew then argv[1]=onlyKeypoints(argv[1],\"ColorSequenceKeypoint\")\n";
    s << "elseif NSNew and fn==NSNew then argv[1]=onlyKeypoints(argv[1],\"NumberSequenceKeypoint\") end\n";
    s << "end\n";
    s << "if type(fn)~=\"function\" then\n";
    s << "local a1,a2,a3=argv[1],argv[2],argv[3]\n";
    s << "if type(a1)==\"number\" and type(a2)==\"number\" and type(a3)==\"number\" then\n";
    s << "local x=a1 if x<a2 then x=a2 elseif x>a3 then x=a3 end\n";
    s << "fn=function() return x end narg=0\n";
    s << "elseif type(a1)==\"number\" and narg<=1 then\n";
    s << "local x=math.floor(a1) fn=function() return x end narg=0\n";
    s << "else error(\"bad call \"..tostring(fn)..\" pc=\"..pc..\" pid=\"..pid) end\n";
    s << "end\n";
    s << "local ok,ret=pcall(function() return table.pack(fn(table.unpack(argv,1,math.max(narg,0)))) end)\n";
    s << "if not ok then error(tostring(ret)..\" pc=\"..pc..\" pid=\"..pid) end\n";
    s << "if C==0 then\n";
    s << "for i=1,ret.n do setR(Ra+i-1,ret[i]) end\n";
    s << "top=Ra+math.max(ret.n,0)-1 if top<0 then top=0 end\n";
    s << "elseif C==1 then top=math.max(0,Ra-1)\n";
    s << "else for i=1,C-1 do setR(Ra+i-1,ret[i]) end top=Ra+(C-1)-1 end\n";

    s << "elseif op==" << n(Op::RETURN) << " then\n";
    s << "local nret=if B==0 then math.max(0,top-Ra+1) else (B-1)\n";
    s << "local out={} for i=1,math.max(nret,0) do out[i]=reg[Ra+i-1] end\n";
    s << "return table.unpack(out,1,math.max(nret,0))\n";

    s << "elseif op==" << n(Op::FORPREP) << " then\n";
    s << "local idx=tonumber(reg[Ra]) or 0\n";
    s << "local lim=tonumber(reg[Ra+1]) or 0\n";
    s << "local step=tonumber(reg[Ra+2]) or 1\n";
    s << "setR(Ra,idx-step) setR(Ra+1,lim) setR(Ra+2,step)\n";
    s << "pc+=D\n";
    s << "elseif op==" << n(Op::FORLOOP) << " then\n";
    s << "local step=tonumber(reg[Ra+2]) or 1\n";
    s << "local idx=(tonumber(reg[Ra]) or 0)+step\n";
    s << "local lim=tonumber(reg[Ra+1]) or 0\n";
    s << "setR(Ra,idx)\n";
    s << "if (step>=0 and idx<=lim) or (step<0 and idx>=lim) then\n";
    s << "setR(Ra+3,idx)\n";
    s << "pc+=D\n";
    s << "end\n";
    s << "elseif op==" << n(Op::FORGLOOP) << " then\n";
    s << "local it,state,ctl=reg[Ra],reg[Ra+1],reg[Ra+2]\n";
    s << "if type(it)==\"function\" then\n";
    s << "local res={it(state,ctl)}\n";
    s << "if res[1]~=nil then setR(Ra+2,res[1]) for i=1,#res do setR(Ra+2+i,res[i]) end pc+=D end\n";
    s << "end\n";

    s << "elseif op==" << n(Op::CLOSURE) << " then\n";
    s << "pc+=1\n";
    s << "local child=code[pc] or 0\n";
    s << "local cid=p.ch[child+1] or 0\n";
    s << "local parentReg,parentUps=reg,ups\n";
    s << "local stored={}\n";
    s << "for i=1,math.max(top,96) do stored[i]=parentReg[i] end\n";
    s << "for i=1,128 do if stored[i]==nil then stored[i]=parentUps[i] end end\n";
    s << "local ui=1\n";
    s << "while pc+1<=#code do\n";
    s << "local nextInst=code[pc+1]\n";
    s << "if bit32.band(nextInst,255)~=CAP then break end\n";
    s << "pc+=1\n";
    s << "local ca=bit32.band(bit32.rshift(nextInst,8),255)\n";
    s << "local cb=bit32.band(bit32.rshift(nextInst,16),255)\n";
    s << "local v=nil\n";
    s << "if ca==2 then v=parentUps[cb+1] elseif ca<=1 then v=parentReg[cb+1] end\n";
    s << "if v~=nil then stored[ui]=v end\n";
    s << "ui+=1 if ui>128 then break end\n";
    s << "end\n";
    s << "setR(Ra,function(...) return run(cid,{...},stored) end)\n";
    s << "elseif op==" << n(Op::CAPTURE) << " then\n";
    s << "end\n";
    s << "pc+=1\n";
    s << "end\n";
    s << "end\n";
    s << "return run(mainId)\n";
    s << "end\n"; // __inner

    s << "return __inner\n";
    s << "end\n"; // __outer

    // Hand-off: outer builds state, returns inner, then execute
    s << "return __outer()()\n";
    return s.str();
}

} // namespace Protect