#include "translator.hpp"
#include "Luau/Bytecode.h"

#include "lua.h"
#include "lualib.h"
#include "luacode.h"

#define LUA_CORE
#include "lobject.h"
#include "lstate.h"

#include <cstring>
#include <cstdio>
#include <sstream>

Translator::Translator(uint32_t seed)
    : seed_(seed ? seed : 0xA341316Cu), map_(makeOpcodeMap(seed_)) {}

uint8_t Translator::Reader::u8() { return 0; }
uint32_t Translator::Reader::u32() { return 0; }
uint32_t Translator::Reader::varint() { return 0; }
std::string Translator::Reader::bytes(uint32_t) { return {}; }

static int luauInsnLength(uint8_t op) {
    switch (op) {
    case LOP_GETGLOBAL:
    case LOP_SETGLOBAL:
    case LOP_GETIMPORT:
    case LOP_GETTABLEKS:
    case LOP_SETTABLEKS:
    case LOP_NAMECALL:
    case LOP_NEWTABLE:
    case LOP_SETLIST:
    case LOP_FASTCALL:
    case LOP_FASTCALL1:
    case LOP_FASTCALL2:
    case LOP_FASTCALL2K:
    case LOP_JUMPIFEQ:
    case LOP_JUMPIFLE:
    case LOP_JUMPIFLT:
    case LOP_JUMPIFNOTEQ:
    case LOP_JUMPIFNOTLE:
    case LOP_JUMPIFNOTLT:
        return 2;
    default:
        return 1;
    }
}

static FlyConstant convertConst(const TValue* o) {
    FlyConstant c;
    if (ttisboolean(o)) {
        c.type = FlyConstant::BOOL;
        c.b = bvalue(o) != 0;
    } else if (ttisnumber(o)) {
        c.type = FlyConstant::NUMBER;
        c.n = nvalue(o);
    } else if (ttisstring(o)) {
        c.type = FlyConstant::STRING;
        TString* ts = tsvalue(o);
        const char* s = getstr(ts);
        c.s.assign(s, s + ts->len);
    } else {
        c.type = FlyConstant::NIL;
    }
    return c;
}

bool Translator::remapFunction(const std::vector<uint32_t>& luauCode,
                               FlyProto& proto,
                               std::string& err) const {
    auto mop = [&](Op o) { return map_[static_cast<size_t>(o)]; };
    struct Jump {
        size_t patchIndex;
        int oldTarget;
    };
    std::vector<size_t> oldToNew(luauCode.size() + 1, 0);
    std::vector<Jump> jumps;

    auto emitABC = [&](Op o, uint8_t a, uint8_t b, uint8_t c) {
        proto.code.push_back(packABC(mop(o), a, b, c));
    };
    auto emitJump = [&](Op o, uint8_t a, int oldTarget) {
        jumps.push_back({proto.code.size(), oldTarget});
        proto.code.push_back(packAD(mop(o), a, 0));
    };
    auto emitK = [&](uint32_t idx) { proto.code.push_back(idx | 0x80000000u); };
    auto emitDead = [&](size_t at) {
        uint32_t h = seed_ ^ uint32_t(at * 2654435769u);
        if ((h & 3u) == 0)
            proto.code.push_back(packAD(mop(Op::JMP), 0, 0));
        if ((h & 5u) == 5u)
            proto.code.push_back(packABC(mop(Op::MOVE), 0, 0, 0));
    };

    size_t pc = 0;
    while (pc < luauCode.size()) {
        oldToNew[pc] = proto.code.size();
        uint32_t insn = luauCode[pc];
        uint8_t op = uint8_t(LUAU_INSN_OP(insn));
        uint8_t A = uint8_t(LUAU_INSN_A(insn));
        uint8_t B = uint8_t(LUAU_INSN_B(insn));
        uint8_t C = uint8_t(LUAU_INSN_C(insn));
        int16_t D = int16_t(LUAU_INSN_D(insn));
        int len = luauInsnLength(op);
        uint32_t aux = 0;
        if (len == 2) {
            if (pc + 1 >= luauCode.size()) {
                err = "truncated aux";
                return false;
            }
            aux = luauCode[pc + 1];
        }
        int nextOld = int(pc + size_t(len));

        switch (op) {
        case LOP_NOP:
        case LOP_BREAK:
        case LOP_PREPVARARGS:
            break;
        case LOP_LOADNIL:
            emitABC(Op::LOADNIL, A, A, 0);
            break;
        case LOP_LOADB:
            emitABC(Op::LOADBOOL, A, B, 0);
            if (C != 0) emitJump(Op::JMP, 0, nextOld + int(C));
            break;
        case LOP_LOADN:
            emitABC(Op::LOADK, A, 0, 0);
            proto.code.push_back(uint32_t(int32_t(D)));
            break;
        case LOP_LOADK:
            emitABC(Op::LOADK, A, 0, 0);
            emitK(uint32_t(D));
            break;
        case LOP_MOVE:
            emitABC(Op::MOVE, A, B, 0);
            break;
        case LOP_GETGLOBAL:
            emitABC(Op::GETGLOBAL, A, 0, 0);
            emitK(aux);
            break;
        case LOP_SETGLOBAL:
            emitABC(Op::SETGLOBAL, A, 0, 0);
            emitK(aux);
            break;
        case LOP_GETIMPORT: {
            int count = int(aux >> 30);
            int id0 = int((aux >> 20) & 1023);
            int id1 = int((aux >> 10) & 1023);
            emitABC(Op::GETGLOBAL, A, 0, 0);
            emitK(uint32_t(id0));
            if (count > 1) {
                emitABC(Op::GETTABLEKS, A, A, 0);
                emitK(uint32_t(id1));
            }
            break;
        }
        case LOP_GETTABLE:
            emitABC(Op::GETTABLE, A, B, C);
            break;
        case LOP_SETTABLE:
            emitABC(Op::SETTABLE, A, B, C);
            break;
        case LOP_GETTABLEKS:
            emitABC(Op::GETTABLEKS, A, B, 0);
            emitK(aux);
            break;
        case LOP_NEWTABLE:
            emitABC(Op::NEWTABLE, A, B, C);
            break;
        case LOP_ADD:
        case LOP_ADDK:
            emitABC(Op::ADD, A, B, C);
            break;
        case LOP_SUB:
        case LOP_SUBK:
            emitABC(Op::SUB, A, B, C);
            break;
        case LOP_MUL:
        case LOP_MULK:
            emitABC(Op::MUL, A, B, C);
            break;
        case LOP_DIV:
        case LOP_DIVK:
            emitABC(Op::DIV, A, B, C);
            break;
        case LOP_MOD:
        case LOP_MODK:
            emitABC(Op::MOD, A, B, C);
            break;
        case LOP_POW:
        case LOP_POWK:
            emitABC(Op::POW, A, B, C);
            break;
        case LOP_NOT:
            emitABC(Op::NOT, A, B, 0);
            break;
        case LOP_MINUS:
            emitABC(Op::UNM, A, B, 0);
            break;
        case LOP_LENGTH:
            emitABC(Op::LEN, A, B, 0);
            break;
        case LOP_CONCAT:
            emitABC(Op::CONCAT, A, B, C);
            break;
        case LOP_JUMP:
        case LOP_JUMPBACK:
            emitJump(Op::JMP, 0, nextOld + D);
            break;
        case LOP_JUMPIF:
            emitJump(Op::JMPIF, A, nextOld + D);
            break;
        case LOP_JUMPIFNOT:
            emitJump(Op::JMPIFNOT, A, nextOld + D);
            break;
        case LOP_CALL:
            emitABC(Op::CALL, A, B, C);
            break;
        case LOP_RETURN:
            emitABC(Op::RETURN, A, B, 0);
            break;
        case LOP_FORNPREP:
            emitJump(Op::FORPREP, A, nextOld + D);
            break;
        case LOP_FORNLOOP:
            emitJump(Op::FORLOOP, A, nextOld + D);
            break;
        case LOP_NEWCLOSURE:
            emitABC(Op::CLOSURE, A, 0, 0);
            proto.code.push_back(uint32_t(int32_t(D)));
            break;
        case LOP_DUPCLOSURE:
            emitABC(Op::CLOSURE, A, 0, 0);
            proto.code.push_back(0);
            break;
        case LOP_GETVARARGS:
            emitABC(Op::VARARG, A, B, 0);
            break;
        default:
            break;
        }
        emitDead(pc);
        pc += size_t(len);
    }
    oldToNew[luauCode.size()] = proto.code.size();

    for (const Jump& j : jumps) {
        int t = j.oldTarget;
        size_t target = (t < 0) ? 0
                                : (t >= int(oldToNew.size()) ? proto.code.size()
                                                             : oldToNew[size_t(t)]);
        int32_t rel = int32_t(target) - int32_t(j.patchIndex + 1);
        if (rel < -32768) rel = -32768;
        if (rel > 32767) rel = 32767;
        uint32_t word = proto.code[j.patchIndex];
        proto.code[j.patchIndex] = packAD(insnOp(word), insnA(word), int16_t(rel));
    }
    return true;
}

bool Translator::remapPublic(const std::vector<uint32_t>& code, FlyProto& proto, std::string& err) const {
    return remapFunction(code, proto, err);
}

static uint32_t pullProto(const Translator* self, struct Proto* p, std::vector<FlyProto>& out, std::string& err) {
    std::vector<uint32_t> kids;
    for (int i = 0; i < p->sizep; ++i) {
        uint32_t id = pullProto(self, p->p[i], out, err);
        if (!err.empty()) return 0;
        kids.push_back(id);
    }

    FlyProto dst;
    dst.maxstack = p->maxstacksize;
    dst.numparams = p->numparams;
    dst.nups = p->nups;
    dst.isvararg = p->is_vararg;
    dst.childProtos = kids;

    for (int i = 0; i < p->sizek; ++i)
        dst.constants.push_back(convertConst(&p->k[i]));

    std::vector<uint32_t> code;
    code.reserve(size_t(p->sizecode));
    for (int i = 0; i < p->sizecode; ++i)
        code.push_back(uint32_t(p->code[i]));

    if (!self->remapPublic(code, dst, err))
        return 0;

    uint32_t id = uint32_t(out.size());
    out.push_back(std::move(dst));
    return id;
}

bool Translator::parseLuau(const std::vector<uint8_t>& data,
                           std::vector<FlyProto>& out,
                           uint32_t& mainId,
                           std::string& err) const {
    if (data.empty()) {
        err = "empty bytecode";
        return false;
    }

    lua_State* L = luaL_newstate();
    if (!L) {
        err = "luaL_newstate failed";
        return false;
    }
    luaL_openlibs(L);

    int st = luau_load(
        L,
        "=fly",
        reinterpret_cast<const char*>(data.data()),
        data.size(),
        0
    );
    if (st != 0) {
        const char* msg = lua_tostring(L, -1);
        err = std::string("luau_load failed: ") + (msg ? msg : "?");
        lua_close(L);
        return false;
    }

    const TValue* fo = L->top - 1;
    if (!ttisfunction(fo)) {
        err = "loaded value is not a function";
        lua_close(L);
        return false;
    }
    Closure* cl = clvalue(fo);
    if (cl->isC || !cl->l.p) {
        err = "loaded closure has no proto";
        lua_close(L);
        return false;
    }

    mainId = pullProto(this, cl->l.p, out, err);
    lua_close(L);
    return err.empty() && !out.empty();
}

Translator::Result Translator::translate(const Bytecode& luauBlob) const {
    Result r;
    if (luauBlob.empty()) {
        r.error = "empty luau bytecode";
        return r;
    }
    if (!parseLuau(luauBlob.data(), r.protos, r.mainId, r.error))
        return r;
    r.encoded = encodeCustom(r.protos, r.mainId);
    r.success = true;
    return r;
}

Bytecode Translator::encodeCustom(const std::vector<FlyProto>& protos, uint32_t mainId) const {
    std::vector<uint8_t> blob;
    auto w8 = [&](uint8_t v) { blob.push_back(v); };
    auto w32 = [&](uint32_t v) {
        blob.push_back(uint8_t(v));
        blob.push_back(uint8_t(v >> 8));
        blob.push_back(uint8_t(v >> 16));
        blob.push_back(uint8_t(v >> 24));
    };

    w32(0x3252504C);
    w32(seed_);
    w8(1);
    w32(uint32_t(protos.size()));
    w32(mainId);

    for (const auto& p : protos) {
        w8(p.maxstack);
        w8(p.numparams);
        w8(p.nups);
        w8(p.isvararg);

        w32(uint32_t(p.code.size()));
        for (uint32_t w : p.code)
            w32(w);

        w32(uint32_t(p.constants.size()));
        for (const auto& c : p.constants) {
            w8(uint8_t(c.type));
            if (c.type == FlyConstant::BOOL) {
                w8(c.b ? 1 : 0);
            } else if (c.type == FlyConstant::NUMBER) {
                uint64_t bits = 0;
                std::memcpy(&bits, &c.n, 8);
                for (int i = 0; i < 8; ++i)
                    w8(uint8_t(bits >> (8 * i)));
            } else if (c.type == FlyConstant::STRING) {
                w32(uint32_t(c.s.size()));
                for (size_t i = 0; i < c.s.size(); ++i) {
                    uint8_t ch = static_cast<uint8_t>(c.s[i]);
                    uint8_t key = static_cast<uint8_t>(seed_ + static_cast<uint32_t>(i) * 13u);
                    w8(static_cast<uint8_t>(ch ^ key));
                }
            }
        }

        w32(uint32_t(p.childProtos.size()));
        for (uint32_t id : p.childProtos)
            w32(id);
    }
    return Bytecode(std::move(blob));
}