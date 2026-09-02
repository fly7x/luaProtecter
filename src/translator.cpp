#include "translator.hpp"
#include "Luau/Bytecode.h"
#include <cstring>

Translator::Translator(uint32_t seed)
    : seed_(seed ? seed : 0xA341316Cu), map_(makeOpcodeMap(seed_)) {}

uint8_t Translator::Reader::u8() {
    if (!ok || p >= end) { ok = false; return 0; }
    return *p++;
}

uint32_t Translator::Reader::u32() {
    uint32_t a = u8(), b = u8(), c = u8(), d = u8();
    return a | (b << 8) | (c << 16) | (d << 24);
}

uint32_t Translator::Reader::varint() {
    uint32_t result = 0, shift = 0;
    for (;;) {
        uint8_t b = u8();
        if (!ok) return 0;
        result |= uint32_t(b & 0x7F) << shift;
        if ((b & 0x80) == 0) return result;
        shift += 7;
        if (shift > 28) { ok = false; return 0; }
    }
}

std::string Translator::Reader::bytes(uint32_t n) {
    if (!ok || p + n > end) { ok = false; return {}; }
    std::string s(reinterpret_cast<const char*>(p), n);
    p += n;
    return s;
}

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

bool Translator::parseLuau(const std::vector<uint8_t>& data,
                           std::vector<Proto>& out,
                           uint32_t& mainId,
                           std::string& err) const {
    Reader rd;
    rd.p = data.data();
    rd.end = data.data() + data.size();

    uint8_t version = rd.u8();
    if (!rd.ok || version < 3) {
        err = "unsupported luau bytecode version";
        return false;
    }
    if (version >= 4)
        (void)rd.u8();

    uint32_t nstrings = rd.varint();
    std::vector<std::string> strings;
    strings.reserve(nstrings);
    for (uint32_t i = 0; i < nstrings && rd.ok; ++i) {
        uint32_t len = rd.varint();
        strings.push_back(rd.bytes(len));
    }
    if (!rd.ok) { err = "string table truncated"; return false; }

    auto intern = [&](uint32_t idx) -> std::string {
        if (idx == 0 || idx > strings.size()) return {};
        return strings[idx - 1];
    };

    uint32_t nfuncs = rd.varint();
    if (!rd.ok || nfuncs == 0) { err = "no functions"; return false; }
    out.assign(nfuncs, Proto{});

    for (uint32_t f = 0; f < nfuncs; ++f) {
        Proto proto;
        proto.maxstack  = rd.u8();
        proto.numparams = rd.u8();
        proto.nups      = rd.u8();
        proto.isvararg  = rd.u8();
        (void)rd.u8();

        uint32_t typeSize = rd.varint();
        (void)rd.bytes(typeSize);

        uint32_t ncode = rd.varint();
        std::vector<uint32_t> luauCode;
        luauCode.reserve(ncode);
        for (uint32_t i = 0; i < ncode && rd.ok; ++i)
            luauCode.push_back(rd.u32());

        uint32_t nk = rd.varint();
        proto.constants.reserve(nk);
        for (uint32_t i = 0; i < nk && rd.ok; ++i) {
            uint8_t tag = rd.u8();
            Constant c;
            switch (tag) {
            case 0:
                c.type = Constant::NIL;
                break;
            case 1:
                c.type = Constant::BOOL;
                c.b = rd.u8() != 0;
                break;
            case 2: {
                c.type = Constant::NUMBER;
                uint64_t bits = 0;
                for (int b = 0; b < 8; ++b) bits |= uint64_t(rd.u8()) << (8 * b);
                std::memcpy(&c.n, &bits, 8);
                break;
            }
            case 3: {
                c.type = Constant::STRING;
                c.s = intern(rd.varint());
                break;
            }
            case 4:
                (void)rd.u32();
                c.type = Constant::NIL;
                break;
            case 5: {
                uint32_t len = rd.varint();
                for (uint32_t k = 0; k < len; ++k) (void)rd.varint();
                c.type = Constant::NIL;
                break;
            }
            case 6:
                (void)rd.varint();
                c.type = Constant::NIL;
                break;
            default:
                for (int k = 0; k < 16 && rd.ok; ++k) (void)rd.u8();
                c.type = Constant::NIL;
                break;
            }
            proto.constants.push_back(std::move(c));
        }

        uint32_t np = rd.varint();
        for (uint32_t i = 0; i < np && rd.ok; ++i)
            proto.childProtos.push_back(rd.varint());

        uint8_t lineGapLog2 = rd.u8();
        if (lineGapLog2) {
            for (uint32_t i = 0; i < ncode && rd.ok; ++i) (void)rd.u8();
            uint32_t intervals = ((ncode - 1) >> lineGapLog2) + 1;
            for (uint32_t i = 0; i < intervals && rd.ok; ++i) (void)rd.u32();
        }

        (void)rd.varint();
        uint32_t locvars = rd.varint();
        for (uint32_t i = 0; i < locvars && rd.ok; ++i) {
            (void)rd.varint();
            (void)rd.varint();
            (void)rd.varint();
            (void)rd.u8();
        }
        uint32_t upvalNames = rd.varint();
        for (uint32_t i = 0; i < upvalNames && rd.ok; ++i) (void)rd.varint();

        if (!rd.ok) {
            err = "function blob truncated at proto " + std::to_string(f);
            return false;
        }

        std::string remapErr;
        if (!remapFunction(luauCode, proto, remapErr)) {
            err = remapErr;
            return false;
        }
        out[f] = std::move(proto);
    }

    mainId = rd.varint();
    if (!rd.ok || mainId >= out.size()) {
        err = "bad main proto id";
        return false;
    }
    return true;
}

bool Translator::remapFunction(const std::vector<uint32_t>& luauCode,
                               Proto& proto,
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
    auto emitConstIndex = [&](uint32_t idx) {
        proto.code.push_back(idx | 0x80000000u);
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
                err = "truncated aux instruction";
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
            emitConstIndex(uint32_t(D));
            break;
        case LOP_MOVE:
            emitABC(Op::MOVE, A, B, 0);
            break;
        case LOP_GETGLOBAL:
            emitABC(Op::GETGLOBAL, A, 0, 0);
            emitConstIndex(aux);
            break;
        case LOP_SETGLOBAL:
            emitABC(Op::SETGLOBAL, A, 0, 0);
            emitConstIndex(aux);
            break;
        case LOP_GETIMPORT: {
            int count = int(aux >> 30);
            int id0 = int((aux >> 20) & 1023);
            int id1 = int((aux >> 10) & 1023);
            if (count <= 1) {
                emitABC(Op::GETGLOBAL, A, 0, 0);
                emitConstIndex(uint32_t(id0));
            } else {
                emitABC(Op::GETGLOBAL, A, 0, 0);
                emitConstIndex(uint32_t(id0));
                emitABC(Op::GETTABLEKS, A, A, 0);
                emitConstIndex(uint32_t(id1));
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
            emitConstIndex(aux);
            break;
        case LOP_SETTABLEKS:
            emitABC(Op::LOADK, 255, 0, 0);
            emitConstIndex(aux);
            emitABC(Op::SETTABLE, A, B, 255);
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
        pc += size_t(len);
    }
    oldToNew[luauCode.size()] = proto.code.size();

    auto remapTarget = [&](int oldTarget) -> size_t {
        if (oldTarget < 0) return 0;
        if (oldTarget >= int(oldToNew.size())) return proto.code.size();
        return oldToNew[size_t(oldTarget)];
    };

    for (const Jump& j : jumps) {
        size_t target = remapTarget(j.oldTarget);
        int32_t rel = int32_t(target) - int32_t(j.patchIndex + 1);
        if (rel < -32768) rel = -32768;
        if (rel > 32767) rel = 32767;
        uint32_t word = proto.code[j.patchIndex];
        proto.code[j.patchIndex] = packAD(insnOp(word), insnA(word), int16_t(rel));
    }
    return true;
}

Bytecode Translator::encodeCustom(const std::vector<Proto>& protos, uint32_t mainId) const {
    std::vector<uint8_t> out;
    auto w8 = [&](uint8_t v) { out.push_back(v); };
    auto w32 = [&](uint32_t v) {
        out.push_back(uint8_t(v));
        out.push_back(uint8_t(v >> 8));
        out.push_back(uint8_t(v >> 16));
        out.push_back(uint8_t(v >> 24));
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
        for (uint32_t w : p.code) w32(w);
        w32(uint32_t(p.constants.size()));
        for (const auto& c : p.constants) {
            w8(uint8_t(c.type));
            if (c.type == Constant::BOOL) {
                w8(c.b ? 1 : 0);
            } else if (c.type == Constant::NUMBER) {
                uint64_t bits = 0;
                std::memcpy(&bits, &c.n, 8);
                for (int i = 0; i < 8; ++i) w8(uint8_t(bits >> (8 * i)));
            } else if (c.type == Constant::STRING) {
                w32(uint32_t(c.s.size()));
                for (unsigned char ch : c.s) w8(ch);
            }
        }
        w32(uint32_t(p.childProtos.size()));
        for (uint32_t id : p.childProtos) w32(id);
    }
    return Bytecode(std::move(out));
}