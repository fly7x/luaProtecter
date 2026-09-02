#include "translator.hpp"
#include <cstring>
#include <cmath>

Translator::Translator(uint32_t seed)
    : seed_(seed ? seed : 0xA341316C), map_(makeOpcodeMap(seed_)) {}

uint8_t Translator::Reader::u8() {
    if (p >= end) { ok = false; return 0; }
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
        if ((b & 0x80) == 0) break;
        shift += 7;
        if (shift > 28) { ok = false; return 0; }
    }
    return result;
}
std::string Translator::Reader::str(uint32_t n) {
    if (!ok || p + n > end) { ok = false; return {}; }
    std::string s(reinterpret_cast<const char*>(p), n);
    p += n;
    return s;
}

static uint8_t luauOp(uint32_t insn) { return uint8_t(insn & 0xFF); }
static uint8_t luauA(uint32_t insn)  { return uint8_t((insn >> 8) & 0xFF); }
static uint8_t luauB(uint32_t insn)  { return uint8_t((insn >> 16) & 0xFF); }
static uint8_t luauC(uint32_t insn)  { return uint8_t((insn >> 24) & 0xFF); }
static int16_t luauD(uint32_t insn)  { return int16_t(insn >> 16); }

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
    Reader rd{ data.data(), data.data() + data.size() };

    uint8_t version = rd.u8();
    if (!rd.ok || version < 3 || version > 6) {
        // current Luau LBC versions are in this range; bump if needed
        err = "unsupported luau bytecode version: " + std::to_string(version);
        return false;
    }

    // types version exists on newer blobs
    if (version >= 4) {
        (void)rd.u8();
    }

    uint32_t nstrings = rd.varint();
    std::vector<std::string> strings;
    strings.reserve(nstrings);
    for (uint32_t i = 0; i < nstrings && rd.ok; ++i) {
        uint32_t len = rd.varint();
        strings.push_back(rd.str(len));
    }
    if (!rd.ok) { err = "string table truncated"; return false; }

    uint32_t nfuncs = rd.varint();
    if (!rd.ok || nfuncs == 0) { err = "no functions"; return false; }

    out.resize(nfuncs);

    for (uint32_t f = 0; f < nfuncs; ++f) {
        Proto proto;
        proto.maxstack  = rd.u8();
        proto.numparams = rd.u8();
        proto.nups      = rd.u8();
        proto.isvararg  = rd.u8();
        uint8_t flags   = rd.u8();
        (void)flags;

        uint32_t typeSize = rd.varint();
        (void)rd.str(typeSize); // skip typeinfo

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
            case 0: c.type = Constant::NIL; break;          // LBC_CONSTANT_NIL
            case 1: c.type = Constant::BOOL; c.b = rd.u8() != 0; break;
            case 2: {                                       // number
                c.type = Constant::NUMBER;
                uint64_t bits = 0;
                for (int b = 0; b < 8; ++b) bits |= uint64_t(rd.u8()) << (8 * b);
                std::memcpy(&c.n, &bits, 8);
                break;
            }
            case 3: {                                       // string index
                c.type = Constant::STRING;
                uint32_t idx = rd.varint();
                if (idx == 0 || idx > strings.size()) { err = "bad string const"; return false; }
                c.s = strings[idx - 1];
                break;
            }
            case 4: case 5: case 6: case 7: {               // import / table / closure later
                // skip payload we don't use yet
                if (tag == 4) { (void)rd.u32(); }           // import
                else if (tag == 5) {                        // table
                    uint32_t len = rd.varint();
                    for (uint32_t k = 0; k < len; ++k) (void)rd.varint();
                } else if (tag == 6) { (void)rd.u32(); }     // closure
                else { /* vector: 3 or 4 floats depending on version */ 
                    for (int k = 0; k < 4; ++k) {
                        for (int b = 0; b < 4; ++b) (void)rd.u8();
                    }
                }
                c.type = Constant::NIL;
                break;
            }
            default:
                err = "unknown constant tag " + std::to_string(tag);
                return false;
            }
            proto.constants.push_back(std::move(c));
        }

        uint32_t np = rd.varint();
        for (uint32_t i = 0; i < np && rd.ok; ++i)
            proto.childProtos.push_back(rd.varint());

        // skip lineinfo + debug
        uint32_t lineGap = rd.u8();
        uint32_t absLineInfoCount = rd.varint();
        for (uint32_t i = 0; i < ncode && rd.ok; ++i) (void)rd.u8(); // line deltas
        for (uint32_t i = 0; i < absLineInfoCount && rd.ok; ++i) (void)rd.u32();
        (void)lineGap;

        uint32_t locvars = rd.varint();
        for (uint32_t i = 0; i < locvars && rd.ok; ++i) {
            (void)rd.varint(); (void)rd.varint(); (void)rd.varint(); (void)rd.u8();
        }
        uint32_t upvalNames = rd.varint();
        for (uint32_t i = 0; i < upvalNames && rd.ok; ++i) (void)rd.varint();

        if (!rd.ok) { err = "function blob truncated"; return false; }

        std::string remapErr;
        if (!remapFunction(luauCode, proto, proto.constants, remapErr)) {
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
                               const std::vector<Constant>& k,
                               std::string& err) const {
    auto mop = [&](Op o) { return map_[static_cast<size_t>(o)]; };

    for (size_t pc = 0; pc < luauCode.size(); ) {
        uint32_t insn = luauCode[pc++];
        uint8_t op = luauOp(insn);
        uint8_t A = luauA(insn);
        uint8_t B = luauB(insn);
        uint8_t C = luauC(insn);
        int16_t D = luauD(insn);

        // Luau opcodes (stable-ish subset). See Luau/Bytecode.h.
        switch (op) {
        case 2: // LOADNIL
            proto.code.push_back(packABC(mop(Op::LOADNIL), A, A, 0));
            break;
        case 3: // LOADB  A, B, C   R[A]=bool(B); pc += C
            proto.code.push_back(packABC(mop(Op::LOADBOOL), A, B, 0));
            if (C != 0) proto.code.push_back(packAD(mop(Op::JMP), 0, int16_t(C)));
            break;
        case 4: // LOADN  A, D      R[A]=D
            proto.code.push_back(packABC(mop(Op::LOADK), A, 0, 0));
            proto.code.push_back(uint32_t(int32_t(D))); // immediate as next word
            break;
        case 5: { // LOADK A, D     R[A]=K[D]
            proto.code.push_back(packABC(mop(Op::LOADK), A, 0, 0));
            if (D < 0 || size_t(D) >= k.size()) { err = "LOADK out of range"; return false; }
            // store constant index as next word; VM looks it up
            proto.code.push_back(uint32_t(D) | 0x80000000u); // high bit = const pool
            break;
        }
        case 6: // MOVE A, B
            proto.code.push_back(packABC(mop(Op::MOVE), A, B, 0));
            break;
        case 7: // GETGLOBAL A, D + AUX
            if (pc >= luauCode.size()) { err = "GETGLOBAL missing aux"; return false; }
            proto.code.push_back(packABC(mop(Op::GETGLOBAL), A, 0, 0));
            proto.code.push_back(luauCode[pc++]); // aux = string const index
            break;
        case 8: // SETGLOBAL A, D + AUX
            if (pc >= luauCode.size()) { err = "SETGLOBAL missing aux"; return false; }
            proto.code.push_back(packABC(mop(Op::SETGLOBAL), A, 0, 0));
            proto.code.push_back(luauCode[pc++]);
            break;
        case 12: // GETTABLE A B C   R[A]=R[B][R[C]]
            proto.code.push_back(packABC(mop(Op::GETTABLE), A, B, C));
            break;
        case 13: // SETTABLE
            proto.code.push_back(packABC(mop(Op::SETTABLE), A, B, C));
            break;
        case 18: // NEWTABLE A B C + AUX
            if (pc >= luauCode.size()) { err = "NEWTABLE missing aux"; return false; }
            proto.code.push_back(packABC(mop(Op::NEWTABLE), A, B, C));
            proto.code.push_back(luauCode[pc++]);
            break;
        case 20: // ADD A B C
            proto.code.push_back(packABC(mop(Op::ADD), A, B, C));
            break;
        case 21: // SUB
            proto.code.push_back(packABC(mop(Op::SUB), A, B, C));
            break;
        case 22: // MUL
            proto.code.push_back(packABC(mop(Op::MUL), A, B, C));
            break;
        case 23: // DIV
            proto.code.push_back(packABC(mop(Op::DIV), A, B, C));
            break;
        case 25: // MOD
            proto.code.push_back(packABC(mop(Op::MOD), A, B, C));
            break;
        case 26: // POW
            proto.code.push_back(packABC(mop(Op::POW), A, B, C));
            break;
        case 51: // JUMP  D
            proto.code.push_back(packAD(mop(Op::JMP), 0, D));
            break;
        case 52: case 53: // JUMPIF / JUMPIFNOT  treat as EQ-style later
            proto.code.push_back(packAD(mop(Op::JMP), 0, D));
            break;
        case 65: // CALL A B C
            proto.code.push_back(packABC(mop(Op::CALL), A, B, C));
            break;
        case 66: // RETURN A B
            proto.code.push_back(packABC(mop(Op::RETURN), A, B, 0));
            break;
        case 75: // FORNPREP
            proto.code.push_back(packAD(mop(Op::FORPREP), A, D));
            break;
        case 76: // FORNLOOP
            proto.code.push_back(packAD(mop(Op::FORLOOP), A, D));
            break;
        case 79: // DUPCLOSURE / NEWCLOSURE-ish
            proto.code.push_back(packABC(mop(Op::CLOSURE), A, 0, 0));
            proto.code.push_back(uint32_t(int32_t(D)));
            break;
        case 80: // PREPVARARGS
            break; // no-op in our simple VM
        case 81: // LOADVX / VARARG
            proto.code.push_back(packABC(mop(Op::VARARG), A, B, 0));
            break;
        case 0: case 1: // NOP / BREAK
            break;
        default:
            // skip unknown (FASTCALL, IMPORT, GETTABLEN, etc.) for now
            // if opcode has AUX we may desync — this is the next thing to harden
            break;
        }
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

    w32(0x3252504C); // "LPR2"
    w32(seed_);
    w8(1);
    w32(uint32_t(protos.size()));
    w32(mainId);

    for (const auto& p : protos) {
        w8(p.maxstack); w8(p.numparams); w8(p.nups); w8(p.isvararg);
        w32(uint32_t(p.code.size()));
        for (uint32_t w : p.code) w32(w);

        w32(uint32_t(p.constants.size()));
        for (const auto& c : p.constants) {
            w8(uint8_t(c.type));
            if (c.type == Constant::BOOL) w8(c.b ? 1 : 0);
            else if (c.type == Constant::NUMBER) {
                uint64_t bits = 0;
                std::memcpy(&bits, &c.n, 8);
                for (int i = 0; i < 8; ++i) w8(uint8_t(bits >> (8 * i)));
            } else if (c.type == Constant::STRING) {
                w32(uint32_t(c.s.size()));
                for (char ch : c.s) w8(uint8_t(ch));
            }
        }

        w32(uint32_t(p.childProtos.size()));
        for (uint32_t id : p.childProtos) w32(id);
    }
    return Bytecode(std::move(out));
}