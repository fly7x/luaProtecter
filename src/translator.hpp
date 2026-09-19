#pragma once

#include "isa.hpp"
#include "bytecode.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <array>

// Forward declare Luau Proto (from lobject.h) so headers stay light
struct Proto;

struct FlyConstant {
    enum Type : uint8_t { NIL = 0, BOOL = 1, NUMBER = 2, STRING = 3 };
    Type type = NIL;
    bool b = false;
    double n = 0.0;
    std::string s;
};

struct FlyProto {
    uint8_t maxstack = 0;
    uint8_t numparams = 0;
    uint8_t nups = 0;
    uint8_t isvararg = 0;
    std::vector<uint32_t> code;
    std::vector<FlyConstant> constants;
    std::vector<uint32_t> childProtos;
};

class Translator {
public:
    explicit Translator(uint32_t seed = 0);

    struct Result {
        bool success = false;
        std::string error;
        std::vector<FlyProto> protos;
        uint32_t mainId = 0;
        Bytecode encoded;
    };

    Result translate(const Bytecode& luauBlob) const;

    bool parseLuau(const std::vector<uint8_t>& data,
                   std::vector<FlyProto>& out,
                   uint32_t& mainId,
                   std::string& err) const;

    Bytecode encodeCustom(const std::vector<FlyProto>& protos, uint32_t mainId) const;

    // Remap without Luau Proto* (DUPCLOSURE falls back)
    bool remapPublic(const std::vector<uint32_t>& code,
                     FlyProto& proto,
                     std::string& err) const;

    // Remap with Luau Proto* so DUPCLOSURE can resolve real child index
    bool remapPublic(const std::vector<uint32_t>& code,
                     FlyProto& proto,
                     std::string& err,
                     Proto* luauProto) const;

    bool remapFunction(const std::vector<uint32_t>& luauCode,
                       FlyProto& proto,
                       std::string& err,
                       Proto* luauProto = nullptr) const;

    uint32_t seed() const { return seed_; }
    const std::array<uint8_t, static_cast<size_t>(Op::COUNT)>& map() const { return map_; }

private:
    uint32_t seed_;
    std::array<uint8_t, static_cast<size_t>(Op::COUNT)> map_;

    // Optional reader stubs (kept for compatibility with older code)
    struct Reader {
        uint8_t u8();
        uint32_t u32();
        uint32_t varint();
        std::string bytes(uint32_t n);
    };
};