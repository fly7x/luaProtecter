#pragma once

#include "bytecode.hpp"
#include "isa.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// Forward-declare Luau Proto (from lobject.h) without forcing full includes here
struct Proto;

class Translator {
public:
    struct Result {
        bool success = false;
        std::string error;
        std::vector<Protect::FlyProto> protos;
        uint32_t mainId = 0;
        Bytecode encoded;
    };

    explicit Translator(uint32_t seed = 0);

    Result translate(const Bytecode& luauBlob) const;

    bool remapPublic(const std::vector<uint32_t>& code,
                     Protect::FlyProto& proto,
                     std::string& err) const;

    bool remapPublic(const std::vector<uint32_t>& code,
                     Protect::FlyProto& proto,
                     std::string& err,
                     Proto* luauProto) const;

    Bytecode encodeCustom(const std::vector<Protect::FlyProto>& protos,
                          uint32_t mainId) const;

    const std::array<uint8_t, static_cast<size_t>(Protect::Op::COUNT)>& map() const {
        return map_;
    }

private:
    struct Reader {
        uint8_t u8();
        uint32_t u32();
        uint32_t varint();
        std::string bytes(uint32_t n);
    };

    bool remapFunction(const std::vector<uint32_t>& luauCode,
                       Protect::FlyProto& proto,
                       std::string& err,
                       Proto* luauProto) const;

    bool parseLuau(const std::vector<uint8_t>& data,
                   std::vector<Protect::FlyProto>& out,
                   uint32_t& mainId,
                   std::string& err) const;

    uint32_t seed_;
    std::array<uint8_t, static_cast<size_t>(Protect::Op::COUNT)> map_;
};