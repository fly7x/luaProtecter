#pragma once

#include "bytecode.hpp"
#include "isa.hpp"
#include <cstdint>
#include <string>
#include <vector>

struct Constant {
    enum Type { NIL = 0, BOOL = 1, NUMBER = 2, STRING = 3 } type = NIL;
    bool b = false;
    double n = 0.0;
    std::string s;
};

struct Proto {
    uint8_t maxstack = 2;
    uint8_t numparams = 0;
    uint8_t nups = 0;
    uint8_t isvararg = 0;
    std::vector<uint32_t> code;
    std::vector<Constant> constants;
    std::vector<uint32_t> childProtos;
};

class Translator {
public:
    struct Result {
        bool success = false;
        std::string error;
        std::vector<Proto> protos;
        uint32_t mainId = 0;
        Bytecode encoded;
    };

    explicit Translator(uint32_t seed);
    Result translate(const Bytecode& luauBlob) const;

private:
    uint32_t seed_;
    std::array<uint8_t, static_cast<size_t>(Op::COUNT)> map_;

    struct Reader {
        const uint8_t* p = nullptr;
        const uint8_t* end = nullptr;
        bool ok = true;

        uint8_t u8();
        uint32_t u32();
        uint32_t varint();
        std::string bytes(uint32_t n);
    };

    bool parseLuau(const std::vector<uint8_t>& data,
                   std::vector<Proto>& out,
                   uint32_t& mainId,
                   std::string& err) const;

    bool remapFunction(const std::vector<uint32_t>& luauCode,
                       Proto& proto,
                       std::string& err) const;

    Bytecode encodeCustom(const std::vector<Proto>& protos, uint32_t mainId) const;
};