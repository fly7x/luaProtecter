#include "compiler.hpp"
#include "luacode.h"
#include "Luau/Bytecode.h"
#include <cstring>
#include <cstdlib>
#include <cstdint>

Compiler::Result Compiler::compile(const std::string& source) const {
    Result result;
    if (source.empty()) {
        result.error = "Source is empty";
        return result;
    }

    lua_CompileOptions options{};
    options.optimizationLevel = 1;
    options.debugLevel = 0;
    options.typeInfoLevel = 0;
    options.coverageLevel = 0;

    size_t bytecodeSize = 0;
    char* compiled = luau_compile(source.data(), source.size(), &options, &bytecodeSize);

    if (!compiled || bytecodeSize == 0) {
        result.error = "Luau compile returned nothing";
        if (compiled) std::free(compiled);
        return result;
    }

    unsigned char version = static_cast<unsigned char>(compiled[0]);
    bool looksLikeBytecode = version >= LBC_VERSION_MIN && version <= LBC_VERSION_MAX;

    if (!looksLikeBytecode) {
        result.error.assign(compiled, compiled + bytecodeSize);
        std::free(compiled);
        return result;
    }

    result.bytecode = Bytecode(std::vector<uint8_t>(
        reinterpret_cast<uint8_t*>(compiled),
        reinterpret_cast<uint8_t*>(compiled) + bytecodeSize
    ));
    result.success = true;
    std::free(compiled);
    return result;
}