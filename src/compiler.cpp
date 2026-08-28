#include "compiler.hpp"
#include "luacode.h"
#include <cstring>
#include <cstdlib>

Compiler::Result Compiler::compile(const std::string& source) const {
    Result result;
    if (source.empty()) {
        result.error = "Source is empty";
        return result;
    }
    
    lua_CompileOptions options{};
    options.optimizationLevel = 2;
    options.debugLevel = 0;
    options.typeInfoLevel = 0;
    options.coverageLevel = 0;
    
    size_t bytecodeSize = 0;
    char* compiled = luau_compile(source.data(), source.size(), &options, &bytecodeSize);
    
    if (!compiled || bytecodeSize == 0) {
        result.error = "Luau compile failed";
        if (compiled) std::free(compiled);
        return result;
    }
    
    // Check for error marker (Luau returns bytecode with error string if compilation fails)
    if (bytecodeSize >= 4 && 
        compiled[0] == 'L' && compiled[1] == 'B' && compiled[2] == 'C') {
        // Valid bytecode header
        result.bytecode = Bytecode(std::vector<uint8_t>(compiled, compiled + bytecodeSize));
        result.success = true;
    } else {
        // Error message encoded as string
        std::string errorMsg(compiled, bytecodeSize);
        result.error = errorMsg;
    }
    
    std::free(compiled);
    return result;
}