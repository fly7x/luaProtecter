#pragma once

#include <string>
#include <cstdint>

namespace Protect {

struct AstOptions {
    bool validateCompile = true;  // also run official Luau compile
    bool stripComments = false;   // keep false for pure pass-through tests
    bool addBanner = true;
};

struct AstResult {
    bool success = false;
    std::string code;
    std::string error;
};

// Step 1: parse with Luau AST. Zero transforms → output runs like original.
AstResult astPassThrough(const std::string& source, const AstOptions& options = {});

} // namespace Protect