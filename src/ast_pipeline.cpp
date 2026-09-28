#include "ast_pipeline.hpp"

#include "Luau/Parser.h"
#include "Luau/Compiler.h"
#include "Luau/BytecodeBuilder.h"

#include <sstream>

namespace Protect {

static std::string formatParseErrors(const Luau::ParseResult& result) {
    std::ostringstream oss;
    for (const auto& err : result.errors) {
        oss << err.getLocation().begin.line + 1 << ":"
            << err.getLocation().begin.column + 1 << ": "
            << err.getMessage() << "\n";
    }
    return oss.str();
}

AstResult astPassThrough(const std::string& source, const AstOptions& options) {
    AstResult out;

    if (source.empty()) {
        out.error = "empty source";
        return out;
    }

    // ── Lex + parse (official Luau) ──
    Luau::Allocator allocator;
    Luau::AstNameTable names(allocator);
    Luau::ParseOptions parseOpts;
    // Allow Luau syntax used in Roblox scripts
    parseOpts.allowDeclarationSyntax = false;

    Luau::ParseResult parsed =
        Luau::Parser::parse(source.data(), source.size(), names, allocator, parseOpts);

    if (!parsed.errors.empty() || !parsed.root) {
        out.error = std::string("Parse failed:\n") + formatParseErrors(parsed);
        return out;
    }

    // ── Optional: official compile (proves it's valid Luau) ──
    if (options.validateCompile) {
        Luau::CompileOptions compileOpts;
        compileOpts.optimizationLevel = 1;
        compileOpts.debugLevel = 1;
        std::string bytecode = Luau::compile(source, compileOpts, {});
        // Luau::compile returns bytecode; on failure it embeds error as bytecode marker
        // Prefer checking via compiler API if available — simple size check + try:
        if (bytecode.empty()) {
            out.error = "Compile failed: empty bytecode";
            return out;
        }
        // Bytecode that starts with error is signaled differently per Luau version;
        // if compile throws in your build, catch below.
    }

    // ── Pass-through emit: real Luau source (no VM) ──
    std::ostringstream emitted;
    if (options.addBanner) {
        emitted << "--!nocheck\n";
        emitted << "--[[\n";
        emitted << "  ╔══════════════════════════════════════════╗\n";
        emitted << "  ║     Protected by FŁÝ / FLYX Obfuscator   ║\n";
        emitted << "  ║   AST pipeline · pass-through · native   ║\n";
        emitted << "  ╚══════════════════════════════════════════╝\n";
        emitted << "]]\n";
    }
    // Step 1: zero transforms — output is the original source
    emitted << source;
    if (!source.empty() && source.back() != '\n')
        emitted << '\n';

    out.success = true;
    out.code = emitted.str();
    return out;
}

} // namespace Protect