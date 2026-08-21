#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class Bytecode
{
public:
    Bytecode() = default;

    explicit Bytecode(
        const std::string& data
    );

    explicit Bytecode(
        std::vector<std::uint8_t> data
    );

    const std::vector<std::uint8_t>& data() const noexcept;

    std::size_t size() const noexcept;

    bool empty() const noexcept;

    /*
     * Encode the binary Luau bytecode into text that can safely
     * travel through JSON/HTTP.
     */
    std::string toBase64() const;

    /*
     * Decode a Base64 payload back into binary bytecode.
     */
    static Bytecode fromBase64(
        const std::string& encoded
    );

private:
    std::vector<std::uint8_t> bytes;
};