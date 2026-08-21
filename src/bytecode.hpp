#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class Bytecode
{
public:
    Bytecode() = default;

    explicit Bytecode(const std::string& data);

    explicit Bytecode(std::vector<std::uint8_t> data);

    const std::vector<std::uint8_t>& data() const noexcept;

    std::size_t size() const noexcept;

    bool empty() const noexcept;

    std::string toBase64() const;

    static Bytecode fromBase64(
        const std::string& encoded
    );

private:
    std::vector<std::uint8_t> bytes;
};