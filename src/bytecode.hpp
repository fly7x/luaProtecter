#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

class Bytecode
{
public:
    Bytecode() = default;

    explicit Bytecode(std::vector<std::uint8_t> data);

    explicit Bytecode(const std::string& data);

    const std::vector<std::uint8_t>& data() const noexcept;

    std::vector<std::uint8_t>& data() noexcept;

    std::size_t size() const noexcept;

    bool empty() const noexcept;

    void clear() noexcept;

    void append(
        const std::uint8_t* data,
        std::size_t size
    );

    void append(
        const std::vector<std::uint8_t>& data
    );

    std::string asString() const;

private:
    std::vector<std::uint8_t> bytes;
};