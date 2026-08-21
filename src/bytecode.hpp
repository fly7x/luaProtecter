#pragma once

#include <cstdint>
#include <vector>

class Bytecode
{
public:
    Bytecode() = default;

    explicit Bytecode(
        std::vector<std::uint8_t> data
    )
        : data_(
            std::move(data)
        )
    {
    }

    const std::vector<std::uint8_t>& data() const
    {
        return data_;
    }

    std::vector<std::uint8_t>& data()
    {
        return data_;
    }

    bool empty() const
    {
        return data_.empty();
    }

    std::size_t size() const
    {
        return data_.size();
    }

private:
    std::vector<std::uint8_t> data_;
};