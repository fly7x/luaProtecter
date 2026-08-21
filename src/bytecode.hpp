#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <utility>

class Bytecode
{
public:
    Bytecode() = default;

    explicit Bytecode(
        std::vector<std::uint8_t> data
    )
        : data_(std::move(data))
    {
    }

    explicit Bytecode(
        const std::string& data
    )
        : data_(
            data.begin(),
            data.end()
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

    std::string toString() const
    {
        return std::string(
            reinterpret_cast<const char*>(
                data_.data()
            ),
            data_.size()
        );
    }

private:
    std::vector<std::uint8_t> data_;
};