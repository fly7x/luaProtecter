#include "bytecode.hpp"

#include <stdexcept>
#include <utility>

Bytecode::Bytecode(
    std::vector<std::uint8_t> data
)
    : bytes(std::move(data))
{
}

Bytecode::Bytecode(
    const std::string& data
)
    : bytes(
        data.begin(),
        data.end()
    )
{
}

const std::vector<std::uint8_t>&
Bytecode::data() const noexcept
{
    return bytes;
}

std::vector<std::uint8_t>&
Bytecode::data() noexcept
{
    return bytes;
}

std::size_t
Bytecode::size() const noexcept
{
    return bytes.size();
}

bool
Bytecode::empty() const noexcept
{
    return bytes.empty();
}

void
Bytecode::clear() noexcept
{
    bytes.clear();
}

void
Bytecode::append(
    const std::uint8_t* data,
    std::size_t size
)
{
    if (data == nullptr && size != 0)
    {
        throw std::invalid_argument(
            "Bytecode::append received null data"
        );
    }

    bytes.insert(
        bytes.end(),
        data,
        data + size
    );
}

void
Bytecode::append(
    const std::vector<std::uint8_t>& data
)
{
    bytes.insert(
        bytes.end(),
        data.begin(),
        data.end()
    );
}

std::string
Bytecode::asString() const
{
    return std::string(
        reinterpret_cast<const char*>(bytes.data()),
        bytes.size()
    );
}