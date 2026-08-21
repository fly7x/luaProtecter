#include "bytecode.hpp"

#include <stdexcept>
#include <string>
#include <utility>

namespace
{
    constexpr char BASE64_TABLE[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    int base64Value(char c)
    {
        if (c >= 'A' && c <= 'Z')
            return c - 'A';

        if (c >= 'a' && c <= 'z')
            return c - 'a' + 26;

        if (c >= '0' && c <= '9')
            return c - '0' + 52;

        if (c == '+')
            return 62;

        if (c == '/')
            return 63;

        return -1;
    }
}

Bytecode::Bytecode(const std::string& data)
    : bytes(data.begin(), data.end())
{
}

Bytecode::Bytecode(std::vector<std::uint8_t> data)
    : bytes(std::move(data))
{
}

const std::vector<std::uint8_t>&
Bytecode::data() const noexcept
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

std::string
Bytecode::toBase64() const
{
    std::string output;

    output.reserve(
        ((bytes.size() + 2) / 3) * 4
    );

    std::size_t i = 0;

    while (i + 2 < bytes.size())
    {
        const std::uint32_t value =
            (static_cast<std::uint32_t>(bytes[i]) << 16) |
            (static_cast<std::uint32_t>(bytes[i + 1]) << 8) |
            static_cast<std::uint32_t>(bytes[i + 2]);

        output.push_back(
            BASE64_TABLE[(value >> 18) & 0x3F]
        );

        output.push_back(
            BASE64_TABLE[(value >> 12) & 0x3F]
        );

        output.push_back(
            BASE64_TABLE[(value >> 6) & 0x3F]
        );

        output.push_back(
            BASE64_TABLE[value & 0x3F]
        );

        i += 3;
    }

    const std::size_t remaining =
        bytes.size() - i;

    if (remaining == 1)
    {
        const std::uint32_t value =
            static_cast<std::uint32_t>(bytes[i]) << 16;

        output.push_back(
            BASE64_TABLE[(value >> 18) & 0x3F]
        );

        output.push_back(
            BASE64_TABLE[(value >> 12) & 0x3F]
        );

        output.push_back('=');
        output.push_back('=');
    }
    else if (remaining == 2)
    {
        const std::uint32_t value =
            (static_cast<std::uint32_t>(bytes[i]) << 16) |
            (static_cast<std::uint32_t>(bytes[i + 1]) << 8);

        output.push_back(
            BASE64_TABLE[(value >> 18) & 0x3F]
        );

        output.push_back(
            BASE64_TABLE[(value >> 12) & 0x3F]
        );

        output.push_back(
            BASE64_TABLE[(value >> 6) & 0x3F]
        );

        output.push_back('=');
    }

    return output;
}

Bytecode
Bytecode::fromBase64(
    const std::string& encoded
)
{
    if (encoded.empty())
        return Bytecode{};

    if (encoded.size() % 4 != 0)
    {
        throw std::runtime_error(
            "Invalid Base64 length"
        );
    }

    std::vector<std::uint8_t> output;

    output.reserve(
        (encoded.size() / 4) * 3
    );

    for (
        std::size_t i = 0;
        i < encoded.size();
        i += 4
    )
    {
        const char a = encoded[i];
        const char b = encoded[i + 1];
        const char c = encoded[i + 2];
        const char d = encoded[i + 3];

        const int va = base64Value(a);
        const int vb = base64Value(b);

        if (va < 0 || vb < 0)
        {
            throw std::runtime_error(
                "Invalid Base64 character"
            );
        }

        const int vc =
            c == '=' ? 0 : base64Value(c);

        const int vd =
            d == '=' ? 0 : base64Value(d);

        if (c != '=' && vc < 0)
        {
            throw std::runtime_error(
                "Invalid Base64 character"
            );
        }

        if (d != '=' && vd < 0)
        {
            throw std::runtime_error(
                "Invalid Base64 character"
            );
        }

        const std::uint32_t value =
            (static_cast<std::uint32_t>(va) << 18) |
            (static_cast<std::uint32_t>(vb) << 12) |
            (static_cast<std::uint32_t>(vc) << 6) |
            static_cast<std::uint32_t>(vd);

        output.push_back(
            static_cast<std::uint8_t>(
                (value >> 16) & 0xFF
            )
        );

        if (c != '=')
        {
            output.push_back(
                static_cast<std::uint8_t>(
                    (value >> 8) & 0xFF
                )
            );
        }

        if (d != '=')
        {
            output.push_back(
                static_cast<std::uint8_t>(
                    value & 0xFF
                )
            );
        }
    }

    return Bytecode(std::move(output));
}