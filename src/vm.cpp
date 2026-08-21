#include "vm.hpp"

#include <cstdint>
#include <sstream>
#include <stdexcept>
#include <string>

namespace
{
    std::string hex32(std::uint32_t value)
    {
        static constexpr char hex[] =
            "0123456789abcdef";

        std::string out(8, '0');

        for (int i = 7; i >= 0; --i)
        {
            out[static_cast<std::size_t>(i)] =
                hex[value & 0x0Fu];

            value >>= 4;
        }

        return out;
    }
}

bool VM::validate(
    const Bytecode& bytecode,
    std::string& error
) const
{
    error.clear();

    if (bytecode.empty())
    {
        error = "Empty Luau bytecode.";
        return false;
    }

    /*
     * The compiler is responsible for producing valid Luau
     * bytecode.  The VM layer only accepts a non-empty,
     * structurally complete bytecode object.
     */
    if (bytecode.data.empty())
    {
        error = "Luau compiler returned no bytecode.";
        return false;
    }

    return true;
}

std::string VM::package(
    const Bytecode& bytecode
) const
{
    std::string error;

    if (!validate(bytecode, error))
        throw std::runtime_error(error);

    /*
     * Keep the compiled representation binary-safe.
     *
     * Do not convert bytecode into Lua source and do not expose
     * the original source text here.
     */
    std::ostringstream out;

    out << "--!native\n";
    out << "-- Luau compiled payload\n";
    out << "-- payload-size:" << bytecode.data.size() << "\n";
    out << "-- payload-hash:" << hex32(bytecode.hash()) << "\n";

    return out.str();
}