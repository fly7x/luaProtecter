#include "vm.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "Luau/Compiler.h"
#include "lua.h"
#include "lualib.h"

namespace
{
    constexpr std::uint32_t MAGIC = 0x31564D4Cu; // LVM1
    constexpr std::uint8_t VERSION = 1;

    constexpr std::size_t HEADER_SIZE = 13;

    bool readU32(
        const std::vector<std::uint8_t>& data,
        std::size_t& position,
        std::uint32_t& value
    )
    {
        if (position > data.size() ||
            data.size() - position < 4)
        {
            return false;
        }

        value =
            static_cast<std::uint32_t>(data[position]) |
            (static_cast<std::uint32_t>(data[position + 1]) << 8) |
            (static_cast<std::uint32_t>(data[position + 2]) << 16) |
            (static_cast<std::uint32_t>(data[position + 3]) << 24);

        position += 4;
        return true;
    }

    std::uint32_t mix32(
        std::uint32_t value
    )
    {
        value ^= value >> 16;
        value *= 0x7FEB352Du;
        value ^= value >> 15;
        value *= 0x846CA68Bu;
        value ^= value >> 16;

        return value;
    }

    std::uint8_t keyByte(
        std::uint32_t seed,
        std::size_t position
    )
    {
        const std::uint32_t index =
            static_cast<std::uint32_t>(position);

        std::uint32_t state =
            seed ^
            (index * 0x9E3779B9u);

        state = mix32(state);

        return static_cast<std::uint8_t>(
            state & 0xFFu
        );
    }

    bool unwrap(
        const Bytecode& package,
        std::vector<std::uint8_t>& recovered,
        std::string& error
    )
    {
        const auto& data = package.data();

        if (data.size() < HEADER_SIZE)
        {
            error = "Protected bytecode is too small";
            return false;
        }

        std::size_t position = 0;

        std::uint32_t magic = 0;

        if (!readU32(data, position, magic))
        {
            error = "Invalid protected bytecode header";
            return false;
        }

        if (magic != MAGIC)
        {
            error = "Invalid LVM package";
            return false;
        }

        const std::uint8_t version =
            data[position++];

        if (version != VERSION)
        {
            error = "Unsupported LVM package version";
            return false;
        }

        std::uint32_t seed = 0;

        if (!readU32(data, position, seed))
        {
            error = "Missing LVM seed";
            return false;
        }

        std::uint32_t originalSize = 0;

        if (!readU32(
                data,
                position,
                originalSize
            ))
        {
            error = "Missing LVM bytecode size";
            return false;
        }

        const std::size_t payloadSize =
            data.size() - position;

        if (
            static_cast<std::size_t>(
                originalSize
            ) != payloadSize
        )
        {
            error = "Protected bytecode size mismatch";
            return false;
        }

        recovered.resize(payloadSize);

        for (
            std::size_t i = 0;
            i < payloadSize;
            ++i
        )
        {
            recovered[i] =
                static_cast<std::uint8_t>(
                    data[position + i] ^
                    keyByte(seed, i)
                );
        }

        return true;
    }

    std::string luaError(
        lua_State* state
    )
    {
        const char* message =
            lua_tostring(
                state,
                -1
            );

        if (!message)
            return "Luau execution failed";

        return message;
    }
}

bool VM::execute(
    const Bytecode& bytecode,
    std::string& output
) const
{
    output.clear();

    std::vector<std::uint8_t> recovered;

    std::string error;

    if (!unwrap(
            bytecode,
            recovered,
            error
        ))
    {
        output = error;
        return false;
    }

    if (recovered.empty())
    {
        output = "Recovered Luau bytecode is empty";
        return false;
    }

    /*
     * Create a real Luau state.
     */
    lua_State* state =
        luaL_newstate();

    if (!state)
    {
        output = "Failed to create Luau state";
        return false;
    }

    luaL_openlibs(state);

    /*
     * The recovered data is Luau bytecode.
     *
     * luaL_loadbuffer is intentionally used here instead
     * of interpreting individual instructions ourselves.
     */
    const int loadResult =
        luaL_loadbuffer(
            state,
            reinterpret_cast<const char*>(
                recovered.data()
            ),
            recovered.size(),
            "@protected"
        );

    if (loadResult != 0)
    {
        output = luaError(state);

        lua_close(state);

        return false;
    }

    /*
     * Execute the loaded Luau chunk.
     */
    const int callResult =
        lua_pcall(
            state,
            0,
            LUA_MULTRET,
            0
        );

    if (callResult != 0)
    {
        output = luaError(state);

        lua_close(state);

        return false;
    }

    /*
     * Collect returned values as a basic diagnostic.
     *
     * Normal print() output should be redirected through
     * a custom print function if the HTTP API needs to
     * capture it.
     */
    const int resultCount =
        lua_gettop(state);

    if (resultCount > 0)
    {
        for (int i = 1; i <= resultCount; ++i)
        {
            if (i > 1)
                output += '\n';

            if (lua_isstring(state, i))
            {
                output +=
                    lua_tostring(state, i);
            }
            else
            {
                output +=
                    luaL_tolstring(
                        state,
                        i,
                        nullptr
                    );

                lua_pop(state, 1);
            }
        }
    }

    lua_close(state);

    return true;
}