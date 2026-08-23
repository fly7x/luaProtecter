#include "vm.hpp"

#include <Luau/Compiler.h>

#include "luacode.h"
#include "lua.h"
#include "lualib.h"

#include <cstdlib>
#include <cstring>
#include <string>

namespace
{
    int writer(
        lua_State*,
        const void* data,
        size_t size,
        void* userdata
    )
    {
        std::string* output =
            static_cast<std::string*>(userdata);

        if (data && size)
        {
            output->append(
                static_cast<const char*>(data),
                size
            );
        }

        return 0;
    }

    std::string getError(lua_State* L)
    {
        const char* message =
            lua_tostring(L, -1);

        if (!message)
            return "Unknown Luau runtime error";

        return message;
    }
}

bool VM::execute(
    const Bytecode& bytecode,
    std::string& output
) const
{
    output.clear();

    const std::vector<std::uint8_t>& data =
        bytecode.data();

    if (data.empty())
    {
        output = "Empty Luau bytecode";
        return false;
    }

    lua_State* L =
        luaL_newstate();

    if (!L)
    {
        output = "Failed to create Luau state";
        return false;
    }

    luaL_openlibs(L);

    /*
     * Keep execution isolated.
     *
     * This is especially useful for the server-side
     * protection pipeline because the state is not
     * shared between requests.
     */
    luaL_sandbox(L);

    const int loadResult =
        luau_load(
            L,
            "@LuaProtecter",
            reinterpret_cast<const char*>(
                data.data()
            ),
            data.size(),
            0
        );

    if (loadResult != 0)
    {
        output =
            "Luau bytecode load failed: " +
            getError(L);

        lua_close(L);
        return false;
    }

    /*
     * Execute the loaded chunk.
     *
     * pcall is used instead of the old
     * luaL_loadbuffer approach.
     */
    const int callResult =
        lua_pcall(
            L,
            0,
            LUA_MULTRET,
            0
        );

    if (callResult != 0)
    {
        output =
            "Luau execution failed: " +
            getError(L);

        lua_close(L);
        return false;
    }

    lua_close(L);

    return true;
}