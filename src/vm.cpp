#include "vm.hpp"

#include <lua.h>
#include <lualib.h>

#include <stdexcept>
#include <string>

namespace
{
    void* luaAllocator(
        void*,
        void* ptr,
        size_t,
        size_t newSize
    )
    {
        if (newSize == 0)
        {
            std::free(ptr);
            return nullptr;
        }

        return std::realloc(
            ptr,
            newSize
        );
    }

    int capturePrint(
        lua_State* L
    )
    {
        void* context =
            lua_getthreaddata(L);

        if (!context)
            return 0;

        auto* output =
            static_cast<std::string*>(
                context
            );

        const int count =
            lua_gettop(L);

        for (int i = 1; i <= count; ++i)
        {
            if (i > 1)
                output->push_back('\t');

            size_t length = 0;

            const char* value =
                luaL_tolstring(
                    L,
                    i,
                    &length
                );

            if (value)
            {
                output->append(
                    value,
                    length
                );
            }

            lua_pop(L, 1);
        }

        output->push_back('\n');

        return 0;
    }
}

bool VM::execute(
    const Bytecode& bytecode,
    std::string& output
) const
{
    output.clear();

    if (bytecode.empty())
    {
        output =
            "Bytecode is empty";

        return false;
    }

    lua_State* L =
        lua_newstate(
            luaAllocator,
            nullptr
        );

    if (!L)
    {
        output =
            "Failed to create Luau state";

        return false;
    }

    luaL_openlibs(L);

    /*
     * Luau's thread data gives us a small place to
     * associate our output buffer with this execution.
     */
    lua_setthreaddata(
        L,
        &output
    );

    /*
     * Load the compiled Luau bytecode.
     */
    const int loadResult =
        luau_load(
            L,
            "@protected",
            reinterpret_cast<const char*>(
                bytecode.data().data()
            ),
            bytecode.size(),
            0
        );

    if (loadResult != 0)
    {
        const char* error =
            lua_tostring(
                L,
                -1
            );

        output =
            error
                ? error
                : "Luau bytecode load failed";

        lua_close(L);

        return false;
    }

    /*
     * Execute the loaded chunk.
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
        const char* error =
            lua_tostring(
                L,
                -1
            );

        output =
            error
                ? error
                : "Luau runtime error";

        lua_close(L);

        return false;
    }

    lua_close(L);

    return true;
}