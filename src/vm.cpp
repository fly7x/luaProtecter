#include "vm.hpp"
#include <Luau/Compiler.h>
#include <lua.h>
#include <lauxlib.h>
#include <luacode.h>
#include <stdexcept>
#include <string>
namespace
{
    /*
     * Lua print replacement used by the embedded VM.
     *
     * We capture print() output instead of writing directly
     * to stdout so the HTTP server can return it.
     */
    struct ExecutionContext
    {
        std::string* output = nullptr;
    };
    void appendValue(
        lua_State* state,
        std::string& output,
        int index
    )
    {
        const char* value =
            luaL_tolstring(
                state,
                index,
                nullptr
            );
        if (value != nullptr)
        {
            if (!output.empty())
                output += '\t';
            output += value;
        }
        lua_pop(state, 1);
    }
    int protectedPrint(
        lua_State* state
    )
    {
        ExecutionContext* context =
            static_cast<ExecutionContext*>(
                lua_getthreaddata(state)
            );
        if (
            context == nullptr ||
            context->output == nullptr
        )
        {
            return 0;
        }
        const int count =
            lua_gettop(state);
        for (int i = 1; i <= count; ++i)
        {
            appendValue(
                state,
                *context->output,
                i
            );
        }
        *context->output += '\n';
        return 0;
    }
    void installPrint(
        lua_State* state,
        ExecutionContext& context
    )
    {
        lua_setthreaddata(
            state,
            &context
        );
        lua_pushcfunction(
            state,
            protectedPrint,
            "print"
        );
        lua_setglobal(
            state,
            "print"
        );
    }
    std::string getError(
        lua_State* state
    )
    {
        const char* message =
            lua_tostring(
                state,
                -1
            );
        if (message == nullptr)
            return "Unknown Luau runtime error";
        return std::string(message);
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
            "Luau bytecode is empty";
        return false;
    }
    lua_State* state =
        luaL_newstate();
    if (state == nullptr)
    {
        output =
            "Failed to create Luau VM state";
        return false;
    }
    try
    {
        /*
         * Open the standard Luau libraries.
         *
         * If this service is intended to execute untrusted
         * input, replace this with an explicitly restricted
         * library set rather than exposing the full standard
         * environment.
         */
        luaL_openlibs(state);
        ExecutionContext context;
        context.output = &output;
        installPrint(
            state,
            context
        );
        /*
         * Load the REAL Luau bytecode.
         *
         * This is not our previous LVM1 format.
         */
        const std::vector<std::uint8_t>& bytes =
            bytecode.data();
        const int loadResult =
            luau_load(
                state,
                "=protected",
                reinterpret_cast<const char*>(
                    bytes.data()
                ),
                bytes.size(),
                0
            );
        if (loadResult != 0)
        {
            output =
                "Luau bytecode load failed: " +
                getError(state);
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
            const std::string error =
                getError(state);
            output +=
                "Luau runtime error: " +
                error;
            lua_close(state);
            return false;
        }
        lua_close(state);
        return true;
    }
    catch (const std::exception& exception)
    {
        output =
            std::string(
                "VM exception: "
            ) +
            exception.what();
        lua_close(state);
        return false;
    }
    catch (...)
    {
        output =
            "Unknown VM exception";
        lua_close(state);
        return false;
    }
}