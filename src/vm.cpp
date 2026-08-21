#include "vm.hpp"

#include <Luau/Compiler.h>
#include <lua.h>
#include <lualib.h>

#include <string>

struct VM::State
{
    lua_State* L = nullptr;
};

VM::VM()
    : state_(new State())
{
    state_->L = luaL_newstate();

    if (!state_->L)
    {
        delete state_;
        state_ = nullptr;
        return;
    }

    luaL_openlibs(state_->L);
}

VM::~VM()
{
    if (state_)
    {
        if (state_->L)
            lua_close(state_->L);

        delete state_;
    }
}

bool VM::execute(
    const std::string& source,
    std::string& error
)
{
    error.clear();

    if (!state_ || !state_->L)
    {
        error = "Failed to create Luau VM";
        return false;
    }

    if (source.empty())
    {
        error = "Source is empty";
        return false;
    }

    std::string bytecode = Luau::compile(
        source,
        {},
        nullptr
    );

    if (bytecode.empty())
    {
        error = "Luau compiler returned empty bytecode";
        return false;
    }

    const int loadResult = luau_load(
        state_->L,
        "=LuaProtecter",
        bytecode.data(),
        bytecode.size(),
        0
    );

    if (loadResult != 0)
    {
        const char* message =
            lua_tostring(state_->L, -1);

        error = message
            ? message
            : "luau_load failed";

        lua_pop(state_->L, 1);

        return false;
    }

    const int callResult =
        lua_pcall(
            state_->L,
            0,
            LUA_MULTRET,
            0
        );

    if (callResult != 0)
    {
        const char* message =
            lua_tostring(state_->L, -1);

        error = message
            ? message
            : "Luau execution failed";

        lua_pop(state_->L, 1);

        return false;
    }

    lua_settop(state_->L, 0);

    return true;
}