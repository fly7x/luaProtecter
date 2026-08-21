#include "vm.hpp"

#include "lua.h"
#include "lualib.h"
#include "luacode.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace
{
    constexpr std::size_t MAX_OUTPUT_SIZE =
        4 * 1024 * 1024;

    /*
     * Append output while preventing a malicious script from
     * generating an unbounded response.
     */
    void appendOutput(
        std::string& output,
        const char* text,
        std::size_t length
    )
    {
        if (!text || length == 0)
            return;

        if (output.size() >= MAX_OUTPUT_SIZE)
            return;

        const std::size_t remaining =
            MAX_OUTPUT_SIZE - output.size();

        const std::size_t amount =
            length < remaining
                ? length
                : remaining;

        output.append(
            text,
            amount
        );
    }

    /*
     * Convert a Luau value to a readable string.
     *
     * luaL_tolstring is part of Luau's public Lua-compatible
     * auxiliary API.
     */
    void appendStackValue(
        lua_State* L,
        int index,
        std::string& output
    )
    {
        size_t length = 0;

        const char* value =
            luaL_tolstring(
                L,
                index,
                &length
            );

        if (value)
        {
            appendOutput(
                output,
                value,
                length
            );
        }

        lua_pop(L, 1);
    }

    /*
     * Replacement print implementation.
     *
     * This allows the embedded VM to return print() output to
     * the HTTP server instead of writing directly to stdout.
     */
    int vmPrint(
        lua_State* L
    )
    {
        std::string* output =
            static_cast<std::string*>(
                lua_getthreaddata(L)
            );

        if (!output)
            return 0;

        const int count =
            lua_gettop(L);

        for (int i = 1; i <= count; ++i)
        {
            if (i > 1)
                appendOutput(
                    *output,
                    "\t",
                    1
                );

            size_t length = 0;

            const char* value =
                luaL_tolstring(
                    L,
                    i,
                    &length
                );

            if (value)
            {
                appendOutput(
                    *output,
                    value,
                    length
                );
            }

            lua_pop(L, 1);
        }

        appendOutput(
            *output,
            "\n",
            1
        );

        return 0;
    }

    /*
     * Install our print implementation.
     */
    void installPrint(
        lua_State* L
    )
    {
        lua_pushcfunction(
            L,
            vmPrint,
            "print"
        );

        lua_setglobal(
            L,
            "print"
        );
    }

    /*
     * Get the error currently sitting on the Luau stack.
     */
    std::string getError(
        lua_State* L
    )
    {
        if (lua_gettop(L) == 0)
            return "Unknown Luau VM error";

        size_t length = 0;

        const char* message =
            luaL_tolstring(
                L,
                -1,
                &length
            );

        if (!message)
        {
            lua_pop(L, 1);

            return "Unknown Luau VM error";
        }

        std::string result(
            message,
            length
        );

        lua_pop(L, 1);

        return result;
    }

    /*
     * Execute the already-compiled Luau bytecode.
     */
    bool executeLuauBytecode(
        const std::vector<std::uint8_t>& bytes,
        std::string& output
    )
    {
        if (bytes.empty())
        {
            output =
                "Bytecode is empty";

            return false;
        }

        /*
         * Create an isolated Luau state.
         */
        lua_State* L =
            luaL_newstate();

        if (!L)
        {
            output =
                "Failed to create Luau VM state";

            return false;
        }

        /*
         * Make the state responsible for the lifetime of the
         * execution output pointer.
         *
         * The pointer itself is owned by VM::execute().
         */
        lua_setthreaddata(
            L,
            &output
        );

        /*
         * Open Luau's standard libraries.
         *
         * If your production configuration wants a stricter
         * sandbox, this can be replaced with only the libraries
         * you explicitly want to expose.
         */
        luaL_openlibs(L);

        /*
         * Replace print() so the caller receives its output.
         */
        installPrint(L);

        /*
         * Load the REAL Luau bytecode.
         *
         * This is the Luau API intended for embedding.
         * Do NOT use luaL_loadbuffer(); Luau uses luau_load().
         */
        const int loadResult =
            luau_load(
                L,
                "@protected",
                reinterpret_cast<const char*>(
                    bytes.data()
                ),
                bytes.size(),
                0
            );

        if (loadResult != 0)
        {
            output =
                getError(L);

            lua_close(L);

            return false;
        }

        /*
         * The loaded chunk is now on top of the stack.
         *
         * Execute it with protected-call semantics so runtime
         * errors are returned instead of crashing the server.
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
            const std::string error =
                getError(L);

            if (!output.empty())
                output += "\n";

            output +=
                "Luau runtime error: ";

            output += error;

            lua_close(L);

            return false;
        }

        /*
         * Successful execution.
         *
         * Normally the output has already been captured by our
         * print implementation.
         */
        lua_close(L);

        return true;
    }
}

bool VM::execute(
    const Bytecode& bytecode,
    std::string& output
) const
{
    output.clear();

    /*
     * Bytecode owns the actual compiled Luau bytes.
     */
    const std::vector<std::uint8_t>& bytes =
        bytecode.data();

    return executeLuauBytecode(
        bytes,
        output
    );
}