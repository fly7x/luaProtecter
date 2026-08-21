#include "vm.hpp"

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{
    /*
     * ---------------------------------------------------------
     * Custom VM instruction set
     * ---------------------------------------------------------
     */

    constexpr std::uint8_t OP_HALT = 0x01;
    constexpr std::uint8_t OP_PUSH_STRING = 0x02;
    constexpr std::uint8_t OP_PRINT = 0x03;

    /*
     * ---------------------------------------------------------
     * Custom bytecode header
     * ---------------------------------------------------------
     *
     * LVM1
     * version = 1
     */

    constexpr std::uint8_t MAGIC_0 = 'L';
    constexpr std::uint8_t MAGIC_1 = 'V';
    constexpr std::uint8_t MAGIC_2 = 'M';
    constexpr std::uint8_t MAGIC_3 = '1';

    constexpr std::uint8_t VERSION = 1;

    /*
     * Read a little-endian uint32.
     */
    bool readU32(
        const std::vector<std::uint8_t>& bytes,
        std::size_t& position,
        std::uint32_t& value
    )
    {
        if (
            position + 4 >
            bytes.size()
        )
        {
            return false;
        }

        value =
            static_cast<std::uint32_t>(
                bytes[position]
            )
            |
            (
                static_cast<std::uint32_t>(
                    bytes[position + 1]
                )
                << 8
            )
            |
            (
                static_cast<std::uint32_t>(
                    bytes[position + 2]
                )
                << 16
            )
            |
            (
                static_cast<std::uint32_t>(
                    bytes[position + 3]
                )
                << 24
            );

        position += 4;

        return true;
    }

    /*
     * Read a length-prefixed string.
     *
     * Format:
     *
     * [uint32 length]
     * [raw bytes]
     */
    bool readString(
        const std::vector<std::uint8_t>& bytes,
        std::size_t& position,
        std::string& value
    )
    {
        std::uint32_t length = 0;

        if (
            !readU32(
                bytes,
                position,
                length
            )
        )
        {
            return false;
        }

        if (
            static_cast<std::size_t>(length) >
            bytes.size() - position
        )
        {
            return false;
        }

        value.assign(
            reinterpret_cast<const char*>(
                bytes.data() + position
            ),
            static_cast<std::size_t>(length)
        );

        position +=
            static_cast<std::size_t>(
                length
            );

        return true;
    }

    /*
     * Validate the custom bytecode header.
     */
    bool validateHeader(
        const std::vector<std::uint8_t>& bytes,
        std::size_t& position,
        std::string& error
    )
    {
        /*
         * Header:
         *
         * byte 0 = L
         * byte 1 = V
         * byte 2 = M
         * byte 3 = 1
         * byte 4 = version
         */

        if (bytes.size() < 5)
        {
            error =
                "Bytecode is too small";

            return false;
        }

        if (
            bytes[0] != MAGIC_0 ||
            bytes[1] != MAGIC_1 ||
            bytes[2] != MAGIC_2 ||
            bytes[3] != MAGIC_3
        )
        {
            error =
                "Invalid LVM magic";

            return false;
        }

        if (
            bytes[4] != VERSION
        )
        {
            error =
                "Unsupported LVM bytecode version";

            return false;
        }

        position = 5;

        return true;
    }
}

bool VM::execute(
    const Bytecode& bytecode,
    std::string& output
) const
{
    output.clear();

    const std::vector<std::uint8_t>& bytes =
        bytecode.data();

    if (bytes.empty())
    {
        output =
            "Bytecode is empty";

        return false;
    }

    std::size_t position = 0;

    std::string error;

    if (
        !validateHeader(
            bytes,
            position,
            error
        )
    )
    {
        output = error;
        return false;
    }

    /*
     * ---------------------------------------------------------
     * VM stack
     * ---------------------------------------------------------
     */

    std::vector<std::string> stack;

    /*
     * Safety limit.
     *
     * Prevents malformed bytecode from running
     * indefinitely.
     */
    constexpr std::size_t MAX_INSTRUCTIONS =
        1'000'000;

    std::size_t instructionCount = 0;

    bool halted = false;

    /*
     * ---------------------------------------------------------
     * Main interpreter loop
     * ---------------------------------------------------------
     */

    while (
        position <
        bytes.size()
    )
    {
        ++instructionCount;

        if (
            instructionCount >
            MAX_INSTRUCTIONS
        )
        {
            output =
                "VM instruction limit exceeded";

            return false;
        }

        const std::uint8_t opcode =
            bytes[position++];

        switch (opcode)
        {
            /*
             * -------------------------------------------------
             * HALT
             * -------------------------------------------------
             */

            case OP_HALT:
            {
                halted = true;

                /*
                 * HALT should normally be the final
                 * instruction.
                 */
                if (
                    position !=
                    bytes.size()
                )
                {
                    output =
                        "Trailing bytes after HALT";

                    return false;
                }

                break;
            }

            /*
             * -------------------------------------------------
             * PUSH_STRING
             * -------------------------------------------------
             *
             * Encoding:
             *
             * 02
             * uint32 length
             * string bytes
             */

            case OP_PUSH_STRING:
            {
                std::string value;

                if (
                    !readString(
                        bytes,
                        position,
                        value
                    )
                )
                {
                    output =
                        "Malformed PUSH_STRING instruction";

                    return false;
                }

                stack.push_back(
                    std::move(value)
                );

                break;
            }

            /*
             * -------------------------------------------------
             * PRINT
             * -------------------------------------------------
             *
             * Pops one string from the stack.
             */

            case OP_PRINT:
            {
                if (stack.empty())
                {
                    output =
                        "PRINT attempted with empty stack";

                    return false;
                }

                std::string value =
                    std::move(
                        stack.back()
                    );

                stack.pop_back();

                output += value;

                /*
                 * Match normal print() behaviour.
                 */
                output += '\n';

                break;
            }

            /*
             * -------------------------------------------------
             * Unknown opcode
             * -------------------------------------------------
             */

            default:
            {
                output =
                    "Unknown VM opcode: " +
                    std::to_string(
                        static_cast<unsigned int>(
                            opcode
                        )
                    );

                return false;
            }
        }

        if (halted)
            break;
    }

    /*
     * A valid program must contain HALT.
     */
    if (!halted)
    {
        output =
            "VM reached end of bytecode without HALT";

        return false;
    }

    return true;
}