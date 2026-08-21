#include "vm.hpp"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace
{
    // =========================================================
    // Custom VM instruction set
    // =========================================================

    constexpr std::uint8_t OP_HALT        = 0x01;
    constexpr std::uint8_t OP_PUSH_STRING = 0x02;
    constexpr std::uint8_t OP_PRINT       = 0x03;

    // =========================================================
    // Custom bytecode header
    //
    // LVM1
    // version = 1
    // =========================================================

    constexpr std::uint8_t MAGIC_0 = 'L';
    constexpr std::uint8_t MAGIC_1 = 'V';
    constexpr std::uint8_t MAGIC_2 = 'M';
    constexpr std::uint8_t MAGIC_3 = '1';

    constexpr std::uint8_t VERSION = 1;

    constexpr std::size_t HEADER_SIZE = 5;

    // =========================================================
    // Limits
    // =========================================================

    constexpr std::size_t MAX_INSTRUCTIONS = 1'000'000;
    constexpr std::size_t MAX_STRING_SIZE = 16 * 1024 * 1024;
    constexpr std::size_t MAX_STACK_SIZE = 1'000'000;
    constexpr std::size_t MAX_OUTPUT_SIZE = 64 * 1024 * 1024;

    // =========================================================
    // Little-endian uint32 reader
    // =========================================================

    bool readU32(
        const std::vector<std::uint8_t>& bytes,
        std::size_t& position,
        std::uint32_t& value
    )
    {
        if (position > bytes.size())
            return false;

        if (bytes.size() - position < 4)
            return false;

        value =
            static_cast<std::uint32_t>(bytes[position])
            |
            (static_cast<std::uint32_t>(
                bytes[position + 1]
            ) << 8)
            |
            (static_cast<std::uint32_t>(
                bytes[position + 2]
            ) << 16)
            |
            (static_cast<std::uint32_t>(
                bytes[position + 3]
            ) << 24);

        position += 4;

        return true;
    }

    // =========================================================
    // Read length-prefixed string
    //
    // [uint32 length]
    // [raw string bytes]
    // =========================================================

    bool readString(
        const std::vector<std::uint8_t>& bytes,
        std::size_t& position,
        std::string& value
    )
    {
        std::uint32_t length = 0;

        if (!readU32(bytes, position, length))
            return false;

        const std::size_t stringLength =
            static_cast<std::size_t>(length);

        if (stringLength > MAX_STRING_SIZE)
            return false;

        if (position > bytes.size())
            return false;

        if (stringLength > bytes.size() - position)
            return false;

        value.assign(
            reinterpret_cast<const char*>(
                bytes.data() + position
            ),
            stringLength
        );

        position += stringLength;

        return true;
    }

    // =========================================================
    // Header validation
    // =========================================================

    bool validateHeader(
        const std::vector<std::uint8_t>& bytes,
        std::size_t& position,
        std::string& error
    )
    {
        if (bytes.size() < HEADER_SIZE)
        {
            error = "Bytecode is too small";
            return false;
        }

        if (
            bytes[0] != MAGIC_0 ||
            bytes[1] != MAGIC_1 ||
            bytes[2] != MAGIC_2 ||
            bytes[3] != MAGIC_3
        )
        {
            error = "Invalid LVM magic";
            return false;
        }

        if (bytes[4] != VERSION)
        {
            error = "Unsupported LVM bytecode version";
            return false;
        }

        position = HEADER_SIZE;

        return true;
    }

    // =========================================================
    // Safely append VM output
    // =========================================================

    bool appendOutput(
        std::string& output,
        const std::string& value
    )
    {
        if (value.size() >
            MAX_OUTPUT_SIZE - std::min(
                output.size(),
                MAX_OUTPUT_SIZE
            ))
        {
            return false;
        }

        output += value;

        return true;
    }

    bool appendOutputChar(
        std::string& output,
        char value
    )
    {
        if (output.size() >= MAX_OUTPUT_SIZE)
            return false;

        output.push_back(value);

        return true;
    }
}

// =============================================================
// VM
// =============================================================

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
        output = "Bytecode is empty";
        return false;
    }

    // ---------------------------------------------------------
    // Validate header
    // ---------------------------------------------------------

    std::size_t position = 0;
    std::string error;

    if (!validateHeader(
            bytes,
            position,
            error
        ))
    {
        output = error;
        return false;
    }

    // ---------------------------------------------------------
    // VM stack
    //
    // Current instruction set only has strings.
    // Later this can become a Value variant supporting:
    //
    // nil
    // boolean
    // number
    // string
    // table
    // function
    // userdata
    // thread
    // etc.
    // ---------------------------------------------------------

    std::vector<std::string> stack;

    stack.reserve(32);

    // ---------------------------------------------------------
    // Interpreter state
    // ---------------------------------------------------------

    std::size_t instructionCount = 0;

    bool halted = false;

    // ---------------------------------------------------------
    // Main interpreter loop
    // ---------------------------------------------------------

    while (position < bytes.size())
    {
        if (++instructionCount > MAX_INSTRUCTIONS)
        {
            output = "VM instruction limit exceeded";
            return false;
        }

        const std::uint8_t opcode =
            bytes[position++];

        switch (opcode)
        {
            // =================================================
            // HALT
            // =================================================

            case OP_HALT:
            {
                halted = true;

                if (position != bytes.size())
                {
                    output =
                        "Trailing bytes after HALT";

                    return false;
                }

                break;
            }

            // =================================================
            // PUSH_STRING
            //
            // Format:
            //
            // 02
            // uint32 length
            // string bytes
            // =================================================

            case OP_PUSH_STRING:
            {
                if (stack.size() >= MAX_STACK_SIZE)
                {
                    output =
                        "VM stack limit exceeded";

                    return false;
                }

                std::string value;

                if (!readString(
                        bytes,
                        position,
                        value
                    ))
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

            // =================================================
            // PRINT
            //
            // Pops the top string and writes it to output.
            // =================================================

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

                if (!appendOutput(
                        output,
                        value
                    ))
                {
                    output =
                        "VM output limit exceeded";

                    return false;
                }

                if (!appendOutputChar(
                        output,
                        '\n'
                    ))
                {
                    output =
                        "VM output limit exceeded";

                    return false;
                }

                break;
            }

            // =================================================
            // UNKNOWN OPCODE
            // =================================================

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

    // ---------------------------------------------------------
    // Program must terminate with HALT
    // ---------------------------------------------------------

    if (!halted)
    {
        output =
            "VM reached end of bytecode without HALT";

        return false;
    }

    return true;
}