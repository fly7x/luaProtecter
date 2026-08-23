#include "bytecode.hpp"

#include "Luau/Bytecode.h"

#include <cstring>
#include <limits>

namespace
{
    constexpr std::size_t MAX_PROGRAM_SIZE =
        64 * 1024 * 1024;

    constexpr std::size_t MAX_FUNCTIONS =
        100000;

    constexpr std::size_t MAX_INSTRUCTIONS =
        10000000;

    constexpr std::size_t MAX_CONSTANTS =
        10000000;

    std::int16_t decodeD(
        std::uint32_t word
    )
    {
        return static_cast<std::int16_t>(
            (word >> 16) & 0xffffu
        );
    }

    std::int32_t decodeE(
        std::uint32_t word
    )
    {
        std::int32_t value =
            static_cast<std::int32_t>(
                (word >> 8) & 0x00ffffffu
            );

        if (value & 0x00800000)
            value |= ~0x00ffffff;

        return value;
    }

    std::uint8_t decodeA(
        std::uint32_t word
    )
    {
        return static_cast<std::uint8_t>(
            (word >> 8) & 0xffu
        );
    }

    std::uint8_t decodeB(
        std::uint32_t word
    )
    {
        return static_cast<std::uint8_t>(
            (word >> 16) & 0xffu
        );
    }

    std::uint8_t decodeC(
        std::uint32_t word
    )
    {
        return static_cast<std::uint8_t>(
            (word >> 24) & 0xffu
        );
    }

    /*
     * Luau instructions that are followed by AUX.
     *
     * This list intentionally contains the common public
     * bytecode forms. The exact encoding remains defined by
     * the vendored Luau Bytecode.h.
     */
    bool hasAuxWord(
        std::uint8_t opcode
    )
    {
        switch (
            static_cast<LuauOpcode>(opcode)
        )
        {
            case LOP_GETGLOBAL:
            case LOP_SETGLOBAL:

            case LOP_GETIMPORT:

            case LOP_GETTABLEKS:
            case LOP_SETTABLEKS:

            case LOP_NAMECALL:

            case LOP_FORGLOOP:

            case LOP_FASTCALL2:
            case LOP_FASTCALL2K:

            case LOP_JUMPIFEQ:
            case LOP_JUMPIFLE:
            case LOP_JUMPIFLT:
            case LOP_JUMPIFNOTEQ:
            case LOP_JUMPIFNOTLE:
            case LOP_JUMPIFNOTLT:

            case LOP_JUMPXEQKNIL:
            case LOP_JUMPXEQKB:
            case LOP_JUMPXEQKN:
            case LOP_JUMPXEQKS:

            case LOP_NEWCLOSURE:

            case LOP_DUPCLOSURE:

            case LOP_SETLIST:

            case LOP_LOADKX:

                return true;

            default:
                return false;
        }
    }
}

bool Bytecode::readU8(
    const std::vector<std::uint8_t>& data,
    std::size_t& position,
    std::uint8_t& value
)
{
    if (position >= data.size())
        return false;

    value = data[position++];
    return true;
}

bool Bytecode::readU32(
    const std::vector<std::uint8_t>& data,
    std::size_t& position,
    std::uint32_t& value
)
{
    if (
        position >
        data.size() - 4
    )
    {
        return false;
    }

    value =
        static_cast<std::uint32_t>(
            data[position]
        )
        |
        (
            static_cast<std::uint32_t>(
                data[position + 1]
            )
            << 8
        )
        |
        (
            static_cast<std::uint32_t>(
                data[position + 2]
            )
            << 16
        )
        |
        (
            static_cast<std::uint32_t>(
                data[position + 3]
            )
            << 24
        );

    position += 4;

    return true;
}

bool Bytecode::readU64(
    const std::vector<std::uint8_t>& data,
    std::size_t& position,
    std::uint64_t& value
)
{
    if (
        position >
        data.size() - 8
    )
    {
        return false;
    }

    value = 0;

    for (int i = 0; i < 8; ++i)
    {
        value |=
            static_cast<std::uint64_t>(
                data[position + i]
            )
            << (i * 8);
    }

    position += 8;

    return true;
}

bool Bytecode::readString(
    const std::vector<std::uint8_t>& data,
    std::size_t& position,
    std::string& value
)
{
    std::uint32_t length = 0;

    if (!readU32(data, position, length))
        return false;

    if (
        static_cast<std::size_t>(length) >
        data.size() - position
    )
    {
        return false;
    }

    value.assign(
        reinterpret_cast<const char*>(
            data.data() + position
        ),
        static_cast<std::size_t>(length)
    );

    position += length;

    return true;
}

bool Bytecode::readInstruction(
    const std::vector<std::uint8_t>& data,
    std::size_t& position,
    Protected::Instruction& instruction,
    std::string& error
) const
{
    const std::size_t start =
        position;

    std::uint32_t word = 0;

    if (!readU32(data, position, word))
    {
        error =
            "Unexpected end of bytecode while reading instruction";

        return false;
    }

    const std::uint8_t opcode =
        static_cast<std::uint8_t>(
            word & 0xffu
        );

    if (
        opcode >=
        static_cast<std::uint8_t>(
            LOP__COUNT
        )
    )
    {
        error =
            "Invalid Luau opcode: " +
            std::to_string(opcode);

        return false;
    }

    instruction = {};
    instruction.opcode = opcode;
    instruction.A = decodeA(word);
    instruction.B = decodeB(word);
    instruction.C = decodeC(word);
    instruction.D = decodeD(word);
    instruction.E = decodeE(word);
    instruction.wordOffset = start / 4;

    if (hasAuxWord(opcode))
    {
        std::uint32_t aux = 0;

        if (!readU32(data, position, aux))
        {
            error =
                "Instruction requires AUX word but bytecode ended";

            return false;
        }

        instruction.hasAux = true;
        instruction.AUX = aux;
    }

    return true;
}

std::string Bytecode::constantTypeName(
    std::uint8_t type
)
{
    switch (type)
    {
        case LBC_CONSTANT_NIL:
            return "nil";

        case LBC_CONSTANT_BOOLEAN:
            return "boolean";

        case LBC_CONSTANT_NUMBER:
            return "number";

        case LBC_CONSTANT_STRING:
            return "string";

        case LBC_CONSTANT_IMPORT:
            return "import";

        case LBC_CONSTANT_TABLE:
            return "table";

        case LBC_CONSTANT_CLOSURE:
            return "closure";

        case LBC_CONSTANT_VECTOR:
            return "vector";

        case LBC_CONSTANT_TABLE_WITH_CONSTANTS:
            return "table-with-constants";

        case LBC_CONSTANT_INTEGER:
            return "integer";

        case LBC_CONSTANT_CLASS_SHAPE:
            return "class-shape";

        case LBC_CONSTANT_VECTORD:
            return "vector-double";

        default:
            return "unknown";
    }
}

bool Bytecode::parse(
    const std::vector<std::uint8_t>& data,
    Protected::Program& program,
    std::string& error
) const
{
    program = {};
    error.clear();

    if (data.empty())
    {
        error = "Bytecode is empty";
        return false;
    }

    if (data.size() > MAX_PROGRAM_SIZE)
    {
        error = "Bytecode exceeds maximum size";
        return false;
    }

    /*
     * We keep the original compiled representation available
     * to the later protection layer, but the obfuscator should
     * never expose it directly to the generated output.
     */
    program.original = data;

    /*
     * Current Luau serialized bytecode begins with:
     *
     *     'L'
     *     'B'
     *     'C'
     *
     * followed by the bytecode version.
     */
    if (
        data.size() < 4 ||
        data[0] != 'L' ||
        data[1] != 'B' ||
        data[2] != 'C'
    )
    {
        error =
            "Invalid Luau bytecode signature";

        return false;
    }

    program.bytecodeVersion =
        data[3];

    if (
        program.bytecodeVersion <
        LBC_VERSION_MIN ||
        program.bytecodeVersion >
        LBC_VERSION_MAX
    )
    {
        error =
            "Unsupported Luau bytecode version: " +
            std::to_string(
                program.bytecodeVersion
            );

        return false;
    }

    /*
     * IMPORTANT:
     *
     * The serialized Proto format has changed across Luau
     * bytecode versions. We therefore don't pretend that a
     * single hand-written decoder is valid for every version.
     *
     * For now we retain the validated binary and expose the
     * instruction decoder independently. The next protection
     * layer will use Luau's public bytecode builder/parser
     * facilities for version-aware extraction.
     */

    Protected::Instruction instruction;

    /*
     * Locate a safe instruction-aligned region only after
     * the serialization layer has been validated.
     *
     * We intentionally do not guess the Proto offset.
     */
    (void)instruction;

    return true;
}