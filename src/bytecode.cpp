#include "bytecode.hpp"

#include <cstring>
#include <limits>

namespace LuaProtecter
{
    namespace
    {
        constexpr std::uint32_t MAGIC =
            0x4C50564Du; // "LPVM"

        constexpr std::uint32_t MAX_CODE =
            1'000'000;

        constexpr std::uint32_t MAX_CONSTANTS =
            1'000'000;

        constexpr std::uint32_t MAX_CHILDREN =
            100'000;

        constexpr std::uint32_t MAX_STRING =
            16 * 1024 * 1024;

        void writeU8(
            std::vector<std::uint8_t>& out,
            std::uint8_t value
        )
        {
            out.push_back(value);
        }

        void writeU32(
            std::vector<std::uint8_t>& out,
            std::uint32_t value
        )
        {
            out.push_back(
                static_cast<std::uint8_t>(
                    value & 0xFFu
                )
            );

            out.push_back(
                static_cast<std::uint8_t>(
                    (value >> 8) & 0xFFu
                )
            );

            out.push_back(
                static_cast<std::uint8_t>(
                    (value >> 16) & 0xFFu
                )
            );

            out.push_back(
                static_cast<std::uint8_t>(
                    (value >> 24) & 0xFFu
                )
            );
        }

        void writeI32(
            std::vector<std::uint8_t>& out,
            std::int32_t value
        )
        {
            std::uint32_t raw = 0;

            static_assert(
                sizeof(raw) ==
                sizeof(value)
            );

            std::memcpy(
                &raw,
                &value,
                sizeof(raw)
            );

            writeU32(
                out,
                raw
            );
        }

        void writeU64(
            std::vector<std::uint8_t>& out,
            std::uint64_t value
        )
        {
            for (int i = 0; i < 8; ++i)
            {
                out.push_back(
                    static_cast<std::uint8_t>(
                        (value >> (i * 8)) &
                        0xFFu
                    )
                );
            }
        }

        void writeDouble(
            std::vector<std::uint8_t>& out,
            double value
        )
        {
            std::uint64_t raw = 0;

            static_assert(
                sizeof(raw) ==
                sizeof(value)
            );

            std::memcpy(
                &raw,
                &value,
                sizeof(raw)
            );

            writeU64(
                out,
                raw
            );
        }

        void writeBytes(
            std::vector<std::uint8_t>& out,
            const std::string& value
        )
        {
            writeU32(
                out,
                static_cast<std::uint32_t>(
                    value.size()
                )
            );

            out.insert(
                out.end(),
                value.begin(),
                value.end()
            );
        }

        class Reader
        {
        public:
            explicit Reader(
                const std::vector<std::uint8_t>& data
            )
                : data(data)
            {
            }

            bool readU8(
                std::uint8_t& value
            )
            {
                if (!canRead(1))
                    return false;

                value =
                    data[position++];

                return true;
            }

            bool readU32(
                std::uint32_t& value
            )
            {
                if (!canRead(4))
                    return false;

                value =
                    static_cast<std::uint32_t>(
                        data[position]
                    ) |
                    (
                        static_cast<std::uint32_t>(
                            data[position + 1]
                        ) << 8
                    ) |
                    (
                        static_cast<std::uint32_t>(
                            data[position + 2]
                        ) << 16
                    ) |
                    (
                        static_cast<std::uint32_t>(
                            data[position + 3]
                        ) << 24
                    );

                position += 4;

                return true;
            }

            bool readI32(
                std::int32_t& value
            )
            {
                std::uint32_t raw = 0;

                if (!readU32(raw))
                    return false;

                std::memcpy(
                    &value,
                    &raw,
                    sizeof(value)
                );

                return true;
            }

            bool readU64(
                std::uint64_t& value
            )
            {
                if (!canRead(8))
                    return false;

                value = 0;

                for (int i = 0; i < 8; ++i)
                {
                    value |=
                        static_cast<std::uint64_t>(
                            data[position + i]
                        ) << (i * 8);
                }

                position += 8;

                return true;
            }

            bool readDouble(
                double& value
            )
            {
                std::uint64_t raw = 0;

                if (!readU64(raw))
                    return false;

                std::memcpy(
                    &value,
                    &raw,
                    sizeof(value)
                );

                return true;
            }

            bool readString(
                std::string& value
            )
            {
                std::uint32_t size = 0;

                if (!readU32(size))
                    return false;

                if (size > MAX_STRING)
                    return false;

                if (
                    !canRead(
                        static_cast<std::size_t>(
                            size
                        )
                    )
                )
                {
                    return false;
                }

                value.assign(
                    reinterpret_cast<
                        const char*
                    >(
                        data.data() + position
                    ),
                    size
                );

                position += size;

                return true;
            }

            bool finished() const
            {
                return position ==
                    data.size();
            }

        private:
            const std::vector<std::uint8_t>& data;

            std::size_t position = 0;

            bool canRead(
                std::size_t amount
            ) const
            {
                return amount <=
                    data.size() - position;
            }
        };

        void writeInstruction(
            std::vector<std::uint8_t>& out,
            const Instruction& instruction
        )
        {
            writeU8(
                out,
                static_cast<std::uint8_t>(
                    instruction.op
                )
            );

            writeU8(
                out,
                instruction.a
            );

            writeU8(
                out,
                instruction.b
            );

            writeU8(
                out,
                instruction.c
            );

            writeI32(
                out,
                instruction.aux
            );
        }

        bool readInstruction(
            Reader& reader,
            Instruction& instruction
        )
        {
            std::uint8_t opcode = 0;

            if (
                !reader.readU8(
                    opcode
                )
            )
            {
                return false;
            }

            if (
                !isValidOpcode(opcode)
            )
            {
                return false;
            }

            instruction.op =
                static_cast<OpCode>(
                    opcode
                );

            if (
                !reader.readU8(
                    instruction.a
                )
            )
            {
                return false;
            }

            if (
                !reader.readU8(
                    instruction.b
                )
            )
            {
                return false;
            }

            if (
                !reader.readU8(
                    instruction.c
                )
            )
            {
                return false;
            }

            if (
                !reader.readI32(
                    instruction.aux
                )
            )
            {
                return false;
            }

            return true;
        }

        void writeConstant(
            std::vector<std::uint8_t>& out,
            const Constant& constant
        )
        {
            writeU8(
                out,
                static_cast<std::uint8_t>(
                    constant.type
                )
            );

            switch (constant.type)
            {
                case ConstantType::Nil:
                    break;

                case ConstantType::Boolean:
                    writeU8(
                        out,
                        constant.booleanValue
                            ? 1
                            : 0
                    );
                    break;

                case ConstantType::Number:
                    writeDouble(
                        out,
                        constant.numberValue
                    );
                    break;

                case ConstantType::String:
                    writeBytes(
                        out,
                        constant.stringValue
                    );
                    break;
            }
        }

        bool readConstant(
            Reader& reader,
            Constant& constant
        )
        {
            std::uint8_t type = 0;

            if (
                !reader.readU8(type)
            )
            {
                return false;
            }

            if (
                type >
                static_cast<std::uint8_t>(
                    ConstantType::String
                )
            )
            {
                return false;
            }

            constant =
                Constant{};

            constant.type =
                static_cast<ConstantType>(
                    type
                );

            switch (constant.type)
            {
                case ConstantType::Nil:
                    return true;

                case ConstantType::Boolean:
                {
                    std::uint8_t value = 0;

                    if (
                        !reader.readU8(value)
                    )
                    {
                        return false;
                    }

                    if (value > 1)
                        return false;

                    constant.booleanValue =
                        value != 0;

                    return true;
                }

                case ConstantType::Number:
                {
                    return reader.readDouble(
                        constant.numberValue
                    );
                }

                case ConstantType::String:
                {
                    return reader.readString(
                        constant.stringValue
                    );
                }
            }

            return false;
        }

        void writePrototype(
            std::vector<std::uint8_t>& out,
            const Prototype& prototype
        )
        {
            writeU32(
                out,
                prototype.registerCount
            );

            writeU32(
                out,
                prototype.parameterCount
            );

            writeU32(
                out,
                prototype.upvalueCount
            );

            writeU8(
                out,
                prototype.isVararg
                    ? 1
                    : 0
            );

            writeU32(
                out,
                static_cast<std::uint32_t>(
                    prototype.constants.size()
                )
            );

            for (
                const Constant& constant :
                prototype.constants
            )
            {
                writeConstant(
                    out,
                    constant
                );
            }

            writeU32(
                out,
                static_cast<std::uint32_t>(
                    prototype.code.size()
                )
            );

            for (
                const Instruction& instruction :
                prototype.code
            )
            {
                writeInstruction(
                    out,
                    instruction
                );
            }

            writeU32(
                out,
                static_cast<std::uint32_t>(
                    prototype.children.size()
                )
            );

            for (
                const Prototype& child :
                prototype.children
            )
            {
                writePrototype(
                    out,
                    child
                );
            }
        }

        bool readPrototype(
            Reader& reader,
            Prototype& prototype,
            std::uint32_t depth = 0
        )
        {
            /*
             * Protect the deserializer from maliciously deep
             * prototype trees.
             */
            constexpr std::uint32_t MAX_DEPTH = 256;

            if (depth > MAX_DEPTH)
                return false;

            prototype =
                Prototype{};

            if (
                !reader.readU32(
                    prototype.registerCount
                )
            )
            {
                return false;
            }

            if (
                !reader.readU32(
                    prototype.parameterCount
                )
            )
            {
                return false;
            }

            if (
                !reader.readU32(
                    prototype.upvalueCount
                )
            )
            {
                return false;
            }

            std::uint8_t vararg = 0;

            if (
                !reader.readU8(
                    vararg
                )
            )
            {
                return false;
            }

            if (vararg > 1)
                return false;

            prototype.isVararg =
                vararg != 0;

            std::uint32_t constantCount = 0;

            if (
                !reader.readU32(
                    constantCount
                )
            )
            {
                return false;
            }

            if (
                constantCount >
                MAX_CONSTANTS
            )
            {
                return false;
            }

            prototype.constants.reserve(
                constantCount
            );

            for (
                std::uint32_t i = 0;
                i < constantCount;
                ++i
            )
            {
                Constant constant;

                if (
                    !readConstant(
                        reader,
                        constant
                    )
                )
                {
                    return false;
                }

                prototype.constants.push_back(
                    std::move(constant)
                );
            }

            std::uint32_t codeCount = 0;

            if (
                !reader.readU32(
                    codeCount
                )
            )
            {
                return false;
            }

            if (
                codeCount >
                MAX_CODE
            )
            {
                return false;
            }

            prototype.code.reserve(
                codeCount
            );

            for (
                std::uint32_t i = 0;
                i < codeCount;
                ++i
            )
            {
                Instruction instruction;

                if (
                    !readInstruction(
                        reader,
                        instruction
                    )
                )
                {
                    return false;
                }

                prototype.code.push_back(
                    instruction
                );
            }

            std::uint32_t childCount = 0;

            if (
                !reader.readU32(
                    childCount
                )
            )
            {
                return false;
            }

            if (
                childCount >
                MAX_CHILDREN
            )
            {
                return false;
            }

            prototype.children.reserve(
                childCount
            );

            for (
                std::uint32_t i = 0;
                i < childCount;
                ++i
            )
            {
                Prototype child;

                if (
                    !readPrototype(
                        reader,
                        child,
                        depth + 1
                    )
                )
                {
                    return false;
                }

                prototype.children.push_back(
                    std::move(child)
                );
            }

            return true;
        }
    }

    std::vector<std::uint8_t> serialize(
        const Program& program
    )
    {
        std::vector<std::uint8_t> output;

        /*
         * Reserve a small amount initially. The vector will grow
         * automatically for larger programs.
         */
        output.reserve(1024);

        /*
         * Header:
         *
         * magic
         * version
         * seed
         */
        writeU32(
            output,
            MAGIC
        );

        writeU32(
            output,
            program.version
        );

        writeU32(
            output,
            program.seed
        );

        writePrototype(
            output,
            program.main
        );

        return output;
    }

    bool deserialize(
        const std::vector<std::uint8_t>& data,
        Program& program
    )
    {
        if (data.empty())
            return false;

        Reader reader(data);

        std::uint32_t magic = 0;

        if (
            !reader.readU32(
                magic
            )
        )
        {
            return false;
        }

        if (magic != MAGIC)
            return false;

        Program result;

        if (
            !reader.readU32(
                result.version
            )
        )
        {
            return false;
        }

        /*
         * Version zero is not valid.
         */
        if (result.version == 0)
            return false;

        if (
            !reader.readU32(
                result.seed
            )
        )
        {
            return false;
        }

        if (
            !readPrototype(
                reader,
                result.main
            )
        )
        {
            return false;
        }

        /*
         * Reject trailing garbage. This keeps the format
         * deterministic and prevents accidental acceptance of
         * concatenated malformed programs.
         */
        if (!reader.finished())
            return false;

        program =
            std::move(result);

        return true;
    }

    const char* opcodeName(
        OpCode opcode
    )
    {
        switch (opcode)
        {
            case OpCode::Nop:
                return "NOP";

            case OpCode::LoadNil:
                return "LOADNIL";

            case OpCode::LoadBool:
                return "LOADBOOL";

            case OpCode::LoadNumber:
                return "LOADNUMBER";

            case OpCode::LoadString:
                return "LOADSTRING";

            case OpCode::Move:
                return "MOVE";

            case OpCode::GetGlobal:
                return "GETGLOBAL";

            case OpCode::SetGlobal:
                return "SETGLOBAL";

            case OpCode::GetTable:
                return "GETTABLE";

            case OpCode::SetTable:
                return "SETTABLE";

            case OpCode::Add:
                return "ADD";

            case OpCode::Sub:
                return "SUB";

            case OpCode::Mul:
                return "MUL";

            case OpCode::Div:
                return "DIV";

            case OpCode::Mod:
                return "MOD";

            case OpCode::Pow:
                return "POW";

            case OpCode::Neg:
                return "NEG";

            case OpCode::Equal:
                return "EQ";

            case OpCode::NotEqual:
                return "NEQ";

            case OpCode::Less:
                return "LT";

            case OpCode::LessEqual:
                return "LE";

            case OpCode::Greater:
                return "GT";

            case OpCode::GreaterEqual:
                return "GE";

            case OpCode::Not:
                return "NOT";

            case OpCode::Test:
                return "TEST";

            case OpCode::Jump:
                return "JUMP";

            case OpCode::JumpIfFalse:
                return "JUMP_IF_FALSE";

            case OpCode::JumpIfTrue:
                return "JUMP_IF_TRUE";

            case OpCode::NewClosure:
                return "CLOSURE";

            case OpCode::Call:
                return "CALL";

            case OpCode::Return:
                return "RETURN";

            case OpCode::Concat:
                return "CONCAT";

            case OpCode::Halt:
                return "HALT";
        }

        return "UNKNOWN";
    }

    bool isValidOpcode(
        std::uint8_t opcode
    )
    {
        return opcode <=
            static_cast<std::uint8_t>(
                OpCode::Halt
            );
    }

    std::uint32_t opcodeCount()
    {
        return static_cast<std::uint32_t>(
            static_cast<std::uint8_t>(
                OpCode::Halt
            )
        ) + 1;
    }
}