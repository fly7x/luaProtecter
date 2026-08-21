#include "vm.hpp"

#include <cmath>
#include <iostream>
#include <limits>
#include <utility>

namespace LuaProtecter
{
    namespace
    {
        /*
         * Small deterministic mixer used for the instruction
         * encoding. The transformer will use the same operation.
         */
        std::uint32_t mix(
            std::uint32_t value,
            std::uint32_t seed
        )
        {
            value ^= seed + 0x9E3779B9u;

            value *= 0x85EBCA6Bu;

            value ^= value >> 13;

            value *= 0xC2B2AE35u;

            value ^= value >> 16;

            return value;
        }

        /*
         * Decode an encoded opcode.
         *
         * Because mix() is not conveniently invertible here,
         * the VM uses a small opcode search space.
         *
         * This is deliberately simple for the first VM layer;
         * later the compiler can emit a per-build opcode map.
         */
        std::uint32_t decodeOpcode(
            std::uint32_t encoded,
            std::uint32_t seed
        )
        {
            for (
                std::uint32_t candidate = 0;
                candidate <= 32;
                ++candidate
            )
            {
                if (
                    mix(
                        candidate,
                        seed
                    ) == encoded
                )
                {
                    return candidate;
                }
            }

            return std::numeric_limits<std::uint32_t>::max();
        }
    }

    std::uint32_t VM::decodeOpcode(
        std::uint32_t encoded,
        std::uint32_t seed
    )
    {
        return ::LuaProtecter::decodeOpcode(
            encoded,
            seed
        );
    }

    void VM::push(
        Value value
    )
    {
        stack.push_back(
            std::move(value)
        );
    }

    VM::Value VM::pop()
    {
        if (stack.empty())
        {
            return {};
        }

        Value value =
            std::move(
                stack.back()
            );

        stack.pop_back();

        return value;
    }

    VM::Value VM::constantToValue(
        const Constant& constant
    ) const
    {
        Value value;

        switch (constant.type)
        {
            case Constant::Type::String:
            {
                value.type =
                    Value::Type::String;

                value.string =
                    constant.stringValue;

                break;
            }

            case Constant::Type::Number:
            {
                value.type =
                    Value::Type::Number;

                value.number =
                    constant.numberValue;

                break;
            }
        }

        return value;
    }

    bool VM::executeInstruction(
        const Instruction& instruction,
        const Program& program
    )
    {
        const std::uint32_t opcode =
            decodeOpcode(
                instruction.opcode,
                program.seed
            );

        if (
            opcode ==
            std::numeric_limits<std::uint32_t>::max()
        )
        {
            return false;
        }

        switch (
            static_cast<OpCode>(opcode)
        )
        {
            case OpCode::Nop:
            {
                return true;
            }

            case OpCode::PushString:
            {
                if (
                    instruction.a >=
                    program.constants.size()
                )
                {
                    return false;
                }

                push(
                    constantToValue(
                        program.constants[
                            instruction.a
                        ]
                    )
                );

                return true;
            }

            case OpCode::PushNumber:
            {
                if (
                    instruction.a >=
                    program.constants.size()
                )
                {
                    return false;
                }

                push(
                    constantToValue(
                        program.constants[
                            instruction.a
                        ]
                    )
                );

                return true;
            }

            case OpCode::GetGlobal:
            {
                /*
                 * The native VM cannot directly access Roblox's
                 * global environment.
                 *
                 * This first implementation exposes only the
                 * host-side demonstration globals.
                 */
                if (
                    instruction.a >=
                    program.constants.size()
                )
                {
                    return false;
                }

                const Constant& constant =
                    program.constants[
                        instruction.a
                    ];

                if (
                    constant.type !=
                    Constant::Type::String
                )
                {
                    return false;
                }

                Value global;

                global.type =
                    Value::Type::String;

                global.string =
                    constant.stringValue;

                push(
                    std::move(global)
                );

                return true;
            }

            case OpCode::SetGlobal:
            {
                /*
                 * Reserved for the expanded environment layer.
                 */
                if (stack.empty())
                    return false;

                pop();

                return true;
            }

            case OpCode::Add:
            {
                if (stack.size() < 2)
                    return false;

                Value rhs = pop();
                Value lhs = pop();

                if (
                    lhs.type !=
                        Value::Type::Number ||
                    rhs.type !=
                        Value::Type::Number
                )
                {
                    return false;
                }

                Value result;

                result.type =
                    Value::Type::Number;

                result.number =
                    lhs.number +
                    rhs.number;

                push(
                    std::move(result)
                );

                return true;
            }

            case OpCode::Sub:
            {
                if (stack.size() < 2)
                    return false;

                Value rhs = pop();
                Value lhs = pop();

                if (
                    lhs.type !=
                        Value::Type::Number ||
                    rhs.type !=
                        Value::Type::Number
                )
                {
                    return false;
                }

                Value result;

                result.type =
                    Value::Type::Number;

                result.number =
                    lhs.number -
                    rhs.number;

                push(
                    std::move(result)
                );

                return true;
            }

            case OpCode::Mul:
            {
                if (stack.size() < 2)
                    return false;

                Value rhs = pop();
                Value lhs = pop();

                if (
                    lhs.type !=
                        Value::Type::Number ||
                    rhs.type !=
                        Value::Type::Number
                )
                {
                    return false;
                }

                Value result;

                result.type =
                    Value::Type::Number;

                result.number =
                    lhs.number *
                    rhs.number;

                push(
                    std::move(result)
                );

                return true;
            }

            case OpCode::Div:
            {
                if (stack.size() < 2)
                    return false;

                Value rhs = pop();
                Value lhs = pop();

                if (
                    lhs.type !=
                        Value::Type::Number ||
                    rhs.type !=
                        Value::Type::Number
                )
                {
                    return false;
                }

                if (
                    std::abs(rhs.number) <=
                    std::numeric_limits<double>::epsilon()
                )
                {
                    return false;
                }

                Value result;

                result.type =
                    Value::Type::Number;

                result.number =
                    lhs.number /
                    rhs.number;

                push(
                    std::move(result)
                );

                return true;
            }

            case OpCode::Call:
            {
                /*
                 * Calls are handled by the host bridge once the
                 * environment layer is connected.
                 *
                 * For now this validates the stack shape and
                 * consumes the requested arguments.
                 */
                const std::size_t count =
                    instruction.a;

                if (
                    stack.size() <
                    count + 1
                )
                {
                    return false;
                }

                for (
                    std::size_t i = 0;
                    i < count;
                    ++i
                )
                {
                    pop();
                }

                pop();

                Value result;

                result.type =
                    Value::Type::Nil;

                push(
                    std::move(result)
                );

                return true;
            }

            case OpCode::Return:
            {
                halted = true;

                return true;
            }

            case OpCode::Pop:
            {
                if (stack.empty())
                    return false;

                pop();

                return true;
            }

            case OpCode::Jump:
            {
                /*
                 * The main execute loop normally advances PC.
                 *
                 * Convert the operand into a signed relative
                 * offset.
                 */
                const std::int32_t offset =
                    static_cast<std::int32_t>(
                        instruction.a
                    );

                const std::int64_t target =
                    static_cast<std::int64_t>(
                        programCounter
                    ) +
                    offset;

                if (
                    target < 0 ||
                    target >=
                        static_cast<std::int64_t>(
                            program.code.size()
                        )
                )
                {
                    return false;
                }

                programCounter =
                    static_cast<std::size_t>(
                        target
                    );

                return true;
            }

            case OpCode::JumpIfFalse:
            {
                if (stack.empty())
                    return false;

                Value condition =
                    pop();

                bool truthy = false;

                switch (condition.type)
                {
                    case Value::Type::Nil:
                        truthy = false;
                        break;

                    case Value::Type::Number:
                        truthy =
                            condition.number != 0.0;
                        break;

                    case Value::Type::String:
                        truthy = true;
                        break;
                }

                if (!truthy)
                {
                    const std::int32_t offset =
                        static_cast<std::int32_t>(
                            instruction.a
                        );

                    const std::int64_t target =
                        static_cast<std::int64_t>(
                            programCounter
                        ) +
                        offset;

                    if (
                        target < 0 ||
                        target >=
                            static_cast<std::int64_t>(
                                program.code.size()
                            )
                    )
                    {
                        return false;
                    }

                    programCounter =
                        static_cast<std::size_t>(
                            target
                        );
                }

                return true;
            }

            case OpCode::Halt:
            {
                halted = true;

                return true;
            }

            default:
            {
                return false;
            }
        }
    }

    bool VM::execute(
        const Program& program
    )
    {
        stack.clear();

        stackBase = 0;

        programCounter = 0;

        halted = false;

        if (program.code.empty())
            return false;

        /*
         * Safety limit prevents malformed bytecode from creating
         * an infinite interpreter loop.
         */
        constexpr std::size_t MAX_STEPS =
            10'000'000;

        std::size_t steps = 0;

        while (!halted)
        {
            if (
                programCounter >=
                program.code.size()
            )
            {
                return false;
            }

            if (++steps > MAX_STEPS)
            {
                return false;
            }

            const Instruction instruction =
                program.code[
                    programCounter
                ];

            /*
             * Save the current instruction index.
             * Jump instructions may modify programCounter.
             */
            const std::size_t before =
                programCounter;

            if (
                !executeInstruction(
                    instruction,
                    program
                )
            )
            {
                return false;
            }

            if (halted)
                break;

            /*
             * Unless an instruction explicitly changed PC,
             * advance to the next instruction.
             */
            if (
                programCounter ==
                before
            )
            {
                ++programCounter;
            }
        }

        return true;
    }
}