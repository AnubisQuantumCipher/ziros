// Stack-machine constraint evaluator for Goldilocks field.
// Compiles AirExpr trees to bytecode, interprets on GPU.
// Each thread evaluates ALL constraints for ONE row of the trace.
//
// Uses field helpers from field_goldilocks.metal (concatenated at compile time).

// Instruction opcodes (upper 8 bits of u32 instruction word)
constant uint8_t OP_CONST = 0;   // push constants[operand]
constant uint8_t OP_LOAD  = 1;   // push trace[row * width + operand]
constant uint8_t OP_ADD   = 2;   // pop 2, push sum
constant uint8_t OP_SUB   = 3;   // pop 2, push difference
constant uint8_t OP_MUL   = 4;   // pop 2, push product
constant uint8_t OP_DUP   = 5;   // duplicate top of stack
constant uint8_t OP_EMIT  = 6;   // pop and write to output[row * n_constraints + operand]

kernel void constraint_eval_goldilocks(
    device const uint64_t* trace [[buffer(0)]],
    device const uint32_t* bytecode [[buffer(1)]],
    device const uint64_t* constants [[buffer(2)]],
    device uint64_t* output [[buffer(3)]],
    constant uint32_t& width [[buffer(4)]],
    constant uint32_t& n_instructions [[buffer(5)]],
    constant uint32_t& n_constraints [[buffer(6)]],
    uint tid [[thread_position_in_grid]])
{
    // Each thread processes one row
    uint row = tid;

    // Fixed-size stack (32 deep should handle any reasonable constraint tree)
    uint64_t stack[32];
    uint sp = 0;

    for (uint pc = 0; pc < n_instructions; pc++) {
        uint32_t instr = bytecode[pc];
        uint8_t op = uint8_t(instr >> 24);
        uint32_t operand = instr & 0x00FFFFFF;

        switch (op) {
            case OP_CONST:
                stack[sp++] = constants[operand];
                break;
            case OP_LOAD:
                stack[sp++] = trace[row * width + operand];
                break;
            case OP_ADD: {
                uint64_t b = stack[--sp];
                uint64_t a = stack[--sp];
                stack[sp++] = gl_add(a, b);
                break;
            }
            case OP_SUB: {
                uint64_t b = stack[--sp];
                uint64_t a = stack[--sp];
                stack[sp++] = gl_sub(a, b);
                break;
            }
            case OP_MUL: {
                uint64_t b = stack[--sp];
                uint64_t a = stack[--sp];
                stack[sp++] = gl_mul(a, b);
                break;
            }
            case OP_DUP:
                stack[sp] = stack[sp - 1];
                sp++;
                break;
            case OP_EMIT: {
                uint64_t val = stack[--sp];
                output[row * n_constraints + operand] = val;
                break;
            }
        }
    }
}
