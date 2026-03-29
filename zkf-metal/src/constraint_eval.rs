//! GPU-accelerated constraint evaluation via stack-machine bytecode.
//!
//! AIR constraint expressions are compiled to a simple bytecode format that
//! a GPU kernel interprets per-row. Each thread evaluates ALL constraints for
//! one row of the trace matrix.

use crate::async_dispatch;
use crate::device::{self, MetalContext};
use crate::shader_library::kernels;
use objc2_metal::{
    MTLCommandBuffer, MTLCommandEncoder, MTLComputeCommandEncoder, MTLComputePipelineState, MTLSize,
};
use std::ptr::NonNull;

/// Bytecode opcodes (must match constraint_eval.metal).
pub const OP_CONST: u8 = 0;
pub const OP_LOAD: u8 = 1;
pub const OP_ADD: u8 = 2;
pub const OP_SUB: u8 = 3;
pub const OP_MUL: u8 = 4;
pub const OP_DUP: u8 = 5;
pub const OP_EMIT: u8 = 6;

/// Encode an instruction: opcode in top 8 bits, operand in lower 24 bits.
pub fn encode_instruction(op: u8, operand: u32) -> u32 {
    ((op as u32) << 24) | (operand & 0x00FFFFFF)
}

/// Builder for constraint bytecode programs.
pub struct ConstraintCompiler {
    bytecode: Vec<u32>,
    constants: Vec<u64>,
    n_constraints: usize,
}

impl Default for ConstraintCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl ConstraintCompiler {
    pub fn new() -> Self {
        Self {
            bytecode: Vec::new(),
            constants: Vec::new(),
            n_constraints: 0,
        }
    }

    /// Push a constant value onto the stack.
    pub fn push_const(&mut self, value: u64) {
        let idx = self.constants.len() as u32;
        self.constants.push(value);
        self.bytecode.push(encode_instruction(OP_CONST, idx));
    }

    /// Push a trace column value onto the stack.
    pub fn load_column(&mut self, col: u32) {
        self.bytecode.push(encode_instruction(OP_LOAD, col));
    }

    /// Pop two values, push their sum.
    pub fn add(&mut self) {
        self.bytecode.push(encode_instruction(OP_ADD, 0));
    }

    /// Pop two values, push their difference.
    pub fn sub(&mut self) {
        self.bytecode.push(encode_instruction(OP_SUB, 0));
    }

    /// Pop two values, push their product.
    pub fn mul(&mut self) {
        self.bytecode.push(encode_instruction(OP_MUL, 0));
    }

    /// Duplicate the top of stack.
    pub fn dup(&mut self) {
        self.bytecode.push(encode_instruction(OP_DUP, 0));
    }

    /// Pop top of stack and write to constraint output slot.
    pub fn emit(&mut self, constraint_idx: u32) {
        self.bytecode
            .push(encode_instruction(OP_EMIT, constraint_idx));
        if constraint_idx as usize >= self.n_constraints {
            self.n_constraints = constraint_idx as usize + 1;
        }
    }

    /// Get the compiled bytecode and constant pool.
    pub fn finish(self) -> (Vec<u32>, Vec<u64>, usize) {
        (self.bytecode, self.constants, self.n_constraints)
    }
}

const MIN_CONSTRAINT_EVAL_ROWS: usize = 1_024;

/// Metal constraint evaluation accelerator.
pub struct MetalConstraintEval {
    ctx: &'static MetalContext,
}

impl MetalConstraintEval {
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { ctx })
    }

    /// Evaluate compiled constraints on a trace matrix (Goldilocks field).
    ///
    /// `trace`: flat row-major trace matrix (n_rows * width u64 values)
    /// `width`: number of columns in the trace
    /// `bytecode`: compiled constraint program
    /// `constants`: constant pool for the program
    /// `n_constraints`: number of constraint outputs per row
    ///
    /// Returns: flat array of n_rows * n_constraints constraint evaluations.
    pub fn eval_trace_goldilocks(
        &self,
        trace: &[u64],
        width: usize,
        bytecode: &[u32],
        constants: &[u64],
        n_constraints: usize,
    ) -> Option<Vec<u64>> {
        if width == 0 || trace.is_empty() || !trace.len().is_multiple_of(width) {
            return None;
        }
        let n_rows = trace.len() / width;
        if n_rows < MIN_CONSTRAINT_EVAL_ROWS || bytecode.is_empty() || n_constraints == 0 {
            return None;
        }

        let pipeline = self.ctx.pipeline(kernels::CONSTRAINT_EVAL_GOLDILOCKS)?;

        let trace_buf = self.ctx.new_buffer_from_slice(trace)?;
        let bytecode_buf = self.ctx.new_buffer_from_slice(bytecode)?;
        let const_buf = if constants.is_empty() {
            self.ctx.new_buffer(8)? // Metal requires non-zero length
        } else {
            self.ctx.new_buffer_from_slice(constants)?
        };
        let output_size = n_rows * n_constraints;
        let output_buf = self
            .ctx
            .new_buffer(output_size * std::mem::size_of::<u64>())?;

        let width_u32 = width as u32;
        let n_instr = bytecode.len() as u32;
        let n_const = n_constraints as u32;

        let cmd = self.ctx.command_buffer()?;
        let enc = cmd.computeCommandEncoder()?;

        unsafe {
            enc.setComputePipelineState(&pipeline);
            enc.setBuffer_offset_atIndex(Some(&*trace_buf), 0, 0);
            enc.setBuffer_offset_atIndex(Some(&*bytecode_buf), 0, 1);
            enc.setBuffer_offset_atIndex(Some(&*const_buf), 0, 2);
            enc.setBuffer_offset_atIndex(Some(&*output_buf), 0, 3);
            enc.setBytes_length_atIndex(NonNull::from(&width_u32).cast(), 4, 4);
            enc.setBytes_length_atIndex(NonNull::from(&n_instr).cast(), 4, 5);
            enc.setBytes_length_atIndex(NonNull::from(&n_const).cast(), 4, 6);

            let max_tpg = pipeline.maxTotalThreadsPerThreadgroup().min(256);
            let num_groups = n_rows.div_ceil(max_tpg);

            enc.dispatchThreadgroups_threadsPerThreadgroup(
                MTLSize {
                    width: num_groups,
                    height: 1,
                    depth: 1,
                },
                MTLSize {
                    width: max_tpg,
                    height: 1,
                    depth: 1,
                },
            );
        }

        enc.endEncoding();
        async_dispatch::commit_and_wait(cmd, "constraint-eval").ok()?;

        Some(self.ctx.read_buffer(&output_buf, output_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GL_P: u64 = 0xFFFFFFFF00000001;

    fn gl_add(a: u64, b: u64) -> u64 {
        let sum = a as u128 + b as u128;
        if sum >= GL_P as u128 {
            (sum - GL_P as u128) as u64
        } else {
            sum as u64
        }
    }

    fn gl_mul(a: u64, b: u64) -> u64 {
        let prod = a as u128 * b as u128;
        let lo = prod as u64;
        let hi = (prod >> 64) as u64;
        let hi_shifted = (hi as u128) * ((1u128 << 32) - 1);
        let sum = lo as u128 + hi_shifted;
        let lo2 = sum as u64;
        let hi2 = (sum >> 64) as u64;
        if hi2 == 0 {
            if lo2 >= GL_P { lo2 - GL_P } else { lo2 }
        } else {
            let hi2_shifted = (hi2 as u128) * ((1u128 << 32) - 1);
            let final_sum = lo2 as u128 + hi2_shifted;
            (final_sum % GL_P as u128) as u64
        }
    }

    #[test]
    fn constraint_eval_add_mul() {
        let eval = match MetalConstraintEval::new() {
            Some(e) => e,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        // Constraint: c0 = col[0] + col[1], c1 = col[0] * col[1]
        let mut compiler = ConstraintCompiler::new();
        // c0 = col[0] + col[1]
        compiler.load_column(0);
        compiler.load_column(1);
        compiler.add();
        compiler.emit(0);
        // c1 = col[0] * col[1]
        compiler.load_column(0);
        compiler.load_column(1);
        compiler.mul();
        compiler.emit(1);

        let (bytecode, constants, n_constraints) = compiler.finish();
        assert_eq!(n_constraints, 2);

        let n_rows = 2048;
        let width = 2;
        let trace: Vec<u64> = (0..n_rows * width)
            .map(|i| ((i as u64) * 7 + 1) % GL_P)
            .collect();

        let result =
            eval.eval_trace_goldilocks(&trace, width, &bytecode, &constants, n_constraints);
        assert!(result.is_some(), "GPU constraint eval should succeed");
        let result = result.unwrap();
        assert_eq!(result.len(), n_rows * n_constraints);

        for row in 0..n_rows {
            let a = trace[row * width];
            let b = trace[row * width + 1];
            let expected_sum = gl_add(a, b);
            let expected_prod = gl_mul(a, b);
            assert_eq!(
                result[row * n_constraints],
                expected_sum,
                "Sum mismatch at row {}",
                row
            );
            assert_eq!(
                result[row * n_constraints + 1],
                expected_prod,
                "Prod mismatch at row {}",
                row
            );
        }
    }
}
