//! Hardware acceleration traits and registry for ZK proving bottleneck operations.
//!
//! The two primary bottlenecks in ZK proving are:
//! - **MSM** (Multi-Scalar Multiplication): Computing ∑ s_i · G_i for scalar s_i and group points G_i
//! - **NTT** (Number Theoretic Transform): FFT over finite fields for polynomial operations
//!
//! These traits provide a backend-agnostic abstraction for GPU, FPGA, and other
//! hardware accelerators. CPU fallback implementations are always available.
//!
//! The `AcceleratorRegistry` provides a global priority-ordered registry:
//! - Metal GPU accelerators are inserted at priority 0 (highest) on macOS
//! - CPU fallbacks are always registered as the lowest priority
//! - Query `accelerator_registry()` to get the best available accelerator

use crate::{FieldElement, FieldId, ZkfResult};
use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::sync::{Mutex, OnceLock};

/// Accelerator for Multi-Scalar Multiplication (MSM).
///
/// MSM computes the sum of scalar-point products: result = ∑ scalars[i] * bases[i].
/// This is the dominant cost in Groth16 proving and KZG commitment schemes.
pub trait MsmAccelerator: Send + Sync {
    /// Human-readable name for this accelerator (e.g., "cuda-msm", "cpu-pippenger").
    fn name(&self) -> &str;

    /// Whether this accelerator is available on the current system.
    fn is_available(&self) -> bool;

    /// Perform MSM over G1 curve points.
    ///
    /// `scalars` and `bases` must have the same length. `bases` are encoded
    /// group points (format is accelerator-specific, typically uncompressed affine).
    fn msm_g1(&self, scalars: &[FieldElement], bases: &[Vec<u8>]) -> ZkfResult<Vec<u8>>;

    /// Perform MSM over G2 curve points (for pairing-based schemes).
    fn msm_g2(&self, scalars: &[FieldElement], bases: &[Vec<u8>]) -> ZkfResult<Vec<u8>> {
        let _ = (scalars, bases);
        Err(crate::ZkfError::Backend(
            "G2 MSM not supported by this accelerator".to_string(),
        ))
    }

    /// Maximum batch size this accelerator can handle efficiently.
    fn max_batch_size(&self) -> usize {
        1 << 20 // 1M points default
    }

    /// Minimum batch size that should use this accelerator rather than CPU fallback.
    fn min_batch_size(&self) -> usize {
        1
    }
}

/// Accelerator for Number Theoretic Transform (NTT).
///
/// NTT is the finite field equivalent of FFT, used for polynomial multiplication
/// and evaluation in STARK/FRI proving and PLONK polynomial commitments.
pub trait NttAccelerator: Send + Sync {
    /// Human-readable name for this accelerator.
    fn name(&self) -> &str;

    /// Whether this accelerator is available on the current system.
    fn is_available(&self) -> bool;

    /// Perform forward NTT (evaluation form → coefficient form).
    ///
    /// `values` must have length equal to a power of 2.
    fn forward_ntt(&self, values: &mut [FieldElement]) -> ZkfResult<()>;

    /// Perform inverse NTT (coefficient form → evaluation form).
    fn inverse_ntt(&self, values: &mut [FieldElement]) -> ZkfResult<()>;

    /// Maximum supported NTT size (log2).
    fn max_log_size(&self) -> u32 {
        24 // 2^24 = 16M elements default
    }
}

/// Accelerator for batch cryptographic hashing (SHA-256, Keccak-256).
///
/// Batch hashing is used in Merkle tree construction and STARK commitment
/// schemes. GPU acceleration provides significant speedup for large batches.
pub trait HashAccelerator: Send + Sync {
    /// Human-readable name for this accelerator.
    fn name(&self) -> &str;

    /// Whether this accelerator is available on the current system.
    fn is_available(&self) -> bool;

    /// Batch SHA-256: hash `n` inputs of `input_len` bytes each.
    ///
    /// `inputs` must be exactly `n * input_len` bytes (contiguous).
    /// Returns `n * 32` bytes of SHA-256 digests.
    fn batch_sha256(&self, inputs: &[u8], input_len: usize) -> ZkfResult<Vec<u8>>;

    /// Batch Keccak-256: hash `n` inputs of `input_len` bytes each.
    fn batch_keccak256(&self, inputs: &[u8], input_len: usize) -> ZkfResult<Vec<u8>>;

    /// Minimum batch size for efficient GPU dispatch.
    fn min_batch_size(&self) -> usize {
        1_000
    }
}

/// Accelerator for batch Poseidon2 permutations.
///
/// Poseidon2 is the primary hash function used in Plonky3 STARK provers.
/// GPU batch permutation provides 10-50x speedup over CPU for large batches.
pub trait Poseidon2Accelerator: Send + Sync {
    /// Human-readable name for this accelerator.
    fn name(&self) -> &str;

    /// Whether this accelerator is available on the current system.
    fn is_available(&self) -> bool;

    /// Batch Poseidon2 permutation over Goldilocks field (width=16, u64 elements).
    ///
    /// `states` is a flat array of `n_perms * 16` u64 field elements, modified in-place.
    fn batch_permute_goldilocks(
        &self,
        states: &mut [u64],
        round_constants: &[u64],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> ZkfResult<()>;

    /// Batch Poseidon2 permutation over BabyBear field (width=16, u32 elements).
    fn batch_permute_babybear(
        &self,
        states: &mut [u32],
        round_constants: &[u32],
        n_external_rounds: u32,
        n_internal_rounds: u32,
    ) -> ZkfResult<()>;

    /// Minimum batch size for efficient GPU dispatch.
    fn min_batch_size(&self) -> usize {
        500
    }
}

/// Accelerator for batch field arithmetic operations.
///
/// Batch field ops (add, sub, mul) are used in witness generation and
/// polynomial evaluation. GPU acceleration provides speedup for large batches.
pub trait FieldOpsAccelerator: Send + Sync {
    /// Human-readable name for this accelerator.
    fn name(&self) -> &str;

    /// Whether this accelerator is available on the current system.
    fn is_available(&self) -> bool;

    /// Batch element-wise addition over Goldilocks field (in-place on `a`).
    fn batch_add_goldilocks(&self, a: &mut [u64], b: &[u64]) -> ZkfResult<()>;

    /// Batch element-wise multiplication over Goldilocks field (in-place on `a`).
    fn batch_mul_goldilocks(&self, a: &mut [u64], b: &[u64]) -> ZkfResult<()>;

    /// Batch element-wise subtraction over Goldilocks field (in-place on `a`).
    fn batch_sub_goldilocks(&self, a: &mut [u64], b: &[u64]) -> ZkfResult<()>;

    /// Minimum batch size for efficient GPU dispatch.
    fn min_batch_size(&self) -> usize {
        4_000
    }
}

/// Accelerator for polynomial operations (evaluation, coset, quotient).
pub trait PolyOpsAccelerator: Send + Sync {
    /// Human-readable name for this accelerator.
    fn name(&self) -> &str;

    /// Whether this accelerator is available on the current system.
    fn is_available(&self) -> bool;

    /// Batch polynomial evaluation using Horner's method.
    /// Evaluates a polynomial (given by `coeffs`) at each point in `points`.
    fn batch_eval_goldilocks(&self, coeffs: &[u64], points: &[u64]) -> ZkfResult<Vec<u64>>;

    /// Evaluate polynomial on coset `shift * omega^i` for i in 0..2^log_n.
    fn coset_eval_goldilocks(&self, coeffs: &[u64], shift: u64, log_n: u32) -> ZkfResult<Vec<u64>>;

    /// Compute quotient polynomial: (f(x) - f_z) / (x - z) per evaluation point.
    fn quotient_goldilocks(&self, evals: &[u64], z: u64, f_z: u64) -> ZkfResult<Vec<u64>>;

    /// Minimum batch size for efficient GPU dispatch.
    fn min_batch_size(&self) -> usize {
        1_024
    }
}

/// Accelerator for FRI folding operations.
pub trait FriAccelerator: Send + Sync {
    /// Human-readable name for this accelerator.
    fn name(&self) -> &str;

    /// Whether this accelerator is available on the current system.
    fn is_available(&self) -> bool;

    /// FRI fold: combine pairs of evaluations using random challenge alpha.
    /// g[i] = (f[2i] + f[2i+1]) / 2 + alpha * (f[2i] - f[2i+1]) * inv_twiddles[i]
    fn fold_goldilocks(
        &self,
        evals: &[u64],
        alpha: u64,
        inv_twiddles: &[u64],
    ) -> ZkfResult<Vec<u64>>;

    /// Minimum polynomial size for efficient GPU dispatch.
    fn min_fold_size(&self) -> usize {
        1_024
    }
}

/// Accelerator for constraint evaluation (stack-machine bytecode interpreter).
pub trait ConstraintEvalAccelerator: Send + Sync {
    /// Human-readable name for this accelerator.
    fn name(&self) -> &str;

    /// Whether this accelerator is available on the current system.
    fn is_available(&self) -> bool;

    /// Evaluate compiled constraints on a trace matrix.
    /// Returns flat array of constraint results: n_rows * n_constraints elements.
    fn eval_trace_goldilocks(
        &self,
        trace: &[u64],
        width: usize,
        bytecode: &[u32],
        constants: &[u64],
        n_constraints: usize,
    ) -> ZkfResult<Vec<u64>>;

    /// Minimum number of rows for efficient GPU dispatch.
    fn min_rows(&self) -> usize {
        1_024
    }
}

/// CPU fallback MSM accelerator.
///
/// Performs MSM by interpreting scalars as BN254 Fr elements and bases as
/// compressed G1Affine points, then computing a native arkworks MSM.
pub struct CpuMsmAccelerator;

impl MsmAccelerator for CpuMsmAccelerator {
    fn name(&self) -> &str {
        "cpu-msm"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn msm_g1(&self, scalars: &[FieldElement], bases: &[Vec<u8>]) -> ZkfResult<Vec<u8>> {
        if scalars.len() != bases.len() {
            return Err(crate::ZkfError::Backend(format!(
                "MSM size mismatch: {} scalars vs {} bases",
                scalars.len(),
                bases.len()
            )));
        }
        if scalars.is_empty() {
            return serialize_g1_affine(&G1Affine::identity());
        }

        let ark_bases = bases
            .iter()
            .map(|encoded| {
                G1Affine::deserialize_compressed(encoded.as_slice()).map_err(|err| {
                    crate::ZkfError::Backend(format!("invalid BN254 G1 base: {err}"))
                })
            })
            .collect::<ZkfResult<Vec<_>>>()?;
        let scalar_bigints = scalars
            .iter()
            .map(field_element_to_bn254_fr)
            .map(|scalar| scalar.map(|scalar| scalar.into_bigint()))
            .collect::<ZkfResult<Vec<_>>>()?;

        let result = G1Projective::msm_bigint(&ark_bases, &scalar_bigints);
        serialize_g1_affine(&result.into_affine())
    }
}

fn field_element_to_bn254_fr(value: &FieldElement) -> ZkfResult<Fr> {
    let normalized = value.normalized_bigint(FieldId::Bn254)?;
    let (_, bytes) = normalized.to_bytes_le();
    Ok(Fr::from_le_bytes_mod_order(&bytes))
}

fn serialize_g1_affine(point: &G1Affine) -> ZkfResult<Vec<u8>> {
    let mut bytes = Vec::new();
    point.serialize_compressed(&mut bytes).map_err(|err| {
        crate::ZkfError::Backend(format!("failed to serialize BN254 point: {err}"))
    })?;
    Ok(bytes)
}

/// CPU fallback NTT accelerator.
///
/// Performs in-place radix-2 Cooley-Tukey NTT over the Goldilocks field
/// (p = 2^64 - 2^32 + 1). The field element values are extracted from
/// `FieldElement.to_le_bytes()` (first 8 bytes as u64).
pub struct CpuNttAccelerator;

/// Goldilocks field modulus: p = 2^64 - 2^32 + 1
const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

/// Modular multiplication for Goldilocks field using 128-bit intermediate.
fn goldilocks_mul(a: u64, b: u64) -> u64 {
    let prod = (a as u128) * (b as u128);
    goldilocks_reduce_128(prod)
}

/// Reduce a 128-bit value modulo Goldilocks p.
fn goldilocks_reduce_128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    // p = 2^64 - 2^32 + 1, so 2^64 ≡ 2^32 - 1 (mod p)
    // x = hi * 2^64 + lo ≡ hi * (2^32 - 1) + lo (mod p)
    let hi_shifted = (hi as u128) * ((1u128 << 32) - 1);
    let sum = lo as u128 + hi_shifted;
    // One more reduction if needed
    let lo2 = sum as u64;
    let hi2 = (sum >> 64) as u64;
    if hi2 == 0 {
        if lo2 >= GOLDILOCKS_P {
            lo2 - GOLDILOCKS_P
        } else {
            lo2
        }
    } else {
        let hi2_shifted = (hi2 as u128) * ((1u128 << 32) - 1);
        let final_sum = lo2 as u128 + hi2_shifted;
        (final_sum % GOLDILOCKS_P as u128) as u64
    }
}

/// Modular exponentiation for Goldilocks field.
fn goldilocks_pow(mut base: u64, mut exp: u64) -> u64 {
    let mut result = 1u64;
    base %= GOLDILOCKS_P;
    while exp > 0 {
        if exp & 1 == 1 {
            result = goldilocks_mul(result, base);
        }
        exp >>= 1;
        base = goldilocks_mul(base, base);
    }
    result
}

/// Modular inverse via Fermat's little theorem: a^{-1} = a^{p-2} mod p.
fn goldilocks_inv(a: u64) -> u64 {
    goldilocks_pow(a, GOLDILOCKS_P - 2)
}

/// Modular subtraction in Goldilocks field.
fn goldilocks_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        GOLDILOCKS_P - (b - a)
    }
}

/// Modular addition in Goldilocks field.
fn goldilocks_add(a: u64, b: u64) -> u64 {
    let sum = a as u128 + b as u128;
    if sum >= GOLDILOCKS_P as u128 {
        (sum - GOLDILOCKS_P as u128) as u64
    } else {
        sum as u64
    }
}

/// Extract u64 from FieldElement (first 8 bytes, little-endian).
fn field_element_to_u64(fe: &FieldElement) -> u64 {
    let bytes = fe.to_le_bytes();
    let mut buf = [0u8; 8];
    let len = bytes.len().min(8);
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_le_bytes(buf)
}

/// Convert u64 back to FieldElement.
fn u64_to_field_element(v: u64) -> FieldElement {
    FieldElement::new(v.to_string())
}

/// Bit-reversal permutation for NTT.
fn bit_reverse_permutation(values: &mut [u64]) {
    let n = values.len();
    let log_n = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - log_n);
        if i < j {
            values.swap(i, j);
        }
    }
}

impl NttAccelerator for CpuNttAccelerator {
    fn name(&self) -> &str {
        "cpu-ntt"
    }

    fn is_available(&self) -> bool {
        true
    }

    fn forward_ntt(&self, values: &mut [FieldElement]) -> ZkfResult<()> {
        let n = values.len();
        if n == 0 {
            return Ok(());
        }
        if !n.is_power_of_two() {
            return Err(crate::ZkfError::Backend(format!(
                "NTT size must be a power of 2, got {n}"
            )));
        }
        if n == 1 {
            return Ok(());
        }

        // Extract u64 values
        let mut data: Vec<u64> = values.iter().map(field_element_to_u64).collect();

        // Bit-reversal permutation
        bit_reverse_permutation(&mut data);

        // Primitive root of unity: ω = 7^((p-1)/n) mod p
        let omega = goldilocks_pow(7, (GOLDILOCKS_P - 1) / n as u64);

        // Cooley-Tukey butterfly
        let mut len = 2;
        while len <= n {
            let half = len / 2;
            let w_step = goldilocks_pow(omega, (n / len) as u64);
            for start in (0..n).step_by(len) {
                let mut w = 1u64;
                for j in 0..half {
                    let u = data[start + j];
                    let v = goldilocks_mul(data[start + j + half], w);
                    data[start + j] = goldilocks_add(u, v);
                    data[start + j + half] = goldilocks_sub(u, v);
                    w = goldilocks_mul(w, w_step);
                }
            }
            len *= 2;
        }

        // Write back
        for (i, val) in data.iter().enumerate() {
            values[i] = u64_to_field_element(*val);
        }
        Ok(())
    }

    fn inverse_ntt(&self, values: &mut [FieldElement]) -> ZkfResult<()> {
        let n = values.len();
        if n <= 1 {
            return Ok(());
        }
        if !n.is_power_of_two() {
            return Err(crate::ZkfError::Backend(format!(
                "NTT size must be a power of 2, got {n}"
            )));
        }

        let mut data: Vec<u64> = values.iter().map(field_element_to_u64).collect();

        bit_reverse_permutation(&mut data);

        // Inverse root: ω^{-1} = 7^{-(p-1)/n} = (7^{(p-1)/n})^{-1}
        let omega = goldilocks_pow(7, (GOLDILOCKS_P - 1) / n as u64);
        let omega_inv = goldilocks_inv(omega);

        let mut len = 2;
        while len <= n {
            let half = len / 2;
            let w_step = goldilocks_pow(omega_inv, (n / len) as u64);
            for start in (0..n).step_by(len) {
                let mut w = 1u64;
                for j in 0..half {
                    let u = data[start + j];
                    let v = goldilocks_mul(data[start + j + half], w);
                    data[start + j] = goldilocks_add(u, v);
                    data[start + j + half] = goldilocks_sub(u, v);
                    w = goldilocks_mul(w, w_step);
                }
            }
            len *= 2;
        }

        // Multiply by n^{-1}
        let n_inv = goldilocks_inv(n as u64);
        for val in data.iter_mut() {
            *val = goldilocks_mul(*val, n_inv);
        }

        for (i, val) in data.iter().enumerate() {
            values[i] = u64_to_field_element(*val);
        }
        Ok(())
    }
}

/// Global accelerator registry with priority ordering.
///
/// Accelerators are stored in priority order (index 0 = highest priority).
/// Metal GPU accelerators should be registered at priority 0, with CPU
/// fallbacks at the end.
pub struct AcceleratorRegistry {
    msm: Vec<Box<dyn MsmAccelerator>>,
    ntt: Vec<Box<dyn NttAccelerator>>,
    hash: Vec<Box<dyn HashAccelerator>>,
    poseidon2: Vec<Box<dyn Poseidon2Accelerator>>,
    field_ops: Vec<Box<dyn FieldOpsAccelerator>>,
    poly_ops: Vec<Box<dyn PolyOpsAccelerator>>,
    fri: Vec<Box<dyn FriAccelerator>>,
    constraint_eval: Vec<Box<dyn ConstraintEvalAccelerator>>,
}

impl AcceleratorRegistry {
    fn new() -> Self {
        let mut reg = Self {
            msm: Vec::new(),
            ntt: Vec::new(),
            hash: Vec::new(),
            poseidon2: Vec::new(),
            field_ops: Vec::new(),
            poly_ops: Vec::new(),
            fri: Vec::new(),
            constraint_eval: Vec::new(),
        };
        // Always register CPU fallbacks
        reg.msm.push(Box::new(CpuMsmAccelerator));
        reg.ntt.push(Box::new(CpuNttAccelerator));
        reg
    }

    /// Register an MSM accelerator at a given priority (0 = highest).
    pub fn register_msm(&mut self, priority: usize, acc: Box<dyn MsmAccelerator>) {
        let idx = priority.min(self.msm.len());
        self.msm.insert(idx, acc);
    }

    /// Register an NTT accelerator at a given priority (0 = highest).
    pub fn register_ntt(&mut self, priority: usize, acc: Box<dyn NttAccelerator>) {
        let idx = priority.min(self.ntt.len());
        self.ntt.insert(idx, acc);
    }

    /// Register a hash accelerator at a given priority (0 = highest).
    pub fn register_hash(&mut self, priority: usize, acc: Box<dyn HashAccelerator>) {
        let idx = priority.min(self.hash.len());
        self.hash.insert(idx, acc);
    }

    /// Register a Poseidon2 accelerator at a given priority (0 = highest).
    pub fn register_poseidon2(&mut self, priority: usize, acc: Box<dyn Poseidon2Accelerator>) {
        let idx = priority.min(self.poseidon2.len());
        self.poseidon2.insert(idx, acc);
    }

    /// Register a field ops accelerator at a given priority (0 = highest).
    pub fn register_field_ops(&mut self, priority: usize, acc: Box<dyn FieldOpsAccelerator>) {
        let idx = priority.min(self.field_ops.len());
        self.field_ops.insert(idx, acc);
    }

    /// Register a poly ops accelerator at a given priority (0 = highest).
    pub fn register_poly_ops(&mut self, priority: usize, acc: Box<dyn PolyOpsAccelerator>) {
        let idx = priority.min(self.poly_ops.len());
        self.poly_ops.insert(idx, acc);
    }

    /// Register a FRI accelerator at a given priority (0 = highest).
    pub fn register_fri(&mut self, priority: usize, acc: Box<dyn FriAccelerator>) {
        let idx = priority.min(self.fri.len());
        self.fri.insert(idx, acc);
    }

    /// Register a constraint eval accelerator at a given priority (0 = highest).
    pub fn register_constraint_eval(
        &mut self,
        priority: usize,
        acc: Box<dyn ConstraintEvalAccelerator>,
    ) {
        let idx = priority.min(self.constraint_eval.len());
        self.constraint_eval.insert(idx, acc);
    }

    /// Get the best available MSM accelerator.
    pub fn best_msm(&self) -> &dyn MsmAccelerator {
        self.msm
            .iter()
            .find(|a| a.is_available())
            .map(|a| a.as_ref())
            .unwrap_or(&CpuMsmAccelerator as &dyn MsmAccelerator)
    }

    /// Get the best available NTT accelerator.
    pub fn best_ntt(&self) -> &dyn NttAccelerator {
        self.ntt
            .iter()
            .find(|a| a.is_available())
            .map(|a| a.as_ref())
            .unwrap_or(&CpuNttAccelerator as &dyn NttAccelerator)
    }

    /// Get the best available hash accelerator, if any.
    pub fn best_hash(&self) -> Option<&dyn HashAccelerator> {
        self.hash
            .iter()
            .find(|a| a.is_available())
            .map(|a| a.as_ref())
    }

    /// Get the best available Poseidon2 accelerator, if any.
    pub fn best_poseidon2(&self) -> Option<&dyn Poseidon2Accelerator> {
        self.poseidon2
            .iter()
            .find(|a| a.is_available())
            .map(|a| a.as_ref())
    }

    /// List all registered MSM accelerators in priority order.
    pub fn msm_accelerators(&self) -> &[Box<dyn MsmAccelerator>] {
        &self.msm
    }

    /// List all registered NTT accelerators in priority order.
    pub fn ntt_accelerators(&self) -> &[Box<dyn NttAccelerator>] {
        &self.ntt
    }

    /// List all registered hash accelerators in priority order.
    pub fn hash_accelerators(&self) -> &[Box<dyn HashAccelerator>] {
        &self.hash
    }

    /// List all registered Poseidon2 accelerators in priority order.
    pub fn poseidon2_accelerators(&self) -> &[Box<dyn Poseidon2Accelerator>] {
        &self.poseidon2
    }

    /// Get the best available field ops accelerator, if any.
    pub fn best_field_ops(&self) -> Option<&dyn FieldOpsAccelerator> {
        self.field_ops
            .iter()
            .find(|a| a.is_available())
            .map(|a| a.as_ref())
    }

    /// List all registered field ops accelerators in priority order.
    pub fn field_ops_accelerators(&self) -> &[Box<dyn FieldOpsAccelerator>] {
        &self.field_ops
    }

    /// Get the best available poly ops accelerator, if any.
    pub fn best_poly_ops(&self) -> Option<&dyn PolyOpsAccelerator> {
        self.poly_ops
            .iter()
            .find(|a| a.is_available())
            .map(|a| a.as_ref())
    }

    /// List all registered poly ops accelerators in priority order.
    pub fn poly_ops_accelerators(&self) -> &[Box<dyn PolyOpsAccelerator>] {
        &self.poly_ops
    }

    /// Get the best available FRI accelerator, if any.
    pub fn best_fri(&self) -> Option<&dyn FriAccelerator> {
        self.fri
            .iter()
            .find(|a| a.is_available())
            .map(|a| a.as_ref())
    }

    /// List all registered FRI accelerators in priority order.
    pub fn fri_accelerators(&self) -> &[Box<dyn FriAccelerator>] {
        &self.fri
    }

    /// Get the best available constraint eval accelerator, if any.
    pub fn best_constraint_eval(&self) -> Option<&dyn ConstraintEvalAccelerator> {
        self.constraint_eval
            .iter()
            .find(|a| a.is_available())
            .map(|a| a.as_ref())
    }

    /// List all registered constraint-eval accelerators in priority order.
    pub fn constraint_eval_accelerators(&self) -> &[Box<dyn ConstraintEvalAccelerator>] {
        &self.constraint_eval
    }
}

static REGISTRY: OnceLock<Mutex<AcceleratorRegistry>> = OnceLock::new();

/// Get the global accelerator registry.
///
/// On first call, initializes with CPU fallbacks. Metal GPU accelerators
/// are registered by `zkf-backends` when the `metal-gpu` feature is enabled.
pub fn accelerator_registry() -> &'static Mutex<AcceleratorRegistry> {
    REGISTRY.get_or_init(|| Mutex::new(AcceleratorRegistry::new()))
}

/// Query available MSM accelerators on the system (priority-ordered).
pub fn available_msm_accelerators() -> Vec<Box<dyn MsmAccelerator>> {
    // Return from registry, but since we can't move out of Mutex,
    // return fresh instances matching the registry state.
    vec![Box::new(CpuMsmAccelerator)]
}

/// Query available NTT accelerators on the system.
pub fn available_ntt_accelerators() -> Vec<Box<dyn NttAccelerator>> {
    vec![Box::new(CpuNttAccelerator)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, PrimeGroup};

    #[test]
    fn cpu_msm_available() {
        let acc = CpuMsmAccelerator;
        assert!(acc.is_available());
        assert_eq!(acc.name(), "cpu-msm");
    }

    #[test]
    fn cpu_ntt_available() {
        let acc = CpuNttAccelerator;
        assert!(acc.is_available());
        assert_eq!(acc.name(), "cpu-ntt");
    }

    #[test]
    fn msm_size_mismatch() {
        let acc = CpuMsmAccelerator;
        let scalars = vec![FieldElement::from_i64(1)];
        let bases: Vec<Vec<u8>> = vec![vec![0], vec![1]];
        assert!(acc.msm_g1(&scalars, &bases).is_err());
    }

    #[test]
    fn available_accelerators_include_cpu() {
        let msm = available_msm_accelerators();
        assert!(!msm.is_empty());
        assert!(msm[0].is_available());

        let ntt = available_ntt_accelerators();
        assert!(!ntt.is_empty());
        assert!(ntt[0].is_available());
    }

    #[test]
    fn goldilocks_arithmetic() {
        // Basic sanity checks
        assert_eq!(goldilocks_add(0, 0), 0);
        assert_eq!(goldilocks_add(1, 1), 2);
        assert_eq!(goldilocks_mul(2, 3), 6);
        assert_eq!(goldilocks_sub(5, 3), 2);
        assert_eq!(goldilocks_sub(0, 1), GOLDILOCKS_P - 1);

        // Inverse: a * a^{-1} = 1
        let a = 42u64;
        let a_inv = goldilocks_inv(a);
        assert_eq!(goldilocks_mul(a, a_inv), 1);
    }

    #[test]
    fn ntt_forward_inverse_roundtrip() {
        let acc = CpuNttAccelerator;
        let original = vec![
            FieldElement::from_i64(1),
            FieldElement::from_i64(2),
            FieldElement::from_i64(3),
            FieldElement::from_i64(4),
        ];
        let mut values = original.clone();

        acc.forward_ntt(&mut values).unwrap();
        // After forward NTT, values should differ from original
        assert_ne!(values, original);

        acc.inverse_ntt(&mut values).unwrap();
        // After inverse, should be back to original
        for (a, b) in values.iter().zip(original.iter()) {
            assert_eq!(
                field_element_to_u64(a),
                field_element_to_u64(b),
                "NTT roundtrip mismatch"
            );
        }
    }

    #[test]
    fn ntt_size_8_roundtrip() {
        let acc = CpuNttAccelerator;
        let original: Vec<FieldElement> = (0..8).map(|i| FieldElement::from_i64(i + 1)).collect();
        let mut values = original.clone();

        acc.forward_ntt(&mut values).unwrap();
        acc.inverse_ntt(&mut values).unwrap();

        for (a, b) in values.iter().zip(original.iter()) {
            assert_eq!(field_element_to_u64(a), field_element_to_u64(b));
        }
    }

    #[test]
    fn ntt_rejects_non_power_of_two() {
        let acc = CpuNttAccelerator;
        let mut values = vec![FieldElement::from_i64(1); 3];
        assert!(acc.forward_ntt(&mut values).is_err());
    }

    #[test]
    fn registry_has_cpu_fallbacks() {
        let reg = accelerator_registry().lock().unwrap();
        assert!(reg.best_msm().is_available());
        assert_eq!(reg.best_msm().name(), "cpu-msm");
        assert!(reg.best_ntt().is_available());
        assert_eq!(reg.best_ntt().name(), "cpu-ntt");
    }

    #[test]
    fn msm_empty_input() {
        let acc = CpuMsmAccelerator;
        let result = acc.msm_g1(&[], &[]).unwrap();
        assert_eq!(result.len(), 32); // identity point
    }

    #[test]
    fn msm_matches_arkworks_reference() {
        let acc = CpuMsmAccelerator;
        let generator = G1Affine::generator();
        let mut generator_bytes = Vec::new();
        generator
            .serialize_compressed(&mut generator_bytes)
            .expect("generator serializes");

        let result_bytes = acc
            .msm_g1(
                &[FieldElement::from_i64(1), FieldElement::from_i64(2)],
                &[generator_bytes.clone(), generator_bytes],
            )
            .expect("cpu msm succeeds");

        let result =
            G1Affine::deserialize_compressed(result_bytes.as_slice()).expect("result deserializes");
        let expected = generator
            .into_group()
            .mul_bigint(Fr::from(3u64).into_bigint())
            .into_affine();

        assert_eq!(result, expected);
    }

    #[test]
    fn msm_rejects_invalid_base_bytes() {
        let acc = CpuMsmAccelerator;
        let err = acc
            .msm_g1(&[FieldElement::from_i64(1)], &[vec![1, 2, 3]])
            .expect_err("invalid encoding must fail");
        assert!(err.to_string().contains("invalid BN254 G1 base"));
    }
}
