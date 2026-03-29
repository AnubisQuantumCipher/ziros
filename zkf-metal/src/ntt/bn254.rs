//! BN254 Fr NTT via Metal GPU.
//!
//! Provides forward and inverse NTT over the BN254 scalar field (Fr),
//! using the same radix-2 DIT butterfly algorithm as the Goldilocks NTT
//! but with 4-limb Montgomery arithmetic on GPU.
//!
//! This module is the bridge between Arkworks' `EvaluationDomain<Fr>`
//! and the Metal GPU NTT kernels.

use crate::device::{self, MetalContext};
use crate::ntt::radix2;
use ark_bn254::Fr;
use ark_ff::{BigInt, Field, One, PrimeField};
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

/// BN254 Fr modulus: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const FR_MODULUS: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// Montgomery R mod r (form of 1)
const FR_ONE_MONT: [u64; 4] = [
    0xac96341c4ffffffb,
    0x36fc76959f60cd29,
    0x666ea36f7879462e,
    0x0e0a77c19a07df2f,
];

/// Montgomery R^2 mod r (for converting to Montgomery form)
const FR_R2: [u64; 4] = [
    0x1bb8e645ae216da7,
    0x53fe3ab1e35c59e3,
    0x8c49833d53bb8085,
    0x0216d0b17f4e44a5,
];

/// -r^(-1) mod 2^64
const FR_INV: u64 = 0xc2e1f593efffffffu64;

/// BN254 Fr has 2-adicity of 28: r - 1 = 2^28 * t where t is odd.
/// The 2-adic generator (primitive 2^28-th root of unity) in standard form:
/// g_28 = 5 (the multiplicative generator raised to t).
/// Actually, arkworks uses: TWO_ADIC_ROOT_OF_UNITY for BN254 Fr.
const TWO_ADICITY: u32 = 28;

/// Primitive 2^28-th root of unity in BN254 Fr (standard representation, NOT Montgomery).
/// This is ark_bn254::Fr::TWO_ADIC_ROOT_OF_UNITY =
/// 19103219067921713944291392827692070036145651957329286315305642004821462161904
const TWO_ADIC_ROOT: [u64; 4] = [
    0x9bd61b6e725b19f0,
    0x402d111e41112ed4,
    0x00e0a7eb8ef62abc,
    0x2a3c09f0a58a7e85,
];

/// Metal-accelerated BN254 Fr NTT.
pub struct MetalBn254Ntt {
    ctx: &'static MetalContext,
}

impl MetalBn254Ntt {
    /// Create if Metal GPU is available.
    pub fn new() -> Option<Self> {
        let ctx = device::global_context()?;
        Some(Self { ctx })
    }

    /// Forward NTT in-place on BN254 Fr elements.
    ///
    /// `data` is a slice of Fr elements in Montgomery form, each represented
    /// as 4 × u64 (little-endian limb order). Total length = n * 4.
    ///
    /// The data is assumed to already be in bit-reversed order (standard DIT).
    pub fn forward_ntt_mont(&self, data: &mut [u64], n: usize) -> Option<()> {
        assert_eq!(data.len(), n * 4, "data must contain n * 4 u64 limbs");
        assert!(n.is_power_of_two(), "n must be a power of 2");

        let log_n = n.trailing_zeros() as usize;
        assert!(
            log_n <= TWO_ADICITY as usize,
            "log_n exceeds 2-adicity of BN254 Fr"
        );

        let twiddles = precompute_bn254_twiddles(log_n, false);
        let twiddle_buf = self.ctx.new_buffer_from_slice(&twiddles)?;
        let data_buf = self.ctx.new_buffer_from_slice(data)?;

        radix2::dispatch_ntt_bn254(self.ctx, &data_buf, &twiddle_buf, n)?;

        // Read back results
        let result: Vec<u64> = self.ctx.read_buffer(&data_buf, n * 4);
        data.copy_from_slice(&result);

        Some(())
    }

    /// Inverse NTT in-place on BN254 Fr elements (Montgomery form).
    ///
    /// After the inverse butterfly, each element is scaled by 1/n.
    pub fn inverse_ntt_mont(&self, data: &mut [u64], n: usize) -> Option<()> {
        self.inverse_ntt_mont_raw(data, n)?;

        // Scale by 1/n (in Montgomery form)
        let log_n = n.trailing_zeros() as usize;
        let n_inv = fr_mont_inv_of_power_of_two(log_n);
        for i in 0..n {
            let offset = i * 4;
            let mut elem = [
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ];
            elem = fr_mont_mul(elem, n_inv);
            data[offset..offset + 4].copy_from_slice(&elem);
        }

        Some(())
    }

    /// Inverse NTT WITHOUT 1/n scaling — caller handles scaling.
    ///
    /// Used when the caller needs to combine 1/n scaling with other
    /// operations (e.g., coset unshift in Arkworks integration).
    pub fn inverse_ntt_mont_raw(&self, data: &mut [u64], n: usize) -> Option<()> {
        assert_eq!(data.len(), n * 4);
        assert!(n.is_power_of_two());

        let log_n = n.trailing_zeros() as usize;
        let twiddles = precompute_bn254_twiddles(log_n, true);
        let twiddle_buf = self.ctx.new_buffer_from_slice(&twiddles)?;
        let data_buf = self.ctx.new_buffer_from_slice(data)?;

        radix2::dispatch_ntt_bn254(self.ctx, &data_buf, &twiddle_buf, n)?;

        let result: Vec<u64> = self.ctx.read_buffer(&data_buf, n * 4);
        data.copy_from_slice(&result);

        Some(())
    }

    /// Forward FFT with Arkworks-compatible coset semantics.
    ///
    /// `values` are in natural order and remain in natural order on success.
    pub fn fft_in_place(&self, values: &mut [Fr], offset: Fr) -> Option<()> {
        self.transform_in_place(values, offset, false)
    }

    /// Inverse FFT with Arkworks-compatible coset semantics.
    ///
    /// `values` are in natural order and remain in natural order on success.
    pub fn ifft_in_place(&self, values: &mut [Fr], offset: Fr) -> Option<()> {
        self.transform_in_place(values, offset, true)
    }

    fn transform_in_place(&self, values: &mut [Fr], offset: Fr, inverse: bool) -> Option<()> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return None;
        }

        let n = values.len();
        let log_n = n.trailing_zeros() as usize;
        if log_n > TWO_ADICITY as usize {
            return None;
        }

        let mut staged = values.to_vec();
        if !inverse && !offset.is_one() {
            distribute_powers_in_place(&mut staged, offset);
        }

        let mut data = fr_vec_to_mont_limbs(&staged);
        bit_reverse_permute_fr_limbs(&mut data);

        if inverse {
            self.inverse_ntt_mont(&mut data, n)?;
        } else {
            self.forward_ntt_mont(&mut data, n)?;
        }

        let mut transformed = mont_limbs_to_fr_vec(&data)?;
        if inverse && !offset.is_one() {
            distribute_powers_in_place(&mut transformed, offset.inverse()?);
        }

        for (dst, src) in values.iter_mut().zip(transformed.into_iter()) {
            *dst = src;
        }

        Some(())
    }
}

/// Precompute twiddle factors for BN254 Fr NTT.
///
/// Twiddles are stored in Montgomery form, 4 × u64 per entry,
/// in the tree layout: twiddles[(half + pos) * 4 .. (half + pos + 1) * 4].
fn precompute_bn254_twiddles(log_n: usize, inverse: bool) -> Vec<u64> {
    type TwiddleCache = Mutex<BTreeMap<(usize, bool), Vec<u64>>>;
    static TWIDDLE_CACHE: OnceLock<TwiddleCache> = OnceLock::new();

    let cache = TWIDDLE_CACHE.get_or_init(|| Mutex::new(BTreeMap::new()));
    if let Ok(cache) = cache.lock()
        && let Some(twiddles) = cache.get(&(log_n, inverse))
    {
        return twiddles.clone();
    }

    let n = 1usize << log_n;
    // Total storage: n elements × 4 limbs = n * 4 u64s
    let mut twiddles = vec![0u64; n * 4];

    // Get primitive Nth root of unity
    // g_n = g_28^(2^(28-log_n))
    let g = {
        let mut base = to_mont(TWO_ADIC_ROOT);
        for _ in 0..(TWO_ADICITY as usize - log_n) {
            base = fr_mont_mul(base, base);
        }
        if inverse { fr_mont_inv(base) } else { base }
    };

    for stage in 0..log_n {
        let half = 1usize << stage;
        let step = n >> (stage + 1);

        for j in 0..half {
            let exp = j * step;
            let w = fr_mont_pow(g, exp);
            let idx = (half + j) * 4;
            twiddles[idx] = w[0];
            twiddles[idx + 1] = w[1];
            twiddles[idx + 2] = w[2];
            twiddles[idx + 3] = w[3];
        }
    }

    if let Ok(mut cache) = cache.lock() {
        cache.insert((log_n, inverse), twiddles.clone());
    }

    twiddles
}

// ============================================================================
// BN254 Fr Montgomery arithmetic (CPU-side, for twiddle precomputation)
// ============================================================================

/// Convert standard representation to Montgomery form: a * R mod r
fn to_mont(a: [u64; 4]) -> [u64; 4] {
    fr_mont_mul(a, FR_R2)
}

/// Convert Montgomery representation back to standard form.
fn from_mont(a: [u64; 4]) -> [u64; 4] {
    fr_mont_mul(a, [1, 0, 0, 0])
}

fn fr_to_mont_limbs(value: &Fr) -> [u64; 4] {
    to_mont(value.into_bigint().0)
}

fn mont_limbs_to_fr(limbs: [u64; 4]) -> Option<Fr> {
    Fr::from_bigint(BigInt::<4>(from_mont(limbs)))
}

fn fr_vec_to_mont_limbs(values: &[Fr]) -> Vec<u64> {
    let mut data = Vec::with_capacity(values.len() * 4);
    for value in values {
        data.extend_from_slice(&fr_to_mont_limbs(value));
    }
    data
}

fn mont_limbs_to_fr_vec(data: &[u64]) -> Option<Vec<Fr>> {
    if !data.len().is_multiple_of(4) {
        return None;
    }
    let mut values = Vec::with_capacity(data.len() / 4);
    for chunk in data.chunks_exact(4) {
        values.push(mont_limbs_to_fr([chunk[0], chunk[1], chunk[2], chunk[3]])?);
    }
    Some(values)
}

fn bit_reverse_permute_fr_limbs(data: &mut [u64]) {
    let n = data.len() / 4;
    if n <= 1 {
        return;
    }
    let log_n = n.trailing_zeros();
    for i in 0..n {
        let j = (i as u32).reverse_bits() >> (u32::BITS - log_n);
        if (i as u32) < j {
            let j = j as usize;
            for limb in 0..4 {
                data.swap(i * 4 + limb, j * 4 + limb);
            }
        }
    }
}

fn distribute_powers_in_place(values: &mut [Fr], offset: Fr) {
    let mut power = Fr::one();
    for value in values {
        *value *= power;
        power *= offset;
    }
}

/// Montgomery multiplication: (a * b * R^(-1)) mod r
fn fr_mont_mul(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut t = [0u128; 5]; // accumulator with extra limb

    for &b_i in &b {
        // Multiply-accumulate: t += a * b[i]
        let mut carry = 0u128;
        for j in 0..4 {
            t[j] += (a[j] as u128) * (b_i as u128) + carry;
            carry = t[j] >> 64;
            t[j] &= 0xFFFFFFFFFFFFFFFF;
        }
        t[4] += carry;

        // Montgomery reduction: m = t[0] * FR_INV mod 2^64
        let m = (t[0] as u64).wrapping_mul(FR_INV);

        // t += FR_MODULUS * m, then shift right by 64
        carry = 0;
        for j in 0..4 {
            let prod = (FR_MODULUS[j] as u128) * (m as u128) + t[j] + carry;
            if j > 0 {
                t[j - 1] = prod & 0xFFFFFFFFFFFFFFFF;
            }
            carry = prod >> 64;
        }
        t[3] = t[4] + carry;
        t[4] = t[3] >> 64;
        t[3] &= 0xFFFFFFFFFFFFFFFF;
    }

    let mut result = [t[0] as u64, t[1] as u64, t[2] as u64, t[3] as u64];

    // Final conditional subtraction
    if fr_gte(result, FR_MODULUS) {
        result = fr_sub_no_borrow(result, FR_MODULUS);
    }

    result
}

fn fr_gte(a: [u64; 4], b: [u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true // equal
}

fn fr_sub_no_borrow(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (r1, b1) = a[i].overflowing_sub(b[i]);
        let (r2, b2) = r1.overflowing_sub(borrow);
        result[i] = r2;
        borrow = (b1 as u64) + (b2 as u64);
    }
    result
}

/// Compute a^exp in Montgomery form via square-and-multiply.
fn fr_mont_pow(base: [u64; 4], exp: usize) -> [u64; 4] {
    if exp == 0 {
        return FR_ONE_MONT;
    }
    let mut result = FR_ONE_MONT;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = fr_mont_mul(result, b);
        }
        b = fr_mont_mul(b, b);
        e >>= 1;
    }
    result
}

/// Compute modular inverse via Fermat's little theorem: a^(-1) = a^(r-2) mod r.
fn fr_mont_inv(a: [u64; 4]) -> [u64; 4] {
    // r - 2 in limbs
    let exp = [
        FR_MODULUS[0].wrapping_sub(2),
        FR_MODULUS[1],
        FR_MODULUS[2],
        FR_MODULUS[3],
    ];
    fr_mont_pow_bigint(a, exp)
}

fn fr_mont_pow_bigint(base: [u64; 4], exp: [u64; 4]) -> [u64; 4] {
    let mut result = FR_ONE_MONT;
    let mut b = base;
    for limb in exp.iter() {
        let mut e = *limb;
        for _ in 0..64 {
            if e & 1 == 1 {
                result = fr_mont_mul(result, b);
            }
            b = fr_mont_mul(b, b);
            e >>= 1;
        }
    }
    result
}

/// Compute 1/2^log_n in Montgomery form.
fn fr_mont_inv_of_power_of_two(log_n: usize) -> [u64; 4] {
    // 2 in Montgomery form
    let two_mont = to_mont([2, 0, 0, 0]);
    // 2^log_n in Montgomery form
    let n_mont = fr_mont_pow(two_mont, log_n);
    // Invert
    fr_mont_inv(n_mont)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::FftField;
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

    const METAL_FIELD_SOURCE: &str = include_str!("../shaders/field_bn254_fr.metal");
    const RUST_MONT_SOURCE: &str = include_str!("bn254.rs");
    const LEAN_MONT_SOURCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/proofs/lean/Bn254Montgomery.lean"
    ));

    fn parse_hex_assignment(source: &str, anchor: &str) -> u64 {
        let line = source
            .lines()
            .find(|line| line.contains(anchor))
            .unwrap_or_else(|| panic!("missing anchor `{anchor}`"));
        let start = line
            .find("0x")
            .unwrap_or_else(|| panic!("missing hex literal for `{anchor}`"));
        let rest = &line[start + 2..];
        let end = rest
            .find(|ch: char| !ch.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        u64::from_str_radix(&rest[..end], 16)
            .unwrap_or_else(|_| panic!("invalid hex literal for `{anchor}`"))
    }

    fn parse_hex_array(source: &str, anchor: &str) -> [u64; 4] {
        let start = source
            .find(anchor)
            .unwrap_or_else(|| panic!("missing array anchor `{anchor}`"));
        let mut rest = &source[start..];
        let mut values = Vec::with_capacity(4);
        while values.len() < 4 {
            let hex_start = rest
                .find("0x")
                .unwrap_or_else(|| panic!("missing array value for `{anchor}`"));
            rest = &rest[hex_start + 2..];
            let end = rest
                .find(|ch: char| !ch.is_ascii_hexdigit())
                .unwrap_or(rest.len());
            values.push(
                u64::from_str_radix(&rest[..end], 16)
                    .unwrap_or_else(|_| panic!("invalid array value for `{anchor}`")),
            );
            rest = &rest[end..];
        }
        [values[0], values[1], values[2], values[3]]
    }

    fn assert_markers_in_order(source: &str, markers: &[&str]) {
        let mut offset = 0usize;
        for marker in markers {
            let found = source[offset..]
                .find(marker)
                .unwrap_or_else(|| panic!("missing ordered marker `{marker}`"));
            offset += found + marker.len();
        }
    }

    #[test]
    fn fr_mont_mul_identity() {
        let one = FR_ONE_MONT;
        let result = fr_mont_mul(one, one);
        assert_eq!(result, one, "1 * 1 should equal 1 in Montgomery form");
    }

    #[test]
    fn fr_mont_mul_commutative() {
        let a = to_mont([7, 0, 0, 0]);
        let b = to_mont([13, 0, 0, 0]);
        let ab = fr_mont_mul(a, b);
        let ba = fr_mont_mul(b, a);
        assert_eq!(ab, ba, "Montgomery multiplication should be commutative");
        // 7 * 13 = 91
        let expected = to_mont([91, 0, 0, 0]);
        assert_eq!(ab, expected);
    }

    #[test]
    fn fr_root_of_unity_order() {
        // g^(2^28) should equal 1 in Montgomery form
        let g = to_mont(TWO_ADIC_ROOT);
        let mut val = g;
        for _ in 0..28 {
            val = fr_mont_mul(val, val);
        }
        assert_eq!(val, FR_ONE_MONT, "g^(2^28) should be 1");
    }

    #[test]
    fn twiddle_precomputation() {
        let twiddles = precompute_bn254_twiddles(4, false);
        // n=16, should have 16*4 = 64 u64s
        assert_eq!(twiddles.len(), 64);
        // twiddles[1*4..2*4] should be the root of unity (stage 0, pos 0)
        let w1 = [twiddles[4], twiddles[5], twiddles[6], twiddles[7]];
        assert_ne!(w1, [0, 0, 0, 0], "first twiddle should be non-zero");
    }

    #[test]
    fn bn254_constants_match_metal_and_lean_proof_surface() {
        assert_eq!(
            parse_hex_array(METAL_FIELD_SOURCE, "constant Fr FR_R"),
            FR_MODULUS
        );
        assert_eq!(
            parse_hex_array(METAL_FIELD_SOURCE, "constant Fr FR_ONE"),
            FR_ONE_MONT
        );
        assert_eq!(
            parse_hex_array(METAL_FIELD_SOURCE, "constant Fr FR_R2"),
            FR_R2
        );
        assert_eq!(
            parse_hex_assignment(METAL_FIELD_SOURCE, "constant uint64_t FR_INV"),
            FR_INV
        );

        assert_eq!(
            [
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254ModulusLimb0"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254ModulusLimb1"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254ModulusLimb2"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254ModulusLimb3"),
            ],
            FR_MODULUS
        );
        assert_eq!(
            [
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254OneMontLimb0"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254OneMontLimb1"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254OneMontLimb2"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254OneMontLimb3"),
            ],
            FR_ONE_MONT
        );
        assert_eq!(
            [
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254R2Limb0"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254R2Limb1"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254R2Limb2"),
                parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254R2Limb3"),
            ],
            FR_R2
        );
        assert_eq!(
            parse_hex_assignment(LEAN_MONT_SOURCE, "def bn254Inv"),
            FR_INV
        );
    }

    #[test]
    fn bn254_cios_shape_matches_shader_and_rust_mirror() {
        assert_markers_in_order(
            METAL_FIELD_SOURCE,
            &[
                "for (int i = 0; i < 4; i++)",
                "fr_mul64(t0, FR_INV, m_hi, m);",
                "fr_mac(FR_R.limbs[0], m, t0, carry);",
                "fr_mac(FR_R.limbs[3], m, t3, carry);",
                "// Shift down",
                "// Final conditional subtraction",
            ],
        );

        assert_markers_in_order(
            RUST_MONT_SOURCE,
            &[
                "for &b_i in &b {",
                "let m = (t[0] as u64).wrapping_mul(FR_INV);",
                "let prod = (FR_MODULUS[j] as u128) * (m as u128) + t[j] + carry;",
                "t[3] = t[4] + carry;",
                "// Final conditional subtraction",
            ],
        );
    }

    #[test]
    fn metal_bn254_ntt_roundtrip() {
        let ntt = match MetalBn254Ntt::new() {
            Some(n) => n,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 16; // small test
        let mut data = vec![0u64; n * 4];

        // Fill with small values in Montgomery form
        for i in 0..n {
            let val = to_mont([(i + 1) as u64, 0, 0, 0]);
            data[i * 4] = val[0];
            data[i * 4 + 1] = val[1];
            data[i * 4 + 2] = val[2];
            data[i * 4 + 3] = val[3];
        }

        // Bit-reverse permutation on Fr elements (4 u64s each)
        let log_n = n.trailing_zeros();
        for i in 0..n {
            let j = (i as u32).reverse_bits() >> (32 - log_n);
            if (i as u32) < j {
                let j = j as usize;
                for k in 0..4 {
                    data.swap(i * 4 + k, j * 4 + k);
                }
            }
        }

        let original = data.clone();

        // Forward NTT
        ntt.forward_ntt_mont(&mut data, n)
            .expect("forward NTT failed");

        // Should have changed
        assert_ne!(data, original, "NTT should modify data");

        // Bit-reverse again for inverse
        for i in 0..n {
            let j = (i as u32).reverse_bits() >> (32 - log_n);
            if (i as u32) < j {
                let j = j as usize;
                for k in 0..4 {
                    data.swap(i * 4 + k, j * 4 + k);
                }
            }
        }

        // Inverse NTT
        ntt.inverse_ntt_mont(&mut data, n)
            .expect("inverse NTT failed");

        // Bit-reverse to get back to natural order
        for i in 0..n {
            let j = (i as u32).reverse_bits() >> (32 - log_n);
            if (i as u32) < j {
                let j = j as usize;
                for k in 0..4 {
                    data.swap(i * 4 + k, j * 4 + k);
                }
            }
        }

        // Should recover original
        assert_eq!(
            data, original,
            "NTT -> INTT roundtrip should recover original"
        );
    }

    #[test]
    fn metal_bn254_fft_matches_arkworks_coset_fft() {
        let ntt = match MetalBn254Ntt::new() {
            Some(n) => n,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 1 << 10;
        let offset = Fr::GENERATOR;
        let mut gpu_values: Vec<Fr> = (0..n).map(|i| Fr::from((i + 1) as u64)).collect();
        let mut cpu_values = gpu_values.clone();

        ntt.fft_in_place(&mut gpu_values, offset)
            .expect("metal fft failed");
        GeneralEvaluationDomain::<Fr>::new(n)
            .expect("domain")
            .get_coset(offset)
            .expect("coset")
            .fft_in_place(&mut cpu_values);

        assert_eq!(gpu_values, cpu_values);
    }

    #[test]
    fn metal_bn254_ifft_matches_arkworks_coset_ifft() {
        let ntt = match MetalBn254Ntt::new() {
            Some(n) => n,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        let n = 1 << 10;
        let offset = Fr::GENERATOR;
        let domain = GeneralEvaluationDomain::<Fr>::new(n)
            .expect("domain")
            .get_coset(offset)
            .expect("coset");
        let mut gpu_values: Vec<Fr> = (0..n).map(|i| Fr::from((i + 3) as u64)).collect();
        let mut cpu_values = gpu_values.clone();
        domain.fft_in_place(&mut gpu_values);
        cpu_values.clone_from(&gpu_values);

        ntt.ifft_in_place(&mut gpu_values, offset)
            .expect("metal ifft failed");
        domain.ifft_in_place(&mut cpu_values);

        assert_eq!(gpu_values, cpu_values);
    }
}
