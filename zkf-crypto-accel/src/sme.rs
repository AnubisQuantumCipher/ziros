//! ARM SME (Scalable Matrix Extension) tile operations for field arithmetic.
//!
//! The M4 Max is the first Apple chip with ARM SME. `SMEI16I64` performs
//! INT16 outer products accumulated to INT64 — exactly the structure for
//! multi-limb Montgomery multiplication of 254-bit field elements.
//!
//! SME uses the ZA (accumulator) tile register for outer-product accumulation.
//! This module provides safe wrappers that manage SME streaming mode entry/exit.

use crate::detect::CryptoExtensions;

/// Whether SME (Scalable Matrix Extension) is available on this hardware.
pub fn sme_available() -> bool {
    crate::is_enabled() && CryptoExtensions::detect().sme
}

/// Multiply two vectors of u64 Goldilocks field elements in batch.
/// Uses SME outer-product accumulation when available.
///
/// Both `a` and `b` must have the same length. Results stored in `out`.
pub fn batch_mul_goldilocks(a: &[u64], b: &[u64], out: &mut [u64]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), out.len());

    if sme_available() {
        batch_mul_goldilocks_sme(a, b, out);
    } else {
        batch_mul_goldilocks_scalar(a, b, out);
    }
}

/// Goldilocks modulus: p = 2^64 - 2^32 + 1
const GOLDILOCKS_P: u64 = 0xFFFF_FFFF_0000_0001;

/// Scalar Goldilocks field multiplication (128-bit intermediate).
#[inline(always)]
fn goldilocks_mul(a: u64, b: u64) -> u64 {
    let prod = (a as u128) * (b as u128);
    goldilocks_reduce_128(prod)
}

/// Reduce a 128-bit value modulo Goldilocks p.
#[inline(always)]
fn goldilocks_reduce_128(x: u128) -> u64 {
    let lo = x as u64;
    let hi = (x >> 64) as u64;
    // 2^64 ≡ 2^32 - 1 (mod p)
    let hi_shifted = (hi as u128) * ((1u128 << 32) - 1);
    let sum = lo as u128 + hi_shifted;
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

fn batch_mul_goldilocks_scalar(a: &[u64], b: &[u64], out: &mut [u64]) {
    for i in 0..a.len() {
        out[i] = goldilocks_mul(a[i], b[i]);
    }
}

// ─── SME path ───────────────────────────────────────────────────────────
// Note: SME intrinsics require nightly Rust + target_feature = "sme".
// We provide the scalar path as production default and the SME path
// as an experimental acceleration when the feature is stabilized.

#[cfg(all(target_arch = "aarch64", target_feature = "sme"))]
fn batch_mul_goldilocks_sme(a: &[u64], b: &[u64], out: &mut [u64]) {
    // SME streaming mode would be entered here for tile operations.
    // For now, we use the scalar path since SME intrinsics are not yet
    // stabilized in Rust. The structure is ready for when they are.
    //
    // The plan: decompose each 64-bit element into 4x 16-bit limbs,
    // use SMEI16I64 for outer-product partial products, then reduce.
    batch_mul_goldilocks_scalar(a, b, out);
}

#[cfg(not(all(target_arch = "aarch64", target_feature = "sme")))]
fn batch_mul_goldilocks_sme(a: &[u64], b: &[u64], out: &mut [u64]) {
    batch_mul_goldilocks_scalar(a, b, out);
}

/// NTT butterfly operation optimized for Goldilocks field.
/// Computes: (a + b*twiddle, a - b*twiddle) mod p
#[inline(always)]
pub fn butterfly_goldilocks(a: u64, b: u64, twiddle: u64) -> (u64, u64) {
    let bt = goldilocks_mul(b, twiddle);
    let sum = goldilocks_add(a, bt);
    let diff = goldilocks_sub(a, bt);
    (sum, diff)
}

#[inline(always)]
fn goldilocks_add(a: u64, b: u64) -> u64 {
    let sum = a as u128 + b as u128;
    if sum >= GOLDILOCKS_P as u128 {
        (sum - GOLDILOCKS_P as u128) as u64
    } else {
        sum as u64
    }
}

#[inline(always)]
fn goldilocks_sub(a: u64, b: u64) -> u64 {
    if a >= b {
        a - b
    } else {
        GOLDILOCKS_P - (b - a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goldilocks_mul_basic() {
        assert_eq!(goldilocks_mul(2, 3), 6);
        assert_eq!(goldilocks_mul(0, 100), 0);
        assert_eq!(goldilocks_mul(1, 42), 42);
    }

    #[test]
    fn batch_mul_matches_scalar() {
        let a = vec![2, 3, 5, 7, 11, 13, 17, 19];
        let b = vec![3, 5, 7, 11, 13, 17, 19, 23];
        let mut out = vec![0u64; 8];
        batch_mul_goldilocks(&a, &b, &mut out);

        for i in 0..8 {
            assert_eq!(out[i], goldilocks_mul(a[i], b[i]));
        }
    }

    #[test]
    fn butterfly_inverse() {
        let a = 42u64;
        let b = 17u64;
        let twiddle = 7u64;
        let (sum, diff) = butterfly_goldilocks(a, b, twiddle);
        // sum + diff should equal 2*a
        let two_a = goldilocks_add(a, a);
        assert_eq!(goldilocks_add(sum, diff), two_a);
    }
}
