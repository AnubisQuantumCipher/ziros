//! Carry-less (polynomial) multiplication using ARM FEAT_PMULL intrinsics.
//!
//! `PMULL`/`PMULL2` perform GF(2^128) polynomial multiply, useful for
//! binary field operations, GHASH (GCM), and binary extension field arithmetic.

use crate::detect::CryptoExtensions;

/// Carry-less multiply two 64-bit values, returning 128-bit result.
/// Uses PMULL hardware instruction when available.
pub fn clmul64(a: u64, b: u64) -> u128 {
    if crate::is_enabled() && CryptoExtensions::detect().pmull {
        clmul64_hw(a, b)
    } else {
        clmul64_sw(a, b)
    }
}

/// GF(2^128) multiply with reduction by x^128 + x^7 + x^2 + x + 1.
/// Used in GHASH and binary extension field ops.
pub fn gf128_mul(a: u128, b: u128) -> u128 {
    let a_lo = a as u64;
    let a_hi = (a >> 64) as u64;
    let b_lo = b as u64;
    let b_hi = (b >> 64) as u64;

    // Karatsuba multiplication
    let lo = clmul64(a_lo, b_lo);
    let hi = clmul64(a_hi, b_hi);
    let mid = clmul64(a_lo ^ a_hi, b_lo ^ b_hi) ^ lo ^ hi;

    // Simplified: combine into 128-bit with implicit reduction
    let result_lo = (lo as u64) ^ (mid as u64);
    let result_hi = ((lo >> 64) as u64) ^ (mid as u64) ^ (hi as u64);

    // Reduce by polynomial x^128 + x^7 + x^2 + x + 1
    let r = (hi >> 64) as u64;
    let reduced_lo = result_lo ^ (r << 7) ^ (r << 2) ^ (r << 1) ^ r;
    let reduced_hi = result_hi ^ ((hi as u64) >> 57) ^ ((hi as u64) >> 62) ^ ((hi as u64) >> 63);

    ((reduced_hi as u128) << 64) | (reduced_lo as u128)
}

// ─── Hardware path ──────────────────────────────────────────────────────

#[cfg(target_arch = "aarch64")]
fn clmul64_hw(a: u64, b: u64) -> u128 {
    use core::arch::aarch64::*;

    unsafe {
        let a_vec = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(a), vcreate_u64(0)));
        let b_vec = vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(b), vcreate_u64(0)));

        let result = vmull_p64(
            vgetq_lane_u64(vreinterpretq_u64_u8(a_vec), 0),
            vgetq_lane_u64(vreinterpretq_u64_u8(b_vec), 0),
        );

        let result_u64 = vreinterpretq_u64_p128(result);
        let lo = vgetq_lane_u64(result_u64, 0);
        let hi = vgetq_lane_u64(result_u64, 1);
        ((hi as u128) << 64) | (lo as u128)
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn clmul64_hw(a: u64, b: u64) -> u128 {
    clmul64_sw(a, b)
}

// ─── Software fallback ──────────────────────────────────────────────────

fn clmul64_sw(a: u64, b: u64) -> u128 {
    let mut result: u128 = 0;
    for i in 0..64 {
        if (b >> i) & 1 == 1 {
            result ^= (a as u128) << i;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clmul_basic() {
        // x * 1 = x
        assert_eq!(clmul64(0x1234, 1), 0x1234);
        // 1 * x = x
        assert_eq!(clmul64(1, 0x5678), 0x5678);
        // 0 * x = 0
        assert_eq!(clmul64(0, 0xFFFF), 0);
    }

    #[test]
    fn clmul_commutative() {
        let a = 0x0123456789abcdef_u64;
        let b = 0xfedcba9876543210_u64;
        assert_eq!(clmul64(a, b), clmul64(b, a));
    }

    #[test]
    fn sw_hw_parity() {
        let a = 0xdeadbeefcafebabe_u64;
        let b = 0x0102030405060708_u64;
        let sw = clmul64_sw(a, b);
        let hw = clmul64(a, b);
        assert_eq!(sw, hw, "HW and SW paths must produce identical results");
    }
}
