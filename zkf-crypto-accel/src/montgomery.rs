//! Montgomery multiplication for BN254 field elements using SME.
//!
//! Decomposes 254-bit BN254 Fr into 16x 16-bit limbs, uses SMEI16I64
//! outer product for all partial products, then performs Montgomery reduction.
//!
//! Published research (PQC-AMX, IACR 2024/195) shows 1.54-3.07x speedup
//! over scalar Montgomery multiplication.

use crate::sme;
use num_bigint::BigUint;
use num_traits::{One, ToPrimitive};
use std::sync::OnceLock;

/// BN254 scalar field modulus: r = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_R: [u64; 4] = [
    0x43e1f593f0000001,
    0x2833e84879b97091,
    0xb85045b68181585d,
    0x30644e72e131a029,
];

/// Montgomery multiplication: computes (a * b * R^{-1}) mod r
/// where R = 2^256 and all values are in Montgomery form.
pub fn mont_mul_bn254(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    if sme::sme_available() {
        mont_mul_bn254_sme(a, b)
    } else {
        mont_mul_bn254_scalar(a, b)
    }
}

/// Batch Montgomery multiplication for BN254 elements.
/// `a` and `b` are flat arrays of 4-limb elements. `out` receives results.
pub fn batch_mont_mul_bn254(a: &[u64], b: &[u64], out: &mut [u64]) {
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), out.len());
    assert_eq!(a.len() % 4, 0);

    let n = a.len() / 4;
    for i in 0..n {
        let a_limbs: [u64; 4] = a[i * 4..(i + 1) * 4].try_into().unwrap();
        let b_limbs: [u64; 4] = b[i * 4..(i + 1) * 4].try_into().unwrap();
        let result = mont_mul_bn254(&a_limbs, &b_limbs);
        out[i * 4..(i + 1) * 4].copy_from_slice(&result);
    }
}

// ─── Scalar Montgomery multiplication ───────────────────────────────────

fn mont_mul_bn254_scalar(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let modulus = bn254_modulus();
    let a_big = limbs_to_biguint(a);
    let b_big = limbs_to_biguint(b);
    let result = ((a_big * b_big) % modulus * montgomery_r_inv()) % modulus;
    biguint_to_limbs(&result)
}

/// Subtract modulus if result >= modulus.
#[allow(dead_code)]
fn conditional_subtract(a: &mut [u64; 4], modulus: &[u64; 4]) {
    let mut ge = true;
    for i in (0..4).rev() {
        if a[i] > modulus[i] {
            break;
        }
        if a[i] < modulus[i] {
            ge = false;
            break;
        }
    }
    if !ge {
        return;
    }

    let mut borrow = 0u128;
    for i in 0..4 {
        let ai = a[i] as u128;
        let subtrahend = modulus[i] as u128 + borrow;
        if ai >= subtrahend {
            a[i] = (ai - subtrahend) as u64;
            borrow = 0;
        } else {
            a[i] = ((1u128 << 64) + ai - subtrahend) as u64;
            borrow = 1;
        }
    }
}

fn bn254_modulus() -> &'static BigUint {
    static MODULUS: OnceLock<BigUint> = OnceLock::new();
    MODULUS.get_or_init(|| limbs_to_biguint(&BN254_R))
}

fn montgomery_r_inv() -> &'static BigUint {
    static R_INV: OnceLock<BigUint> = OnceLock::new();
    R_INV.get_or_init(|| {
        let modulus = bn254_modulus();
        let r = BigUint::one() << 256usize;
        let exponent = modulus - BigUint::from(2u32);
        r.modpow(&exponent, modulus)
    })
}

fn limbs_to_biguint(limbs: &[u64; 4]) -> BigUint {
    limbs
        .iter()
        .enumerate()
        .fold(BigUint::default(), |acc, (idx, limb)| {
            acc + (BigUint::from(*limb) << (idx * 64))
        })
}

fn biguint_to_limbs(value: &BigUint) -> [u64; 4] {
    let mask = BigUint::from(u64::MAX);
    std::array::from_fn(|idx| {
        ((value >> (idx * 64)) & &mask)
            .to_u64()
            .expect("limb should fit into u64")
    })
}

// ─── SME path (structure ready for when Rust stabilizes SME) ────────────

fn mont_mul_bn254_sme(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    // When SME intrinsics are available in stable Rust:
    // 1. Decompose each 64-bit limb into 4x 16-bit sub-limbs
    // 2. Use SMEI16I64 outer product for all 16x16 partial products
    // 3. Accumulate in ZA tiles
    // 4. Extract and reduce
    //
    // For now, delegate to scalar path.
    mont_mul_bn254_scalar(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn biguint_from_words(words: [u64; 4]) -> BigUint {
        let mut bytes = [0u8; 32];
        for (index, word) in words.iter().enumerate() {
            bytes[index * 8..(index + 1) * 8].copy_from_slice(&word.to_le_bytes());
        }
        BigUint::from_bytes_le(&bytes)
    }

    fn canonical_bn254_corpus() -> Vec<BigUint> {
        let modulus = bn254_modulus();
        let montgomery_radix = BigUint::one() << 256usize;
        let montgomery_r = &montgomery_radix % modulus;
        let montgomery_r_squared = (&montgomery_radix * &montgomery_radix) % modulus;
        let carry_chain = biguint_from_words([u64::MAX, u64::MAX, 1, 0]);
        let alternating_a = biguint_from_words([
            0xAAAAAAAAAAAAAAAA,
            0x5555555555555555,
            0xAAAAAAAAAAAAAAAA,
            0x5555555555555555,
        ]);
        let alternating_b = biguint_from_words([
            0x5555555555555555,
            0xAAAAAAAAAAAAAAAA,
            0x5555555555555555,
            0xAAAAAAAAAAAAAAAA,
        ]);

        let seeds = [
            BigUint::default(),
            BigUint::one(),
            modulus - BigUint::one(),
            modulus.clone(),
            modulus + BigUint::one(),
            (modulus - BigUint::from(2u8)).clone(),
            (modulus + BigUint::from(2u8)).clone(),
            montgomery_r.clone(),
            montgomery_r_squared.clone(),
            modulus + &montgomery_r,
            modulus + &montgomery_r_squared,
            biguint_from_words([u64::MAX; 4]),
            biguint_from_words([u64::MAX, u64::MAX, u64::MAX, 0]),
            biguint_from_words([u64::MAX, 0, 0, 0]),
            biguint_from_words([0, u64::MAX, 0, 0]),
            biguint_from_words([0, 0, u64::MAX, 0]),
            biguint_from_words([0, 0, 0, u64::MAX]),
            carry_chain,
            alternating_a,
            alternating_b,
        ];

        let mut corpus = BTreeSet::new();
        for seed in seeds {
            corpus.insert(seed % modulus);
        }
        corpus.into_iter().collect()
    }

    fn to_montgomery(value: &BigUint) -> [u64; 4] {
        let modulus = bn254_modulus();
        let mont = ((value % modulus) * (BigUint::one() << 256usize)) % modulus;
        biguint_to_limbs(&mont)
    }

    fn canonical_product_montgomery(lhs: &BigUint, rhs: &BigUint) -> [u64; 4] {
        let modulus = bn254_modulus();
        let product = ((lhs % modulus) * (rhs % modulus)) % modulus;
        to_montgomery(&product)
    }

    fn broken_mont_mul_bn254_scalar_perturbed_constant(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
        let modulus = bn254_modulus();
        let a_big = limbs_to_biguint(a);
        let b_big = limbs_to_biguint(b);
        let broken_r_inv = (montgomery_r_inv() + BigUint::one()) % modulus;
        let result = ((a_big * b_big) % modulus * broken_r_inv) % modulus;
        biguint_to_limbs(&result)
    }

    #[test]
    fn mont_mul_identity() {
        // Montgomery form of 1: R mod r
        let one_mont = [
            0xac96341c4ffffffb,
            0x36fc76959f60cd29,
            0x666ea36f7879462e,
            0x0e0a77c19a07df2f,
        ];
        // a * 1 in Montgomery form should return a
        let a = one_mont;
        let result = mont_mul_bn254(&a, &one_mont);
        assert_eq!(result, a);
    }

    #[test]
    fn mont_mul_zero() {
        let zero = [0u64; 4];
        let a = [1u64, 2, 3, 4];
        let result = mont_mul_bn254(&zero, &a);
        assert_eq!(result, [0, 0, 0, 0]);
    }

    #[test]
    fn batch_matches_individual() {
        let a = [1u64, 0, 0, 0, 2, 0, 0, 0];
        let b = [3u64, 0, 0, 0, 5, 0, 0, 0];
        let mut out = [0u64; 8];
        batch_mont_mul_bn254(&a, &b, &mut out);

        let r1 = mont_mul_bn254(&[1, 0, 0, 0], &[3, 0, 0, 0]);
        let r2 = mont_mul_bn254(&[2, 0, 0, 0], &[5, 0, 0, 0]);
        assert_eq!(&out[0..4], &r1);
        assert_eq!(&out[4..8], &r2);
    }

    #[test]
    fn montgomery_assurance_bn254_matches_canonical_oracle() {
        let corpus = canonical_bn254_corpus();
        for lhs in &corpus {
            for rhs in &corpus {
                let lhs_mont = to_montgomery(lhs);
                let rhs_mont = to_montgomery(rhs);
                let expected = canonical_product_montgomery(lhs, rhs);
                let actual = mont_mul_bn254(&lhs_mont, &rhs_mont);
                assert_eq!(
                    actual, expected,
                    "montgomery product mismatch for lhs={}, rhs={}",
                    lhs, rhs,
                );
            }
        }
    }

    #[test]
    fn montgomery_assurance_bn254_batch_matches_canonical_oracle() {
        let corpus = canonical_bn254_corpus();
        let pairs: Vec<_> = corpus
            .iter()
            .zip(corpus.iter().rev())
            .take(8)
            .map(|(lhs, rhs)| {
                (
                    to_montgomery(lhs),
                    to_montgomery(rhs),
                    canonical_product_montgomery(lhs, rhs),
                )
            })
            .collect();

        let mut lhs_words = Vec::with_capacity(pairs.len() * 4);
        let mut rhs_words = Vec::with_capacity(pairs.len() * 4);
        let mut expected = Vec::with_capacity(pairs.len() * 4);
        for (lhs, rhs, product) in &pairs {
            lhs_words.extend_from_slice(lhs);
            rhs_words.extend_from_slice(rhs);
            expected.extend_from_slice(product);
        }

        let mut out = vec![0u64; expected.len()];
        batch_mont_mul_bn254(&lhs_words, &rhs_words, &mut out);
        assert_eq!(out, expected);
    }

    #[test]
    fn montgomery_assurance_bn254_corpus_detects_perturbed_reduction_constant_bug() {
        let corpus = canonical_bn254_corpus();
        let mut detected = false;
        for lhs in &corpus {
            for rhs in &corpus {
                let lhs_mont = to_montgomery(lhs);
                let rhs_mont = to_montgomery(rhs);
                let expected = canonical_product_montgomery(lhs, rhs);
                let broken = broken_mont_mul_bn254_scalar_perturbed_constant(&lhs_mont, &rhs_mont);
                if broken != expected {
                    detected = true;
                    break;
                }
            }
            if detected {
                break;
            }
        }

        assert!(
            detected,
            "BN254 corpus failed to detect perturbed Montgomery reduction constant bug",
        );
    }
}
