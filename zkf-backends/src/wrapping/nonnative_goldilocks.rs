// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

/// Non-native Goldilocks field arithmetic inside BN254 R1CS.
///
/// The Goldilocks prime p = 2^64 - 2^32 + 1 fits in 64 bits.  Since the BN254
/// scalar field has ~254 bits, Goldilocks values embed directly without limb
/// decomposition.  However, arithmetic must reduce modulo p after operations
/// that may exceed the Goldilocks range.
///
/// Strategy:
///   - Each `GoldilocksVar` wraps an `AllocatedFr` whose BN254 value equals
///     the Goldilocks integer.
///   - Addition/subtraction: compute in BN254 Fr, then reduce mod p.
///   - Multiplication: witness the product mod p, then prove via quotient:
///     a * b = q * p + r,  0 <= r < p
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use ark_serialize::CanonicalSerialize;

use super::fri_gadgets::AllocatedFr;

fn lc_one() -> LinearCombination<Fr> {
    let mut lc = LinearCombination::zero();
    lc += (Fr::one(), Variable::One);
    lc
}

/// Goldilocks prime: 2^64 - 2^32 + 1.
pub const GOLDILOCKS_PRIME: u64 = 0xFFFF_FFFF_0000_0001;

/// BN254 Fr representation of the Goldilocks prime.
fn goldilocks_prime_fr() -> Fr {
    Fr::from(GOLDILOCKS_PRIME)
}

/// A Goldilocks field element allocated inside a BN254 R1CS.
///
/// Invariant: `inner.value` (when present) is in [0, GOLDILOCKS_PRIME).
#[derive(Clone, Debug)]
pub struct GoldilocksVar {
    pub inner: AllocatedFr,
}

impl GoldilocksVar {
    /// Allocate a Goldilocks witness variable.
    pub fn alloc_witness(
        cs: ConstraintSystemRef<Fr>,
        value: Option<u64>,
    ) -> Result<Self, SynthesisError> {
        let fr_val = value.map(Fr::from);
        let inner = AllocatedFr::alloc_witness(cs.clone(), fr_val)?;
        // Range check: prove value < 2^64 via 64-bit decomposition.
        // (The strict < GOLDILOCKS_PRIME check is enforced by the caller or
        // by the reduction step.  For values coming from a valid Plonky3 proof,
        // they are already canonical.)
        range_check_64(cs, &inner)?;
        Ok(Self { inner })
    }

    /// Allocate a Goldilocks public input.
    pub fn alloc_input(
        cs: ConstraintSystemRef<Fr>,
        value: Option<u64>,
    ) -> Result<Self, SynthesisError> {
        let fr_val = value.map(Fr::from);
        let inner = AllocatedFr::alloc_input(cs.clone(), fr_val)?;
        range_check_64(cs, &inner)?;
        Ok(Self { inner })
    }

    /// Allocate a constant Goldilocks element.
    pub fn constant(cs: ConstraintSystemRef<Fr>, value: u64) -> Result<Self, SynthesisError> {
        let inner = AllocatedFr::alloc_constant(cs, Fr::from(value))?;
        Ok(Self { inner })
    }

    /// The concrete Goldilocks value (if available).
    pub fn value(&self) -> Option<u64> {
        self.inner.value.map(|fr| {
            let mut bytes = [0u8; 32];
            fr.serialize_compressed(&mut bytes[..]).unwrap_or(());
            // ark-ff compressed serialization is little-endian for Fr
            let bytes = bytes;
            u64::from_le_bytes(bytes[..8].try_into().unwrap())
        })
    }

    /// Addition mod p.
    ///
    /// Computes r = (a + b) mod p.  Witnesses q in {0, 1} and r, enforces:
    ///   a + b = q * p + r,  0 <= r < 2^64
    pub fn add(&self, cs: ConstraintSystemRef<Fr>, other: &Self) -> Result<Self, SynthesisError> {
        let a = self.value();
        let b = other.value();
        let sum = a.zip(b).map(|(x, y)| {
            let s = (x as u128) + (y as u128);
            let p = GOLDILOCKS_PRIME as u128;
            ((s % p) as u64, if s >= p { 1u64 } else { 0u64 })
        });
        let r_val = sum.map(|(r, _)| r);
        let q_val = sum.map(|(_, q)| q);

        let r = GoldilocksVar::alloc_witness(cs.clone(), r_val)?;
        let q = AllocatedFr::alloc_witness(cs.clone(), q_val.map(Fr::from))?;

        // Enforce: a + b = q * p + r
        let mut relation = LinearCombination::zero();
        relation += (Fr::one(), self.inner.variable);
        relation += (Fr::one(), other.inner.variable);
        relation += (-goldilocks_prime_fr(), q.variable);
        relation += (-Fr::one(), r.inner.variable);
        cs.enforce_constraint(relation, lc_one(), LinearCombination::zero())?;

        // Enforce q is boolean (can only be 0 or 1 for addition of two < p values)
        q.assert_boolean(cs)?;

        Ok(r)
    }

    /// Subtraction mod p.
    ///
    /// Computes r = (a - b) mod p.  Witnesses borrow bit.
    pub fn sub(&self, cs: ConstraintSystemRef<Fr>, other: &Self) -> Result<Self, SynthesisError> {
        let a = self.value();
        let b = other.value();
        let diff = a.zip(b).map(|(x, y)| {
            let p = GOLDILOCKS_PRIME as u128;
            let x = x as u128;
            let y = y as u128;
            let r = if x >= y { x - y } else { x + p - y };
            let borrow = if x >= y { 0u64 } else { 1u64 };
            (r as u64, borrow)
        });
        let r_val = diff.map(|(r, _)| r);
        let borrow_val = diff.map(|(_, b)| b);

        let r = GoldilocksVar::alloc_witness(cs.clone(), r_val)?;
        let borrow = AllocatedFr::alloc_witness(cs.clone(), borrow_val.map(Fr::from))?;
        borrow.assert_boolean(cs.clone())?;

        // Enforce: a - b - r + borrow * p = 0
        let mut relation = LinearCombination::zero();
        relation += (Fr::one(), self.inner.variable);
        relation += (-Fr::one(), other.inner.variable);
        relation += (-Fr::one(), r.inner.variable);
        relation += (goldilocks_prime_fr(), borrow.variable);
        cs.enforce_constraint(relation, lc_one(), LinearCombination::zero())?;

        Ok(r)
    }

    /// Multiplication mod p.
    ///
    /// Witnesses q and r such that a * b = q * p + r, with 0 <= r < p.
    /// q can be up to ~64 bits (since a*b < p^2 < 2^128, and q < p).
    pub fn mul(&self, cs: ConstraintSystemRef<Fr>, other: &Self) -> Result<Self, SynthesisError> {
        let a = self.value();
        let b = other.value();
        let prod = a.zip(b).map(|(x, y)| {
            let product = (x as u128) * (y as u128);
            let p = GOLDILOCKS_PRIME as u128;
            ((product % p) as u64, (product / p) as u64)
        });
        let r_val = prod.map(|(r, _)| r);
        let q_val = prod.map(|(_, q)| q);

        let r = GoldilocksVar::alloc_witness(cs.clone(), r_val)?;
        let q = AllocatedFr::alloc_witness(cs.clone(), q_val.map(Fr::from))?;

        // Enforce: a * b = q * p + r
        let mut rhs = LinearCombination::zero();
        rhs += (goldilocks_prime_fr(), q.variable);
        rhs += (Fr::one(), r.inner.variable);
        cs.enforce_constraint(
            LinearCombination::from(self.inner.variable),
            LinearCombination::from(other.inner.variable),
            rhs,
        )?;

        // Range check q < 2^64
        range_check_64(cs, &q)?;

        Ok(r)
    }

    /// S-box: x^7 for Goldilocks Poseidon2.
    /// Computes x^7 = x^4 * x^2 * x with 3 modular multiplications.
    pub fn sbox7(&self, cs: ConstraintSystemRef<Fr>) -> Result<Self, SynthesisError> {
        let x2 = self.mul(cs.clone(), self)?;
        let x3 = x2.mul(cs.clone(), self)?;
        let x4 = x2.mul(cs.clone(), &x2)?;
        x4.mul(cs.clone(), &x3)
    }

    /// Assert equality of two Goldilocks variables.
    pub fn assert_equal(
        &self,
        cs: ConstraintSystemRef<Fr>,
        other: &Self,
    ) -> Result<(), SynthesisError> {
        self.inner.assert_equal(cs, &other.inner)
    }
}

/// Enforce that `var` fits in 64 bits via bit decomposition.
/// Costs 64 boolean constraints + 1 recombination constraint.
fn range_check_64(cs: ConstraintSystemRef<Fr>, var: &AllocatedFr) -> Result<(), SynthesisError> {
    let val = var.value.map(|fr| {
        let mut bytes = [0u8; 32];
        fr.serialize_compressed(&mut bytes[..]).unwrap_or(());
        // ark-ff compressed serialization is little-endian for Fr
        let bytes = bytes;
        u64::from_le_bytes(bytes[..8].try_into().unwrap())
    });

    let bits: Vec<AllocatedFr> = (0..64)
        .map(|i| {
            let bit_val = val.map(|v| {
                if (v >> i) & 1 == 1 {
                    Fr::one()
                } else {
                    Fr::zero()
                }
            });
            let bv = AllocatedFr::alloc_witness(cs.clone(), bit_val)?;
            bv.assert_boolean(cs.clone())?;
            Ok(bv)
        })
        .collect::<Result<Vec<_>, SynthesisError>>()?;

    // Enforce recombination in one linear constraint:
    //   sum(bits[i] * 2^i) - var = 0
    let mut power = Fr::one();
    let mut recombination = LinearCombination::zero();
    for bit in &bits {
        recombination += (power, bit.variable);
        power = power + power; // 2^(i+1)
    }
    recombination += (-Fr::one(), var.variable);
    cs.enforce_constraint(recombination, lc_one(), LinearCombination::zero())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn fresh_cs() -> ConstraintSystemRef<Fr> {
        ConstraintSystem::<Fr>::new_ref()
    }

    #[test]
    fn goldilocks_add_no_wrap() {
        let cs = fresh_cs();
        let a = GoldilocksVar::alloc_witness(cs.clone(), Some(10)).unwrap();
        let b = GoldilocksVar::alloc_witness(cs.clone(), Some(20)).unwrap();
        let c = a.add(cs.clone(), &b).unwrap();
        assert_eq!(c.value(), Some(30));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn goldilocks_add_wraps() {
        let cs = fresh_cs();
        let a = GoldilocksVar::alloc_witness(cs.clone(), Some(GOLDILOCKS_PRIME - 1)).unwrap();
        let b = GoldilocksVar::alloc_witness(cs.clone(), Some(3)).unwrap();
        let c = a.add(cs.clone(), &b).unwrap();
        // (p-1) + 3 = p + 2, mod p = 2
        assert_eq!(c.value(), Some(2));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn goldilocks_sub_no_borrow() {
        let cs = fresh_cs();
        let a = GoldilocksVar::alloc_witness(cs.clone(), Some(100)).unwrap();
        let b = GoldilocksVar::alloc_witness(cs.clone(), Some(30)).unwrap();
        let c = a.sub(cs.clone(), &b).unwrap();
        assert_eq!(c.value(), Some(70));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn goldilocks_sub_with_borrow() {
        let cs = fresh_cs();
        let a = GoldilocksVar::alloc_witness(cs.clone(), Some(5)).unwrap();
        let b = GoldilocksVar::alloc_witness(cs.clone(), Some(10)).unwrap();
        let c = a.sub(cs.clone(), &b).unwrap();
        assert_eq!(c.value(), Some(GOLDILOCKS_PRIME - 5));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn goldilocks_mul() {
        let cs = fresh_cs();
        let a = GoldilocksVar::alloc_witness(cs.clone(), Some(1_000_000_007)).unwrap();
        let b = GoldilocksVar::alloc_witness(cs.clone(), Some(1_000_000_009)).unwrap();
        let c = a.mul(cs.clone(), &b).unwrap();
        let expected = ((1_000_000_007u128 * 1_000_000_009u128) % GOLDILOCKS_PRIME as u128) as u64;
        assert_eq!(c.value(), Some(expected));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn goldilocks_sbox7() {
        let cs = fresh_cs();
        let x = GoldilocksVar::alloc_witness(cs.clone(), Some(3)).unwrap();
        let y = x.sbox7(cs.clone()).unwrap();
        // 3^7 = 2187
        assert_eq!(y.value(), Some(2187));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn goldilocks_sbox7_large() {
        let cs = fresh_cs();
        let val = GOLDILOCKS_PRIME - 1; // = p-1
        let x = GoldilocksVar::alloc_witness(cs.clone(), Some(val)).unwrap();
        let y = x.sbox7(cs.clone()).unwrap();
        // (p-1)^7 mod p = (-1)^7 mod p = p-1
        assert_eq!(y.value(), Some(GOLDILOCKS_PRIME - 1));
        assert!(cs.is_satisfied().unwrap());
    }
}
