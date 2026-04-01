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

//! Non-native Pallas field arithmetic in BN254 R1CS.
//!
//! Pallas modulus is 255 bits, BN254 Fr is 254 bits and needs a 2-limb representation
//! with range checks. Each Pallas element is split as:
//!
//! `x = x_lo + x_hi * 2^128`
//!
//! where `x_lo < 2^128` and `x_hi < 2^127` (since the Pallas modulus is below 2^255).
//!
//! Non-native operations have about 3x overhead vs native:
//! - Addition: 2 native additions + conditional modular reduction (4 constraints)
//! - Multiplication: 4 native multiplications + carry propagation + reduction (~20 constraints)
//! - Equality: 2 native equality checks (2 constraints)
#[cfg(feature = "nova-compression")]
use ark_bn254::Fr as BN254Fr;
#[cfg(feature = "nova-compression")]
use ark_relations::r1cs::{ConstraintSystemRef, LinearCombination, SynthesisError, Variable};

/// Pallas field modulus (p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001)
#[cfg(feature = "nova-compression")]
pub const PALLAS_MODULUS_LO: u128 = 0x992d30ed00000001_224698fc094cf91bu128;
#[cfg(feature = "nova-compression")]
pub const PALLAS_MODULUS_HI: u128 = 0x4000000000000000_0000000000000000u128;

/// A non-native Pallas field element in BN254 R1CS.
///
/// Represented as two variables (lo, hi) where value = lo + hi * 2^128.
#[cfg(feature = "nova-compression")]
#[derive(Clone, Copy)]
pub struct PallasVar {
    pub lo: Variable,
    pub hi: Variable,
    lo_value: Option<u128>,
    hi_value: Option<u128>,
}

#[cfg(feature = "nova-compression")]
impl PallasVar {
    /// Allocate a new non-native Pallas variable from a 255-bit value.
    pub fn alloc(
        cs: ConstraintSystemRef<BN254Fr>,
        value: impl FnOnce() -> Result<[u64; 4], SynthesisError>,
        label: &str,
    ) -> Result<Self, SynthesisError> {
        let limbs = value()?;

        // Split into lo (128 bits) and hi (127 bits)
        let lo_u128 = limbs[0] as u128 | ((limbs[1] as u128) << 64);
        let hi_u128 = limbs[2] as u128 | ((limbs[3] as u128) << 64);

        let lo_var = cs.new_witness_variable(|| Ok(u128_to_bn254(lo_u128)))?;
        let hi_var = cs.new_witness_variable(|| Ok(u128_to_bn254(hi_u128)))?;

        // Range checks
        super::nova_verifier_circuit::range_check_128(
            cs.clone(),
            lo_var,
            Some(lo_u128),
            &format!("{label}_lo"),
        )?;
        // hi needs only 127 bits, but 128-bit range check is safe (over-constrained is OK)
        super::nova_verifier_circuit::range_check_128(
            cs.clone(),
            hi_var,
            Some(hi_u128),
            &format!("{label}_hi"),
        )?;

        Ok(PallasVar {
            lo: lo_var,
            hi: hi_var,
            lo_value: Some(lo_u128),
            hi_value: Some(hi_u128),
        })
    }

    /// Allocate a Pallas variable as a public input.
    pub fn alloc_input(
        cs: ConstraintSystemRef<BN254Fr>,
        value: impl FnOnce() -> Result<[u64; 4], SynthesisError>,
        _label: &str,
    ) -> Result<Self, SynthesisError> {
        let limbs = value()?;
        let lo_u128 = limbs[0] as u128 | ((limbs[1] as u128) << 64);
        let hi_u128 = limbs[2] as u128 | ((limbs[3] as u128) << 64);

        let lo_var = cs.new_input_variable(|| Ok(u128_to_bn254(lo_u128)))?;
        let hi_var = cs.new_input_variable(|| Ok(u128_to_bn254(hi_u128)))?;

        Ok(PallasVar {
            lo: lo_var,
            hi: hi_var,
            lo_value: Some(lo_u128),
            hi_value: Some(hi_u128),
        })
    }

    fn value_parts(&self) -> Option<(u128, u128)> {
        self.lo_value.zip(self.hi_value)
    }

    /// Constrain two PallasVars to be equal.
    pub fn enforce_equal(
        cs: ConstraintSystemRef<BN254Fr>,
        a: &PallasVar,
        b: &PallasVar,
    ) -> Result<(), SynthesisError> {
        cs.enforce_constraint(
            LinearCombination::from(a.lo),
            LinearCombination::from(Variable::One),
            LinearCombination::from(b.lo),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(a.hi),
            LinearCombination::from(Variable::One),
            LinearCombination::from(b.hi),
        )?;
        Ok(())
    }

    /// Non-native addition: result = a + b mod p_pallas.
    ///
    /// Adds ~6 constraints (2 additions + conditional reduction).
    pub fn add(
        cs: ConstraintSystemRef<BN254Fr>,
        a: &PallasVar,
        b: &PallasVar,
        _label: &str,
    ) -> Result<PallasVar, SynthesisError> {
        #[derive(Clone, Copy)]
        struct AddWitness {
            sum_lo: u128,
            sum_hi: u128,
            carry: u128,
            reduce: u128,
            borrow: u128,
            result_lo: u128,
            result_hi: u128,
            hi_tail: u128,
            hi_is_top: u128,
            top_lo_gap: u128,
        }

        let witness = a
            .value_parts()
            .zip(b.value_parts())
            .map(|((a_lo, a_hi), (b_lo, b_hi))| {
                let (sum_lo, carry_out) = a_lo.overflowing_add(b_lo);
                let carry = if carry_out { 1u128 } else { 0u128 };
                let sum_hi = a_hi + b_hi + carry;

                let reduce = if sum_hi > PALLAS_MODULUS_HI
                    || (sum_hi == PALLAS_MODULUS_HI && sum_lo >= PALLAS_MODULUS_LO)
                {
                    1u128
                } else {
                    0u128
                };

                let (result_lo, borrow, result_hi) = if reduce == 1 {
                    let (reduced_lo, borrow_out) = sum_lo.overflowing_sub(PALLAS_MODULUS_LO);
                    let borrow = if borrow_out { 1u128 } else { 0u128 };
                    let reduced_hi = sum_hi - PALLAS_MODULUS_HI - borrow;
                    (reduced_lo, borrow, reduced_hi)
                } else {
                    (sum_lo, 0u128, sum_hi)
                };

                let hi_is_top = if result_hi == PALLAS_MODULUS_HI {
                    1u128
                } else {
                    0u128
                };
                let hi_tail = if hi_is_top == 1 { 0u128 } else { result_hi };
                let top_lo_gap = if hi_is_top == 1 {
                    (PALLAS_MODULUS_LO - 1)
                        .checked_sub(result_lo)
                        .expect("canonical Pallas result must satisfy lo <= modulus_lo - 1")
                } else {
                    0u128
                };

                AddWitness {
                    sum_lo,
                    sum_hi,
                    carry,
                    reduce,
                    borrow,
                    result_lo,
                    result_hi,
                    hi_tail,
                    hi_is_top,
                    top_lo_gap,
                }
            });

        // Compute sum = a + b (may exceed modulus)
        let sum_lo =
            cs.new_witness_variable(|| Ok(u128_to_bn254(witness.map_or(0, |value| value.sum_lo))))?;
        let sum_hi =
            cs.new_witness_variable(|| Ok(u128_to_bn254(witness.map_or(0, |value| value.sum_hi))))?;

        // carry bit: sum may produce carry from lo to hi
        let carry = cs.new_witness_variable(|| {
            Ok(BN254Fr::from(witness.map_or(0, |value| value.carry) as u64))
        })?;
        let reduce = cs.new_witness_variable(|| {
            Ok(BN254Fr::from(witness.map_or(0, |value| value.reduce) as u64))
        })?;
        let borrow = cs.new_witness_variable(|| {
            Ok(BN254Fr::from(witness.map_or(0, |value| value.borrow) as u64))
        })?;
        let result_lo = cs.new_witness_variable(|| {
            Ok(u128_to_bn254(witness.map_or(0, |value| value.result_lo)))
        })?;
        let result_hi = cs.new_witness_variable(|| {
            Ok(u128_to_bn254(witness.map_or(0, |value| value.result_hi)))
        })?;
        let hi_tail = cs
            .new_witness_variable(|| Ok(u128_to_bn254(witness.map_or(0, |value| value.hi_tail))))?;
        let hi_is_top = cs.new_witness_variable(|| {
            Ok(BN254Fr::from(
                witness.map_or(0, |value| value.hi_is_top) as u64
            ))
        })?;
        let top_lo_gap = cs.new_witness_variable(|| {
            Ok(u128_to_bn254(witness.map_or(0, |value| value.top_lo_gap)))
        })?;

        super::nova_verifier_circuit::range_check_128(
            cs.clone(),
            sum_lo,
            witness.map(|value| value.sum_lo),
            "pallas_sum_lo",
        )?;
        super::nova_verifier_circuit::range_check_128(
            cs.clone(),
            sum_hi,
            witness.map(|value| value.sum_hi),
            "pallas_sum_hi",
        )?;
        super::nova_verifier_circuit::range_check_128(
            cs.clone(),
            result_lo,
            witness.map(|value| value.result_lo),
            "pallas_result_lo",
        )?;
        super::nova_verifier_circuit::range_check_128(
            cs.clone(),
            top_lo_gap,
            witness.map(|value| value.top_lo_gap),
            "pallas_top_lo_gap",
        )?;
        range_check_bits(
            cs.clone(),
            hi_tail,
            witness.map(|value| value.hi_tail),
            126,
            "pallas_hi_tail",
        )?;

        // Boolean constraint on carry
        cs.enforce_constraint(
            LinearCombination::from(carry),
            LinearCombination::from(Variable::One) - LinearCombination::from(carry),
            LinearCombination::zero(),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(reduce),
            LinearCombination::from(Variable::One) - LinearCombination::from(reduce),
            LinearCombination::zero(),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(borrow),
            LinearCombination::from(Variable::One) - LinearCombination::from(borrow),
            LinearCombination::zero(),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(hi_is_top),
            LinearCombination::from(Variable::One) - LinearCombination::from(hi_is_top),
            LinearCombination::zero(),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(borrow),
            LinearCombination::from(reduce),
            LinearCombination::from(borrow),
        )?;

        // sum_lo + carry * 2^128 = a_lo + b_lo
        let two_128 = u128_to_bn254(1u128 << 127) + u128_to_bn254(1u128 << 127);
        cs.enforce_constraint(
            LinearCombination::from(a.lo) + LinearCombination::from(b.lo),
            LinearCombination::from(Variable::One),
            LinearCombination::from(sum_lo) + (two_128, carry),
        )?;

        // sum_hi = a_hi + b_hi + carry
        cs.enforce_constraint(
            LinearCombination::from(a.hi)
                + LinearCombination::from(b.hi)
                + LinearCombination::from(carry),
            LinearCombination::from(Variable::One),
            LinearCombination::from(sum_hi),
        )?;

        cs.enforce_constraint(
            LinearCombination::from(sum_lo) + (two_128, borrow),
            LinearCombination::from(Variable::One),
            LinearCombination::from(result_lo) + (u128_to_bn254(PALLAS_MODULUS_LO), reduce),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(sum_hi),
            LinearCombination::from(Variable::One),
            LinearCombination::from(result_hi)
                + (u128_to_bn254(PALLAS_MODULUS_HI), reduce)
                + LinearCombination::from(borrow),
        )?;

        cs.enforce_constraint(
            LinearCombination::from(result_hi),
            LinearCombination::from(Variable::One),
            LinearCombination::from(hi_tail) + (u128_to_bn254(PALLAS_MODULUS_HI), hi_is_top),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(hi_is_top),
            LinearCombination::from(hi_tail),
            LinearCombination::zero(),
        )?;
        let top_lo_bound = LinearCombination::from(result_lo)
            + (BN254Fr::from(1u64), top_lo_gap)
            + (-u128_to_bn254(PALLAS_MODULUS_LO - 1), Variable::One);
        cs.enforce_constraint(
            LinearCombination::from(hi_is_top),
            top_lo_bound,
            LinearCombination::zero(),
        )?;

        Ok(PallasVar {
            lo: result_lo,
            hi: result_hi,
            lo_value: witness.map(|value| value.result_lo),
            hi_value: witness.map(|value| value.result_hi),
        })
    }
}

#[cfg(feature = "nova-compression")]
fn range_check_bits(
    cs: ConstraintSystemRef<BN254Fr>,
    var: Variable,
    value: Option<u128>,
    bits: usize,
    label: &str,
) -> Result<(), SynthesisError> {
    let mut sum_lc = LinearCombination::<BN254Fr>::zero();
    let mut power = BN254Fr::from(1u64);
    let raw = value.unwrap_or(0);

    for bit_idx in 0..bits {
        let bit_value = ((raw >> bit_idx) & 1) as u64;
        let bit = cs.new_witness_variable(|| Ok(BN254Fr::from(bit_value)))?;

        cs.enforce_constraint(
            LinearCombination::from(bit),
            LinearCombination::from(Variable::One) - LinearCombination::from(bit),
            LinearCombination::zero(),
        )?;

        sum_lc += (power, bit);
        power = power + power;
    }

    cs.enforce_constraint(
        sum_lc,
        LinearCombination::from(Variable::One),
        LinearCombination::from(var),
    )?;

    let _ = label;
    Ok(())
}

/// Convert a u128 value to BN254Fr.
#[cfg(feature = "nova-compression")]
fn u128_to_bn254(val: u128) -> BN254Fr {
    let lo = (val & 0xFFFFFFFFFFFFFFFF) as u64;
    let hi = (val >> 64) as u64;
    BN254Fr::from(lo) + BN254Fr::from(hi) * BN254Fr::from(1u64 << 32) * BN254Fr::from(1u64 << 32)
}

#[cfg(all(test, feature = "nova-compression"))]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    fn fresh_cs() -> ConstraintSystemRef<BN254Fr> {
        ConstraintSystem::<BN254Fr>::new_ref()
    }

    fn limbs(lo: u128, hi: u128) -> [u64; 4] {
        [lo as u64, (lo >> 64) as u64, hi as u64, (hi >> 64) as u64]
    }

    #[test]
    fn pallas_add_no_wrap() {
        let cs = fresh_cs();
        let a = PallasVar::alloc(cs.clone(), || Ok(limbs(10, 0)), "a").unwrap();
        let b = PallasVar::alloc(cs.clone(), || Ok(limbs(20, 0)), "b").unwrap();
        let c = PallasVar::add(cs.clone(), &a, &b, "sum").unwrap();
        assert_eq!(c.value_parts(), Some((30, 0)));
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn pallas_add_wraps_once_at_modulus() {
        let cs = fresh_cs();
        let a = PallasVar::alloc(
            cs.clone(),
            || Ok(limbs(PALLAS_MODULUS_LO - 1, PALLAS_MODULUS_HI)),
            "a",
        )
        .unwrap();
        let b = PallasVar::alloc(cs.clone(), || Ok(limbs(5, 0)), "b").unwrap();
        let c = PallasVar::add(cs.clone(), &a, &b, "sum").unwrap();
        assert_eq!(c.value_parts(), Some((4, 0)));
        assert!(cs.is_satisfied().unwrap());
    }
}
