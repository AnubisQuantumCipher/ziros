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

//! Decode an arkworks-compressed Groth16 BN254 verification key into
//! Solidity-ready 0x-prefixed big-endian hex literals.
//!
//! The arkworks backend serializes VKs with `CanonicalSerialize::serialize_compressed`
//! (little-endian, compressed curve points). Solidity needs uncompressed affine
//! coordinates as big-endian uint256 values. This module bridges the two.

use ark_bn254::{Bn254, Fq};
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::VerifyingKey;
use ark_serialize::CanonicalDeserialize;

/// Parsed Groth16 VK with all curve point coordinates as 0x-prefixed
/// big-endian hex strings, ready for embedding in Solidity source.
pub struct Groth16VkHex {
    pub alpha_g1: [String; 2],
    /// G2 ordering: [x_c1, x_c0, y_c1, y_c0] — matches the Ethereum
    /// alt_bn128 precompile layout.
    pub beta_g2: [String; 4],
    pub gamma_g2: [String; 4],
    pub delta_g2: [String; 4],
    pub ic: Vec<[String; 2]>,
}

/// Attempt to decode arkworks-compressed Groth16 BN254 VK bytes.
///
/// Returns `None` if deserialization fails (e.g. empty or corrupt VK).
pub fn decode_groth16_vk(vk_bytes: &[u8]) -> Option<Groth16VkHex> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes).ok()?;

    // Reject VKs with zero/identity curve points — these would allow proof forgery.
    if vk.alpha_g1.is_zero()
        || vk.beta_g2.is_zero()
        || vk.gamma_g2.is_zero()
        || vk.delta_g2.is_zero()
    {
        return None;
    }
    for ic_point in &vk.gamma_abc_g1 {
        if ic_point.is_zero() {
            return None;
        }
    }

    let g1_hex = |p: ark_bn254::G1Affine| -> [String; 2] {
        if p.is_zero() {
            return [zero(), zero()];
        }
        [fq_to_hex(p.x().unwrap()), fq_to_hex(p.y().unwrap())]
    };

    let g2_hex = |p: ark_bn254::G2Affine| -> [String; 4] {
        if p.is_zero() {
            return [zero(), zero(), zero(), zero()];
        }
        let x = p.x().unwrap();
        let y = p.y().unwrap();
        // Ethereum precompile ordering: (x_imaginary, x_real, y_imaginary, y_real)
        // i.e. (c1, c0, c1, c0) in arkworks Fq2 = c0 + c1*u
        [
            fq_to_hex(x.c1),
            fq_to_hex(x.c0),
            fq_to_hex(y.c1),
            fq_to_hex(y.c0),
        ]
    };

    let ic: Vec<[String; 2]> = vk.gamma_abc_g1.iter().map(|p| g1_hex(*p)).collect();

    Some(Groth16VkHex {
        alpha_g1: g1_hex(vk.alpha_g1),
        beta_g2: g2_hex(vk.beta_g2),
        gamma_g2: g2_hex(vk.gamma_g2),
        delta_g2: g2_hex(vk.delta_g2),
        ic,
    })
}

fn fq_to_hex(f: Fq) -> String {
    let repr = f.into_bigint();
    let bytes = repr.to_bytes_be();
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in &bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn zero() -> String {
    "0x0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;

    /// Trivial circuit: a single public input constrained to equal 1.
    #[derive(Clone)]
    struct TrivialCircuit;

    impl ConstraintSynthesizer<ark_bn254::Fr> for TrivialCircuit {
        fn generate_constraints(
            self,
            cs: ConstraintSystemRef<ark_bn254::Fr>,
        ) -> Result<(), SynthesisError> {
            use ark_ff::One;
            use ark_relations::r1cs::{LinearCombination, Variable};
            let val = ark_bn254::Fr::one();
            let var = cs.new_input_variable(|| Ok(val))?;
            // 1 * var = 1
            cs.enforce_constraint(
                LinearCombination::from(Variable::One),
                LinearCombination::from(var),
                LinearCombination::from(Variable::One),
            )?;
            Ok(())
        }
    }

    #[test]
    fn roundtrip_vk_decodes_to_nonzero_points() {
        crate::with_serialized_heavy_backend_test(|| {
            use rand::SeedableRng;
            let mut rng = rand::rngs::StdRng::seed_from_u64(42);
            let (_pk, vk) = Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut rng)
                .expect("setup should succeed");

            let mut vk_bytes = Vec::new();
            vk.serialize_compressed(&mut vk_bytes).unwrap();

            let decoded = decode_groth16_vk(&vk_bytes).expect("decode should succeed");

            let all_zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
            assert_ne!(
                decoded.alpha_g1[0], all_zero,
                "alpha_g1.x should not be zero"
            );
            assert_ne!(
                decoded.alpha_g1[1], all_zero,
                "alpha_g1.y should not be zero"
            );

            assert_ne!(decoded.beta_g2[0], all_zero, "beta_g2 should not be zero");
            assert_ne!(decoded.gamma_g2[0], all_zero, "gamma_g2 should not be zero");
            assert_ne!(decoded.delta_g2[0], all_zero, "delta_g2 should not be zero");
            assert_eq!(decoded.ic.len(), 2, "IC should have 2 points");
            assert_ne!(decoded.ic[0][0], all_zero, "IC[0].x should not be zero");
            for coord in &decoded.alpha_g1 {
                assert!(coord.starts_with("0x"), "should be 0x-prefixed");
                assert_eq!(coord.len(), 66, "BN254 Fq is 32 bytes = 66 hex chars");
            }
        });
    }

    #[test]
    fn empty_vk_returns_none() {
        assert!(decode_groth16_vk(&[]).is_none());
        assert!(decode_groth16_vk(&[1, 2, 3]).is_none());
    }
}
