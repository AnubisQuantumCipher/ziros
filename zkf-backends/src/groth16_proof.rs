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

//! Decode an arkworks-compressed Groth16 BN254 proof into Solidity-ready
//! uncompressed affine coordinates (0x-prefixed big-endian hex literals).
//!
//! A Groth16 proof has three elements:
//!   - A ∈ G1 (32 bytes compressed)
//!   - B ∈ G2 (64 bytes compressed)
//!   - C ∈ G1 (32 bytes compressed)
//!
//! Solidity `verifyProof(uint[2] a, uint[2][2] b, uint[2] c, uint[] input)`
//! expects uncompressed affine coordinates as big-endian uint256 values.

use ark_bn254::Bn254;
use ark_ec::AffineRepr;
use ark_groth16::Proof;
use ark_serialize::CanonicalDeserialize;

use crate::groth16_hex::{ZERO_HEX, fq_to_hex, g1_to_hex};

/// Decoded Groth16 proof with all curve point coordinates as 0x-prefixed
/// big-endian hex strings, ready for Solidity calldata.
pub struct Groth16ProofHex {
    /// A point (G1): [x, y]
    pub a: [String; 2],
    /// B point (G2): [[x_c1, x_c0], [y_c1, y_c0]] — Ethereum precompile ordering
    pub b: [[String; 2]; 2],
    /// C point (G1): [x, y]
    pub c: [String; 2],
}

/// Decode arkworks-compressed Groth16 BN254 proof bytes.
///
/// Returns `None` if deserialization fails.
pub fn decode_groth16_proof(proof_bytes: &[u8]) -> Option<Groth16ProofHex> {
    let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes).ok()?;

    let a = g1_to_hex(proof.a);
    let c = g1_to_hex(proof.c);

    // G2 point B — Ethereum precompile ordering: [[x_im, x_re], [y_im, y_re]]
    let b = if proof.b.is_zero() {
        [
            [ZERO_HEX.to_string(), ZERO_HEX.to_string()],
            [ZERO_HEX.to_string(), ZERO_HEX.to_string()],
        ]
    } else {
        let bx = proof.b.x().unwrap();
        let by = proof.b.y().unwrap();
        [
            [fq_to_hex(bx.c1), fq_to_hex(bx.c0)],
            [fq_to_hex(by.c1), fq_to_hex(by.c0)],
        ]
    };

    Some(Groth16ProofHex { a, b, c })
}

// Re-export for backward compatibility with existing callers.
pub use crate::groth16_hex::public_input_to_hex;

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;

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
            cs.enforce_constraint(
                LinearCombination::from(Variable::One),
                LinearCombination::from(var),
                LinearCombination::from(Variable::One),
            )?;
            Ok(())
        }
    }

    #[test]
    fn roundtrip_proof_decodes() {
        crate::with_serialized_heavy_backend_test(|| {
            use rand::SeedableRng;
            let mut rng = rand::rngs::StdRng::seed_from_u64(42);
            let (pk, _vk) = Groth16::<Bn254>::circuit_specific_setup(TrivialCircuit, &mut rng)
                .expect("setup should succeed");

            let proof = Groth16::<Bn254>::prove(&pk, TrivialCircuit, &mut rng)
                .expect("prove should succeed");

            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes).unwrap();

            let decoded = decode_groth16_proof(&proof_bytes).expect("decode should succeed");

            assert_ne!(decoded.a[0], ZERO_HEX, "A.x should not be zero");
            assert_ne!(decoded.c[0], ZERO_HEX, "C.x should not be zero");
            assert_ne!(decoded.b[0][0], ZERO_HEX, "B.x should not be zero");
            assert!(decoded.a[0].starts_with("0x"));
            assert_eq!(decoded.a[0].len(), 66);
        });
    }

    #[test]
    fn empty_proof_returns_none() {
        assert!(decode_groth16_proof(&[]).is_none());
        assert!(decode_groth16_proof(&[1, 2, 3]).is_none());
    }
}
