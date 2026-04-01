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

//! BN254 R1CS circuit that binds a Nova-compressed FRI accumulator.
//!
//! The circuit is intentionally small. It does not verify the Spartan proof
//! in-circuit; instead it exposes the final Nova accumulator limbs as Groth16
//! public inputs, range-checks them, and constrains the structural invariants
//! that must hold for a valid compressed proof:
//!
//! 1. `fold_valid_status == 1`
//! 2. `queries_verified_count == num_steps`
//!
//! This keeps the wrapper feasible on laptop-class hardware while making the
//! attestation boundary explicit. Callers that need stronger guarantees must
//! also verify the compressed Nova proof off-circuit.
#[cfg(feature = "nova-compression")]
use super::nova_stark_compress::CompressedStarkProof;
#[cfg(feature = "nova-compression")]
use ark_bn254::Fr as BN254Fr;
#[cfg(feature = "nova-compression")]
use ark_ff::{PrimeField, Zero};
#[cfg(feature = "nova-compression")]
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError as ArkSynthesisError,
};

/// The Groth16 circuit that binds the Nova accumulator for an attested wrap.
#[cfg(feature = "nova-compression")]
#[derive(Clone)]
pub struct NovaVerifierCircuit {
    compressed_proof: Option<CompressedStarkProof>,
    num_steps: u32,
}

#[cfg(feature = "nova-compression")]
impl NovaVerifierCircuit {
    /// Create a new verifier circuit with witness data.
    pub fn new(compressed_proof: CompressedStarkProof) -> Self {
        let num_steps = compressed_proof.num_queries;
        Self {
            compressed_proof: Some(compressed_proof),
            num_steps,
        }
    }

    /// Create a sizing instance (no witness) for Groth16 setup.
    pub fn sizing_instance(num_steps: u32) -> Self {
        Self {
            compressed_proof: None,
            num_steps,
        }
    }
}

/// Number of Pallas scalar field elements in the Nova accumulator.
#[cfg(feature = "nova-compression")]
const ACC_ELEMENTS: usize = 5;
#[cfg(feature = "nova-compression")]
type AccumulatorLimb = Option<(BN254Fr, u128)>;

#[cfg(feature = "nova-compression")]
impl ConstraintSynthesizer<BN254Fr> for NovaVerifierCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<BN254Fr>,
    ) -> Result<(), ArkSynthesisError> {
        use ark_relations::r1cs::{LinearCombination, Variable};

        // Public inputs: accumulator lo/hi limbs, then the number of steps.
        let mut acc_lo_vars = Vec::with_capacity(ACC_ELEMENTS);
        let mut acc_hi_vars = Vec::with_capacity(ACC_ELEMENTS);

        for i in 0..ACC_ELEMENTS {
            let (lo_val, hi_val) = extract_acc_limbs(self.compressed_proof.as_ref(), i);

            let lo =
                cs.new_input_variable(|| Ok(lo_val.map(|(fr, _)| fr).unwrap_or(BN254Fr::zero())))?;
            let hi =
                cs.new_input_variable(|| Ok(hi_val.map(|(fr, _)| fr).unwrap_or(BN254Fr::zero())))?;

            range_check_128(
                cs.clone(),
                lo,
                lo_val.map(|(_, raw)| raw),
                &format!("acc_{i}_lo"),
            )?;
            range_check_128(
                cs.clone(),
                hi,
                hi_val.map(|(_, raw)| raw),
                &format!("acc_{i}_hi"),
            )?;

            acc_lo_vars.push(lo);
            acc_hi_vars.push(hi);
        }

        let num_steps_pub = cs.new_input_variable(|| Ok(BN254Fr::from(self.num_steps as u64)))?;

        // fold_valid_status == 1
        cs.enforce_constraint(
            LinearCombination::from(acc_lo_vars[0]),
            LinearCombination::from(Variable::One),
            LinearCombination::from(Variable::One),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(acc_hi_vars[0]),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        // queries_verified_count == num_steps
        cs.enforce_constraint(
            LinearCombination::from(acc_lo_vars[1]),
            LinearCombination::from(Variable::One),
            LinearCombination::from(num_steps_pub),
        )?;
        cs.enforce_constraint(
            LinearCombination::from(acc_hi_vars[1]),
            LinearCombination::from(Variable::One),
            LinearCombination::zero(),
        )?;

        Ok(())
    }
}

/// Build the Groth16 public inputs for a Nova-compressed proof.
#[cfg(feature = "nova-compression")]
pub fn public_inputs_for_compressed_proof(
    proof: &CompressedStarkProof,
) -> Result<Vec<BN254Fr>, String> {
    let mut public_inputs = Vec::with_capacity(ACC_ELEMENTS * 2 + 1);
    for idx in 0..ACC_ELEMENTS {
        let (lo, hi) = extract_acc_limbs(Some(proof), idx);
        let Some((lo, _)) = lo else {
            return Err(format!("missing low accumulator limb for index {idx}"));
        };
        let Some((hi, _)) = hi else {
            return Err(format!("missing high accumulator limb for index {idx}"));
        };
        public_inputs.push(lo);
        public_inputs.push(hi);
    }
    public_inputs.push(BN254Fr::from(proof.num_queries as u64));
    Ok(public_inputs)
}

/// Extract lo/hi 128-bit limbs for the `idx`-th Pallas scalar in the serialized accumulator.
#[cfg(feature = "nova-compression")]
fn extract_acc_limbs(
    proof: Option<&CompressedStarkProof>,
    idx: usize,
) -> (AccumulatorLimb, AccumulatorLimb) {
    let bytes = match proof {
        None => return (Some((BN254Fr::zero(), 0)), Some((BN254Fr::zero(), 0))),
        Some(p) => &p.final_accumulator,
    };

    let offset = idx * 32;
    if offset + 32 > bytes.len() {
        return (Some((BN254Fr::zero(), 0)), Some((BN254Fr::zero(), 0)));
    }

    let scalar_bytes = &bytes[offset..offset + 32];
    let mut lo_bytes = [0u8; 16];
    let mut hi_bytes = [0u8; 16];
    lo_bytes.copy_from_slice(&scalar_bytes[..16]);
    hi_bytes.copy_from_slice(&scalar_bytes[16..]);

    let lo_raw = u128::from_le_bytes(lo_bytes);
    let hi_raw = u128::from_le_bytes(hi_bytes);

    (
        Some((BN254Fr::from_le_bytes_mod_order(&lo_bytes), lo_raw)),
        Some((BN254Fr::from_le_bytes_mod_order(&hi_bytes), hi_raw)),
    )
}

/// Range-check that `var` fits in 128 bits via witness bit decomposition.
#[cfg(feature = "nova-compression")]
pub(crate) fn range_check_128(
    cs: ConstraintSystemRef<BN254Fr>,
    var: ark_relations::r1cs::Variable,
    value: Option<u128>,
    label: &str,
) -> Result<(), ArkSynthesisError> {
    use ark_relations::r1cs::{LinearCombination, Variable};

    let mut sum_lc = LinearCombination::<BN254Fr>::zero();
    let mut power = BN254Fr::from(1u64);
    let raw = value.unwrap_or(0);

    for j in 0..128 {
        let bit_value = ((raw >> j) & 1) as u64;
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

#[cfg(all(test, feature = "nova-compression"))]
mod tests {
    use super::*;
    use crate::arkworks::{
        create_local_groth16_proof_with_cached_shape, create_local_groth16_setup_with_shape,
    };
    use ark_bn254::Bn254;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_snark::SNARK;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn make_test_proof(num_steps: u32) -> CompressedStarkProof {
        let acc_size = ACC_ELEMENTS * 32;
        let mut final_accumulator = vec![0u8; acc_size];

        final_accumulator[0] = 1;

        let count_bytes = (num_steps as u64).to_le_bytes();
        final_accumulator[32..40].copy_from_slice(&count_bytes);

        CompressedStarkProof {
            compressed_snark_bytes: vec![],
            pp_hash: String::new(),
            final_accumulator,
            num_queries: num_steps,
            max_depth: 8,
            leaf_width: 1,
            num_fri_rounds: 4,
        }
    }

    #[test]
    fn circuit_is_satisfied_for_valid_accumulator() {
        let proof = make_test_proof(32);
        let circuit = NovaVerifierCircuit::new(proof);
        let cs = ConstraintSystem::<BN254Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            cs.is_satisfied().unwrap(),
            "valid accumulator should satisfy the circuit"
        );
        assert!(cs.num_constraints() < 5_000);
    }

    #[test]
    fn sizing_instance_matches_real_constraint_count() {
        let num_steps = 16u32;

        let sizing = NovaVerifierCircuit::sizing_instance(num_steps);
        let cs_sizing = ConstraintSystem::<BN254Fr>::new_ref();
        sizing.generate_constraints(cs_sizing.clone()).unwrap();
        let sizing_count = cs_sizing.num_constraints();

        let proof = make_test_proof(num_steps);
        let real = NovaVerifierCircuit::new(proof);
        let cs_real = ConstraintSystem::<BN254Fr>::new_ref();
        real.generate_constraints(cs_real.clone()).unwrap();
        let real_count = cs_real.num_constraints();

        assert_eq!(sizing_count, real_count);
    }

    #[test]
    fn public_inputs_are_stable() {
        let proof = make_test_proof(7);
        let public_inputs = public_inputs_for_compressed_proof(&proof).unwrap();

        assert_eq!(public_inputs.len(), ACC_ELEMENTS * 2 + 1);
        assert_eq!(public_inputs.last().cloned(), Some(BN254Fr::from(7u64)));
        assert_eq!(public_inputs[0], BN254Fr::from(1u64));
    }

    #[test]
    fn groth16_outer_prove_and_verify_succeeds_for_accumulator_binding() {
        crate::with_serialized_heavy_backend_test(|| {
            let compressed = make_test_proof(3);
            let public_inputs = public_inputs_for_compressed_proof(&compressed).unwrap();

            let mut setup_rng = StdRng::from_seed([0x11; 32]);
            let (pk, prove_shape) = create_local_groth16_setup_with_shape(
                NovaVerifierCircuit::sizing_instance(compressed.num_queries),
                &mut setup_rng,
            )
            .expect("Groth16 setup should succeed for Nova accumulator binding circuit");

            let mut prove_rng = StdRng::from_seed([0x22; 32]);
            let (proof, _) = create_local_groth16_proof_with_cached_shape(
                &pk,
                NovaVerifierCircuit::new(compressed),
                &mut prove_rng,
                &prove_shape,
            )
            .expect("Groth16 outer prove should succeed for Nova accumulator binding circuit");

            let verified = Groth16::<Bn254>::verify(&pk.vk, &public_inputs, &proof)
                .expect("Groth16 verification should run");
            assert!(
                verified,
                "Groth16 outer proof for Nova accumulator binding must verify"
            );
        });
    }
}
