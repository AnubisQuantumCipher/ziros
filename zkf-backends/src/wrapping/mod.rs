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

pub mod air_eval_circuit;
pub mod duplex_challenger;
pub mod fri_gadgets;
pub mod fri_query_step;
pub mod fri_verifier_circuit;
pub mod groth16_recursive_verifier;
pub mod halo2_ipa_accumulator;
pub mod halo2_to_groth16;
pub mod nonnative_bn254_fq;
pub mod nonnative_goldilocks;
pub mod nonnative_pallas;
pub mod nova_stark_compress;
pub mod nova_universal_aggregator;
pub mod nova_verifier_circuit;
pub mod poseidon2_goldilocks;
pub mod stark_to_groth16;

use zkf_core::wrapping::WrapperRegistry;

/// Create a wrapper registry pre-loaded with all available wrapping paths.
///
/// Currently registered wrappers:
/// - **Plonky3 → Groth16**: STARK-to-SNARK wrapping via FRI verifier circuit
/// - **Halo2 → Groth16**: IPA-to-SNARK wrapping via non-native Pasta arithmetic
pub fn default_wrapper_registry() -> WrapperRegistry {
    let mut registry = WrapperRegistry::new();

    // Register the STARK-to-Groth16 wrapper (Plonky3 → Arkworks Groth16)
    registry.register(Box::new(stark_to_groth16::StarkToGroth16Wrapper));

    // Register the Halo2-to-Groth16 wrapper (Halo2 IPA → Arkworks Groth16)
    registry.register(Box::new(halo2_to_groth16::Halo2ToGroth16Wrapper));

    registry
}
