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

//! Goldilocks-specific Poseidon2 round constants and kernel configuration.
//!
//! Round constants are extracted from p3-poseidon2 using the same RNG seed,
//! ensuring bit-identical results with Plonky3's `Poseidon2Goldilocks<16>`.

use p3_field::PrimeField64;
use p3_goldilocks::Goldilocks;
use p3_poseidon2::{ExternalLayerConstants, poseidon2_round_numbers_128};

/// Width of the Poseidon2 permutation.
pub const WIDTH: usize = 16;

/// Internal diagonal matrix for width=16 Goldilocks Poseidon2.
/// These are the (d_i - 1) values from `MATRIX_DIAG_16_GOLDILOCKS` in p3-goldilocks.
/// The internal linear layer computes: state[i] = d_i * state[i] + sum(state)
/// which equals: state[i] = (d_i - 1) * state[i] + (state[i] + sum(state))
/// but p3 stores d_i directly and computes: state[i] = d_i * state[i] + sum
/// where sum = sum of all state elements BEFORE the multiplication.
///
/// We pass the raw diagonal values and replicate the exact computation on GPU.
pub const MATRIX_DIAG_16_GOLDILOCKS: [u64; 16] = [
    0xde9b91a467d6afc0,
    0xc5f16b9c76a9be17,
    0x0ab0fef2d540ac55,
    0x3001d27009d05773,
    0xed23b1f906d3d9eb,
    0x5ce73743cba97054,
    0x1c3bab944af4ba24,
    0x2faa105854dbafae,
    0x53ffb3ae6d421a10,
    0xbcda9df8884ba396,
    0xfc1273e4a31807bb,
    0xc77952573d5142c0,
    0x56683339a819b85e,
    0x328fcbd8f0ddc8eb,
    0xb5101e303fce9cb7,
    0x774487b8c40089bb,
];

/// Flatten round constants into the layout expected by the Metal shader:
/// [external_initial (rounds_f/2 * 16)] [internal (rounds_p)] [external_terminal (rounds_f/2 * 16)]
pub fn flatten_round_constants(seed: u64) -> (Vec<u64>, u32, u32) {
    let (rounds_f, rounds_p) = poseidon2_round_numbers_128::<Goldilocks>(WIDTH, 7)
        .expect("Goldilocks Poseidon2 round numbers");

    use rand09::SeedableRng;
    let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);

    // Generate external constants (same RNG sequence as p3-poseidon2)
    let ext_consts: ExternalLayerConstants<Goldilocks, WIDTH> =
        ExternalLayerConstants::new_from_rng(rounds_f, &mut rng);

    // Generate internal constants (continuing same RNG)
    use rand09::Rng;
    let internal: Vec<u64> = (0..rounds_p)
        .map(|_| {
            let g: Goldilocks = rng.random();
            g.as_canonical_u64()
        })
        .collect();

    // Flatten: external_initial | internal | external_terminal
    let mut flat = Vec::new();

    // First half external rounds
    for arr in ext_consts.get_initial_constants() {
        for g in arr {
            flat.push(g.as_canonical_u64());
        }
    }

    // Internal rounds
    flat.extend_from_slice(&internal);

    // Second half external rounds
    for arr in ext_consts.get_terminal_constants() {
        for g in arr {
            flat.push(g.as_canonical_u64());
        }
    }

    (flat, rounds_f as u32, rounds_p as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_constants_deterministic() {
        let (rc1, f1, p1) = flatten_round_constants(42);
        let (rc2, f2, p2) = flatten_round_constants(42);
        assert_eq!(rc1, rc2);
        assert_eq!(f1, f2);
        assert_eq!(p1, p2);
        // 8 external rounds * 16 + internal rounds
        assert_eq!(rc1.len(), (f1 as usize) * WIDTH + p1 as usize);
    }
}
