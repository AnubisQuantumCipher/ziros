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

//! BabyBear-specific Poseidon2 round constants and kernel configuration.
//!
//! Round constants are extracted from p3-poseidon2 using the same RNG seed,
//! ensuring bit-identical results with Plonky3's `Poseidon2BabyBear<16>`.

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_poseidon2::{ExternalLayerConstants, poseidon2_round_numbers_128};
use std::sync::OnceLock;

/// Width of the Poseidon2 permutation.
pub const WIDTH: usize = 16;

/// Internal diagonal matrix for width=16 BabyBear Poseidon2.
///
/// The internal linear layer is: `(1 + Diag(V)) * state`, where V is:
/// `[-2, 1, 2, 1/2, 3, 4, -1/2, -3, -4, 1/2^8, 1/4, 1/8, 1/2^27, -1/2^8, -1/16, -1/2^27]`
///
/// All values computed as BabyBear field elements (p = 2013265921).
/// On the GPU: `state[i] = V[i] * state[i] + sum(state)` for all i.
pub fn diagonal() -> &'static [u32; 16] {
    static DIAG: OnceLock<[u32; 16]> = OnceLock::new();
    DIAG.get_or_init(|| {
        let two = BabyBear::from_u64(2);
        let inv2 = exp_bb(two, BabyBear::ORDER_U64 - 2);

        let to_u32 = |f: BabyBear| f.as_canonical_u64() as u32;
        let inv_pow2 = |e: u64| {
            let base = BabyBear::from_u64(1u64 << e.min(30));
            let base = if e > 30 {
                let hi = BabyBear::from_u64(1u64 << (e - 30));
                base * hi
            } else {
                base
            };
            exp_bb(base, BabyBear::ORDER_U64 - 2)
        };

        [
            to_u32(-two),                   // -2
            to_u32(BabyBear::ONE),          // 1
            to_u32(two),                    // 2
            to_u32(inv2),                   // 1/2
            to_u32(BabyBear::from_u64(3)),  // 3
            to_u32(BabyBear::from_u64(4)),  // 4
            to_u32(-inv2),                  // -1/2
            to_u32(-BabyBear::from_u64(3)), // -3
            to_u32(-BabyBear::from_u64(4)), // -4
            to_u32(inv_pow2(8)),            // 1/2^8
            to_u32(inv_pow2(2)),            // 1/4
            to_u32(inv_pow2(3)),            // 1/8
            to_u32(inv_pow2(27)),           // 1/2^27
            to_u32(-inv_pow2(8)),           // -1/2^8
            to_u32(-inv_pow2(4)),           // -1/16
            to_u32(-inv_pow2(27)),          // -1/2^27
        ]
    })
}

fn exp_bb(base: BabyBear, exp: u64) -> BabyBear {
    let mut result = BabyBear::ONE;
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result *= b;
        }
        b *= b;
        e >>= 1;
    }
    result
}

/// Flatten round constants into the layout expected by the Metal shader:
/// [external_initial (rounds_f/2 * 16)] [internal (rounds_p)] [external_terminal (rounds_f/2 * 16)]
pub fn flatten_round_constants(seed: u64) -> (Vec<u32>, u32, u32) {
    let (rounds_f, rounds_p) = poseidon2_round_numbers_128::<BabyBear>(WIDTH, 7)
        .expect("BabyBear Poseidon2 round numbers");

    use rand09::SeedableRng;
    let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);

    let ext_consts: ExternalLayerConstants<BabyBear, WIDTH> =
        ExternalLayerConstants::new_from_rng(rounds_f, &mut rng);

    use rand09::Rng;
    let internal: Vec<u32> = (0..rounds_p)
        .map(|_| {
            let g: BabyBear = rng.random();
            g.as_canonical_u64() as u32
        })
        .collect();

    let mut flat = Vec::new();

    for arr in ext_consts.get_initial_constants() {
        for g in arr {
            flat.push(g.as_canonical_u64() as u32);
        }
    }

    flat.extend_from_slice(&internal);

    for arr in ext_consts.get_terminal_constants() {
        for g in arr {
            flat.push(g.as_canonical_u64() as u32);
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
        assert_eq!(rc1.len(), (f1 as usize) * WIDTH + p1 as usize);
    }

    #[test]
    fn diagonal_values_in_range() {
        let diag = diagonal();
        for &d in diag {
            assert!(
                (d as u64) < BabyBear::ORDER_U64,
                "diagonal value {} out of BabyBear range",
                d
            );
        }
    }

    #[test]
    fn diagonal_basic_sanity() {
        let diag = diagonal();
        let p = BabyBear::ORDER_U64 as u32;
        // V[1] = 1
        assert_eq!(diag[1], 1);
        // V[2] = 2
        assert_eq!(diag[2], 2);
        // V[4] = 3
        assert_eq!(diag[4], 3);
        // V[5] = 4
        assert_eq!(diag[5], 4);
        // V[0] = -2 mod p = p - 2
        assert_eq!(diag[0], p - 2);
        // V[7] = -3 mod p = p - 3
        assert_eq!(diag[7], p - 3);
        // V[8] = -4 mod p = p - 4
        assert_eq!(diag[8], p - 4);
    }
}
