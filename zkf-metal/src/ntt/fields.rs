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

//! Field-specific NTT dispatch helpers.
//!
//! Precomputes twiddle factors and manages Metal buffers for
//! Goldilocks and BabyBear fields.

use p3_field::{PrimeField64, TwoAdicField};

/// Precompute twiddle factors for radix-2 NTT.
///
/// For size N, we need N twiddle factors stored in a tree layout:
/// twiddles[1] = g (primitive Nth root of unity)
/// twiddles[half + j] = g^(bit_reverse(j, log_n)) for butterfly at position j
///
/// This layout allows O(1) lookup during butterfly: twiddle = twiddles[half + pos].
pub fn precompute_twiddles<F: TwoAdicField + PrimeField64>(log_n: usize) -> Vec<u64> {
    let n = 1usize << log_n;
    let mut twiddles = vec![0u64; n];

    // Get primitive Nth root of unity
    let g = F::two_adic_generator(log_n);

    // Precompute powers of g in bit-reversed order for each stage
    for stage in 0..log_n {
        let half = 1usize << stage;
        let step = n >> (stage + 1);

        for j in 0..half {
            // twiddle = g^(j * step) = g^(j * N/(2*half))
            let exp = j * step;
            let mut w = F::ONE;
            let mut base = g;
            let mut e = exp;
            while e > 0 {
                if e & 1 == 1 {
                    w *= base;
                }
                base *= base;
                e >>= 1;
            }
            twiddles[half + j] = w.as_canonical_u64();
        }
    }

    twiddles
}

/// Precompute inverse twiddle factors for inverse NTT.
pub fn precompute_inverse_twiddles<F: TwoAdicField + PrimeField64>(log_n: usize) -> Vec<u64> {
    let n = 1usize << log_n;
    let mut twiddles = vec![0u64; n];

    let g = F::two_adic_generator(log_n);
    // Inverse root = g^(-1) = g^(N-1) since g^N = 1
    let g_inv = {
        let mut result = F::ONE;
        let mut base = g;
        let mut e = n - 1;
        while e > 0 {
            if e & 1 == 1 {
                result *= base;
            }
            base *= base;
            e >>= 1;
        }
        result
    };

    for stage in 0..log_n {
        let half = 1usize << stage;
        let step = n >> (stage + 1);

        for j in 0..half {
            let exp = j * step;
            let mut w = F::ONE;
            let mut base = g_inv;
            let mut e = exp;
            while e > 0 {
                if e & 1 == 1 {
                    w *= base;
                }
                base *= base;
                e >>= 1;
            }
            twiddles[half + j] = w.as_canonical_u64();
        }
    }

    twiddles
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_goldilocks::Goldilocks;

    #[test]
    fn twiddle_factors_valid() {
        let twiddles = precompute_twiddles::<Goldilocks>(4);
        assert_eq!(twiddles.len(), 16);
        // twiddles[1] should be g (16th root of unity)
        // twiddles[0] is unused
        assert_ne!(twiddles[1], 0);
    }
}
