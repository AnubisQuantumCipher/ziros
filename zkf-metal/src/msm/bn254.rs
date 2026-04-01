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

//! BN254 curve helpers for Rust-side MSM operations.
//!
//! Handles serialization between arkworks types and Metal buffer layouts,
//! plus the final window combination step (CPU-side).

use ark_bn254::{G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

/// Window size for Pippenger decomposition.
/// 16 bits is optimal for 2^20 - 2^24 point MSMs.
pub const WINDOW_SIZE: u32 = 16;

/// Number of windows needed for 254-bit scalars with given window size.
pub fn num_windows(c: u32) -> u32 {
    254_u32.div_ceil(c)
}

/// Number of buckets per window.
pub fn num_buckets(c: u32) -> u32 {
    1u32 << c
}

/// Serialize an arkworks affine point's coordinates to 4×u64 Montgomery limbs.
/// Returns (x_limbs, y_limbs) each as [u64; 4].
/// Uses internal Montgomery representation directly (not `into_bigint()` which de-Montgomerizes).
pub fn affine_to_limbs(x: &ark_bn254::Fq, y: &ark_bn254::Fq) -> ([u64; 4], [u64; 4]) {
    // .0 accesses the internal BigInt which is in Montgomery form
    (x.0.0, y.0.0)
}

/// Serialize a scalar to 4×u64 limbs (little-endian, non-Montgomery).
pub fn scalar_to_limbs(s: &ark_bn254::Fr) -> [u64; 4] {
    s.into_bigint().0
}

/// Check if a BN254 affine point is the identity (point at infinity).
pub fn is_identity(p: &G1Affine) -> bool {
    p.xy().is_none()
}

/// Combine window results using doublings (CPU-side final step).
///
/// Given `window_results[i]` = partial MSM for window i,
/// compute: result = ∑ window_results[i] * 2^(i*c)
pub fn combine_windows(window_results: &[G1Projective], c: u32) -> G1Projective {
    use ark_bn254::G1Projective as G1;
    use std::ops::AddAssign;

    if window_results.is_empty() {
        return G1::default();
    }

    let mut result = *window_results.last().unwrap();

    // Horner's method: result = ((...((w_{k-1}) * 2^c + w_{k-2}) * 2^c + ...) * 2^c + w_0)
    for i in (0..window_results.len() - 1).rev() {
        // Double c times
        for _ in 0..c {
            result = result + result; // point doubling via addition
        }
        result.add_assign(&window_results[i]);
    }

    result
}

/// Perform bucket reduction for one window (CPU fallback).
///
/// Given bucket contents, compute the running-sum accumulation:
/// window_result = ∑_{j=1}^{2^c - 1} j * bucket[j]
///               = ∑_{j=1}^{2^c - 1} running_sum  where running_sum accumulates from top
pub fn bucket_reduce_window(buckets: &[G1Projective]) -> G1Projective {
    use ark_bn254::G1Projective as G1;

    let mut running_sum = G1::default();
    let mut result = G1::default();

    // Accumulate from highest bucket down
    for i in (1..buckets.len()).rev() {
        running_sum += buckets[i];
        result += running_sum;
    }

    result
}
