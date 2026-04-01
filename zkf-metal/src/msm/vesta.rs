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

//! Vesta curve helpers for Rust-side MSM operations.
//!
//! Handles serialization between `pasta_curves` Vesta types and Metal buffer
//! layouts, plus the final window combination step (CPU-side).

use ff::{Field, PrimeField};
use pasta_curves::arithmetic::CurveAffine;
use pasta_curves::group::Group;
use pasta_curves::group::prime::PrimeCurveAffine;
use pasta_curves::{Eq, EqAffine, Fp, Fq};

const _: () = assert!(std::mem::size_of::<Fq>() == 32);
const _: () = assert!(std::mem::align_of::<Fq>() == 8);

/// Number of windows needed for 255-bit scalars with given window size.
/// Vesta scalar field order is ~2^254.99, so we use 255 bits.
pub fn num_windows(c: u32) -> u32 {
    255_u32.div_ceil(c)
}

/// Number of buckets per window.
pub fn num_buckets(c: u32) -> u32 {
    1u32 << c
}

/// Number of buckets per window with NAF encoding (halved).
pub fn num_buckets_naf(c: u32) -> u32 {
    (1u32 << (c - 1)) + 1
}

/// Convert a 255-bit Vesta scalar to signed-digit NAF window representation.
/// Same encoding as BN254: `abs_value | (sign << 31)`.
pub fn scalar_to_naf_windows(limbs: &[u64; 4], c: u32, num_win: u32) -> Vec<u32> {
    let mut windows = Vec::with_capacity(num_win as usize);
    let mut val = [limbs[0], limbs[1], limbs[2], limbs[3], 0u64];
    let mask = (1u64 << c) - 1;
    let half = 1u64 << (c - 1);

    for _ in 0..num_win {
        let digit = val[0] & mask;
        // Shift right by c bits
        let shift = c as usize;
        debug_assert!(shift > 0 && shift < 64);
        for i in 0..4 {
            val[i] = (val[i] >> shift) | (val[i + 1] << (64 - shift));
        }
        val[4] >>= shift;

        if digit >= half && digit != 0 {
            let abs_digit = ((1u64 << c) - digit) as u32;
            // Add carry +1
            for v in val.iter_mut() {
                let (new_val, overflow) = v.overflowing_add(1);
                *v = new_val;
                if !overflow {
                    break;
                }
            }
            windows.push(abs_digit | (1u32 << 31));
        } else {
            windows.push(digit as u32);
        }
    }

    windows
}

/// Extract the internal Montgomery-form [u64; 4] limbs from a Vesta Fq element.
///
/// # Safety
/// Relies on Fq being a newtype over [u64; 4] in Montgomery form.
/// Verified at compile time by the size/align assertions above.
#[inline]
pub fn fq_to_mont_limbs(f: &Fq) -> [u64; 4] {
    // SAFETY: Fq is a newtype struct wrapping [u64; 4] in Montgomery representation.
    // Size and alignment are verified by compile-time assertions.
    unsafe { std::ptr::read(f as *const Fq as *const [u64; 4]) }
}

/// Construct a Vesta Fq element from raw Montgomery-form limbs.
///
/// # Safety
/// The caller must ensure the limbs represent a valid field element in Montgomery form
/// (i.e., 0 ≤ value < p).
#[inline]
pub fn mont_limbs_to_fq(limbs: [u64; 4]) -> Fq {
    // SAFETY: Fq is a newtype over [u64; 4] in Montgomery form.
    unsafe { std::mem::transmute(limbs) }
}

/// Serialize a Vesta affine point's coordinates to 4×u64 Montgomery limbs.
/// Returns (x_limbs, y_limbs).
pub fn affine_to_limbs(p: &EqAffine) -> ([u64; 4], [u64; 4]) {
    let coords = p.coordinates().unwrap();
    (fq_to_mont_limbs(coords.x()), fq_to_mont_limbs(coords.y()))
}

/// Serialize a Vesta scalar (Fp) to 4×u64 limbs in canonical (non-Montgomery) form.
/// This is what the GPU needs for window extraction.
pub fn scalar_to_limbs(s: &Fp) -> [u64; 4] {
    let repr = s.to_repr();
    let bytes = repr.as_ref();
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let offset = i * 8;
        *limb = u64::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
    }
    limbs
}

/// Check if a Vesta affine point is the identity (point at infinity).
pub fn is_identity(p: &EqAffine) -> bool {
    bool::from(p.is_identity())
}

/// Combine window results using doublings (CPU-side final step).
///
/// Given `window_results[i]` = partial MSM for window i,
/// compute: `result = ∑ window_results[i] * 2^(i*c)`
pub fn combine_windows(window_results: &[Eq], c: u32) -> Eq {
    use std::ops::AddAssign;

    if window_results.is_empty() {
        return Eq::identity();
    }

    let mut result = *window_results.last().unwrap();

    // Horner's method
    for i in (0..window_results.len() - 1).rev() {
        for _ in 0..c {
            result = result.double();
        }
        result.add_assign(&window_results[i]);
    }

    result
}

/// Perform bucket reduction for one window (CPU fallback).
pub fn bucket_reduce_window(buckets: &[Eq]) -> Eq {
    let mut running_sum = Eq::identity();
    let mut result = Eq::identity();

    for i in (1..buckets.len()).rev() {
        running_sum += buckets[i];
        result += running_sum;
    }

    result
}

/// Convert GPU projective point (12 u64s in Montgomery form) to `pasta_curves` Vesta.
///
/// Layout: [X(4 limbs), Y(4 limbs), Z(4 limbs)] in Montgomery form.
/// Converts Jacobian → affine → projective through the public API.
pub fn gpu_proj_to_vesta(data: &[u64]) -> Option<Eq> {
    assert!(data.len() >= 12);

    let z = mont_limbs_to_fq([data[8], data[9], data[10], data[11]]);

    if z == Fq::ZERO {
        return Some(Eq::identity());
    }

    let x = mont_limbs_to_fq([data[0], data[1], data[2], data[3]]);
    let y = mont_limbs_to_fq([data[4], data[5], data[6], data[7]]);

    // Convert Jacobian (X, Y, Z) to affine: x_aff = X/Z², y_aff = Y/Z³
    let z_inv = z.invert();
    if bool::from(z_inv.is_none()) {
        return None;
    }
    let z_inv = z_inv.unwrap();
    let z2_inv = z_inv * z_inv;
    let z3_inv = z2_inv * z_inv;
    let x_aff = x * z2_inv;
    let y_aff = y * z3_inv;

    // Construct affine point (validates on-curve)
    let affine = EqAffine::from_xy(x_aff, y_aff);
    if bool::from(affine.is_none()) {
        return None;
    }

    Some(affine.unwrap().into())
}
