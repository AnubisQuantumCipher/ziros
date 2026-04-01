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

//! Shared hex conversion utilities for Groth16 BN254 curve elements.
//!
//! Used by both `groth16_proof` (proof decoding) and `groth16_vk` (VK decoding)
//! to convert arkworks field elements into Solidity-ready 0x-prefixed big-endian hex.

use ark_bn254::Fq;
use ark_ff::{BigInteger, PrimeField};
use std::fmt::Write;

/// The zero uint256 as a 0x-prefixed 64-hex-char string.
pub const ZERO_HEX: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// Convert an arkworks BN254 base field element to a 0x-prefixed big-endian hex string.
pub fn fq_to_hex(f: Fq) -> String {
    let repr = f.into_bigint();
    let bytes = repr.to_bytes_be();
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in &bytes {
        // Write directly into the string — no intermediate allocation per byte.
        write!(out, "{b:02x}").unwrap();
    }
    out
}

/// Convert a G1 affine point to `[x_hex, y_hex]`.
pub fn g1_to_hex(p: ark_bn254::G1Affine) -> [String; 2] {
    use ark_ec::AffineRepr;
    if p.is_zero() {
        return [ZERO_HEX.to_string(), ZERO_HEX.to_string()];
    }
    [fq_to_hex(p.x().unwrap()), fq_to_hex(p.y().unwrap())]
}

/// Format a public input decimal string as a Solidity uint256 hex literal.
///
/// Handles the full 254-bit BN254 scalar field range via `num_bigint::BigUint`.
/// Falls back to `0x00...00` only for genuinely unparseable strings.
pub fn public_input_to_hex(decimal: &str) -> String {
    use num_bigint::BigUint;
    if let Ok(val) = decimal.parse::<BigUint>() {
        let bytes = val.to_bytes_be();
        let mut out = String::with_capacity(66); // "0x" + 64 hex chars
        out.push_str("0x");
        // Pad to 32 bytes (64 hex chars)
        let pad = 32usize.saturating_sub(bytes.len());
        for _ in 0..pad {
            out.push_str("00");
        }
        for b in &bytes {
            write!(out, "{b:02x}").unwrap();
        }
        out
    } else {
        ZERO_HEX.to_string()
    }
}

/// Flip the last hex digit of a 0x-prefixed hex string to produce a tampered value.
///
/// Used by Foundry test generation to create an invalid proof point.
pub fn tamper_hex(hex: &str) -> String {
    let mut chars: Vec<char> = hex.chars().collect();
    if let Some(last) = chars.last_mut() {
        *last = if *last == '0' { '1' } else { '0' };
    }
    chars.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_hex_is_correct_length() {
        assert_eq!(ZERO_HEX.len(), 66);
        assert!(ZERO_HEX.starts_with("0x"));
    }

    #[test]
    fn public_input_small_value() {
        let hex = public_input_to_hex("91");
        assert_eq!(hex.len(), 66);
        assert!(hex.ends_with("5b"));
    }

    #[test]
    fn public_input_large_value() {
        // BN254 scalar field modulus - 1 (254-bit number)
        let large = "21888242871839275222246405745257275088548364400416034343698204186575808495616";
        let hex = public_input_to_hex(large);
        assert_eq!(hex.len(), 66);
        assert!(hex.starts_with("0x"));
        // Should NOT be zero — this is the truncation bug fix
        assert_ne!(hex, ZERO_HEX);
    }

    #[test]
    fn public_input_zero() {
        assert_eq!(public_input_to_hex("0"), ZERO_HEX);
    }

    #[test]
    fn public_input_unparseable() {
        assert_eq!(public_input_to_hex("not_a_number"), ZERO_HEX);
    }

    #[test]
    fn tamper_flips_last_digit() {
        assert_eq!(tamper_hex("0xabc0"), "0xabc1");
        assert_eq!(tamper_hex("0xabc1"), "0xabc0");
        assert_eq!(tamper_hex("0xabcf"), "0xabc0");
    }
}
