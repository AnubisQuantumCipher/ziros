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

use sha2::{Digest, Sha256};

pub(crate) fn compute_admission_pow(public_key: &[u8], difficulty: u8) -> u64 {
    if difficulty == 0 {
        return 0;
    }
    let mut nonce = 0u64;
    loop {
        if verify_admission_pow(public_key, nonce, difficulty) {
            return nonce;
        }
        nonce = nonce.wrapping_add(1);
    }
}

pub(crate) fn verify_admission_pow(public_key: &[u8], nonce: u64, difficulty: u8) -> bool {
    if difficulty == 0 {
        return true;
    }

    let mut hasher = Sha256::new();
    hasher.update(public_key);
    hasher.update(nonce.to_le_bytes());
    leading_zero_bits(&hasher.finalize()) >= u32::from(difficulty)
}

pub(crate) fn hybrid_admission_pow_identity_bytes(
    legacy_public_key: &[u8],
    public_key_bundle_bytes: Option<Vec<u8>>,
) -> Vec<u8> {
    public_key_bundle_bytes.unwrap_or_else(|| legacy_public_key.to_vec())
}

pub(crate) fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut total = 0u32;
    for byte in bytes {
        let leading = byte.leading_zeros();
        total += leading;
        if *byte != 0 {
            break;
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::{
        compute_admission_pow, hybrid_admission_pow_identity_bytes, leading_zero_bits,
        verify_admission_pow,
    };

    #[test]
    fn pow_verification_round_trips() {
        let nonce = compute_admission_pow(b"peer-a", 8);
        assert!(verify_admission_pow(b"peer-a", nonce, 8));
    }

    #[test]
    fn leading_zero_bits_counts_u8_prefix_bits() {
        assert_eq!(leading_zero_bits(&[]), 0);
        assert_eq!(leading_zero_bits(&[0b1111_1111]), 0);
        assert_eq!(leading_zero_bits(&[0b0001_1111]), 3);
        assert_eq!(leading_zero_bits(&[0, 0b0001_1111]), 11);
    }

    #[test]
    fn bundle_bytes_take_precedence_when_present() {
        assert_eq!(
            hybrid_admission_pow_identity_bytes(b"legacy", Some(vec![1, 2, 3])),
            vec![1, 2, 3]
        );
    }
}
