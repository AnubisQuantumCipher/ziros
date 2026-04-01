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

//! Canonical serialization rules for deterministic IR representations.
//!
//! Canonical JSON has sorted keys at all levels and no extra whitespace,
//! producing deterministic output for content-addressing.

use serde::Serialize;

/// Serialize any serde-serializable value to canonical JSON.
pub fn try_to_canonical_json<T: Serialize>(value: &T) -> serde_json::Result<String> {
    let canonical = serde_json::to_value(value)?;
    serde_json::to_string(&canonical)
}

/// Serialize any serde-serializable value to canonical JSON.
///
/// Canonical JSON has sorted object keys (via serde_json's Value sorting)
/// and minimal whitespace. This ensures identical inputs produce identical
/// byte representations for content-addressing.
#[allow(clippy::panic)]
pub fn to_canonical_json<T: Serialize>(value: &T) -> String {
    match try_to_canonical_json(value) {
        Ok(json) => json,
        Err(err) => panic!("canonical serialization must succeed for valid types: {err}"),
    }
}

/// Compute SHA-256 digest of canonical JSON representation.
pub fn canonical_digest<T: Serialize>(value: &T) -> String {
    use sha2::{Digest, Sha256};
    let json = to_canonical_json(value);
    let hash = Sha256::digest(json.as_bytes());
    format!("{:x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn canonical_json_is_deterministic() {
        let mut map = BTreeMap::new();
        map.insert("z", 1);
        map.insert("a", 2);

        let json1 = to_canonical_json(&map);
        let json2 = to_canonical_json(&map);
        assert_eq!(json1, json2);
        // Keys must be sorted
        assert!(json1.find("\"a\"").unwrap() < json1.find("\"z\"").unwrap());
    }

    #[test]
    fn canonical_digest_is_deterministic() {
        let mut map = BTreeMap::new();
        map.insert("hello", "world");
        let d1 = canonical_digest(&map);
        let d2 = canonical_digest(&map);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn canonical_json_is_compact() {
        let mut map = BTreeMap::new();
        map.insert("key", "value");
        let json = to_canonical_json(&map);
        assert!(!json.contains('\n'));
        assert!(!json.contains("  "));
    }
}
