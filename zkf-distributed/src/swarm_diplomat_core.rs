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

use serde::Serialize;
use sha2::{Digest, Sha256};

pub(crate) fn bounded_gossip_count(pending_len: usize, gossip_max: usize) -> usize {
    pending_len.min(gossip_max.max(1))
}

pub(crate) fn severity_rank(severity: &str) -> u8 {
    match severity {
        "moderate" => 1,
        "high" => 2,
        "critical" => 3,
        "model-integrity-critical" => 4,
        _ => 0,
    }
}

pub(crate) fn intelligence_merkle_root_from_leaves(mut leaves: Vec<String>) -> String {
    leaves.sort();
    if leaves.is_empty() {
        return hash_bytes(b"empty-intelligence");
    }
    while leaves.len() > 1 {
        let mut next = Vec::new();
        for pair in leaves.chunks(2) {
            let left = &pair[0];
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(hash_bytes(format!("{left}{right}").as_bytes()));
        }
        leaves = next;
    }
    leaves
        .pop()
        .unwrap_or_else(|| hash_bytes(b"empty-intelligence"))
}

pub(crate) fn canonical_hash_leaf<T: Serialize>(value: &T) -> String {
    hash_bytes(canonical_json_string(value).as_bytes())
}

pub(crate) fn canonical_json_string<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value).unwrap_or(serde_json::Value::Null) {
        serde_json::Value::Object(map) => {
            let sorted = map
                .into_iter()
                .collect::<std::collections::BTreeMap<_, _>>();
            serde_json::to_string(&sorted).unwrap_or_default()
        }
        serde_json::Value::Array(values) => serde_json::to_string(&values).unwrap_or_default(),
        other => serde_json::to_string(&other).unwrap_or_default(),
    }
}

pub(crate) fn hash_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{bounded_gossip_count, intelligence_merkle_root_from_leaves};

    #[test]
    fn bounded_gossip_count_caps_and_stays_positive() {
        assert_eq!(bounded_gossip_count(0, 0), 0);
        assert_eq!(bounded_gossip_count(5, 0), 1);
        assert_eq!(bounded_gossip_count(5, 2), 2);
    }

    #[test]
    fn intelligence_root_is_order_independent() {
        let left = intelligence_merkle_root_from_leaves(vec!["b".into(), "a".into()]);
        let right = intelligence_merkle_root_from_leaves(vec!["a".into(), "b".into()]);
        assert_eq!(left, right);
    }
}
