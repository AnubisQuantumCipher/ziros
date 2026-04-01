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

use crate::protocol::SubgraphTraceEntry;
use sha2::{Digest, Sha256};

pub(crate) fn output_digest(
    output_data: &[(u32, Vec<u8>)],
    named_outputs: &[(String, Vec<u8>)],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (slot, bytes) in output_data {
        hasher.update(slot.to_le_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    for (name, bytes) in named_outputs {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    }
    hasher.finalize().into()
}

pub(crate) fn trace_digest(trace_entries: &[SubgraphTraceEntry]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for trace in trace_entries {
        hasher.update((trace.node_name.len() as u64).to_le_bytes());
        hasher.update(trace.node_name.as_bytes());
        hasher.update(trace.wall_time_ms.to_le_bytes());
        hasher.update((trace.device.len() as u64).to_le_bytes());
        hasher.update(trace.device.as_bytes());
    }
    hasher.finalize().into()
}

pub(crate) fn attestation_signing_bytes(
    job_id: &str,
    partition_id: u32,
    output_digest: [u8; 32],
    trace_digest: [u8; 32],
    activation_level: Option<u8>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(job_id.len() + 4 + 32 + 32 + 1);
    bytes.extend_from_slice(job_id.as_bytes());
    bytes.extend_from_slice(&partition_id.to_le_bytes());
    bytes.extend_from_slice(&output_digest);
    bytes.extend_from_slice(&trace_digest);
    bytes.push(activation_level.unwrap_or_default());
    bytes
}

pub(crate) fn memory_entry_hash(
    entry_kind: &str,
    signer_peer_id: &str,
    recorded_unix_ms: u128,
    previous_hash: &str,
    payload_json: &[u8],
    signature: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(entry_kind.as_bytes());
    hasher.update(signer_peer_id.as_bytes());
    hasher.update(recorded_unix_ms.to_le_bytes());
    hasher.update(previous_hash.as_bytes());
    hasher.update(payload_json);
    hasher.update(signature);
    hex_string(&hasher.finalize())
}

pub(crate) fn hex_string(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{attestation_signing_bytes, memory_entry_hash, output_digest};

    #[test]
    fn digest_and_signing_bytes_are_deterministic() {
        let digest = output_digest(&[(0, vec![1, 2, 3])], &[("x".into(), vec![4])]);
        let bytes = attestation_signing_bytes("job-1", 0, digest, digest, Some(1));
        assert!(!bytes.is_empty());
        assert_eq!(
            memory_entry_hash("k", "peer", 7, "GENESIS", b"{}", b"sig"),
            memory_entry_hash("k", "peer", 7, "GENESIS", b"{}", b"sig")
        );
    }
}
