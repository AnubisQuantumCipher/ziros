pub(crate) fn digest_prefix8(digest: [u8; 32]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

pub(crate) fn attestation_matches_subgraph_digests(
    expected_output_digest: [u8; 32],
    expected_trace_digest: [u8; 32],
    found_output_digest: [u8; 32],
    found_trace_digest: [u8; 32],
) -> bool {
    expected_output_digest == found_output_digest && expected_trace_digest == found_trace_digest
}

pub(crate) fn coordinator_two_party_unanimous_quorum_accepts(
    remote_digest: [u8; 32],
    local_digest: [u8; 32],
) -> bool {
    digest_prefix8(remote_digest) == digest_prefix8(local_digest)
}

#[cfg(test)]
mod tests {
    use super::{
        attestation_matches_subgraph_digests, coordinator_two_party_unanimous_quorum_accepts,
        digest_prefix8,
    };

    #[test]
    fn attestation_matching_is_exact() {
        assert!(attestation_matches_subgraph_digests(
            [1; 32],
            [2; 32],
            [1; 32],
            [2; 32]
        ));
        assert!(!attestation_matches_subgraph_digests(
            [1; 32],
            [2; 32],
            [1; 32],
            [3; 32]
        ));
    }

    #[test]
    fn quorum_uses_prefix_unanimity() {
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        left[..8].copy_from_slice(&[1; 8]);
        right[..8].copy_from_slice(&[1; 8]);
        right[8] = 9;
        assert_eq!(digest_prefix8(left), [1; 8]);
        assert!(coordinator_two_party_unanimous_quorum_accepts(left, right));
    }
}
