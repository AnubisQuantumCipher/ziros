use crate::config::IntegrityAlgorithm;
use sha2::{Digest, Sha256};

pub(crate) fn frame_length_valid(length: u32, max_frame_size: u32) -> bool {
    length <= max_frame_size
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn encrypted_gossip_fail_closed(
    negotiated: bool,
    plaintext_present: bool,
    encrypted_payload_present: bool,
) -> bool {
    if negotiated {
        !plaintext_present
    } else {
        !plaintext_present && !encrypted_payload_present
    }
}

pub(crate) fn sha256_digest(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

pub(crate) fn fnv1a_digest(bytes: &[u8]) -> Vec<u8> {
    fnv1a_64(bytes).to_le_bytes().to_vec()
}

pub(crate) fn integrity_digest(algorithm: IntegrityAlgorithm, bytes: &[u8]) -> Vec<u8> {
    match algorithm {
        IntegrityAlgorithm::Fnv => fnv1a_digest(bytes),
        IntegrityAlgorithm::Sha256 => sha256_digest(bytes),
    }
}

pub(crate) fn integrity_digest_matches(
    algorithm: IntegrityAlgorithm,
    bytes: &[u8],
    expected_digest: &[u8],
) -> bool {
    integrity_digest(algorithm, bytes) == expected_digest
}

fn fnv1a_64(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::{
        encrypted_gossip_fail_closed, frame_length_valid, integrity_digest,
        integrity_digest_matches, sha256_digest,
    };
    use crate::config::IntegrityAlgorithm;

    #[test]
    fn transport_guards_are_fail_closed() {
        assert!(frame_length_valid(8, 8));
        assert!(!frame_length_valid(9, 8));
        assert!(encrypted_gossip_fail_closed(true, false, true));
        assert!(!encrypted_gossip_fail_closed(true, true, true));
    }

    #[test]
    fn digest_matching_is_exact() {
        let sha_digest = sha256_digest(b"hello");
        assert!(integrity_digest_matches(
            IntegrityAlgorithm::Sha256,
            b"hello",
            &sha_digest,
        ));
        assert!(!integrity_digest_matches(
            IntegrityAlgorithm::Sha256,
            b"bye",
            &sha_digest,
        ));

        let fnv_digest = integrity_digest(IntegrityAlgorithm::Fnv, b"hello");
        assert!(integrity_digest_matches(
            IntegrityAlgorithm::Fnv,
            b"hello",
            &fnv_digest,
        ));
        assert!(!integrity_digest_matches(
            IntegrityAlgorithm::Fnv,
            b"bye",
            &fnv_digest,
        ));
    }
}
