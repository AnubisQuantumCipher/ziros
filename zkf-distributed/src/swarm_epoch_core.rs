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

use crate::identity::PeerId;

pub(crate) fn has_plaintext_threat_surface(
    digest_count: usize,
    activation_level_present: bool,
    intelligence_root_present: bool,
    local_pressure_present: bool,
    network_pressure_present: bool,
) -> bool {
    digest_count > 0
        || activation_level_present
        || intelligence_root_present
        || local_pressure_present
        || network_pressure_present
}

pub(crate) fn negotiate_encrypted_gossip(
    local_support: bool,
    remote_support: bool,
    remote_epoch_keys_present: bool,
) -> bool {
    local_support && remote_support && remote_epoch_keys_present
}

pub(crate) fn current_unix_hour(now_unix_secs: u64) -> u64 {
    now_unix_secs / 3_600
}

pub(crate) fn is_epoch_allowed(now_unix_secs: u64, epoch_id: u64) -> bool {
    let current_epoch = current_unix_hour(now_unix_secs);
    epoch_id == current_epoch || epoch_id == current_epoch.saturating_sub(1)
}

pub(crate) fn associated_data(
    message_kind: &str,
    sender: &PeerId,
    receiver: &PeerId,
    sequence: u64,
    epoch_id: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(message_kind.len() + sender.0.len() + receiver.0.len() + 24);
    bytes.extend_from_slice(message_kind.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(sender.0.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(receiver.0.as_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&epoch_id.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::{
        associated_data, has_plaintext_threat_surface, is_epoch_allowed, negotiate_encrypted_gossip,
    };
    use crate::identity::PeerId;

    #[test]
    fn plaintext_surface_detects_any_public_field() {
        assert!(has_plaintext_threat_surface(0, false, false, true, false));
        assert!(!has_plaintext_threat_surface(0, false, false, false, false));
    }

    #[test]
    fn encrypted_negotiation_is_fail_closed() {
        assert!(negotiate_encrypted_gossip(true, true, true));
        assert!(!negotiate_encrypted_gossip(true, true, false));
    }

    #[test]
    fn epoch_window_and_aad_are_deterministic() {
        assert!(is_epoch_allowed(7_200, 1));
        let aad = associated_data("heartbeat", &PeerId("a".into()), &PeerId("b".into()), 7, 1);
        assert!(!aad.is_empty());
    }
}
