use crate::identity::PeerId;
use crate::protocol::{EncryptedThreatEnvelopeMsg, ThreatDigestMsg};
use crate::swarm_epoch_core;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};

const THREAT_GOSSIP_INFO: &[u8] = b"zkf-swarm-threat-gossip-v1";
pub const THREAT_GOSSIP_PAYLOAD_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ThreatIntelPayload {
    #[serde(default)]
    pub digests: Vec<ThreatDigestMsg>,
    #[serde(default)]
    pub activation_level: Option<u8>,
    #[serde(default)]
    pub intelligence_root: Option<String>,
    #[serde(default)]
    pub local_pressure: Option<f64>,
    #[serde(default)]
    pub network_pressure: Option<f64>,
}

impl ThreatIntelPayload {
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
            && self.activation_level.is_none()
            && self.intelligence_root.is_none()
            && self.local_pressure.is_none()
            && self.network_pressure.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThreatEpochErrorKind {
    EncryptionNotNegotiated,
    MissingEpochMaterial,
    EpochOutsideGraceWindow,
    InvalidPublicKey,
    SerializeFailed,
    EncryptFailed,
    DecryptFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatEpochError {
    pub kind: ThreatEpochErrorKind,
    pub detail: String,
}

impl ThreatEpochError {
    fn new(kind: ThreatEpochErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for ThreatEpochError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for ThreatEpochError {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ThreatEpochAdvertisement {
    pub encrypted_threat_gossip_supported: bool,
    pub threat_epoch_id: Option<u64>,
    pub threat_epoch_public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerThreatChannel {
    pub remote_supports_encryption: bool,
    pub encrypted_negotiated: bool,
    remote_epoch_public_keys: BTreeMap<u64, [u8; 32]>,
}

impl PeerThreatChannel {
    pub fn update_from_advertisement(
        &mut self,
        local_support: bool,
        remote_support: bool,
        epoch_id: Option<u64>,
        public_key: Option<&[u8]>,
        now_unix_secs: u64,
    ) -> Result<(), ThreatEpochError> {
        self.remote_supports_encryption = remote_support;
        if !remote_support {
            self.encrypted_negotiated = false;
            self.remote_epoch_public_keys.clear();
            return Ok(());
        }

        let epoch_id = epoch_id.ok_or_else(|| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::MissingEpochMaterial,
                "remote peer advertised encrypted gossip without an epoch id",
            )
        })?;
        let public_key = public_key.ok_or_else(|| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::MissingEpochMaterial,
                "remote peer advertised encrypted gossip without an epoch public key",
            )
        })?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::InvalidPublicKey,
                "remote threat epoch public key must be exactly 32 bytes",
            )
        })?;

        self.remote_epoch_public_keys.insert(epoch_id, public_key);
        let current_epoch = current_unix_hour(now_unix_secs);
        let previous_epoch = current_epoch.saturating_sub(1);
        self.remote_epoch_public_keys.retain(|candidate_epoch, _| {
            *candidate_epoch == current_epoch || *candidate_epoch == previous_epoch
        });
        self.encrypted_negotiated = swarm_epoch_core::negotiate_encrypted_gossip(
            local_support,
            self.remote_supports_encryption,
            !self.remote_epoch_public_keys.is_empty(),
        );
        Ok(())
    }

    pub fn remote_public_key(&self, epoch_id: u64) -> Option<[u8; 32]> {
        self.remote_epoch_public_keys.get(&epoch_id).copied()
    }
}

#[derive(Debug, Clone)]
struct LocalThreatEpochKeys {
    secret_bytes: [u8; 32],
    public_key: [u8; 32],
}

impl LocalThreatEpochKeys {
    fn generate() -> Self {
        let mut secret_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_bytes);
        let secret = StaticSecret::from(secret_bytes);
        let public_key = PublicKey::from(&secret).to_bytes();
        Self {
            secret_bytes,
            public_key,
        }
    }

    fn secret(&self) -> StaticSecret {
        StaticSecret::from(self.secret_bytes)
    }
}

#[derive(Debug, Default)]
pub struct SwarmEpochManager {
    local_epochs: BTreeMap<u64, LocalThreatEpochKeys>,
}

impl SwarmEpochManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_advertisement(&mut self) -> ThreatEpochAdvertisement {
        self.advertisement_at(unix_time_now_secs())
    }

    pub fn advertisement_at(&mut self, now_unix_secs: u64) -> ThreatEpochAdvertisement {
        self.ensure_epoch_window(now_unix_secs);
        let epoch_id = current_unix_hour(now_unix_secs);
        let keys = self
            .local_epochs
            .get(&epoch_id)
            .expect("current threat epoch key must exist");
        ThreatEpochAdvertisement {
            encrypted_threat_gossip_supported: true,
            threat_epoch_id: Some(epoch_id),
            threat_epoch_public_key: Some(keys.public_key.to_vec()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn encrypt_for_peer(
        &mut self,
        now_unix_secs: u64,
        sender: &PeerId,
        receiver: &PeerId,
        message_kind: &str,
        sequence: u64,
        channel: &PeerThreatChannel,
        payload: &ThreatIntelPayload,
    ) -> Result<EncryptedThreatEnvelopeMsg, ThreatEpochError> {
        if !channel.encrypted_negotiated {
            return Err(ThreatEpochError::new(
                ThreatEpochErrorKind::EncryptionNotNegotiated,
                "encrypted threat gossip was requested before negotiation completed",
            ));
        }

        self.ensure_epoch_window(now_unix_secs);
        let epoch_id = self
            .best_shared_epoch_id(now_unix_secs, channel)
            .ok_or_else(|| {
                ThreatEpochError::new(
                    ThreatEpochErrorKind::MissingEpochMaterial,
                    "no shared current or previous threat gossip epoch exists for this peer",
                )
            })?;
        let local_keys = self
            .local_epochs
            .get(&epoch_id)
            .expect("shared threat epoch must resolve locally");
        let remote_public = channel.remote_public_key(epoch_id).ok_or_else(|| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::MissingEpochMaterial,
                format!("remote epoch public key missing for epoch {epoch_id}"),
            )
        })?;
        let key = derive_peer_key(
            &local_keys.secret(),
            &remote_public,
            epoch_id,
            sender,
            receiver,
        )?;
        let plaintext = postcard::to_allocvec(payload).map_err(|err| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::SerializeFailed,
                format!("failed to serialize encrypted threat payload: {err}"),
            )
        })?;
        let aad = associated_data(message_kind, sender, receiver, sequence, epoch_id);
        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new((&key).into());
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|err| {
                ThreatEpochError::new(
                    ThreatEpochErrorKind::EncryptFailed,
                    format!("failed to encrypt threat intelligence payload: {err}"),
                )
            })?;

        Ok(EncryptedThreatEnvelopeMsg {
            epoch_id,
            nonce: nonce_bytes,
            ciphertext,
            payload_version: THREAT_GOSSIP_PAYLOAD_VERSION,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decrypt_from_peer(
        &mut self,
        now_unix_secs: u64,
        sender: &PeerId,
        receiver: &PeerId,
        message_kind: &str,
        sequence: u64,
        channel: &PeerThreatChannel,
        envelope: &EncryptedThreatEnvelopeMsg,
    ) -> Result<ThreatIntelPayload, ThreatEpochError> {
        if !channel.encrypted_negotiated {
            return Err(ThreatEpochError::new(
                ThreatEpochErrorKind::EncryptionNotNegotiated,
                "received encrypted threat gossip before negotiation completed",
            ));
        }
        if envelope.payload_version != THREAT_GOSSIP_PAYLOAD_VERSION {
            return Err(ThreatEpochError::new(
                ThreatEpochErrorKind::DecryptFailed,
                format!(
                    "unsupported threat gossip payload version {}",
                    envelope.payload_version
                ),
            ));
        }
        if !is_epoch_allowed(now_unix_secs, envelope.epoch_id) {
            return Err(ThreatEpochError::new(
                ThreatEpochErrorKind::EpochOutsideGraceWindow,
                format!(
                    "received threat gossip epoch {} outside the current/previous grace window",
                    envelope.epoch_id
                ),
            ));
        }

        self.ensure_epoch_window(now_unix_secs);
        let local_keys = self.local_epochs.get(&envelope.epoch_id).ok_or_else(|| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::MissingEpochMaterial,
                format!(
                    "local threat epoch material missing for epoch {}",
                    envelope.epoch_id
                ),
            )
        })?;
        let remote_public = channel
            .remote_public_key(envelope.epoch_id)
            .ok_or_else(|| {
                ThreatEpochError::new(
                    ThreatEpochErrorKind::MissingEpochMaterial,
                    format!(
                        "remote threat epoch public key missing for epoch {}",
                        envelope.epoch_id
                    ),
                )
            })?;
        let key = derive_peer_key(
            &local_keys.secret(),
            &remote_public,
            envelope.epoch_id,
            sender,
            receiver,
        )?;
        let aad = associated_data(message_kind, sender, receiver, sequence, envelope.epoch_id);
        let cipher = ChaCha20Poly1305::new((&key).into());
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|err| {
                ThreatEpochError::new(
                    ThreatEpochErrorKind::DecryptFailed,
                    format!("failed to decrypt threat intelligence payload: {err}"),
                )
            })?;
        postcard::from_bytes(&plaintext).map_err(|err| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::SerializeFailed,
                format!("failed to decode encrypted threat intelligence payload: {err}"),
            )
        })
    }

    fn ensure_epoch_window(&mut self, now_unix_secs: u64) {
        let current_epoch = current_unix_hour(now_unix_secs);
        let previous_epoch = current_epoch.saturating_sub(1);
        self.local_epochs
            .entry(current_epoch)
            .or_insert_with(LocalThreatEpochKeys::generate);
        self.local_epochs
            .entry(previous_epoch)
            .or_insert_with(LocalThreatEpochKeys::generate);
        self.local_epochs.retain(|candidate_epoch, _| {
            *candidate_epoch == current_epoch || *candidate_epoch == previous_epoch
        });
    }

    fn best_shared_epoch_id(&self, now_unix_secs: u64, channel: &PeerThreatChannel) -> Option<u64> {
        let current_epoch = current_unix_hour(now_unix_secs);
        let previous_epoch = current_epoch.saturating_sub(1);
        [current_epoch, previous_epoch]
            .into_iter()
            .find(|candidate_epoch| {
                self.local_epochs.contains_key(candidate_epoch)
                    && channel.remote_public_key(*candidate_epoch).is_some()
            })
    }
}

pub fn has_plaintext_threat_surface(
    digests: &[ThreatDigestMsg],
    activation_level: Option<u8>,
    intelligence_root: Option<&str>,
    local_pressure: Option<f64>,
    network_pressure: Option<f64>,
) -> bool {
    swarm_epoch_core::has_plaintext_threat_surface(
        digests.len(),
        activation_level.is_some(),
        intelligence_root.is_some(),
        local_pressure.is_some(),
        network_pressure.is_some(),
    )
}

fn derive_peer_key(
    local_secret: &StaticSecret,
    remote_public: &[u8; 32],
    epoch_id: u64,
    sender: &PeerId,
    receiver: &PeerId,
) -> Result<[u8; 32], ThreatEpochError> {
    let remote_public = PublicKey::from(*remote_public);
    let shared_secret = local_secret.diffie_hellman(&remote_public);
    let salt = epoch_id.to_le_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes());
    let mut key = [0u8; 32];
    let mut info =
        Vec::with_capacity(THREAT_GOSSIP_INFO.len() + sender.0.len() + receiver.0.len() + 16);
    info.extend_from_slice(THREAT_GOSSIP_INFO);
    info.extend_from_slice(&epoch_id.to_le_bytes());
    info.extend_from_slice(sender.0.as_bytes());
    info.push(0);
    info.extend_from_slice(receiver.0.as_bytes());
    hkdf.expand(&info, &mut key).map_err(|_| {
        ThreatEpochError::new(
            ThreatEpochErrorKind::EncryptFailed,
            "failed to derive peer threat gossip key from HKDF",
        )
    })?;
    Ok(key)
}

fn associated_data(
    message_kind: &str,
    sender: &PeerId,
    receiver: &PeerId,
    sequence: u64,
    epoch_id: u64,
) -> Vec<u8> {
    swarm_epoch_core::associated_data(message_kind, sender, receiver, sequence, epoch_id)
}

fn current_unix_hour(now_unix_secs: u64) -> u64 {
    swarm_epoch_core::current_unix_hour(now_unix_secs)
}

fn is_epoch_allowed(now_unix_secs: u64, epoch_id: u64) -> bool {
    swarm_epoch_core::is_epoch_allowed(now_unix_secs, epoch_id)
}

fn unix_time_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> ThreatIntelPayload {
        ThreatIntelPayload {
            digests: vec![ThreatDigestMsg {
                source_peer: [7; 32],
                source_peer_id: Some("peer-a".to_string()),
                timestamp_unix_ms: 42,
                stage_key_hash: 9,
                stage_key: Some("prove".to_string()),
                severity: "high".to_string(),
                kind: "runtime-anomaly".to_string(),
                z_score: 3.5,
                observation_count: 4,
                signature: vec![1; 64],
                #[cfg(feature = "full")]
                signature_bundle: None,
                baseline_commitment: Some("baseline".to_string()),
                execution_fingerprint: Some("fp".to_string()),
                detail: Some("detail".to_string()),
            }],
            activation_level: Some(2),
            intelligence_root: Some("root".to_string()),
            local_pressure: Some(1.5),
            network_pressure: Some(2.5),
        }
    }

    fn negotiate_channels(
        now_unix_secs: u64,
        left: &mut SwarmEpochManager,
        right: &mut SwarmEpochManager,
    ) -> (PeerThreatChannel, PeerThreatChannel) {
        let left_adv = left.advertisement_at(now_unix_secs);
        let right_adv = right.advertisement_at(now_unix_secs);
        let mut left_channel = PeerThreatChannel::default();
        let mut right_channel = PeerThreatChannel::default();
        left_channel
            .update_from_advertisement(
                true,
                right_adv.encrypted_threat_gossip_supported,
                right_adv.threat_epoch_id,
                right_adv.threat_epoch_public_key.as_deref(),
                now_unix_secs,
            )
            .expect("right advert");
        right_channel
            .update_from_advertisement(
                true,
                left_adv.encrypted_threat_gossip_supported,
                left_adv.threat_epoch_id,
                left_adv.threat_epoch_public_key.as_deref(),
                now_unix_secs,
            )
            .expect("left advert");
        (left_channel, right_channel)
    }

    #[test]
    fn bilateral_negotiation_encrypts_and_decrypts() {
        let now = 7_200;
        let mut left = SwarmEpochManager::new();
        let mut right = SwarmEpochManager::new();
        let (left_channel, right_channel) = negotiate_channels(now, &mut left, &mut right);
        let sender = PeerId("peer-left".to_string());
        let receiver = PeerId("peer-right".to_string());
        let payload = sample_payload();
        let envelope = left
            .encrypt_for_peer(
                now,
                &sender,
                &receiver,
                "heartbeat",
                11,
                &left_channel,
                &payload,
            )
            .expect("encrypt");
        let decoded = right
            .decrypt_from_peer(
                now,
                &sender,
                &receiver,
                "heartbeat",
                11,
                &right_channel,
                &envelope,
            )
            .expect("decrypt");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn previous_epoch_is_accepted_within_grace_window() {
        let mut left = SwarmEpochManager::new();
        let mut right = SwarmEpochManager::new();
        let epoch_zero = 3_600;
        let epoch_one = 7_200;
        let (left_channel_epoch_zero, right_channel_epoch_zero) =
            negotiate_channels(epoch_zero, &mut left, &mut right);
        let sender = PeerId("peer-left".to_string());
        let receiver = PeerId("peer-right".to_string());
        let envelope = left
            .encrypt_for_peer(
                epoch_zero,
                &sender,
                &receiver,
                "heartbeat",
                19,
                &left_channel_epoch_zero,
                &sample_payload(),
            )
            .expect("encrypt previous epoch");

        let left_adv_epoch_one = left.advertisement_at(epoch_one);
        let right_adv_epoch_one = right.advertisement_at(epoch_one);
        let mut left_channel = left_channel_epoch_zero;
        let mut right_channel = right_channel_epoch_zero;
        left_channel
            .update_from_advertisement(
                true,
                right_adv_epoch_one.encrypted_threat_gossip_supported,
                right_adv_epoch_one.threat_epoch_id,
                right_adv_epoch_one.threat_epoch_public_key.as_deref(),
                epoch_one,
            )
            .expect("update right");
        right_channel
            .update_from_advertisement(
                true,
                left_adv_epoch_one.encrypted_threat_gossip_supported,
                left_adv_epoch_one.threat_epoch_id,
                left_adv_epoch_one.threat_epoch_public_key.as_deref(),
                epoch_one,
            )
            .expect("update left");

        assert!(
            right
                .decrypt_from_peer(
                    epoch_one,
                    &sender,
                    &receiver,
                    "heartbeat",
                    19,
                    &right_channel,
                    &envelope,
                )
                .is_ok()
        );
    }

    #[test]
    fn older_epochs_are_rejected() {
        let now = 10_800;
        let mut left = SwarmEpochManager::new();
        let mut right = SwarmEpochManager::new();
        let (left_channel, right_channel) = negotiate_channels(3_600, &mut left, &mut right);
        let sender = PeerId("peer-left".to_string());
        let receiver = PeerId("peer-right".to_string());
        let envelope = left
            .encrypt_for_peer(
                3_600,
                &sender,
                &receiver,
                "heartbeat",
                29,
                &left_channel,
                &sample_payload(),
            )
            .expect("encrypt");
        let err = right
            .decrypt_from_peer(
                now,
                &sender,
                &receiver,
                "heartbeat",
                29,
                &right_channel,
                &envelope,
            )
            .expect_err("older epochs must fail closed");
        assert_eq!(err.kind, ThreatEpochErrorKind::EpochOutsideGraceWindow);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let now = 7_200;
        let mut left = SwarmEpochManager::new();
        let mut right = SwarmEpochManager::new();
        let (left_channel, right_channel) = negotiate_channels(now, &mut left, &mut right);
        let sender = PeerId("peer-left".to_string());
        let receiver = PeerId("peer-right".to_string());
        let mut envelope = left
            .encrypt_for_peer(
                now,
                &sender,
                &receiver,
                "heartbeat",
                31,
                &left_channel,
                &sample_payload(),
            )
            .expect("encrypt");
        envelope.ciphertext[0] ^= 0x01;
        let err = right
            .decrypt_from_peer(
                now,
                &sender,
                &receiver,
                "heartbeat",
                31,
                &right_channel,
                &envelope,
            )
            .expect_err("tampered ciphertext must fail");
        assert_eq!(err.kind, ThreatEpochErrorKind::DecryptFailed);
    }

    #[test]
    fn wrong_peer_identity_is_rejected() {
        let now = 7_200;
        let mut left = SwarmEpochManager::new();
        let mut right = SwarmEpochManager::new();
        let (left_channel, right_channel) = negotiate_channels(now, &mut left, &mut right);
        let sender = PeerId("peer-left".to_string());
        let receiver = PeerId("peer-right".to_string());
        let envelope = left
            .encrypt_for_peer(
                now,
                &sender,
                &receiver,
                "heartbeat",
                37,
                &left_channel,
                &sample_payload(),
            )
            .expect("encrypt");
        let err = right
            .decrypt_from_peer(
                now,
                &PeerId("peer-impostor".to_string()),
                &receiver,
                "heartbeat",
                37,
                &right_channel,
                &envelope,
            )
            .expect_err("AAD mismatch must fail");
        assert_eq!(err.kind, ThreatEpochErrorKind::DecryptFailed);
    }
}
