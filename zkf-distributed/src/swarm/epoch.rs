use crate::identity::PeerId;
use crate::protocol::{EncryptedThreatEnvelopeMsg, ThreatDigestMsg};
use crate::swarm_epoch_core;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use libcrux_ml_kem::mlkem1024::{
    MlKem1024Ciphertext, MlKem1024PrivateKey, MlKem1024PublicKey, decapsulate as kem_decapsulate,
    encapsulate as kem_encapsulate, generate_key_pair as kem_generate,
};
use libcrux_ml_kem::{
    KEY_GENERATION_SEED_SIZE as ML_KEM_KEY_GENERATION_SEED_SIZE,
    SHARED_SECRET_SIZE as ML_KEM_SHARED_SECRET_SIZE,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha384;
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};
use zkf_keymanager::{MlKem1024DecapsulationKey, X25519Secret};

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
    pub threat_epoch_ml_kem_public_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteThreatEpochKeys {
    x25519_public_key: [u8; 32],
    ml_kem_public_key: Vec<u8>,
}

impl RemoteThreatEpochKeys {
    fn ml_kem_public_key(&self) -> Result<MlKem1024PublicKey, ThreatEpochError> {
        MlKem1024PublicKey::try_from(self.ml_kem_public_key.as_slice()).map_err(|_| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::InvalidPublicKey,
                "remote threat epoch ML-KEM public key must be exactly 1568 bytes",
            )
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerThreatChannel {
    pub remote_supports_encryption: bool,
    pub encrypted_negotiated: bool,
    remote_epoch_keys: BTreeMap<u64, RemoteThreatEpochKeys>,
}

impl PeerThreatChannel {
    pub fn update_from_advertisement(
        &mut self,
        local_support: bool,
        remote_support: bool,
        epoch_id: Option<u64>,
        public_key: Option<&[u8]>,
        ml_kem_public_key: Option<&[u8]>,
        now_unix_secs: u64,
    ) -> Result<(), ThreatEpochError> {
        self.remote_supports_encryption = remote_support;
        if !remote_support {
            self.encrypted_negotiated = false;
            self.remote_epoch_keys.clear();
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
        let ml_kem_public_key = ml_kem_public_key.ok_or_else(|| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::MissingEpochMaterial,
                "remote peer advertised encrypted gossip without an ML-KEM public key",
            )
        })?;
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::InvalidPublicKey,
                "remote threat epoch public key must be exactly 32 bytes",
            )
        })?;
        MlKem1024PublicKey::try_from(ml_kem_public_key).map_err(|_| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::InvalidPublicKey,
                "remote threat epoch ML-KEM public key must be exactly 1568 bytes",
            )
        })?;

        self.remote_epoch_keys.insert(
            epoch_id,
            RemoteThreatEpochKeys {
                x25519_public_key: public_key,
                ml_kem_public_key: ml_kem_public_key.to_vec(),
            },
        );
        let current_epoch = current_unix_hour(now_unix_secs);
        let previous_epoch = current_epoch.saturating_sub(1);
        self.remote_epoch_keys.retain(|candidate_epoch, _| {
            *candidate_epoch == current_epoch || *candidate_epoch == previous_epoch
        });
        self.encrypted_negotiated = swarm_epoch_core::negotiate_encrypted_gossip(
            local_support,
            self.remote_supports_encryption,
            !self.remote_epoch_keys.is_empty(),
        );
        Ok(())
    }

    fn remote_epoch_keys(&self, epoch_id: u64) -> Option<RemoteThreatEpochKeys> {
        self.remote_epoch_keys.get(&epoch_id).cloned()
    }
}

#[derive(Debug, Clone)]
struct LocalThreatEpochKeys {
    x25519_secret: X25519Secret,
    x25519_public_key: [u8; 32],
    ml_kem_decapsulation_key: MlKem1024DecapsulationKey,
    ml_kem_encapsulation_key: Vec<u8>,
}

impl LocalThreatEpochKeys {
    fn generate() -> Self {
        let x25519_secret_bytes = secure_random_array::<32>();
        let x25519_secret = X25519Secret(x25519_secret_bytes);
        let x25519_secret_key = StaticSecret::from(x25519_secret.0);
        let x25519_public_key = PublicKey::from(&x25519_secret_key).to_bytes();
        let ml_kem_key_pair =
            kem_generate(secure_random_array::<ML_KEM_KEY_GENERATION_SEED_SIZE>());
        Self {
            x25519_secret,
            x25519_public_key,
            ml_kem_decapsulation_key: MlKem1024DecapsulationKey(ml_kem_key_pair.sk().to_vec()),
            ml_kem_encapsulation_key: ml_kem_key_pair.pk().to_vec(),
        }
    }

    fn x25519_secret(&self) -> StaticSecret {
        StaticSecret::from(self.x25519_secret.0)
    }

    fn ml_kem_private_key(&self) -> Result<MlKem1024PrivateKey, ThreatEpochError> {
        MlKem1024PrivateKey::try_from(self.ml_kem_decapsulation_key.0.as_slice()).map_err(|_| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::MissingEpochMaterial,
                "local threat epoch ML-KEM private key must be exactly 3168 bytes",
            )
        })
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
            threat_epoch_public_key: Some(keys.x25519_public_key.to_vec()),
            threat_epoch_ml_kem_public_key: Some(keys.ml_kem_encapsulation_key.clone()),
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
        let remote_epoch_keys = channel.remote_epoch_keys(epoch_id).ok_or_else(|| {
            ThreatEpochError::new(
                ThreatEpochErrorKind::MissingEpochMaterial,
                format!("remote epoch public key missing for epoch {epoch_id}"),
            )
        })?;
        let (key, ml_kem_ciphertext) =
            derive_sender_peer_key(local_keys, &remote_epoch_keys, epoch_id, sender, receiver)?;
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
            ml_kem_ciphertext,
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
        let remote_epoch_keys = channel
            .remote_epoch_keys(envelope.epoch_id)
            .ok_or_else(|| {
                ThreatEpochError::new(
                    ThreatEpochErrorKind::MissingEpochMaterial,
                    format!(
                        "remote threat epoch public key missing for epoch {}",
                        envelope.epoch_id
                    ),
                )
            })?;
        let key = derive_receiver_peer_key(
            local_keys,
            &remote_epoch_keys,
            &envelope.ml_kem_ciphertext,
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
                    && channel.remote_epoch_keys(*candidate_epoch).is_some()
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

fn derive_sender_peer_key(
    local_keys: &LocalThreatEpochKeys,
    remote_epoch_keys: &RemoteThreatEpochKeys,
    epoch_id: u64,
    sender: &PeerId,
    receiver: &PeerId,
) -> Result<([u8; 32], Vec<u8>), ThreatEpochError> {
    let remote_public = PublicKey::from(remote_epoch_keys.x25519_public_key);
    let shared_secret_x25519 = local_keys.x25519_secret().diffie_hellman(&remote_public);
    let remote_ml_kem_public_key = remote_epoch_keys.ml_kem_public_key()?;
    let (ml_kem_ciphertext, shared_secret_kem) = kem_encapsulate(
        &remote_ml_kem_public_key,
        secure_random_array::<ML_KEM_SHARED_SECRET_SIZE>(),
    );
    let key = derive_combined_peer_key(
        shared_secret_x25519.as_bytes(),
        shared_secret_kem.as_slice(),
        epoch_id,
        sender,
        receiver,
    )?;
    Ok((key, ml_kem_ciphertext.as_slice().to_vec()))
}

fn derive_receiver_peer_key(
    local_keys: &LocalThreatEpochKeys,
    remote_epoch_keys: &RemoteThreatEpochKeys,
    ml_kem_ciphertext: &[u8],
    epoch_id: u64,
    sender: &PeerId,
    receiver: &PeerId,
) -> Result<[u8; 32], ThreatEpochError> {
    let remote_public = PublicKey::from(remote_epoch_keys.x25519_public_key);
    let shared_secret_x25519 = local_keys.x25519_secret().diffie_hellman(&remote_public);
    let local_ml_kem_private_key = local_keys.ml_kem_private_key()?;
    let ml_kem_ciphertext = MlKem1024Ciphertext::try_from(ml_kem_ciphertext).map_err(|_| {
        ThreatEpochError::new(
            ThreatEpochErrorKind::DecryptFailed,
            "received ML-KEM ciphertext must be exactly 1568 bytes",
        )
    })?;
    let shared_secret_kem = kem_decapsulate(&local_ml_kem_private_key, &ml_kem_ciphertext);
    derive_combined_peer_key(
        shared_secret_x25519.as_bytes(),
        shared_secret_kem.as_slice(),
        epoch_id,
        sender,
        receiver,
    )
}

fn derive_combined_peer_key(
    shared_secret_x25519: &[u8],
    shared_secret_kem: &[u8],
    epoch_id: u64,
    sender: &PeerId,
    receiver: &PeerId,
) -> Result<[u8; 32], ThreatEpochError> {
    let mut combined_secret = [0u8; 32 + ML_KEM_SHARED_SECRET_SIZE];
    combined_secret[..32].copy_from_slice(shared_secret_x25519);
    combined_secret[32..].copy_from_slice(shared_secret_kem);
    let salt = epoch_id.to_le_bytes();
    let hkdf = Hkdf::<Sha384>::new(Some(&salt), &combined_secret);
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

fn secure_random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
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
                right_adv.threat_epoch_ml_kem_public_key.as_deref(),
                now_unix_secs,
            )
            .expect("right advert");
        right_channel
            .update_from_advertisement(
                true,
                left_adv.encrypted_threat_gossip_supported,
                left_adv.threat_epoch_id,
                left_adv.threat_epoch_public_key.as_deref(),
                left_adv.threat_epoch_ml_kem_public_key.as_deref(),
                now_unix_secs,
            )
            .expect("left advert");
        (left_channel, right_channel)
    }

    #[test]
    fn hybrid_ml_kem_exchange_derives_matching_keys_in_both_directions() {
        let epoch_id = 9;
        let left_peer = PeerId("peer-left".to_string());
        let right_peer = PeerId("peer-right".to_string());
        let left_keys = LocalThreatEpochKeys::generate();
        let right_keys = LocalThreatEpochKeys::generate();
        let left_remote = RemoteThreatEpochKeys {
            x25519_public_key: right_keys.x25519_public_key,
            ml_kem_public_key: right_keys.ml_kem_encapsulation_key.clone(),
        };
        let right_remote = RemoteThreatEpochKeys {
            x25519_public_key: left_keys.x25519_public_key,
            ml_kem_public_key: left_keys.ml_kem_encapsulation_key.clone(),
        };

        let (left_send_key, left_ciphertext) =
            derive_sender_peer_key(&left_keys, &left_remote, epoch_id, &left_peer, &right_peer)
                .expect("left sender key");
        let right_receive_key = derive_receiver_peer_key(
            &right_keys,
            &right_remote,
            &left_ciphertext,
            epoch_id,
            &left_peer,
            &right_peer,
        )
        .expect("right receiver key");
        assert_eq!(left_send_key, right_receive_key);

        let (right_send_key, right_ciphertext) = derive_sender_peer_key(
            &right_keys,
            &right_remote,
            epoch_id,
            &right_peer,
            &left_peer,
        )
        .expect("right sender key");
        let left_receive_key = derive_receiver_peer_key(
            &left_keys,
            &left_remote,
            &right_ciphertext,
            epoch_id,
            &right_peer,
            &left_peer,
        )
        .expect("left receiver key");
        assert_eq!(right_send_key, left_receive_key);
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
                right_adv_epoch_one
                    .threat_epoch_ml_kem_public_key
                    .as_deref(),
                epoch_one,
            )
            .expect("update right");
        right_channel
            .update_from_advertisement(
                true,
                left_adv_epoch_one.encrypted_threat_gossip_supported,
                left_adv_epoch_one.threat_epoch_id,
                left_adv_epoch_one.threat_epoch_public_key.as_deref(),
                left_adv_epoch_one.threat_epoch_ml_kem_public_key.as_deref(),
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
