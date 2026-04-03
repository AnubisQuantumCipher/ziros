use crate::{ApprovalMethod, ApprovalReviewPayload, SubmissionGrant, WalletError, WalletNetwork};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use libcrux_ml_dsa::ml_dsa_87::{
    MLDSA87Signature, MLDSA87SigningKey, MLDSA87VerificationKey, generate_key_pair,
    sign as mldsa_sign, verify as mldsa_verify,
};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
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
use sha2::{Digest, Sha256, Sha384};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use x25519_dalek::{PublicKey, StaticSecret};
use zkf_cloudfs::CloudFS;

const MESSAGING_SCHEMA: &str = "ziros-midnight-wallet-messaging-v1";
const MESSAGE_PAYLOAD_VERSION: u32 = 1;
const MESSAGE_SIGNATURE_CONTEXT: &[u8] = b"ziros-midnight-wallet-message-v1";
const ROOT_INFO: &[u8] = b"ziros-midnight-wallet-messaging-v1";
const STORAGE_INFO: &[u8] = b"ziros-midnight-wallet-messaging-storage-v1";
const IDENTITY_INFO: &[u8] = b"ziros-midnight-wallet-messaging-identity-v1";
const EPOCH_INFO: &[u8] = b"ziros-midnight-wallet-messaging-epoch-v1";
const MAX_CHANNEL_ID_BYTES: usize = 128;
const MAX_TEXT_MESSAGE_BYTES: usize = 512;
const MAX_TRANSFER_RECEIPT_TEXT_BYTES: usize = 256;
const MAX_CREDENTIAL_SUMMARY_BYTES: usize = 256;
const MAX_TX_HASH_BYTES: usize = 128;
const MAX_MAILBOX_CIPHERTEXT_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WalletPeerId(pub String);

impl WalletPeerId {
    pub fn parse(raw: &str) -> Result<Self, WalletError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(WalletError::BridgePolicyViolation(
                "wallet messaging peer id must not be empty".to_string(),
            ));
        }
        if !trimmed.is_ascii() {
            return Err(WalletError::BridgePolicyViolation(
                "wallet messaging peer id must be ASCII".to_string(),
            ));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl std::fmt::Display for WalletPeerId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletMessageKind {
    Text,
    TransferReceipt,
    CredentialRequest,
    CredentialResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletMessageDirection {
    Inbound,
    Outbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WalletMessageStatus {
    Pending,
    Posted,
    Failed,
    Received,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletTransferReceipt {
    pub tx_hash: String,
    pub night_total_raw: String,
    pub dust_total_raw: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCredentialRequest {
    pub request_id: String,
    pub claim_summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletCredentialResponse {
    pub request_id: String,
    pub disclosure_summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_reference: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum WalletMessageContent {
    Text { text: String },
    TransferReceipt(WalletTransferReceipt),
    CredentialRequest(WalletCredentialRequest),
    CredentialResponse(WalletCredentialResponse),
}

impl WalletMessageContent {
    pub fn kind(&self) -> WalletMessageKind {
        match self {
            Self::Text { .. } => WalletMessageKind::Text,
            Self::TransferReceipt(_) => WalletMessageKind::TransferReceipt,
            Self::CredentialRequest(_) => WalletMessageKind::CredentialRequest,
            Self::CredentialResponse(_) => WalletMessageKind::CredentialResponse,
        }
    }

    pub fn preview(&self) -> String {
        match self {
            Self::Text { text } => text.clone(),
            Self::TransferReceipt(receipt) => receipt.summary.clone(),
            Self::CredentialRequest(request) => request.claim_summary.clone(),
            Self::CredentialResponse(response) => response.disclosure_summary.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum WireMessageContent {
    Text { text: String },
    TransferReceipt {
        tx_hash: String,
        night_total_raw: String,
        dust_total_raw: String,
        summary: String,
    },
    CredentialRequest {
        request_id: String,
        claim_summary: String,
    },
    CredentialResponse {
        request_id: String,
        disclosure_summary: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        proof_reference: Option<String>,
    },
}

impl From<&WalletMessageContent> for WireMessageContent {
    fn from(value: &WalletMessageContent) -> Self {
        match value {
            WalletMessageContent::Text { text } => Self::Text { text: text.clone() },
            WalletMessageContent::TransferReceipt(receipt) => Self::TransferReceipt {
                tx_hash: receipt.tx_hash.clone(),
                night_total_raw: receipt.night_total_raw.clone(),
                dust_total_raw: receipt.dust_total_raw.clone(),
                summary: receipt.summary.clone(),
            },
            WalletMessageContent::CredentialRequest(request) => Self::CredentialRequest {
                request_id: request.request_id.clone(),
                claim_summary: request.claim_summary.clone(),
            },
            WalletMessageContent::CredentialResponse(response) => Self::CredentialResponse {
                request_id: response.request_id.clone(),
                disclosure_summary: response.disclosure_summary.clone(),
                proof_reference: response.proof_reference.clone(),
            },
        }
    }
}

impl From<WireMessageContent> for WalletMessageContent {
    fn from(value: WireMessageContent) -> Self {
        match value {
            WireMessageContent::Text { text } => Self::Text { text },
            WireMessageContent::TransferReceipt {
                tx_hash,
                night_total_raw,
                dust_total_raw,
                summary,
            } => Self::TransferReceipt(WalletTransferReceipt {
                tx_hash,
                night_total_raw,
                dust_total_raw,
                summary,
            }),
            WireMessageContent::CredentialRequest {
                request_id,
                claim_summary,
            } => Self::CredentialRequest(WalletCredentialRequest {
                request_id,
                claim_summary,
            }),
            WireMessageContent::CredentialResponse {
                request_id,
                disclosure_summary,
                proof_reference,
            } => Self::CredentialResponse(WalletCredentialResponse {
                request_id,
                disclosure_summary,
                proof_reference,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletMessage {
    pub message_id: String,
    pub channel_id: String,
    pub peer_id: WalletPeerId,
    pub direction: WalletMessageDirection,
    pub status: WalletMessageStatus,
    pub kind: WalletMessageKind,
    pub sequence: u64,
    pub sent_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
    pub dust_cost_raw: String,
    pub envelope_hash: String,
    pub content: WalletMessageContent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletPeerAdvertisement {
    pub epoch_id: u64,
    pub x25519_public_key_hex: String,
    pub ml_kem_public_key_hex: String,
    pub identity_public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletChannelInvite {
    pub peer_id: WalletPeerId,
    pub channel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub advertisement: WalletPeerAdvertisement,
    pub invitation_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletChannelOpenRequest {
    pub peer_id: WalletPeerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub remote_invite: WalletChannelInvite,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConversationView {
    pub peer_id: WalletPeerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub channel_id: String,
    pub unread_count: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_preview: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_message_at: Option<DateTime<Utc>>,
    pub dust_spent_raw: String,
    pub status: ChannelStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelStatus {
    pub peer_id: WalletPeerId,
    pub channel_id: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_invite: Option<WalletChannelInvite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_invite: Option<WalletChannelInvite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opened_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rotated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelOpenReviewPayload {
    pub origin: String,
    pub network: WalletNetwork,
    pub method: ApprovalMethod,
    pub tx_digest: String,
    pub peer_id: WalletPeerId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub human_summary: String,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageSendReviewPayload {
    pub origin: String,
    pub network: WalletNetwork,
    pub method: ApprovalMethod,
    pub tx_digest: String,
    pub peer_id: WalletPeerId,
    pub channel_id: String,
    pub message_kind: WalletMessageKind,
    pub dust_cost_raw: String,
    pub message_preview: String,
    pub human_summary: String,
    #[serde(default)]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxEnvelope {
    pub channel_id: String,
    pub sender_peer_id: WalletPeerId,
    pub receiver_peer_id: WalletPeerId,
    pub message_kind: WalletMessageKind,
    pub sequence: u64,
    pub epoch_id: u64,
    pub sender_advertisement: WalletPeerAdvertisement,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub ml_kem_ciphertext_hex: String,
    pub payload_version: u32,
    pub sender_signature_hex: String,
    pub envelope_hash: String,
    pub posted_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedMessage {
    pub message: WalletMessage,
    pub envelope: MailboxEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_grant: Option<SubmissionGrant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MessagingTransportMode {
    #[default]
    Unavailable,
    HelperAdapter,
    DisabledOnIos,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MessagingTransportStatus {
    pub mode: MessagingTransportMode,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_contract_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_healthy_probe_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_poll_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observed_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MessagingServiceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_contract_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_manifest_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MessagingTransportUpdate {
    pub mode: MessagingTransportMode,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_contract_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_healthy_probe_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_poll_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observed_cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxPostSuccess {
    pub envelope_hash: String,
    pub tx_hash: String,
    pub posted_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailboxPostFailure {
    pub envelope_hash: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EncryptedBlob {
    schema: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChannelRecord {
    peer_id: WalletPeerId,
    display_name: Option<String>,
    channel_id: String,
    state: String,
    reason: Option<String>,
    unread_count: u32,
    last_message_preview: Option<String>,
    last_message_at: Option<DateTime<Utc>>,
    dust_spent_raw: String,
    opened_at: Option<DateTime<Utc>>,
    last_rotated_at: Option<DateTime<Utc>>,
    local_invite: Option<WalletChannelInvite>,
    remote_invite: Option<WalletChannelInvite>,
}

impl ChannelRecord {
    fn into_view(self) -> ConversationView {
        ConversationView {
            peer_id: self.peer_id.clone(),
            display_name: self.display_name,
            channel_id: self.channel_id.clone(),
            unread_count: self.unread_count,
            last_message_preview: self.last_message_preview,
            last_message_at: self.last_message_at,
            dust_spent_raw: self.dust_spent_raw,
            status: ChannelStatus {
                peer_id: self.peer_id,
                channel_id: self.channel_id,
                state: self.state,
                reason: self.reason,
                local_invite: self.local_invite,
                remote_invite: self.remote_invite,
                opened_at: self.opened_at,
                last_rotated_at: self.last_rotated_at,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MessagingIndex {
    schema: String,
    updated_at: DateTime<Utc>,
    #[serde(default)]
    conversations: BTreeMap<String, ChannelRecord>,
    #[serde(default)]
    seen_envelope_keys: BTreeSet<String>,
    transport_status: MessagingTransportStatus,
}

impl MessagingIndex {
    fn new(now: DateTime<Utc>) -> Self {
        Self {
            schema: MESSAGING_SCHEMA.to_string(),
            updated_at: now,
            conversations: BTreeMap::new(),
            seen_envelope_keys: BTreeSet::new(),
            transport_status: MessagingTransportStatus::default(),
        }
    }
}

#[derive(Debug, Clone)]
enum PreparedMessagingAction {
    OpenChannel { request: WalletChannelOpenRequest },
    SendMessage {
        peer_id: WalletPeerId,
        channel_id: String,
        content: WalletMessageContent,
        dust_cost_raw: String,
    },
}

#[derive(Debug, Clone)]
pub struct MessagingState {
    network: WalletNetwork,
    cloudfs: CloudFS,
    index: MessagingIndex,
    prepared: HashMap<String, PreparedMessagingAction>,
    transport_config: MessagingServiceConfig,
}

impl MessagingState {
    pub fn new(
        network: WalletNetwork,
        cloudfs: CloudFS,
        now: DateTime<Utc>,
    ) -> Result<Self, WalletError> {
        let index = cloudfs
            .read_json::<MessagingIndex>(&index_path(network))
            .map_err(WalletError::Storage)?
            .unwrap_or_else(|| MessagingIndex::new(now));
        Ok(Self {
            network,
            cloudfs,
            index,
            prepared: HashMap::new(),
            transport_config: MessagingServiceConfig::default(),
        })
    }

    pub fn clear_volatile(&mut self) {
        self.prepared.clear();
    }

    pub fn configure_transport(&mut self, config: MessagingServiceConfig) {
        self.transport_config = config.clone();
        self.index.transport_status.mailbox_contract_address = config.mailbox_contract_address.clone();
        self.index.transport_status.available = false;
        self.index.transport_status.last_healthy_probe_at = None;
        self.index.transport_status.last_observed_cursor = None;
        self.index.transport_status.mode = match (
            self.transport_config.mailbox_contract_address.as_ref(),
            self.transport_config.mailbox_manifest_path.as_ref(),
        ) {
            (None, _) | (Some(_), None) => MessagingTransportMode::Unavailable,
            (Some(_), Some(_)) if cfg!(target_os = "ios") => MessagingTransportMode::DisabledOnIos,
            (Some(_), Some(_)) => MessagingTransportMode::HelperAdapter,
        };
        self.index.transport_status.reason = Some(match self.index.transport_status.mode {
            MessagingTransportMode::Unavailable => match (
                self.transport_config.mailbox_contract_address.as_ref(),
                self.transport_config.mailbox_manifest_path.as_ref(),
            ) {
                (None, _) => {
                    "Messaging mailbox transport is unavailable until a Compact mailbox contract address is configured.".to_string()
                }
                (Some(_), None) => {
                    "Messaging mailbox transport is unavailable until a mailbox deployment manifest is configured.".to_string()
                }
                _ => "Messaging mailbox transport is unavailable.".to_string(),
            },
            MessagingTransportMode::DisabledOnIos => {
                "Midnight mailbox transport is macOS-only in this tranche. iPhone keeps Messages visible and synced but read-only until a mobile-safe transport exists.".to_string()
            }
            MessagingTransportMode::HelperAdapter => {
                "Messaging mailbox transport is configured and waiting for the macOS helper adapter probe.".to_string()
            }
        });
    }

    pub fn transport_status(&self) -> MessagingTransportStatus {
        self.index.transport_status.clone()
    }

    pub fn update_transport_status(
        &mut self,
        update: MessagingTransportUpdate,
    ) -> Result<MessagingTransportStatus, WalletError> {
        self.index.transport_status.mode = update.mode;
        self.index.transport_status.available = update.available;
        if update.mailbox_contract_address.is_some() {
            self.index.transport_status.mailbox_contract_address = update.mailbox_contract_address;
        }
        if update.last_healthy_probe_at.is_some() {
            self.index.transport_status.last_healthy_probe_at = update.last_healthy_probe_at;
        }
        if update.last_poll_at.is_some() {
            self.index.transport_status.last_poll_at = update.last_poll_at;
        }
        if update.last_observed_cursor.is_some() {
            self.index.transport_status.last_observed_cursor = update.last_observed_cursor;
        }
        self.index.transport_status.reason = update.reason;
        self.persist()?;
        Ok(self.transport_status())
    }

    pub fn list_conversations(&self) -> Vec<ConversationView> {
        let mut conversations: Vec<_> = self
            .index
            .conversations
            .values()
            .cloned()
            .map(ChannelRecord::into_view)
            .collect();
        conversations.sort_by(|left, right| right.last_message_at.cmp(&left.last_message_at));
        conversations
    }

    pub fn channel_status(&self, peer_id: &WalletPeerId) -> Result<ChannelStatus, WalletError> {
        self.index
            .conversations
            .get(peer_id.as_str())
            .cloned()
            .map(ChannelRecord::into_view)
            .map(|view| view.status)
            .ok_or_else(|| {
                WalletError::BridgePolicyViolation(format!(
                    "no messaging channel exists for peer {}",
                    peer_id
                ))
            })
    }

    pub fn conversation(
        &self,
        messaging_root: &[u8],
        peer_id: &WalletPeerId,
    ) -> Result<Vec<WalletMessage>, WalletError> {
        let path = conversation_path(self.network, peer_id);
        let Some(blob) = self
            .cloudfs
            .read_json::<EncryptedBlob>(&path)
            .map_err(WalletError::Storage)?
        else {
            return Ok(Vec::new());
        };
        decrypt_messages(messaging_root, &blob)
    }

    pub fn close_channel(&mut self, peer_id: &WalletPeerId) -> Result<ChannelStatus, WalletError> {
        let record = self.index.conversations.get_mut(peer_id.as_str()).ok_or_else(|| {
            WalletError::BridgePolicyViolation(format!(
                "no messaging channel exists for peer {}",
                peer_id
            ))
        })?;
        record.state = "closed".to_string();
        record.reason = Some("channel closed locally".to_string());
        self.persist()?;
        self.channel_status(peer_id)
    }

    pub fn prepare_open_channel(
        &mut self,
        request: WalletChannelOpenRequest,
    ) -> Result<ApprovalReviewPayload, WalletError> {
        validate_open_channel_request(&request)?;
        let prepared_id = random_token();
        let peer_id = request.peer_id.clone();
        let display_name = request.display_name.clone();
        self.prepared.insert(
            prepared_id.clone(),
            PreparedMessagingAction::OpenChannel { request },
        );
        Ok(ApprovalReviewPayload::channel_open(ChannelOpenReviewPayload {
            origin: "native://wallet".to_string(),
            network: self.network,
            method: ApprovalMethod::OpenMessagingChannel,
            tx_digest: prepared_id,
            peer_id: peer_id.clone(),
            display_name,
            human_summary: format!(
                "Open an encrypted Midnight messaging channel with {peer_id}."
            ),
            warnings: vec![
                "Opening a channel activates wallet-derived messaging keys only after device biometrics succeed.".to_string(),
                "Mailbox posting still requires a configured mailbox contract plus spendable tDUST on the active wallet.".to_string(),
            ],
        }))
    }

    pub fn commit_open_channel(
        &mut self,
        messaging_root: &[u8],
        review_id: &str,
    ) -> Result<ConversationView, WalletError> {
        let prepared = self.prepared.remove(review_id).ok_or_else(|| {
            WalletError::BridgePolicyViolation("prepared messaging approval not found".to_string())
        })?;
        let PreparedMessagingAction::OpenChannel { request } = prepared else {
            return Err(WalletError::BridgePolicyViolation(
                "approval token was not prepared for channel opening".to_string(),
            ));
        };

        let now = Utc::now();
        let local_invite = self.build_local_invite(
            messaging_root,
            request.remote_invite.channel_id.as_str(),
            request.peer_id.clone(),
            request.display_name.clone(),
            now,
        )?;
        self.index.conversations.insert(
            request.peer_id.0.clone(),
            ChannelRecord {
                peer_id: request.peer_id.clone(),
                display_name: request.display_name,
                channel_id: request.remote_invite.channel_id.clone(),
                state: "open".to_string(),
                reason: None,
                unread_count: 0,
                last_message_preview: None,
                last_message_at: None,
                dust_spent_raw: "0".to_string(),
                opened_at: Some(now),
                last_rotated_at: Some(now),
                local_invite: Some(local_invite),
                remote_invite: Some(request.remote_invite),
            },
        );
        self.persist()?;
        self.list_conversations()
            .into_iter()
            .find(|view| view.peer_id == request.peer_id)
            .ok_or_else(|| {
                WalletError::BridgePolicyViolation(
                    "failed to materialize newly opened messaging channel".to_string(),
                )
            })
    }

    pub fn prepare_text(
        &mut self,
        peer_id: WalletPeerId,
        text: String,
    ) -> Result<ApprovalReviewPayload, WalletError> {
        self.prepare_message(peer_id, WalletMessageContent::Text { text })
    }

    pub fn prepare_transfer_receipt(
        &mut self,
        peer_id: WalletPeerId,
        receipt: WalletTransferReceipt,
    ) -> Result<ApprovalReviewPayload, WalletError> {
        self.prepare_message(peer_id, WalletMessageContent::TransferReceipt(receipt))
    }

    pub fn prepare_credential_request(
        &mut self,
        peer_id: WalletPeerId,
        request: WalletCredentialRequest,
    ) -> Result<ApprovalReviewPayload, WalletError> {
        self.prepare_message(peer_id, WalletMessageContent::CredentialRequest(request))
    }

    pub fn prepare_credential_response(
        &mut self,
        peer_id: WalletPeerId,
        response: WalletCredentialResponse,
    ) -> Result<ApprovalReviewPayload, WalletError> {
        self.prepare_message(peer_id, WalletMessageContent::CredentialResponse(response))
    }

    pub fn commit_send_message(
        &mut self,
        messaging_root: &[u8],
        review_id: &str,
    ) -> Result<PreparedMessage, WalletError> {
        if !self.index.transport_status.available {
            return Err(WalletError::BridgePolicyViolation(
                self.index
                    .transport_status
                    .reason
                    .clone()
                    .unwrap_or_else(|| "messaging transport is unavailable".to_string()),
            ));
        }

        let prepared = self.prepared.remove(review_id).ok_or_else(|| {
            WalletError::BridgePolicyViolation("prepared messaging approval not found".to_string())
        })?;
        let PreparedMessagingAction::SendMessage {
            peer_id,
            channel_id,
            content,
            dust_cost_raw,
        } = prepared
        else {
            return Err(WalletError::BridgePolicyViolation(
                "approval token was not prepared for message send".to_string(),
            ));
        };
        let record = self.index.conversations.get(peer_id.as_str()).cloned().ok_or_else(|| {
            WalletError::BridgePolicyViolation(format!(
                "no messaging channel exists for peer {}",
                peer_id
            ))
        })?;
        let remote_invite = record.remote_invite.clone().ok_or_else(|| {
            WalletError::BridgePolicyViolation(
                "channel is missing the peer advertisement required for encryption".to_string(),
            )
        })?;

        let mut messages = self.conversation(messaging_root, &peer_id)?;
        let sequence = messages.last().map(|message| message.sequence + 1).unwrap_or(1);
        let now = Utc::now();
        let envelope = self.encrypt_envelope(
            messaging_root,
            channel_id.as_str(),
            &peer_id,
            remote_invite.advertisement.clone(),
            content.clone(),
            sequence,
            now,
        )?;
        let message = WalletMessage {
            message_id: random_token(),
            channel_id: channel_id.clone(),
            peer_id: peer_id.clone(),
            direction: WalletMessageDirection::Outbound,
            status: WalletMessageStatus::Pending,
            kind: content.kind(),
            sequence,
            sent_at: now,
            received_at: None,
            dust_cost_raw: dust_cost_raw.clone(),
            envelope_hash: envelope.envelope_hash.clone(),
            content: content.clone(),
        };
        messages.push(message.clone());
        self.write_conversation(messaging_root, &peer_id, &messages)?;
        if let Some(channel) = self.index.conversations.get_mut(peer_id.as_str()) {
            channel.last_message_preview = Some(content.preview());
            channel.last_message_at = Some(now);
            channel.last_rotated_at = Some(now);
            channel.dust_spent_raw =
                add_raw_amounts(channel.dust_spent_raw.as_str(), dust_cost_raw.as_str())?;
        }
        self.persist()?;
        Ok(PreparedMessage {
            message,
            envelope,
            submission_grant: None,
        })
    }

    pub fn receive_envelope(
        &mut self,
        messaging_root: &[u8],
        mut envelope: MailboxEnvelope,
    ) -> Result<WalletMessage, WalletError> {
        self.enrich_inbound_envelope(&mut envelope)?;
        validate_envelope_sender_identity(&envelope)?;
        let envelope_key = seen_envelope_key(&envelope);
        if self.index.seen_envelope_keys.contains(&envelope_key) {
            let existing = self
                .conversation(messaging_root, &envelope.sender_peer_id)?
                .into_iter()
                .find(|message| {
                    message.envelope_hash == envelope.envelope_hash
                        && message.sequence == envelope.sequence
                        && message.channel_id == envelope.channel_id
                })
                .ok_or_else(|| {
                    WalletError::BridgePolicyViolation(
                        "duplicate mailbox envelope was observed without a stored message".to_string(),
                    )
                })?;
            return Ok(existing);
        }
        let plaintext = self.decrypt_envelope(messaging_root, &envelope)?;
        let content: WalletMessageContent =
            postcard::from_bytes::<WireMessageContent>(&plaintext)
                .map(WalletMessageContent::from)
                .map_err(|error| {
                WalletError::BridgePolicyViolation(format!(
                    "failed to decode wallet messaging payload: {error}"
                ))
            })?;
        validate_message_content(&content)?;
        let peer_id = envelope.sender_peer_id.clone();
        let now = Utc::now();
        let message = WalletMessage {
            message_id: random_token(),
            channel_id: envelope.channel_id.clone(),
            peer_id: peer_id.clone(),
            direction: WalletMessageDirection::Inbound,
            status: WalletMessageStatus::Received,
            kind: content.kind(),
            sequence: envelope.sequence,
            sent_at: envelope.posted_at,
            received_at: Some(now),
            dust_cost_raw: "0".to_string(),
            envelope_hash: envelope.envelope_hash.clone(),
            content: content.clone(),
        };

        let mut messages = self.conversation(messaging_root, &peer_id)?;
        messages.push(message.clone());
        self.write_conversation(messaging_root, &peer_id, &messages)?;
        self.index.seen_envelope_keys.insert(envelope_key);

        let remote_invite = WalletChannelInvite {
            peer_id: peer_id.clone(),
            channel_id: envelope.channel_id.clone(),
            display_name: None,
            advertisement: envelope.sender_advertisement.clone(),
            invitation_code: format!("ziros-midnight-msg://{}", envelope.channel_id),
        };
        let local_invite = self.build_local_invite(
            messaging_root,
            envelope.channel_id.as_str(),
            peer_id.clone(),
            None,
            now,
        )?;

        let channel = self
            .index
            .conversations
            .entry(peer_id.0.clone())
            .or_insert(ChannelRecord {
                peer_id: peer_id.clone(),
                display_name: None,
                channel_id: envelope.channel_id.clone(),
                state: "open".to_string(),
                reason: None,
                unread_count: 0,
                last_message_preview: None,
                last_message_at: None,
                dust_spent_raw: "0".to_string(),
                opened_at: Some(now),
                last_rotated_at: Some(now),
                local_invite: None,
                remote_invite: None,
            });
        channel.channel_id = envelope.channel_id;
        channel.state = "open".to_string();
        channel.reason = None;
        channel.unread_count = channel.unread_count.saturating_add(1);
        channel.last_message_preview = Some(content.preview());
        channel.last_message_at = Some(now);
        channel.last_rotated_at = Some(now);
        channel.local_invite = Some(local_invite);
        channel.remote_invite = Some(remote_invite);
        self.persist()?;
        Ok(message)
    }

    pub fn poll_mailbox(&mut self) -> Result<MessagingTransportStatus, WalletError> {
        self.index.transport_status.last_poll_at = Some(Utc::now());
        self.persist()?;
        Ok(self.transport_status())
    }

    pub fn complete_mailbox_post(
        &mut self,
        messaging_root: &[u8],
        success: MailboxPostSuccess,
    ) -> Result<WalletMessage, WalletError> {
        let (peer_id, mut messages, message_index) =
            self.find_message_by_envelope_hash(messaging_root, success.envelope_hash.as_str())?;
        let Some(message) = messages.get_mut(message_index) else {
            return Err(WalletError::BridgePolicyViolation(
                "mailbox message disappeared before completion".to_string(),
            ));
        };
        message.status = WalletMessageStatus::Posted;
        message.sent_at = success.posted_at;
        let updated = message.clone();
        let cursor = success.cursor.clone();
        self.write_conversation(messaging_root, &peer_id, &messages)?;
        self.index.transport_status.last_healthy_probe_at = Some(Utc::now());
        self.index.transport_status.available = true;
        self.index.transport_status.reason = None;
        if let Some(cursor) = cursor {
            self.index.transport_status.last_observed_cursor = Some(cursor);
        }
        self.persist()?;
        Ok(updated)
    }

    pub fn fail_mailbox_post(
        &mut self,
        messaging_root: &[u8],
        failure: MailboxPostFailure,
    ) -> Result<WalletMessage, WalletError> {
        let (peer_id, mut messages, message_index) =
            self.find_message_by_envelope_hash(messaging_root, failure.envelope_hash.as_str())?;
        let Some(message) = messages.get_mut(message_index) else {
            return Err(WalletError::BridgePolicyViolation(
                "mailbox message disappeared before failure handling".to_string(),
            ));
        };
        message.status = WalletMessageStatus::Failed;
        let updated = message.clone();
        self.write_conversation(messaging_root, &peer_id, &messages)?;
        self.index.transport_status.available = false;
        self.index.transport_status.reason = Some(failure.reason);
        self.persist()?;
        Ok(updated)
    }

    fn prepare_message(
        &mut self,
        peer_id: WalletPeerId,
        content: WalletMessageContent,
    ) -> Result<ApprovalReviewPayload, WalletError> {
        validate_message_content(&content)?;
        let channel = self.index.conversations.get(peer_id.as_str()).ok_or_else(|| {
            WalletError::BridgePolicyViolation(format!(
                "open a messaging channel with {} before sending messages",
                peer_id
            ))
        })?;
        if channel.state != "open" {
            return Err(WalletError::BridgePolicyViolation(
                channel
                    .reason
                    .clone()
                    .unwrap_or_else(|| "messaging channel is not ready to send".to_string()),
            ));
        }
        if !self.index.transport_status.available {
            return Err(WalletError::BridgePolicyViolation(
                self.index
                    .transport_status
                    .reason
                    .clone()
                    .unwrap_or_else(|| "messaging transport is unavailable".to_string()),
            ));
        }
        let prepared_id = random_token();
        let dust_cost_raw = default_message_dust_cost(content.kind());
        self.prepared.insert(
            prepared_id.clone(),
            PreparedMessagingAction::SendMessage {
                peer_id: peer_id.clone(),
                channel_id: channel.channel_id.clone(),
                content: content.clone(),
                dust_cost_raw: dust_cost_raw.clone(),
            },
        );
        Ok(ApprovalReviewPayload::message_send(MessageSendReviewPayload {
            origin: "native://wallet".to_string(),
            network: self.network,
            method: ApprovalMethod::SendMessage,
            tx_digest: prepared_id,
            peer_id,
            channel_id: channel.channel_id.clone(),
            message_kind: content.kind(),
            dust_cost_raw,
            message_preview: content.preview(),
            human_summary: format!(
                "Spend DUST to post a {} message through Midnight messaging.",
                kind_label(content.kind())
            ),
            warnings: vec![
                "Every mailbox post consumes DUST.".to_string(),
                "This approval authorizes only this exact message envelope.".to_string(),
            ],
        }))
    }

    fn build_local_invite(
        &self,
        messaging_root: &[u8],
        channel_id: &str,
        peer_id: WalletPeerId,
        display_name: Option<String>,
        now: DateTime<Utc>,
    ) -> Result<WalletChannelInvite, WalletError> {
        let epoch_id = current_unix_hour(now.timestamp() as u64);
        let local_advertisement = local_advertisement(messaging_root, epoch_id)?;
        let local_peer_id = local_peer_id(messaging_root)?;
        Ok(WalletChannelInvite {
            peer_id: local_peer_id,
            channel_id: channel_id.to_string(),
            display_name,
            advertisement: local_advertisement,
            invitation_code: format!("ziros-midnight-msg://{}?peer={}", channel_id, peer_id),
        })
    }

    fn encrypt_envelope(
        &self,
        messaging_root: &[u8],
        channel_id: &str,
        receiver_peer_id: &WalletPeerId,
        remote_advertisement: WalletPeerAdvertisement,
        content: WalletMessageContent,
        sequence: u64,
        posted_at: DateTime<Utc>,
    ) -> Result<MailboxEnvelope, WalletError> {
        if channel_id.is_empty() || channel_id.len() > MAX_CHANNEL_ID_BYTES {
            return Err(WalletError::BridgePolicyViolation(format!(
                "messaging channel id must be between 1 and {MAX_CHANNEL_ID_BYTES} bytes"
            )));
        }
        validate_message_content(&content)?;
        let epoch_id = current_unix_hour(posted_at.timestamp() as u64);
        let local_keys = local_epoch_keys(messaging_root, epoch_id)?;
        let local_advertisement = local_advertisement(messaging_root, epoch_id)?;
        let sender_peer_id = local_peer_id(messaging_root)?;
        let remote_x25519_public = decode_fixed_hex::<32>(
            remote_advertisement.x25519_public_key_hex.as_str(),
        )?;
        let remote_x25519_public = PublicKey::from(remote_x25519_public);
        let remote_ml_kem_public_key = MlKem1024PublicKey::try_from(
            hex::decode(remote_advertisement.ml_kem_public_key_hex.as_str())
                .map_err(|error| {
                    WalletError::BridgePolicyViolation(format!(
                        "invalid remote messaging ML-KEM public key: {error}"
                    ))
                })?
                .as_slice(),
        )
        .map_err(|_| {
            WalletError::BridgePolicyViolation(
                "remote messaging ML-KEM public key has the wrong size".to_string(),
            )
        })?;
        let shared_secret_x25519 = local_keys.x25519_secret.diffie_hellman(&remote_x25519_public);
        let (ml_kem_ciphertext, shared_secret_kem) = kem_encapsulate(
            &remote_ml_kem_public_key,
            random_array::<{ ML_KEM_SHARED_SECRET_SIZE }>(),
        );
        let combined_key = derive_combined_key(
            shared_secret_x25519.as_bytes(),
            shared_secret_kem.as_slice(),
            epoch_id,
            sender_peer_id.as_str(),
            receiver_peer_id.as_str(),
        )?;
        let plaintext = postcard::to_allocvec(&WireMessageContent::from(&content)).map_err(|error| {
            WalletError::BridgePolicyViolation(format!(
                "failed to encode messaging payload: {error}"
            ))
        })?;
        let aad = associated_data(
            kind_label(content.kind()),
            sender_peer_id.as_str(),
            receiver_peer_id.as_str(),
            sequence,
            epoch_id,
        );
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new((&combined_key).into());
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                WalletError::BridgePolicyViolation(
                    "failed to encrypt wallet message envelope".to_string(),
                )
            })?;
        if ciphertext.len() > MAX_MAILBOX_CIPHERTEXT_BYTES {
            return Err(WalletError::BridgePolicyViolation(format!(
                "messaging payload exceeds the mailbox ciphertext limit of {MAX_MAILBOX_CIPHERTEXT_BYTES} bytes"
            )));
        }
        let unsigned = EnvelopeSignaturePayload {
            channel_id: channel_id.to_string(),
            sender_peer_id: sender_peer_id.clone(),
            receiver_peer_id: receiver_peer_id.clone(),
            message_kind: content.kind(),
            sequence,
            epoch_id,
            sender_advertisement: local_advertisement.clone(),
            nonce_hex: hex::encode(nonce),
            ciphertext_hex: hex::encode(&ciphertext),
            ml_kem_ciphertext_hex: hex::encode(ml_kem_ciphertext.as_slice()),
            payload_version: MESSAGE_PAYLOAD_VERSION,
            posted_at,
        };
        let signature = sign_envelope(messaging_root, &unsigned)?;
        let envelope_hash = envelope_hash(&unsigned);
        Ok(MailboxEnvelope {
            channel_id: unsigned.channel_id,
            sender_peer_id: unsigned.sender_peer_id,
            receiver_peer_id: unsigned.receiver_peer_id,
            message_kind: unsigned.message_kind,
            sequence: unsigned.sequence,
            epoch_id: unsigned.epoch_id,
            sender_advertisement: unsigned.sender_advertisement,
            nonce_hex: unsigned.nonce_hex,
            ciphertext_hex: unsigned.ciphertext_hex,
            ml_kem_ciphertext_hex: unsigned.ml_kem_ciphertext_hex,
            payload_version: unsigned.payload_version,
            sender_signature_hex: signature,
            envelope_hash,
            posted_at: unsigned.posted_at,
        })
    }

    fn decrypt_envelope(
        &self,
        messaging_root: &[u8],
        envelope: &MailboxEnvelope,
    ) -> Result<Vec<u8>, WalletError> {
        verify_envelope_signature(envelope)?;
        let local_keys = local_epoch_keys(messaging_root, envelope.epoch_id)?;
        let remote_x25519_public = decode_fixed_hex::<32>(
            envelope.sender_advertisement.x25519_public_key_hex.as_str(),
        )?;
        let remote_x25519_public = PublicKey::from(remote_x25519_public);
        let shared_secret_x25519 = local_keys.x25519_secret.diffie_hellman(&remote_x25519_public);
        let ml_kem_private_key = MlKem1024PrivateKey::try_from(
            local_keys.ml_kem_decapsulation_key.as_slice(),
        )
        .map_err(|_| {
            WalletError::BridgePolicyViolation(
                "local messaging ML-KEM private key is corrupt".to_string(),
            )
        })?;
        let ml_kem_ciphertext = MlKem1024Ciphertext::try_from(
            hex::decode(envelope.ml_kem_ciphertext_hex.as_str())
                .map_err(|error| {
                    WalletError::BridgePolicyViolation(format!(
                        "invalid mailbox ML-KEM ciphertext: {error}"
                    ))
                })?
                .as_slice(),
        )
        .map_err(|_| {
            WalletError::BridgePolicyViolation(
                "mailbox ML-KEM ciphertext has the wrong size".to_string(),
            )
        })?;
        let shared_secret_kem = kem_decapsulate(&ml_kem_private_key, &ml_kem_ciphertext);
        let combined_key = derive_combined_key(
            shared_secret_x25519.as_bytes(),
            shared_secret_kem.as_slice(),
            envelope.epoch_id,
            envelope.sender_peer_id.as_str(),
            envelope.receiver_peer_id.as_str(),
        )?;
        let aad = associated_data(
            kind_label(envelope.message_kind),
            envelope.sender_peer_id.as_str(),
            envelope.receiver_peer_id.as_str(),
            envelope.sequence,
            envelope.epoch_id,
        );
        let nonce = hex::decode(envelope.nonce_hex.as_str()).map_err(|error| {
            WalletError::BridgePolicyViolation(format!("invalid mailbox nonce: {error}"))
        })?;
        let ciphertext = hex::decode(envelope.ciphertext_hex.as_str()).map_err(|error| {
            WalletError::BridgePolicyViolation(format!("invalid mailbox ciphertext: {error}"))
        })?;
        let cipher = ChaCha20Poly1305::new((&combined_key).into());
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                WalletError::BridgePolicyViolation(
                    "failed to decrypt mailbox envelope".to_string(),
                )
            })
    }

    fn write_conversation(
        &self,
        messaging_root: &[u8],
        peer_id: &WalletPeerId,
        messages: &[WalletMessage],
    ) -> Result<(), WalletError> {
        let blob = encrypt_messages(messaging_root, messages)?;
        self.cloudfs
            .write_json(conversation_path(self.network, peer_id).as_str(), &blob)
            .map_err(WalletError::Storage)
    }

    fn persist(&mut self) -> Result<(), WalletError> {
        self.index.updated_at = Utc::now();
        self.cloudfs
            .write_json(index_path(self.network).as_str(), &self.index)
            .map_err(WalletError::Storage)
    }

    fn find_message_by_envelope_hash(
        &self,
        messaging_root: &[u8],
        envelope_hash: &str,
    ) -> Result<(WalletPeerId, Vec<WalletMessage>, usize), WalletError> {
        for peer_id in self.index.conversations.keys() {
            let peer_id = WalletPeerId(peer_id.clone());
            let messages = self.conversation(messaging_root, &peer_id)?;
            if let Some(index) = messages
                .iter()
                .position(|message| message.envelope_hash == envelope_hash)
            {
                return Ok((peer_id, messages, index));
            }
        }
        Err(WalletError::BridgePolicyViolation(format!(
            "mailbox envelope {envelope_hash} is not tracked by wallet messaging"
        )))
    }

    fn enrich_inbound_envelope(&self, envelope: &mut MailboxEnvelope) -> Result<(), WalletError> {
        let Some(record) = self.index.conversations.get(envelope.sender_peer_id.as_str()) else {
            if envelope.channel_id.trim().is_empty() {
                return Err(WalletError::BridgePolicyViolation(
                    "mailbox envelope is missing a channel binding for an unknown peer".to_string(),
                ));
            }
            return Ok(());
        };

        if envelope.channel_id.trim().is_empty() {
            envelope.channel_id = record.channel_id.clone();
        } else if envelope.channel_id != record.channel_id {
            return Err(WalletError::BridgePolicyViolation(
                "mailbox envelope channel does not match the locally opened channel".to_string(),
            ));
        }

        if envelope
            .sender_advertisement
            .ml_kem_public_key_hex
            .trim()
            .is_empty()
        {
            if let Some(remote_invite) = &record.remote_invite {
                envelope.sender_advertisement.ml_kem_public_key_hex =
                    remote_invite.advertisement.ml_kem_public_key_hex.clone();
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EnvelopeSignaturePayload {
    channel_id: String,
    sender_peer_id: WalletPeerId,
    receiver_peer_id: WalletPeerId,
    message_kind: WalletMessageKind,
    sequence: u64,
    epoch_id: u64,
    sender_advertisement: WalletPeerAdvertisement,
    nonce_hex: String,
    ciphertext_hex: String,
    ml_kem_ciphertext_hex: String,
    payload_version: u32,
    posted_at: DateTime<Utc>,
}

#[derive(Clone)]
struct LocalEpochKeys {
    x25519_secret: StaticSecret,
    x25519_public_key: [u8; 32],
    ml_kem_decapsulation_key: Vec<u8>,
    ml_kem_encapsulation_key: Vec<u8>,
}

fn validate_open_channel_request(request: &WalletChannelOpenRequest) -> Result<(), WalletError> {
    if request.peer_id != request.remote_invite.peer_id {
        return Err(WalletError::BridgePolicyViolation(
            "messaging open-channel peer mismatch".to_string(),
        ));
    }
    if request.remote_invite.channel_id.trim().is_empty() {
        return Err(WalletError::BridgePolicyViolation(
            "messaging channel id must not be empty".to_string(),
        ));
    }
    if request.remote_invite.channel_id.len() > MAX_CHANNEL_ID_BYTES {
        return Err(WalletError::BridgePolicyViolation(format!(
            "messaging channel id must be at most {MAX_CHANNEL_ID_BYTES} bytes"
        )));
    }
    validate_peer_identity(
        request.peer_id.as_str(),
        request
            .remote_invite
            .advertisement
            .identity_public_key_hex
            .as_str(),
    )
}

fn validate_envelope_sender_identity(envelope: &MailboxEnvelope) -> Result<(), WalletError> {
    validate_peer_identity(
        envelope.sender_peer_id.as_str(),
        envelope
            .sender_advertisement
            .identity_public_key_hex
            .as_str(),
    )
}

fn validate_peer_identity(
    peer_id: &str,
    identity_public_key_hex: &str,
) -> Result<(), WalletError> {
    let identity_public_key = hex::decode(identity_public_key_hex).map_err(|error| {
        WalletError::BridgePolicyViolation(format!(
            "invalid messaging identity public key: {error}"
        ))
    })?;
    let expected = peer_id_from_identity_bytes(&identity_public_key);
    if expected.as_str() != peer_id {
        return Err(WalletError::BridgePolicyViolation(
            "messaging peer id does not match the advertised identity key".to_string(),
        ));
    }
    Ok(())
}

fn validate_message_content(content: &WalletMessageContent) -> Result<(), WalletError> {
    match content {
        WalletMessageContent::Text { text } => {
            if text.trim().is_empty() {
                return Err(WalletError::BridgePolicyViolation(
                    "messaging text messages must not be empty".to_string(),
                ));
            }
            if text.len() > MAX_TEXT_MESSAGE_BYTES {
                return Err(WalletError::BridgePolicyViolation(format!(
                    "messaging text messages must be at most {MAX_TEXT_MESSAGE_BYTES} bytes"
                )));
            }
        }
        WalletMessageContent::TransferReceipt(receipt) => {
            if receipt.tx_hash.trim().is_empty() || receipt.tx_hash.len() > MAX_TX_HASH_BYTES {
                return Err(WalletError::BridgePolicyViolation(format!(
                    "transfer receipt tx hash must be between 1 and {MAX_TX_HASH_BYTES} bytes"
                )));
            }
            if receipt.summary.trim().is_empty()
                || receipt.summary.len() > MAX_TRANSFER_RECEIPT_TEXT_BYTES
            {
                return Err(WalletError::BridgePolicyViolation(format!(
                    "transfer receipt summary must be between 1 and {MAX_TRANSFER_RECEIPT_TEXT_BYTES} bytes"
                )));
            }
        }
        WalletMessageContent::CredentialRequest(request) => {
            if request.request_id.trim().is_empty() || request.request_id.len() > MAX_TX_HASH_BYTES {
                return Err(WalletError::BridgePolicyViolation(format!(
                    "credential request id must be between 1 and {MAX_TX_HASH_BYTES} bytes"
                )));
            }
            if request.claim_summary.trim().is_empty()
                || request.claim_summary.len() > MAX_CREDENTIAL_SUMMARY_BYTES
            {
                return Err(WalletError::BridgePolicyViolation(format!(
                    "credential request summary must be between 1 and {MAX_CREDENTIAL_SUMMARY_BYTES} bytes"
                )));
            }
        }
        WalletMessageContent::CredentialResponse(response) => {
            if response.request_id.trim().is_empty()
                || response.request_id.len() > MAX_TX_HASH_BYTES
            {
                return Err(WalletError::BridgePolicyViolation(format!(
                    "credential response id must be between 1 and {MAX_TX_HASH_BYTES} bytes"
                )));
            }
            if response.disclosure_summary.trim().is_empty()
                || response.disclosure_summary.len() > MAX_CREDENTIAL_SUMMARY_BYTES
            {
                return Err(WalletError::BridgePolicyViolation(format!(
                    "credential response summary must be between 1 and {MAX_CREDENTIAL_SUMMARY_BYTES} bytes"
                )));
            }
        }
    }
    Ok(())
}

fn local_peer_id(messaging_root: &[u8]) -> Result<WalletPeerId, WalletError> {
    let (_, verification_key) = identity_keypair(messaging_root)?;
    Ok(peer_id_from_identity_bytes(verification_key.as_slice()))
}

fn peer_id_from_identity_bytes(bytes: &[u8]) -> WalletPeerId {
    WalletPeerId(format!("midpeer-{}", hex::encode(Sha256::digest(bytes))))
}

fn local_advertisement(
    messaging_root: &[u8],
    epoch_id: u64,
) -> Result<WalletPeerAdvertisement, WalletError> {
    let local_keys = local_epoch_keys(messaging_root, epoch_id)?;
    let (_, verification_key) = identity_keypair(messaging_root)?;
    Ok(WalletPeerAdvertisement {
        epoch_id,
        x25519_public_key_hex: hex::encode(local_keys.x25519_public_key),
        ml_kem_public_key_hex: hex::encode(local_keys.ml_kem_encapsulation_key),
        identity_public_key_hex: hex::encode(verification_key.as_slice()),
    })
}

fn identity_keypair(
    messaging_root: &[u8],
) -> Result<(MLDSA87SigningKey, MLDSA87VerificationKey), WalletError> {
    let randomness =
        derive_labeled_bytes::<{ KEY_GENERATION_RANDOMNESS_SIZE }>(
            messaging_root,
            IDENTITY_INFO,
            None,
        )?;
    let pair = generate_key_pair(randomness);
    Ok((pair.signing_key, pair.verification_key))
}

fn local_epoch_keys(
    messaging_root: &[u8],
    epoch_id: u64,
) -> Result<LocalEpochKeys, WalletError> {
    let x25519_seed = derive_labeled_bytes::<32>(
        messaging_root,
        EPOCH_INFO,
        Some(epoch_label(b"x25519", epoch_id).as_slice()),
    )?;
    let x25519_secret = StaticSecret::from(x25519_seed);
    let x25519_public_key = PublicKey::from(&x25519_secret).to_bytes();
    let ml_kem_seed = derive_labeled_bytes::<{ ML_KEM_KEY_GENERATION_SEED_SIZE }>(
        messaging_root,
        EPOCH_INFO,
        Some(epoch_label(b"ml-kem", epoch_id).as_slice()),
    )?;
    let ml_kem = kem_generate(ml_kem_seed);
    Ok(LocalEpochKeys {
        x25519_secret,
        x25519_public_key,
        ml_kem_decapsulation_key: ml_kem.sk().to_vec(),
        ml_kem_encapsulation_key: ml_kem.pk().to_vec(),
    })
}

fn epoch_label(prefix: &[u8], epoch_id: u64) -> Vec<u8> {
    let mut label = Vec::with_capacity(prefix.len() + 1 + std::mem::size_of::<u64>());
    label.extend_from_slice(prefix);
    label.push(0);
    label.extend_from_slice(&epoch_id.to_le_bytes());
    label
}

fn sign_envelope(
    messaging_root: &[u8],
    envelope: &EnvelopeSignaturePayload,
) -> Result<String, WalletError> {
    let (signing_key, _) = identity_keypair(messaging_root)?;
    let bytes = postcard::to_allocvec(envelope).map_err(|error| {
        WalletError::BridgePolicyViolation(format!(
            "failed to encode messaging envelope for signing: {error}"
        ))
    })?;
    let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut randomness);
    let signature = mldsa_sign(
        &signing_key,
        &bytes,
        MESSAGE_SIGNATURE_CONTEXT,
        randomness,
    )
    .map_err(|_| {
        WalletError::BridgePolicyViolation("failed to sign messaging envelope".to_string())
    })?;
    Ok(hex::encode(signature.as_slice()))
}

fn verify_envelope_signature(envelope: &MailboxEnvelope) -> Result<(), WalletError> {
    let signing_payload = EnvelopeSignaturePayload {
        channel_id: envelope.channel_id.clone(),
        sender_peer_id: envelope.sender_peer_id.clone(),
        receiver_peer_id: envelope.receiver_peer_id.clone(),
        message_kind: envelope.message_kind,
        sequence: envelope.sequence,
        epoch_id: envelope.epoch_id,
        sender_advertisement: envelope.sender_advertisement.clone(),
        nonce_hex: envelope.nonce_hex.clone(),
        ciphertext_hex: envelope.ciphertext_hex.clone(),
        ml_kem_ciphertext_hex: envelope.ml_kem_ciphertext_hex.clone(),
        payload_version: envelope.payload_version,
        posted_at: envelope.posted_at,
    };
    let bytes = postcard::to_allocvec(&signing_payload).map_err(|error| {
        WalletError::BridgePolicyViolation(format!(
            "failed to encode messaging envelope for verification: {error}"
        ))
    })?;
    let verification_key_bytes = decode_fixed_hex::<{ MLDSA87VerificationKey::len() }>(
        envelope
            .sender_advertisement
            .identity_public_key_hex
            .as_str(),
    )?;
    let verification_key = MLDSA87VerificationKey::new(verification_key_bytes);
    let signature_bytes =
        decode_fixed_hex::<{ MLDSA87Signature::len() }>(envelope.sender_signature_hex.as_str())?;
    let signature = MLDSA87Signature::new(signature_bytes);
    mldsa_verify(
        &verification_key,
        &bytes,
        MESSAGE_SIGNATURE_CONTEXT,
        &signature,
    )
    .map_err(|_| {
        WalletError::BridgePolicyViolation(
            "messaging envelope signature verification failed".to_string(),
        )
    })
}

fn envelope_hash(payload: &EnvelopeSignaturePayload) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload.channel_id.as_bytes());
    hasher.update(payload.sender_peer_id.as_str().as_bytes());
    hasher.update(payload.receiver_peer_id.as_str().as_bytes());
    hasher.update(kind_label(payload.message_kind).as_bytes());
    hasher.update(payload.sequence.to_le_bytes());
    hasher.update(payload.epoch_id.to_le_bytes());
    hasher.update(payload.nonce_hex.as_bytes());
    hasher.update(payload.ciphertext_hex.as_bytes());
    hasher.update(payload.ml_kem_ciphertext_hex.as_bytes());
    hex::encode(hasher.finalize())
}

fn encrypt_messages(
    messaging_root: &[u8],
    messages: &[WalletMessage],
) -> Result<EncryptedBlob, WalletError> {
    let storage_key = storage_key(messaging_root)?;
    let cipher = ChaCha20Poly1305::new((&storage_key).into());
    let plaintext = serde_json::to_vec(messages).map_err(|error| {
        WalletError::BridgePolicyViolation(format!(
            "failed to encode messaging conversation: {error}"
        ))
    })?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: STORAGE_INFO,
            },
        )
        .map_err(|_| {
            WalletError::BridgePolicyViolation(
                "failed to encrypt messaging conversation".to_string(),
            )
        })?;
    Ok(EncryptedBlob {
        schema: MESSAGING_SCHEMA.to_string(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
    })
}

fn decrypt_messages(
    messaging_root: &[u8],
    blob: &EncryptedBlob,
) -> Result<Vec<WalletMessage>, WalletError> {
    let storage_key = storage_key(messaging_root)?;
    let cipher = ChaCha20Poly1305::new((&storage_key).into());
    let nonce = hex::decode(blob.nonce_hex.as_str()).map_err(|error| {
        WalletError::BridgePolicyViolation(format!("invalid messaging nonce: {error}"))
    })?;
    let ciphertext = hex::decode(blob.ciphertext_hex.as_str()).map_err(|error| {
        WalletError::BridgePolicyViolation(format!("invalid messaging ciphertext: {error}"))
    })?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: STORAGE_INFO,
            },
        )
        .map_err(|_| {
            WalletError::BridgePolicyViolation(
                "failed to decrypt messaging conversation".to_string(),
            )
        })?;
    serde_json::from_slice::<Vec<WalletMessage>>(&plaintext).map_err(|error| {
        WalletError::BridgePolicyViolation(format!(
            "failed to decode decrypted conversation: {error}"
        ))
    })
}

fn storage_key(messaging_root: &[u8]) -> Result<[u8; 32], WalletError> {
    derive_labeled_bytes::<32>(messaging_root, STORAGE_INFO, None)
}

fn default_message_dust_cost(kind: WalletMessageKind) -> String {
    match kind {
        WalletMessageKind::Text => "1000000".to_string(),
        WalletMessageKind::TransferReceipt => "1500000".to_string(),
        WalletMessageKind::CredentialRequest => "2000000".to_string(),
        WalletMessageKind::CredentialResponse => "2500000".to_string(),
    }
}

fn add_raw_amounts(left: &str, right: &str) -> Result<String, WalletError> {
    let left = left.parse::<u128>().map_err(|_| {
        WalletError::BridgePolicyViolation(format!("invalid raw amount '{left}'"))
    })?;
    let right = right.parse::<u128>().map_err(|_| {
        WalletError::BridgePolicyViolation(format!("invalid raw amount '{right}'"))
    })?;
    Ok(left.saturating_add(right).to_string())
}

fn current_unix_hour(now_unix_secs: u64) -> u64 {
    now_unix_secs / 3600
}

fn associated_data(
    message_kind: &str,
    sender: &str,
    receiver: &str,
    sequence: u64,
    epoch_id: u64,
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(ROOT_INFO);
    aad.push(0);
    aad.extend_from_slice(message_kind.as_bytes());
    aad.push(0);
    aad.extend_from_slice(sender.as_bytes());
    aad.push(0);
    aad.extend_from_slice(receiver.as_bytes());
    aad.extend_from_slice(&sequence.to_le_bytes());
    aad.extend_from_slice(&epoch_id.to_le_bytes());
    aad
}

fn derive_combined_key(
    shared_secret_x25519: &[u8],
    shared_secret_kem: &[u8],
    epoch_id: u64,
    sender: &str,
    receiver: &str,
) -> Result<[u8; 32], WalletError> {
    let mut combined_secret = [0u8; 32 + ML_KEM_SHARED_SECRET_SIZE];
    combined_secret[..32].copy_from_slice(shared_secret_x25519);
    combined_secret[32..].copy_from_slice(shared_secret_kem);
    let hk = Hkdf::<Sha384>::new(Some(&epoch_id.to_le_bytes()), &combined_secret);
    let mut out = [0u8; 32];
    let mut info = Vec::new();
    info.extend_from_slice(ROOT_INFO);
    info.extend_from_slice(&epoch_id.to_le_bytes());
    info.extend_from_slice(sender.as_bytes());
    info.push(0);
    info.extend_from_slice(receiver.as_bytes());
    hk.expand(&info, &mut out).map_err(|_| {
        WalletError::BridgePolicyViolation(
            "failed to derive combined messaging envelope key".to_string(),
        )
    })?;
    Ok(out)
}

fn derive_labeled_bytes<const N: usize>(
    messaging_root: &[u8],
    label: &[u8],
    extra: Option<&[u8]>,
) -> Result<[u8; N], WalletError> {
    let hk = Hkdf::<Sha384>::new(Some(ROOT_INFO), messaging_root);
    let mut info = Vec::with_capacity(label.len() + extra.map(|bytes| bytes.len()).unwrap_or(0));
    info.extend_from_slice(label);
    if let Some(extra) = extra {
        info.extend_from_slice(extra);
    }
    let mut out = [0u8; N];
    hk.expand(&info, &mut out).map_err(|_| {
        WalletError::BridgePolicyViolation("failed to derive messaging key material".to_string())
    })?;
    Ok(out)
}

fn decode_fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], WalletError> {
    let bytes = hex::decode(value).map_err(|error| {
        WalletError::BridgePolicyViolation(format!("invalid hex payload: {error}"))
    })?;
    bytes.try_into().map_err(|_| {
        WalletError::BridgePolicyViolation("hex payload has the wrong size".to_string())
    })
}

fn kind_label(kind: WalletMessageKind) -> &'static str {
    match kind {
        WalletMessageKind::Text => "text",
        WalletMessageKind::TransferReceipt => "transfer-receipt",
        WalletMessageKind::CredentialRequest => "credential-request",
        WalletMessageKind::CredentialResponse => "credential-response",
    }
}

fn index_path(network: WalletNetwork) -> String {
    format!("wallets/midnight/{}/messaging/index.json", network.as_str())
}

fn conversation_path(network: WalletNetwork, peer_id: &WalletPeerId) -> String {
    format!(
        "wallets/midnight/{}/messaging/{}.enc",
        network.as_str(),
        hex::encode(Sha256::digest(peer_id.as_str().as_bytes()))
    )
}

fn seen_envelope_key(envelope: &MailboxEnvelope) -> String {
    format!(
        "{}|{}|{}|{}",
        envelope.channel_id,
        envelope.sender_peer_id.as_str(),
        envelope.sequence,
        envelope.envelope_hash
    )
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_root() -> Vec<u8> {
        vec![7u8; 32]
    }

    fn state() -> MessagingState {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        MessagingState::new(WalletNetwork::Preprod, cloudfs, Utc::now()).expect("state")
    }

    #[test]
    fn conversation_store_round_trips_encrypted_messages() {
        let state = state();
        let root = test_root();
        let peer = WalletPeerId::parse("midpeer-test").expect("peer");
        let messages = vec![WalletMessage {
            message_id: "message-1".to_string(),
            channel_id: "channel-1".to_string(),
            peer_id: peer.clone(),
            direction: WalletMessageDirection::Outbound,
            status: WalletMessageStatus::Pending,
            kind: WalletMessageKind::Text,
            sequence: 1,
            sent_at: Utc::now(),
            received_at: None,
            dust_cost_raw: "1000000".to_string(),
            envelope_hash: "hash".to_string(),
            content: WalletMessageContent::Text {
                text: "hello midnight".to_string(),
            },
        }];
        state
            .write_conversation(&root, &peer, &messages)
            .expect("write conversation");
        let stored = state
            .cloudfs
            .read(conversation_path(WalletNetwork::Preprod, &peer).as_str())
            .expect("read conversation blob");
        let blob_text = String::from_utf8_lossy(&stored);
        assert!(!blob_text.contains("hello midnight"));
        let restored = state.conversation(&root, &peer).expect("restore");
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].content.preview(), "hello midnight");
    }

    #[test]
    fn prepare_open_channel_generates_review() {
        let mut state = state();
        let root = test_root();
        let local_invite = state
            .build_local_invite(
                &root,
                "channel-1",
                WalletPeerId::parse("midpeer-dest").expect("peer"),
                Some("Peer".to_string()),
                Utc::now(),
            )
            .expect("invite");
        let request = WalletChannelOpenRequest {
            peer_id: local_invite.peer_id.clone(),
            display_name: Some("Peer".to_string()),
            remote_invite: local_invite,
        };
        let review = state.prepare_open_channel(request).expect("review");
        assert_eq!(review.method(), ApprovalMethod::OpenMessagingChannel);
    }

    #[test]
    fn mailbox_post_completion_updates_pending_message_and_cursor() {
        let mut state = state();
        let root = test_root();
        let peer = WalletPeerId::parse("midpeer-dest").expect("peer");
        let local_invite = state
            .build_local_invite(&root, "channel-1", peer.clone(), Some("Peer".to_string()), Utc::now())
            .expect("invite");
        state.index.conversations.insert(
            peer.as_str().to_string(),
            ChannelRecord {
                peer_id: peer.clone(),
                display_name: Some("Peer".to_string()),
                channel_id: "channel-1".to_string(),
                state: "open".to_string(),
                reason: None,
                unread_count: 0,
                last_message_preview: None,
                last_message_at: None,
                dust_spent_raw: "0".to_string(),
                opened_at: Some(Utc::now()),
                last_rotated_at: Some(Utc::now()),
                local_invite: Some(local_invite.clone()),
                remote_invite: Some(local_invite),
            },
        );
        state.index.transport_status.available = true;
        let review = state
            .prepare_text(peer.clone(), "hello".to_string())
            .expect("prepare text");
        let prepared = state
            .commit_send_message(&root, review.tx_digest())
            .expect("commit");
        let completed = state
            .complete_mailbox_post(
                &root,
                MailboxPostSuccess {
                    envelope_hash: prepared.message.envelope_hash.clone(),
                    tx_hash: "0xabc".to_string(),
                    posted_at: Utc::now(),
                    cursor: Some("cursor-1".to_string()),
                },
            )
            .expect("complete");
        assert_eq!(completed.status, WalletMessageStatus::Posted);
        assert_eq!(
            state.transport_status().last_observed_cursor.as_deref(),
            Some("cursor-1")
        );
    }

    #[test]
    fn mailbox_post_failure_marks_message_failed() {
        let mut state = state();
        let root = test_root();
        let peer = WalletPeerId::parse("midpeer-dest").expect("peer");
        let local_invite = state
            .build_local_invite(&root, "channel-1", peer.clone(), Some("Peer".to_string()), Utc::now())
            .expect("invite");
        state.index.conversations.insert(
            peer.as_str().to_string(),
            ChannelRecord {
                peer_id: peer.clone(),
                display_name: Some("Peer".to_string()),
                channel_id: "channel-1".to_string(),
                state: "open".to_string(),
                reason: None,
                unread_count: 0,
                last_message_preview: None,
                last_message_at: None,
                dust_spent_raw: "0".to_string(),
                opened_at: Some(Utc::now()),
                last_rotated_at: Some(Utc::now()),
                local_invite: Some(local_invite.clone()),
                remote_invite: Some(local_invite),
            },
        );
        state.index.transport_status.available = true;
        let review = state
            .prepare_text(peer.clone(), "hello".to_string())
            .expect("prepare text");
        let prepared = state
            .commit_send_message(&root, review.tx_digest())
            .expect("commit");
        let failed = state
            .fail_mailbox_post(
                &root,
                MailboxPostFailure {
                    envelope_hash: prepared.message.envelope_hash.clone(),
                    reason: "adapter failed".to_string(),
                },
            )
            .expect("fail");
        assert_eq!(failed.status, WalletMessageStatus::Failed);
        assert_eq!(
            state.transport_status().reason.as_deref(),
            Some("adapter failed")
        );
    }

    #[test]
    fn duplicate_envelope_is_deduped() {
        let mut state = state();
        let root = test_root();
        let peer = WalletPeerId::parse("midpeer-dest").expect("peer");
        let local_invite = state
            .build_local_invite(&root, "channel-1", peer.clone(), Some("Peer".to_string()), Utc::now())
            .expect("invite");
        state.index.conversations.insert(
            peer.as_str().to_string(),
            ChannelRecord {
                peer_id: peer.clone(),
                display_name: Some("Peer".to_string()),
                channel_id: "channel-1".to_string(),
                state: "open".to_string(),
                reason: None,
                unread_count: 0,
                last_message_preview: None,
                last_message_at: None,
                dust_spent_raw: "0".to_string(),
                opened_at: Some(Utc::now()),
                last_rotated_at: Some(Utc::now()),
                local_invite: Some(local_invite.clone()),
                remote_invite: Some(local_invite.clone()),
            },
        );
        let envelope = state
            .encrypt_envelope(
                &root,
                "channel-1",
                &local_peer_id(&root).expect("receiver"),
                local_invite.advertisement,
                WalletMessageContent::Text {
                    text: "hello".to_string(),
                },
                1,
                Utc::now(),
            )
            .expect("envelope");
        let first = state
            .receive_envelope(&root, envelope.clone())
            .expect("first receive");
        let second = state
            .receive_envelope(&root, envelope)
            .expect("second receive");
        assert_eq!(first.envelope_hash, second.envelope_hash);
        assert_eq!(
            state.conversation(&root, &first.peer_id).expect("conversation").len(),
            1
        );
    }
}
