use chrono::{DateTime, Duration, Utc};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::collections::{BTreeSet, HashMap};
use std::io;
use std::time::Duration as StdDuration;
use thiserror::Error;
use ureq::AgentBuilder;
use zeroize::Zeroizing;
use zkf_cloudfs::CloudFS;
use zkf_keymanager::KeyManager;

mod messaging;

pub use messaging::{
    ChannelOpenReviewPayload, ChannelStatus, ConversationView, MailboxEnvelope,
    MailboxPostFailure, MailboxPostSuccess, MessageSendReviewPayload, MessagingServiceConfig,
    MessagingState, MessagingTransportMode, MessagingTransportStatus, MessagingTransportUpdate,
    PreparedMessage, WalletChannelInvite, WalletChannelOpenRequest, WalletCredentialRequest,
    WalletCredentialResponse, WalletMessage, WalletMessageContent, WalletMessageDirection,
    WalletMessageKind, WalletMessageStatus, WalletPeerAdvertisement, WalletPeerId,
    WalletTransferReceipt,
};

const WALLET_STATE_SCHEMA: &str = "ziros-midnight-wallet-state-v1";
const WALLET_ID: &str = "ziros-midnight-wallet";
const NATIVE_ORIGIN: &str = "native://wallet";
const DEFAULT_RELOCK_TIMEOUT_SECONDS: i64 = 300;
const DEFAULT_APPROVAL_TTL_SECONDS: i64 = 180;
const DEFAULT_LARGE_TRANSFER_THRESHOLD_RAW: u128 = 100_000_000_000_000_000u128;
const DEFAULT_RPC_TIMEOUT_SECONDS: u64 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum WalletNetwork {
    Preprod,
    Preview,
}

impl WalletNetwork {
    pub fn parse(raw: &str) -> Result<Self, WalletError> {
        match raw {
            "preprod" => Ok(Self::Preprod),
            "preview" => Ok(Self::Preview),
            other => Err(WalletError::NetworkMismatch {
                expected: "preprod|preview".to_string(),
                actual: other.to_string(),
            }),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preprod => "preprod",
            Self::Preview => "preview",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletServiceConfig {
    pub network: WalletNetwork,
    pub rpc_url: String,
    pub indexer_url: String,
    pub indexer_ws_url: String,
    pub explorer_url: String,
    pub proof_server_url: String,
    pub gateway_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_contract_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_manifest_path: Option<String>,
}

impl WalletServiceConfig {
    pub fn for_network(network: WalletNetwork) -> Self {
        match network {
            WalletNetwork::Preprod => Self {
                network,
                rpc_url: "https://rpc.preprod.midnight.network".to_string(),
                indexer_url: "https://indexer.preprod.midnight.network/api/v4/graphql".to_string(),
                indexer_ws_url: "wss://indexer.preprod.midnight.network/api/v4/graphql/ws"
                    .to_string(),
                explorer_url: "https://explorer.preprod.midnight.network".to_string(),
                proof_server_url: "http://127.0.0.1:6300".to_string(),
                gateway_url: "http://127.0.0.1:6311".to_string(),
                mailbox_contract_address: None,
                mailbox_manifest_path: None,
            },
            WalletNetwork::Preview => Self {
                network,
                rpc_url: "https://rpc.preview.midnight.network".to_string(),
                indexer_url: "https://indexer.preview.midnight.network/api/v4/graphql".to_string(),
                indexer_ws_url: "wss://indexer.preview.midnight.network/api/v4/graphql/ws"
                    .to_string(),
                explorer_url: "https://explorer.preview.midnight.network".to_string(),
                proof_server_url: "http://127.0.0.1:6300".to_string(),
                gateway_url: "http://127.0.0.1:6311".to_string(),
                mailbox_contract_address: None,
                mailbox_manifest_path: None,
            },
        }
    }

    pub fn messaging(&self) -> MessagingServiceConfig {
        MessagingServiceConfig {
            mailbox_contract_address: self.mailbox_contract_address.clone(),
            mailbox_manifest_path: self.mailbox_manifest_path.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicy {
    pub strict_biometrics_only: bool,
    pub relock_timeout_seconds: i64,
    pub approval_ttl_seconds: i64,
    pub large_transfer_threshold_raw: String,
}

impl Default for AuthPolicy {
    fn default() -> Self {
        Self {
            strict_biometrics_only: true,
            relock_timeout_seconds: DEFAULT_RELOCK_TIMEOUT_SECONDS,
            approval_ttl_seconds: DEFAULT_APPROVAL_TTL_SECONDS,
            large_transfer_threshold_raw: DEFAULT_LARGE_TRANSFER_THRESHOLD_RAW.to_string(),
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash,
)]
#[serde(rename_all = "kebab-case")]
pub enum BridgeScope {
    ReadConfig,
    ReadBalances,
    ReadAddresses,
    ReadHistory,
    Transfer,
    Intent,
    Submit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeOriginGrant {
    pub origin: String,
    #[serde(default)]
    pub scopes: BTreeSet<BridgeScope>,
    pub authorized_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalMethod {
    Transfer,
    Intent,
    Submit,
    Shield,
    Unshield,
    DustRegister,
    DustDeregister,
    DustRedesignate,
    SignCredential,
    OpenMessagingChannel,
    SendMessage,
    ExportSeed,
}

impl ApprovalMethod {
    pub fn parse(raw: &str) -> Result<Self, WalletError> {
        match raw {
            "transfer" => Ok(Self::Transfer),
            "intent" => Ok(Self::Intent),
            "submit" => Ok(Self::Submit),
            "shield" => Ok(Self::Shield),
            "unshield" => Ok(Self::Unshield),
            "dust-register" => Ok(Self::DustRegister),
            "dust-deregister" => Ok(Self::DustDeregister),
            "dust-redesignate" => Ok(Self::DustRedesignate),
            "sign-credential" => Ok(Self::SignCredential),
            "open-messaging-channel" => Ok(Self::OpenMessagingChannel),
            "send-message" => Ok(Self::SendMessage),
            "export-seed" => Ok(Self::ExportSeed),
            other => Err(WalletError::BridgePolicyViolation(format!(
                "unsupported approval method '{other}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalDecision {
    Approve,
    Reject,
    Expired,
    AuthFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewOutput {
    pub recipient: String,
    pub token_kind: String,
    pub amount_raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxReviewPayload {
    pub origin: String,
    pub network: WalletNetwork,
    pub method: ApprovalMethod,
    pub tx_digest: String,
    #[serde(default)]
    pub outputs: Vec<ReviewOutput>,
    pub night_total_raw: String,
    #[serde(default)]
    pub dust_total_raw: String,
    #[serde(default)]
    pub fee_raw: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dust_impact: Option<String>,
    pub shielded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prover_route: Option<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub human_summary: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ApprovalReviewKind {
    Transaction,
    ChannelOpen,
    MessageSend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalReviewPayload {
    pub kind: ApprovalReviewKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TxReviewPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_open: Option<ChannelOpenReviewPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_send: Option<MessageSendReviewPayload>,
}

impl ApprovalReviewPayload {
    pub fn transaction(review: TxReviewPayload) -> Self {
        Self {
            kind: ApprovalReviewKind::Transaction,
            transaction: Some(review),
            channel_open: None,
            message_send: None,
        }
    }

    pub fn channel_open(review: ChannelOpenReviewPayload) -> Self {
        Self {
            kind: ApprovalReviewKind::ChannelOpen,
            transaction: None,
            channel_open: Some(review),
            message_send: None,
        }
    }

    pub fn message_send(review: MessageSendReviewPayload) -> Self {
        Self {
            kind: ApprovalReviewKind::MessageSend,
            transaction: None,
            channel_open: None,
            message_send: Some(review),
        }
    }

    pub fn origin(&self) -> &str {
        match self.kind {
            ApprovalReviewKind::Transaction => self
                .transaction
                .as_ref()
                .expect("transaction review payload must be populated")
                .origin
                .as_str(),
            ApprovalReviewKind::ChannelOpen => self
                .channel_open
                .as_ref()
                .expect("channel-open review payload must be populated")
                .origin
                .as_str(),
            ApprovalReviewKind::MessageSend => self
                .message_send
                .as_ref()
                .expect("message-send review payload must be populated")
                .origin
                .as_str(),
        }
    }

    pub fn network(&self) -> WalletNetwork {
        match self.kind {
            ApprovalReviewKind::Transaction => self
                .transaction
                .as_ref()
                .expect("transaction review payload must be populated")
                .network,
            ApprovalReviewKind::ChannelOpen => self
                .channel_open
                .as_ref()
                .expect("channel-open review payload must be populated")
                .network,
            ApprovalReviewKind::MessageSend => self
                .message_send
                .as_ref()
                .expect("message-send review payload must be populated")
                .network,
        }
    }

    pub fn method(&self) -> ApprovalMethod {
        match self.kind {
            ApprovalReviewKind::Transaction => self
                .transaction
                .as_ref()
                .expect("transaction review payload must be populated")
                .method,
            ApprovalReviewKind::ChannelOpen => self
                .channel_open
                .as_ref()
                .expect("channel-open review payload must be populated")
                .method,
            ApprovalReviewKind::MessageSend => self
                .message_send
                .as_ref()
                .expect("message-send review payload must be populated")
                .method,
        }
    }

    pub fn tx_digest(&self) -> &str {
        match self.kind {
            ApprovalReviewKind::Transaction => self
                .transaction
                .as_ref()
                .expect("transaction review payload must be populated")
                .tx_digest
                .as_str(),
            ApprovalReviewKind::ChannelOpen => self
                .channel_open
                .as_ref()
                .expect("channel-open review payload must be populated")
                .tx_digest
                .as_str(),
            ApprovalReviewKind::MessageSend => self
                .message_send
                .as_ref()
                .expect("message-send review payload must be populated")
                .tx_digest
                .as_str(),
        }
    }

    pub fn night_total_raw(&self) -> Option<&str> {
        self.transaction
            .as_ref()
            .map(|transaction| transaction.night_total_raw.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingApprovalView {
    pub pending_id: String,
    pub origin: String,
    pub network: WalletNetwork,
    pub method: ApprovalMethod,
    pub tx_digest: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub review: ApprovalReviewPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub token_id: String,
    pub pending_id: String,
    pub origin: String,
    pub network: WalletNetwork,
    pub method: ApprovalMethod,
    pub tx_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SeedImportKind {
    MasterSeed,
    Mnemonic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedImportMaterial {
    pub kind: SeedImportKind,
    pub value: String,
    pub imported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedImportSummary {
    pub network: WalletNetwork,
    pub kind: SeedImportKind,
    pub imported_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperSessionView {
    pub helper_session_id: String,
    pub network: WalletNetwork,
    pub seed_kind: SeedImportKind,
    pub opened_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperSessionBundle {
    pub session: HelperSessionView,
    pub seed: SeedImportMaterial,
    pub services: WalletServiceConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionGrant {
    pub grant_id: String,
    pub token_id: String,
    pub origin: String,
    pub network: WalletNetwork,
    pub method: ApprovalMethod,
    pub tx_digest: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointHealth {
    pub url: String,
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceHealthSnapshot {
    pub network: WalletNetwork,
    pub rpc: EndpointHealth,
    pub indexer: EndpointHealth,
    pub proof_server: EndpointHealth,
    pub gateway: EndpointHealth,
    pub checked_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletHistoryEntry {
    pub at: DateTime<Utc>,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub schema: String,
    pub wallet_id: String,
    pub network: WalletNetwork,
    pub locked: bool,
    pub has_imported_seed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_seed_kind: Option<SeedImportKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported_seed_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unlocked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activity_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_session: Option<HelperSessionView>,
    pub auth_policy: AuthPolicy,
    pub services: WalletServiceConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_health: Option<ServiceHealthSnapshot>,
    #[serde(default)]
    pub grants: Vec<BridgeOriginGrant>,
    #[serde(default)]
    pub bridge_sessions: Vec<BridgeSessionView>,
    #[serde(default)]
    pub pending_approvals: Vec<PendingApprovalView>,
    pub messaging_status: MessagingTransportStatus,
    #[serde(default)]
    pub history: Vec<WalletHistoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeSessionView {
    pub session_id: String,
    pub origin: String,
    #[serde(default)]
    pub scopes: BTreeSet<BridgeScope>,
    pub created_at: DateTime<Utc>,
    pub last_activity_at: DateTime<Utc>,
}

pub struct WalletHandle {
    network: WalletNetwork,
    services: WalletServiceConfig,
    auth_policy: AuthPolicy,
    state_store: WalletStateStore,
    persistent_state: WalletPersistentState,
    authorizer: Box<dyn BiometricAuthorizer>,
    seed_store: Box<dyn SeedStore>,
    clock: Box<dyn Clock>,
    session: SessionState,
    bridge_sessions: HashMap<String, BridgeSession>,
    pending_approvals: HashMap<String, PendingApproval>,
    approval_tokens: HashMap<String, ApprovalTokenState>,
    submission_grants: HashMap<String, SubmissionGrantState>,
    messaging: MessagingState,
}

impl WalletHandle {
    pub fn new(network: WalletNetwork) -> Result<Self, WalletError> {
        let cloudfs = CloudFS::new().map_err(WalletError::Storage)?;
        Self::with_components(
            network,
            WalletServiceConfig::for_network(network),
            AuthPolicy::default(),
            cloudfs,
            Box::new(SystemBiometricAuthorizer),
            Box::new(KeyManagerSeedStore::new()?),
            Box::new(SystemClock),
        )
    }

    pub fn with_components(
        network: WalletNetwork,
        services: WalletServiceConfig,
        auth_policy: AuthPolicy,
        cloudfs: CloudFS,
        authorizer: Box<dyn BiometricAuthorizer>,
        seed_store: Box<dyn SeedStore>,
        clock: Box<dyn Clock>,
    ) -> Result<Self, WalletError> {
        let state_store = WalletStateStore::new(network, cloudfs);
        let persistent_state = state_store.load()?;
        let mut messaging = MessagingState::new(network, state_store.cloudfs.clone(), Utc::now())?;
        messaging.configure_transport(services.messaging());
        Ok(Self {
            network,
            services,
            auth_policy,
            state_store,
            persistent_state,
            authorizer,
            seed_store,
            clock,
            session: SessionState::default(),
            bridge_sessions: HashMap::new(),
            pending_approvals: HashMap::new(),
            approval_tokens: HashMap::new(),
            submission_grants: HashMap::new(),
            messaging,
        })
    }

    pub fn unlock(&mut self, prompt: &str) -> Result<(), WalletError> {
        let seed = self.seed_store.unlock_seed_material(self.network, prompt)?;
        self.authorizer.ensure_material(self.network)?;
        let now = self.clock.now();
        self.session.unlocked = true;
        self.session.seed_material = Some(seed);
        self.session.unlocked_at = Some(now);
        self.session.last_activity_at = Some(now);
        self.record_history("unlock", "wallet unlocked with biometrics");
        self.persist()
    }

    pub fn lock(&mut self) -> Result<(), WalletError> {
        self.lock_internal();
        self.record_history("lock", "wallet locked");
        self.persist()
    }

    pub fn app_backgrounded(&mut self) -> Result<(), WalletError> {
        self.lock_internal();
        self.record_history("background-lock", "wallet locked after app background");
        self.persist()
    }

    pub fn authorize_operation(
        &mut self,
        method: ApprovalMethod,
        primary_prompt: &str,
        secondary_prompt: Option<&str>,
        amount_raw: Option<&str>,
    ) -> Result<(), WalletError> {
        self.ensure_session_active()?;
        self.authorizer.authenticate(self.network, primary_prompt)?;
        if self.requires_second_prompt(method, amount_raw)? {
            let prompt = secondary_prompt.ok_or_else(|| {
                WalletError::BridgePolicyViolation(
                    "large transfer requires a secondary biometric prompt".to_string(),
                )
            })?;
            self.authorizer.authenticate(self.network, prompt)?;
        }
        self.record_history(
            "authorize-operation",
            &format!("approved {}", method_label(method)),
        );
        self.persist()
    }

    pub fn sync_health(&mut self) -> Result<ServiceHealthSnapshot, WalletError> {
        let checked_at = self.clock.now();
        let snapshot = ServiceHealthSnapshot {
            network: self.network,
            rpc: probe_endpoint(&self.services.rpc_url, checked_at),
            indexer: probe_endpoint(&self.services.indexer_url, checked_at),
            proof_server: probe_endpoint(&self.services.proof_server_url, checked_at),
            gateway: probe_endpoint(&self.services.gateway_url, checked_at),
            checked_at,
        };
        self.persistent_state.last_health = Some(snapshot.clone());
        self.record_history("sync-health", "refreshed service-health snapshot");
        self.persist()?;
        Ok(snapshot)
    }

    pub fn snapshot(&mut self) -> Result<WalletSnapshot, WalletError> {
        self.maybe_relock_on_idle()?;
        Ok(WalletSnapshot {
            schema: WALLET_STATE_SCHEMA.to_string(),
            wallet_id: WALLET_ID.to_string(),
            network: self.network,
            locked: !self.session.unlocked,
            has_imported_seed: self.persistent_state.imported_seed_kind.is_some(),
            imported_seed_kind: self.persistent_state.imported_seed_kind,
            imported_seed_at: self.persistent_state.imported_seed_at,
            unlocked_at: self.session.unlocked_at,
            last_activity_at: self.session.last_activity_at,
            helper_session: self.session.helper_session.clone().map(HelperSession::into_view),
            auth_policy: self.auth_policy.clone(),
            services: self.services.clone(),
            last_health: self.persistent_state.last_health.clone(),
            grants: self.persistent_state.grants.clone(),
            bridge_sessions: self
                .bridge_sessions
                .values()
                .cloned()
                .map(BridgeSession::into_view)
                .collect(),
            pending_approvals: self
                .pending_approvals
                .values()
                .cloned()
                .map(PendingApproval::into_view)
                .collect(),
            messaging_status: self.messaging.transport_status(),
            history: self.persistent_state.history.clone(),
        })
    }

    pub fn import_master_seed(
        &mut self,
        master_seed: &str,
    ) -> Result<SeedImportSummary, WalletError> {
        let normalized = validate_master_seed_input(master_seed)?;
        self.import_seed_material(SeedImportKind::MasterSeed, normalized)
    }

    pub fn import_mnemonic(&mut self, mnemonic: &str) -> Result<SeedImportSummary, WalletError> {
        let normalized = validate_mnemonic_input(mnemonic)?;
        self.import_seed_material(SeedImportKind::Mnemonic, normalized)
    }

    pub fn open_helper_session(&mut self) -> Result<HelperSessionBundle, WalletError> {
        self.ensure_session_active()?;
        let now = self.clock.now();
        let seed = self.active_seed_material()?;
        let session = HelperSession {
            helper_session_id: random_token(),
            network: self.network,
            seed_kind: seed.kind,
            opened_at: now,
            last_activity_at: now,
        };
        let bundle = HelperSessionBundle {
            session: session.clone().into_view(),
            seed,
            services: self.services.clone(),
        };
        self.session.helper_session = Some(session);
        self.record_history("open-helper-session", "opened official midnight helper session");
        self.persist()?;
        Ok(bundle)
    }

    pub fn close_helper_session(&mut self) -> Result<(), WalletError> {
        if self.session.helper_session.take().is_some() {
            self.record_history("close-helper-session", "closed official midnight helper session");
            self.persist()?;
        }
        Ok(())
    }

    pub fn grant_origin(&mut self, mut grant: BridgeOriginGrant) -> Result<(), WalletError> {
        grant.authorized_at = self.clock.now();
        self.persistent_state
            .grants
            .retain(|existing| existing.origin != grant.origin);
        self.persistent_state.grants.push(grant.clone());
        self.persistent_state
            .grants
            .sort_by(|left, right| left.origin.cmp(&right.origin));
        self.record_history("grant-origin", &format!("authorized {}", grant.origin));
        self.persist()
    }

    pub fn revoke_origin(&mut self, origin: &str) -> Result<(), WalletError> {
        self.persistent_state
            .grants
            .retain(|existing| existing.origin != origin);
        self.bridge_sessions
            .retain(|_, session| session.origin != origin);
        self.pending_approvals
            .retain(|_, pending| pending.origin != origin);
        self.approval_tokens
            .retain(|_, token| token.token.origin != origin);
        self.submission_grants
            .retain(|_, grant| grant.grant.origin != origin);
        self.record_history("revoke-origin", &format!("revoked {origin}"));
        self.persist()
    }

    pub fn open_bridge_session(&mut self, origin: &str) -> Result<String, WalletError> {
        let grant = self
            .persistent_state
            .grants
            .iter()
            .find(|grant| grant.origin == origin)
            .cloned()
            .ok_or_else(|| WalletError::OriginUnauthorized(origin.to_string()))?;
        let now = self.clock.now();
        let session = BridgeSession {
            session_id: random_token(),
            origin: origin.to_string(),
            scopes: grant.scopes,
            created_at: now,
            last_activity_at: now,
        };
        let session_id = session.session_id.clone();
        self.bridge_sessions.insert(session_id.clone(), session);
        self.record_history("open-bridge-session", &format!("opened session for {origin}"));
        self.persist()?;
        Ok(session_id)
    }

    pub fn begin_native_action(
        &mut self,
        review: TxReviewPayload,
    ) -> Result<PendingApprovalView, WalletError> {
        self.begin_pending(
            NATIVE_ORIGIN,
            None,
            ApprovalReviewPayload::transaction(review),
            None,
        )
    }

    pub fn begin_bridge_transfer(
        &mut self,
        session_id: &str,
        review: TxReviewPayload,
    ) -> Result<PendingApprovalView, WalletError> {
        self.begin_bridge_pending(
            session_id,
            review,
            BridgeScope::Transfer,
            ApprovalMethod::Transfer,
        )
    }

    pub fn begin_bridge_intent(
        &mut self,
        session_id: &str,
        review: TxReviewPayload,
    ) -> Result<PendingApprovalView, WalletError> {
        self.begin_bridge_pending(
            session_id,
            review,
            BridgeScope::Intent,
            ApprovalMethod::Intent,
        )
    }

    pub fn pending_review(&self, pending_id: &str) -> Result<PendingApprovalView, WalletError> {
        let pending = self
            .pending_approvals
            .get(pending_id)
            .cloned()
            .ok_or(WalletError::ApprovalRequired)?;
        if pending.is_expired(self.clock.now()) {
            return Err(WalletError::ApprovalExpired);
        }
        Ok(pending.into_view())
    }

    pub fn approve_pending(
        &mut self,
        pending_id: &str,
        primary_prompt: &str,
        secondary_prompt: Option<&str>,
    ) -> Result<ApprovalToken, WalletError> {
        self.ensure_session_active()?;
        let pending = self
            .pending_approvals
            .get(pending_id)
            .cloned()
            .ok_or(WalletError::ApprovalRequired)?;
        if pending.is_expired(self.clock.now()) {
            self.pending_approvals.remove(pending_id);
            self.record_history("approve-expired", &format!("expired {pending_id}"));
            self.persist()?;
            return Err(WalletError::ApprovalExpired);
        }

        self.authorizer.authenticate(self.network, primary_prompt)?;
        if self.requires_second_prompt(pending.review.method(), pending.review.night_total_raw())? {
            let prompt = secondary_prompt.ok_or_else(|| {
                WalletError::BridgePolicyViolation(
                    "large transfer requires a secondary biometric prompt".to_string(),
                )
            })?;
            self.authorizer.authenticate(self.network, prompt)?;
        }

        let now = self.clock.now();
        let token = ApprovalToken {
            token_id: random_token(),
            pending_id: pending.pending_id.clone(),
            origin: pending.origin.clone(),
            network: pending.review.network(),
            method: pending.review.method(),
            tx_digest: pending.review.tx_digest().to_string(),
            issued_at: now,
            expires_at: now + Duration::seconds(self.auth_policy.approval_ttl_seconds),
        };
        self.approval_tokens.insert(
            token.token_id.clone(),
            ApprovalTokenState {
                token: token.clone(),
                used: false,
            },
        );
        self.pending_approvals.remove(pending_id);
        self.record_history(
            "approve-pending",
            &format!("approved {} {}", method_label(token.method), token.tx_digest),
        );
        self.persist()?;
        Ok(token)
    }

    pub fn reject_pending(&mut self, pending_id: &str, reason: &str) -> Result<(), WalletError> {
        let pending = self
            .pending_approvals
            .remove(pending_id)
            .ok_or(WalletError::ApprovalRequired)?;
        self.record_history(
            "reject-pending",
            &format!("rejected {}: {}", pending.review.tx_digest(), reason),
        );
        self.persist()
    }

    pub fn consume_native_approval_token(
        &mut self,
        method: ApprovalMethod,
        tx_digest: &str,
        token: &ApprovalToken,
    ) -> Result<(), WalletError> {
        self.consume_approval_token(NATIVE_ORIGIN, method, tx_digest, token)
    }

    pub fn issue_native_submission_grant(
        &mut self,
        method: ApprovalMethod,
        tx_digest: &str,
        token: &ApprovalToken,
    ) -> Result<SubmissionGrant, WalletError> {
        self.issue_submission_grant(NATIVE_ORIGIN, method, tx_digest, token, None)
    }

    pub fn issue_bridge_submission_grant(
        &mut self,
        session_id: &str,
        method: ApprovalMethod,
        tx_digest: &str,
        token: &ApprovalToken,
    ) -> Result<SubmissionGrant, WalletError> {
        let session = self
            .bridge_sessions
            .get_mut(session_id)
            .ok_or_else(|| WalletError::OriginUnauthorized(session_id.to_string()))?;
        if !session.scopes.contains(&BridgeScope::Submit) {
            return Err(WalletError::BridgePolicyViolation(
                "bridge session is missing submit scope".to_string(),
            ));
        }
        session.last_activity_at = self.clock.now();
        let origin = session.origin.clone();
        self.issue_submission_grant(&origin, method, tx_digest, token, Some(session_id))
    }

    pub fn consume_native_submission_grant(
        &mut self,
        method: ApprovalMethod,
        tx_digest: &str,
        grant: &SubmissionGrant,
    ) -> Result<(), WalletError> {
        self.consume_submission_grant(NATIVE_ORIGIN, method, tx_digest, grant, None)
    }

    pub fn consume_bridge_submission_grant(
        &mut self,
        session_id: &str,
        method: ApprovalMethod,
        tx_digest: &str,
        grant: &SubmissionGrant,
    ) -> Result<(), WalletError> {
        let session = self
            .bridge_sessions
            .get_mut(session_id)
            .ok_or_else(|| WalletError::OriginUnauthorized(session_id.to_string()))?;
        if !session.scopes.contains(&BridgeScope::Submit) {
            return Err(WalletError::BridgePolicyViolation(
                "bridge session is missing submit scope".to_string(),
            ));
        }
        session.last_activity_at = self.clock.now();
        let origin = session.origin.clone();
        self.consume_submission_grant(&origin, method, tx_digest, grant, Some(session_id))
    }

    pub fn derive_auxiliary_key(&mut self, label: &str) -> Result<Vec<u8>, WalletError> {
        self.ensure_session_active()?;
        let seed = self.active_seed_material()?;
        let hk = Hkdf::<Sha384>::new(
            Some(self.network.as_str().as_bytes()),
            seed.value.as_bytes(),
        );
        let info = format!("ziros-midnight-wallet:v1:aux:{label}");
        let mut derived = Zeroizing::new(vec![0u8; 32]);
        hk.expand(info.as_bytes(), derived.as_mut_slice())
            .map_err(|_| WalletError::BridgePolicyViolation("failed to derive auxiliary key".to_string()))?;
        Ok(derived.to_vec())
    }

    pub fn messaging_prepare_open_channel(
        &mut self,
        request: WalletChannelOpenRequest,
    ) -> Result<PendingApprovalView, WalletError> {
        self.ensure_session_active()?;
        let review = self.messaging.prepare_open_channel(request)?;
        self.begin_pending(NATIVE_ORIGIN, None, review, None)
    }

    pub fn messaging_commit_open_channel(
        &mut self,
        token: &ApprovalToken,
    ) -> Result<ConversationView, WalletError> {
        self.ensure_session_active()?;
        let messaging_root = self.messaging_root()?;
        self.consume_native_approval_token(
            ApprovalMethod::OpenMessagingChannel,
            token.tx_digest.as_str(),
            token,
        )?;
        let view = self
            .messaging
            .commit_open_channel(messaging_root.as_slice(), token.tx_digest.as_str())?;
        self.record_history(
            "messaging-open-channel",
            &format!("opened messaging channel with {}", view.peer_id),
        );
        self.persist()?;
        Ok(view)
    }

    pub fn messaging_prepare_text(
        &mut self,
        peer_id: WalletPeerId,
        text: String,
    ) -> Result<PendingApprovalView, WalletError> {
        self.ensure_session_active()?;
        let review = self.messaging.prepare_text(peer_id, text)?;
        self.begin_pending(NATIVE_ORIGIN, None, review, None)
    }

    pub fn messaging_prepare_transfer_receipt(
        &mut self,
        peer_id: WalletPeerId,
        receipt: WalletTransferReceipt,
    ) -> Result<PendingApprovalView, WalletError> {
        self.ensure_session_active()?;
        let review = self.messaging.prepare_transfer_receipt(peer_id, receipt)?;
        self.begin_pending(NATIVE_ORIGIN, None, review, None)
    }

    pub fn messaging_prepare_credential_request(
        &mut self,
        peer_id: WalletPeerId,
        request: WalletCredentialRequest,
    ) -> Result<PendingApprovalView, WalletError> {
        self.ensure_session_active()?;
        let review = self.messaging.prepare_credential_request(peer_id, request)?;
        self.begin_pending(NATIVE_ORIGIN, None, review, None)
    }

    pub fn messaging_prepare_credential_response(
        &mut self,
        peer_id: WalletPeerId,
        response: WalletCredentialResponse,
    ) -> Result<PendingApprovalView, WalletError> {
        self.ensure_session_active()?;
        let review = self
            .messaging
            .prepare_credential_response(peer_id, response)?;
        self.begin_pending(NATIVE_ORIGIN, None, review, None)
    }

    pub fn messaging_commit_send_message(
        &mut self,
        token: &ApprovalToken,
    ) -> Result<PreparedMessage, WalletError> {
        self.ensure_session_active()?;
        let messaging_root = self.messaging_root()?;
        let mut prepared = self
            .messaging
            .commit_send_message(messaging_root.as_slice(), token.tx_digest.as_str())?;
        prepared.submission_grant = Some(
            self.issue_mailbox_post_grant_from_token(NATIVE_ORIGIN, &prepared, token)?,
        );
        self.record_history(
            "messaging-send-message",
            &format!(
                "prepared {} message for {}",
                method_label(ApprovalMethod::SendMessage),
                prepared.message.peer_id
            ),
        );
        self.persist()?;
        Ok(prepared)
    }

    pub fn messaging_receive_envelope(
        &mut self,
        envelope: MailboxEnvelope,
    ) -> Result<WalletMessage, WalletError> {
        self.ensure_session_active()?;
        let messaging_root = self.messaging_root()?;
        let message = self
            .messaging
            .receive_envelope(messaging_root.as_slice(), envelope)?;
        self.record_history(
            "messaging-receive-envelope",
            &format!("received {} message", message.peer_id),
        );
        self.persist()?;
        Ok(message)
    }

    pub fn messaging_poll_mailbox(&mut self) -> Result<MessagingTransportStatus, WalletError> {
        self.ensure_session_active()?;
        let status = self.messaging.poll_mailbox()?;
        self.persist()?;
        Ok(status)
    }

    pub fn messaging_update_transport_status(
        &mut self,
        update: MessagingTransportUpdate,
    ) -> Result<MessagingTransportStatus, WalletError> {
        self.ensure_session_active()?;
        let status = self.messaging.update_transport_status(update)?;
        self.persist()?;
        Ok(status)
    }

    pub fn messaging_complete_mailbox_post(
        &mut self,
        success: MailboxPostSuccess,
    ) -> Result<WalletMessage, WalletError> {
        self.ensure_session_active()?;
        let messaging_root = self.messaging_root()?;
        let message = self
            .messaging
            .complete_mailbox_post(messaging_root.as_slice(), success)?;
        self.record_history(
            "messaging-posted-message",
            &format!("posted mailbox message {}", message.envelope_hash),
        );
        self.persist()?;
        Ok(message)
    }

    pub fn messaging_fail_mailbox_post(
        &mut self,
        failure: MailboxPostFailure,
    ) -> Result<WalletMessage, WalletError> {
        self.ensure_session_active()?;
        let messaging_root = self.messaging_root()?;
        let message = self
            .messaging
            .fail_mailbox_post(messaging_root.as_slice(), failure)?;
        self.record_history(
            "messaging-failed-message",
            &format!("failed mailbox message {}", message.envelope_hash),
        );
        self.persist()?;
        Ok(message)
    }

    pub fn messaging_list_conversations(&mut self) -> Result<Vec<ConversationView>, WalletError> {
        self.ensure_session_active()?;
        Ok(self.messaging.list_conversations())
    }

    pub fn messaging_conversation(
        &mut self,
        peer_id: &WalletPeerId,
    ) -> Result<Vec<WalletMessage>, WalletError> {
        self.ensure_session_active()?;
        let messaging_root = self.messaging_root()?;
        self.messaging
            .conversation(messaging_root.as_slice(), peer_id)
    }

    pub fn messaging_channel_status(
        &mut self,
        peer_id: &WalletPeerId,
    ) -> Result<ChannelStatus, WalletError> {
        self.ensure_session_active()?;
        self.messaging.channel_status(peer_id)
    }

    pub fn messaging_close_channel(
        &mut self,
        peer_id: &WalletPeerId,
    ) -> Result<ChannelStatus, WalletError> {
        self.ensure_session_active()?;
        let status = self.messaging.close_channel(peer_id)?;
        self.record_history(
            "messaging-close-channel",
            &format!("closed messaging channel with {}", peer_id),
        );
        self.persist()?;
        Ok(status)
    }

    fn begin_bridge_pending(
        &mut self,
        session_id: &str,
        mut review: TxReviewPayload,
        required_scope: BridgeScope,
        expected_method: ApprovalMethod,
    ) -> Result<PendingApprovalView, WalletError> {
        let session = self
            .bridge_sessions
            .get_mut(session_id)
            .ok_or_else(|| WalletError::OriginUnauthorized(session_id.to_string()))?;
        if !session.scopes.contains(&required_scope) {
            return Err(WalletError::BridgePolicyViolation(format!(
                "bridge session is missing {} scope",
                scope_label(required_scope)
            )));
        }
        if review.method != expected_method {
            return Err(WalletError::BridgePolicyViolation(
                "review payload method does not match bridge entrypoint".to_string(),
            ));
        }
        if review.origin != session.origin {
            return Err(WalletError::BridgePolicyViolation(
                "review origin does not match the authorized bridge session".to_string(),
            ));
        }
        if review.network != self.network {
            return Err(WalletError::NetworkMismatch {
                expected: self.network.as_str().to_string(),
                actual: review.network.as_str().to_string(),
            });
        }
        review.origin = session.origin.clone();
        session.last_activity_at = self.clock.now();
        let origin = session.origin.clone();
        let scopes = session.scopes.clone();
        self.begin_pending(
            origin.as_str(),
            Some(session_id),
            ApprovalReviewPayload::transaction(review),
            Some(scopes),
        )
    }

    fn begin_pending(
        &mut self,
        origin: &str,
        session_id: Option<&str>,
        review: ApprovalReviewPayload,
        scopes: Option<BTreeSet<BridgeScope>>,
    ) -> Result<PendingApprovalView, WalletError> {
        if review.network() != self.network {
            return Err(WalletError::NetworkMismatch {
                expected: self.network.as_str().to_string(),
                actual: review.network().as_str().to_string(),
            });
        }
        if review.origin() != origin {
            return Err(WalletError::BridgePolicyViolation(
                "review origin mismatch".to_string(),
            ));
        }
        if !review.tx_digest().is_ascii() || review.tx_digest().trim().is_empty() {
            return Err(WalletError::BridgePolicyViolation(
                "transaction digest must be a non-empty ASCII token".to_string(),
            ));
        }
        if let Some(health) = &self.persistent_state.last_health
            && !health.proof_server.reachable
            && matches!(
                review.method(),
                ApprovalMethod::Transfer
                    | ApprovalMethod::Intent
                    | ApprovalMethod::Shield
                    | ApprovalMethod::Unshield
                    | ApprovalMethod::DustRegister
                    | ApprovalMethod::DustDeregister
                    | ApprovalMethod::DustRedesignate
            )
        {
            return Err(WalletError::ProofServerUnavailable);
        }
        let now = self.clock.now();
        let pending = PendingApproval {
            pending_id: random_token(),
            origin: origin.to_string(),
            session_id: session_id.map(ToString::to_string),
            scopes,
            created_at: now,
            expires_at: now + Duration::seconds(self.auth_policy.approval_ttl_seconds),
            review,
        };
        let view = pending.clone().into_view();
        self.pending_approvals
            .insert(pending.pending_id.clone(), pending);
        self.record_history("create-pending", &format!("created pending approval for {origin}"));
        self.persist()?;
        Ok(view)
    }

    fn consume_approval_token(
        &mut self,
        expected_origin: &str,
        method: ApprovalMethod,
        tx_digest: &str,
        token: &ApprovalToken,
    ) -> Result<(), WalletError> {
        self.maybe_relock_on_idle()?;
        if token.origin != expected_origin {
            return Err(WalletError::OriginUnauthorized(token.origin.clone()));
        }
        if token.network != self.network {
            return Err(WalletError::NetworkMismatch {
                expected: self.network.as_str().to_string(),
                actual: token.network.as_str().to_string(),
            });
        }
        if token.method != method {
            return Err(WalletError::BridgePolicyViolation(
                "approval token method mismatch".to_string(),
            ));
        }
        if token.tx_digest != tx_digest {
            return Err(WalletError::TxDigestMismatch {
                expected: token.tx_digest.clone(),
                actual: tx_digest.to_string(),
            });
        }
        let state = self
            .approval_tokens
            .get_mut(&token.token_id)
            .ok_or(WalletError::ApprovalRequired)?;
        if state.used {
            return Err(WalletError::BridgePolicyViolation(
                "approval token has already been consumed".to_string(),
            ));
        }
        if state.token != *token {
            return Err(WalletError::BridgePolicyViolation(
                "approval token payload mismatch".to_string(),
            ));
        }
        if token.expires_at < self.clock.now() {
            return Err(WalletError::ApprovalExpired);
        }
        state.used = true;
        self.record_history(
            "consume-approval-token",
            &format!("consumed {} approval token for {}", method_label(method), tx_digest),
        );
        self.persist()
    }

    fn issue_submission_grant(
        &mut self,
        expected_origin: &str,
        method: ApprovalMethod,
        tx_digest: &str,
        token: &ApprovalToken,
        session_id: Option<&str>,
    ) -> Result<SubmissionGrant, WalletError> {
        self.maybe_relock_on_idle()?;
        if token.origin != expected_origin {
            return Err(WalletError::OriginUnauthorized(token.origin.clone()));
        }
        if token.network != self.network {
            return Err(WalletError::NetworkMismatch {
                expected: self.network.as_str().to_string(),
                actual: token.network.as_str().to_string(),
            });
        }
        if token.method != method {
            return Err(WalletError::BridgePolicyViolation(
                "approval token method mismatch".to_string(),
            ));
        }
        if token.tx_digest != tx_digest {
            return Err(WalletError::TxDigestMismatch {
                expected: token.tx_digest.clone(),
                actual: tx_digest.to_string(),
            });
        }

        let state = self
            .approval_tokens
            .get_mut(&token.token_id)
            .ok_or(WalletError::ApprovalRequired)?;
        if state.used {
            return Err(WalletError::BridgePolicyViolation(
                "approval token has already been consumed".to_string(),
            ));
        }
        if state.token != *token {
            return Err(WalletError::BridgePolicyViolation(
                "approval token payload mismatch".to_string(),
            ));
        }
        if token.expires_at < self.clock.now() {
            return Err(WalletError::ApprovalExpired);
        }
        state.used = true;
        let now = self.clock.now();
        let grant = SubmissionGrant {
            grant_id: random_token(),
            token_id: token.token_id.clone(),
            origin: token.origin.clone(),
            network: token.network,
            method: token.method,
            tx_digest: token.tx_digest.clone(),
            issued_at: now,
            expires_at: now + Duration::seconds(self.auth_policy.approval_ttl_seconds),
        };
        self.submission_grants.insert(
            grant.grant_id.clone(),
            SubmissionGrantState {
                grant: grant.clone(),
                used: false,
            },
        );
        self.record_history(
            "issue-submission-grant",
            &format!(
                "issued {} submission grant for {}{}",
                method_label(method),
                tx_digest,
                session_id
                    .map(|value| format!(" via {value}"))
                    .unwrap_or_default()
            ),
        );
        self.persist()?;
        Ok(grant)
    }

    fn issue_mailbox_post_grant_from_token(
        &mut self,
        expected_origin: &str,
        prepared: &PreparedMessage,
        token: &ApprovalToken,
    ) -> Result<SubmissionGrant, WalletError> {
        self.maybe_relock_on_idle()?;
        if token.origin != expected_origin {
            return Err(WalletError::OriginUnauthorized(token.origin.clone()));
        }
        if token.network != self.network {
            return Err(WalletError::NetworkMismatch {
                expected: self.network.as_str().to_string(),
                actual: token.network.as_str().to_string(),
            });
        }
        if token.method != ApprovalMethod::SendMessage {
            return Err(WalletError::BridgePolicyViolation(
                "approval token method mismatch".to_string(),
            ));
        }
        let state = self
            .approval_tokens
            .get_mut(&token.token_id)
            .ok_or(WalletError::ApprovalRequired)?;
        if state.used {
            return Err(WalletError::BridgePolicyViolation(
                "approval token has already been consumed".to_string(),
            ));
        }
        if state.token != *token {
            return Err(WalletError::BridgePolicyViolation(
                "approval token payload mismatch".to_string(),
            ));
        }
        if token.expires_at < self.clock.now() {
            return Err(WalletError::ApprovalExpired);
        }

        state.used = true;
        let now = self.clock.now();
        let grant = SubmissionGrant {
            grant_id: random_token(),
            token_id: token.token_id.clone(),
            origin: token.origin.clone(),
            network: token.network,
            method: ApprovalMethod::SendMessage,
            tx_digest: prepared.message.envelope_hash.clone(),
            issued_at: now,
            expires_at: now + Duration::seconds(self.auth_policy.approval_ttl_seconds),
        };
        self.submission_grants.insert(
            grant.grant_id.clone(),
            SubmissionGrantState {
                grant: grant.clone(),
                used: false,
            },
        );
        self.record_history(
            "issue-mailbox-post-grant",
            &format!("issued send-message grant for {}", prepared.message.envelope_hash),
        );
        self.persist()?;
        Ok(grant)
    }

    fn consume_submission_grant(
        &mut self,
        expected_origin: &str,
        method: ApprovalMethod,
        tx_digest: &str,
        grant: &SubmissionGrant,
        session_id: Option<&str>,
    ) -> Result<(), WalletError> {
        self.maybe_relock_on_idle()?;
        if grant.origin != expected_origin {
            return Err(WalletError::OriginUnauthorized(grant.origin.clone()));
        }
        if grant.network != self.network {
            return Err(WalletError::NetworkMismatch {
                expected: self.network.as_str().to_string(),
                actual: grant.network.as_str().to_string(),
            });
        }
        if grant.method != method {
            return Err(WalletError::BridgePolicyViolation(
                "submission grant method mismatch".to_string(),
            ));
        }
        if grant.tx_digest != tx_digest {
            return Err(WalletError::TxDigestMismatch {
                expected: grant.tx_digest.clone(),
                actual: tx_digest.to_string(),
            });
        }
        let state = self
            .submission_grants
            .get_mut(&grant.grant_id)
            .ok_or(WalletError::ApprovalRequired)?;
        if state.used {
            return Err(WalletError::BridgePolicyViolation(
                "submission grant has already been consumed".to_string(),
            ));
        }
        if state.grant != *grant {
            return Err(WalletError::BridgePolicyViolation(
                "submission grant payload mismatch".to_string(),
            ));
        }
        if grant.expires_at < self.clock.now() {
            return Err(WalletError::ApprovalExpired);
        }
        state.used = true;
        self.record_history(
            "consume-submission-grant",
            &format!(
                "consumed {} submission grant for {}{}",
                method_label(method),
                tx_digest,
                session_id
                    .map(|value| format!(" via {value}"))
                    .unwrap_or_default()
            ),
        );
        self.persist()
    }

    fn requires_second_prompt(
        &self,
        method: ApprovalMethod,
        amount_raw: Option<&str>,
    ) -> Result<bool, WalletError> {
        if method != ApprovalMethod::Transfer {
            return Ok(false);
        }
        let amount = amount_raw
            .map(parse_raw_amount)
            .transpose()?
            .unwrap_or_default();
        let threshold = parse_raw_amount(self.auth_policy.large_transfer_threshold_raw.as_str())?;
        Ok(amount > threshold)
    }

    fn ensure_session_active(&mut self) -> Result<(), WalletError> {
        self.maybe_relock_on_idle()?;
        if !self.session.unlocked {
            return Err(WalletError::AuthRequired);
        }
        self.session.last_activity_at = Some(self.clock.now());
        if let Some(helper_session) = &mut self.session.helper_session {
            helper_session.last_activity_at = self.clock.now();
        }
        Ok(())
    }

    fn maybe_relock_on_idle(&mut self) -> Result<(), WalletError> {
        if !self.session.unlocked {
            return Ok(());
        }
        let Some(last_activity) = self.session.last_activity_at else {
            self.lock_internal();
            return Err(WalletError::Locked);
        };
        let now = self.clock.now();
        if now - last_activity >= Duration::seconds(self.auth_policy.relock_timeout_seconds) {
            self.lock_internal();
            self.record_history("idle-lock", "wallet locked after idle timeout");
            self.persist()?;
            return Err(WalletError::AuthRequired);
        }
        Ok(())
    }

    fn lock_internal(&mut self) {
        self.session = SessionState::default();
        self.messaging.clear_volatile();
    }

    fn active_seed_material(&self) -> Result<SeedImportMaterial, WalletError> {
        self.session
            .seed_material
            .clone()
            .ok_or(WalletError::AuthRequired)
    }

    fn import_seed_material(
        &mut self,
        kind: SeedImportKind,
        value: String,
    ) -> Result<SeedImportSummary, WalletError> {
        let now = self.clock.now();
        self.authorizer.ensure_material(self.network)?;
        let material = SeedImportMaterial {
            kind,
            value,
            imported_at: now,
        };
        self.seed_store.store_seed_material(self.network, &material)?;
        self.persistent_state.imported_seed_kind = Some(kind);
        self.persistent_state.imported_seed_at = Some(now);
        self.record_history("import-seed", &format!("imported {}", seed_kind_label(kind)));
        self.persist()?;
        Ok(SeedImportSummary {
            network: self.network,
            kind,
            imported_at: now,
        })
    }

    fn persist(&mut self) -> Result<(), WalletError> {
        self.persistent_state.updated_at = self.clock.now();
        self.state_store.save(&self.persistent_state)
    }

    fn record_history(&mut self, kind: &str, detail: &str) {
        self.persistent_state.history.push(WalletHistoryEntry {
            at: self.clock.now(),
            kind: kind.to_string(),
            detail: detail.to_string(),
        });
        if self.persistent_state.history.len() > 128 {
            let excess = self.persistent_state.history.len() - 128;
            self.persistent_state.history.drain(0..excess);
        }
    }

    fn messaging_root(&mut self) -> Result<Vec<u8>, WalletError> {
        self.derive_auxiliary_key("messaging")
    }
}

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("locked: wallet is locked")]
    Locked,
    #[error("auth_required: wallet authentication is required")]
    AuthRequired,
    #[error("biometric_failed: biometric authentication failed: {0}")]
    BiometricFailed(String),
    #[error("approval_required: a pending approval is required")]
    ApprovalRequired,
    #[error("approval_expired: the approval window has expired")]
    ApprovalExpired,
    #[error("origin_unauthorized: {0}")]
    OriginUnauthorized(String),
    #[error("network_mismatch: expected {expected}, got {actual}")]
    NetworkMismatch { expected: String, actual: String },
    #[error("tx_digest_mismatch: expected {expected}, got {actual}")]
    TxDigestMismatch { expected: String, actual: String },
    #[error("proof_server_unavailable: proof server is unavailable")]
    ProofServerUnavailable,
    #[error("bridge_policy_violation: {0}")]
    BridgePolicyViolation(String),
    #[error("storage: {0}")]
    Storage(#[from] io::Error),
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

pub trait SeedStore: Send + Sync {
    fn store_seed_material(
        &self,
        network: WalletNetwork,
        material: &SeedImportMaterial,
    ) -> Result<(), WalletError>;
    fn unlock_seed_material(
        &self,
        network: WalletNetwork,
        prompt: &str,
    ) -> Result<SeedImportMaterial, WalletError>;
}

#[derive(Debug, Clone)]
pub struct KeyManagerSeedStore {
    manager: KeyManager,
}

impl KeyManagerSeedStore {
    pub fn new() -> Result<Self, WalletError> {
        Ok(Self {
            manager: KeyManager::new().map_err(WalletError::Storage)?,
        })
    }
}

impl SeedStore for KeyManagerSeedStore {
    fn store_seed_material(
        &self,
        network: WalletNetwork,
        material: &SeedImportMaterial,
    ) -> Result<(), WalletError> {
        let serialized = serde_json::to_vec(material).map_err(|error| {
            WalletError::BridgePolicyViolation(format!(
                "failed to serialize imported seed material: {error}"
            ))
        })?;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            store_secure_seed_item(network, serialized.as_slice()).map_err(WalletError::Storage)?;
            let _ = self
                .manager
                .delete_key(master_seed_account(network).as_str(), master_seed_service(network).as_str());
            Ok(())
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let service = master_seed_service(network);
            let account = master_seed_account(network);
            self.manager
                .store_key(account.as_str(), service.as_str(), serialized.as_slice())
                .map_err(WalletError::Storage)
        }
    }

    fn unlock_seed_material(
        &self,
        network: WalletNetwork,
        prompt: &str,
    ) -> Result<SeedImportMaterial, WalletError> {
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        {
            match retrieve_secure_seed_item(network, Some(prompt)) {
                Ok(seed) => decode_seed_material(seed, network),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    let service = master_seed_service(network);
                    let account = master_seed_account(network);
                    let legacy = match self.manager.retrieve_key(account.as_str(), service.as_str()) {
                        Ok(seed) => seed,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {
                            return Err(WalletError::BridgePolicyViolation(
                                "wallet seed import required before unlock".to_string(),
                            ));
                        }
                        Err(error) => return Err(WalletError::Storage(error)),
                    };
                    store_secure_seed_item(network, legacy.as_slice()).map_err(WalletError::Storage)?;
                    let _ = self.manager.delete_key(account.as_str(), service.as_str());
                    decode_seed_material(legacy, network)
                }
                Err(error) => Err(WalletError::BiometricFailed(error.to_string())),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "ios")))]
        {
            let service = master_seed_service(network);
            let account = master_seed_account(network);
            let seed = self
                .manager
                .retrieve_key(account.as_str(), service.as_str())
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::NotFound {
                        WalletError::BridgePolicyViolation(
                            "wallet seed import required before unlock".to_string(),
                        )
                    } else {
                        WalletError::Storage(error)
                    }
                })?;
            decode_seed_material(seed, network)
        }
    }
}

pub trait BiometricAuthorizer: Send + Sync {
    fn ensure_material(&self, network: WalletNetwork) -> Result<(), WalletError>;
    fn authenticate(&self, network: WalletNetwork, prompt: &str) -> Result<(), WalletError>;
}

#[derive(Debug)]
pub struct SystemBiometricAuthorizer;

#[cfg(any(target_os = "macos", target_os = "ios"))]
impl BiometricAuthorizer for SystemBiometricAuthorizer {
    fn ensure_material(&self, network: WalletNetwork) -> Result<(), WalletError> {
        create_biometric_gate_item(network)
    }

    fn authenticate(&self, network: WalletNetwork, prompt: &str) -> Result<(), WalletError> {
        authenticate_biometric_gate_item(network, prompt)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
impl BiometricAuthorizer for SystemBiometricAuthorizer {
    fn ensure_material(&self, _network: WalletNetwork) -> Result<(), WalletError> {
        Err(WalletError::BiometricFailed(
            "strict device biometrics are only available on Apple platforms".to_string(),
        ))
    }

    fn authenticate(&self, _network: WalletNetwork, _prompt: &str) -> Result<(), WalletError> {
        Err(WalletError::BiometricFailed(
            "strict device biometrics are only available on Apple platforms".to_string(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalletPersistentState {
    schema: String,
    wallet_id: String,
    network: WalletNetwork,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    imported_seed_kind: Option<SeedImportKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    imported_seed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    grants: Vec<BridgeOriginGrant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_health: Option<ServiceHealthSnapshot>,
    #[serde(default)]
    history: Vec<WalletHistoryEntry>,
}

impl WalletPersistentState {
    fn new(network: WalletNetwork, now: DateTime<Utc>) -> Self {
        Self {
            schema: WALLET_STATE_SCHEMA.to_string(),
            wallet_id: WALLET_ID.to_string(),
            network,
            created_at: now,
            updated_at: now,
            imported_seed_kind: None,
            imported_seed_at: None,
            grants: Vec::new(),
            last_health: None,
            history: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct SessionState {
    unlocked: bool,
    unlocked_at: Option<DateTime<Utc>>,
    last_activity_at: Option<DateTime<Utc>>,
    seed_material: Option<SeedImportMaterial>,
    helper_session: Option<HelperSession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HelperSession {
    helper_session_id: String,
    network: WalletNetwork,
    seed_kind: SeedImportKind,
    opened_at: DateTime<Utc>,
    last_activity_at: DateTime<Utc>,
}

impl HelperSession {
    fn into_view(self) -> HelperSessionView {
        HelperSessionView {
            helper_session_id: self.helper_session_id,
            network: self.network,
            seed_kind: self.seed_kind,
            opened_at: self.opened_at,
            last_activity_at: self.last_activity_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BridgeSession {
    session_id: String,
    origin: String,
    scopes: BTreeSet<BridgeScope>,
    created_at: DateTime<Utc>,
    last_activity_at: DateTime<Utc>,
}

impl BridgeSession {
    fn into_view(self) -> BridgeSessionView {
        BridgeSessionView {
            session_id: self.session_id,
            origin: self.origin,
            scopes: self.scopes,
            created_at: self.created_at,
            last_activity_at: self.last_activity_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingApproval {
    pending_id: String,
    origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scopes: Option<BTreeSet<BridgeScope>>,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    review: ApprovalReviewPayload,
}

impl PendingApproval {
    fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }

    fn into_view(self) -> PendingApprovalView {
        PendingApprovalView {
            pending_id: self.pending_id,
            origin: self.origin,
            network: self.review.network(),
            method: self.review.method(),
            tx_digest: self.review.tx_digest().to_string(),
            created_at: self.created_at,
            expires_at: self.expires_at,
            review: self.review,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ApprovalTokenState {
    token: ApprovalToken,
    used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SubmissionGrantState {
    grant: SubmissionGrant,
    used: bool,
}

#[derive(Debug, Clone)]
struct WalletStateStore {
    network: WalletNetwork,
    cloudfs: CloudFS,
}

impl WalletStateStore {
    fn new(network: WalletNetwork, cloudfs: CloudFS) -> Self {
        Self { network, cloudfs }
    }

    fn load(&self) -> Result<WalletPersistentState, WalletError> {
        let now = Utc::now();
        Ok(self
            .cloudfs
            .read_json::<WalletPersistentState>(self.state_path().as_str())
            .map_err(WalletError::Storage)?
            .unwrap_or_else(|| WalletPersistentState::new(self.network, now)))
    }

    fn save(&self, state: &WalletPersistentState) -> Result<(), WalletError> {
        self.cloudfs
            .write_json(self.state_path().as_str(), state)
            .map_err(WalletError::Storage)
    }

    fn state_path(&self) -> String {
        format!("wallets/midnight/{}/state.json", self.network.as_str())
    }
}

fn probe_endpoint(url: &str, checked_at: DateTime<Utc>) -> EndpointHealth {
    let agent = AgentBuilder::new()
        .timeout_connect(StdDuration::from_secs(DEFAULT_RPC_TIMEOUT_SECONDS))
        .timeout_read(StdDuration::from_secs(DEFAULT_RPC_TIMEOUT_SECONDS))
        .timeout_write(StdDuration::from_secs(DEFAULT_RPC_TIMEOUT_SECONDS))
        .build();
    match agent.get(url).call() {
        Ok(response) => EndpointHealth {
            url: url.to_string(),
            reachable: true,
            status_code: Some(response.status()),
            error: None,
            checked_at,
        },
        Err(ureq::Error::Status(status, _)) => EndpointHealth {
            url: url.to_string(),
            reachable: true,
            status_code: Some(status),
            error: None,
            checked_at,
        },
        Err(error) => EndpointHealth {
            url: url.to_string(),
            reachable: false,
            status_code: None,
            error: Some(error.to_string()),
            checked_at,
        },
    }
}

fn parse_raw_amount(raw: &str) -> Result<u128, WalletError> {
    raw.parse::<u128>().map_err(|_| {
        WalletError::BridgePolicyViolation(format!("invalid raw amount '{raw}'"))
    })
}

fn method_label(method: ApprovalMethod) -> &'static str {
    match method {
        ApprovalMethod::Transfer => "transfer",
        ApprovalMethod::Intent => "intent",
        ApprovalMethod::Submit => "submit",
        ApprovalMethod::Shield => "shield",
        ApprovalMethod::Unshield => "unshield",
        ApprovalMethod::DustRegister => "dust-register",
        ApprovalMethod::DustDeregister => "dust-deregister",
        ApprovalMethod::DustRedesignate => "dust-redesignate",
        ApprovalMethod::SignCredential => "sign-credential",
        ApprovalMethod::OpenMessagingChannel => "open-messaging-channel",
        ApprovalMethod::SendMessage => "send-message",
        ApprovalMethod::ExportSeed => "export-seed",
    }
}

fn scope_label(scope: BridgeScope) -> &'static str {
    match scope {
        BridgeScope::ReadConfig => "read-config",
        BridgeScope::ReadBalances => "read-balances",
        BridgeScope::ReadAddresses => "read-addresses",
        BridgeScope::ReadHistory => "read-history",
        BridgeScope::Transfer => "transfer",
        BridgeScope::Intent => "intent",
        BridgeScope::Submit => "submit",
    }
}

fn master_seed_service(network: WalletNetwork) -> String {
    format!("com.ziros.midnight.wallet.{}.master-seed", network.as_str())
}

fn master_seed_account(network: WalletNetwork) -> String {
    format!("{}-master-seed", network.as_str())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn secure_seed_service(network: WalletNetwork) -> String {
    format!("com.ziros.midnight.wallet.{}.secure-seed", network.as_str())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn secure_seed_account(network: WalletNetwork) -> String {
    format!("{}-secure-seed", network.as_str())
}

fn decode_seed_material(
    stored: Vec<u8>,
    _network: WalletNetwork,
) -> Result<SeedImportMaterial, WalletError> {
    if let Ok(material) = serde_json::from_slice::<SeedImportMaterial>(&stored) {
        return Ok(material);
    }

    if let Ok(value) = String::from_utf8(stored.clone()) {
        let trimmed = value.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(SeedImportMaterial {
                kind: SeedImportKind::MasterSeed,
                value: trimmed,
                imported_at: Utc::now(),
            });
        }
    }

    Ok(SeedImportMaterial {
        kind: SeedImportKind::MasterSeed,
        value: hex_encode(&stored),
        imported_at: Utc::now(),
    })
}

fn validate_master_seed_input(raw: &str) -> Result<String, WalletError> {
    let normalized = raw.trim();
    if normalized.len() < 32 || !normalized.is_ascii() {
        return Err(WalletError::BridgePolicyViolation(
            "master seed must be an ASCII secret with at least 32 characters".to_string(),
        ));
    }
    Ok(normalized.to_string())
}

fn validate_mnemonic_input(raw: &str) -> Result<String, WalletError> {
    let normalized = raw
        .split_whitespace()
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let word_count = normalized.split_whitespace().count();
    if !matches!(word_count, 12 | 15 | 18 | 21 | 24) {
        return Err(WalletError::BridgePolicyViolation(
            "mnemonic must contain 12, 15, 18, 21, or 24 words".to_string(),
        ));
    }
    Ok(normalized)
}

fn seed_kind_label(kind: SeedImportKind) -> &'static str {
    match kind {
        SeedImportKind::MasterSeed => "master-seed",
        SeedImportKind::Mnemonic => "mnemonic",
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn random_token() -> String {
    let mut bytes = [0u8; 24];
    OsRng.fill_bytes(&mut bytes);
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest.update(Utc::now().timestamp_nanos_opt().unwrap_or_default().to_le_bytes());
    format!("{:x}", digest.finalize())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn create_biometric_gate_item(network: WalletNetwork) -> Result<(), WalletError> {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework_sys::access_control::kSecAccessControlBiometryCurrentSet;
    use security_framework_sys::base::errSecDuplicateItem;
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable,
        kSecClass, kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::SecItemAdd;

    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlBiometryCurrentSet,
    )
    .map_err(|error| WalletError::BiometricFailed(error.to_string()))?;
    let service = biometric_gate_service(network);
    let account = biometric_gate_account(network);
    let payload = random_gate_payload();
    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            CFBoolean::from(false).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
            access_control.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(payload.as_slice()).into_CFType(),
        ),
    ];
    let dict = CFDictionary::from_CFType_pairs(&query);
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status == errSecDuplicateItem {
        Ok(())
    } else {
        cvt_status(status).map_err(WalletError::BiometricFailed)
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn authenticate_biometric_gate_item(
    network: WalletNetwork,
    prompt: &str,
) -> Result<(), WalletError> {
    match copy_biometric_gate_payload(network, prompt) {
        Ok(payload) => validate_biometric_gate_payload(payload),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            create_biometric_gate_item(network)?;
            let payload = copy_biometric_gate_payload(network, prompt)
                .map_err(|retry_error| WalletError::BiometricFailed(retry_error.to_string()))?;
            validate_biometric_gate_payload(payload)
        }
        Err(error) => Err(WalletError::BiometricFailed(error.to_string())),
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn copy_biometric_gate_payload(network: WalletNetwork, prompt: &str) -> io::Result<Vec<u8>> {
    use core_foundation::base::CFTypeRef;
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnData,
    };
    use security_framework_sys::keychain_item::SecItemCopyMatching;

    unsafe extern "C" {
        static kSecUseOperationPrompt: *const core_foundation::string::__CFString;
    }

    let service = biometric_gate_service(network);
    let account = biometric_gate_account(network);
    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            CFBoolean::from(false).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::from(true).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecUseOperationPrompt) },
            CFString::from(prompt).into_CFType(),
        ),
    ];
    let dict = CFDictionary::from_CFType_pairs(&query);
    let mut value: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut value) };
    if status == errSecItemNotFound {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing biometric gate item {service}/{account}"),
        ));
    }
    cvt_status(status).map_err(io::Error::other)?;
    if value.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing biometric gate item {service}/{account}"),
        ));
    }
    let data = unsafe { CFData::wrap_under_create_rule(value as _) };
    Ok(data.bytes().to_vec())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn validate_biometric_gate_payload(payload: Vec<u8>) -> Result<(), WalletError> {
    if payload.is_empty() {
        return Err(WalletError::BiometricFailed(
            "biometric gate item returned empty payload".to_string(),
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn random_gate_payload() -> Vec<u8> {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.to_vec()
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn store_secure_seed_item(network: WalletNetwork, bytes: &[u8]) -> io::Result<()> {
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework_sys::access_control::kSecAccessControlBiometryCurrentSet;
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrAccessControl, kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable,
        kSecClass, kSecClassGenericPassword, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemAdd, SecItemDelete};

    let access_control = SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenPasscodeSetThisDeviceOnly),
        kSecAccessControlBiometryCurrentSet,
    )
    .map_err(|error| io::Error::other(error.to_string()))?;
    let service = secure_seed_service(network);
    let account = secure_seed_account(network);
    let selector = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            CFBoolean::from(false).into_CFType(),
        ),
    ];
    let selector_dict = CFDictionary::from_CFType_pairs(&selector);
    let delete_status = unsafe { SecItemDelete(selector_dict.as_concrete_TypeRef()) };
    if delete_status != 0 && delete_status != errSecItemNotFound {
        cvt_status(delete_status).map_err(io::Error::other)?;
    }

    let query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            CFBoolean::from(false).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccessControl) },
            access_control.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecValueData) },
            CFData::from_buffer(bytes).into_CFType(),
        ),
    ];
    let dict = CFDictionary::from_CFType_pairs(&query);
    let status = unsafe { SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut()) };
    cvt_status(status).map_err(io::Error::other)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn retrieve_secure_seed_item(
    network: WalletNetwork,
    prompt: Option<&str>,
) -> io::Result<Vec<u8>> {
    use core_foundation::base::CFTypeRef;
    use core_foundation::base::TCFType;
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::string::CFString;
    use security_framework_sys::base::errSecItemNotFound;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrService, kSecAttrSynchronizable, kSecClass,
        kSecClassGenericPassword, kSecReturnData,
    };
    use security_framework_sys::keychain_item::SecItemCopyMatching;

    unsafe extern "C" {
        static kSecUseOperationPrompt: *const core_foundation::string::__CFString;
    }

    let service = secure_seed_service(network);
    let account = secure_seed_account(network);
    let mut query = vec![
        (
            unsafe { CFString::wrap_under_get_rule(kSecClass) },
            unsafe { CFString::wrap_under_get_rule(kSecClassGenericPassword) }.into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrService) },
            CFString::from(service.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrAccount) },
            CFString::from(account.as_str()).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecAttrSynchronizable) },
            CFBoolean::from(false).into_CFType(),
        ),
        (
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::from(true).into_CFType(),
        ),
    ];
    if let Some(prompt) = prompt {
        query.push((
            unsafe { CFString::wrap_under_get_rule(kSecUseOperationPrompt) },
            CFString::from(prompt).into_CFType(),
        ));
    }
    let dict = CFDictionary::from_CFType_pairs(&query);
    let mut value: CFTypeRef = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(dict.as_concrete_TypeRef(), &mut value) };
    if status == errSecItemNotFound {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing secure seed item {service}/{account}"),
        ));
    }
    cvt_status(status).map_err(io::Error::other)?;
    if value.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("missing secure seed item {service}/{account}"),
        ));
    }
    let data = unsafe { CFData::wrap_under_create_rule(value as _) };
    Ok(data.bytes().to_vec())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn biometric_gate_service(network: WalletNetwork) -> String {
    format!("com.ziros.midnight.wallet.{}.auth-gate", network.as_str())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn biometric_gate_account(network: WalletNetwork) -> String {
    format!("{}-auth-gate", network.as_str())
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn cvt_status(status: i32) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "Security.framework error {}",
            security_framework::base::Error::from_code(status)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[derive(Debug)]
    struct FixedClock {
        now: Arc<Mutex<DateTime<Utc>>>,
    }

    impl FixedClock {
        fn new(now: DateTime<Utc>) -> Self {
            Self {
                now: Arc::new(Mutex::new(now)),
            }
        }

        fn advance_seconds(&self, seconds: i64) {
            let mut guard = self.now.lock().expect("clock lock");
            *guard += Duration::seconds(seconds);
        }
    }

    impl Clock for FixedClock {
        fn now(&self) -> DateTime<Utc> {
            *self.now.lock().expect("clock lock")
        }
    }

    #[derive(Debug, Default)]
    struct MemorySeedStore {
        seeds: Mutex<HashMap<WalletNetwork, SeedImportMaterial>>,
    }

    impl SeedStore for MemorySeedStore {
        fn store_seed_material(
            &self,
            network: WalletNetwork,
            material: &SeedImportMaterial,
        ) -> Result<(), WalletError> {
            self.seeds
                .lock()
                .expect("seed lock")
                .insert(network, material.clone());
            Ok(())
        }

        fn unlock_seed_material(
            &self,
            network: WalletNetwork,
            _prompt: &str,
        ) -> Result<SeedImportMaterial, WalletError> {
            let guard = self.seeds.lock().expect("seed lock");
            guard
                .get(&network)
                .cloned()
                .ok_or_else(|| {
                    WalletError::BridgePolicyViolation(
                        "wallet seed import required before unlock".to_string(),
                    )
                })
        }
    }

    #[derive(Debug, Default)]
    struct CountingAuthorizer {
        ensures: Mutex<usize>,
        prompts: Mutex<Vec<String>>,
        fail: Mutex<bool>,
        fail_ensure: Mutex<bool>,
    }

    impl CountingAuthorizer {
        fn ensure_count(&self) -> usize {
            *self.ensures.lock().expect("ensure lock")
        }

        fn prompt_count(&self) -> usize {
            self.prompts.lock().expect("prompt lock").len()
        }

        fn recorded_prompts(&self) -> Vec<String> {
            self.prompts.lock().expect("prompt lock").clone()
        }
    }

    impl BiometricAuthorizer for Arc<CountingAuthorizer> {
        fn ensure_material(&self, _network: WalletNetwork) -> Result<(), WalletError> {
            if *self.fail_ensure.lock().expect("fail ensure lock") {
                return Err(WalletError::BiometricFailed(
                    "failed to provision biometric gate".to_string(),
                ));
            }
            *self.ensures.lock().expect("ensure lock") += 1;
            Ok(())
        }

        fn authenticate(&self, _network: WalletNetwork, prompt: &str) -> Result<(), WalletError> {
            if *self.fail.lock().expect("fail lock") {
                return Err(WalletError::BiometricFailed("rejected".to_string()));
            }
            self.prompts
                .lock()
                .expect("prompt lock")
                .push(prompt.to_string());
            Ok(())
        }
    }

    fn review(origin: &str, method: ApprovalMethod, night_total_raw: &str) -> TxReviewPayload {
        TxReviewPayload {
            origin: origin.to_string(),
            network: WalletNetwork::Preprod,
            method,
            tx_digest: format!("digest-{origin}-{night_total_raw}"),
            outputs: vec![ReviewOutput {
                recipient: "midnight1recipient".to_string(),
                token_kind: "NIGHT".to_string(),
                amount_raw: night_total_raw.to_string(),
            }],
            night_total_raw: night_total_raw.to_string(),
            dust_total_raw: "0".to_string(),
            fee_raw: "100".to_string(),
            dust_impact: None,
            shielded: true,
            prover_route: Some("proof-server".to_string()),
            warnings: vec!["review".to_string()],
            human_summary: "test review".to_string(),
        }
    }

    fn wallet_fixture(
        authorizer: Arc<CountingAuthorizer>,
        clock: FixedClock,
    ) -> WalletHandle {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        WalletHandle::with_components(
            WalletNetwork::Preprod,
            WalletServiceConfig::for_network(WalletNetwork::Preprod),
            AuthPolicy::default(),
            cloudfs,
            Box::new(authorizer),
            Box::new(MemorySeedStore::default()),
            Box::new(clock),
        )
        .expect("wallet fixture")
    }

    fn import_test_seed(wallet: &mut WalletHandle) {
        wallet
            .import_master_seed("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("import test seed");
    }

    #[test]
    fn second_prompt_is_required_for_large_transfer() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer.clone(), clock);
        import_test_seed(&mut wallet);
        wallet.unlock("Unlock").expect("unlock");
        let grant = BridgeOriginGrant {
            origin: "https://dapp.example".to_string(),
            scopes: BTreeSet::from([BridgeScope::Transfer, BridgeScope::Submit]),
            authorized_at: Utc::now(),
            note: None,
        };
        wallet.grant_origin(grant).expect("grant");
        let session = wallet
            .open_bridge_session("https://dapp.example")
            .expect("session");
        let pending = wallet
            .begin_bridge_transfer(
                session.as_str(),
                review("https://dapp.example", ApprovalMethod::Transfer, "100000000000000001"),
            )
            .expect("pending");
        let token = wallet
            .approve_pending(
                pending.pending_id.as_str(),
                "Approve transfer",
                Some("Approve large transfer"),
            )
            .expect("token");
        let grant = wallet
            .issue_bridge_submission_grant(
                session.as_str(),
                ApprovalMethod::Transfer,
                token.tx_digest.as_str(),
                &token,
            )
            .expect("grant");
        wallet
            .consume_bridge_submission_grant(
                session.as_str(),
                ApprovalMethod::Transfer,
                token.tx_digest.as_str(),
                &grant,
            )
            .expect("consume grant");
        assert_eq!(authorizer.prompt_count(), 2);
        assert_eq!(
            authorizer.recorded_prompts(),
            vec![
                "Approve transfer".to_string(),
                "Approve large transfer".to_string()
            ]
        );
    }

    #[test]
    fn replayed_approval_token_is_rejected() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer, clock);
        import_test_seed(&mut wallet);
        wallet.unlock("Unlock").expect("unlock");
        let grant = BridgeOriginGrant {
            origin: "https://dapp.example".to_string(),
            scopes: BTreeSet::from([BridgeScope::Transfer, BridgeScope::Submit]),
            authorized_at: Utc::now(),
            note: None,
        };
        wallet.grant_origin(grant).expect("grant");
        let session = wallet
            .open_bridge_session("https://dapp.example")
            .expect("session");
        let pending = wallet
            .begin_bridge_transfer(
                session.as_str(),
                review("https://dapp.example", ApprovalMethod::Transfer, "10"),
            )
            .expect("pending");
        let token = wallet
            .approve_pending(pending.pending_id.as_str(), "Approve transfer", None)
            .expect("token");
        let grant = wallet
            .issue_bridge_submission_grant(
                session.as_str(),
                ApprovalMethod::Transfer,
                token.tx_digest.as_str(),
                &token,
            )
            .expect("grant");
        wallet
            .consume_bridge_submission_grant(
                session.as_str(),
                ApprovalMethod::Transfer,
                grant.tx_digest.as_str(),
                &grant,
            )
            .expect("first submit");
        let error = wallet
            .consume_bridge_submission_grant(
                session.as_str(),
                ApprovalMethod::Transfer,
                grant.tx_digest.as_str(),
                &grant,
            )
            .expect_err("replay should fail");
        assert!(matches!(error, WalletError::BridgePolicyViolation(_)));
    }

    #[test]
    fn origin_mismatch_is_rejected() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer, clock);
        let grant = BridgeOriginGrant {
            origin: "https://dapp.example".to_string(),
            scopes: BTreeSet::from([BridgeScope::Transfer]),
            authorized_at: Utc::now(),
            note: None,
        };
        wallet.grant_origin(grant).expect("grant");
        let session = wallet
            .open_bridge_session("https://dapp.example")
            .expect("session");
        let error = wallet
            .begin_bridge_transfer(
                session.as_str(),
                review("https://evil.example", ApprovalMethod::Transfer, "10"),
            )
            .expect_err("origin mismatch should fail");
        assert!(matches!(error, WalletError::BridgePolicyViolation(_)));
    }

    #[test]
    fn idle_relock_blocks_sensitive_operations() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer, FixedClock { now: clock.now.clone() });
        import_test_seed(&mut wallet);
        wallet.unlock("Unlock").expect("unlock");
        clock.advance_seconds(DEFAULT_RELOCK_TIMEOUT_SECONDS + 1);
        let error = wallet
            .authorize_operation(ApprovalMethod::Shield, "Shield", None, None)
            .expect_err("idle relock should force auth");
        assert!(matches!(error, WalletError::AuthRequired));
        assert!(wallet.snapshot().expect("snapshot").locked);
    }

    #[test]
    fn auxiliary_domains_are_distinct() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer, clock);
        import_test_seed(&mut wallet);
        wallet.unlock("Unlock").expect("unlock");
        let messaging = wallet
            .derive_auxiliary_key("messaging")
            .expect("messaging key");
        let swarm = wallet.derive_auxiliary_key("swarm").expect("swarm key");
        assert_ne!(messaging, swarm);
    }

    #[test]
    fn token_digest_mismatch_fails_closed() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer, clock);
        import_test_seed(&mut wallet);
        wallet.unlock("Unlock").expect("unlock");
        let pending = wallet
            .begin_native_action(review(NATIVE_ORIGIN, ApprovalMethod::Transfer, "10"))
            .expect("pending");
        let token = wallet
            .approve_pending(pending.pending_id.as_str(), "Approve transfer", None)
            .expect("token");
        let grant = wallet
            .issue_native_submission_grant(
                ApprovalMethod::Transfer,
                token.tx_digest.as_str(),
                &token,
            )
            .expect("grant");
        let error = wallet
            .consume_native_submission_grant(ApprovalMethod::Transfer, "mutated-digest", &grant)
            .expect_err("digest mismatch should fail");
        assert!(matches!(error, WalletError::TxDigestMismatch { .. }));
    }

    #[test]
    fn unlock_requires_imported_seed_material() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer, clock);
        let error = wallet.unlock("Unlock").expect_err("unlock should fail without import");
        assert!(matches!(error, WalletError::BridgePolicyViolation(_)));
    }

    #[test]
    fn import_provisions_biometric_material_before_persisting_seed() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer.clone(), clock);
        import_test_seed(&mut wallet);
        assert_eq!(authorizer.ensure_count(), 1);
        assert!(wallet.snapshot().expect("snapshot").has_imported_seed);
    }

    #[test]
    fn import_fails_closed_when_biometric_material_cannot_be_provisioned() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        *authorizer
            .fail_ensure
            .lock()
            .expect("fail ensure lock") = true;
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer, clock);
        let error = wallet
            .import_master_seed(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect_err("import should fail when biometric provisioning fails");
        assert!(matches!(error, WalletError::BiometricFailed(_)));
        assert!(!wallet.snapshot().expect("snapshot").has_imported_seed);
    }

    #[test]
    fn helper_session_is_cleared_on_lock() {
        let authorizer = Arc::new(CountingAuthorizer::default());
        let clock = FixedClock::new(Utc::now());
        let mut wallet = wallet_fixture(authorizer, clock);
        wallet
            .import_mnemonic(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            )
            .expect("import mnemonic");
        wallet.unlock("Unlock").expect("unlock");
        let helper = wallet.open_helper_session().expect("helper session");
        assert_eq!(helper.seed.kind, SeedImportKind::Mnemonic);
        assert!(wallet.snapshot().expect("snapshot").helper_session.is_some());
        wallet.lock().expect("lock");
        assert!(wallet.snapshot().expect("snapshot").helper_session.is_none());
    }
}
