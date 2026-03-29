//! WorkerService: accept assignments, execute locally, return results.

use crate::bundle::DistributedExecutionBundle;
use crate::config::ClusterConfig;
use crate::error::DistributedError;
use crate::execution::execute_assignment_with_capability;
use crate::identity::{NodeCapability, PROTOCOL_VERSION, PeerId, SWARM_PROTOCOL_VERSION};
use crate::protocol::{
    AssignAckMsg, AttestationChainMsg, AttestationMetadata, EncryptedThreatEnvelopeMsg,
    HandshakeAckMsg, HeartbeatAckMsg, MessageBody, SubgraphFailedMsg, SubgraphResultMsg,
    WireMessage, heartbeat_ack_signing_bytes, heartbeat_signing_bytes,
};
use crate::swarm::{
    Diplomat, LocalPeerIdentity, PeerThreatChannel, ReputationEvidence, ReputationEvidenceKind,
    ReputationTracker, SwarmEpochManager, ThreatIntelPayload, admission_pow_identity_bytes,
    attestation_signing_bytes, decode_threat_digest, has_plaintext_threat_surface,
    local_identity_label, output_digest, persist_attestation_chain,
    persist_threat_intelligence_outcome, trace_digest, verify_admission_pow,
};
use crate::transfer::BufferTransferManager;
use crate::transport::{Connection, Transport, create_transport};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;
use zkf_runtime::swarm::{SentinelState, SwarmConfig, SwarmController};

struct PendingAssignment {
    bundle: DistributedExecutionBundle,
    input_boundary_slots: Vec<u32>,
}

#[derive(Default)]
struct ThreatIntelWireSurface {
    threat_digests: Vec<crate::protocol::ThreatDigestMsg>,
    activation_level: Option<u8>,
    intelligence_root: Option<String>,
    local_pressure: Option<f64>,
    network_pressure: Option<f64>,
    encrypted_threat_payload: Option<EncryptedThreatEnvelopeMsg>,
}

/// A worker node that accepts and executes subgraph assignments from a coordinator.
pub struct WorkerService {
    config: ClusterConfig,
    swarm_config: SwarmConfig,
    transport: Box<dyn Transport>,
    transport_note: Option<String>,
    transfer_manager: BufferTransferManager,
    local_capability: NodeCapability,
    swarm_identity: LocalPeerIdentity,
    swarm_controller: SwarmController,
    diplomat: Diplomat,
    reputation: ReputationTracker,
    sentinel: Option<SentinelState>,
    shutdown: Arc<AtomicBool>,
    admitted_swarm_peers: BTreeMap<String, u128>,
    admitted_swarm_capabilities: HashMap<String, NodeCapability>,
    peer_threat_channels: BTreeMap<String, PeerThreatChannel>,
    threat_epoch_manager: SwarmEpochManager,
    sequence: u64,
    assignments: HashMap<(String, u32), PendingAssignment>,
    received_boundary_buffers: HashMap<String, HashMap<u32, Vec<u8>>>,
    partition_failures_once: HashMap<u32, String>,
}

impl WorkerService {
    pub fn new(config: ClusterConfig) -> Result<Self, DistributedError> {
        if !ClusterConfig::is_enabled() {
            return Err(DistributedError::Disabled);
        }

        let resolved = create_transport(config.transport)?;
        let transfer_manager = BufferTransferManager::new(&config);
        let swarm_config = SwarmConfig::from_env();
        let mut local_capability = NodeCapability::local();
        let identity_label =
            local_identity_label(&local_capability.hostname, config.bind_addr.port());
        let swarm_identity = LocalPeerIdentity::load_or_create(&swarm_config, &identity_label)
            .map_err(|err| DistributedError::Config(err.to_string()))?;
        local_capability.peer_id = swarm_identity.stable_peer_id();
        local_capability.ed25519_public_key = swarm_identity.public_key_bytes();
        local_capability.signature_scheme = Some(swarm_identity.signature_scheme());
        local_capability.public_key_bundle = Some(swarm_identity.public_key_bundle());
        let swarm_controller = if swarm_config.enabled {
            SwarmController::new(swarm_config.clone())
        } else {
            SwarmController::disabled()
        };
        let diplomat = Diplomat::new(swarm_config.gossip_max_digests_per_heartbeat);
        let reputation = ReputationTracker::new(&swarm_config)
            .map_err(|err| DistributedError::Config(err.to_string()))?;
        let sentinel = swarm_config.enabled.then(|| {
            let source_peer = local_capability
                .ed25519_public_key
                .as_slice()
                .try_into()
                .unwrap_or([0; 32]);
            let mut sentinel = SentinelState::new(&swarm_config.sentinel, source_peer);
            sentinel.set_source_peer_id(local_capability.peer_id.0.clone());
            sentinel
        });

        Ok(Self {
            config,
            swarm_config,
            transport: resolved.transport,
            transport_note: resolved.fallback_note,
            transfer_manager,
            local_capability,
            swarm_identity,
            swarm_controller,
            diplomat,
            reputation,
            sentinel,
            shutdown: Arc::new(AtomicBool::new(false)),
            admitted_swarm_peers: BTreeMap::new(),
            admitted_swarm_capabilities: HashMap::new(),
            peer_threat_channels: BTreeMap::new(),
            threat_epoch_manager: SwarmEpochManager::new(),
            sequence: 0,
            assignments: HashMap::new(),
            received_boundary_buffers: HashMap::new(),
            partition_failures_once: HashMap::new(),
        })
    }

    /// Get a handle to signal shutdown.
    pub fn shutdown_handle(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    pub fn transport_name(&self) -> &'static str {
        self.transport.name()
    }

    pub fn transport_note(&self) -> Option<&str> {
        self.transport_note.as_deref()
    }

    fn register_admitted_swarm_peer(&mut self, peer_id: &PeerId) -> Result<(), DistributedError> {
        let now_ms = unix_time_now_ms();
        self.admitted_swarm_peers
            .retain(|_, seen_at| now_ms.saturating_sub(*seen_at) <= 2 * 60 * 60 * 1000);
        if self.admitted_swarm_peers.contains_key(&peer_id.0) {
            return Ok(());
        }
        let recent_cutoff = now_ms.saturating_sub(60 * 60 * 1000);
        let new_peers_in_last_hour = self
            .admitted_swarm_peers
            .values()
            .filter(|seen_at| **seen_at >= recent_cutoff)
            .count();
        let established_peer_count = self
            .admitted_swarm_peers
            .values()
            .filter(|seen_at| **seen_at < recent_cutoff)
            .count()
            .max(1);
        let allowed_new_peers = established_peer_count
            .saturating_mul(self.swarm_config.max_new_peers_per_hour_multiplier.max(1));
        if new_peers_in_last_hour >= allowed_new_peers {
            return Err(DistributedError::HandshakeFailed {
                peer_id: peer_id.0.clone(),
                reason: format!(
                    "admission rate limit exceeded: {} new peers in the last hour with {} established peers",
                    new_peers_in_last_hour, established_peer_count
                ),
            });
        }
        self.admitted_swarm_peers.insert(peer_id.0.clone(), now_ms);
        Ok(())
    }

    fn local_threat_epoch_advertisement(&mut self) -> crate::swarm::ThreatEpochAdvertisement {
        if !self.swarm_config.enabled {
            return crate::swarm::ThreatEpochAdvertisement::default();
        }
        self.threat_epoch_manager.current_advertisement()
    }

    fn note_peer_threat_advertisement(
        &mut self,
        peer_id: &PeerId,
        remote_support: bool,
        epoch_id: Option<u64>,
        public_key: Option<&[u8]>,
        entry_kind: Option<&str>,
    ) {
        if !self.swarm_config.enabled {
            return;
        }
        let result = self
            .peer_threat_channels
            .entry(peer_id.0.clone())
            .or_default()
            .update_from_advertisement(
                true,
                remote_support,
                epoch_id,
                public_key,
                unix_time_now_secs(),
            );
        if let Err(err) = result {
            self.record_peer_threat_intel_failure(
                peer_id,
                entry_kind.unwrap_or("encrypted-threat-intel-auth-failure"),
                &err.to_string(),
            );
        }
    }

    fn prepare_threat_wire_surface(
        &mut self,
        peer_id: &PeerId,
        message_kind: &str,
        sequence: u64,
    ) -> ThreatIntelWireSurface {
        if !self.swarm_config.enabled {
            return ThreatIntelWireSurface::default();
        }
        let Some(channel) = self.peer_threat_channels.get(&peer_id.0).cloned() else {
            return ThreatIntelWireSurface::default();
        };
        if !channel.remote_supports_encryption || !channel.encrypted_negotiated {
            return ThreatIntelWireSurface::default();
        }
        let swarm_telemetry = self.swarm_controller.telemetry_digest();
        let payload = self.diplomat.drain_threat_payload(
            Some(self.swarm_controller.activation_level() as u8),
            swarm_telemetry.as_ref(),
        );
        if payload.is_empty() {
            return ThreatIntelWireSurface::default();
        }
        match self.threat_epoch_manager.encrypt_for_peer(
            unix_time_now_secs(),
            &self.local_capability.peer_id,
            peer_id,
            message_kind,
            sequence,
            &channel,
            &payload,
        ) {
            Ok(encrypted_threat_payload) => ThreatIntelWireSurface {
                encrypted_threat_payload: Some(encrypted_threat_payload),
                ..ThreatIntelWireSurface::default()
            },
            Err(err) => {
                self.record_peer_threat_intel_failure(
                    peer_id,
                    "encrypted-threat-intel-auth-failure",
                    &err.to_string(),
                );
                ThreatIntelWireSurface::default()
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_threat_wire_surface(
        &mut self,
        sender: &PeerId,
        capability: &NodeCapability,
        message_kind: &str,
        sequence: u64,
        digests: &[crate::protocol::ThreatDigestMsg],
        activation_level: Option<u8>,
        intelligence_root: Option<&str>,
        local_pressure: Option<f64>,
        network_pressure: Option<f64>,
        encrypted_threat_payload: Option<&EncryptedThreatEnvelopeMsg>,
    ) -> Option<ThreatIntelPayload> {
        if !self.swarm_config.enabled {
            return None;
        }
        let channel = self
            .peer_threat_channels
            .get(&sender.0)
            .cloned()
            .unwrap_or_default();
        let plaintext_present = has_plaintext_threat_surface(
            digests,
            activation_level,
            intelligence_root,
            local_pressure,
            network_pressure,
        );
        if channel.encrypted_negotiated {
            if plaintext_present {
                self.record_peer_threat_intel_failure(
                    sender,
                    "encrypted-threat-intel-auth-failure",
                    "plaintext threat intelligence was sent after encrypted negotiation completed",
                );
                return None;
            }
            let envelope = encrypted_threat_payload?;
            match self.threat_epoch_manager.decrypt_from_peer(
                unix_time_now_secs(),
                sender,
                &self.local_capability.peer_id,
                message_kind,
                sequence,
                &channel,
                envelope,
            ) {
                Ok(payload) => Some(payload),
                Err(err) => {
                    self.record_peer_threat_intel_failure(
                        &capability.peer_id,
                        "encrypted-threat-intel-auth-failure",
                        &err.to_string(),
                    );
                    None
                }
            }
        } else {
            if plaintext_present || encrypted_threat_payload.is_some() {
                let reason = if channel.remote_supports_encryption {
                    "threat intelligence was sent before encrypted gossip negotiation completed"
                } else {
                    "threat intelligence is disabled when peers do not support encrypted gossip"
                };
                self.record_peer_threat_intel_failure(
                    &capability.peer_id,
                    "encrypted-threat-intel-auth-failure",
                    reason,
                );
            }
            None
        }
    }

    fn ingest_threat_payload(
        &mut self,
        sender: &PeerId,
        capability: &NodeCapability,
        payload: &ThreatIntelPayload,
        heartbeat: bool,
    ) -> String {
        let ingest = if heartbeat {
            self.diplomat.ingest_verified_heartbeat(
                sender,
                &capability.ed25519_public_key,
                capability.public_key_bundle.as_ref(),
                &payload.digests,
                payload.activation_level,
            )
        } else {
            self.diplomat.ingest_verified_threat_gossip(
                sender,
                &capability.ed25519_public_key,
                capability.public_key_bundle.as_ref(),
                &crate::protocol::ThreatGossipMsg {
                    digests: payload.digests.clone(),
                    activation_level: payload.activation_level,
                    intelligence_root: payload.intelligence_root.clone(),
                    local_pressure: payload.local_pressure,
                    network_pressure: payload.network_pressure,
                    encrypted_threat_payload: None,
                },
            )
        };
        let runtime_digests = ingest
            .accepted_digests
            .iter()
            .map(decode_threat_digest)
            .collect::<Vec<_>>();
        if !runtime_digests.is_empty() {
            self.swarm_controller.record_digests(&runtime_digests);
        }
        if let Some(pressure) = combine_pressure(payload.local_pressure, payload.network_pressure) {
            self.swarm_controller.record_peer_pressure(
                sender.0.clone(),
                payload.activation_level.unwrap_or_default(),
                pressure,
                self.reputation.score_for(sender),
            );
        }
        ingest.intelligence_root
    }

    fn record_peer_threat_intel_failure(
        &mut self,
        peer_id: &PeerId,
        entry_kind: &str,
        reason: &str,
    ) {
        let observed_at_unix_ms = unix_time_now_ms();
        let _ = self.reputation.record_event(
            peer_id,
            ReputationEvidenceKind::ThreatDigestContradicted,
            ReputationEvidence {
                observed_at_unix_ms,
                ..Default::default()
            },
        );
        let payload = serde_json::json!({
            "peer_id": peer_id.0,
            "reason": reason,
            "observed_at_unix_ms": observed_at_unix_ms,
        });
        let _ = persist_threat_intelligence_outcome(
            &self.swarm_config,
            entry_kind,
            &self.local_capability.peer_id.0,
            &[],
            "auth-failure",
            &payload,
        );
    }

    fn persist_peer_threat_intelligence(
        &mut self,
        peer_id: &PeerId,
        entry_kind: &str,
        intelligence_root: &str,
        payload: &ThreatIntelPayload,
    ) {
        let payload = serde_json::json!({
            "peer_id": peer_id.0,
            "digest_count": payload.digests.len(),
            "activation_level": payload.activation_level,
            "intelligence_root": payload.intelligence_root,
            "local_pressure": payload.local_pressure,
            "network_pressure": payload.network_pressure,
        });
        let _ = persist_threat_intelligence_outcome(
            &self.swarm_config,
            entry_kind,
            &self.local_capability.peer_id.0,
            &[],
            intelligence_root,
            &payload,
        );
    }

    fn send_handshake_rejection(
        &mut self,
        conn: &mut dyn Connection,
        reason: impl Into<String>,
    ) -> Result<(), DistributedError> {
        let ack = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::HandshakeAck(HandshakeAckMsg {
                capability: self.local_capability.clone(),
                accepted: false,
                reason: Some(reason.into()),
                ed25519_public_key: Vec::new(),
                handshake_signature: Vec::new(),
                public_key_bundle: None,
                handshake_signature_bundle: None,
                swarm_protocol_version: 0,
                encrypted_threat_gossip_supported: false,
                threat_epoch_id: None,
                threat_epoch_public_key: None,
            }),
        };
        self.sequence += 1;
        conn.send(&ack)
    }

    fn verify_attestation_chain(&self, chain: &AttestationChainMsg) -> bool {
        chain.attestations.iter().all(|attestation| {
            LocalPeerIdentity::verify_signed_message(
                &attestation.public_key,
                attestation.public_key_bundle.as_ref(),
                &attestation_signing_bytes(
                    &chain.job_id,
                    chain.partition_id,
                    attestation.output_digest,
                    attestation.trace_digest,
                    attestation.activation_level,
                ),
                &attestation.signature,
                attestation.signature_bundle.as_ref(),
            )
        })
    }

    /// Inject a single partition failure on the next matching execute request.
    /// This is used by integration tests to verify local retry semantics.
    pub fn inject_partition_failure_once(&mut self, partition_id: u32, reason: impl Into<String>) {
        self.partition_failures_once
            .insert(partition_id, reason.into());
    }

    /// Run the worker listen loop (blocking).
    pub fn run(&mut self) -> Result<(), DistributedError> {
        let mut listener = self.transport.listen(self.config.bind_addr)?;
        if let Some(note) = &self.transport_note {
            log::warn!("{note}");
        }
        log::info!(
            "worker listening on {} via {} (peer_id: {})",
            listener.local_addr(),
            self.transport.name(),
            self.local_capability.peer_id,
        );

        while !self.shutdown.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok(conn) => {
                    if let Err(e) = self.handle_connection(conn) {
                        log::warn!("connection handler error: {e}");
                    }
                }
                Err(e) => {
                    if self.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    log::warn!("accept error: {e}");
                }
            }
        }

        log::info!("worker shutting down");
        Ok(())
    }

    fn handle_connection(&mut self, mut conn: Box<dyn Connection>) -> Result<(), DistributedError> {
        let remote = conn.remote_addr();
        log::debug!("accepted connection from {remote}");

        loop {
            let msg = match conn.recv(Some(Duration::from_secs(30))) {
                Ok(m) => m,
                Err(DistributedError::Io(_)) => {
                    log::debug!("connection from {remote} closed");
                    break;
                }
                Err(e) => {
                    log::warn!("recv error from {remote}: {e}");
                    break;
                }
            };
            let message_sequence = msg.sequence;

            match msg.body {
                MessageBody::Handshake(ref hs) => {
                    self.handle_handshake(&mut *conn, &msg.sender, hs)?;
                }
                MessageBody::Heartbeat(ref hb) => {
                    if !self.ingest_heartbeat(&msg.sender, hb, message_sequence) {
                        log::warn!("ignoring unsigned or invalid heartbeat from {}", msg.sender);
                        continue;
                    }
                    self.handle_heartbeat(&mut *conn, &msg.sender)?;
                }
                MessageBody::AssignSubgraph(ref assign) => {
                    self.handle_assign(&mut *conn, &msg.sender, assign)?;
                }
                MessageBody::TransferRequest(ref req) => {
                    let (data, _stats) = self.transfer_manager.recv_buffer(
                        &mut *conn,
                        &self.local_capability.peer_id,
                        req,
                        &mut self.sequence,
                    )?;
                    self.received_boundary_buffers
                        .entry(req.job_id.clone())
                        .or_default()
                        .insert(req.slot, data);
                    log::debug!(
                        "received boundary buffer slot {} ({} bytes) from {}",
                        req.slot,
                        req.total_bytes,
                        msg.sender
                    );
                }
                MessageBody::ExecuteSubgraph(ref exec) => {
                    self.handle_execute(&mut *conn, &msg.sender, exec)?;
                }
                MessageBody::JobAbort(ref abort) => {
                    self.cleanup_job(&abort.job_id);
                    log::info!("job {} aborted: {}", abort.job_id, abort.reason);
                    break;
                }
                MessageBody::JobComplete(ref complete) => {
                    self.cleanup_job(&complete.job_id);
                    log::debug!("job {} completed", complete.job_id);
                    break;
                }
                MessageBody::ThreatGossip(ref gossip) => {
                    if let Some(capability) = self.admitted_swarm_capabilities.get(&msg.sender.0) {
                        let peer = capability.clone();
                        if let Some(payload) = self.decode_threat_wire_surface(
                            &msg.sender,
                            &peer,
                            "threat-gossip",
                            message_sequence,
                            &gossip.digests,
                            gossip.activation_level,
                            gossip.intelligence_root.as_deref(),
                            gossip.local_pressure,
                            gossip.network_pressure,
                            gossip.encrypted_threat_payload.as_ref(),
                        ) {
                            let intelligence_root =
                                self.ingest_threat_payload(&msg.sender, &peer, &payload, false);
                            self.persist_peer_threat_intelligence(
                                &msg.sender,
                                "encrypted-threat-intelligence",
                                &intelligence_root,
                                &payload,
                            );
                        }
                    }
                }
                MessageBody::AttestationChain(ref chain) => {
                    if self.verify_attestation_chain(chain) {
                        let _ = persist_attestation_chain(&self.swarm_config, chain);
                    } else {
                        log::warn!(
                            "ignoring invalid attestation chain for job {} partition {} from {}",
                            chain.job_id,
                            chain.partition_id,
                            msg.sender
                        );
                    }
                }
                _ => {
                    log::debug!("ignoring unexpected message type from {remote}");
                }
            }
        }

        Ok(())
    }

    fn handle_handshake(
        &mut self,
        conn: &mut dyn Connection,
        sender: &PeerId,
        hs: &crate::protocol::HandshakeMsg,
    ) -> Result<(), DistributedError> {
        if hs.swarm_protocol_version >= SWARM_PROTOCOL_VERSION
            && !hs.ed25519_public_key.is_empty()
            && !hs.handshake_signature.is_empty()
            && !LocalPeerIdentity::verify_signed_message(
                &hs.ed25519_public_key,
                hs.public_key_bundle.as_ref(),
                &handshake_signing_bytes(
                    &hs.capability,
                    hs.swarm_protocol_version,
                    hs.encrypted_threat_gossip_supported,
                    hs.threat_epoch_id,
                    hs.threat_epoch_public_key.as_deref(),
                ),
                &hs.handshake_signature,
                hs.handshake_signature_bundle.as_ref(),
            )
        {
            self.send_handshake_rejection(conn, "invalid swarm handshake signature")?;
            return Ok(());
        }
        let admission_identity =
            admission_pow_identity_bytes(&hs.ed25519_public_key, hs.public_key_bundle.as_ref());
        if self.swarm_config.enabled
            && !verify_admission_pow(
                &admission_identity,
                hs.admission_pow_nonce.unwrap_or_default(),
                self.swarm_config.admission_pow_difficulty,
            )
        {
            self.send_handshake_rejection(conn, "invalid admission proof-of-work")?;
            return Ok(());
        }
        if let Err(err) = self.register_admitted_swarm_peer(sender) {
            self.send_handshake_rejection(conn, err.to_string())?;
            return Ok(());
        }
        self.note_peer_threat_advertisement(
            sender,
            hs.encrypted_threat_gossip_supported,
            hs.threat_epoch_id,
            hs.threat_epoch_public_key.as_deref(),
            Some("encrypted-threat-intel-advertisement"),
        );
        let threat_advertisement = self.local_threat_epoch_advertisement();
        let signing_bytes = handshake_signing_bytes(
            &self.local_capability,
            SWARM_PROTOCOL_VERSION,
            threat_advertisement.encrypted_threat_gossip_supported,
            threat_advertisement.threat_epoch_id,
            threat_advertisement.threat_epoch_public_key.as_deref(),
        );
        let handshake_signature = self.swarm_identity.sign(&signing_bytes);
        let handshake_signature_bundle = self.swarm_identity.sign_bundle(&signing_bytes);
        let mut capability = hs.capability.clone();
        if capability.ed25519_public_key.is_empty() {
            capability.ed25519_public_key = hs.ed25519_public_key.clone();
        }
        if capability.public_key_bundle.is_none() {
            capability.public_key_bundle = hs.public_key_bundle.clone();
        }
        if capability.signature_scheme.is_none() {
            capability.signature_scheme = hs.public_key_bundle.as_ref().map(|bundle| bundle.scheme);
        }
        self.admitted_swarm_capabilities
            .insert(sender.0.clone(), capability);
        let ack = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::HandshakeAck(HandshakeAckMsg {
                capability: self.local_capability.clone(),
                accepted: true,
                reason: None,
                ed25519_public_key: self.local_capability.ed25519_public_key.clone(),
                handshake_signature,
                public_key_bundle: self.local_capability.public_key_bundle.clone(),
                handshake_signature_bundle: Some(handshake_signature_bundle),
                swarm_protocol_version: if self.swarm_config.enabled {
                    SWARM_PROTOCOL_VERSION
                } else {
                    0
                },
                encrypted_threat_gossip_supported: threat_advertisement
                    .encrypted_threat_gossip_supported,
                threat_epoch_id: threat_advertisement.threat_epoch_id,
                threat_epoch_public_key: threat_advertisement.threat_epoch_public_key,
            }),
        };
        self.sequence += 1;
        conn.send(&ack)?;
        log::info!("handshake completed with peer {sender}");
        Ok(())
    }

    fn handle_heartbeat(
        &mut self,
        conn: &mut dyn Connection,
        sender: &PeerId,
    ) -> Result<(), DistributedError> {
        let threat_advertisement = self.local_threat_epoch_advertisement();
        let threat_surface =
            self.prepare_threat_wire_surface(sender, "heartbeat-ack", self.sequence);
        let mut heartbeat_ack = HeartbeatAckMsg {
            acknowledged: true,
            encrypted_threat_gossip_supported: threat_advertisement
                .encrypted_threat_gossip_supported,
            threat_epoch_id: threat_advertisement.threat_epoch_id,
            threat_epoch_public_key: threat_advertisement.threat_epoch_public_key,
            threat_digests: threat_surface.threat_digests,
            activation_level: threat_surface.activation_level,
            intelligence_root: threat_surface.intelligence_root,
            local_pressure: threat_surface.local_pressure,
            network_pressure: threat_surface.network_pressure,
            encrypted_threat_payload: threat_surface.encrypted_threat_payload,
            signature_bundle: None,
        };
        let signing_bytes = heartbeat_ack_signing_bytes(&heartbeat_ack);
        heartbeat_ack.signature_bundle = Some(self.swarm_identity.sign_bundle(&signing_bytes));
        let ack = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::HeartbeatAck(heartbeat_ack),
        };
        self.sequence += 1;
        conn.send(&ack)?;
        Ok(())
    }

    fn handle_assign(
        &mut self,
        conn: &mut dyn Connection,
        _sender: &PeerId,
        assign: &crate::protocol::AssignSubgraphMsg,
    ) -> Result<(), DistributedError> {
        let bundle = match DistributedExecutionBundle::decode_postcard(&assign.subgraph_data) {
            Ok(bundle) => bundle,
            Err(err) => {
                self.send_assign_ack(
                    conn,
                    assign.job_id.clone(),
                    assign.partition_id,
                    false,
                    Some(err.to_string()),
                )?;
                return Ok(());
            }
        };

        log::info!(
            "assigned partition {} of job {} ({} work units, {} graph nodes)",
            assign.partition_id,
            assign.job_id,
            assign.estimated_work,
            bundle.graph_nodes.len(),
        );
        self.assignments.insert(
            (assign.job_id.clone(), assign.partition_id),
            PendingAssignment {
                bundle,
                input_boundary_slots: assign
                    .input_boundary_slots
                    .iter()
                    .map(|(slot, _)| *slot)
                    .collect(),
            },
        );
        self.send_assign_ack(conn, assign.job_id.clone(), assign.partition_id, true, None)
    }

    fn handle_execute(
        &mut self,
        conn: &mut dyn Connection,
        _sender: &PeerId,
        exec: &crate::protocol::ExecuteSubgraphMsg,
    ) -> Result<(), DistributedError> {
        log::info!(
            "executing partition {} of job {}",
            exec.partition_id,
            exec.job_id,
        );

        let key = (exec.job_id.clone(), exec.partition_id);
        let partition_id = exec.partition_id;
        let pending = match self.assignments.remove(&key) {
            Some(pending) => pending,
            None => {
                return self.send_failed_result(
                    conn,
                    &exec.job_id,
                    exec.partition_id,
                    "received execute request for an unknown assignment",
                );
            }
        };

        if let Some(reason) = self.partition_failures_once.remove(&partition_id) {
            return self.send_failed_result(conn, &exec.job_id, partition_id, &reason);
        }

        let boundary_buffers = match self
            .take_partition_input_buffers(&exec.job_id, &pending.input_boundary_slots)
        {
            Ok(buffers) => buffers,
            Err(err) => {
                return self.send_failed_result(conn, &exec.job_id, partition_id, &err.to_string());
            }
        };

        let job_id = exec.job_id.clone();
        let local_capability = self.local_capability.clone();
        let local_activation_level = self.swarm_controller.activation_level() as u8;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(execute_assignment_with_capability(
                &local_capability,
                pending.bundle,
                boundary_buffers,
                local_activation_level,
            ));
        });

        let heartbeat_poll = self
            .config
            .heartbeat_interval
            .min(Duration::from_millis(250))
            .max(Duration::from_millis(25));

        loop {
            match rx.try_recv() {
                Ok(Ok(executed)) => {
                    let attestation = self.build_attestation(
                        &job_id,
                        partition_id,
                        &executed.output_data,
                        &executed.named_outputs,
                        &executed.trace_entries,
                    );
                    self.collect_swarm_digests(&executed.node_traces);
                    let result = WireMessage {
                        version: PROTOCOL_VERSION,
                        sender: self.local_capability.peer_id.clone(),
                        sequence: self.sequence,
                        body: MessageBody::SubgraphResult(SubgraphResultMsg {
                            job_id: job_id.clone(),
                            partition_id,
                            output_data: executed.output_data,
                            named_outputs: executed.named_outputs,
                            compiled_program: executed
                                .compiled_program
                                .as_ref()
                                .map(serde_json::to_vec)
                                .transpose()?,
                            proof_artifact: executed
                                .proof_artifact
                                .as_ref()
                                .map(serde_json::to_vec)
                                .transpose()?,
                            wall_time_ms: executed.wall_time.as_millis() as u64,
                            trace_entries: executed.trace_entries,
                            final_trust_model: executed.final_trust_model,
                            peak_memory_bytes: executed.peak_memory_bytes,
                            attestation,
                        }),
                    };
                    self.sequence += 1;
                    conn.send(&result)?;
                    return Ok(());
                }
                Ok(Err(err)) => {
                    return self.send_failed_result(conn, &job_id, partition_id, &err.to_string());
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    return self.send_failed_result(
                        conn,
                        &job_id,
                        partition_id,
                        "worker execution channel disconnected unexpectedly",
                    );
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }

            match conn.recv(Some(heartbeat_poll)) {
                Ok(msg) => match msg.body {
                    MessageBody::Heartbeat(ref heartbeat) => {
                        if !self.ingest_heartbeat(&msg.sender, heartbeat, msg.sequence) {
                            log::warn!(
                                "ignoring unsigned or invalid heartbeat from {} while executing",
                                msg.sender
                            );
                            continue;
                        }
                        self.handle_heartbeat(conn, &msg.sender)?;
                    }
                    MessageBody::JobAbort(ref abort) => {
                        log::info!(
                            "job {} aborted during execution: {}",
                            abort.job_id,
                            abort.reason
                        );
                        return self.send_failed_result(
                            conn,
                            &job_id,
                            partition_id,
                            &format!("job aborted by coordinator: {}", abort.reason),
                        );
                    }
                    _ => {
                        log::debug!(
                            "ignoring message while partition {} of job {} is running",
                            partition_id,
                            job_id
                        );
                    }
                },
                Err(err) if is_timeout_error(&err) => {}
                Err(err) => return Err(err),
            }
        }
    }
}

impl WorkerService {
    fn send_assign_ack(
        &mut self,
        conn: &mut dyn Connection,
        job_id: String,
        partition_id: u32,
        accepted: bool,
        reason: Option<String>,
    ) -> Result<(), DistributedError> {
        let ack = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::AssignAck(AssignAckMsg {
                job_id,
                partition_id,
                accepted,
                reason,
            }),
        };
        self.sequence += 1;
        conn.send(&ack)?;
        Ok(())
    }

    fn take_partition_input_buffers(
        &mut self,
        job_id: &str,
        slots: &[u32],
    ) -> Result<HashMap<u32, Vec<u8>>, DistributedError> {
        if slots.is_empty() {
            return Ok(HashMap::new());
        }

        let Some(job_buffers) = self.received_boundary_buffers.get_mut(job_id) else {
            return Err(DistributedError::TransferFailed {
                slot: slots[0],
                reason: format!("missing boundary buffers for job {job_id}"),
            });
        };

        let mut resolved = HashMap::with_capacity(slots.len());
        for slot in slots {
            let data =
                job_buffers
                    .remove(slot)
                    .ok_or_else(|| DistributedError::TransferFailed {
                        slot: *slot,
                        reason: format!("missing transferred boundary buffer for job {job_id}"),
                    })?;
            resolved.insert(*slot, data);
        }

        if job_buffers.is_empty() {
            self.received_boundary_buffers.remove(job_id);
        }

        Ok(resolved)
    }

    fn cleanup_job(&mut self, job_id: &str) {
        self.assignments
            .retain(|(candidate, _), _| candidate != job_id);
        self.received_boundary_buffers.remove(job_id);
    }

    fn send_failed_result(
        &mut self,
        conn: &mut dyn Connection,
        job_id: &str,
        partition_id: u32,
        reason: &str,
    ) -> Result<(), DistributedError> {
        let result = WireMessage {
            version: PROTOCOL_VERSION,
            sender: self.local_capability.peer_id.clone(),
            sequence: self.sequence,
            body: MessageBody::SubgraphFailed(SubgraphFailedMsg {
                job_id: job_id.to_string(),
                partition_id,
                reason: reason.to_string(),
            }),
        };
        self.sequence += 1;
        conn.send(&result)?;
        Ok(())
    }

    fn ingest_heartbeat(
        &mut self,
        sender: &PeerId,
        heartbeat: &crate::protocol::HeartbeatMsg,
        message_sequence: u64,
    ) -> bool {
        if let Some(capability) = self.admitted_swarm_capabilities.get(&sender.0) {
            let signature_bundle = heartbeat.signature_bundle.as_ref();
            if signature_bundle.is_some()
                && !LocalPeerIdentity::verify_signed_message(
                    &capability.ed25519_public_key,
                    capability.public_key_bundle.as_ref(),
                    &heartbeat_signing_bytes(heartbeat),
                    &[],
                    signature_bundle,
                )
            {
                return false;
            }
            let capability = capability.clone();
            self.note_peer_threat_advertisement(
                sender,
                heartbeat.encrypted_threat_gossip_supported,
                heartbeat.threat_epoch_id,
                heartbeat.threat_epoch_public_key.as_deref(),
                Some("encrypted-threat-intel-advertisement"),
            );
            if let Some(payload) = self.decode_threat_wire_surface(
                sender,
                &capability,
                "heartbeat",
                message_sequence,
                &heartbeat.threat_digests,
                heartbeat.activation_level,
                heartbeat.intelligence_root.as_deref(),
                heartbeat.local_pressure,
                heartbeat.network_pressure,
                heartbeat.encrypted_threat_payload.as_ref(),
            ) {
                let intelligence_root =
                    self.ingest_threat_payload(sender, &capability, &payload, true);
                self.persist_peer_threat_intelligence(
                    sender,
                    "encrypted-threat-intelligence",
                    &intelligence_root,
                    &payload,
                );
            }
            return true;
        }
        false
    }

    fn collect_swarm_digests(&mut self, traces: &[zkf_runtime::NodeTrace]) {
        if !self.swarm_config.enabled {
            return;
        }
        let Some(sentinel) = self.sentinel.as_mut() else {
            return;
        };
        for trace in traces {
            let _ = sentinel.observe(trace, &self.swarm_config.sentinel);
        }
        let mut digests = sentinel.drain_digests();
        for digest in &mut digests {
            let signing_bytes = digest.signing_bytes();
            let signature_bundle = self.swarm_identity.sign_bundle(&signing_bytes);
            digest.signature = signature_bundle.ed25519.clone();
            digest.signature_bundle = Some(signature_bundle);
        }
        if !digests.is_empty() {
            self.diplomat.enqueue_runtime_digests(&digests);
            self.swarm_controller.record_digests(&digests);
        }
    }

    fn build_attestation(
        &self,
        job_id: &str,
        partition_id: u32,
        output_data: &[(u32, Vec<u8>)],
        named_outputs: &[(String, Vec<u8>)],
        trace_entries: &[crate::protocol::SubgraphTraceEntry],
    ) -> Option<AttestationMetadata> {
        if !self.swarm_config.enabled {
            return None;
        }
        let output_digest = output_digest(output_data, named_outputs);
        let trace_digest = trace_digest(trace_entries);
        let activation_level = Some(self.swarm_controller.activation_level() as u8);
        let signing_bytes = attestation_signing_bytes(
            job_id,
            partition_id,
            output_digest,
            trace_digest,
            activation_level,
        );
        let signature_bundle = self.swarm_identity.sign_bundle(&signing_bytes);
        let attestation = AttestationMetadata {
            signer_peer_id: self.local_capability.peer_id.0.clone(),
            public_key: self.local_capability.ed25519_public_key.clone(),
            public_key_bundle: self.local_capability.public_key_bundle.clone(),
            output_digest,
            trace_digest,
            signature: signature_bundle.ed25519.clone(),
            signature_bundle: Some(signature_bundle),
            activation_level,
        };
        let _ = persist_attestation_chain(
            &self.swarm_config,
            &AttestationChainMsg {
                job_id: job_id.to_string(),
                partition_id,
                attestations: vec![attestation.clone()],
            },
        );
        Some(attestation)
    }
}

fn is_timeout_error(err: &DistributedError) -> bool {
    match err {
        DistributedError::Io(message) => {
            let message = message.to_ascii_lowercase();
            message.contains("timed out")
                || message.contains("would block")
                || message.contains("temporarily unavailable")
        }
        _ => false,
    }
}

fn handshake_signing_bytes(
    capability: &NodeCapability,
    swarm_protocol_version: u32,
    encrypted_threat_gossip_supported: bool,
    threat_epoch_id: Option<u64>,
    threat_epoch_public_key: Option<&[u8]>,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(capability.peer_id.0.as_bytes());
    bytes.extend_from_slice(capability.hostname.as_bytes());
    bytes.extend_from_slice(&capability.protocol_version.to_le_bytes());
    bytes.extend_from_slice(&swarm_protocol_version.to_le_bytes());
    bytes.extend_from_slice(&capability.ed25519_public_key);
    if let Some(bundle) = &capability.public_key_bundle {
        bytes.extend_from_slice(&bundle.canonical_bytes());
    }
    crate::protocol::append_threat_epoch_advertisement_bytes(
        &mut bytes,
        encrypted_threat_gossip_supported,
        threat_epoch_id,
        threat_epoch_public_key,
    );
    bytes
}

fn unix_time_now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

fn unix_time_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or_default()
}

fn combine_pressure(local_pressure: Option<f64>, network_pressure: Option<f64>) -> Option<f64> {
    match (local_pressure, network_pressure) {
        (Some(local), Some(network)) => Some(local.max(network)),
        (Some(local), None) => Some(local),
        (None, Some(network)) => Some(network),
        (None, None) => None,
    }
}
