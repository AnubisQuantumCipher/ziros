use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use zkf_backends::backend_for;
use zkf_core::{BackendKind, generate_witness};
use zkf_distributed::protocol::{
    AttestationChainMsg, AttestationMetadata, ConsensusVoteMsg, ReputationRecordMsg,
    ReputationSyncMsg,
};
use zkf_distributed::swarm::{attestation_signing_bytes, persist_attestation_chain};
use zkf_distributed::{
    ConsensusCollector, Diplomat, LocalPeerIdentity, PeerId, ReputationEvidence,
    ReputationEvidenceKind, ReputationTracker,
};
use zkf_runtime::control_plane::{ControlPlaneRequest, finalize_control_plane_execution};
use zkf_runtime::swarm::builder::{promote_rule, record_shadow_observation, shadow_rule};
use zkf_runtime::swarm::sentinel::WelfordState;
use zkf_runtime::{
    ActivationLevel, AnomalySeverity, BuilderRuleRecord, DetectionCondition, DetectionRule,
    DevicePlacement, GraphExecutionReport, JobKind, NodeTrace, RuleState, RuntimeSecurityContext,
    SecurityAction, SecuritySupervisor, SentinelConfig, SentinelState, SwarmConfig,
    SwarmController, ThreatSignalKind, TrustModel, evaluate_control_plane,
};

static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn with_swarm_home<T>(f: impl FnOnce(&Path) -> T) -> T {
    let _guard = ENV_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let temp = tempfile::tempdir().unwrap();
    let previous = [
        ("HOME", std::env::var_os("HOME")),
        ("ZKF_SWARM", std::env::var_os("ZKF_SWARM")),
        (
            "ZKF_SWARM_KEY_BACKEND",
            std::env::var_os("ZKF_SWARM_KEY_BACKEND"),
        ),
        (
            "ZKF_SECURITY_POLICY_MODE",
            std::env::var_os("ZKF_SECURITY_POLICY_MODE"),
        ),
    ];
    unsafe {
        std::env::set_var("HOME", temp.path());
        std::env::set_var("ZKF_SWARM", "1");
        std::env::set_var("ZKF_SWARM_KEY_BACKEND", "file");
        std::env::set_var("ZKF_SECURITY_POLICY_MODE", "observe");
    }
    let result = f(temp.path());
    unsafe {
        for (key, value) in previous {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
    result
}

fn empty_report() -> GraphExecutionReport {
    GraphExecutionReport {
        node_traces: Vec::new(),
        total_wall_time: Duration::ZERO,
        peak_memory_bytes: 0,
        gpu_nodes: 0,
        cpu_nodes: 0,
        delegated_nodes: 0,
        final_trust_model: TrustModel::Cryptographic,
        fallback_nodes: 0,
        watchdog_alerts: Vec::new(),
    }
}

fn anomaly_trace(stage_key: &str, wall_time_ms: u64) -> NodeTrace {
    NodeTrace {
        node_id: zkf_runtime::NodeId::new(),
        op_name: "BackendProve",
        stage_key: stage_key.to_string(),
        placement: DevicePlacement::Cpu,
        trust_model: TrustModel::Cryptographic,
        wall_time: Duration::from_millis(wall_time_ms),
        problem_size: Some(1),
        input_bytes: 32,
        output_bytes: 32,
        predicted_cpu_ms: None,
        predicted_gpu_ms: None,
        prediction_confidence: None,
        prediction_observation_count: None,
        input_digest: [0; 8],
        output_digest: [1; 8],
        allocated_bytes_after: 0,
        accelerator_name: None,
        fell_back: false,
        buffer_residency: None,
        delegated: false,
        delegated_backend: None,
    }
}

fn write_rule_record(record: &BuilderRuleRecord) {
    let config = SwarmConfig::from_env();
    fs::create_dir_all(&config.rules_path).unwrap();
    let path = config.rules_path.join(format!("{}.json", record.rule.id));
    let bytes = serde_json::to_vec_pretty(record).unwrap();
    fs::write(path, bytes).unwrap();
}

fn test_rule_record(
    rule_id: &str,
    state: RuleState,
    action: SecurityAction,
    shadow_observation_count: u64,
    shadow_false_positive_rate: f64,
) -> BuilderRuleRecord {
    BuilderRuleRecord {
        rule: DetectionRule {
            id: rule_id.to_string(),
            condition: DetectionCondition::SignalBurst {
                kind: ThreatSignalKind::RuntimeAnomaly,
                count: 3,
                window_ms: 1_000,
            },
            action,
            confidence: 0.95,
            min_observations: 3,
        },
        state,
        created_unix_ms: 1,
        updated_unix_ms: 1,
        shadow_observation_count,
        shadow_false_positive_rate,
        history: vec![],
    }
}

#[test]
fn slow_poison_routes_to_control_plane_without_swarm_escalation() {
    with_swarm_home(|_| {
        let program = zkf_examples::mul_add_program();
        let request = ControlPlaneRequest::for_program(JobKind::Prove, None, Some(&program), None);
        let decision = evaluate_control_plane(&request);
        let expected_ms = decision
            .anomaly_baseline
            .expected_duration_ms
            .or(decision.duration_estimate.upper_bound_ms)
            .unwrap_or(1.0)
            .max(1.0);
        let report = GraphExecutionReport {
            total_wall_time: Duration::from_secs_f64((expected_ms * 12.0) / 1_000.0),
            cpu_nodes: 1,
            ..empty_report()
        };
        let summary = finalize_control_plane_execution(decision, &report, None);
        let swarm = SwarmController::new(SwarmConfig::from_env());

        assert_ne!(summary.anomaly_verdict.severity, AnomalySeverity::Normal);
        assert_eq!(swarm.activation_level(), ActivationLevel::Dormant);
        assert_eq!(swarm.verdict().threat_digest_count, 0);
    });
}

#[test]
fn flash_mob_requires_two_thirds_and_causes_dos_not_math_corruption() {
    let mut below_threshold = ConsensusCollector::new(1_000);
    let base = ConsensusVoteMsg {
        job_id: "job-flash".to_string(),
        partition_id: 0,
        voter_peer_id: "a".to_string(),
        severity: "high".to_string(),
        accepted: true,
        output_digest: [9; 32],
        recorded_unix_ms: 1,
    };
    below_threshold.record_vote(base.clone(), 5);
    below_threshold.record_vote(
        ConsensusVoteMsg {
            voter_peer_id: "b".to_string(),
            ..base.clone()
        },
        5,
    );
    below_threshold.record_vote(
        ConsensusVoteMsg {
            voter_peer_id: "c".to_string(),
            ..base.clone()
        },
        5,
    );
    below_threshold.record_vote(
        ConsensusVoteMsg {
            voter_peer_id: "d".to_string(),
            accepted: false,
            ..base.clone()
        },
        5,
    );
    let rejected = below_threshold.record_vote(
        ConsensusVoteMsg {
            voter_peer_id: "e".to_string(),
            accepted: false,
            ..base.clone()
        },
        5,
    );
    assert!(
        !rejected.unwrap().accepted,
        "3/5 must not clear the 2/3 bar"
    );

    let mut at_threshold = ConsensusCollector::new(1_000);
    for voter in ["a", "b", "c", "d"] {
        at_threshold.record_vote(
            ConsensusVoteMsg {
                voter_peer_id: voter.to_string(),
                ..base.clone()
            },
            6,
        );
    }
    at_threshold.record_vote(
        ConsensusVoteMsg {
            voter_peer_id: "e".to_string(),
            accepted: false,
            ..base.clone()
        },
        6,
    );
    let accepted = at_threshold.record_vote(
        ConsensusVoteMsg {
            voter_peer_id: "f".to_string(),
            accepted: false,
            ..base
        },
        6,
    );
    assert!(accepted.unwrap().accepted, "4/6 must clear the 2/3 bar");

    let program = zkf_examples::mul_add_program();
    let witness = generate_witness(&program, &zkf_examples::mul_add_inputs(7, 5)).unwrap();
    let backend = backend_for(BackendKind::ArkworksGroth16);
    let compiled = backend.compile(&program).unwrap();
    let artifact = backend.prove(&compiled, &witness).unwrap();
    assert!(
        backend.verify(&compiled, &artifact).unwrap(),
        "consensus pressure must not corrupt proof semantics"
    );
}

#[test]
fn attestation_chain_persists_and_verifies_signatures() {
    with_swarm_home(|_| {
        let config = SwarmConfig::from_env();
        let signer_a = LocalPeerIdentity::load_or_create(&config, "attestor-a").unwrap();
        let signer_b = LocalPeerIdentity::load_or_create(&config, "attestor-b").unwrap();

        let build_attestation = |signer: &LocalPeerIdentity,
                                 signer_peer_id: &str,
                                 output_digest: [u8; 32],
                                 trace_digest: [u8; 32],
                                 activation_level: u8| {
            let public_key = signer.public_key_bytes();
            let signature = signer.sign(&attestation_signing_bytes(
                "job-attest",
                7,
                output_digest,
                trace_digest,
                Some(activation_level),
            ));
            AttestationMetadata {
                signer_peer_id: signer_peer_id.to_string(),
                public_key,
                public_key_bundle: Some(signer.public_key_bundle()),
                output_digest,
                trace_digest,
                signature,
                signature_bundle: Some(signer.sign_bundle(&attestation_signing_bytes(
                    "job-attest",
                    7,
                    output_digest,
                    trace_digest,
                    Some(activation_level),
                ))),
                activation_level: Some(activation_level),
            }
        };

        let chain = AttestationChainMsg {
            job_id: "job-attest".to_string(),
            partition_id: 7,
            attestations: vec![
                build_attestation(
                    &signer_a,
                    "attestor-a",
                    [1; 32],
                    [2; 32],
                    ActivationLevel::Alert as u8,
                ),
                build_attestation(
                    &signer_b,
                    "attestor-b",
                    [3; 32],
                    [4; 32],
                    ActivationLevel::Active as u8,
                ),
            ],
        };

        persist_attestation_chain(&config, &chain).unwrap();

        let attestation_dir = config.swarm_root().join("attestations");
        let mut persisted = fs::read_dir(&attestation_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        persisted.sort();
        assert_eq!(persisted.len(), 1);

        let stored: AttestationChainMsg =
            serde_json::from_slice(&fs::read(&persisted[0]).unwrap()).unwrap();
        assert_eq!(stored.job_id, chain.job_id);
        assert_eq!(stored.partition_id, chain.partition_id);
        assert_eq!(stored.attestations.len(), 2);

        for attestation in &stored.attestations {
            assert!(
                LocalPeerIdentity::verify(
                    &attestation.public_key,
                    &attestation_signing_bytes(
                        &stored.job_id,
                        stored.partition_id,
                        attestation.output_digest,
                        attestation.trace_digest,
                        attestation.activation_level,
                    ),
                    &attestation.signature,
                ),
                "persisted attestation must verify after fan-out persistence"
            );
        }
    });
}

#[test]
fn reputation_farming_buys_at_most_one_pre_activation_hit() {
    with_swarm_home(|_| {
        let config = SwarmConfig::from_env();
        let mut tracker = ReputationTracker::new(&config).unwrap();
        let peer = PeerId("peer-farmer".to_string());
        let baseline = tracker.score_for(&peer);

        for _ in 0..10 {
            tracker
                .record_event(
                    &peer,
                    ReputationEvidenceKind::QuorumAgreement,
                    ReputationEvidence {
                        observed_at_unix_ms: 1,
                        ..Default::default()
                    },
                )
                .unwrap();
        }
        let farmed = tracker.score_for(&peer);
        tracker
            .record_event(
                &peer,
                ReputationEvidenceKind::QuorumDisagreement,
                ReputationEvidence {
                    observed_at_unix_ms: 2,
                    ..Default::default()
                },
            )
            .unwrap();
        let after_disagreement = tracker.score_for(&peer);

        assert!(
            (baseline - 0.25).abs() < 1e-6,
            "fresh peers must start probationary below the quorum-voter threshold"
        );
        assert!(
            farmed < 0.70,
            "hourly-capped farming must not lift a probationary peer to quorum-voter status"
        );
        assert!(
            after_disagreement < farmed,
            "negative evidence must still reduce trust"
        );
    });
}

#[test]
fn gossip_flood_stays_within_local_and_heartbeat_caps() {
    let config = SentinelConfig {
        min_baseline_observations: 1,
        digest_rate_limit_per_sec: 2,
        ..SentinelConfig::default()
    };
    let trace = anomaly_trace("backend-prove", 500);
    let mut sentinel = SentinelState::new(&config, [7; 32]);
    sentinel.stage_baselines.insert(
        trace.stage_key.clone(),
        WelfordState {
            count: 20,
            mean: 1.0,
            m2: 1.0,
        },
    );

    for _ in 0..5 {
        let _ = sentinel.observe(&trace, &config);
    }
    let local_digests = sentinel.drain_digests();
    assert_eq!(
        local_digests.len(),
        2,
        "local sentinel flood must hit the rate cap"
    );

    let mut diplomat = Diplomat::new(1);
    diplomat.enqueue_runtime_digests(&local_digests);
    let gossip = diplomat.threat_gossip_message(Some(ActivationLevel::Alert as u8), None);
    assert_eq!(gossip.digests.len(), 1, "heartbeat gossip must stay capped");
}

#[test]
fn rogue_builder_cannot_skip_candidate_validated_shadow_live() {
    with_swarm_home(|_| {
        write_rule_record(&test_rule_record(
            "rogue-builder",
            RuleState::Candidate,
            SecurityAction::DisableHeuristicShortcuts,
            0,
            0.0,
        ));
        assert!(shadow_rule("rogue-builder").is_err());
        assert!(promote_rule("rogue-builder").is_err());

        write_rule_record(&test_rule_record(
            "rogue-builder",
            RuleState::Validated,
            SecurityAction::DisableHeuristicShortcuts,
            0,
            0.0,
        ));
        let shadowed = shadow_rule("rogue-builder").unwrap();
        assert_eq!(shadowed.state, RuleState::Shadow);
        let promoted = promote_rule("rogue-builder").unwrap();
        assert_eq!(promoted.state, RuleState::Live);

        write_rule_record(&test_rule_record(
            "rogue-reject",
            RuleState::Shadow,
            SecurityAction::RejectJob,
            49,
            0.0,
        ));
        let stayed_shadow = record_shadow_observation("rogue-reject", false).unwrap();
        assert_eq!(
            stayed_shadow.state,
            RuleState::Shadow,
            "high-impact rules must not auto-promote"
        );
    });
}

#[test]
fn network_partition_recovers_without_reconciliation_logic() {
    with_swarm_home(|_| {
        let config = SwarmConfig::from_env();
        let mut tracker = ReputationTracker::new(&config).unwrap();
        let peer = PeerId("peer-partition".to_string());
        tracker
            .record_event(
                &peer,
                ReputationEvidenceKind::HeartbeatTimeout,
                ReputationEvidence {
                    observed_at_unix_ms: 1,
                    ..Default::default()
                },
            )
            .unwrap();
        let partitioned = tracker.score_for(&peer);

        tracker
            .apply_advisory_snapshot(&ReputationSyncMsg {
                records: vec![ReputationRecordMsg {
                    peer_id: peer.0.clone(),
                    score: 0.95,
                    evidence: "remote-partition-view".to_string(),
                    recorded_unix_ms: 2,
                }],
            })
            .unwrap();
        let after_snapshot = tracker.score_for(&peer);
        assert!(
            (after_snapshot - partitioned).abs() < 1e-6,
            "remote snapshots must remain advisory during partition recovery"
        );

        tracker
            .record_event(
                &peer,
                ReputationEvidenceKind::HeartbeatResumed,
                ReputationEvidence {
                    observed_at_unix_ms: 3,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            tracker.score_for(&peer) > partitioned,
            "local recovery evidence must restore trust without reconciliation logic"
        );
    });
}

#[test]
fn key_theft_rotation_invalidates_old_identity_and_flags_auth_failure() {
    with_swarm_home(|_| {
        let config = SwarmConfig::from_env();
        let original = LocalPeerIdentity::load_or_create(&config, "peer-auth").unwrap();
        let payload = b"swarm-auth-check";
        let original_signature = original.sign(payload);
        let original_public_key = original.public_key_bytes();

        let rotated = LocalPeerIdentity::rotate(&config, "peer-auth").unwrap();
        let rotated_public_key = rotated.public_key_bytes();

        assert_ne!(original_public_key, rotated_public_key);
        assert!(LocalPeerIdentity::verify(
            &original_public_key,
            payload,
            &original_signature,
        ));
        assert!(
            !LocalPeerIdentity::verify(&rotated_public_key, payload, &original_signature),
            "rotating the key must invalidate the stolen signer"
        );

        let evaluation = SecuritySupervisor::evaluate(
            &empty_report(),
            None,
            Some(&RuntimeSecurityContext {
                auth_failure_count: 1,
                ..Default::default()
            }),
            None,
        );
        assert!(
            evaluation
                .verdict
                .signals
                .iter()
                .any(|signal| { signal.kind == ThreatSignalKind::AuthFailure })
        );
    });
}
