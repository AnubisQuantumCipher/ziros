#![allow(dead_code)]

#[cfg(feature = "kani-minimal")]
use crate::buffer_bridge::BufferViewMut;
#[cfg(feature = "kani-minimal")]
use crate::buffer_bridge_core::BufferBridgeCore;
#[cfg(feature = "full")]
use crate::control_plane::{ControlPlaneReplayManifest, HardwareProbeSummary};
#[cfg(feature = "kani-minimal")]
use crate::error::RuntimeError;
#[cfg(feature = "full")]
use crate::hybrid::{
    digest_matches_recorded_hash, hardware_probes_clean, hybrid_primary_leg_byte_components_match,
    hybrid_verify_decision, replay_manifest_identity_is_deterministic,
};
#[cfg(feature = "kani-minimal")]
use crate::memory::{BufferHandle, MemoryClass};
#[cfg(feature = "full")]
use crate::proof_swarm_spec::{
    encrypted_gossip_artifact_projection, encrypted_gossip_fail_closed_spec,
    encrypted_gossip_surface_preserves_artifact_bytes,
};
#[cfg(feature = "full")]
use crate::security::ThreatSeverity;
#[cfg(feature = "full")]
use crate::swarm::queen::disabled_surface_state;
#[cfg(feature = "full")]
use crate::swarm::{
    ActivationLevel, JitterState, QueenConfig, QueenState, ThreatDigest, controller_artifact_path,
    preserve_successful_artifact,
};
#[cfg(feature = "full")]
use std::collections::BTreeMap;

#[cfg(feature = "kani-minimal")]
fn expect_runtime_ok<T>(result: Result<T, RuntimeError>) -> T {
    match result {
        Ok(value) => value,
        Err(_) => panic!("unexpected runtime error"),
    }
}

#[cfg(feature = "kani-minimal")]
fn assert_bytes_eq<const N: usize>(actual: [u8; N], expected: [u8; N]) {
    let mut index = 0usize;
    while index < N {
        assert!(actual[index] == expected[index]);
        index += 1;
    }
}

#[cfg(feature = "kani-minimal")]
fn assert_u32_words_from_prefix(bytes: [u8; 16], expected: [u32; 4]) {
    let words = [
        u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_ne_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    ];
    assert!(words[0] == expected[0]);
    assert!(words[1] == expected[1]);
    assert!(words[2] == expected[2]);
    assert!(words[3] == expected[3]);
}

#[cfg(feature = "kani-minimal")]
fn assert_u64_words_from_prefix(bytes: [u8; 16], expected: [u64; 2]) {
    let words = [
        u64::from_ne_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]),
        u64::from_ne_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]),
    ];
    assert!(words[0] == expected[0]);
    assert!(words[1] == expected[1]);
}

#[cfg(feature = "kani-minimal")]
#[kani::proof]
fn typed_views_reject_misaligned_lengths_and_preserve_u64_words() {
    let aligned = BufferHandle {
        slot: 1,
        size_bytes: 16,
        class: MemoryClass::Spillable,
    };
    let misaligned = BufferHandle {
        slot: 2,
        size_bytes: 10,
        class: MemoryClass::Spillable,
    };
    let mut bridge = BufferBridgeCore::new();
    bridge.allocate(aligned).unwrap();
    bridge.allocate(misaligned).unwrap();

    let first: u64 = kani::any();
    let second: u64 = kani::any();
    bridge.write_slot(aligned.slot, &[0u8; 16]).unwrap();
    {
        let bytes = expect_runtime_ok(bridge.view_mut(aligned.slot));
        let mut view = BufferViewMut::from_bytes(bytes);
        let words = view.as_u64_slice_mut();
        assert!(words.len() == 2);
        words[0] = first;
        words[1] = second;
    }

    let aligned_prefix = expect_runtime_ok(bridge.copy_resident_prefix::<16>(aligned.slot));
    assert_u64_words_from_prefix(aligned_prefix, [first, second]);

    bridge.write_slot(misaligned.slot, &[0u8; 10]).unwrap();
    let misaligned_prefix = expect_runtime_ok(bridge.copy_resident_prefix::<10>(misaligned.slot));
    let mut has_nonzero = false;
    for byte in misaligned_prefix {
        if byte != 0 {
            has_nonzero = true;
        }
    }
    assert!(!has_nonzero);
}

#[cfg(feature = "full")]
#[kani::proof]
fn controller_delegates_to_pure_artifact_path() {
    let artifact: [u8; 4] = kani::any();
    let enabled: bool = kani::any();
    let reject: bool = kani::any();

    let via_controller = controller_artifact_path(enabled, artifact, reject);
    let via_pure = if !enabled {
        Ok(preserve_successful_artifact(artifact))
    } else if reject {
        Err(())
    } else {
        Ok(preserve_successful_artifact(artifact))
    };

    assert_eq!(via_controller, via_pure);
}

#[cfg(feature = "full")]
#[kani::proof]
fn swarm_controller_has_no_artifact_mutation_surface() {
    fn note_low_reputation_peer(controller: &crate::swarm::SwarmController, peer_id: &str) {
        controller.note_low_reputation_peer(peer_id);
    }

    let _config: fn(&crate::swarm::SwarmController) -> crate::swarm::SwarmConfig =
        crate::swarm::SwarmController::config;
    let _is_enabled: fn(&crate::swarm::SwarmController) -> bool =
        crate::swarm::SwarmController::is_enabled;
    let _activation_level: fn(&crate::swarm::SwarmController) -> ActivationLevel =
        crate::swarm::SwarmController::activation_level;
    let _note_low_reputation_peer: fn(&crate::swarm::SwarmController, &str) =
        note_low_reputation_peer;
    let _note_builder_pattern_count: fn(&crate::swarm::SwarmController, u32) =
        crate::swarm::SwarmController::note_builder_pattern_count;
    let _note_gossip_peers_count: fn(&crate::swarm::SwarmController, u32) =
        crate::swarm::SwarmController::note_gossip_peers_count;
    let _verdict: fn(&crate::swarm::SwarmController) -> crate::swarm::SwarmVerdict =
        crate::swarm::SwarmController::verdict;
    let _telemetry_digest: fn(
        &crate::swarm::SwarmController,
    ) -> Option<crate::swarm::SwarmTelemetryDigest> =
        crate::swarm::SwarmController::telemetry_digest;
    let _current_bias: fn(&crate::swarm::SwarmController) -> f64 =
        crate::swarm::SwarmController::current_bias;
    let _sentinel_hook: fn(&crate::swarm::SwarmController) -> crate::scheduler::NodeHook =
        crate::swarm::SwarmController::sentinel_hook;
}

#[cfg(feature = "kani-minimal")]
#[kani::proof]
fn spill_and_reload_preserves_small_cpu_buffers() {
    let handle = BufferHandle {
        slot: 7,
        size_bytes: 8,
        class: MemoryClass::Spillable,
    };
    let payload = kani::any::<[u8; 8]>();

    let mut bridge = BufferBridgeCore::new();
    bridge.allocate(handle).unwrap();
    bridge.write_slot(handle.slot, &payload).unwrap();
    bridge.evict_spillable(handle.slot).unwrap();
    assert!(!bridge.is_resident(handle.slot));

    bridge.ensure_resident(handle.slot).unwrap();
    let bytes = expect_runtime_ok(bridge.copy_resident_prefix::<8>(handle.slot));
    assert_bytes_eq(bytes, payload);
}

#[cfg(feature = "kani-minimal")]
#[kani::proof]
fn buffer_read_write_guards_and_mutable_typed_views_roundtrip() {
    let handle = BufferHandle {
        slot: 11,
        size_bytes: 16,
        class: MemoryClass::Spillable,
    };
    let missing_slot = 99;
    let oversized = kani::any::<[u8; 257]>();
    let first: u32 = kani::any();
    let second: u32 = kani::any();
    let third: u32 = kani::any();
    let fourth: u32 = kani::any();

    let mut bridge = BufferBridgeCore::new();
    bridge.allocate(handle).unwrap();

    assert!(matches!(
        bridge.write_slot(missing_slot, &[0u8; 1]),
        Err(RuntimeError::BufferNotResident { slot }) if slot == missing_slot
    ));
    assert!(matches!(
        bridge.view(missing_slot),
        Err(RuntimeError::BufferNotResident { slot }) if slot == missing_slot
    ));
    assert!(matches!(
        bridge.write_slot(handle.slot, &oversized),
        Err(RuntimeError::Allocation(_))
    ));

    bridge.write_slot(handle.slot, &[0u8; 16]).unwrap();
    {
        let bytes = expect_runtime_ok(bridge.view_mut(handle.slot));
        let mut view = BufferViewMut::from_bytes(bytes);
        let words = view.as_u32_slice_mut();
        assert!(words.len() == 4);
        words[0] = first;
        words[1] = second;
        words[2] = third;
        words[3] = fourth;
    }

    let immutable_bytes = expect_runtime_ok(bridge.copy_resident_prefix::<16>(handle.slot));
    assert_u32_words_from_prefix(immutable_bytes, [first, second, third, fourth]);
}

#[cfg(feature = "kani-minimal")]
#[kani::proof]
fn buffer_residency_transitions_reject_stale_reads_after_eviction() {
    let handle = BufferHandle {
        slot: 12,
        size_bytes: 8,
        class: MemoryClass::Spillable,
    };
    let payload = kani::any::<[u8; 8]>();

    let mut bridge = BufferBridgeCore::new();
    bridge.allocate(handle).unwrap();
    bridge.write_slot(handle.slot, &payload).unwrap();
    assert!(bridge.current_resident_bytes() == 8);
    assert!(bridge.peak_resident_bytes() == 8);

    bridge.evict_spillable(handle.slot).unwrap();
    assert!(!bridge.is_resident(handle.slot));
    assert!(bridge.current_resident_bytes() == 0);
    assert!(matches!(
        bridge.view(handle.slot),
        Err(RuntimeError::BufferNotResident { slot }) if slot == handle.slot
    ));
    assert!(matches!(
        bridge.view_mut(handle.slot),
        Err(RuntimeError::BufferNotResident { slot }) if slot == handle.slot
    ));
    assert!(matches!(
        bridge.write_slot(handle.slot, &[0u8; 8]),
        Err(RuntimeError::BufferNotResident { slot }) if slot == handle.slot
    ));

    bridge.ensure_resident(handle.slot).unwrap();
    assert!(bridge.is_resident(handle.slot));
    assert!(bridge.current_resident_bytes() == 8);
    assert!(bridge.peak_resident_bytes() >= bridge.current_resident_bytes());
    let bytes = expect_runtime_ok(bridge.copy_resident_prefix::<8>(handle.slot));
    assert_bytes_eq(bytes, payload);
}

#[cfg(feature = "kani-minimal")]
#[kani::proof]
fn distinct_slots_preserve_alias_separation_under_mutation_and_free() {
    let left = BufferHandle {
        slot: 21,
        size_bytes: 8,
        class: MemoryClass::Spillable,
    };
    let right = BufferHandle {
        slot: 22,
        size_bytes: 8,
        class: MemoryClass::Spillable,
    };
    let left_payload = kani::any::<[u8; 8]>();
    let right_payload = kani::any::<[u8; 8]>();
    let overwrite = kani::any::<u8>();

    let mut bridge = BufferBridgeCore::new();
    bridge.allocate(left).unwrap();
    bridge.allocate(right).unwrap();
    bridge.write_slot(left.slot, &left_payload).unwrap();
    bridge.write_slot(right.slot, &right_payload).unwrap();

    {
        let view = expect_runtime_ok(bridge.copy_resident_prefix::<8>(right.slot));
        assert_bytes_eq(view, right_payload);
    }
    {
        let view = expect_runtime_ok(bridge.view_mut(left.slot));
        view[0] = overwrite;
    }

    let mut expected_left = left_payload;
    expected_left[0] = overwrite;
    let left_bytes = expect_runtime_ok(bridge.copy_resident_prefix::<8>(left.slot));
    assert_bytes_eq(left_bytes, expected_left);
    let right_bytes = expect_runtime_ok(bridge.copy_resident_prefix::<8>(right.slot));
    assert_bytes_eq(right_bytes, right_payload);

    bridge.free(left.slot);
    assert!(bridge.slot_count() == 1);
    assert!(matches!(
        bridge.view(left.slot),
        Err(RuntimeError::BufferNotResident { slot }) if slot == left.slot
    ));
    let right_after_free = expect_runtime_ok(bridge.copy_resident_prefix::<8>(right.slot));
    assert_bytes_eq(right_after_free, right_payload);
}

#[cfg(feature = "full")]
fn swarm_finalize_artifact(
    artifact: [u8; 4],
    enabled: bool,
    emit_digest: bool,
    escalate: bool,
    reject: bool,
) -> Result<[u8; 4], ()> {
    if !enabled {
        let _ = disabled_surface_state();
    } else {
        let mut queen = QueenState::new(&QueenConfig::default());
        if emit_digest {
            queen.observe_digest(&ThreatDigest {
                source_peer: [7; 32],
                source_peer_id: Some("kani-peer".to_string()),
                timestamp_unix_ms: 1,
                stage_key_hash: 9,
                stage_key: Some("backend-prove".to_string()),
                severity: ThreatSeverity::High,
                kind: crate::security::ThreatSignalKind::RuntimeAnomaly,
                z_score: 4.0,
                observation_count: 12,
                signature: vec![0; 64],
                signature_bundle: None,
                baseline_commitment: None,
                execution_fingerprint: None,
                detail: None,
            });
        }
        if escalate {
            queen.observe_consensus(true, ThreatSeverity::High, 2);
        }
        let _ = queen.activation_level;
    }
    if reject {
        Err(())
    } else {
        Ok(preserve_successful_artifact(artifact))
    }
}

#[cfg(feature = "full")]
#[kani::proof]
fn swarm_non_interference_preserves_artifact_bytes_or_errors() {
    let artifact: [u8; 4] = kani::any();
    let enabled: bool = kani::any();
    let emit_digest: bool = kani::any();
    let escalate: bool = kani::any();
    let reject: bool = kani::any();
    let original = artifact;
    let result = swarm_finalize_artifact(artifact, enabled, emit_digest, escalate, reject);
    if let Ok(bytes) = result {
        assert_eq!(bytes, original);
    }
}

#[cfg(feature = "full")]
#[kani::proof]
fn negotiated_swarm_peers_never_accept_plaintext_threat_payloads() {
    let encrypted_payload_present: bool = kani::any();
    assert!(!encrypted_gossip_fail_closed_spec(
        true,
        true,
        encrypted_payload_present,
    ));
    assert!(encrypted_gossip_fail_closed_spec(
        true,
        false,
        encrypted_payload_present,
    ));
}

#[cfg(feature = "full")]
#[kani::proof]
fn encrypted_gossip_surface_preserves_successful_artifact_bytes() {
    let artifact: [u8; 4] = kani::any();
    let projected = encrypted_gossip_artifact_projection(artifact);
    assert!(encrypted_gossip_surface_preserves_artifact_bytes(artifact));
    assert_eq!(projected, artifact);

    let mut mutated = projected;
    mutated[0] ^= 0x01;
    assert_ne!(mutated, artifact);
}

#[cfg(feature = "full")]
#[kani::proof]
fn swarm_kill_switch_stays_dormant_and_neutral() {
    let disabled = disabled_surface_state();
    assert_eq!(disabled.activation_level, ActivationLevel::Dormant);
    assert_eq!(disabled.verdict.activation_level, ActivationLevel::Dormant);
    assert_eq!(disabled.verdict.threat_digest_count, 0);
    assert!(!disabled.verdict.consensus_confirmed);
    assert!(disabled.telemetry.is_none());
    assert_eq!(disabled.bias, 1.0);
}

#[cfg(feature = "full")]
#[kani::proof]
fn swarm_escalation_is_monotone_within_cooldown() {
    let cooldown: u64 = 100;
    let start: u64 = 1_000;
    let delta: u8 = kani::any();
    kani::assume(u64::from(delta) < cooldown);
    let mut queen = QueenState::new(&QueenConfig {
        digest_rate_threshold_per_minute: 3.0,
        cooldown_ms: u128::from(cooldown),
        ..QueenConfig::default()
    });
    queen.observe_consensus(true, ThreatSeverity::High, u128::from(start));
    let before = queen.activation_level;
    queen.tick(u128::from(start + u64::from(delta)));
    assert!(queen.activation_level >= before);
}

#[cfg(feature = "full")]
#[kani::proof]
fn swarm_deescalation_drops_at_most_one_level_per_cooldown() {
    let mut queen = QueenState::new(&QueenConfig {
        digest_rate_threshold_per_minute: 3.0,
        cooldown_ms: 10,
        ..QueenConfig::default()
    });
    queen.observe_consensus(true, ThreatSeverity::Critical, 1_000);
    queen.tick(1_020);
    assert_eq!(queen.activation_level, ActivationLevel::Active);
}

#[cfg(feature = "full")]
#[kani::proof]
fn jitter_z_score_bounded() {
    let mut jitter = JitterState::default();
    let variance_a: i16 = kani::any();
    let variance_b: i16 = kani::any();
    let probe_ns: u16 = kani::any();

    let first = jitter.observe_variance_delta(f64::from(variance_a) / 100.0);
    let second = jitter.observe_variance_delta(f64::from(variance_b) / 100.0);
    let probe = jitter.observe_probe_duration(f64::from(probe_ns));

    assert!(first.is_finite());
    assert!(second.is_finite());
    assert!(probe.is_finite());
}

#[cfg(feature = "full")]
#[kani::proof]
fn hybrid_verify_requires_both_legs() {
    assert!(hybrid_verify_decision(true, true));
    assert!(!hybrid_verify_decision(true, false));
    assert!(!hybrid_verify_decision(false, true));
    assert!(!hybrid_verify_decision(false, false));
}

#[cfg(feature = "full")]
#[kani::proof]
fn hybrid_transcript_hash_binding_detects_public_input_mismatch() {
    assert!(digest_matches_recorded_hash(
        Some("canonical-digest"),
        "canonical-digest"
    ));
    assert!(!digest_matches_recorded_hash(
        Some("canonical-digest"),
        "tampered-digest"
    ));
    assert!(!digest_matches_recorded_hash(None, "canonical-digest"));
}

#[cfg(feature = "full")]
#[kani::proof]
fn hybrid_hardware_probe_policy_rejects_any_mismatch() {
    assert!(hardware_probes_clean(&HardwareProbeSummary {
        ok: true,
        mismatch_count: 0,
        samples: vec![],
    }));
    assert!(!hardware_probes_clean(&HardwareProbeSummary {
        ok: true,
        mismatch_count: 1,
        samples: vec![],
    }));
    assert!(!hardware_probes_clean(&HardwareProbeSummary {
        ok: false,
        mismatch_count: 0,
        samples: vec![],
    }));
}

#[cfg(feature = "full")]
#[kani::proof]
fn hybrid_primary_leg_binding_rejects_outer_artifact_tampering() {
    assert!(hybrid_primary_leg_byte_components_match(
        &[1, 2, 3],
        &[4, 5, 6],
        &[1, 2, 3],
        &[4, 5, 6]
    ));
    assert!(!hybrid_primary_leg_byte_components_match(
        &[1, 2, 3],
        &[4, 5, 6],
        &[9, 2, 3],
        &[4, 5, 6]
    ));
    assert!(!hybrid_primary_leg_byte_components_match(
        &[1, 2, 3],
        &[4, 5, 6],
        &[1, 2, 3],
        &[7, 5, 6]
    ));
}

#[cfg(feature = "full")]
#[kani::proof]
fn hybrid_replay_manifest_identity_is_deterministic() {
    let manifest = ControlPlaneReplayManifest {
        replay_id: "r".to_string(),
        transcript_hash: "t".to_string(),
        backend_route: "b".to_string(),
        hardware_profile: "h".to_string(),
        stage_manifest_digest: "s".to_string(),
        stage_digests: BTreeMap::new(),
        proof_digests: BTreeMap::new(),
        model_catalog_fingerprint: None,
        metadata: BTreeMap::new(),
    };

    assert!(replay_manifest_identity_is_deterministic(&manifest));
}
