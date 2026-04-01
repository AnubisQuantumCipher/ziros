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

use crate::cmd::swarm::{
    list_rules_report, promote_rule_report, regenerate_identity_report, reputation_log_entries,
    reputation_scores_report, reputation_verify_report, revoke_rule_report, rotate_identity_report,
    rule_history_report, shadow_rule_report, swarm_status_report,
};
use crate::tests::with_temp_home_and_env;
use crate::{cli::Commands, cmd};
use std::fs;
use zkf_distributed::{ReputationEvidence, ReputationEvidenceKind, ReputationTracker};
use zkf_runtime::swarm::builder::{BuilderRuleRecord, DetectionCondition, DetectionRule};
use zkf_runtime::{RuleState, SecurityAction, SwarmConfig, ThreatSignalKind};

#[test]
fn swarm_status_report_includes_rule_and_reputation_summaries() {
    with_temp_home_and_env(&[], || {
        let config = SwarmConfig::from_env();
        let rule = BuilderRuleRecord {
            rule: DetectionRule {
                id: "rule-cli".to_string(),
                condition: DetectionCondition::SignalBurst {
                    kind: ThreatSignalKind::RuntimeAnomaly,
                    count: 2,
                    window_ms: 1_000,
                },
                action: SecurityAction::DisableHeuristicShortcuts,
                confidence: 0.8,
                min_observations: 3,
            },
            state: RuleState::Shadow,
            created_unix_ms: 1,
            updated_unix_ms: 2,
            shadow_observation_count: 12,
            shadow_false_positive_rate: 0.02,
            history: vec!["shadow".to_string()],
        };
        fs::create_dir_all(&config.rules_path).unwrap();
        fs::write(
            config.rules_path.join("rule-cli.json"),
            serde_json::to_vec_pretty(&rule).unwrap(),
        )
        .unwrap();

        let mut tracker = ReputationTracker::new(&config).unwrap();
        tracker
            .record_event(
                &zkf_distributed::PeerId("peer-a".to_string()),
                ReputationEvidenceKind::AttestationValid,
                ReputationEvidence {
                    observed_at_unix_ms: 10,
                    ..Default::default()
                },
            )
            .unwrap();

        let report = swarm_status_report().unwrap();
        assert_eq!(report.shadow_rule_count, 1);
        assert_eq!(report.recent_rules[0].id, "rule-cli");
        assert_eq!(report.recent_reputation_events[0].peer_id, "peer-a");
        assert!(!report.public_key_resynced);
    });
}

#[test]
fn swarm_status_report_flags_public_key_resync_repairs() {
    with_temp_home_and_env(&[], || {
        let config = SwarmConfig::from_env();
        let report = swarm_status_report().unwrap();
        assert!(!report.public_key_resynced);

        let path = config
            .identity_path
            .join(format!("{}.ed25519", report.identity_label));
        fs::write(
            {
                let mut public = path.clone();
                public.set_extension("ed25519.pub");
                public
            },
            [0u8; 32],
        )
        .unwrap();

        let repaired = swarm_status_report().unwrap();
        assert!(repaired.public_key_resynced);
    });
}

#[test]
fn rotate_identity_report_returns_peer_material() {
    with_temp_home_and_env(&[], || {
        let report = rotate_identity_report().unwrap();
        assert!(
            report["peer_id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("swarm-")
        );
        assert_eq!(report["backend"].as_str().unwrap_or_default(), "file");
    });
}

#[test]
fn reputation_log_entries_return_new_event_shape() {
    with_temp_home_and_env(&[], || {
        let config = SwarmConfig::from_env();
        let mut tracker = ReputationTracker::new(&config).unwrap();
        tracker
            .record_event(
                &zkf_distributed::PeerId("peer-b".to_string()),
                ReputationEvidenceKind::QuorumAgreement,
                ReputationEvidence {
                    job_id: Some("job-1".to_string()),
                    partition_id: Some(0),
                    observed_at_unix_ms: 11,
                    ..Default::default()
                },
            )
            .unwrap();
        let events = reputation_log_entries(Some("peer-b")).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].peer_id, "peer-b");
        assert_eq!(events[0].evidence.job_id.as_deref(), Some("job-1"));
    });
}

#[test]
fn rule_reports_cover_list_shadow_promote_history_and_revoke() {
    with_temp_home_and_env(&[], || {
        let config = SwarmConfig::from_env();
        let rule = BuilderRuleRecord {
            rule: DetectionRule {
                id: "rule-flow".to_string(),
                condition: DetectionCondition::ReputationBelow { threshold: 0.4 },
                action: SecurityAction::DisableHeuristicShortcuts,
                confidence: 0.9,
                min_observations: 5,
            },
            state: RuleState::Validated,
            created_unix_ms: 1,
            updated_unix_ms: 2,
            shadow_observation_count: 0,
            shadow_false_positive_rate: 0.0,
            history: vec!["validated".to_string()],
        };
        fs::create_dir_all(&config.rules_path).unwrap();
        fs::write(
            config.rules_path.join("rule-flow.json"),
            serde_json::to_vec_pretty(&rule).unwrap(),
        )
        .unwrap();

        let listed = list_rules_report().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].rule.id, "rule-flow");

        let shadowed = shadow_rule_report("rule-flow").unwrap();
        assert_eq!(shadowed.state, RuleState::Shadow);

        let promoted = promote_rule_report("rule-flow").unwrap();
        assert_eq!(promoted.state, RuleState::Live);

        let history = rule_history_report("rule-flow").unwrap();
        assert_eq!(history.state, RuleState::Live);
        assert!(
            history
                .history
                .iter()
                .any(|entry| entry == "manually-promoted")
        );

        let revoked = revoke_rule_report("rule-flow").unwrap();
        assert_eq!(revoked.state, RuleState::Revoked);
    });
}

#[test]
fn regenerate_identity_report_requires_force() {
    with_temp_home_and_env(&[], || {
        let err = regenerate_identity_report(false).unwrap_err();
        assert!(err.contains("--force"));

        let report = regenerate_identity_report(true).unwrap();
        assert!(
            report["peer_id"]
                .as_str()
                .unwrap_or_default()
                .starts_with("swarm-")
        );
    });
}

#[test]
fn reputation_scores_and_verify_reports_work() {
    with_temp_home_and_env(&[], || {
        let config = SwarmConfig::from_env();
        let mut tracker = ReputationTracker::new(&config).unwrap();
        tracker
            .record_event(
                &zkf_distributed::PeerId("peer-c".to_string()),
                ReputationEvidenceKind::HeartbeatResumed,
                ReputationEvidence {
                    observed_at_unix_ms: 12,
                    ..Default::default()
                },
            )
            .unwrap();

        let scores = reputation_scores_report(Some("peer-c")).unwrap();
        assert_eq!(scores.len(), 1);
        assert_eq!(scores[0].peer_id, "peer-c");
        assert!(scores[0].score > 0.25);

        let verified = reputation_verify_report(Some("peer-c")).unwrap();
        assert_eq!(verified["verified"], serde_json::json!(true));
        assert_eq!(verified["peer_id"], serde_json::json!("peer-c"));
        assert_eq!(verified["event_count"], serde_json::json!(1));
    });
}

#[test]
fn reputation_reports_support_all_scope() {
    with_temp_home_and_env(&[], || {
        let config = SwarmConfig::from_env();
        let mut tracker = ReputationTracker::new(&config).unwrap();
        tracker
            .record_event(
                &zkf_distributed::PeerId("peer-d".to_string()),
                ReputationEvidenceKind::ThreatDigestCorroborated,
                ReputationEvidence {
                    observed_at_unix_ms: 13,
                    ..Default::default()
                },
            )
            .unwrap();

        let scores = reputation_scores_report(None).unwrap();
        assert_eq!(scores.len(), 1);
        let events = reputation_log_entries(None).unwrap();
        assert_eq!(events.len(), 1);
        let verified = reputation_verify_report(None).unwrap();
        assert_eq!(verified["verified"], serde_json::json!(true));
    });
}

#[test]
fn cli_commands_write_entrypoint_observations() {
    with_temp_home_and_env(&[], || {
        cmd::handle(Commands::Capabilities { json: false }, false).unwrap();

        let entrypoints_dir = SwarmConfig::from_env().swarm_root().join("entrypoints");
        let mut entries = fs::read_dir(&entrypoints_dir)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        entries.sort_by_key(|entry| entry.file_name());
        assert_eq!(entries.len(), 1);

        let payload = fs::read_to_string(entries[0].path()).unwrap();
        assert!(payload.contains("\"surface\": \"cli\""));
        assert!(payload.contains("\"name\": \"capabilities\""));
    });
}
