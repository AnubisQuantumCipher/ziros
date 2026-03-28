use super::config::SwarmConfig;
use crate::security::{
    RuntimeModelIntegrity, SecurityAction, SecurityVerdict, ThreatSeverity, ThreatSignalKind,
};
use crate::swarm_builder_core;
use crate::telemetry_collector::telemetry_corpus_stats;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
const MIN_SHADOW_OBSERVATIONS: u64 = 50;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttackTaxonomy {
    Reconnaissance,
    Injection,
    SideChannel,
    ResourceExhaustion,
    IntegrityCompromise,
    Coordination,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GenomeState {
    Shadow,
    Confirmed,
    Live,
    Revoked,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AttackGenomeProvenance {
    #[serde(default)]
    pub imported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_by_peer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_pattern_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackGenome {
    pub id: String,
    pub created_unix_ms: u128,
    pub updated_unix_ms: u128,
    pub state: GenomeState,
    pub taxonomy: AttackTaxonomy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signal_sequence: Vec<ThreatSignalKind>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub severity_sequence: Vec<ThreatSeverity>,
    #[serde(default)]
    pub occurrence_count: u64,
    #[serde(default)]
    pub prefix_match_count: u64,
    #[serde(default)]
    pub local_confirmation_count: u64,
    #[serde(default)]
    pub provenance: AttackGenomeProvenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttackPattern {
    pub id: String,
    pub created_unix_ms: u128,
    pub last_seen_unix_ms: u128,
    pub occurrence_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage_key: Option<String>,
    pub signal_kind: ThreatSignalKind,
    pub severity: ThreatSeverity,
    #[serde(default)]
    pub taxonomy: AttackTaxonomy,
    pub z_score_range: (f64, f64),
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timing_deviation_ms: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_peer_hash: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub genome_id: Option<String>,
    #[serde(default)]
    pub detection_rule: Option<DetectionRule>,
    pub absorbed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleState {
    Candidate,
    Validated,
    Shadow,
    Live,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub condition: DetectionCondition,
    pub action: SecurityAction,
    pub confidence: f64,
    pub min_observations: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DetectionCondition {
    ZScoreAbove {
        stage: String,
        threshold: f64,
    },
    TimingDeviationAbove {
        stage: String,
        ms: f64,
    },
    ReputationBelow {
        threshold: f64,
    },
    SignalBurst {
        kind: ThreatSignalKind,
        count: u32,
        window_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BuilderRuleRecord {
    pub rule: DetectionRule,
    pub state: RuleState,
    pub created_unix_ms: u128,
    pub updated_unix_ms: u128,
    #[serde(default)]
    pub shadow_observation_count: u64,
    #[serde(default)]
    pub shadow_false_positive_rate: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RetrainRequest {
    pub model_lane: String,
    pub reason: String,
    pub corpus_hash: String,
    pub corpus_record_count: u64,
    pub pattern_ids: Vec<String>,
    pub requested_unix_ms: u128,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RollbackMarker {
    pub rule_id: String,
    pub rolled_back_at_unix_ms: u128,
    pub from_state: RuleState,
    pub to_state: RuleState,
    pub reason: String,
    pub peer_key: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct PromotionRecord {
    pub rule_id: String,
    pub promoted_at_unix_ms: u128,
    pub from_state: RuleState,
    pub to_state: RuleState,
    pub shadow_observation_count: u64,
    pub shadow_false_positive_rate: f64,
    pub promoting_peer_key: [u8; 32],
    pub signature: Vec<u8>,
}

pub fn record_security_event(
    verdict: &SecurityVerdict,
    model_integrity: &RuntimeModelIntegrity,
) -> io::Result<Vec<AttackPattern>> {
    let config = SwarmConfig::from_env();
    if !config.enabled {
        return Ok(Vec::new());
    }
    fs::create_dir_all(&config.pattern_library_path)?;
    fs::create_dir_all(&config.retrain_queue_path)?;
    fs::create_dir_all(&config.rules_path)?;

    let timestamp = unix_time_now_ms();
    let taxonomy = classify_taxonomy(
        &verdict
            .signals
            .iter()
            .map(|signal| signal.kind)
            .collect::<Vec<_>>(),
    );
    let mut patterns = Vec::new();
    for (index, signal) in verdict.signals.iter().enumerate() {
        let id = format!("pattern-{timestamp}-{index}");
        let pattern = AttackPattern {
            id: id.clone(),
            created_unix_ms: timestamp,
            last_seen_unix_ms: timestamp,
            occurrence_count: 1,
            stage_key: signal.stage_key.clone(),
            signal_kind: signal.kind,
            severity: signal.severity,
            taxonomy,
            z_score_range: (
                signal.observed_value.unwrap_or_default(),
                signal.observed_value.unwrap_or_default(),
            ),
            timing_deviation_ms: signal.observed_value,
            source_peer_hash: Some(signal.source.bytes().fold(0u64, |acc, byte| {
                acc.wrapping_mul(16777619) ^ u64::from(byte)
            })),
            genome_id: None,
            detection_rule: None,
            absorbed: !model_integrity.integrity_failures.is_empty()
                || !model_integrity.freshness_notices.is_empty(),
        };
        write_json(
            config.pattern_library_path.join(format!("{id}.json")),
            &pattern,
        )?;
        patterns.push(pattern);
    }

    patterns.extend(sequence_attack_genomes(
        &config, verdict, timestamp, taxonomy, &patterns,
    )?);

    if patterns.len() >= 3 {
        let rule = generate_detection_rule(&patterns[0]);
        let mut record = BuilderRuleRecord {
            rule: rule.clone(),
            state: RuleState::Candidate,
            created_unix_ms: timestamp,
            updated_unix_ms: timestamp,
            shadow_observation_count: 0,
            shadow_false_positive_rate: 0.0,
            history: vec!["candidate-created".to_string()],
        };
        let validated_state = validate_rule_against_telemetry(&config, &rule)?;
        record.state = validated_state;
        record
            .history
            .push(format!("candidate-evaluated:{validated_state:?}"));
        write_json(config.rules_path.join(format!("{}.json", rule.id)), &record)?;
    }

    if let Ok(stats) = telemetry_corpus_stats()
        && should_queue_retrain(&config, stats.record_count)?
    {
        let request = RetrainRequest {
            model_lane: "security".to_string(),
            reason: format!(
                "security verdict {} produced {} new swarm patterns",
                verdict.risk_level.as_str(),
                patterns.len()
            ),
            corpus_hash: stats.corpus_hash,
            corpus_record_count: stats.record_count,
            pattern_ids: patterns.iter().map(|pattern| pattern.id.clone()).collect(),
            requested_unix_ms: timestamp,
        };
        write_json(
            config
                .retrain_queue_path
                .join(format!("retrain-{timestamp}.json")),
            &request,
        )?;
    }

    Ok(patterns)
}

pub fn list_rules() -> io::Result<Vec<BuilderRuleRecord>> {
    let config = SwarmConfig::from_env();
    read_rule_records(&config.rules_path)
}

pub fn list_genomes() -> io::Result<Vec<AttackGenome>> {
    let config = SwarmConfig::from_env();
    read_genome_records(&genome_library_dir(&config))
}

pub fn genome_history(genome_id: &str) -> io::Result<AttackGenome> {
    let config = SwarmConfig::from_env();
    read_json(genome_library_dir(&config).join(format!("{genome_id}.json")))
}

pub fn import_shared_genome(
    genome: &AttackGenome,
    shared_by_peer: &str,
) -> io::Result<AttackGenome> {
    let config = SwarmConfig::from_env();
    let mut imported = genome.clone();
    imported.state = GenomeState::Shadow;
    imported.updated_unix_ms = unix_time_now_ms();
    imported.local_confirmation_count = 0;
    imported.provenance.imported = true;
    imported.provenance.shared_by_peer = Some(shared_by_peer.to_string());
    write_json(
        genome_library_dir(&config).join(format!("{}.json", imported.id)),
        &imported,
    )?;
    Ok(imported)
}

pub fn rule_history(rule_id: &str) -> io::Result<BuilderRuleRecord> {
    let config = SwarmConfig::from_env();
    read_json(config.rules_path.join(format!("{rule_id}.json")))
}

pub fn shadow_rule(rule_id: &str) -> io::Result<BuilderRuleRecord> {
    transition_rule(rule_id, RuleState::Shadow, "manually-shadowed")
}

pub fn revoke_rule(rule_id: &str) -> io::Result<BuilderRuleRecord> {
    transition_rule(rule_id, RuleState::Revoked, "manually-revoked")
}

pub fn promote_rule(rule_id: &str) -> io::Result<BuilderRuleRecord> {
    transition_rule(rule_id, RuleState::Live, "manually-promoted")
}

pub fn record_shadow_observation(
    rule_id: &str,
    false_positive: bool,
) -> io::Result<BuilderRuleRecord> {
    let mut record = rule_history(rule_id)?;
    if !matches!(record.state, RuleState::Shadow | RuleState::Live) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "shadow observations require Shadow or Live rules, found {:?}",
                record.state
            ),
        ));
    }
    record.shadow_observation_count += 1;
    let total = record.shadow_observation_count as f64;
    let old_weight = if total <= 1.0 {
        0.0
    } else {
        (total - 1.0) / total
    };
    let new_sample = if false_positive { 1.0 } else { 0.0 };
    record.shadow_false_positive_rate =
        (record.shadow_false_positive_rate * old_weight) + (new_sample / total);
    record.updated_unix_ms = unix_time_now_ms();
    record.history.push(format!(
        "shadow-observation:false_positive={false_positive}"
    ));
    let config = SwarmConfig::from_env();
    write_shadow_log_entry(&config, &record, false_positive)?;
    match swarm_builder_core::next_rule_state_after_shadow_observation(
        record.state,
        record.shadow_observation_count,
        (record.shadow_false_positive_rate * 1000.0).round() as u32,
        auto_promotion_allowed(&record.rule),
    ) {
        RuleState::Live if record.state == RuleState::Shadow => {
            record = promote_record(record, "auto-promoted-from-shadow")?;
        }
        RuleState::Revoked if record.state == RuleState::Shadow => {
            record = revoke_record(record, "shadow-false-positive-rate-too-high")?;
        }
        RuleState::Revoked if record.state == RuleState::Live => {
            record = revoke_record(record, "live-false-positive-rate-too-high")?;
        }
        _ => {}
    }
    write_json(
        config.rules_path.join(format!("{}.json", record.rule.id)),
        &record,
    )?;
    Ok(record)
}

pub fn write_rollback_marker(marker: &RollbackMarker) -> io::Result<PathBuf> {
    let config = SwarmConfig::from_env();
    fs::create_dir_all(&config.rollbacks_path)?;
    let path = config.rollbacks_path.join(format!(
        "{}-{}.json",
        marker.rule_id, marker.rolled_back_at_unix_ms
    ));
    write_json(&path, marker)?;
    Ok(path)
}

pub fn pattern_count() -> io::Result<u32> {
    let config = SwarmConfig::from_env();
    count_json_entries(&config.pattern_library_path).map(|count| count as u32)
}

fn transition_rule(
    rule_id: &str,
    next_state: RuleState,
    event: &str,
) -> io::Result<BuilderRuleRecord> {
    let mut record = rule_history(rule_id)?;
    if !swarm_builder_core::transition_allowed(record.state, next_state) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "rule state transition {:?} -> {:?} is not allowed on the shipped Swarm surface",
                record.state, next_state
            ),
        ));
    }
    record = match next_state {
        RuleState::Shadow => transition_record(record, next_state, event)?,
        RuleState::Live => promote_record(record, event)?,
        RuleState::Revoked => revoke_record(record, event)?,
        other => transition_record(record, other, event)?,
    };
    let config = SwarmConfig::from_env();
    write_json(
        config.rules_path.join(format!("{}.json", record.rule.id)),
        &record,
    )?;
    Ok(record)
}

fn transition_record(
    mut record: BuilderRuleRecord,
    next_state: RuleState,
    event: &str,
) -> io::Result<BuilderRuleRecord> {
    record.state = next_state;
    record.updated_unix_ms = unix_time_now_ms();
    record.history.push(event.to_string());
    Ok(record)
}

fn promote_record(mut record: BuilderRuleRecord, event: &str) -> io::Result<BuilderRuleRecord> {
    let config = SwarmConfig::from_env();
    fs::create_dir_all(&config.promotions_path)?;
    let previous = record.state;
    record = transition_record(record, RuleState::Live, event)?;
    let promotion = sign_promotion_record(&record, previous, RuleState::Live)?;
    let path = config.promotions_path.join(format!(
        "{}-{}.json",
        record.rule.id, record.updated_unix_ms
    ));
    write_json(path, &promotion)?;
    Ok(record)
}

fn revoke_record(mut record: BuilderRuleRecord, reason: &str) -> io::Result<BuilderRuleRecord> {
    let previous = record.state;
    record = transition_record(record, RuleState::Revoked, reason)?;
    if previous != RuleState::Revoked {
        let (peer_key, signature) = builder_signature(&rollback_signing_bytes(
            &record.rule.id,
            previous,
            RuleState::Revoked,
            &record.updated_unix_ms.to_le_bytes(),
        ))?;
        let _ = write_rollback_marker(&RollbackMarker {
            rule_id: record.rule.id.clone(),
            rolled_back_at_unix_ms: record.updated_unix_ms,
            from_state: previous,
            to_state: RuleState::Revoked,
            reason: reason.to_string(),
            peer_key,
            signature,
        })?;
    }
    Ok(record)
}

fn read_rule_records(dir: &Path) -> io::Result<Vec<BuilderRuleRecord>> {
    let mut records = Vec::new();
    if !dir.exists() {
        return Ok(records);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        records.push(read_json(entry.path())?);
    }
    records.sort_by_key(|record| record.created_unix_ms);
    Ok(records)
}

fn generate_detection_rule(pattern: &AttackPattern) -> DetectionRule {
    let condition = if let Some(stage_key) = &pattern.stage_key {
        DetectionCondition::ZScoreAbove {
            stage: stage_key.clone(),
            threshold: pattern.z_score_range.1.max(3.0),
        }
    } else {
        DetectionCondition::SignalBurst {
            kind: pattern.signal_kind,
            count: 3,
            window_ms: 60_000,
        }
    };
    let action = match pattern.taxonomy {
        AttackTaxonomy::Reconnaissance => SecurityAction::QuorumVerify,
        AttackTaxonomy::Injection | AttackTaxonomy::IntegrityCompromise => {
            SecurityAction::RejectJob
        }
        AttackTaxonomy::SideChannel => SecurityAction::DisableHeuristicShortcuts,
        AttackTaxonomy::ResourceExhaustion => SecurityAction::ReduceParallelism,
        AttackTaxonomy::Coordination => SecurityAction::RedundantExecution,
        AttackTaxonomy::Unknown => SecurityAction::DisableHeuristicShortcuts,
    };
    DetectionRule {
        id: format!("rule-{}", pattern.id),
        condition,
        action,
        confidence: 0.7,
        min_observations: 3,
    }
}

fn sequence_attack_genomes(
    config: &SwarmConfig,
    verdict: &SecurityVerdict,
    timestamp: u128,
    taxonomy: AttackTaxonomy,
    patterns: &[AttackPattern],
) -> io::Result<Vec<AttackPattern>> {
    let observed_sequence = verdict
        .signals
        .iter()
        .map(|signal| signal.kind)
        .collect::<Vec<_>>();
    if observed_sequence.is_empty() {
        return Ok(Vec::new());
    }

    let stage_key = verdict
        .signals
        .iter()
        .find_map(|signal| signal.stage_key.clone());
    let mut genomes = read_genome_records(&genome_library_dir(config))?;
    let mut generated_patterns = Vec::new();
    for genome in genomes.iter_mut() {
        if genome.state == GenomeState::Revoked {
            continue;
        }
        if genome.signal_sequence.starts_with(&observed_sequence)
            && genome.signal_sequence.len() > observed_sequence.len()
        {
            genome.prefix_match_count += 1;
            genome.updated_unix_ms = timestamp;
            generated_patterns.push(AttackPattern {
                id: format!("pattern-{timestamp}-prefix-{}", genome.id),
                created_unix_ms: timestamp,
                last_seen_unix_ms: timestamp,
                occurrence_count: 1,
                stage_key: genome.stage_key.clone().or_else(|| stage_key.clone()),
                signal_kind: ThreatSignalKind::AttackGenomePrefixMatch,
                severity: genome
                    .severity_sequence
                    .iter()
                    .copied()
                    .max()
                    .unwrap_or(ThreatSeverity::Moderate),
                taxonomy: genome.taxonomy,
                z_score_range: (0.0, 0.0),
                timing_deviation_ms: None,
                source_peer_hash: None,
                genome_id: Some(genome.id.clone()),
                detection_rule: None,
                absorbed: false,
            });
            write_json(
                genome_library_dir(config).join(format!("{}.json", genome.id)),
                genome,
            )?;
        }
    }

    let matching_id = genomes.iter().position(|genome| {
        genome.stage_key == stage_key && genome.signal_sequence == observed_sequence
    });
    if let Some(index) = matching_id {
        let mut genome = genomes.remove(index);
        genome.occurrence_count += 1;
        genome.updated_unix_ms = timestamp;
        if genome.provenance.imported {
            genome.local_confirmation_count += 1;
            if genome.state == GenomeState::Shadow && genome.local_confirmation_count >= 1 {
                genome.state = GenomeState::Live;
            }
        }
        write_json(
            genome_library_dir(config).join(format!("{}.json", genome.id)),
            &genome,
        )?;
    } else {
        let genome = AttackGenome {
            id: format!("genome-{timestamp}"),
            created_unix_ms: timestamp,
            updated_unix_ms: timestamp,
            state: GenomeState::Live,
            taxonomy,
            stage_key,
            signal_sequence: observed_sequence,
            severity_sequence: verdict
                .signals
                .iter()
                .map(|signal| signal.severity)
                .collect(),
            occurrence_count: 1,
            prefix_match_count: 0,
            local_confirmation_count: 1,
            provenance: AttackGenomeProvenance {
                imported: false,
                shared_by_peer: None,
                first_pattern_id: patterns.first().map(|pattern| pattern.id.clone()),
            },
        };
        write_json(
            genome_library_dir(config).join(format!("{}.json", genome.id)),
            &genome,
        )?;
    }

    Ok(generated_patterns)
}

fn classify_taxonomy(signal_kinds: &[ThreatSignalKind]) -> AttackTaxonomy {
    swarm_builder_core::classify_taxonomy(signal_kinds)
}

fn validate_rule_against_telemetry(
    config: &SwarmConfig,
    rule: &DetectionRule,
) -> io::Result<RuleState> {
    let telemetry_dir = config
        .pattern_library_path
        .parent()
        .map(PathBuf::from)
        .unwrap_or_else(|| config.swarm_root())
        .join("..")
        .join("telemetry");
    let mut total = 0usize;
    let mut matches = 0usize;
    if telemetry_dir.exists() {
        for entry in fs::read_dir(telemetry_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            total += 1;
            let value: serde_json::Value = read_json(entry.path())?;
            if rule_matches_telemetry(rule, &value) {
                matches += 1;
            }
        }
    }
    if total == 0 {
        return Ok(RuleState::Validated);
    }
    let ratio = matches as f64 / total as f64;
    Ok(if ratio > 0.30 {
        RuleState::Revoked
    } else {
        RuleState::Validated
    })
}

fn auto_promotion_allowed(rule: &DetectionRule) -> bool {
    swarm_builder_core::auto_promotion_allowed(rule)
}

fn should_queue_retrain(config: &SwarmConfig, current_record_count: u64) -> io::Result<bool> {
    let latest = latest_retrain_request(config)?;
    Ok(swarm_builder_core::should_queue_retrain(
        latest.as_ref().map(|request| request.corpus_record_count),
        current_record_count,
    ))
}

fn latest_retrain_request(config: &SwarmConfig) -> io::Result<Option<RetrainRequest>> {
    if !config.retrain_queue_path.exists() {
        return Ok(None);
    }
    let mut latest: Option<RetrainRequest> = None;
    for entry in fs::read_dir(&config.retrain_queue_path)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let request: RetrainRequest = read_json(entry.path())?;
        let replace = latest
            .as_ref()
            .map(|existing| request.requested_unix_ms > existing.requested_unix_ms)
            .unwrap_or(true);
        if replace {
            latest = Some(request);
        }
    }
    Ok(latest)
}

fn sign_promotion_record(
    record: &BuilderRuleRecord,
    from_state: RuleState,
    to_state: RuleState,
) -> io::Result<PromotionRecord> {
    let signing_bytes = promotion_signing_bytes(record, from_state, to_state);
    let (promoting_peer_key, signature) = builder_signature(&signing_bytes)?;
    Ok(PromotionRecord {
        rule_id: record.rule.id.clone(),
        promoted_at_unix_ms: record.updated_unix_ms,
        from_state,
        to_state,
        shadow_observation_count: record.shadow_observation_count,
        shadow_false_positive_rate: record.shadow_false_positive_rate,
        promoting_peer_key,
        signature,
    })
}

fn promotion_signing_bytes(
    record: &BuilderRuleRecord,
    from_state: RuleState,
    to_state: RuleState,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(record.rule.id.as_bytes());
    bytes.extend_from_slice(format!("{from_state:?}").as_bytes());
    bytes.extend_from_slice(format!("{to_state:?}").as_bytes());
    bytes.extend_from_slice(&record.shadow_observation_count.to_le_bytes());
    bytes.extend_from_slice(&record.shadow_false_positive_rate.to_le_bytes());
    bytes.extend_from_slice(&record.updated_unix_ms.to_le_bytes());
    bytes
}

fn rollback_signing_bytes(
    rule_id: &str,
    from_state: RuleState,
    to_state: RuleState,
    timestamp: &[u8; 16],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(rule_id.as_bytes());
    bytes.extend_from_slice(format!("{from_state:?}").as_bytes());
    bytes.extend_from_slice(format!("{to_state:?}").as_bytes());
    bytes.extend_from_slice(timestamp);
    bytes
}

fn builder_signature(bytes: &[u8]) -> io::Result<([u8; 32], Vec<u8>)> {
    let seed = load_or_create_builder_seed()?;
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(bytes).to_bytes().to_vec();
    let peer_key = signing_key.verifying_key().to_bytes();
    Ok((peer_key, signature))
}

fn load_or_create_builder_seed() -> io::Result<[u8; 32]> {
    let config = SwarmConfig::from_env();
    fs::create_dir_all(&config.identity_path)?;
    let path = config.identity_path.join("builder-promoter.ed25519");
    if path.exists() {
        let bytes = fs::read(&path)?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "builder promoter key material is corrupt",
            )
        })?;
        return Ok(seed);
    }
    let seed = zkf_core::secure_random::secure_random_seed().map_err(io::Error::other)?;
    fs::write(&path, seed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(seed)
}

fn write_shadow_log_entry(
    config: &SwarmConfig,
    record: &BuilderRuleRecord,
    false_positive: bool,
) -> io::Result<()> {
    let path = config.shadow_log_path.join(format!(
        "{}-{}.json",
        record.rule.id, record.updated_unix_ms
    ));
    write_json(
        path,
        &serde_json::json!({
            "rule_id": record.rule.id,
            "state": format!("{:?}", record.state),
            "shadow_observation_count": record.shadow_observation_count,
            "shadow_false_positive_rate": record.shadow_false_positive_rate,
            "false_positive": false_positive,
            "recorded_unix_ms": record.updated_unix_ms,
        }),
    )
}

fn rule_matches_telemetry(rule: &DetectionRule, value: &serde_json::Value) -> bool {
    match &rule.condition {
        DetectionCondition::ZScoreAbove { stage, threshold } => value
            .pointer("/outcome/per_stage_times_ms")
            .and_then(|map| map.get(stage))
            .and_then(|value| value.as_f64())
            .map(|observed| observed >= *threshold)
            .unwrap_or(false),
        DetectionCondition::TimingDeviationAbove { stage, ms } => value
            .pointer("/outcome/per_stage_times_ms")
            .and_then(|map| map.get(stage))
            .and_then(|value| value.as_f64())
            .map(|observed| observed >= *ms)
            .unwrap_or(false),
        DetectionCondition::ReputationBelow { threshold } => value
            .pointer("/swarm_telemetry/activation_level")
            .and_then(|value| value.as_f64())
            .map(|level| level < *threshold)
            .unwrap_or(false),
        DetectionCondition::SignalBurst { count, .. } => value
            .pointer("/watchdog_alerts")
            .and_then(|alerts| alerts.as_array())
            .map(|alerts| alerts.len() as u32 >= *count)
            .unwrap_or(false),
    }
}

fn count_json_entries(dir: &Path) -> io::Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) == Some("json") {
            count += 1;
        }
    }
    Ok(count)
}

fn genome_library_dir(config: &SwarmConfig) -> PathBuf {
    config.swarm_root().join("genomes")
}

fn read_genome_records(dir: &Path) -> io::Result<Vec<AttackGenome>> {
    let mut records = Vec::new();
    if !dir.exists() {
        return Ok(records);
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        records.push(read_json(entry.path())?);
    }
    records.sort_by_key(|record| record.created_unix_ms);
    Ok(records)
}

fn read_json<T: for<'de> Deserialize<'de>>(path: impl AsRef<Path>) -> io::Result<T> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    fs::write(path, bytes)
}

fn unix_time_now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_temp_home<T>(f: impl FnOnce(&Path) -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().unwrap();
        let old_home = std::env::var_os("HOME");
        unsafe {
            std::env::set_var("HOME", temp.path());
        }
        let result = f(temp.path());
        unsafe {
            if let Some(old_home) = old_home {
                std::env::set_var("HOME", old_home);
            } else {
                std::env::remove_var("HOME");
            }
        }
        result
    }

    #[test]
    fn builder_generates_detection_rule() {
        let pattern = AttackPattern {
            id: "pattern-1".to_string(),
            created_unix_ms: 1,
            last_seen_unix_ms: 1,
            occurrence_count: 3,
            stage_key: Some("ntt".to_string()),
            signal_kind: ThreatSignalKind::RuntimeAnomaly,
            severity: ThreatSeverity::High,
            taxonomy: AttackTaxonomy::Injection,
            z_score_range: (4.0, 5.0),
            timing_deviation_ms: Some(12.0),
            source_peer_hash: Some(7),
            genome_id: None,
            detection_rule: None,
            absorbed: false,
        };
        let rule = generate_detection_rule(&pattern);
        assert!(matches!(
            rule.condition,
            DetectionCondition::ZScoreAbove { .. }
        ));
        assert_eq!(rule.action, SecurityAction::RejectJob);
    }

    #[test]
    fn builder_absorbs_pattern_and_queues_retraining() {
        with_temp_home(|home| {
            let verdict = SecurityVerdict {
                risk_level: crate::security::SecurityRiskLevel::High,
                risk_score: None,
                signals: vec![
                    crate::security::ThreatSignal {
                        kind: ThreatSignalKind::RuntimeAnomaly,
                        severity: ThreatSeverity::High,
                        source: "unit".to_string(),
                        message: "signal one".to_string(),
                        stage_key: Some("ntt".to_string()),
                        observed_value: Some(4.0),
                        count: Some(1),
                    },
                    crate::security::ThreatSignal {
                        kind: ThreatSignalKind::RuntimeAnomaly,
                        severity: ThreatSeverity::High,
                        source: "unit".to_string(),
                        message: "signal two".to_string(),
                        stage_key: Some("ntt".to_string()),
                        observed_value: Some(5.0),
                        count: Some(1),
                    },
                    crate::security::ThreatSignal {
                        kind: ThreatSignalKind::RuntimeAnomaly,
                        severity: ThreatSeverity::High,
                        source: "unit".to_string(),
                        message: "signal three".to_string(),
                        stage_key: Some("ntt".to_string()),
                        observed_value: Some(6.0),
                        count: Some(1),
                    },
                ],
                actions: vec![SecurityAction::DisableHeuristicShortcuts],
                policy_source: "test".to_string(),
                countdown_safe: false,
                model_fingerprint: None,
                quarantined: false,
                reason: "test".to_string(),
            };
            let model_integrity = RuntimeModelIntegrity {
                policy_mode: crate::security::SecurityPolicyMode::Observe,
                trusted: true,
                pinned: true,
                allow_unpinned_dev_bypass: false,
                lane_fingerprints: Default::default(),
                lane_sources: Default::default(),
                manifest_hashes: Default::default(),
                integrity_failures: Vec::new(),
                freshness_notices: Vec::new(),
                quarantined_lanes: Vec::new(),
            };
            let telemetry_dir = home.join(".zkf").join("telemetry");
            fs::create_dir_all(&telemetry_dir).unwrap();
            write_json(
                telemetry_dir.join("record.json"),
                &serde_json::json!({
                    "outcome": { "per_stage_times_ms": { "ntt": 1.0 } },
                    "watchdog_alerts": [],
                    "swarm_telemetry": { "activation_level": 0 }
                }),
            )
            .unwrap();

            let patterns = record_security_event(&verdict, &model_integrity).unwrap();
            assert_eq!(patterns.len(), 3);
            let config = SwarmConfig::from_env();
            assert!(count_json_entries(&config.pattern_library_path).unwrap() >= 3);
            assert!(count_json_entries(&config.retrain_queue_path).unwrap() >= 1);
            assert_eq!(list_rules().unwrap()[0].state, RuleState::Validated);
            assert_eq!(list_genomes().unwrap().len(), 1);
        });
    }

    #[test]
    fn genome_prefix_detection_fires_on_early_attack_phase() {
        with_temp_home(|_| {
            let shared = AttackGenome {
                id: "shared-prefix".to_string(),
                created_unix_ms: 1,
                updated_unix_ms: 1,
                state: GenomeState::Live,
                taxonomy: AttackTaxonomy::Injection,
                stage_key: Some("backend-prove".to_string()),
                signal_sequence: vec![
                    ThreatSignalKind::RateLimitViolation,
                    ThreatSignalKind::AuthFailure,
                    ThreatSignalKind::TelemetryIntegrityMismatch,
                ],
                severity_sequence: vec![
                    ThreatSeverity::Moderate,
                    ThreatSeverity::High,
                    ThreatSeverity::Critical,
                ],
                occurrence_count: 1,
                prefix_match_count: 0,
                local_confirmation_count: 1,
                provenance: AttackGenomeProvenance::default(),
            };
            import_shared_genome(&shared, "peer-remote").unwrap();
            let config = SwarmConfig::from_env();
            let mut promoted = genome_history("shared-prefix").unwrap();
            promoted.state = GenomeState::Live;
            write_json(
                genome_library_dir(&config).join("shared-prefix.json"),
                &promoted,
            )
            .unwrap();

            let verdict = SecurityVerdict {
                risk_level: crate::security::SecurityRiskLevel::High,
                risk_score: None,
                signals: vec![
                    crate::security::ThreatSignal {
                        kind: ThreatSignalKind::RateLimitViolation,
                        severity: ThreatSeverity::Moderate,
                        source: "unit".to_string(),
                        message: "burst".to_string(),
                        stage_key: Some("backend-prove".to_string()),
                        observed_value: Some(1.0),
                        count: Some(4),
                    },
                    crate::security::ThreatSignal {
                        kind: ThreatSignalKind::AuthFailure,
                        severity: ThreatSeverity::High,
                        source: "unit".to_string(),
                        message: "auth probe".to_string(),
                        stage_key: Some("backend-prove".to_string()),
                        observed_value: Some(2.0),
                        count: Some(2),
                    },
                ],
                actions: vec![SecurityAction::QuorumVerify],
                policy_source: "test".to_string(),
                countdown_safe: false,
                model_fingerprint: None,
                quarantined: false,
                reason: "prefix".to_string(),
            };
            let model_integrity = RuntimeModelIntegrity {
                policy_mode: crate::security::SecurityPolicyMode::Observe,
                trusted: true,
                pinned: true,
                allow_unpinned_dev_bypass: false,
                lane_fingerprints: Default::default(),
                lane_sources: Default::default(),
                manifest_hashes: Default::default(),
                integrity_failures: Vec::new(),
                freshness_notices: Vec::new(),
                quarantined_lanes: Vec::new(),
            };
            let patterns = record_security_event(&verdict, &model_integrity).unwrap();
            assert!(patterns.iter().any(|pattern| {
                pattern.signal_kind == ThreatSignalKind::AttackGenomePrefixMatch
                    && pattern.genome_id.as_deref() == Some("shared-prefix")
            }));
            assert_eq!(
                genome_history("shared-prefix").unwrap().prefix_match_count,
                1
            );
        });
    }

    #[test]
    fn shared_genome_stays_shadow_until_local_confirmation() {
        with_temp_home(|_| {
            let shared = AttackGenome {
                id: "shadowed".to_string(),
                created_unix_ms: 1,
                updated_unix_ms: 1,
                state: GenomeState::Live,
                taxonomy: AttackTaxonomy::Injection,
                stage_key: Some("backend-prove".to_string()),
                signal_sequence: vec![
                    ThreatSignalKind::AuthFailure,
                    ThreatSignalKind::TelemetryIntegrityMismatch,
                ],
                severity_sequence: vec![ThreatSeverity::High, ThreatSeverity::Critical],
                occurrence_count: 1,
                prefix_match_count: 0,
                local_confirmation_count: 1,
                provenance: AttackGenomeProvenance::default(),
            };
            let imported = import_shared_genome(&shared, "peer-remote").unwrap();
            assert_eq!(imported.state, GenomeState::Shadow);
            assert_eq!(
                genome_history("shadowed").unwrap().state,
                GenomeState::Shadow
            );

            let verdict = SecurityVerdict {
                risk_level: crate::security::SecurityRiskLevel::Critical,
                risk_score: None,
                signals: vec![
                    crate::security::ThreatSignal {
                        kind: ThreatSignalKind::AuthFailure,
                        severity: ThreatSeverity::High,
                        source: "unit".to_string(),
                        message: "auth probe".to_string(),
                        stage_key: Some("backend-prove".to_string()),
                        observed_value: Some(2.0),
                        count: Some(2),
                    },
                    crate::security::ThreatSignal {
                        kind: ThreatSignalKind::TelemetryIntegrityMismatch,
                        severity: ThreatSeverity::Critical,
                        source: "unit".to_string(),
                        message: "tamper".to_string(),
                        stage_key: Some("backend-prove".to_string()),
                        observed_value: Some(4.0),
                        count: Some(1),
                    },
                ],
                actions: vec![SecurityAction::RejectJob],
                policy_source: "test".to_string(),
                countdown_safe: false,
                model_fingerprint: None,
                quarantined: false,
                reason: "confirm".to_string(),
            };
            let model_integrity = RuntimeModelIntegrity {
                policy_mode: crate::security::SecurityPolicyMode::Observe,
                trusted: true,
                pinned: true,
                allow_unpinned_dev_bypass: false,
                lane_fingerprints: Default::default(),
                lane_sources: Default::default(),
                manifest_hashes: Default::default(),
                integrity_failures: Vec::new(),
                freshness_notices: Vec::new(),
                quarantined_lanes: Vec::new(),
            };
            let _ = record_security_event(&verdict, &model_integrity).unwrap();
            let confirmed = genome_history("shadowed").unwrap();
            assert_eq!(confirmed.state, GenomeState::Live);
            assert_eq!(confirmed.local_confirmation_count, 1);
        });
    }

    #[test]
    fn shadow_observations_auto_promote_low_impact_rules() {
        with_temp_home(|_| {
            let config = SwarmConfig::from_env();
            let record = BuilderRuleRecord {
                rule: DetectionRule {
                    id: "rule-shadow".to_string(),
                    condition: DetectionCondition::SignalBurst {
                        kind: ThreatSignalKind::RuntimeAnomaly,
                        count: 3,
                        window_ms: 1000,
                    },
                    action: SecurityAction::DisableHeuristicShortcuts,
                    confidence: 0.9,
                    min_observations: 3,
                },
                state: RuleState::Shadow,
                created_unix_ms: 1,
                updated_unix_ms: 1,
                shadow_observation_count: MIN_SHADOW_OBSERVATIONS - 1,
                shadow_false_positive_rate: 0.0,
                history: vec![],
            };
            write_json(config.rules_path.join("rule-shadow.json"), &record).unwrap();
            let updated = record_shadow_observation("rule-shadow", false).unwrap();
            assert_eq!(updated.state, RuleState::Live);
        });
    }

    #[test]
    fn high_impact_rules_are_not_auto_promoted() {
        with_temp_home(|_| {
            let config = SwarmConfig::from_env();
            let record = BuilderRuleRecord {
                rule: DetectionRule {
                    id: "rule-reject".to_string(),
                    condition: DetectionCondition::SignalBurst {
                        kind: ThreatSignalKind::RuntimeAnomaly,
                        count: 3,
                        window_ms: 1000,
                    },
                    action: SecurityAction::RejectJob,
                    confidence: 0.9,
                    min_observations: 3,
                },
                state: RuleState::Shadow,
                created_unix_ms: 1,
                updated_unix_ms: 1,
                shadow_observation_count: MIN_SHADOW_OBSERVATIONS - 1,
                shadow_false_positive_rate: 0.0,
                history: vec![],
            };
            write_json(config.rules_path.join("rule-reject.json"), &record).unwrap();
            let updated = record_shadow_observation("rule-reject", false).unwrap();
            assert_eq!(updated.state, RuleState::Shadow);
        });
    }

    #[test]
    fn shadow_false_positive_rate_revokes_rule() {
        with_temp_home(|_| {
            let config = SwarmConfig::from_env();
            let record = BuilderRuleRecord {
                rule: DetectionRule {
                    id: "rule-noisy".to_string(),
                    condition: DetectionCondition::SignalBurst {
                        kind: ThreatSignalKind::RuntimeAnomaly,
                        count: 3,
                        window_ms: 1000,
                    },
                    action: SecurityAction::DisableHeuristicShortcuts,
                    confidence: 0.9,
                    min_observations: 3,
                },
                state: RuleState::Shadow,
                created_unix_ms: 1,
                updated_unix_ms: 1,
                shadow_observation_count: MIN_SHADOW_OBSERVATIONS - 1,
                shadow_false_positive_rate: 0.25,
                history: vec![],
            };
            write_json(config.rules_path.join("rule-noisy.json"), &record).unwrap();
            let updated = record_shadow_observation("rule-noisy", true).unwrap();
            assert_eq!(updated.state, RuleState::Revoked);
            assert!(count_json_entries(&config.rollbacks_path).unwrap() >= 1);
        });
    }
}
