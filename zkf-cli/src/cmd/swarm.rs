use serde::Serialize;
use zkf_distributed::{
    ClusterConfig, LocalPeerIdentity, PeerReputation, ReputationEvent, load_reputation_events,
    load_reputation_events_for, load_reputation_score_for, load_reputation_scores,
    local_identity_label, verify_reputation_log, verify_reputation_log_report,
};
use zkf_runtime::swarm::builder;
use zkf_runtime::swarm::{SwarmConfig, current_activation_level};
use zkf_runtime::{BuilderRuleRecord, RuleState};

#[derive(Debug, Serialize)]
pub(crate) struct SwarmStatusReport {
    pub(crate) enabled: bool,
    pub(crate) activation_level: String,
    pub(crate) key_backend: String,
    pub(crate) identity_label: String,
    pub(crate) peer_id: String,
    pub(crate) public_key: String,
    pub(crate) public_key_resynced: bool,
    pub(crate) rule_count: usize,
    pub(crate) candidate_rule_count: usize,
    pub(crate) shadow_rule_count: usize,
    pub(crate) live_rule_count: usize,
    pub(crate) pattern_count: u32,
    pub(crate) reputation_entries: usize,
    pub(crate) recent_rules: Vec<RuleSummary>,
    pub(crate) recent_reputation_events: Vec<RecentReputationEvent>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RuleSummary {
    pub(crate) id: String,
    pub(crate) state: String,
    pub(crate) shadow_observation_count: u64,
    pub(crate) shadow_false_positive_rate: f64,
}

#[derive(Debug, Serialize)]
pub(crate) struct RecentReputationEvent {
    pub(crate) peer_id: String,
    pub(crate) event: String,
    pub(crate) old_reputation: f64,
    pub(crate) new_reputation: f64,
}

pub(crate) fn handle_swarm(command: crate::cli::SwarmCommands) -> Result<(), String> {
    match command {
        crate::cli::SwarmCommands::Status { json } => handle_status(json),
        crate::cli::SwarmCommands::RotateKey { json } => handle_rotate_key(json),
        crate::cli::SwarmCommands::RegenerateKey { force, json } => {
            handle_regenerate_key(force, json)
        }
        crate::cli::SwarmCommands::ListRules { json } => handle_list_rules(json),
        crate::cli::SwarmCommands::ShadowRule { rule_id, json } => {
            handle_rule_transition(json, shadow_rule_report(&rule_id))
        }
        crate::cli::SwarmCommands::PromoteRule { rule_id, json } => {
            handle_rule_transition(json, promote_rule_report(&rule_id))
        }
        crate::cli::SwarmCommands::RevokeRule { rule_id, json } => {
            handle_rule_transition(json, revoke_rule_report(&rule_id))
        }
        crate::cli::SwarmCommands::RuleHistory { rule_id, json } => {
            handle_rule_transition(json, rule_history_report(&rule_id))
        }
        crate::cli::SwarmCommands::Reputation { peer_id, all, json } => {
            handle_reputation(peer_scope(peer_id.as_deref(), all)?, json)
        }
        crate::cli::SwarmCommands::ReputationLog { peer_id, all, json } => {
            handle_reputation_log(peer_scope(peer_id.as_deref(), all)?, json)
        }
        crate::cli::SwarmCommands::ReputationVerify { peer_id, all, json } => {
            handle_reputation_verify(peer_scope(peer_id.as_deref(), all)?, json)
        }
    }
}

fn peer_scope(peer_id: Option<&str>, all: bool) -> Result<Option<&str>, String> {
    if all && peer_id.is_some() {
        return Err("specify either <peer_id> or --all, not both".to_string());
    }
    Ok(peer_id)
}

fn handle_status(json: bool) -> Result<(), String> {
    let report = swarm_status_report()?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "swarm status: enabled={} activation={} backend={} peer_id={} rules={} (candidate={} shadow={} live={}) patterns={} reputations={}",
            report.enabled,
            report.activation_level,
            report.key_backend,
            report.peer_id,
            report.rule_count,
            report.candidate_rule_count,
            report.shadow_rule_count,
            report.live_rule_count,
            report.pattern_count,
            report.reputation_entries
        );
        if report.public_key_resynced {
            println!("warning: repaired the local swarm public-key sidecar from the private seed");
        }
    }
    Ok(())
}

fn handle_rotate_key(json: bool) -> Result<(), String> {
    render_identity_report(json, rotate_identity_report()?)
}

fn handle_regenerate_key(force: bool, json: bool) -> Result<(), String> {
    render_identity_report(json, regenerate_identity_report(force)?)
}

fn render_identity_report(json: bool, payload: serde_json::Value) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "rotated swarm identity: peer_id={} backend={}",
            payload["peer_id"].as_str().unwrap_or_default(),
            payload["backend"].as_str().unwrap_or_default()
        );
    }
    Ok(())
}

fn handle_list_rules(json: bool) -> Result<(), String> {
    let rules = list_rules_report()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&rules).map_err(|err| err.to_string())?
        );
    } else {
        for rule in rules {
            println!(
                "{} state={:?} action={:?} min_obs={}",
                rule.rule.id, rule.state, rule.rule.action, rule.rule.min_observations
            );
        }
    }
    Ok(())
}

fn handle_rule_transition<T>(json: bool, result: Result<T, String>) -> Result<(), String>
where
    T: Serialize,
{
    let value = result?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&value).map_err(|err| err.to_string())?
        );
    }
    Ok(())
}

fn handle_reputation(peer_id: Option<&str>, json: bool) -> Result<(), String> {
    let reputations = reputation_scores_report(peer_id)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&reputations).map_err(|err| err.to_string())?
        );
    } else {
        for entry in reputations {
            println!("{} {:.2}", entry.peer_id, entry.score);
        }
    }
    Ok(())
}

fn handle_reputation_log(peer_id: Option<&str>, json: bool) -> Result<(), String> {
    let events = reputation_log_entries(peer_id)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&events).map_err(|err| err.to_string())?
        );
    } else {
        for event in events {
            println!(
                "{} {:?} {:.2}->{:.2} at {}",
                event.peer_id,
                event.event,
                event.old_reputation,
                event.new_reputation,
                event.timestamp_unix_ms
            );
        }
    }
    Ok(())
}

fn handle_reputation_verify(peer_id: Option<&str>, json: bool) -> Result<(), String> {
    let payload = reputation_verify_report(peer_id)?;
    if json {
        println!("{payload}");
    } else if let Some(peer_id) = peer_id {
        println!("swarm reputation log verified for {peer_id}");
    } else {
        println!("swarm reputation log verified");
    }
    Ok(())
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(crate) fn swarm_status_report() -> Result<SwarmStatusReport, String> {
    let swarm_config = SwarmConfig::from_env();
    let cluster_config = ClusterConfig::from_env().map_err(|err| err.to_string())?;
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    let identity_label = local_identity_label(&hostname, cluster_config.bind_addr.port());
    let identity = LocalPeerIdentity::load_or_create(&swarm_config, &identity_label)
        .map_err(|err| err.to_string())?;
    let rules = builder::list_rules().map_err(|err| err.to_string())?;
    let pattern_count = builder::pattern_count().unwrap_or_default();
    let reputations = load_reputation_scores().map_err(|err| err.to_string())?;
    let recent_events = reputation_log_entries(None)?;
    Ok(SwarmStatusReport {
        enabled: swarm_config.enabled,
        activation_level: current_activation_level().as_str().to_string(),
        key_backend: swarm_config.key_backend.as_str().to_string(),
        identity_label,
        peer_id: identity.stable_peer_id().0,
        public_key: hex_string(&identity.public_key_bytes()),
        public_key_resynced: identity.public_key_resynced(),
        rule_count: rules.len(),
        candidate_rule_count: rules
            .iter()
            .filter(|rule| rule.state == RuleState::Candidate)
            .count(),
        shadow_rule_count: rules
            .iter()
            .filter(|rule| rule.state == RuleState::Shadow)
            .count(),
        live_rule_count: rules
            .iter()
            .filter(|rule| rule.state == RuleState::Live)
            .count(),
        pattern_count,
        reputation_entries: reputations.len(),
        recent_rules: rules
            .iter()
            .rev()
            .take(5)
            .map(|rule| RuleSummary {
                id: rule.rule.id.clone(),
                state: format!("{:?}", rule.state),
                shadow_observation_count: rule.shadow_observation_count,
                shadow_false_positive_rate: rule.shadow_false_positive_rate,
            })
            .collect(),
        recent_reputation_events: recent_events
            .iter()
            .rev()
            .take(5)
            .map(|event| RecentReputationEvent {
                peer_id: event.peer_id.clone(),
                event: format!("{:?}", event.event),
                old_reputation: event.old_reputation,
                new_reputation: event.new_reputation,
            })
            .collect(),
    })
}

pub(crate) fn list_rules_report() -> Result<Vec<BuilderRuleRecord>, String> {
    builder::list_rules().map_err(|err| err.to_string())
}

pub(crate) fn rule_history_report(rule_id: &str) -> Result<BuilderRuleRecord, String> {
    builder::rule_history(rule_id).map_err(|err| err.to_string())
}

pub(crate) fn shadow_rule_report(rule_id: &str) -> Result<BuilderRuleRecord, String> {
    builder::shadow_rule(rule_id).map_err(|err| err.to_string())
}

pub(crate) fn promote_rule_report(rule_id: &str) -> Result<BuilderRuleRecord, String> {
    builder::promote_rule(rule_id).map_err(|err| err.to_string())
}

pub(crate) fn revoke_rule_report(rule_id: &str) -> Result<BuilderRuleRecord, String> {
    builder::revoke_rule(rule_id).map_err(|err| err.to_string())
}

pub(crate) fn rotate_identity_report() -> Result<serde_json::Value, String> {
    let swarm_config = SwarmConfig::from_env();
    let cluster_config = ClusterConfig::from_env().map_err(|err| err.to_string())?;
    let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
    let identity_label = local_identity_label(&hostname, cluster_config.bind_addr.port());
    let identity =
        LocalPeerIdentity::rotate(&swarm_config, &identity_label).map_err(|err| err.to_string())?;
    Ok(serde_json::json!({
        "identity_label": identity_label,
        "peer_id": identity.stable_peer_id().0,
        "public_key": hex_string(&identity.public_key_bytes()),
        "backend": identity.backend_name(),
    }))
}

pub(crate) fn regenerate_identity_report(force: bool) -> Result<serde_json::Value, String> {
    if !force {
        return Err("`zkf swarm regenerate-key` requires `--force`".to_string());
    }
    rotate_identity_report()
}

pub(crate) fn reputation_scores_report(
    peer_id: Option<&str>,
) -> Result<Vec<PeerReputation>, String> {
    match peer_id {
        Some(peer_id) => load_reputation_score_for(peer_id)
            .map_err(|err| err.to_string())?
            .map(|entry| vec![entry])
            .ok_or_else(|| format!("no reputation score found for peer {peer_id}")),
        None => load_reputation_scores().map_err(|err| err.to_string()),
    }
}

pub(crate) fn reputation_log_entries(
    peer_id: Option<&str>,
) -> Result<Vec<ReputationEvent>, String> {
    match peer_id {
        Some(peer_id) => load_reputation_events_for(peer_id).map_err(|err| err.to_string()),
        None => load_reputation_events().map_err(|err| err.to_string()),
    }
}

pub(crate) fn reputation_verify_report(peer_id: Option<&str>) -> Result<serde_json::Value, String> {
    match peer_id {
        Some(peer_id) => serde_json::to_value(
            verify_reputation_log_report(Some(peer_id)).map_err(|err| err.to_string())?,
        )
        .map_err(|err| err.to_string()),
        None => {
            verify_reputation_log().map_err(|err| err.to_string())?;
            Ok(serde_json::json!({ "verified": true }))
        }
    }
}
