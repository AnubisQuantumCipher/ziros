use crate::state::{ensure_ziros_layout, hermes_home_root, ziros_home_root};
use crate::types::{
    AgentRunOptionsV1, BridgeFallbackPolicyV1, BridgePolicyV1, BridgeStatusReportV1,
    BridgeTaskClassV1, GoalIntentV1, ReasoningProvenanceV1, WorkgraphV1,
};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use zkf_command_surface::now_rfc3339;

const BRIDGE_POLICY_SCHEMA: &str = "ziros-bridge-policy-v1";
const BRIDGE_STATUS_SCHEMA: &str = "ziros-agent-bridge-status-v1";
const LAB_ROUTER_SCHEMA: &str = "hermes-crypto-bridge-routing-policy-v1";
const PRIMARY_LANE: &str = "chatgpt-pro-bridge";
const PRIMARY_MODEL_LABEL: &str = "GPT-5.4 Thinking";
const BRIDGE_AUTH_MODE: &str = "chatgpt-pro-subscription";
const GATEWAY_LABEL: &str = "com.ziros.gateway";
const LOCALHOSTRUN_LABEL: &str = "com.ziros.chatgpt-localhostrun";
const DEFAULT_GATEWAY_BIND: &str = "127.0.0.1:8788";

#[derive(Debug, Deserialize)]
struct GatewayConfigV1 {
    bind: String,
}

pub fn bridge_policy_path() -> PathBuf {
    ziros_home_root().join("bridge-policy.json")
}

fn chatgpt_bridge_root() -> PathBuf {
    ziros_home_root().join("chatgpt-bridge")
}

fn gateway_config_path() -> PathBuf {
    chatgpt_bridge_root().join("gateway-config.json")
}

fn mcp_url_path() -> PathBuf {
    chatgpt_bridge_root().join("mcp-url.txt")
}

fn crypto_operator_lab_bridge_policy_path() -> PathBuf {
    hermes_home_root()
        .join("crypto-operator-lab")
        .join("router")
        .join("bridge-routing-policy.json")
}

pub fn default_bridge_policy() -> BridgePolicyV1 {
    BridgePolicyV1 {
        schema: BRIDGE_POLICY_SCHEMA.to_string(),
        primary_lane: PRIMARY_LANE.to_string(),
        primary_model_label: PRIMARY_MODEL_LABEL.to_string(),
        critical_task_classes: vec![
            BridgeTaskClassV1::Planning,
            BridgeTaskClassV1::Implementation,
            BridgeTaskClassV1::Audit,
            BridgeTaskClassV1::Proof,
            BridgeTaskClassV1::RepoForensics,
            BridgeTaskClassV1::Release,
        ],
        local_execution_required: true,
        allow_remote_mutation: false,
        fallback_policy: BridgeFallbackPolicyV1::FailClosed,
        fallback_allowed_task_classes: Vec::new(),
        downgrade_label_required: true,
    }
}

pub fn load_bridge_policy() -> Result<BridgePolicyV1, String> {
    let _ = ensure_ziros_layout()?;
    let path = bridge_policy_path();
    let policy = if path.exists() {
        serde_json::from_slice::<BridgePolicyV1>(
            &fs::read(&path)
                .map_err(|error| format!("failed to read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?
    } else {
        let policy = default_bridge_policy();
        save_bridge_policy(&policy)?;
        policy
    };
    let _ = sync_crypto_operator_lab_bridge_policy(&policy);
    Ok(policy)
}

pub fn save_bridge_policy(policy: &BridgePolicyV1) -> Result<(), String> {
    let _ = ensure_ziros_layout()?;
    let path = bridge_policy_path();
    let body = serde_json::to_vec_pretty(policy).map_err(|error| error.to_string())?;
    fs::write(&path, body).map_err(|error| format!("failed to write {}: {error}", path.display()))
}

pub fn bridge_status() -> Result<BridgeStatusReportV1, String> {
    let policy = load_bridge_policy()?;
    let mcp_url = read_trimmed_path(&mcp_url_path()).or_else(read_mcp_url_from_log);
    let bind = read_gateway_config()
        .map(|config| config.bind)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_GATEWAY_BIND.to_string());
    Ok(BridgeStatusReportV1 {
        schema: BRIDGE_STATUS_SCHEMA.to_string(),
        generated_at: now_rfc3339(),
        policy_path: bridge_policy_path().display().to_string(),
        bridge_present: mcp_url.is_some(),
        bridge_mcp_url: mcp_url.clone(),
        bridge_remote_health: mcp_url.as_deref().map(url_health_ok).unwrap_or(false),
        bridge_local_gateway_health: url_health_ok(&format!("http://{bind}/health")),
        bridge_gateway_configured: gateway_config_path().exists(),
        bridge_gateway_running: launch_agent_running(GATEWAY_LABEL),
        bridge_tunnel_running: launch_agent_running(LOCALHOSTRUN_LABEL),
        bridge_model_label: policy.primary_model_label.clone(),
        bridge_exposure: if policy.allow_remote_mutation {
            "remote-bridge-write".to_string()
        } else {
            "remote-bridge-read-only".to_string()
        },
        bridge_auth_mode: BRIDGE_AUTH_MODE.to_string(),
        primary_intelligence_lane: policy.primary_lane.clone(),
        fallback_policy: policy.fallback_policy,
        policy,
    })
}

pub fn classify_task(goal: &str, intent: &GoalIntentV1) -> BridgeTaskClassV1 {
    let lower_goal = goal.to_ascii_lowercase();
    let workflow = intent.workflow_kind.as_str();
    if workflow.contains("release") || workflow == "evidence-bundle" {
        return BridgeTaskClassV1::Release;
    }
    if workflow.contains("benchmark") {
        return BridgeTaskClassV1::Benchmark;
    }
    if workflow.contains("proof") {
        return BridgeTaskClassV1::Proof;
    }
    if workflow == "generic-investigation" {
        if lower_goal.contains("audit")
            || lower_goal.contains("vulnerability")
            || lower_goal.contains("crypto review")
            || lower_goal.contains("zero-day")
        {
            return BridgeTaskClassV1::Audit;
        }
        if lower_goal.contains("forensics")
            || lower_goal.contains("trace")
            || lower_goal.contains("inventory")
        {
            return BridgeTaskClassV1::RepoForensics;
        }
        if lower_goal.contains("study")
            || lower_goal.contains("learn")
            || lower_goal.contains("read")
        {
            return BridgeTaskClassV1::Study;
        }
        return BridgeTaskClassV1::Retrieval;
    }
    if lower_goal.contains("exploit")
        || lower_goal.contains("poc")
        || lower_goal.contains("reproduce")
    {
        return BridgeTaskClassV1::LocalPoc;
    }
    if lower_goal.contains("audit")
        || lower_goal.contains("review")
        || lower_goal.contains("side-channel")
    {
        return BridgeTaskClassV1::Audit;
    }
    if lower_goal.contains("plan") || lower_goal.contains("strategy") {
        return BridgeTaskClassV1::Planning;
    }
    if workflow.starts_with("midnight-")
        || workflow.starts_with("subsystem-")
        || workflow == "proof-app-build"
    {
        return BridgeTaskClassV1::Implementation;
    }
    BridgeTaskClassV1::Study
}

pub fn build_reasoning_provenance(
    policy: &BridgePolicyV1,
    task_class: BridgeTaskClassV1,
    options: &AgentRunOptionsV1,
) -> ReasoningProvenanceV1 {
    let reasoning_lane = options
        .reasoning_lane
        .clone()
        .unwrap_or_else(|| "embedded-zkf-planner".to_string());
    let primary_lane_used = reasoning_lane == policy.primary_lane;
    let downgrade_reason = (!primary_lane_used).then(|| {
        if matches!(policy.fallback_policy, BridgeFallbackPolicyV1::FailClosed)
            && policy.critical_task_classes.contains(&task_class)
        {
            format!(
                "bridge-first policy requires {} ({}) for critical task class {}",
                policy.primary_lane,
                policy.primary_model_label,
                task_class.as_str()
            )
        } else {
            format!(
                "primary reasoning lane {} was not used",
                policy.primary_lane
            )
        }
    });
    ReasoningProvenanceV1 {
        task_class,
        reasoning_lane,
        reasoning_primary: primary_lane_used,
        reasoning_model_label: options.reasoning_model_label.clone().unwrap_or_else(|| {
            if primary_lane_used {
                policy.primary_model_label.clone()
            } else if let Some(model_override) = options.model_override.clone() {
                model_override
            } else {
                "embedded-zkf-planner".to_string()
            }
        }),
        reasoning_origin: options.reasoning_origin.clone().unwrap_or_else(|| {
            if options.provider_override.is_some() || options.model_override.is_some() {
                "local-provider".to_string()
            } else {
                "local-agent".to_string()
            }
        }),
        execution_origin: "local-hermes".to_string(),
        primary_lane_expected: policy.primary_lane.clone(),
        primary_lane_used,
        downgraded_from_primary: !primary_lane_used,
        downgrade_reason,
    }
}

pub fn apply_bridge_policy_guards(
    workgraph: &mut WorkgraphV1,
    policy: &BridgePolicyV1,
    provenance: &ReasoningProvenanceV1,
) {
    if provenance.primary_lane_used {
        return;
    }
    if !policy
        .critical_task_classes
        .contains(&provenance.task_class)
    {
        return;
    }
    if !matches!(policy.fallback_policy, BridgeFallbackPolicyV1::FailClosed) {
        return;
    }
    workgraph.blocked_prerequisites.push(format!(
        "bridge-first policy requires {} ({}) for task class {}; local downgrade is blocked",
        policy.primary_lane,
        policy.primary_model_label,
        provenance.task_class.as_str()
    ));
}

pub fn should_bypass_local_model_intent_compilation(options: &AgentRunOptionsV1) -> bool {
    load_bridge_policy()
        .map(|policy| {
            if options
                .reasoning_lane
                .as_deref()
                .is_some_and(|lane| lane == policy.primary_lane)
            {
                return true;
            }
            policy.primary_lane == PRIMARY_LANE
        })
        .unwrap_or(false)
}

pub fn sync_crypto_operator_lab_bridge_policy(policy: &BridgePolicyV1) -> Result<(), String> {
    let path = crypto_operator_lab_bridge_policy_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let payload = json!({
        "schema": LAB_ROUTER_SCHEMA,
        "generated_at": now_rfc3339(),
        "primary_reasoning_lane": policy.primary_lane,
        "primary_model_label": policy.primary_model_label,
        "local_execution_required": policy.local_execution_required,
        "allow_remote_mutation": policy.allow_remote_mutation,
        "fallback_policy": policy.fallback_policy,
        "critical_task_classes": policy.critical_task_classes,
        "fallback_allowed_task_classes": policy.fallback_allowed_task_classes,
        "downgrade_label_required": policy.downgrade_label_required,
    });
    let body = serde_json::to_vec_pretty(&payload).map_err(|error| error.to_string())?;
    fs::write(&path, body).map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn read_gateway_config() -> Option<GatewayConfigV1> {
    fs::read(gateway_config_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<GatewayConfigV1>(&bytes).ok())
}

fn read_trimmed_path(path: &std::path::Path) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_mcp_url_from_log() -> Option<String> {
    let path = ziros_home_root()
        .join("logs")
        .join("chatgpt-localhostrun.stdout.log");
    let text = fs::read_to_string(path).ok()?;
    text.lines().rev().find_map(|line| {
        line.split_whitespace()
            .find(|part| part.starts_with("https://") && part.ends_with(".lhr.life"))
            .map(|value| format!("{}/mcp", value.trim_end_matches('/')))
    })
}

fn url_health_ok(url: &str) -> bool {
    let health_url = if url.ends_with("/mcp") {
        format!("{}/health", url.trim_end_matches("/mcp"))
    } else if url.ends_with("/health") {
        url.to_string()
    } else {
        format!("{}/health", url.trim_end_matches('/'))
    };
    ureq::get(&health_url)
        .timeout(std::time::Duration::from_secs(2))
        .call()
        .map(|response| response.status() >= 200 && response.status() < 300)
        .unwrap_or(false)
}

fn launch_agent_running(label: &str) -> bool {
    let uid = std::env::var("UID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            Command::new("id")
                .arg("-u")
                .output()
                .ok()
                .and_then(|output| String::from_utf8(output.stdout).ok())
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        });
    let Some(uid) = uid else {
        return false;
    };
    Command::new("launchctl")
        .args(["print", &format!("gui/{uid}/{label}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::{BridgeFallbackPolicyV1, BridgeTaskClassV1, classify_task, default_bridge_policy};
    use crate::types::{GoalIntentV1, IntentScopeV1};

    #[test]
    fn default_policy_is_bridge_first_fail_closed() {
        let policy = default_bridge_policy();
        assert_eq!(policy.primary_lane, "chatgpt-pro-bridge");
        assert_eq!(policy.primary_model_label, "GPT-5.4 Thinking");
        assert!(matches!(
            policy.fallback_policy,
            BridgeFallbackPolicyV1::FailClosed
        ));
        assert!(
            policy
                .critical_task_classes
                .contains(&BridgeTaskClassV1::Audit)
        );
    }

    #[test]
    fn classifies_release_and_audit_tasks() {
        let release_intent = GoalIntentV1 {
            summary: "release".to_string(),
            workflow_kind: "evidence-bundle".to_string(),
            scope: IntentScopeV1::Release,
            requested_outputs: Vec::new(),
            hints: None,
        };
        assert!(matches!(
            classify_task("prepare the release bundle", &release_intent),
            BridgeTaskClassV1::Release
        ));

        let audit_intent = GoalIntentV1 {
            summary: "audit".to_string(),
            workflow_kind: "generic-investigation".to_string(),
            scope: IntentScopeV1::Project,
            requested_outputs: Vec::new(),
            hints: None,
        };
        assert!(matches!(
            classify_task(
                "audit this TLS implementation for side-channel issues",
                &audit_intent
            ),
            BridgeTaskClassV1::Audit
        ));
    }
}
