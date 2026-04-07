use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use zkf_command_surface::midnight::MidnightStatusReportV1;
use zkf_command_surface::{
    ActionDescriptorV1, ArtifactRefV1, CommandErrorClassV1, MetricRecordV1, RiskClassV1,
};
use zkf_wallet::{ApprovalToken, WalletNetwork};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SessionStatusV1 {
    Planned,
    Blocked,
    Cancelled,
    Completed,
}

impl SessionStatusV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Blocked => "blocked",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunOptionsV1 {
    pub strict: bool,
    pub compat_allowed: bool,
    pub wallet_network: WalletNetwork,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<PathBuf>,
    #[serde(default = "default_use_worktree")]
    pub use_worktree: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_override: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub intent: Option<GoalIntentV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_override: Option<String>,
}

impl Default for AgentRunOptionsV1 {
    fn default() -> Self {
        Self {
            strict: true,
            compat_allowed: false,
            wallet_network: WalletNetwork::Preprod,
            project_root: None,
            use_worktree: true,
            workflow_override: None,
            intent: None,
            provider_override: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IntentScopeV1 {
    Host,
    Project,
    Release,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TargetChainProfileV1 {
    Midnight,
    Evm,
    Hybrid,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentHintsV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_wallet: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_metal: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subsystem_style: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub midnight_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_template: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_parallel: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub benchmark_distributed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_chain: Option<TargetChainProfileV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalIntentV1 {
    pub summary: String,
    pub workflow_kind: String,
    pub scope: IntentScopeV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_outputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<IntentHintsV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRequirementV1 {
    pub id: String,
    pub required: bool,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuccessPredicateV1 {
    pub id: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPolicyV1 {
    pub strict: bool,
    pub compat_allowed: bool,
    pub stop_on_first_failure: bool,
    pub require_explicit_approval_for_high_risk: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRequirementsV1 {
    pub strict: bool,
    pub compat_allowed: bool,
    pub require_midnight: bool,
    pub require_evm: bool,
    pub require_wallet: bool,
    pub require_metal: bool,
    pub wallet_network: WalletNetwork,
}

impl WorkflowRequirementsV1 {
    pub fn for_goal(goal: &str, intent: &GoalIntentV1, options: &AgentRunOptionsV1) -> Self {
        let lower = goal.to_ascii_lowercase();
        let hints = intent.hints.as_ref();
        let require_wallet = hints
            .and_then(|value| value.require_wallet)
            .unwrap_or_else(|| match intent.workflow_kind.as_str() {
            "midnight-contract-ops" | "subsystem-midnight-ops" => {
                lower.contains("deploy")
                    || lower.contains("submit")
                    || lower.contains("call")
                    || lower.contains("wallet")
            }
            _ => false,
        });
        let require_metal = hints
            .and_then(|value| value.require_metal)
            .unwrap_or(
                intent.workflow_kind == "benchmark-report"
                    || intent.workflow_kind == "subsystem-benchmark"
                    || lower.contains("metal")
                    || lower.contains("gpu")
                    || lower.contains("apple silicon"),
            );
        Self {
            strict: options.strict,
            compat_allowed: options.compat_allowed,
            require_midnight: intent.workflow_kind.starts_with("midnight-")
                || intent.workflow_kind == "subsystem-midnight-ops",
            require_evm: intent.workflow_kind == "subsystem-evm-ops",
            require_wallet,
            require_metal,
            wallet_network: options.wallet_network,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletReadinessV1 {
    pub network: String,
    pub ready: bool,
    pub locked: bool,
    pub has_imported_seed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustGateReportV1 {
    pub schema: String,
    pub gate_id: String,
    pub generated_at: String,
    pub workflow_kind: String,
    pub strict: bool,
    pub compat_allowed: bool,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub prerequisites: Vec<String>,
    pub truth_snapshot: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub midnight_status: Option<MidnightStatusReportV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<WalletReadinessV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvironmentSnapshotV1 {
    pub schema: String,
    pub snapshot_id: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub workflow_kind: String,
    pub strict: bool,
    pub compat_allowed: bool,
    pub truth_snapshot: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub midnight_status: Option<MidnightStatusReportV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet: Option<WalletReadinessV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkgraphNodeV1 {
    pub node_id: String,
    pub label: String,
    pub action_name: String,
    pub status: String,
    pub approval_required: bool,
    pub risk_class: RiskClassV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub success_predicates: Vec<SuccessPredicateV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub depends_on: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expected_artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkgraphV1 {
    pub schema: String,
    pub workgraph_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub workflow_kind: String,
    pub status: String,
    pub goal: String,
    pub intent: GoalIntentV1,
    pub execution_policy: ExecutionPolicyV1,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_requirements: Vec<CapabilityRequirementV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_prerequisites: Vec<String>,
    pub nodes: Vec<WorkgraphNodeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionReceiptV1 {
    pub schema: String,
    pub receipt_id: String,
    pub session_id: String,
    pub action_name: String,
    pub status: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionDescriptorV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRefV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub metrics: Vec<MetricRecordV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_class: Option<CommandErrorClassV1>,
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRecordV1 {
    pub schema: String,
    pub artifact_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub created_at: String,
    pub artifact: ArtifactRefV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcedureRecordV1 {
    pub schema: String,
    pub procedure_id: String,
    pub created_at: String,
    pub workflow_kind: String,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub action_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentRecordV1 {
    pub schema: String,
    pub incident_id: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub action_name: String,
    pub error_class: CommandErrorClassV1,
    pub summary: String,
    pub details: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestRecordV1 {
    pub schema: String,
    pub approval_request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub created_at: String,
    pub pending_id: String,
    pub risk_class: RiskClassV1,
    pub action_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wallet_pending_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalTokenRecordV1 {
    pub schema: String,
    pub token_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub created_at: String,
    pub pending_id: String,
    pub token: ApprovalToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmissionGrantRecordV1 {
    pub schema: String,
    pub grant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    pub summary: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecordV1 {
    pub schema: String,
    pub deployment_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub created_at: String,
    pub workflow_kind: String,
    pub summary: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorktreeRecordV1 {
    pub schema: String,
    pub worktree_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub created_at: String,
    pub repo_root: String,
    pub worktree_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    pub branch_name: String,
    pub head_commit: String,
    pub managed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointRecordV1 {
    pub schema: String,
    pub checkpoint_id: String,
    pub session_id: String,
    pub created_at: String,
    pub label: String,
    pub session_status: SessionStatusV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_receipt_id: Option<String>,
    pub workgraph: WorkgraphV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRouteRecordV1 {
    pub schema: String,
    pub route_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub created_at: String,
    pub role: String,
    pub provider: String,
    pub locality: String,
    pub ready: bool,
    pub summary: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProbeResultV1 {
    pub schema: String,
    pub probe_id: String,
    pub generated_at: String,
    pub provider: String,
    pub role: String,
    pub locality: String,
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSessionViewV1 {
    pub session_id: String,
    pub status: SessionStatusV1,
    pub workflow_kind: String,
    pub goal_summary: String,
    pub created_at: String,
    pub updated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workgraph_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub session: AgentSessionViewV1,
    pub trust_gate: TrustGateReportV1,
    pub workgraph: WorkgraphV1,
    pub receipts: Vec<ActionReceiptV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSessionRequestV1 {
    pub goal: String,
    pub options: AgentRunOptionsV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunSessionResponseV1 {
    pub schema: String,
    pub generated_at: String,
    pub report: AgentRunReportV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentExplainReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<AgentSessionViewV1>,
    pub trust_gate: TrustGateReportV1,
    pub workgraph: WorkgraphV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeSessionRequestV1 {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeSessionResponseV1 {
    pub schema: String,
    pub generated_at: String,
    pub report: AgentRunReportV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectRecordV1 {
    pub name: String,
    pub root_path: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub socket_path: String,
    pub socket_present: bool,
    pub sessions: Vec<AgentSessionViewV1>,
    pub projects: Vec<ProjectRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentLogsReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub session_id: String,
    pub receipts: Vec<ActionReceiptV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentArtifactsReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub artifacts: Vec<ArtifactRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentDeploymentsReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub deployments: Vec<DeploymentRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentEnvironmentReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub environments: Vec<EnvironmentSnapshotV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProceduresReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub procedures: Vec<ProcedureRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentIncidentsReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub incidents: Vec<IncidentRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentApprovalLineageReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub approval_requests: Vec<ApprovalRequestRecordV1>,
    pub approval_tokens: Vec<ApprovalTokenRecordV1>,
    pub submission_grants: Vec<SubmissionGrantRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWorktreeListReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub worktrees: Vec<WorktreeRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCheckpointListReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub session_id: String,
    pub checkpoints: Vec<CheckpointRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProviderStatusReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub routes: Vec<ProviderRouteRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProviderTestReportV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub probes: Vec<ProviderProbeResultV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWorkflowListReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub workflows: Vec<GoalIntentV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubscriptionRequestV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_receipt_id: Option<String>,
    #[serde(default = "default_event_limit")]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSubscriptionResponseV1 {
    pub schema: String,
    pub generated_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub receipts: Vec<ActionReceiptV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMemorySessionsReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub sessions: Vec<AgentSessionViewV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWorkflowShowReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub workgraph: WorkgraphV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentListProjectsReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub projects: Vec<ProjectRecordV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWorktreeCreateRequestV1 {
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentWorktreeCleanupRequestV1 {
    pub worktree_id: String,
    #[serde(default)]
    pub remove_files: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCheckpointCreateRequestV1 {
    pub session_id: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCheckpointRollbackRequestV1 {
    pub checkpoint_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProviderRouteRequestV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProviderTestRequestV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_override: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentProjectRegisterRequestV1 {
    pub name: String,
    pub root_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCancelRequestV1 {
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentApproveRequestV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub wallet_network: WalletNetwork,
    pub pending_id: String,
    pub primary_prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_prompt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestV1 {
    pub request: AgentApproveRequestV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponseV1 {
    pub schema: String,
    pub generated_at: String,
    pub outcome: WalletApprovalOutcomeV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRejectRequestV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub wallet_network: WalletNetwork,
    pub pending_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistent_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_root: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletApprovalOutcomeV1 {
    pub schema: String,
    pub operation_id: String,
    pub generated_at: String,
    pub token: ApprovalToken,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_status: Option<SessionStatusV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submission_grant: Option<SubmissionGrantRecordV1>,
}

fn default_event_limit() -> usize {
    50
}

fn default_use_worktree() -> bool {
    true
}
