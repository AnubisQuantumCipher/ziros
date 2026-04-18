mod brain;
mod bridge;
mod browser;
mod checkpoint;
mod daemon;
mod executor;
mod hermes;
mod llm;
mod mcp;
mod planner;
mod provider;
mod provider_profiles;
mod state;
mod trust_gate;
mod types;
mod web;
mod worktree;

pub use bridge::{bridge_policy_path, bridge_status, load_bridge_policy, save_bridge_policy};
pub use browser::{browser_eval, browser_open, browser_status};
pub use daemon::{
    AgentRpcRequestV1, AgentRpcResponseV1, call_daemon, default_socket_path, handle_rpc_request,
    serve_daemon,
};
pub use mcp::{McpExposureV1, handle_mcp_jsonrpc_bytes, mcp_server_manifest, serve_mcp_stdio};
pub use provider_profiles::{
    ProviderCredentialRefV1, ProviderKindV1, ProviderProfileStoreV1, ProviderProfileV1,
    ProviderRoleBindingV1, load_api_key, load_provider_profile_store, openai_credential_ref,
    ordered_profiles_for_selection, remove_provider_profile, save_provider_profile_store,
    set_default_provider_profile, store_openai_api_key, upsert_provider_profile,
};
pub use state::{
    AgentStateLayoutReportV1, AgentStateMigrationRecordV1, agent_root as ziros_agent_root,
    brain_path as ziros_agent_brain_path, config_path as ziros_config_path, ensure_ziros_layout,
    first_run_marker_path as ziros_first_run_marker_path, hermes_config_path, hermes_home_root,
    hermes_memories_root, hermes_pack_lock_path, hermes_pack_root, hermes_skills_root,
    hermes_soul_path, install_root as ziros_install_root,
    legacy_agent_root as ziros_legacy_agent_root, logs_root as ziros_logs_root,
    managed_bin_root as ziros_managed_bin_root,
    provider_profiles_path as ziros_provider_profiles_path, socket_path as ziros_agent_socket_path,
    state_root as ziros_state_root, ziros_home_root,
};
pub use types::{
    ActionReceiptV1, AgentApprovalLineageReportV1, AgentApproveRequestV1, AgentArtifactsReportV1,
    AgentBridgeHandoffAcceptRequestV1, AgentBridgeHandoffListReportV1,
    AgentBridgeHandoffPrepareReportV1, AgentBridgeHandoffPrepareRequestV1,
    AgentBrowserEvalReportV1, AgentBrowserEvalRequestV1, AgentBrowserKindV1,
    AgentBrowserOpenReportV1, AgentBrowserOpenRequestV1, AgentBrowserStatusReportV1,
    AgentCancelRequestV1, AgentCheckpointCreateRequestV1, AgentCheckpointListReportV1,
    AgentCheckpointRollbackRequestV1, AgentDeploymentsReportV1, AgentEnvironmentReportV1,
    AgentExplainReportV1, AgentIncidentsReportV1, AgentListProjectsReportV1, AgentLogsReportV1,
    AgentMemorySessionsReportV1, AgentProceduresReportV1, AgentProjectRegisterRequestV1,
    AgentProviderRouteRequestV1, AgentProviderStatusReportV1, AgentProviderTestReportV1,
    AgentProviderTestRequestV1, AgentRejectRequestV1, AgentRunOptionsV1, AgentRunReportV1,
    AgentSessionViewV1, AgentStatusReportV1, AgentWebFetchReportV1, AgentWebFetchRequestV1,
    AgentWorkflowListReportV1, AgentWorkflowShowReportV1, AgentWorktreeCleanupRequestV1,
    AgentWorktreeCreateRequestV1, AgentWorktreeListReportV1, ApprovalRequestRecordV1,
    ApprovalRequestV1, ApprovalResponseV1, ApprovalTokenRecordV1, ArtifactRecordV1,
    BridgeFallbackPolicyV1, BridgeHandoffRecordV1, BridgePolicyV1, BridgeStatusReportV1,
    BridgeTaskClassV1, CheckpointRecordV1, DeploymentRecordV1, EventSubscriptionRequestV1,
    EventSubscriptionResponseV1, GoalIntentV1, GuardrailViolationV1, HermesBootstrapAssetV1,
    HermesConfigStatusV1, HermesDoctorReportV1, HermesExportBootstrapReportV1,
    HermesInstallReportV1, HermesManagedAssetStatusV1, HermesPackDiffV1, HermesPackStatusV1,
    OperatorProfileV1, ProcedureRecordV1, ProjectRecordV1, ProviderProbeResultV1,
    ProviderRouteRecordV1, ReasoningProvenanceV1, ResumeSessionRequestV1, ResumeSessionResponseV1,
    RunSessionRequestV1, RunSessionResponseV1, SubmissionGrantRecordV1, TrustGateReportV1,
    WorkgraphV1, WorktreeRecordV1,
};
pub use web::web_fetch;

use brain::BrainStore;
use bridge::{
    apply_bridge_policy_guards, build_reasoning_provenance, classify_task, default_bridge_policy,
    should_bypass_local_model_intent_compilation,
};
use checkpoint::{create_checkpoint_record, rollback_to_checkpoint_record};
use executor::execute_workgraph;
use hermes::{
    hermes_diff as hermes_diff_impl, hermes_doctor as hermes_doctor_impl,
    hermes_export_bootstrap as hermes_export_bootstrap_impl, hermes_install as hermes_install_impl,
    hermes_status as hermes_status_impl, hermes_sync as hermes_sync_impl,
};
use llm::try_compile_goal_intent;
use planner::{build_workgraph, compile_goal_intent, workflow_catalog};
use provider::{probe_provider_routes, select_provider_routes};
use std::collections::HashSet;
use trust_gate::resolve_trust_gate;
use types::{
    EnvironmentSnapshotV1, IncidentRecordV1, SessionStatusV1, WalletApprovalOutcomeV1,
    WorkflowRequirementsV1,
};
use worktree::{cleanup_worktree_record, create_session_worktree};
use zkf_command_surface::wallet::{WalletContextV1, approve_pending, reject_pending};
use zkf_command_surface::{CommandErrorClassV1, RiskClassV1, new_operation_id};

pub fn agent_status(limit: usize) -> Result<AgentStatusReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentStatusReportV1 {
        schema: "ziros-agent-status-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        socket_path: default_socket_path()?.display().to_string(),
        socket_present: default_socket_path()?.exists(),
        sessions: brain.list_sessions(limit)?,
        projects: brain.list_projects()?,
    })
}

pub fn plan_goal(goal: &str, options: AgentRunOptionsV1) -> Result<AgentExplainReportV1, String> {
    let intent = resolve_goal_intent(goal, &options);
    let workflow_kind = intent.workflow_kind.clone();
    let bridge_policy = load_bridge_policy().unwrap_or_else(|_| default_bridge_policy());
    let task_class = classify_task(goal, &intent);
    let reasoning_provenance = build_reasoning_provenance(&bridge_policy, task_class, &options);
    let requirements = WorkflowRequirementsV1::for_goal(goal, &intent, &options);
    let trust_gate =
        resolve_trust_gate(&workflow_kind, &requirements, options.project_root.clone())?;
    let mut workgraph = build_workgraph(goal, &intent, &requirements, &trust_gate);
    apply_execution_policy_guards(&mut workgraph)?;
    apply_bridge_policy_guards(&mut workgraph, &bridge_policy, &reasoning_provenance);
    Ok(AgentExplainReportV1 {
        schema: "ziros-agent-explain-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session: None,
        trust_gate,
        workgraph,
        reasoning_provenance,
    })
}

pub fn run_goal(goal: &str, options: AgentRunOptionsV1) -> Result<AgentRunReportV1, String> {
    run_goal_with_receipts(goal, options, |_| {})
}

pub fn run_goal_with_receipts<F>(
    goal: &str,
    options: AgentRunOptionsV1,
    mut on_receipt: F,
) -> Result<AgentRunReportV1, String>
where
    F: FnMut(&ActionReceiptV1),
{
    let brain = BrainStore::open_default()?;
    run_goal_with_store(&brain, goal, options, &mut on_receipt)
}

pub fn explain_session(session_id: &str) -> Result<AgentExplainReportV1, String> {
    let brain = BrainStore::open_default()?;
    explain_session_with_store(&brain, session_id)
}

pub fn resume_session(session_id: &str) -> Result<AgentRunReportV1, String> {
    resume_session_with_receipts(session_id, |_| {})
}

pub fn resume_session_with_receipts<F>(
    session_id: &str,
    mut on_receipt: F,
) -> Result<AgentRunReportV1, String>
where
    F: FnMut(&ActionReceiptV1),
{
    let brain = BrainStore::open_default()?;
    let (mut session, trust_gate, mut workgraph) = load_session_state(&brain, session_id)?;
    if matches!(
        session.status,
        SessionStatusV1::Completed | SessionStatusV1::Cancelled
    ) {
        return Ok(AgentRunReportV1 {
            schema: "ziros-agent-run-v1".to_string(),
            generated_at: zkf_command_surface::now_rfc3339(),
            session,
            trust_gate,
            workgraph,
            receipts: brain.list_receipts(session_id)?,
            reasoning_provenance: ReasoningProvenanceV1 {
                task_class: BridgeTaskClassV1::Study,
                reasoning_lane: "session-resume".to_string(),
                reasoning_primary: false,
                reasoning_model_label: "session-resume".to_string(),
                reasoning_origin: "local-agent".to_string(),
                execution_origin: "local-hermes".to_string(),
                primary_lane_expected: default_bridge_policy().primary_lane,
                primary_lane_used: false,
                downgraded_from_primary: true,
                downgrade_reason: Some(
                    "session resume reused stored workgraph state rather than replaying primary reasoning"
                        .to_string(),
                ),
            },
        });
    }

    let options = resume_options(&session, &trust_gate);
    apply_execution_policy_guards(&mut workgraph)?;
    if trust_gate.blocked || !workgraph.blocked_prerequisites.is_empty() {
        workgraph.status = "blocked".to_string();
        brain.update_workgraph(&workgraph)?;
        brain.update_session_status(&session.session_id, SessionStatusV1::Blocked)?;
        session.status = SessionStatusV1::Blocked;
        let receipt = brain.append_receipt(&brain.new_receipt(
            &session.session_id,
            "execution-policy",
            "blocked",
            &serde_json::json!({
                "blocked_prerequisites": workgraph.blocked_prerequisites.clone(),
            }),
        )?)?;
        on_receipt(&receipt);
    } else {
        let _ = execute_workgraph(
            &brain,
            &mut session,
            &mut workgraph,
            &options,
            &mut on_receipt,
        )?;
    }
    let latest_receipt_id = brain
        .list_receipts(&session.session_id)?
        .last()
        .map(|receipt| receipt.receipt_id.clone());
    let checkpoint = create_checkpoint_record(
        &brain,
        &session,
        &workgraph,
        if session.status == SessionStatusV1::Completed {
            "resume-completed"
        } else {
            "resume-paused"
        },
        latest_receipt_id,
    )?;
    let _ = brain.store_checkpoint(&checkpoint)?;

    Ok(AgentRunReportV1 {
        schema: "ziros-agent-run-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session,
        trust_gate,
        workgraph,
        receipts: brain.list_receipts(session_id)?,
        reasoning_provenance: ReasoningProvenanceV1 {
            task_class: BridgeTaskClassV1::Study,
            reasoning_lane: "session-resume".to_string(),
            reasoning_primary: false,
            reasoning_model_label: "session-resume".to_string(),
            reasoning_origin: "local-agent".to_string(),
            execution_origin: "local-hermes".to_string(),
            primary_lane_expected: default_bridge_policy().primary_lane,
            primary_lane_used: false,
            downgraded_from_primary: true,
            downgrade_reason: Some(
                "session resume reused stored workgraph state rather than replaying primary reasoning"
                    .to_string(),
            ),
        },
    })
}

fn run_goal_with_store<F>(
    brain: &BrainStore,
    goal: &str,
    options: AgentRunOptionsV1,
    on_receipt: &mut F,
) -> Result<AgentRunReportV1, String>
where
    F: FnMut(&ActionReceiptV1),
{
    let intent = resolve_goal_intent(goal, &options);
    let workflow_kind = intent.workflow_kind.clone();
    let bridge_policy = load_bridge_policy().unwrap_or_else(|_| default_bridge_policy());
    let task_class = classify_task(goal, &intent);
    let reasoning_provenance = build_reasoning_provenance(&bridge_policy, task_class, &options);
    let mut options = options;
    options.project_root =
        effective_project_root(&workflow_kind, goal, options.project_root.take())?;
    let mut session = brain.create_session(
        goal,
        &workflow_kind,
        SessionStatusV1::Planned,
        options.project_root.clone(),
    )?;

    let provider_routes = select_provider_routes(
        Some(&session.session_id),
        &workflow_kind,
        options.provider_override.as_deref(),
        options.model_override.as_deref(),
    );
    for route in &provider_routes {
        let _ = brain.store_provider_route(route)?;
    }

    if options.use_worktree
        && let Some((record, project_root)) = create_session_worktree(
            brain,
            &session.session_id,
            &workflow_kind,
            goal,
            options.project_root.as_deref(),
        )?
    {
        let _ = brain.register_worktree(&record)?;
        options.project_root = project_root.clone();
        brain.update_session_project_root(&session.session_id, project_root.as_deref())?;
        session = brain
            .get_session(&session.session_id)?
            .ok_or_else(|| format!("unknown agent session '{}'", session.session_id))?;
    }

    let requirements = WorkflowRequirementsV1::for_goal(goal, &intent, &options);
    let trust_gate =
        resolve_trust_gate(&workflow_kind, &requirements, options.project_root.clone())?;
    let mut workgraph = build_workgraph(goal, &intent, &requirements, &trust_gate);
    apply_execution_policy_guards(&mut workgraph)?;
    apply_bridge_policy_guards(&mut workgraph, &bridge_policy, &reasoning_provenance);
    let status = if trust_gate.blocked {
        SessionStatusV1::Blocked
    } else if !workgraph.blocked_prerequisites.is_empty() {
        SessionStatusV1::Blocked
    } else {
        SessionStatusV1::Planned
    };
    if status != SessionStatusV1::Planned {
        brain.update_session_status(&session.session_id, status)?;
    }
    let capability_snapshot_id =
        brain.store_capability_snapshot(&session.session_id, &trust_gate)?;
    let _environment = brain.store_environment_snapshot(&EnvironmentSnapshotV1 {
        schema: "ziros-agent-environment-snapshot-v1".to_string(),
        snapshot_id: new_operation_id("environment-snapshot"),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: Some(session.session_id.clone()),
        workflow_kind: workflow_kind.clone(),
        strict: trust_gate.strict,
        compat_allowed: trust_gate.compat_allowed,
        truth_snapshot: trust_gate.truth_snapshot.clone(),
        midnight_status: trust_gate.midnight_status.clone(),
        wallet: trust_gate.wallet.clone(),
        reasoning_provenance: Some(reasoning_provenance.clone()),
    })?;
    let workgraph = brain.store_workgraph(
        &session.session_id,
        capability_snapshot_id.clone(),
        &workgraph,
    )?;
    session = brain.attach_workgraph(
        &session.session_id,
        &workgraph.workgraph_id,
        capability_snapshot_id,
    )?;
    let receipt_created = brain.append_receipt(&brain.new_receipt(
        &session.session_id,
        "session-created",
        status.as_str(),
        &serde_json::json!({
            "goal": goal,
            "workflow_kind": workflow_kind,
        }),
    )?)?;
    on_receipt(&receipt_created);
    if let Some(route) = provider_routes.first() {
        let receipt_provider = brain.append_receipt(&brain.new_receipt(
            &session.session_id,
            "provider-route",
            "ready",
            route,
        )?)?;
        on_receipt(&receipt_provider);
    }
    let receipt_reasoning = brain.append_receipt(&brain.new_receipt(
        &session.session_id,
        "reasoning-lane",
        if reasoning_provenance.primary_lane_used {
            "primary"
        } else if status == SessionStatusV1::Blocked {
            "blocked"
        } else {
            "degraded"
        },
        &reasoning_provenance,
    )?)?;
    on_receipt(&receipt_reasoning);
    if let Some(worktree) = brain
        .list_worktrees(Some(&session.session_id))?
        .into_iter()
        .last()
    {
        let receipt_worktree = brain.append_receipt(&brain.new_receipt(
            &session.session_id,
            "worktree",
            "ready",
            &worktree,
        )?)?;
        on_receipt(&receipt_worktree);
    }
    let receipt_gate = brain.append_receipt(&brain.new_receipt(
        &session.session_id,
        "trust-gate",
        if trust_gate.blocked {
            "blocked"
        } else {
            "ready"
        },
        &trust_gate,
    )?)?;
    on_receipt(&receipt_gate);
    let receipt_plan = brain.append_receipt(&brain.new_receipt(
        &session.session_id,
        "planner",
        if trust_gate.blocked || !workgraph.blocked_prerequisites.is_empty() {
            "blocked"
        } else {
            "planned"
        },
        &workgraph,
    )?)?;
    on_receipt(&receipt_plan);
    let checkpoint = create_checkpoint_record(
        brain,
        &session,
        &workgraph,
        "planned",
        Some(receipt_plan.receipt_id.clone()),
    )?;
    let _ = brain.store_checkpoint(&checkpoint)?;

    let mut workgraph = workgraph;
    if !trust_gate.blocked && workgraph.blocked_prerequisites.is_empty() {
        let _ = execute_workgraph(brain, &mut session, &mut workgraph, &options, on_receipt)?;
    } else {
        session.status = status;
    }
    let final_receipt_id = brain
        .list_receipts(&session.session_id)?
        .last()
        .map(|receipt| receipt.receipt_id.clone());
    let checkpoint = create_checkpoint_record(
        brain,
        &session,
        &workgraph,
        if session.status == SessionStatusV1::Completed {
            "completed"
        } else {
            "paused"
        },
        final_receipt_id,
    )?;
    let _ = brain.store_checkpoint(&checkpoint)?;
    let receipts = brain.list_receipts(&session.session_id)?;
    Ok(AgentRunReportV1 {
        schema: "ziros-agent-run-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session,
        trust_gate,
        workgraph,
        receipts,
        reasoning_provenance,
    })
}

fn apply_execution_policy_guards(workgraph: &mut WorkgraphV1) -> Result<(), String> {
    if workgraph.execution_policy.structured_command_first {
        let offenders = workgraph
            .nodes
            .iter()
            .filter(|node| !action_uses_structured_surface(&node.action_name))
            .map(|node| format!("{} ({})", node.label, node.action_name))
            .collect::<Vec<_>>();
        if !offenders.is_empty() {
            workgraph.blocked_prerequisites.push(format!(
                "structured_command_first violated by: {}",
                offenders.join(", ")
            ));
        }
    }

    if workgraph.execution_policy.postflight_required
        && !workgraph_has_required_postflight(workgraph)
    {
        workgraph.blocked_prerequisites.push(
            "postflight_required violated: mutating workgraph has no dependent postflight action"
                .to_string(),
        );
    }

    if workgraph.execution_policy.operator_profile == OperatorProfileV1::HermesRigorous {
        let doctor = hermes_doctor_impl()?;
        if !doctor.healthy {
            let mut codes = doctor
                .status
                .violations
                .iter()
                .map(|issue| issue.code.as_str())
                .take(5)
                .collect::<Vec<_>>();
            if doctor.status.violations.len() > 5 {
                codes.push("...");
            }
            workgraph.blocked_prerequisites.push(format!(
                "Hermes rigorous profile unhealthy; run `{}` and resolve: {}",
                doctor.repair_command,
                codes.join(", ")
            ));
        }
    }

    workgraph.blocked_prerequisites.sort();
    workgraph.blocked_prerequisites.dedup();
    if !workgraph.blocked_prerequisites.is_empty() {
        workgraph.status = "blocked".to_string();
    }
    Ok(())
}

fn workgraph_has_required_postflight(workgraph: &WorkgraphV1) -> bool {
    let mutating_nodes = workgraph
        .nodes
        .iter()
        .filter(|node| node.risk_class == RiskClassV1::WorkspaceMutation)
        .map(|node| node.node_id.as_str())
        .collect::<HashSet<_>>();
    if mutating_nodes.is_empty() {
        return true;
    }
    workgraph.nodes.iter().any(|node| {
        node.risk_class != RiskClassV1::WorkspaceMutation
            && node_depends_on_any(workgraph, node, &mutating_nodes)
    })
}

fn node_depends_on_any(
    workgraph: &WorkgraphV1,
    node: &crate::types::WorkgraphNodeV1,
    candidates: &HashSet<&str>,
) -> bool {
    let mut pending = node.depends_on.clone();
    let mut visited = HashSet::new();
    while let Some(node_id) = pending.pop() {
        if !visited.insert(node_id.clone()) {
            continue;
        }
        if candidates.contains(node_id.as_str()) {
            return true;
        }
        if let Some(parent) = workgraph
            .nodes
            .iter()
            .find(|candidate| candidate.node_id == node_id)
        {
            pending.extend(parent.depends_on.iter().cloned());
        }
    }
    false
}

fn action_uses_structured_surface(action_name: &str) -> bool {
    action_name.starts_with("truth.")
        || action_name.starts_with("wallet.")
        || action_name.starts_with("subsystem.")
        || action_name.starts_with("midnight.")
        || action_name.starts_with("runtime.")
        || action_name.starts_with("app.")
        || action_name.starts_with("proof.")
        || action_name.starts_with("release.")
        || action_name.starts_with("evm.")
        || action_name.starts_with("swarm.")
        || action_name.starts_with("cluster.")
        || action_name.starts_with("agent.")
}

fn explain_session_with_store(
    brain: &BrainStore,
    session_id: &str,
) -> Result<AgentExplainReportV1, String> {
    let (session, trust_gate, workgraph) = load_session_state(brain, session_id)?;
    let reasoning_provenance = brain
        .list_environment_snapshots(Some(session_id))?
        .into_iter()
        .filter_map(|snapshot| snapshot.reasoning_provenance)
        .last()
        .unwrap_or(ReasoningProvenanceV1 {
            task_class: BridgeTaskClassV1::Study,
            reasoning_lane: "session-explain".to_string(),
            reasoning_primary: false,
            reasoning_model_label: "session-explain".to_string(),
            reasoning_origin: "local-agent".to_string(),
            execution_origin: "local-hermes".to_string(),
            primary_lane_expected: "chatgpt-pro-bridge".to_string(),
            primary_lane_used: false,
            downgraded_from_primary: true,
            downgrade_reason: Some(
                "session has no stored reasoning provenance; explanation is using local fallback metadata"
                    .to_string(),
            ),
        });
    Ok(AgentExplainReportV1 {
        schema: "ziros-agent-explain-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session: Some(session),
        trust_gate,
        workgraph,
        reasoning_provenance,
    })
}

pub fn cancel_session(request: AgentCancelRequestV1) -> Result<AgentSessionViewV1, String> {
    let brain = BrainStore::open_default()?;
    brain.update_session_status(&request.session_id, SessionStatusV1::Cancelled)?;
    brain.append_receipt(&brain.new_receipt(
        &request.session_id,
        "cancel",
        "cancelled",
        &serde_json::json!({ "reason": request.reason }),
    )?)?;
    brain
        .get_session(&request.session_id)?
        .ok_or_else(|| format!("unknown agent session '{}'", request.session_id))
}

pub fn session_logs(session_id: &str) -> Result<AgentLogsReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentLogsReportV1 {
        schema: "ziros-agent-logs-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.to_string(),
        receipts: brain.list_receipts(session_id)?,
    })
}

pub fn event_subscription(
    request: EventSubscriptionRequestV1,
) -> Result<EventSubscriptionResponseV1, String> {
    let brain = BrainStore::open_default()?;
    let mut receipts = if let Some(session_id) = request.session_id.as_deref() {
        brain.list_receipts(session_id)?
    } else {
        let mut combined = Vec::new();
        for session in brain.list_sessions(request.limit.max(1))? {
            combined.extend(brain.list_receipts(&session.session_id)?);
        }
        combined.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        combined
    };
    if let Some(after_receipt_id) = request.after_receipt_id.as_deref()
        && let Some(position) = receipts
            .iter()
            .position(|receipt| receipt.receipt_id == after_receipt_id)
    {
        receipts = receipts.into_iter().skip(position + 1).collect();
    }
    if receipts.len() > request.limit {
        let start = receipts.len() - request.limit;
        receipts = receipts.split_off(start);
    }
    Ok(EventSubscriptionResponseV1 {
        schema: "ziros-agent-event-subscription-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: request.session_id,
        receipts,
    })
}

pub fn memory_sessions(limit: usize) -> Result<AgentMemorySessionsReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentMemorySessionsReportV1 {
        schema: "ziros-agent-memory-sessions-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        sessions: brain.list_sessions(limit)?,
    })
}

pub fn session_artifacts(session_id: Option<&str>) -> Result<AgentArtifactsReportV1, String> {
    let brain = BrainStore::open_default()?;
    session_artifacts_with_store(&brain, session_id)
}

fn session_artifacts_with_store(
    brain: &BrainStore,
    session_id: Option<&str>,
) -> Result<AgentArtifactsReportV1, String> {
    Ok(AgentArtifactsReportV1 {
        schema: "ziros-agent-artifacts-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.map(str::to_string),
        artifacts: brain.list_artifacts(session_id)?,
    })
}

pub fn session_deployments(session_id: Option<&str>) -> Result<AgentDeploymentsReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentDeploymentsReportV1 {
        schema: "ziros-agent-deployments-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.map(str::to_string),
        deployments: brain.list_deployments(session_id)?,
    })
}

pub fn session_environments(session_id: Option<&str>) -> Result<AgentEnvironmentReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentEnvironmentReportV1 {
        schema: "ziros-agent-environments-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.map(str::to_string),
        environments: brain.list_environment_snapshots(session_id)?,
    })
}

pub fn list_procedures() -> Result<AgentProceduresReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentProceduresReportV1 {
        schema: "ziros-agent-procedures-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        procedures: brain.list_procedures()?,
    })
}

pub fn list_incidents(session_id: Option<&str>) -> Result<AgentIncidentsReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentIncidentsReportV1 {
        schema: "ziros-agent-incidents-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.map(str::to_string),
        incidents: brain.list_incidents(session_id)?,
    })
}

pub fn approval_lineage(session_id: Option<&str>) -> Result<AgentApprovalLineageReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentApprovalLineageReportV1 {
        schema: "ziros-agent-approval-lineage-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.map(str::to_string),
        approval_requests: brain.list_approval_requests(session_id)?,
        approval_tokens: brain.list_approval_tokens(session_id)?,
        submission_grants: brain.list_submission_grants(session_id)?,
    })
}

pub fn list_worktrees(session_id: Option<&str>) -> Result<AgentWorktreeListReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentWorktreeListReportV1 {
        schema: "ziros-agent-worktrees-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.map(str::to_string),
        worktrees: brain.list_worktrees(session_id)?,
    })
}

pub fn create_worktree(request: AgentWorktreeCreateRequestV1) -> Result<WorktreeRecordV1, String> {
    let brain = BrainStore::open_default()?;
    let session = brain
        .get_session(&request.session_id)?
        .ok_or_else(|| format!("unknown agent session '{}'", request.session_id))?;
    let (record, project_root) = create_session_worktree(
        &brain,
        &request.session_id,
        &session.workflow_kind,
        &session.goal_summary,
        session.project_root.as_deref().map(std::path::Path::new),
    )?
    .map(|(record, project_root)| (record, project_root))
    .ok_or_else(|| "this session does not require a managed worktree".to_string())?;
    brain.update_session_project_root(&request.session_id, project_root.as_deref())?;
    brain.register_worktree(&record)
}

pub fn cleanup_worktree(
    request: AgentWorktreeCleanupRequestV1,
) -> Result<WorktreeRecordV1, String> {
    let brain = BrainStore::open_default()?;
    let record = brain
        .get_worktree(&request.worktree_id)?
        .ok_or_else(|| format!("unknown worktree '{}'", request.worktree_id))?;
    cleanup_worktree_record(&record, request.remove_files)?;
    Ok(record)
}

pub fn list_checkpoints(session_id: &str) -> Result<AgentCheckpointListReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentCheckpointListReportV1 {
        schema: "ziros-agent-checkpoints-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.to_string(),
        checkpoints: brain.list_checkpoints(session_id)?,
    })
}

pub fn create_checkpoint(
    request: AgentCheckpointCreateRequestV1,
) -> Result<CheckpointRecordV1, String> {
    let brain = BrainStore::open_default()?;
    let (session, _, workgraph) = load_session_state(&brain, &request.session_id)?;
    let latest_receipt_id = brain
        .list_receipts(&request.session_id)?
        .last()
        .map(|receipt| receipt.receipt_id.clone());
    let checkpoint = create_checkpoint_record(
        &brain,
        &session,
        &workgraph,
        &request.label,
        latest_receipt_id,
    )?;
    brain.store_checkpoint(&checkpoint)
}

pub fn rollback_checkpoint(
    request: AgentCheckpointRollbackRequestV1,
) -> Result<CheckpointRecordV1, String> {
    let brain = BrainStore::open_default()?;
    let checkpoint = brain
        .get_checkpoint(&request.checkpoint_id)?
        .ok_or_else(|| format!("unknown checkpoint '{}'", request.checkpoint_id))?;
    rollback_to_checkpoint_record(&brain, &checkpoint)?;
    Ok(checkpoint)
}

pub fn provider_status(session_id: Option<&str>) -> Result<AgentProviderStatusReportV1, String> {
    let bridge_status = bridge_status().ok();
    let routes = match session_id {
        Some(session_id) => {
            let brain = BrainStore::open_default()?;
            let stored = brain.list_provider_routes(Some(session_id))?;
            if stored.is_empty() {
                select_provider_routes(Some(session_id), "ad-hoc", None, None)
            } else {
                stored
            }
        }
        None => select_provider_routes(None, "ad-hoc", None, None),
    };
    Ok(AgentProviderStatusReportV1 {
        schema: "ziros-agent-providers-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: session_id.map(str::to_string),
        routes,
        primary_intelligence_lane: bridge_status
            .as_ref()
            .map(|status| status.primary_intelligence_lane.clone()),
        fallback_policy: bridge_status.as_ref().map(|status| status.fallback_policy),
        bridge_status,
    })
}

pub fn provider_route(
    request: AgentProviderRouteRequestV1,
) -> Result<AgentProviderStatusReportV1, String> {
    let session_id = request.session_id.as_deref();
    let bridge_status = bridge_status().ok();
    let routes = match session_id {
        Some(session_id) => {
            let brain = BrainStore::open_default()?;
            let stored = brain.list_provider_routes(Some(session_id))?;
            if request.provider_override.is_none() && !stored.is_empty() {
                stored
            } else {
                let routes = select_provider_routes(
                    Some(session_id),
                    "ad-hoc",
                    request.provider_override.as_deref(),
                    request.model_override.as_deref(),
                );
                for route in &routes {
                    let _ = brain.store_provider_route(route)?;
                }
                routes
            }
        }
        None => select_provider_routes(
            None,
            "ad-hoc",
            request.provider_override.as_deref(),
            request.model_override.as_deref(),
        ),
    };
    Ok(AgentProviderStatusReportV1 {
        schema: "ziros-agent-provider-routes-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: request.session_id,
        routes,
        primary_intelligence_lane: bridge_status
            .as_ref()
            .map(|status| status.primary_intelligence_lane.clone()),
        fallback_policy: bridge_status.as_ref().map(|status| status.fallback_policy),
        bridge_status,
    })
}

pub fn provider_test(
    request: AgentProviderTestRequestV1,
) -> Result<AgentProviderTestReportV1, String> {
    let route_report = provider_route(AgentProviderRouteRequestV1 {
        session_id: request.session_id.clone(),
        provider_override: request.provider_override,
        model_override: request.model_override,
    })?;
    Ok(AgentProviderTestReportV1 {
        schema: "ziros-agent-provider-tests-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        session_id: route_report.session_id,
        probes: probe_provider_routes(&route_report.routes),
    })
}

pub fn web_fetch_report(request: AgentWebFetchRequestV1) -> Result<AgentWebFetchReportV1, String> {
    web_fetch(request)
}

pub fn browser_status_report() -> Result<AgentBrowserStatusReportV1, String> {
    browser_status()
}

pub fn browser_open_report(
    request: AgentBrowserOpenRequestV1,
) -> Result<AgentBrowserOpenReportV1, String> {
    browser_open(request)
}

pub fn browser_eval_report(
    request: AgentBrowserEvalRequestV1,
) -> Result<AgentBrowserEvalReportV1, String> {
    browser_eval(request)
}

pub fn workflow_list() -> Result<AgentWorkflowListReportV1, String> {
    Ok(AgentWorkflowListReportV1 {
        schema: "ziros-agent-workflows-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        workflows: workflow_catalog(),
    })
}

pub fn workflow_show(workgraph_id: &str) -> Result<AgentWorkflowShowReportV1, String> {
    let brain = BrainStore::open_default()?;
    let workgraph = brain
        .get_workgraph(workgraph_id)?
        .ok_or_else(|| format!("unknown workgraph '{workgraph_id}'"))?;
    Ok(AgentWorkflowShowReportV1 {
        schema: "ziros-agent-workgraph-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        workgraph,
    })
}

pub fn hermes_status() -> Result<HermesPackStatusV1, String> {
    hermes_status_impl()
}

pub fn hermes_diff() -> Result<HermesPackDiffV1, String> {
    hermes_diff_impl()
}

pub fn hermes_install() -> Result<HermesInstallReportV1, String> {
    hermes_install_impl()
}

pub fn hermes_sync() -> Result<HermesInstallReportV1, String> {
    hermes_sync_impl()
}

pub fn hermes_doctor() -> Result<HermesDoctorReportV1, String> {
    hermes_doctor_impl()
}

pub fn hermes_export_bootstrap() -> Result<HermesExportBootstrapReportV1, String> {
    hermes_export_bootstrap_impl()
}

pub fn register_project(request: AgentProjectRegisterRequestV1) -> Result<ProjectRecordV1, String> {
    let brain = BrainStore::open_default()?;
    brain.register_project(&request.name, &request.root_path)
}

pub fn list_projects() -> Result<AgentListProjectsReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentListProjectsReportV1 {
        schema: "ziros-agent-projects-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        projects: brain.list_projects()?,
    })
}

pub fn prepare_bridge_handoff(
    request: AgentBridgeHandoffPrepareRequestV1,
) -> Result<AgentBridgeHandoffPrepareReportV1, String> {
    let brain = BrainStore::open_default()?;
    let handoff_id = new_operation_id("bridge-handoff");
    let now = zkf_command_surface::now_rfc3339();
    let mut options = request.options;
    if request.origin.contains("remote") || request.origin.contains("chatgpt") {
        let bridge_policy = load_bridge_policy().unwrap_or_else(|_| default_bridge_policy());
        if options.reasoning_lane.is_none() {
            options.reasoning_lane = Some(bridge_policy.primary_lane.clone());
        }
        if options.reasoning_model_label.is_none() {
            options.reasoning_model_label = Some(bridge_policy.primary_model_label.clone());
        }
        if options.reasoning_origin.is_none() {
            options.reasoning_origin = Some("chatgpt-pro-bridge".to_string());
        }
    }
    let record = BridgeHandoffRecordV1 {
        schema: "ziros-agent-bridge-handoff-v1".to_string(),
        handoff_id: handoff_id.clone(),
        bridge_session_id: handoff_id.clone(),
        created_at: now.clone(),
        updated_at: now,
        origin: request.origin,
        status: "prepared".to_string(),
        goal: request.goal,
        options,
        local_command: format!(
            "ziros agent bridge accept --handoff-id {}",
            shell_escape_arg(&handoff_id)
        ),
        session_id: None,
        session_status: None,
        last_error: None,
    };
    let handoff = brain.store_bridge_handoff(&record)?;
    Ok(AgentBridgeHandoffPrepareReportV1 {
        schema: "ziros-agent-bridge-handoff-prepare-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        handoff,
    })
}

pub fn list_bridge_handoffs() -> Result<AgentBridgeHandoffListReportV1, String> {
    let brain = BrainStore::open_default()?;
    Ok(AgentBridgeHandoffListReportV1 {
        schema: "ziros-agent-bridge-handoffs-v1".to_string(),
        generated_at: zkf_command_surface::now_rfc3339(),
        handoffs: brain.list_bridge_handoffs()?,
    })
}

pub fn accept_bridge_handoff(
    request: AgentBridgeHandoffAcceptRequestV1,
) -> Result<AgentRunReportV1, String> {
    let brain = BrainStore::open_default()?;
    let mut handoff = brain
        .get_bridge_handoff(&request.handoff_id)?
        .ok_or_else(|| format!("unknown bridge handoff '{}'", request.handoff_id))?;
    if let Err(error) = validate_remote_handoff_options(&handoff) {
        handoff.updated_at = zkf_command_surface::now_rfc3339();
        handoff.last_error = Some(error.clone());
        let _ = brain.store_bridge_handoff(&handoff)?;
        return Err(error);
    }
    handoff.status = "accepted".to_string();
    handoff.updated_at = zkf_command_surface::now_rfc3339();
    handoff.last_error = None;
    let _ = brain.store_bridge_handoff(&handoff)?;

    match run_goal_with_store(&brain, &handoff.goal, handoff.options.clone(), &mut |_| {}) {
        Ok(report) => {
            handoff.status = report.session.status.as_str().to_string();
            handoff.updated_at = zkf_command_surface::now_rfc3339();
            handoff.session_id = Some(report.session.session_id.clone());
            handoff.session_status = Some(report.session.status);
            handoff.last_error = None;
            let _ = brain.store_bridge_handoff(&handoff)?;
            Ok(report)
        }
        Err(error) => {
            handoff.status = "failed".to_string();
            handoff.updated_at = zkf_command_surface::now_rfc3339();
            handoff.last_error = Some(error.clone());
            let _ = brain.store_bridge_handoff(&handoff)?;
            Err(error)
        }
    }
}

fn validate_remote_handoff_options(handoff: &BridgeHandoffRecordV1) -> Result<(), String> {
    let is_remote = handoff.origin.contains("remote") || handoff.origin.contains("chatgpt");
    if !is_remote {
        return Ok(());
    }
    if !handoff.options.strict {
        return Err(
            "refusing to accept remote handoff with strict=false; prepare a fresh strict handoff."
                .to_string(),
        );
    }
    if handoff.options.project_root.is_some() {
        return Err(
            "refusing to accept remote handoff with a caller-supplied project_root; choose the \
local workspace at accept time instead."
                .to_string(),
        );
    }
    Ok(())
}

pub fn approve_request(request: AgentApproveRequestV1) -> Result<WalletApprovalOutcomeV1, String> {
    let mut wallet = WalletContextV1 {
        network: Some(request.wallet_network),
        persistent_root: request.persistent_root.clone(),
        cache_root: request.cache_root.clone(),
    }
    .open_handle()?;
    let approval_request = if let Some(session_id) = request.session_id.as_deref() {
        let brain = BrainStore::open_default()?;
        latest_session_approval_request(&brain, session_id)?
    } else {
        None
    };
    let token = approve_pending(
        &mut wallet,
        &request.pending_id,
        &request.primary_prompt,
        request.secondary_prompt.as_deref(),
    )?;
    let mut session_status = None;
    let mut submission_grant = None;
    if let Some(session_id) = request.session_id.as_deref() {
        let brain = BrainStore::open_default()?;
        brain.store_approval_token(&ApprovalTokenRecordV1 {
            schema: "ziros-agent-approval-token-v1".to_string(),
            token_id: new_operation_id("approval-token"),
            session_id: Some(session_id.to_string()),
            created_at: zkf_command_surface::now_rfc3339(),
            pending_id: request.pending_id.clone(),
            token: token.clone(),
            approval_request_id: approval_request
                .as_ref()
                .map(|record| record.approval_request_id.clone()),
            node_id: approval_request
                .as_ref()
                .and_then(|record| record.node_id.clone()),
            bridge_session_id: request.bridge_session_id.clone(),
        })?;
        if let Some(approval_request) = approval_request.as_ref() {
            unblock_approval_request(&brain, session_id, approval_request)?;
        } else {
            unblock_approval_nodes(&brain, session_id, "wallet.pending.approve")?;
        }
        brain.append_receipt(&brain.new_receipt(
            session_id,
            "wallet-approve",
            "approved",
            &token,
        )?)?;
        match resume_session_with_receipts(session_id, |_| {}) {
            Ok(resumed) => {
                session_status = Some(resumed.session.status);
                submission_grant = brain
                    .list_submission_grants(Some(session_id))?
                    .into_iter()
                    .last();
            }
            Err(error) => {
                brain.store_incident(&IncidentRecordV1 {
                    schema: "ziros-agent-incident-v1".to_string(),
                    incident_id: new_operation_id("incident"),
                    created_at: zkf_command_surface::now_rfc3339(),
                    session_id: Some(session_id.to_string()),
                    action_name: "wallet.pending.approve".to_string(),
                    error_class: CommandErrorClassV1::Unknown,
                    summary: "Approval succeeded but session resume failed.".to_string(),
                    details: serde_json::json!({
                        "pending_id": request.pending_id,
                        "error": error,
                    }),
                })?;
                brain.append_receipt(&brain.new_receipt(
                    session_id,
                    "wallet-approve-resume",
                    "failed",
                    &serde_json::json!({
                        "pending_id": request.pending_id,
                        "error": error,
                    }),
                )?)?;
                session_status = Some(SessionStatusV1::Blocked);
            }
        }
    }
    Ok(WalletApprovalOutcomeV1 {
        schema: "ziros-agent-wallet-approval-v1".to_string(),
        operation_id: new_operation_id("wallet-approve"),
        generated_at: zkf_command_surface::now_rfc3339(),
        token,
        session_id: request.session_id,
        session_status,
        submission_grant,
    })
}

pub fn reject_request(request: AgentRejectRequestV1) -> Result<(), String> {
    let mut wallet = WalletContextV1 {
        network: Some(request.wallet_network),
        persistent_root: request.persistent_root.clone(),
        cache_root: request.cache_root.clone(),
    }
    .open_handle()?;
    reject_pending(&mut wallet, &request.pending_id, &request.reason)?;
    if let Some(session_id) = request.session_id.as_deref() {
        let brain = BrainStore::open_default()?;
        if let Some(approval_request) = latest_session_approval_request(&brain, session_id)? {
            reject_approval_request(&brain, session_id, &approval_request, &request.reason)?;
        }
        brain.store_incident(&IncidentRecordV1 {
            schema: "ziros-agent-incident-v1".to_string(),
            incident_id: new_operation_id("incident"),
            created_at: zkf_command_surface::now_rfc3339(),
            session_id: Some(session_id.to_string()),
            action_name: "wallet.pending.approve".to_string(),
            error_class: CommandErrorClassV1::ApprovalRequired,
            summary: "Wallet approval was explicitly rejected.".to_string(),
            details: serde_json::json!({
                "pending_id": request.pending_id,
                "reason": request.reason,
            }),
        })?;
        brain.append_receipt(&brain.new_receipt(
            session_id,
            "wallet-reject",
            "rejected",
            &serde_json::json!({
                "pending_id": request.pending_id,
                "reason": request.reason,
            }),
        )?)?;
    }
    Ok(())
}

fn load_session_state(
    brain: &BrainStore,
    session_id: &str,
) -> Result<(AgentSessionViewV1, TrustGateReportV1, WorkgraphV1), String> {
    let session = brain
        .get_session(session_id)?
        .ok_or_else(|| format!("unknown agent session '{session_id}'"))?;
    let workgraph = brain
        .get_workgraph(
            session
                .workgraph_id
                .as_deref()
                .ok_or_else(|| format!("session '{session_id}' has no stored workgraph"))?,
        )?
        .ok_or_else(|| format!("missing workgraph for session '{session_id}'"))?;
    let trust_gate = brain
        .get_capability_snapshot(
            session
                .capability_snapshot_id
                .as_deref()
                .ok_or_else(|| format!("session '{session_id}' has no capability snapshot"))?,
        )?
        .ok_or_else(|| format!("missing capability snapshot for session '{session_id}'"))?;
    Ok((session, trust_gate, workgraph))
}

fn resume_options(
    session: &AgentSessionViewV1,
    trust_gate: &TrustGateReportV1,
) -> AgentRunOptionsV1 {
    let wallet_network = trust_gate
        .wallet
        .as_ref()
        .and_then(|wallet| zkf_wallet::WalletNetwork::parse(&wallet.network).ok())
        .or_else(|| {
            trust_gate
                .midnight_status
                .as_ref()
                .and_then(|status| match status.network.as_str() {
                    "preview" => Some(zkf_wallet::WalletNetwork::Preview),
                    "preprod" => Some(zkf_wallet::WalletNetwork::Preprod),
                    _ => None,
                })
        })
        .unwrap_or(zkf_wallet::WalletNetwork::Preprod);
    AgentRunOptionsV1 {
        strict: trust_gate.strict,
        compat_allowed: trust_gate.compat_allowed,
        wallet_network,
        project_root: session
            .project_root
            .as_deref()
            .map(std::path::PathBuf::from),
        use_worktree: true,
        workflow_override: Some(trust_gate.workflow_kind.clone()),
        intent: None,
        provider_override: None,
        model_override: None,
        reasoning_lane: None,
        reasoning_model_label: None,
        reasoning_origin: None,
    }
}

fn effective_project_root(
    workflow_kind: &str,
    goal: &str,
    project_root: Option<std::path::PathBuf>,
) -> Result<Option<std::path::PathBuf>, String> {
    if project_root.is_some() {
        return Ok(project_root);
    }
    let prefix = match workflow_kind {
        "midnight-contract-ops" => Some("midnight"),
        "subsystem-midnight-ops" => Some("subsystem-midnight"),
        "subsystem-scaffold" | "subsystem-modify" | "subsystem-proof" => Some("subsystem"),
        "subsystem-benchmark" => Some("subsystem-benchmark"),
        "subsystem-evidence-release" => Some("subsystem-release"),
        "proof-app-build" => Some("proof-app"),
        _ => None,
    };
    let Some(prefix) = prefix else {
        return Ok(None);
    };
    let cwd = std::env::current_dir()
        .map_err(|error| format!("failed to read current directory: {error}"))?;
    let slug = goal
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .split('-')
        .filter(|segment| !segment.is_empty())
        .take(6)
        .collect::<Vec<_>>()
        .join("-");
    let suffix = if slug.is_empty() {
        "session"
    } else {
        slug.as_str()
    };
    Ok(Some(cwd.join(format!(
        "{prefix}-{suffix}-{}",
        new_operation_id("project")
    ))))
}

fn resolve_goal_intent(goal: &str, options: &AgentRunOptionsV1) -> GoalIntentV1 {
    options
        .intent
        .clone()
        .or_else(|| {
            if should_bypass_local_model_intent_compilation(options) {
                None
            } else {
                try_compile_goal_intent(goal, options)
            }
        })
        .unwrap_or_else(|| compile_goal_intent(goal, options.workflow_override.as_deref()))
}

fn latest_session_approval_request(
    brain: &BrainStore,
    session_id: &str,
) -> Result<Option<ApprovalRequestRecordV1>, String> {
    Ok(brain
        .list_approval_requests(Some(session_id))?
        .into_iter()
        .last())
}

fn unblock_approval_nodes(
    brain: &BrainStore,
    session_id: &str,
    action_name: &str,
) -> Result<(), String> {
    let session = brain
        .get_session(session_id)?
        .ok_or_else(|| format!("unknown agent session '{session_id}'"))?;
    let Some(workgraph_id) = session.workgraph_id.as_deref() else {
        return Ok(());
    };
    let mut workgraph = brain
        .get_workgraph(workgraph_id)?
        .ok_or_else(|| format!("missing workgraph for session '{session_id}'"))?;
    let mut changed = false;
    for node in &mut workgraph.nodes {
        if node.action_name == action_name && node.status == "blocked" {
            node.status = "completed".to_string();
            changed = true;
        }
    }
    if changed {
        workgraph.status = "planned".to_string();
        brain.update_workgraph(&workgraph)?;
        brain.update_session_status(session_id, SessionStatusV1::Planned)?;
    }
    Ok(())
}

fn unblock_approval_request(
    brain: &BrainStore,
    session_id: &str,
    approval_request: &ApprovalRequestRecordV1,
) -> Result<(), String> {
    let Some(node_id) = approval_request.node_id.as_deref() else {
        return unblock_approval_nodes(brain, session_id, &approval_request.action_name);
    };
    let session = brain
        .get_session(session_id)?
        .ok_or_else(|| format!("unknown agent session '{session_id}'"))?;
    let Some(workgraph_id) = session.workgraph_id.as_deref() else {
        return Ok(());
    };
    let mut workgraph = brain
        .get_workgraph(workgraph_id)?
        .ok_or_else(|| format!("missing workgraph for session '{session_id}'"))?;
    let mut changed = false;
    for node in &mut workgraph.nodes {
        if node.node_id == node_id && node.status == "blocked" {
            node.status = "completed".to_string();
            changed = true;
        }
    }
    if changed {
        workgraph.status = "planned".to_string();
        brain.update_workgraph(&workgraph)?;
        brain.update_session_status(session_id, SessionStatusV1::Planned)?;
    }
    Ok(())
}

fn reject_approval_request(
    brain: &BrainStore,
    session_id: &str,
    approval_request: &ApprovalRequestRecordV1,
    reason: &str,
) -> Result<(), String> {
    let Some(node_id) = approval_request.node_id.as_deref() else {
        return Ok(());
    };
    let session = brain
        .get_session(session_id)?
        .ok_or_else(|| format!("unknown agent session '{session_id}'"))?;
    let Some(workgraph_id) = session.workgraph_id.as_deref() else {
        return Ok(());
    };
    let mut workgraph = brain
        .get_workgraph(workgraph_id)?
        .ok_or_else(|| format!("missing workgraph for session '{session_id}'"))?;
    let mut changed = false;
    for node in &mut workgraph.nodes {
        if node.node_id == node_id && node.status == "blocked" {
            node.status = "failed".to_string();
            changed = true;
        }
    }
    if changed {
        workgraph.status = "blocked".to_string();
        brain.update_workgraph(&workgraph)?;
        brain.update_session_status(session_id, SessionStatusV1::Blocked)?;
        brain.append_receipt(&brain.new_receipt(
            session_id,
            "wallet-approval",
            "rejected",
            &serde_json::json!({
                "approval_request_id": approval_request.approval_request_id,
                "node_id": node_id,
                "reason": reason,
            }),
        )?)?;
    }
    Ok(())
}

fn shell_escape_arg(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/'))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\"'\"'"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;
    use zkf_cloudfs::CloudFS;

    #[test]
    fn planner_blocks_midnight_when_gate_is_unready() {
        let report = plan_goal(
            "build and deploy a midnight contract",
            AgentRunOptionsV1::default(),
        )
        .expect("plan");
        assert_eq!(report.workgraph.workflow_kind, "midnight-contract-ops");
        assert!(
            report.trust_gate.blocked || !report.workgraph.blocked_prerequisites.is_empty(),
            "midnight trust gate should block on an unready host"
        );
    }

    #[test]
    fn run_goal_executes_repo_analysis_workgraph() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        prepare_test_hermes_home(&temp.path().join("hermes-home"));
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        let brain = BrainStore::open_with_cloudfs(cloudfs).expect("brain");
        let report = run_goal_with_store(
            &brain,
            "inspect the current ZirOS status",
            AgentRunOptionsV1 {
                strict: false,
                ..AgentRunOptionsV1::default()
            },
            &mut |_| {},
        )
        .expect("run");
        assert_eq!(report.session.status, SessionStatusV1::Completed);
        assert!(
            report
                .workgraph
                .nodes
                .iter()
                .all(|node| node.status == "completed")
        );
        assert!(
            report
                .receipts
                .iter()
                .any(|receipt| receipt.action_name == "truth.inspect")
        );
        clear_test_hermes_home();
    }

    #[test]
    fn run_goal_executes_proof_app_workgraph_via_cli_fallback() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        prepare_test_hermes_home(&temp.path().join("hermes-home"));
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        let brain = BrainStore::open_with_cloudfs(cloudfs).expect("brain");
        let fake_cli = temp.path().join("fake-zkf-cli.sh");
        fs::write(
            &fake_cli,
            r#"#!/bin/sh
set -eu
cmd="$1"
shift
case "$cmd" in
  app)
    sub="$1"
    shift
    if [ "$sub" = "init" ]; then
      out=""
      while [ "$#" -gt 0 ]; do
        if [ "$1" = "--out" ]; then
          out="$2"
          shift 2
        else
          shift
        fi
      done
      mkdir -p "$out"
      printf '{"program":{"field":"bn254"}}\n' > "$out/zirapp.json"
      printf '{"x":"3","y":"5"}\n' > "$out/inputs.compliant.json"
      printf '{"x":"0","y":"0"}\n' > "$out/inputs.violation.json"
    fi
    ;;
  prove)
    out=""
    compiled=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --out) out="$2"; shift 2 ;;
        --compiled-out) compiled="$2"; shift 2 ;;
        *) shift ;;
      esac
    done
    printf '{"status":"ok"}\n' > "$out"
    printf '{"status":"compiled"}\n' > "$compiled"
    ;;
  verify)
    ;;
  benchmark)
    out=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--out" ]; then
        out="$2"
        shift 2
      else
        shift
      fi
    done
    printf '{"schema":"benchmark-report"}\n' > "$out"
    ;;
esac
"#,
        )
        .expect("fake cli");
        let mut permissions = fs::metadata(&fake_cli).expect("metadata").permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(0o755);
            fs::set_permissions(&fake_cli, permissions).expect("chmod");
        }
        unsafe {
            std::env::set_var("ZKF_AGENT_ZKF_BIN", &fake_cli);
        }

        let project_root = temp.path().join("proof-app");
        let report = run_goal_with_store(
            &brain,
            "build a proof app and prove it",
            AgentRunOptionsV1 {
                strict: false,
                compat_allowed: true,
                wallet_network: zkf_wallet::WalletNetwork::Preprod,
                project_root: Some(project_root.clone()),
                use_worktree: false,
                workflow_override: None,
                intent: None,
                provider_override: None,
                model_override: None,
                reasoning_lane: Some("chatgpt-pro-bridge".to_string()),
                reasoning_model_label: Some("GPT-5.4 Thinking".to_string()),
                reasoning_origin: Some("chatgpt-pro-bridge".to_string()),
            },
            &mut |_| {},
        )
        .expect("run");
        unsafe {
            std::env::remove_var("ZKF_AGENT_ZKF_BIN");
        }
        clear_test_hermes_home();

        assert_eq!(report.session.status, SessionStatusV1::Completed);
        assert!(project_root.join("zirapp.json").exists());
        assert!(
            report
                .receipts
                .iter()
                .any(|receipt| receipt.action_name == "proof.compile-prove-verify")
        );
    }

    #[test]
    fn plan_goal_blocks_when_hermes_rigorous_pack_is_missing() {
        let _guard = env_lock().lock().expect("env lock");
        let temp = tempdir().expect("tempdir");
        unsafe {
            std::env::set_var("HERMES_HOME", temp.path().join("missing-pack"));
        }
        let report = plan_goal(
            "inspect the current ZirOS status",
            AgentRunOptionsV1 {
                strict: false,
                ..AgentRunOptionsV1::default()
            },
        )
        .expect("plan");
        assert!(
            report
                .workgraph
                .blocked_prerequisites
                .iter()
                .any(|issue| issue.contains("Hermes rigorous profile unhealthy"))
        );
        clear_test_hermes_home();
    }

    #[test]
    fn approval_unblock_moves_blocked_workgraph_back_to_planned() {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        let brain = BrainStore::open_with_cloudfs(cloudfs).expect("brain");
        let session = brain
            .create_session(
                "deploy a midnight contract",
                "midnight-contract-ops",
                SessionStatusV1::Blocked,
                Some(temp.path().join("project")),
            )
            .expect("session");
        let trust_gate = TrustGateReportV1 {
            schema: "ziros-trust-gate-v1".to_string(),
            gate_id: new_operation_id("trust-gate"),
            generated_at: zkf_command_surface::now_rfc3339(),
            workflow_kind: "midnight-contract-ops".to_string(),
            strict: false,
            compat_allowed: true,
            blocked: false,
            prerequisites: Vec::new(),
            truth_snapshot: serde_json::json!({}),
            midnight_status: None,
            wallet: None,
        };
        let capability_snapshot_id = brain
            .store_capability_snapshot(&session.session_id, &trust_gate)
            .expect("snapshot");
        let workgraph = WorkgraphV1 {
            schema: "ziros-workgraph-v1".to_string(),
            workgraph_id: new_operation_id("workgraph"),
            session_id: Some(session.session_id.clone()),
            workflow_kind: "midnight-contract-ops".to_string(),
            status: "blocked".to_string(),
            goal: "deploy a midnight contract".to_string(),
            intent: crate::types::GoalIntentV1 {
                summary: "deploy a midnight contract".to_string(),
                workflow_kind: "midnight-contract-ops".to_string(),
                scope: crate::types::IntentScopeV1::Project,
                requested_outputs: vec!["deploy-prepare.json".to_string()],
                hints: None,
            },
            execution_policy: crate::types::ExecutionPolicyV1 {
                strict: false,
                compat_allowed: true,
                stop_on_first_failure: true,
                require_explicit_approval_for_high_risk: true,
                operator_profile: crate::types::OperatorProfileV1::HermesRigorous,
                structured_command_first: true,
                postflight_required: true,
            },
            capability_requirements: Vec::new(),
            blocked_prerequisites: Vec::new(),
            nodes: vec![crate::types::WorkgraphNodeV1 {
                node_id: "node-wallet-approval".to_string(),
                label: "Approve Midnight submission".to_string(),
                action_name: "wallet.pending.approve".to_string(),
                status: "blocked".to_string(),
                approval_required: true,
                risk_class: zkf_command_surface::RiskClassV1::WalletSignOrSubmit,
                success_predicates: Vec::new(),
                depends_on: Vec::new(),
                expected_artifacts: vec!["approval-token.json".to_string()],
            }],
        };
        let stored = brain
            .store_workgraph(
                &session.session_id,
                capability_snapshot_id.clone(),
                &workgraph,
            )
            .expect("store workgraph");
        let _ = brain
            .attach_workgraph(
                &session.session_id,
                &stored.workgraph_id,
                capability_snapshot_id,
            )
            .expect("attach");

        unblock_approval_nodes(&brain, &session.session_id, "wallet.pending.approve")
            .expect("unblock");
        let session = brain
            .get_session(&session.session_id)
            .expect("load session")
            .expect("session");
        let workgraph = brain
            .get_workgraph(&stored.workgraph_id)
            .expect("load workgraph")
            .expect("workgraph");
        assert_eq!(session.status, SessionStatusV1::Planned);
        assert_eq!(workgraph.status, "planned");
        assert_eq!(workgraph.nodes[0].status, "completed");
    }

    #[test]
    fn explicit_intent_beats_keyword_inference() {
        let report = plan_goal(
            "deploy a midnight contract and benchmark it",
            AgentRunOptionsV1 {
                strict: false,
                compat_allowed: true,
                intent: Some(crate::types::GoalIntentV1 {
                    summary: "inspect host readiness".to_string(),
                    workflow_kind: "host-readiness".to_string(),
                    scope: crate::types::IntentScopeV1::Host,
                    requested_outputs: vec!["capabilities.json".to_string()],
                    hints: Some(crate::types::IntentHintsV1 {
                        require_wallet: Some(false),
                        require_metal: Some(false),
                        ..crate::types::IntentHintsV1::default()
                    }),
                }),
                ..AgentRunOptionsV1::default()
            },
        )
        .expect("plan");
        assert_eq!(report.workgraph.workflow_kind, "host-readiness");
        assert_eq!(report.workgraph.intent.workflow_kind, "host-readiness");
        assert!(
            report
                .workgraph
                .capability_requirements
                .iter()
                .all(|requirement| requirement.id != "wallet" && requirement.id != "midnight")
        );
    }

    #[test]
    fn workflow_requirements_prefer_intent_hints() {
        let intent = crate::types::GoalIntentV1 {
            summary: "benchmark a subsystem".to_string(),
            workflow_kind: "subsystem-benchmark".to_string(),
            scope: crate::types::IntentScopeV1::Project,
            requested_outputs: vec!["benchmark-report.json".to_string()],
            hints: Some(crate::types::IntentHintsV1 {
                require_wallet: Some(true),
                require_metal: Some(true),
                benchmark_parallel: Some(true),
                benchmark_distributed: Some(true),
                ..crate::types::IntentHintsV1::default()
            }),
        };
        let requirements = WorkflowRequirementsV1::for_goal(
            "plain goal with no hardware keywords",
            &intent,
            &AgentRunOptionsV1::default(),
        );
        assert!(requirements.require_wallet);
        assert!(requirements.require_metal);
    }

    #[test]
    fn approval_request_unblocks_only_its_exact_node() {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        let brain = BrainStore::open_with_cloudfs(cloudfs).expect("brain");
        let session = brain
            .create_session(
                "deploy a midnight contract",
                "midnight-contract-ops",
                SessionStatusV1::Blocked,
                Some(temp.path().join("project")),
            )
            .expect("session");
        let trust_gate = TrustGateReportV1 {
            schema: "ziros-trust-gate-v1".to_string(),
            gate_id: new_operation_id("trust-gate"),
            generated_at: zkf_command_surface::now_rfc3339(),
            workflow_kind: "midnight-contract-ops".to_string(),
            strict: false,
            compat_allowed: true,
            blocked: false,
            prerequisites: Vec::new(),
            truth_snapshot: serde_json::json!({}),
            midnight_status: None,
            wallet: None,
        };
        let capability_snapshot_id = brain
            .store_capability_snapshot(&session.session_id, &trust_gate)
            .expect("snapshot");
        let workgraph = WorkgraphV1 {
            schema: "ziros-workgraph-v1".to_string(),
            workgraph_id: new_operation_id("workgraph"),
            session_id: Some(session.session_id.clone()),
            workflow_kind: "midnight-contract-ops".to_string(),
            status: "blocked".to_string(),
            goal: "deploy a midnight contract".to_string(),
            intent: crate::types::GoalIntentV1 {
                summary: "deploy a midnight contract".to_string(),
                workflow_kind: "midnight-contract-ops".to_string(),
                scope: crate::types::IntentScopeV1::Project,
                requested_outputs: vec!["deploy-prepare.json".to_string()],
                hints: None,
            },
            execution_policy: crate::types::ExecutionPolicyV1 {
                strict: false,
                compat_allowed: true,
                stop_on_first_failure: true,
                require_explicit_approval_for_high_risk: true,
                operator_profile: crate::types::OperatorProfileV1::HermesRigorous,
                structured_command_first: true,
                postflight_required: true,
            },
            capability_requirements: Vec::new(),
            blocked_prerequisites: Vec::new(),
            nodes: vec![
                crate::types::WorkgraphNodeV1 {
                    node_id: "node-wallet-approval-a".to_string(),
                    label: "Approve Midnight submission A".to_string(),
                    action_name: "wallet.pending.approve".to_string(),
                    status: "blocked".to_string(),
                    approval_required: true,
                    risk_class: zkf_command_surface::RiskClassV1::WalletSignOrSubmit,
                    success_predicates: Vec::new(),
                    depends_on: Vec::new(),
                    expected_artifacts: vec!["approval-token.json".to_string()],
                },
                crate::types::WorkgraphNodeV1 {
                    node_id: "node-wallet-approval-b".to_string(),
                    label: "Approve Midnight submission B".to_string(),
                    action_name: "wallet.pending.approve".to_string(),
                    status: "blocked".to_string(),
                    approval_required: true,
                    risk_class: zkf_command_surface::RiskClassV1::WalletSignOrSubmit,
                    success_predicates: Vec::new(),
                    depends_on: Vec::new(),
                    expected_artifacts: vec!["approval-token.json".to_string()],
                },
            ],
        };
        let stored = brain
            .store_workgraph(
                &session.session_id,
                capability_snapshot_id.clone(),
                &workgraph,
            )
            .expect("store workgraph");
        let _ = brain
            .attach_workgraph(
                &session.session_id,
                &stored.workgraph_id,
                capability_snapshot_id,
            )
            .expect("attach");
        let approval_request = ApprovalRequestRecordV1 {
            schema: "ziros-agent-approval-request-v1".to_string(),
            approval_request_id: new_operation_id("approval-request"),
            session_id: Some(session.session_id.clone()),
            created_at: zkf_command_surface::now_rfc3339(),
            pending_id: "node-wallet-approval-a".to_string(),
            risk_class: zkf_command_surface::RiskClassV1::WalletSignOrSubmit,
            action_name: "wallet.pending.approve".to_string(),
            node_id: Some("node-wallet-approval-a".to_string()),
            wallet_pending_id: Some("wallet-pending-1".to_string()),
        };
        unblock_approval_request(&brain, &session.session_id, &approval_request)
            .expect("unblock exact request");
        let workgraph = brain
            .get_workgraph(&stored.workgraph_id)
            .expect("load workgraph")
            .expect("workgraph");
        assert_eq!(workgraph.nodes[0].status, "completed");
        assert_eq!(workgraph.nodes[1].status, "blocked");
    }

    #[test]
    fn workflow_list_exposes_expected_builtins() {
        let report = workflow_list().expect("workflow list");
        let workflow_kinds = report
            .workflows
            .iter()
            .map(|workflow| workflow.workflow_kind.as_str())
            .collect::<Vec<_>>();
        assert!(workflow_kinds.contains(&"subsystem-scaffold"));
        assert!(workflow_kinds.contains(&"subsystem-midnight-ops"));
        assert!(workflow_kinds.contains(&"proof-app-build"));
        assert!(workflow_kinds.contains(&"midnight-contract-ops"));
        assert!(workflow_kinds.contains(&"benchmark-report"));
    }

    #[test]
    fn session_artifacts_reports_registered_artifacts() {
        let temp = tempdir().expect("tempdir");
        let cloudfs = CloudFS::from_roots(
            temp.path().join("persistent"),
            temp.path().join("cache"),
            false,
        );
        let brain = BrainStore::open_with_cloudfs(cloudfs).expect("brain");
        let session = brain
            .create_session(
                "inspect artifacts",
                "repo-analysis",
                SessionStatusV1::Completed,
                None,
            )
            .expect("session");
        brain
            .register_artifact(
                Some(&session.session_id),
                zkf_command_surface::ArtifactRefV1 {
                    label: "plan".to_string(),
                    path: temp.path().join("plan.json").display().to_string(),
                    kind: Some("json".to_string()),
                },
            )
            .expect("artifact");

        let report = session_artifacts_with_store(&brain, Some(&session.session_id))
            .expect("artifact report");
        assert_eq!(report.artifacts.len(), 1);
        assert_eq!(report.artifacts[0].artifact.label, "plan");
    }

    #[test]
    fn remote_handoff_validation_rejects_non_strict_options() {
        let error = validate_remote_handoff_options(&BridgeHandoffRecordV1 {
            schema: "ziros-agent-bridge-handoff-v1".to_string(),
            handoff_id: "bridge-handoff-test".to_string(),
            bridge_session_id: "bridge-handoff-test".to_string(),
            created_at: "2026-04-13T00:00:00Z".to_string(),
            updated_at: "2026-04-13T00:00:00Z".to_string(),
            origin: "remote-mcp".to_string(),
            status: "prepared".to_string(),
            goal: "inspect host readiness".to_string(),
            options: AgentRunOptionsV1 {
                strict: false,
                ..AgentRunOptionsV1::default()
            },
            local_command: "ziros agent bridge accept --handoff-id bridge-handoff-test".to_string(),
            session_id: None,
            session_status: None,
            last_error: None,
        })
        .expect_err("remote strict=false handoff should be rejected");
        assert!(error.contains("strict=false"));
    }

    #[test]
    fn remote_handoff_validation_rejects_caller_project_root() {
        let error = validate_remote_handoff_options(&BridgeHandoffRecordV1 {
            schema: "ziros-agent-bridge-handoff-v1".to_string(),
            handoff_id: "bridge-handoff-test".to_string(),
            bridge_session_id: "bridge-handoff-test".to_string(),
            created_at: "2026-04-13T00:00:00Z".to_string(),
            updated_at: "2026-04-13T00:00:00Z".to_string(),
            origin: "chatgpt-pro-bridge".to_string(),
            status: "prepared".to_string(),
            goal: "build proof app".to_string(),
            options: AgentRunOptionsV1 {
                strict: true,
                project_root: Some(PathBuf::from("/tmp/attacker")),
                ..AgentRunOptionsV1::default()
            },
            local_command: "ziros agent bridge accept --handoff-id bridge-handoff-test".to_string(),
            session_id: None,
            session_status: None,
            last_error: None,
        })
        .expect_err("remote project_root handoff should be rejected");
        assert!(error.contains("project_root"));
    }

    #[test]
    fn local_handoff_validation_allows_non_strict_local_origin() {
        validate_remote_handoff_options(&BridgeHandoffRecordV1 {
            schema: "ziros-agent-bridge-handoff-v1".to_string(),
            handoff_id: "bridge-handoff-test".to_string(),
            bridge_session_id: "bridge-handoff-test".to_string(),
            created_at: "2026-04-13T00:00:00Z".to_string(),
            updated_at: "2026-04-13T00:00:00Z".to_string(),
            origin: "local-cli".to_string(),
            status: "prepared".to_string(),
            goal: "inspect host readiness".to_string(),
            options: AgentRunOptionsV1 {
                strict: false,
                project_root: Some(PathBuf::from("/tmp/local")),
                ..AgentRunOptionsV1::default()
            },
            local_command: "ziros agent bridge accept --handoff-id bridge-handoff-test".to_string(),
            session_id: None,
            session_status: None,
            last_error: None,
        })
        .expect("local handoff should remain allowed");
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn prepare_test_hermes_home(path: &Path) {
        unsafe {
            std::env::set_var("HERMES_HOME", path);
        }
        hermes_sync().expect("sync hermes pack");
    }

    fn clear_test_hermes_home() {
        unsafe {
            std::env::remove_var("HERMES_HOME");
        }
    }
}
