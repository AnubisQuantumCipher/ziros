use crate::{
    accept_bridge_handoff, agent_status, approval_lineage, cancel_session, cleanup_worktree,
    create_checkpoint, create_worktree, event_subscription, list_bridge_handoffs,
    list_checkpoints, list_incidents, list_procedures, list_projects, list_worktrees,
    memory_sessions, plan_goal, prepare_bridge_handoff, provider_route, provider_status,
    provider_test, register_project, resume_session, rollback_checkpoint, run_goal,
    session_artifacts, session_deployments, session_environments, session_logs, workflow_list,
    workflow_show,
};
use crate::{approve_request, reject_request};
use crate::types::{
    AgentApproveRequestV1, AgentBridgeHandoffAcceptRequestV1,
    AgentBridgeHandoffPrepareRequestV1, AgentCancelRequestV1, AgentCheckpointCreateRequestV1,
    AgentCheckpointRollbackRequestV1, AgentProjectRegisterRequestV1,
    AgentProviderRouteRequestV1, AgentProviderTestRequestV1, AgentRejectRequestV1,
    AgentRunOptionsV1, AgentWorktreeCleanupRequestV1, AgentWorktreeCreateRequestV1,
    EventSubscriptionRequestV1,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use crate::state::{ensure_ziros_layout, socket_path as managed_socket_path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case")]
pub enum AgentRpcRequestV1 {
    Status { limit: usize },
    Plan { goal: String, options: AgentRunOptionsV1 },
    Run { goal: String, options: AgentRunOptionsV1 },
    Resume { session_id: String },
    Cancel { request: AgentCancelRequestV1 },
    Logs { session_id: String },
    Artifacts { session_id: Option<String> },
    Approvals { session_id: Option<String> },
    Deployments { session_id: Option<String> },
    Environments { session_id: Option<String> },
    Procedures,
    Incidents { session_id: Option<String> },
    MemorySessions { limit: usize },
    WorkflowList,
    WorkflowShow { workgraph_id: String },
    ProjectRegister { request: AgentProjectRegisterRequestV1 },
    ProjectList,
    BridgeHandoffPrepare { request: AgentBridgeHandoffPrepareRequestV1 },
    BridgeHandoffList,
    BridgeHandoffAccept { request: AgentBridgeHandoffAcceptRequestV1 },
    WorktreeList { session_id: Option<String> },
    WorktreeCreate { request: AgentWorktreeCreateRequestV1 },
    WorktreeCleanup { request: AgentWorktreeCleanupRequestV1 },
    CheckpointList { session_id: String },
    CheckpointCreate { request: AgentCheckpointCreateRequestV1 },
    CheckpointRollback { request: AgentCheckpointRollbackRequestV1 },
    ProviderStatus { session_id: Option<String> },
    ProviderRoute { request: AgentProviderRouteRequestV1 },
    ProviderTest { request: AgentProviderTestRequestV1 },
    Approve { request: AgentApproveRequestV1 },
    Reject { request: AgentRejectRequestV1 },
    EventSubscribe { request: EventSubscriptionRequestV1 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRpcResponseV1 {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn default_socket_path() -> Result<PathBuf, String> {
    let _ = ensure_ziros_layout()?;
    Ok(managed_socket_path())
}

pub fn serve_daemon(socket_path: Option<PathBuf>) -> Result<(), String> {
    let socket_path = socket_path.unwrap_or(default_socket_path()?);
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    if socket_path.exists() {
        let _ = fs::remove_file(&socket_path);
    }
    let listener = UnixListener::bind(&socket_path)
        .map_err(|error| format!("failed to bind {}: {error}", socket_path.display()))?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let _ = handle_stream(stream);
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn handle_stream(mut stream: UnixStream) -> Result<(), String> {
    let mut line = String::new();
    let mut reader = BufReader::new(stream.try_clone().map_err(|error| error.to_string())?);
    reader.read_line(&mut line).map_err(|error| error.to_string())?;
    if line.trim().is_empty() {
        return Ok(());
    }
    let request: AgentRpcRequestV1 =
        serde_json::from_str(&line).map_err(|error| error.to_string())?;
    let response = match handle_rpc_request(request) {
        Ok(data) => AgentRpcResponseV1 {
            ok: true,
            data: Some(data),
            error: None,
        },
        Err(error) => AgentRpcResponseV1 {
            ok: false,
            data: None,
            error: Some(error),
        },
    };
    let body = serde_json::to_vec(&response).map_err(|error| error.to_string())?;
    stream.write_all(&body).map_err(|error| error.to_string())?;
    stream.write_all(b"\n").map_err(|error| error.to_string())
}

pub fn call_daemon(
    request: &AgentRpcRequestV1,
    socket_path: Option<PathBuf>,
) -> Result<AgentRpcResponseV1, String> {
    let socket_path = socket_path.unwrap_or(default_socket_path()?);
    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|error| format!("failed to connect {}: {error}", socket_path.display()))?;
    let body = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    stream.write_all(&body).map_err(|error| error.to_string())?;
    stream.write_all(b"\n").map_err(|error| error.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|error| error.to_string())?;
    serde_json::from_str(&line).map_err(|error| error.to_string())
}

pub fn handle_rpc_request(request: AgentRpcRequestV1) -> Result<Value, String> {
    match request {
        AgentRpcRequestV1::Status { limit } => {
            serde_json::to_value(agent_status(limit)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Plan { goal, options } => {
            serde_json::to_value(plan_goal(&goal, options)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Run { goal, options } => {
            serde_json::to_value(run_goal(&goal, options)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Resume { session_id } => {
            serde_json::to_value(resume_session(&session_id)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Cancel { request } => {
            serde_json::to_value(cancel_session(request)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Logs { session_id } => {
            serde_json::to_value(session_logs(&session_id)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Artifacts { session_id } => {
            serde_json::to_value(session_artifacts(session_id.as_deref())?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Approvals { session_id } => {
            serde_json::to_value(approval_lineage(session_id.as_deref())?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Deployments { session_id } => {
            serde_json::to_value(session_deployments(session_id.as_deref())?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Environments { session_id } => {
            serde_json::to_value(session_environments(session_id.as_deref())?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Procedures => {
            serde_json::to_value(list_procedures()?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Incidents { session_id } => {
            serde_json::to_value(list_incidents(session_id.as_deref())?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::MemorySessions { limit } => serde_json::to_value(memory_sessions(limit)?)
            .map_err(|error| error.to_string()),
        AgentRpcRequestV1::WorkflowList => {
            serde_json::to_value(workflow_list()?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::WorkflowShow { workgraph_id } => {
            serde_json::to_value(workflow_show(&workgraph_id)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::ProjectRegister { request } => {
            serde_json::to_value(register_project(request)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::ProjectList => {
            serde_json::to_value(list_projects()?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::BridgeHandoffPrepare { request } => {
            serde_json::to_value(prepare_bridge_handoff(request)?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::BridgeHandoffList => {
            serde_json::to_value(list_bridge_handoffs()?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::BridgeHandoffAccept { request } => {
            serde_json::to_value(accept_bridge_handoff(request)?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::WorktreeList { session_id } => {
            serde_json::to_value(list_worktrees(session_id.as_deref())?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::WorktreeCreate { request } => {
            serde_json::to_value(create_worktree(request)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::WorktreeCleanup { request } => {
            serde_json::to_value(cleanup_worktree(request)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::CheckpointList { session_id } => {
            serde_json::to_value(list_checkpoints(&session_id)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::CheckpointCreate { request } => {
            serde_json::to_value(create_checkpoint(request)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::CheckpointRollback { request } => {
            serde_json::to_value(rollback_checkpoint(request)?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::ProviderStatus { session_id } => {
            serde_json::to_value(provider_status(session_id.as_deref())?)
                .map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::ProviderRoute { request } => {
            serde_json::to_value(provider_route(request)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::ProviderTest { request } => {
            serde_json::to_value(provider_test(request)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Approve { request } => {
            serde_json::to_value(approve_request(request)?).map_err(|error| error.to_string())
        }
        AgentRpcRequestV1::Reject { request } => {
            reject_request(request)?;
            Ok(serde_json::json!({ "status": "ok" }))
        }
        AgentRpcRequestV1::EventSubscribe { request } => {
            serde_json::to_value(event_subscription(request)?).map_err(|error| error.to_string())
        }
    }
}
