use crate::daemon::{AgentRpcRequestV1, handle_rpc_request};
use crate::types::{
    AgentApproveRequestV1, AgentBridgeHandoffAcceptRequestV1,
    AgentBridgeHandoffPrepareRequestV1, AgentCheckpointCreateRequestV1,
    AgentCheckpointRollbackRequestV1, AgentProjectRegisterRequestV1,
    AgentProviderRouteRequestV1, AgentProviderTestRequestV1, AgentRejectRequestV1,
    AgentRunOptionsV1, AgentWorktreeCleanupRequestV1, AgentWorktreeCreateRequestV1,
    EventSubscriptionRequestV1, GoalIntentV1,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use zkf_wallet::WalletNetwork;

const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpExposureV1 {
    LocalStdio,
    RemoteBridgeReadOnly,
    RemoteBridgeWrite,
}

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    pub jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

pub fn serve_mcp_stdio() -> Result<(), String> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    loop {
        let Some(request) = read_message(&mut reader)? else {
            break;
        };
        let response = match handle_mcp_request(request, McpExposureV1::LocalStdio) {
            Ok(response) => response,
            Err(error) => JsonRpcResponse {
                jsonrpc: "2.0",
                id: None,
                result: None,
                error: Some(JsonRpcError {
                    code: -32603,
                    message: error,
                }),
            },
        };
        if response.id.is_none() && response.result.is_none() && response.error.is_none() {
            continue;
        }
        write_message(&mut writer, &response)?;
    }
    Ok(())
}

pub fn handle_mcp_jsonrpc_bytes(
    body: &[u8],
    exposure: McpExposureV1,
) -> Result<Vec<u8>, String> {
    let request: JsonRpcRequest =
        serde_json::from_slice(body).map_err(|error| error.to_string())?;
    let response = match handle_mcp_request(request, exposure) {
        Ok(response) => response,
        Err(error) => JsonRpcResponse {
            jsonrpc: "2.0",
            id: None,
            result: None,
            error: Some(JsonRpcError {
                code: -32603,
                message: error,
            }),
        },
    };
    serde_json::to_vec(&response).map_err(|error| error.to_string())
}

pub fn mcp_server_manifest(exposure: McpExposureV1) -> Value {
    json!({
        "schema": "ziros-mcp-server-v1",
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "serverInfo": {
            "name": "ziros-agent",
            "version": env!("CARGO_PKG_VERSION")
        },
        "transport": "jsonrpc-http-post",
        "exposure": exposure_label(exposure),
        "localExecutionBoundary": "ziros-agentd",
        "instructions": "Use the existing ZirOS MCP tool surface remotely for planning and inspection, then accept mutating execution locally through ZirOS.",
        "tools": tool_definitions(exposure),
    })
}

fn exposure_label(exposure: McpExposureV1) -> &'static str {
    match exposure {
        McpExposureV1::LocalStdio => "local-stdio",
        McpExposureV1::RemoteBridgeReadOnly => "remote-bridge-read-only",
        McpExposureV1::RemoteBridgeWrite => "remote-bridge-write",
    }
}

fn handle_mcp_request(
    request: JsonRpcRequest,
    exposure: McpExposureV1,
) -> Result<JsonRpcResponse, String> {
    if request.jsonrpc != "2.0" {
        return Ok(error_response(
            request.id,
            -32600,
            "invalid jsonrpc version".to_string(),
        ));
    }
    match request.method.as_str() {
        "initialize" => {
            let protocol_version = request
                .params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(MCP_PROTOCOL_VERSION);
            Ok(JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(json!({
                    "protocolVersion": protocol_version,
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "ziros-agent",
                        "version": env!("CARGO_PKG_VERSION")
                    },
                    "instructions": "Use the ZirOS agent tools to inspect status, plan workgraphs, fetch receipts, and route approved local execution through the same ZirOS daemon core.",
                    "zirosExposure": exposure_label(exposure)
                })),
                error: None,
            })
        }
        "notifications/initialized" => Ok(empty_notification()),
        "ping" => Ok(JsonRpcResponse {
            jsonrpc: "2.0",
            id: request.id,
            result: Some(json!({})),
            error: None,
        }),
        "tools/list" => Ok(JsonRpcResponse {
            jsonrpc: "2.0",
            id: request.id,
            result: Some(json!({ "tools": tool_definitions(exposure) })),
            error: None,
        }),
        "tools/call" => {
            let name = request
                .params
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| "tools/call requires params.name".to_string())?;
            let arguments = request
                .params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let result = call_tool(name, arguments, exposure)?;
            Ok(JsonRpcResponse {
                jsonrpc: "2.0",
                id: request.id,
                result: Some(result),
                error: None,
            })
        }
        _ if request.id.is_none() => Ok(empty_notification()),
        _ => Ok(error_response(
            request.id,
            -32601,
            format!("unsupported MCP method '{}'", request.method),
        )),
    }
}

fn call_tool(name: &str, arguments: Value, exposure: McpExposureV1) -> Result<Value, String> {
    if !is_tool_allowed(name, exposure) {
        return Ok(tool_error(format!(
            "tool '{}' is not exposed for {}",
            name,
            exposure_label(exposure)
        )));
    }
    let request = match name {
        "agent_status" => AgentRpcRequestV1::Status {
            limit: read_usize(&arguments, "limit", 10)?,
        },
        "agent_plan" => {
            let goal = read_string(&arguments, "goal")?;
            AgentRpcRequestV1::Plan {
                goal,
                options: read_run_options(&arguments)?,
            }
        }
        "agent_run" => {
            let goal = read_string(&arguments, "goal")?;
            AgentRpcRequestV1::Run {
                goal,
                options: read_run_options(&arguments)?,
            }
        }
        "agent_resume" => AgentRpcRequestV1::Resume {
            session_id: read_string(&arguments, "session_id")?,
        },
        "agent_logs" => AgentRpcRequestV1::Logs {
            session_id: read_string(&arguments, "session_id")?,
        },
        "agent_artifacts" => AgentRpcRequestV1::Artifacts {
            session_id: read_optional_string(&arguments, "session_id"),
        },
        "agent_approvals" => AgentRpcRequestV1::Approvals {
            session_id: read_optional_string(&arguments, "session_id"),
        },
        "agent_deployments" => AgentRpcRequestV1::Deployments {
            session_id: read_optional_string(&arguments, "session_id"),
        },
        "agent_environments" => AgentRpcRequestV1::Environments {
            session_id: read_optional_string(&arguments, "session_id"),
        },
        "agent_procedures" => AgentRpcRequestV1::Procedures,
        "agent_incidents" => AgentRpcRequestV1::Incidents {
            session_id: read_optional_string(&arguments, "session_id"),
        },
        "agent_event_subscribe" => AgentRpcRequestV1::EventSubscribe {
            request: EventSubscriptionRequestV1 {
                session_id: read_optional_string(&arguments, "session_id"),
                after_receipt_id: read_optional_string(&arguments, "after_receipt_id"),
                limit: read_usize(&arguments, "limit", 50)?,
            },
        },
        "agent_workflow_list" => AgentRpcRequestV1::WorkflowList,
        "agent_workflow_show" => AgentRpcRequestV1::WorkflowShow {
            workgraph_id: read_string(&arguments, "workgraph_id")?,
        },
        "agent_projects_list" => AgentRpcRequestV1::ProjectList,
        "agent_projects_register" => AgentRpcRequestV1::ProjectRegister {
            request: AgentProjectRegisterRequestV1 {
                name: read_string(&arguments, "name")?,
                root_path: read_string(&arguments, "root_path")?,
            },
        },
        "agent_bridge_prepare" => AgentRpcRequestV1::BridgeHandoffPrepare {
            request: AgentBridgeHandoffPrepareRequestV1 {
                origin: read_optional_string(&arguments, "origin")
                    .unwrap_or_else(|| "remote-mcp".to_string()),
                goal: read_string(&arguments, "goal")?,
                options: read_run_options(&arguments)?,
            },
        },
        "agent_bridge_handoffs" => AgentRpcRequestV1::BridgeHandoffList,
        "agent_bridge_accept" => AgentRpcRequestV1::BridgeHandoffAccept {
            request: AgentBridgeHandoffAcceptRequestV1 {
                handoff_id: read_string(&arguments, "handoff_id")?,
            },
        },
        "agent_worktrees_list" => AgentRpcRequestV1::WorktreeList {
            session_id: read_optional_string(&arguments, "session_id"),
        },
        "agent_worktrees_create" => AgentRpcRequestV1::WorktreeCreate {
            request: AgentWorktreeCreateRequestV1 {
                session_id: read_string(&arguments, "session_id")?,
            },
        },
        "agent_worktrees_cleanup" => AgentRpcRequestV1::WorktreeCleanup {
            request: AgentWorktreeCleanupRequestV1 {
                worktree_id: read_string(&arguments, "worktree_id")?,
                remove_files: arguments
                    .get("remove_files")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
        },
        "agent_checkpoints_list" => AgentRpcRequestV1::CheckpointList {
            session_id: read_string(&arguments, "session_id")?,
        },
        "agent_checkpoints_create" => AgentRpcRequestV1::CheckpointCreate {
            request: AgentCheckpointCreateRequestV1 {
                session_id: read_string(&arguments, "session_id")?,
                label: read_string(&arguments, "label")?,
            },
        },
        "agent_checkpoints_rollback" => AgentRpcRequestV1::CheckpointRollback {
            request: AgentCheckpointRollbackRequestV1 {
                checkpoint_id: read_string(&arguments, "checkpoint_id")?,
            },
        },
        "agent_provider_status" => AgentRpcRequestV1::ProviderStatus {
            session_id: read_optional_string(&arguments, "session_id"),
        },
        "agent_provider_route" => AgentRpcRequestV1::ProviderRoute {
            request: AgentProviderRouteRequestV1 {
                session_id: read_optional_string(&arguments, "session_id"),
                provider_override: read_optional_string(&arguments, "provider_override"),
                model_override: read_optional_string(&arguments, "model_override"),
            },
        },
        "agent_provider_test" => AgentRpcRequestV1::ProviderTest {
            request: AgentProviderTestRequestV1 {
                session_id: read_optional_string(&arguments, "session_id"),
                provider_override: read_optional_string(&arguments, "provider_override"),
                model_override: read_optional_string(&arguments, "model_override"),
            },
        },
        "agent_approve" => AgentRpcRequestV1::Approve {
            request: AgentApproveRequestV1 {
                session_id: read_optional_string(&arguments, "session_id"),
                wallet_network: read_wallet_network(&arguments)?,
                pending_id: read_string(&arguments, "pending_id")?,
                primary_prompt: read_string(&arguments, "primary_prompt")?,
                secondary_prompt: read_optional_string(&arguments, "secondary_prompt"),
                bridge_session_id: read_optional_string(&arguments, "bridge_session_id"),
                persistent_root: read_optional_path(&arguments, "persistent_root"),
                cache_root: read_optional_path(&arguments, "cache_root"),
            },
        },
        "agent_reject" => AgentRpcRequestV1::Reject {
            request: AgentRejectRequestV1 {
                session_id: read_optional_string(&arguments, "session_id"),
                wallet_network: read_wallet_network(&arguments)?,
                pending_id: read_string(&arguments, "pending_id")?,
                reason: read_string(&arguments, "reason")?,
                persistent_root: read_optional_path(&arguments, "persistent_root"),
                cache_root: read_optional_path(&arguments, "cache_root"),
            },
        },
        other => return Ok(tool_error(format!("unknown agent tool '{other}'"))),
    };
    match handle_rpc_request(request) {
        Ok(payload) => Ok(tool_ok(payload)),
        Err(error) => Ok(tool_error(error)),
    }
}

fn tool_definitions(exposure: McpExposureV1) -> Vec<Value> {
    let mut tools = vec![
        json!({
            "name": "agent_status",
            "description": "Inspect the live ZirOS agent daemon status, socket path, recent sessions, and registered projects.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": { "type": "integer", "minimum": 1, "default": 10 }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_plan",
            "description": "Resolve trust gates and compile a product-level ZirOS workgraph without creating a new run session.",
            "inputSchema": goal_schema()
        }),
    ];
    if matches!(exposure, McpExposureV1::LocalStdio | McpExposureV1::RemoteBridgeWrite) {
        tools.extend(vec![
            json!({
                "name": "agent_run",
                "description": "Create a ZirOS agent session, persist the trust gate snapshot, execute eligible workgraph nodes, and stop honestly at completion or a real block boundary.",
                "inputSchema": goal_schema()
            }),
            json!({
                "name": "agent_resume",
                "description": "Resume execution for a stored ZirOS agent session when pending nodes remain runnable.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string" }
                    },
                    "required": ["session_id"],
                    "additionalProperties": false
                }
            }),
        ]);
    }
    tools.extend(vec![
        json!({
            "name": "agent_logs",
            "description": "Fetch append-only action receipts for a ZirOS agent session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "required": ["session_id"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_artifacts",
            "description": "Fetch recorded artifact references for a ZirOS agent session or for the whole local Brain.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_approvals",
            "description": "Fetch approval requests, approval tokens, and submission grants for a ZirOS agent session or for the whole local Brain.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_deployments",
            "description": "Fetch recorded deployment summaries for a ZirOS agent session or for the whole local Brain.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_environments",
            "description": "Fetch persisted environment snapshots for a ZirOS agent session or for the whole local Brain.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_procedures",
            "description": "List reusable procedures promoted from successful ZirOS agent runs.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_incidents",
            "description": "List persisted incidents promoted from failed ZirOS agent runs.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_event_subscribe",
            "description": "Fetch receipts after a known receipt id so callers can poll the append-only event stream.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "after_receipt_id": { "type": "string" },
                    "limit": { "type": "integer", "minimum": 1, "default": 50 }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_workflow_list",
            "description": "List the built-in ZirOS agent workflow families compiled by the planner.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_workflow_show",
            "description": "Load a stored ZirOS workgraph by id.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workgraph_id": { "type": "string" }
                },
                "required": ["workgraph_id"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_projects_list",
            "description": "List registered ZirOS agent projects from the local Brain store.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_bridge_prepare",
            "description": "Prepare a local ZirOS bridge handoff so ChatGPT can plan remotely and the operator can accept execution locally.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "origin": { "type": "string", "default": "remote-mcp" },
                    "goal": { "type": "string" },
                    "workflow_override": { "type": "string" },
                    "strict": { "type": "boolean", "default": true },
                    "compat_allowed": { "type": "boolean", "default": false },
                    "use_worktree": { "type": "boolean", "default": true },
                    "wallet_network": { "type": "string", "default": "preprod" },
                    "project_root": { "type": "string" },
                    "provider_override": { "type": "string" },
                    "model_override": { "type": "string" }
                },
                "required": ["goal"],
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_bridge_handoffs",
            "description": "List prepared and accepted ZirOS bridge handoffs.",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        }),
    ]);
    if matches!(exposure, McpExposureV1::LocalStdio | McpExposureV1::RemoteBridgeWrite) {
        tools.extend(vec![
            json!({
                "name": "agent_projects_register",
                "description": "Register a project root so the ZirOS agent can reuse it across sessions.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": { "type": "string" },
                        "root_path": { "type": "string" }
                    },
                    "required": ["name", "root_path"],
                    "additionalProperties": false
                }
            }),
            json!({
                "name": "agent_bridge_accept",
                "description": "Accept a prepared bridge handoff and execute it locally through ZirOS.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "handoff_id": { "type": "string" }
                    },
                    "required": ["handoff_id"],
                    "additionalProperties": false
                }
            }),
        ]);
    }
    tools.extend(vec![
        json!({
            "name": "agent_worktrees_list",
            "description": "List daemon-managed worktrees for a session or for the whole local Brain.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
    ]);
    if matches!(exposure, McpExposureV1::LocalStdio | McpExposureV1::RemoteBridgeWrite) {
        tools.extend(vec![
            json!({
                "name": "agent_worktrees_create",
                "description": "Create a managed worktree for a stored ZirOS agent session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string" }
                    },
                    "required": ["session_id"],
                    "additionalProperties": false
                }
            }),
            json!({
                "name": "agent_worktrees_cleanup",
                "description": "Remove a daemon-managed worktree by id.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "worktree_id": { "type": "string" },
                        "remove_files": { "type": "boolean", "default": false }
                    },
                    "required": ["worktree_id"],
                    "additionalProperties": false
                }
            }),
        ]);
    }
    tools.extend(vec![
        json!({
            "name": "agent_checkpoints_list",
            "description": "List persisted checkpoints for a ZirOS agent session.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "required": ["session_id"],
                "additionalProperties": false
            }
        }),
    ]);
    if matches!(exposure, McpExposureV1::LocalStdio | McpExposureV1::RemoteBridgeWrite) {
        tools.extend(vec![
            json!({
                "name": "agent_checkpoints_create",
                "description": "Create a checkpoint for a stored ZirOS agent session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string" },
                        "label": { "type": "string" }
                    },
                    "required": ["session_id", "label"],
                    "additionalProperties": false
                }
            }),
            json!({
                "name": "agent_checkpoints_rollback",
                "description": "Rollback a stored ZirOS agent session to a checkpoint.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "checkpoint_id": { "type": "string" }
                    },
                    "required": ["checkpoint_id"],
                    "additionalProperties": false
                }
            }),
        ]);
    }
    tools.extend(vec![
        json!({
            "name": "agent_provider_status",
            "description": "Inspect local-first provider routing and any detected local model endpoints.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_provider_route",
            "description": "Resolve local-first provider routing, optionally forcing an explicit provider override.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "provider_override": { "type": "string" },
                    "model_override": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
        json!({
            "name": "agent_provider_test",
            "description": "Probe detected local-first providers and report endpoint readiness.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": { "type": "string" },
                    "provider_override": { "type": "string" },
                    "model_override": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
    ]);
    if matches!(exposure, McpExposureV1::LocalStdio | McpExposureV1::RemoteBridgeWrite) {
        tools.extend(vec![
            json!({
                "name": "agent_approve",
                "description": "Approve a pending wallet request through the ZirOS wallet policy core and optionally attach the receipt to an agent session.",
                "inputSchema": approval_schema("primary_prompt")
            }),
            json!({
                "name": "agent_reject",
                "description": "Reject a pending wallet request through the ZirOS wallet policy core and optionally attach the receipt to an agent session.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string" },
                        "wallet_network": { "type": "string", "default": "preprod" },
                        "pending_id": { "type": "string" },
                        "reason": { "type": "string" },
                        "persistent_root": { "type": "string" },
                        "cache_root": { "type": "string" }
                    },
                    "required": ["pending_id", "reason"],
                    "additionalProperties": false
                }
            }),
        ]);
    }
    tools
}

fn is_tool_allowed(name: &str, exposure: McpExposureV1) -> bool {
    match exposure {
        McpExposureV1::LocalStdio | McpExposureV1::RemoteBridgeWrite => true,
        McpExposureV1::RemoteBridgeReadOnly => matches!(
            name,
            "agent_status"
                | "agent_plan"
                | "agent_logs"
                | "agent_artifacts"
                | "agent_approvals"
                | "agent_deployments"
                | "agent_environments"
                | "agent_procedures"
                | "agent_incidents"
                | "agent_event_subscribe"
                | "agent_workflow_list"
                | "agent_workflow_show"
                | "agent_projects_list"
                | "agent_bridge_prepare"
                | "agent_bridge_handoffs"
                | "agent_worktrees_list"
                | "agent_checkpoints_list"
                | "agent_provider_status"
                | "agent_provider_route"
                | "agent_provider_test"
        ),
    }
}

fn goal_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "goal": { "type": "string" },
            "workflow_override": { "type": "string" },
            "strict": { "type": "boolean", "default": true },
            "compat_allowed": { "type": "boolean", "default": false },
            "use_worktree": { "type": "boolean", "default": true },
            "wallet_network": { "type": "string", "default": "preprod" },
            "project_root": { "type": "string" },
            "intent": {
                "type": "object",
                "properties": {
                    "summary": { "type": "string" },
                    "workflow_kind": { "type": "string" },
                    "scope": { "type": "string", "enum": ["host", "project", "release"] },
                    "requested_outputs": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "hints": {
                        "type": "object",
                        "properties": {
                            "require_wallet": { "type": "boolean" },
                            "require_metal": { "type": "boolean" },
                            "subsystem_style": { "type": "string" },
                            "midnight_template": { "type": "string" },
                            "app_template": { "type": "string" },
                            "benchmark_parallel": { "type": "boolean" },
                            "benchmark_distributed": { "type": "boolean" }
                        },
                        "additionalProperties": false
                    }
                },
                "required": ["summary", "workflow_kind", "scope"],
                "additionalProperties": false
            },
            "provider_override": { "type": "string" },
            "model_override": { "type": "string" }
        },
        "required": ["goal"],
        "additionalProperties": false
    })
}

fn approval_schema(prompt_field: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "session_id": { "type": "string" },
            "wallet_network": { "type": "string", "default": "preprod" },
            "pending_id": { "type": "string" },
            prompt_field: { "type": "string" },
            "secondary_prompt": { "type": "string" },
            "bridge_session_id": { "type": "string" },
            "persistent_root": { "type": "string" },
            "cache_root": { "type": "string" }
        },
        "required": ["pending_id", prompt_field],
        "additionalProperties": false
    })
}

fn read_message<R: BufRead>(reader: &mut R) -> Result<Option<JsonRpcRequest>, String> {
    let mut content_length = None;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).map_err(|error| error.to_string())?;
        if read == 0 {
            return Ok(None);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if let Some(value) = trimmed.strip_prefix("Content-Length:") {
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|error| error.to_string())?;
            content_length = Some(parsed);
        }
    }
    let length = content_length.ok_or_else(|| "missing Content-Length header".to_string())?;
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).map_err(|error| error.to_string())?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn write_message<W: Write>(writer: &mut W, response: &JsonRpcResponse) -> Result<(), String> {
    let body = serde_json::to_vec(response).map_err(|error| error.to_string())?;
    writer
        .write_all(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes())
        .map_err(|error| error.to_string())?;
    writer.write_all(&body).map_err(|error| error.to_string())?;
    writer.flush().map_err(|error| error.to_string())
}

fn error_response(id: Option<Value>, code: i64, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(JsonRpcError { code, message }),
    }
}

fn empty_notification() -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0",
        id: None,
        result: None,
        error: None,
    }
}

fn tool_ok(payload: Value) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
            }
        ],
        "isError": false
    })
}

fn tool_error(message: String) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": message
            }
        ],
        "isError": true
    })
}

fn read_run_options(arguments: &Value) -> Result<AgentRunOptionsV1, String> {
    Ok(AgentRunOptionsV1 {
        strict: arguments
            .get("strict")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        compat_allowed: arguments
            .get("compat_allowed")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        wallet_network: read_wallet_network(arguments)?,
        project_root: read_optional_path(arguments, "project_root"),
        use_worktree: arguments
            .get("use_worktree")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        workflow_override: read_optional_string(arguments, "workflow_override"),
        intent: read_optional_intent(arguments)?,
        provider_override: read_optional_string(arguments, "provider_override"),
        model_override: read_optional_string(arguments, "model_override"),
    })
}

fn read_optional_intent(arguments: &Value) -> Result<Option<GoalIntentV1>, String> {
    arguments
        .get("intent")
        .cloned()
        .map(|value| serde_json::from_value::<GoalIntentV1>(value))
        .transpose()
        .map_err(|error| error.to_string())
}

fn read_wallet_network(arguments: &Value) -> Result<WalletNetwork, String> {
    let value = arguments
        .get("wallet_network")
        .and_then(Value::as_str)
        .unwrap_or("preprod");
    WalletNetwork::parse(value).map_err(|error| error.to_string())
}

fn read_string(arguments: &Value, key: &str) -> Result<String, String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| format!("missing required argument '{key}'"))
}

fn read_optional_string(arguments: &Value, key: &str) -> Option<String> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn read_optional_path(arguments: &Value, key: &str) -> Option<PathBuf> {
    arguments
        .get(key)
        .and_then(Value::as_str)
        .map(PathBuf::from)
}

fn read_usize(arguments: &Value, key: &str, default: usize) -> Result<usize, String> {
    match arguments.get(key).and_then(Value::as_u64) {
        Some(value) => usize::try_from(value).map_err(|error| error.to_string()),
        None => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_request_returns_tool_capability() {
        let response = handle_mcp_request(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: "initialize".to_string(),
            params: json!({
                "protocolVersion": "2024-11-05"
            }),
        }, McpExposureV1::LocalStdio)
        .expect("initialize");
        let result = response.result.expect("result");
        assert_eq!(result["capabilities"]["tools"], json!({}));
    }

    #[test]
    fn tools_call_unknown_tool_returns_tool_error_result() {
        let response = handle_mcp_request(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(2)),
            method: "tools/call".to_string(),
            params: json!({
                "name": "nope",
                "arguments": {}
            }),
        }, McpExposureV1::LocalStdio)
        .expect("tool call");
        let result = response.result.expect("result");
        assert_eq!(result["isError"], json!(true));
    }

    #[test]
    fn remote_bridge_exposure_hides_mutating_tools() {
        let response = handle_mcp_request(JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(3)),
            method: "tools/list".to_string(),
            params: json!({}),
        }, McpExposureV1::RemoteBridgeReadOnly)
        .expect("tools/list");
        let result = response.result.expect("result");
        let tools = result["tools"].as_array().expect("tools array");
        let names = tools
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        assert!(names.contains(&"agent_bridge_prepare"));
        assert!(!names.contains(&"agent_run"));
        assert!(!names.contains(&"agent_approve"));
    }
}
