use crate::cli::{
    AgentApprovalCommands, AgentBridgeCommands, AgentBrowserCommands, AgentCheckpointCommands,
    AgentCommands, AgentHermesCommands, AgentMcpCommands, AgentMemoryCommands,
    AgentProjectCommands, AgentProviderCommands, AgentWebCommands, AgentWorkflowCommands,
    AgentWorktreeCommands,
};
use serde::Serialize;
use std::path::PathBuf;
use zkf_agent::{
    ActionReceiptV1, AgentApproveRequestV1, AgentBridgeHandoffAcceptRequestV1,
    AgentBridgeHandoffPrepareRequestV1, AgentBrowserEvalRequestV1, AgentBrowserKindV1,
    AgentBrowserOpenRequestV1, AgentCancelRequestV1, AgentCheckpointCreateRequestV1,
    AgentCheckpointRollbackRequestV1, AgentProjectRegisterRequestV1, AgentProviderRouteRequestV1,
    AgentProviderTestRequestV1, AgentRejectRequestV1, AgentRunOptionsV1, AgentWebFetchRequestV1,
    AgentWorktreeCleanupRequestV1, AgentWorktreeCreateRequestV1, accept_bridge_handoff,
    agent_status, approval_lineage, approve_request, bridge_status, browser_eval_report,
    browser_open_report, browser_status_report, cancel_session, cleanup_worktree,
    create_checkpoint, create_worktree, explain_session, hermes_diff, hermes_doctor,
    hermes_export_bootstrap, hermes_install, hermes_status, hermes_sync, list_bridge_handoffs,
    list_checkpoints, list_incidents, list_procedures, list_projects, list_worktrees,
    memory_sessions, plan_goal, prepare_bridge_handoff, provider_route, provider_status,
    provider_test, register_project, reject_request, resume_session_with_receipts,
    rollback_checkpoint, run_goal_with_receipts, serve_mcp_stdio, session_artifacts,
    session_deployments, session_environments, session_logs, web_fetch_report, workflow_list,
    workflow_show,
};
use zkf_command_surface::{CommandEventKindV1, CommandEventV1, JsonlEventSink, new_operation_id};
use zkf_wallet::WalletNetwork;

pub(crate) fn handle_agent(
    json_output: bool,
    events_jsonl: Option<PathBuf>,
    command: AgentCommands,
) -> Result<(), String> {
    let action_id = new_operation_id("agent");
    let mut sink = JsonlEventSink::open(events_jsonl)?;
    emit(
        &mut sink,
        CommandEventKindV1::Started,
        &action_id,
        "agent command started",
    )?;
    match command {
        AgentCommands::Doctor {
            goal,
            workflow,
            strict,
            allow_compat,
            project,
            no_worktree,
            provider,
            model,
        } => {
            let explain = plan_goal(
                goal.as_deref()
                    .unwrap_or("inspect current ZirOS host state"),
                AgentRunOptionsV1 {
                    strict,
                    compat_allowed: allow_compat,
                    project_root: project,
                    use_worktree: !no_worktree,
                    workflow_override: workflow,
                    provider_override: provider,
                    model_override: model,
                    ..AgentRunOptionsV1::default()
                },
            )?;
            print_output(json_output, &explain.trust_gate)?
        }
        AgentCommands::Status { limit } => print_output(json_output, &agent_status(limit)?)?,
        AgentCommands::Plan {
            goal,
            workflow,
            strict,
            allow_compat,
            project,
            no_worktree,
            provider,
            model,
        } => print_output(
            json_output,
            &plan_goal(
                &goal,
                AgentRunOptionsV1 {
                    strict,
                    compat_allowed: allow_compat,
                    project_root: project,
                    use_worktree: !no_worktree,
                    workflow_override: workflow,
                    provider_override: provider,
                    model_override: model,
                    ..AgentRunOptionsV1::default()
                },
            )?,
        )?,
        AgentCommands::Run {
            goal,
            workflow,
            strict,
            allow_compat,
            project,
            no_worktree,
            provider,
            model,
        } => print_output(
            json_output,
            &run_goal_with_receipts(
                &goal,
                AgentRunOptionsV1 {
                    strict,
                    compat_allowed: allow_compat,
                    project_root: project,
                    use_worktree: !no_worktree,
                    workflow_override: workflow,
                    provider_override: provider,
                    model_override: model,
                    ..AgentRunOptionsV1::default()
                },
                |receipt| {
                    let _ = emit_receipt_event(&mut sink, &action_id, receipt);
                },
            )?,
        )?,
        AgentCommands::Resume { session_id } => print_output(
            json_output,
            &resume_session_with_receipts(&session_id, |receipt| {
                let _ = emit_receipt_event(&mut sink, &action_id, receipt);
            })?,
        )?,
        AgentCommands::Explain { session_id } => {
            print_output(json_output, &explain_session(&session_id)?)?
        }
        AgentCommands::Cancel { session_id, reason } => print_output(
            json_output,
            &cancel_session(AgentCancelRequestV1 { session_id, reason })?,
        )?,
        AgentCommands::Logs { session_id } => {
            print_output(json_output, &session_logs(&session_id)?)?
        }
        AgentCommands::Approve {
            session_id,
            wallet_network,
            pending_id,
            primary_prompt,
            secondary_prompt,
            bridge_session_id,
            persistent_root,
            cache_root,
        } => {
            let wallet_network =
                WalletNetwork::parse(&wallet_network).map_err(|error| error.to_string())?;
            print_output(
                json_output,
                &approve_request(AgentApproveRequestV1 {
                    session_id,
                    wallet_network,
                    pending_id,
                    primary_prompt,
                    secondary_prompt,
                    bridge_session_id,
                    persistent_root,
                    cache_root,
                })?,
            )?
        }
        AgentCommands::Reject {
            session_id,
            wallet_network,
            pending_id,
            reason,
            persistent_root,
            cache_root,
        } => {
            let wallet_network =
                WalletNetwork::parse(&wallet_network).map_err(|error| error.to_string())?;
            reject_request(AgentRejectRequestV1 {
                session_id,
                wallet_network,
                pending_id,
                reason,
                persistent_root,
                cache_root,
            })?;
            print_output(json_output, &serde_json::json!({ "status": "ok" }))?
        }
        AgentCommands::Memory { command } => match command {
            AgentMemoryCommands::Sessions { limit } => {
                print_output(json_output, &memory_sessions(limit)?)?
            }
            AgentMemoryCommands::Receipts { session_id } => {
                print_output(json_output, &session_logs(&session_id)?)?
            }
            AgentMemoryCommands::Artifacts { session_id } => {
                print_output(json_output, &session_artifacts(session_id.as_deref())?)?
            }
            AgentMemoryCommands::Deployments { session_id } => {
                print_output(json_output, &session_deployments(session_id.as_deref())?)?
            }
            AgentMemoryCommands::Environments { session_id } => {
                print_output(json_output, &session_environments(session_id.as_deref())?)?
            }
            AgentMemoryCommands::Procedures => print_output(json_output, &list_procedures()?)?,
            AgentMemoryCommands::Incidents { session_id } => {
                print_output(json_output, &list_incidents(session_id.as_deref())?)?
            }
        },
        AgentCommands::Approvals { command } => match command {
            AgentApprovalCommands::List { session_id } => {
                print_output(json_output, &approval_lineage(session_id.as_deref())?)?
            }
        },
        AgentCommands::Project { command } => match command {
            AgentProjectCommands::Register { name, root } => print_output(
                json_output,
                &register_project(AgentProjectRegisterRequestV1 {
                    name,
                    root_path: root,
                })?,
            )?,
            AgentProjectCommands::List => print_output(json_output, &list_projects()?)?,
        },
        AgentCommands::Bridge { command } => match command {
            AgentBridgeCommands::Status => print_output(json_output, &bridge_status()?)?,
            AgentBridgeCommands::Prepare {
                goal,
                origin,
                workflow,
                strict,
                allow_compat,
                project,
                no_worktree,
                provider,
                model,
            } => print_output(
                json_output,
                &prepare_bridge_handoff(AgentBridgeHandoffPrepareRequestV1 {
                    origin,
                    goal,
                    options: AgentRunOptionsV1 {
                        strict,
                        compat_allowed: allow_compat,
                        project_root: project,
                        use_worktree: !no_worktree,
                        workflow_override: workflow,
                        provider_override: provider,
                        model_override: model,
                        ..AgentRunOptionsV1::default()
                    },
                })?,
            )?,
            AgentBridgeCommands::List => print_output(json_output, &list_bridge_handoffs()?)?,
            AgentBridgeCommands::Accept { handoff_id } => print_output(
                json_output,
                &accept_bridge_handoff(AgentBridgeHandoffAcceptRequestV1 { handoff_id })?,
            )?,
        },
        AgentCommands::Browser { command } => match command {
            AgentBrowserCommands::Status => print_output(json_output, &browser_status_report()?)?,
            AgentBrowserCommands::Open {
                url,
                browser,
                activate,
                new_window,
            } => print_output(
                json_output,
                &browser_open_report(AgentBrowserOpenRequestV1 {
                    url,
                    browser: parse_browser_kind(browser)?,
                    activate: Some(activate),
                    new_window: Some(new_window),
                })?,
            )?,
            AgentBrowserCommands::Eval {
                script,
                url,
                browser,
                activate,
                wait_millis,
            } => print_output(
                json_output,
                &browser_eval_report(AgentBrowserEvalRequestV1 {
                    script,
                    url,
                    browser: parse_browser_kind(browser)?,
                    activate: Some(activate),
                    wait_millis,
                })?,
            )?,
        },
        AgentCommands::Web { command } => match command {
            AgentWebCommands::Fetch { url, max_bytes } => print_output(
                json_output,
                &web_fetch_report(AgentWebFetchRequestV1 { url, max_bytes })?,
            )?,
        },
        AgentCommands::Workflow { command } => match command {
            AgentWorkflowCommands::List => print_output(json_output, &workflow_list()?)?,
            AgentWorkflowCommands::Show { workgraph_id } => {
                print_output(json_output, &workflow_show(&workgraph_id)?)?
            }
        },
        AgentCommands::Worktree { command } => match command {
            AgentWorktreeCommands::List { session_id } => {
                print_output(json_output, &list_worktrees(session_id.as_deref())?)?
            }
            AgentWorktreeCommands::Create { session_id } => print_output(
                json_output,
                &create_worktree(AgentWorktreeCreateRequestV1 { session_id })?,
            )?,
            AgentWorktreeCommands::Cleanup {
                worktree_id,
                remove_files,
            } => print_output(
                json_output,
                &cleanup_worktree(AgentWorktreeCleanupRequestV1 {
                    worktree_id,
                    remove_files,
                })?,
            )?,
        },
        AgentCommands::Checkpoint { command } => match command {
            AgentCheckpointCommands::List { session_id } => {
                print_output(json_output, &list_checkpoints(&session_id)?)?
            }
            AgentCheckpointCommands::Create { session_id, label } => print_output(
                json_output,
                &create_checkpoint(AgentCheckpointCreateRequestV1 { session_id, label })?,
            )?,
            AgentCheckpointCommands::Rollback { checkpoint_id } => print_output(
                json_output,
                &rollback_checkpoint(AgentCheckpointRollbackRequestV1 { checkpoint_id })?,
            )?,
        },
        AgentCommands::Provider { command } => match command {
            AgentProviderCommands::Status { session_id } => {
                print_output(json_output, &provider_status(session_id.as_deref())?)?
            }
            AgentProviderCommands::Route {
                session_id,
                provider,
                model,
            } => print_output(
                json_output,
                &provider_route(AgentProviderRouteRequestV1 {
                    session_id,
                    provider_override: provider,
                    model_override: model,
                })?,
            )?,
            AgentProviderCommands::Test {
                session_id,
                provider,
                model,
            } => print_output(
                json_output,
                &provider_test(AgentProviderTestRequestV1 {
                    session_id,
                    provider_override: provider,
                    model_override: model,
                })?,
            )?,
        },
        AgentCommands::Hermes { command } => match command {
            AgentHermesCommands::Status => print_output(json_output, &hermes_status()?)?,
            AgentHermesCommands::Diff => print_output(json_output, &hermes_diff()?)?,
            AgentHermesCommands::Install => print_output(json_output, &hermes_install()?)?,
            AgentHermesCommands::Sync => print_output(json_output, &hermes_sync()?)?,
            AgentHermesCommands::Doctor => print_output(json_output, &hermes_doctor()?)?,
            AgentHermesCommands::ExportBootstrap => {
                print_output(json_output, &hermes_export_bootstrap()?)?
            }
        },
        AgentCommands::Mcp { command } => match command {
            AgentMcpCommands::Serve => serve_mcp_stdio()?,
        },
    }
    emit(
        &mut sink,
        CommandEventKindV1::Completed,
        &action_id,
        "agent command completed",
    )
}

fn emit(
    sink: &mut Option<JsonlEventSink>,
    kind: CommandEventKindV1,
    action_id: &str,
    message: &str,
) -> Result<(), String> {
    if let Some(sink) = sink.as_mut() {
        sink.emit(&CommandEventV1::new(action_id, kind, message))?;
    }
    Ok(())
}

fn emit_receipt_event(
    sink: &mut Option<JsonlEventSink>,
    action_id: &str,
    receipt: &ActionReceiptV1,
) -> Result<(), String> {
    let kind = match receipt.status.as_str() {
        "started" => CommandEventKindV1::Started,
        "completed" | "approved" | "ready" | "planned" => CommandEventKindV1::Completed,
        "failed" | "blocked" | "cancelled" | "rejected" => CommandEventKindV1::Failed,
        _ => CommandEventKindV1::Progress,
    };
    let mut event = CommandEventV1::new(
        action_id,
        kind,
        format!("{} {}", receipt.action_name, receipt.status),
    );
    event.session_id = Some(receipt.session_id.clone());
    event.stage = Some(receipt.action_name.clone());
    event.metrics = Some(receipt.payload.clone());
    emit_raw(sink, &event)
}

fn emit_raw(sink: &mut Option<JsonlEventSink>, event: &CommandEventV1) -> Result<(), String> {
    if let Some(sink) = sink.as_mut() {
        sink.emit(event)?;
    }
    Ok(())
}

fn print_output<T: Serialize>(json_output: bool, value: &T) -> Result<(), String> {
    let rendered = serde_json::to_value(value).map_err(|error| error.to_string())?;
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&rendered).map_err(|error| error.to_string())?
        );
    } else {
        println!("{}", human_render(&rendered));
    }
    Ok(())
}

fn human_render(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(schema) = map.get("schema").and_then(serde_json::Value::as_str) {
                let mut lines = vec![format!("schema: {schema}")];
                for key in [
                    "generated_at",
                    "operation_id",
                    "session_id",
                    "session_status",
                    "workflow_kind",
                    "status",
                    "healthy",
                    "socket_path",
                    "socket_present",
                    "pack_root",
                    "lock_path",
                    "contract_path",
                    "manifest_path",
                    "config_path",
                    "install_complete",
                    "doctor_ok",
                    "repair_command",
                    "policy_path",
                    "bridge_present",
                    "bridge_remote_health",
                    "bridge_local_gateway_health",
                    "bridge_gateway_configured",
                    "bridge_gateway_running",
                    "bridge_tunnel_running",
                    "bridge_model_label",
                    "bridge_exposure",
                    "bridge_auth_mode",
                    "primary_intelligence_lane",
                    "fallback_policy",
                    "platform",
                    "supported",
                    "preferred_automation_browser",
                    "browser",
                    "request_url",
                    "final_url",
                    "host",
                    "policy_scope",
                    "status_code",
                    "status_text",
                    "redirected",
                    "content_type",
                    "canonical_url",
                    "title",
                    "requested_url",
                    "ok",
                    "activated",
                    "new_window",
                    "current_url",
                    "raw_result",
                ] {
                    if let Some(value) = map.get(key) {
                        lines.push(format!("{key}: {}", scalar_or_json(value)));
                    }
                }
                for key in [
                    "sessions",
                    "projects",
                    "receipts",
                    "artifacts",
                    "workflows",
                    "deployments",
                    "environments",
                    "procedures",
                    "incidents",
                    "approval_requests",
                    "approval_tokens",
                    "submission_grants",
                    "worktrees",
                    "checkpoints",
                    "routes",
                    "probes",
                    "assets",
                    "violations",
                    "missing_assets",
                    "changed_assets",
                    "config_issues",
                    "lock_issues",
                    "skills_written",
                    "assets_written",
                    "same_host_links",
                    "notes",
                ] {
                    if let Some(value) = map.get(key).and_then(serde_json::Value::as_array) {
                        lines.push(format!("{key}: {} item(s)", value.len()));
                    }
                }
                if let Some(workgraph) = map.get("workgraph") {
                    lines.push(format!("workgraph: {}", scalar_or_json(workgraph)));
                }
                if let Some(prereqs) = map
                    .get("prerequisites")
                    .or_else(|| map.get("blocked_prerequisites"))
                    .and_then(serde_json::Value::as_array)
                    && !prereqs.is_empty()
                {
                    lines.push("prerequisites:".to_string());
                    for item in prereqs {
                        lines.push(format!("- {}", scalar_or_json(item)));
                    }
                }
                lines.join("\n")
            } else {
                serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
            }
        }
        _ => serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string()),
    }
}

fn scalar_or_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "null".to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::String(value) => value.clone(),
        _ => serde_json::to_string(value).unwrap_or_else(|_| value.to_string()),
    }
}

fn parse_browser_kind(value: Option<String>) -> Result<Option<AgentBrowserKindV1>, String> {
    value
        .map(|browser| match browser.as_str() {
            "default" => Ok(AgentBrowserKindV1::Default),
            "safari" => Ok(AgentBrowserKindV1::Safari),
            "chrome" => Ok(AgentBrowserKindV1::Chrome),
            other => Err(format!(
                "invalid browser '{}' ; expected one of: default, safari, chrome",
                other
            )),
        })
        .transpose()
}
