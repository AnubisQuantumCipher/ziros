use crate::brain::BrainStore;
use crate::checkpoint::create_checkpoint_record;
use crate::types::{
    ActionReceiptV1, AgentRunOptionsV1, AgentSessionViewV1, ApprovalRequestRecordV1,
    IncidentRecordV1, IntentHintsV1, ProcedureRecordV1, SubmissionGrantRecordV1,
    WorkgraphNodeV1, WorkgraphV1,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use zkf_command_surface::app::scaffold as scaffold_app;
use zkf_command_surface::cluster::status as cluster_status;
use zkf_command_surface::evm::diagnose as evm_diagnose;
use zkf_command_surface::midnight::{
    MidnightNetworkV1, compile_contract, deploy_prepare, status as midnight_status,
};
use zkf_command_surface::release::evidence_bundle;
use zkf_command_surface::runtime::benchmark as runtime_benchmark;
use zkf_command_surface::shell::{read_json_file, run_zkf_cli, workspace_root};
use zkf_command_surface::subsystem::{
    bundle_public as bundle_subsystem_public, evm_export as export_subsystem_evm,
    prove as prove_subsystem_bundle, scaffold as scaffold_subsystem_bundle,
    validate as validate_subsystem_bundle, verify as verify_subsystem_bundle,
    verify_completeness as verify_subsystem_completeness,
    verify_release_pin as verify_subsystem_release_pin,
};
use zkf_command_surface::swarm::status as swarm_status;
use zkf_command_surface::truth::collect_truth_snapshot;
use zkf_command_surface::wallet::{
    WalletContextV1, issue_bridge_grant, issue_native_grant, snapshot as wallet_snapshot,
    sync_health,
};
use zkf_command_surface::{
    ActionDescriptorV1, ActionResultEnvelopeV1, ArtifactRefV1, CommandErrorClassV1,
    MetricRecordV1, RiskClassV1,
};
use zkf_wallet::WalletNetwork;

pub fn execute_workgraph<F>(
    brain: &BrainStore,
    session: &mut AgentSessionViewV1,
    workgraph: &mut WorkgraphV1,
    options: &AgentRunOptionsV1,
    mut on_receipt: F,
) -> Result<Vec<ActionReceiptV1>, String>
where
    F: FnMut(&ActionReceiptV1),
{
    let mut emitted = Vec::new();
    if workgraph.status == "blocked" || session.status.as_str() == "blocked" {
        return Ok(emitted);
    }

    loop {
        let mut progressed = false;
        let mut pending_exists = false;

        for index in 0..workgraph.nodes.len() {
            if workgraph.nodes[index].status != "pending" {
                continue;
            }
            let node = workgraph.nodes[index].clone();
            pending_exists = true;
            if !dependencies_completed(workgraph, &node) {
                continue;
            }
            progressed = true;

            if node.approval_required {
                workgraph.nodes[index].status = "blocked".to_string();
                workgraph.status = "blocked".to_string();
                brain.update_workgraph(workgraph)?;
                brain.update_session_status(
                    &session.session_id,
                    crate::types::SessionStatusV1::Blocked,
                )?;
                session.status = crate::types::SessionStatusV1::Blocked;
                brain.store_approval_request(&ApprovalRequestRecordV1 {
                    schema: "ziros-agent-approval-request-v1".to_string(),
                    approval_request_id: zkf_command_surface::new_operation_id("approval-request"),
                    session_id: Some(session.session_id.clone()),
                    created_at: zkf_command_surface::now_rfc3339(),
                    pending_id: node.node_id.clone(),
                    risk_class: node.risk_class,
                    action_name: node.action_name.clone(),
                    node_id: Some(node.node_id.clone()),
                    wallet_pending_id: None,
                })?;
                emit_receipt(
                    brain,
                    receipt_with_payload(
                        &session.session_id,
                        descriptor_for(&node),
                        "blocked",
                        json!({
                            "node_id": node.node_id,
                            "label": node.label,
                            "reason": "approval required before execution can continue",
                        }),
                    )
                    .with_error_class(CommandErrorClassV1::ApprovalRequired),
                    &mut emitted,
                    &mut on_receipt,
                )?;
                let checkpoint = create_checkpoint_record(
                    brain,
                    session,
                    workgraph,
                    "approval-blocked",
                    emitted.last().map(|receipt| receipt.receipt_id.clone()),
                )?;
                let _ = brain.store_checkpoint(&checkpoint)?;
                return Ok(emitted);
            }

            workgraph.nodes[index].status = "running".to_string();
            brain.update_workgraph(workgraph)?;
            emit_receipt(
                brain,
                receipt_with_payload(
                    &session.session_id,
                    descriptor_for(&node),
                    "started",
                    json!({
                        "node_id": node.node_id,
                        "label": node.label,
                    }),
                ),
                &mut emitted,
                &mut on_receipt,
            )?;

            match execute_node_action(brain, session, workgraph, &node, options) {
                Ok(envelope) => {
                    workgraph.nodes[index].status = "completed".to_string();
                    brain.update_workgraph(workgraph)?;
                    for artifact in &envelope.artifacts {
                        let _ = brain.register_artifact(Some(&session.session_id), artifact.clone())?;
                    }
                    if node.action_name == "midnight.contract.deploy-prepare" {
                        let _ = brain.store_deployment(&crate::types::DeploymentRecordV1 {
                            schema: "ziros-agent-deployment-v1".to_string(),
                            deployment_id: zkf_command_surface::new_operation_id("deployment"),
                            session_id: Some(session.session_id.clone()),
                            created_at: zkf_command_surface::now_rfc3339(),
                            workflow_kind: workgraph.workflow_kind.clone(),
                            summary: envelope.payload.clone().unwrap_or_else(|| json!({})),
                        })?;
                    }
                    emit_receipt(
                        brain,
                        receipt_from_envelope(&session.session_id, &envelope),
                        &mut emitted,
                        &mut on_receipt,
                    )?;
                    let checkpoint = create_checkpoint_record(
                        brain,
                        session,
                        workgraph,
                        &format!("completed:{}", node.action_name),
                        emitted.last().map(|receipt| receipt.receipt_id.clone()),
                    )?;
                    let _ = brain.store_checkpoint(&checkpoint)?;
                }
                Err(error) => {
                    workgraph.nodes[index].status = "failed".to_string();
                    workgraph.status = "blocked".to_string();
                    brain.update_workgraph(workgraph)?;
                    brain.update_session_status(
                        &session.session_id,
                        crate::types::SessionStatusV1::Blocked,
                    )?;
                    session.status = crate::types::SessionStatusV1::Blocked;
                    let error_class = classify_error(&node.action_name, &error);
                    brain.store_incident(&IncidentRecordV1 {
                        schema: "ziros-agent-incident-v1".to_string(),
                        incident_id: zkf_command_surface::new_operation_id("incident"),
                        created_at: zkf_command_surface::now_rfc3339(),
                        session_id: Some(session.session_id.clone()),
                        action_name: node.action_name.clone(),
                        error_class,
                        summary: format!("{} failed", node.label),
                        details: json!({
                            "node_id": node.node_id,
                            "label": node.label,
                            "error": error,
                        }),
                    })?;
                    emit_receipt(
                        brain,
                        receipt_with_payload(
                            &session.session_id,
                            descriptor_for(&node),
                            "failed",
                            json!({
                                "node_id": node.node_id,
                                "label": node.label,
                                "error": error,
                            }),
                        )
                        .with_error_class(error_class),
                        &mut emitted,
                        &mut on_receipt,
                    )?;
                    let checkpoint = create_checkpoint_record(
                        brain,
                        session,
                        workgraph,
                        &format!("failed:{}", node.action_name),
                        emitted.last().map(|receipt| receipt.receipt_id.clone()),
                    )?;
                    let _ = brain.store_checkpoint(&checkpoint)?;
                    return Ok(emitted);
                }
            }
        }

        if !pending_exists {
            workgraph.status = "completed".to_string();
            brain.update_workgraph(workgraph)?;
            brain.update_session_status(
                &session.session_id,
                crate::types::SessionStatusV1::Completed,
            )?;
            session.status = crate::types::SessionStatusV1::Completed;
            let _ = brain.store_procedure(&ProcedureRecordV1 {
                schema: "ziros-agent-procedure-v1".to_string(),
                procedure_id: zkf_command_surface::new_operation_id("procedure"),
                created_at: zkf_command_surface::now_rfc3339(),
                workflow_kind: workgraph.workflow_kind.clone(),
                summary: workgraph.intent.summary.clone(),
                action_names: workgraph
                    .nodes
                    .iter()
                    .map(|node| node.action_name.clone())
                    .collect(),
            })?;
            return Ok(emitted);
        }

        if !progressed {
            workgraph.status = "blocked".to_string();
            brain.update_workgraph(workgraph)?;
            brain.update_session_status(
                &session.session_id,
                crate::types::SessionStatusV1::Blocked,
            )?;
            session.status = crate::types::SessionStatusV1::Blocked;
            emit_receipt(
                brain,
                receipt_with_payload(
                    &session.session_id,
                    ActionDescriptorV1 {
                        name: "scheduler".to_string(),
                        family: "scheduler".to_string(),
                        risk_class: RiskClassV1::ReadOnly,
                        expected_artifacts: Vec::new(),
                    },
                    "blocked",
                    json!({
                        "reason": "no runnable nodes remained; inspect dependency or approval state",
                    }),
                )
                .with_error_class(CommandErrorClassV1::DependencyBlocked),
                &mut emitted,
                &mut on_receipt,
            )?;
            let checkpoint = create_checkpoint_record(
                brain,
                session,
                workgraph,
                "dependency-blocked",
                emitted.last().map(|receipt| receipt.receipt_id.clone()),
            )?;
            let _ = brain.store_checkpoint(&checkpoint)?;
            return Ok(emitted);
        }
    }
}

fn emit_receipt<F>(
    brain: &BrainStore,
    receipt: ActionReceiptV1,
    emitted: &mut Vec<ActionReceiptV1>,
    on_receipt: &mut F,
) -> Result<(), String>
where
    F: FnMut(&ActionReceiptV1),
{
    let receipt = brain.append_receipt(&receipt)?;
    on_receipt(&receipt);
    emitted.push(receipt);
    Ok(())
}

fn dependencies_completed(workgraph: &WorkgraphV1, node: &WorkgraphNodeV1) -> bool {
    node.depends_on.iter().all(|dependency| {
        workgraph
            .nodes
            .iter()
            .find(|candidate| &candidate.node_id == dependency)
            .is_some_and(|candidate| candidate.status == "completed")
    })
}

fn execute_node_action(
    brain: &BrainStore,
    session: &AgentSessionViewV1,
    workgraph: &WorkgraphV1,
    node: &WorkgraphNodeV1,
    options: &AgentRunOptionsV1,
) -> Result<ActionResultEnvelopeV1, String> {
    let descriptor = descriptor_for(node);
    let payload = match descriptor.name.as_str() {
        "truth.inspect" => serde_json::to_value(collect_truth_snapshot()?)
            .map_err(|error| error.to_string())?,
        "truth.capabilities" => collect_truth_snapshot()?.capabilities,
        "truth.metal" => collect_truth_snapshot()?.metal,
        "wallet.snapshot" => execute_wallet_snapshot(options)?,
        "wallet.submission-grant.issue" => execute_wallet_submission_grant(brain, session)?,
        "subsystem.scaffold" => execute_subsystem_scaffold(session, workgraph)?,
        "subsystem.prove" => execute_subsystem_prove(session)?,
        "subsystem.verify" => execute_subsystem_verify(session)?,
        "subsystem.bundle-public" => execute_subsystem_bundle_public(session)?,
        "subsystem.validate" => execute_subsystem_validate(session)?,
        "subsystem.evm-export" => execute_subsystem_evm_export(session)?,
        "subsystem.verify-completeness" => execute_subsystem_verify_completeness(session)?,
        "subsystem.verify-release-pin" => execute_subsystem_verify_release_pin(session)?,
        "midnight.status" => serde_json::to_value(midnight_status(
            wallet_network_to_midnight_network(options.wallet_network),
            session.project_root.as_deref().map(Path::new),
            None,
            None,
        )?)
        .map_err(|error| error.to_string())?,
        "midnight.project.scaffold" => execute_midnight_scaffold(session, workgraph, options)?,
        "midnight.contract.compile" => execute_midnight_compile(brain, session, options)?,
        "midnight.contract.deploy-prepare" => {
            execute_midnight_deploy_prepare(brain, session, options)?
        }
        "runtime.benchmark" => execute_runtime_benchmark(brain, session, workgraph)?,
        "app.scaffold" => execute_app_scaffold(session, workgraph)?,
        "proof.compile-prove-verify" => execute_proof_workflow(brain, session)?,
        "release.evidence-bundle" => execute_evidence_bundle(brain, session)?,
        "evm.diagnose" => serde_json::to_value(evm_diagnose(
            session.project_root.as_deref().map(Path::new),
            workspace_root(),
        )?)
        .map_err(|error| error.to_string())?,
        "swarm.status" => serde_json::to_value(swarm_status()?).map_err(|error| error.to_string())?,
        "cluster.status" => serde_json::to_value(cluster_status()?).map_err(|error| error.to_string())?,
        "agent.plan" => json!({
            "goal": workgraph.goal,
            "workflow_kind": workgraph.workflow_kind,
            "message": "generic plan retained for operator review",
        }),
        other => return Err(format!("no ZirOS agent executor is registered for action '{other}'")),
    };

    let mut envelope = ActionResultEnvelopeV1::success(
        zkf_command_surface::new_operation_id("action"),
        descriptor,
        Some(payload.clone()),
    );
    envelope.status = "completed".to_string();
    envelope.artifacts = extract_artifacts(&payload);
    envelope.metrics = extract_metrics(&payload);
    Ok(envelope)
}

fn execute_wallet_snapshot(options: &AgentRunOptionsV1) -> Result<Value, String> {
    let mut wallet = WalletContextV1 {
        network: Some(options.wallet_network),
        ..WalletContextV1::default()
    }
    .open_handle()?;
    let snapshot = wallet_snapshot(&mut wallet)?;
    let health = sync_health(&mut wallet).ok();
    Ok(json!({
        "snapshot": snapshot,
        "sync_health": health,
    }))
}

fn execute_wallet_submission_grant(
    brain: &BrainStore,
    session: &AgentSessionViewV1,
) -> Result<Value, String> {
    let token_record = brain
        .list_approval_tokens(Some(&session.session_id))?
        .into_iter()
        .last()
        .ok_or_else(|| format!("session '{}' has no stored approval token", session.session_id))?;
    let mut wallet = WalletContextV1 {
        network: Some(token_record.token.network),
        ..WalletContextV1::default()
    }
    .open_handle()?;
    let grant = if token_record.token.origin == "native://wallet" {
        issue_native_grant(
            &mut wallet,
            token_record.token.method,
            &token_record.token.tx_digest,
            &token_record.token,
        )?
    } else {
        let bridge_session_id = token_record
            .bridge_session_id
            .as_deref()
            .ok_or_else(|| {
                format!(
                    "approval token '{}' requires --bridge-session-id to issue a bridge submission grant",
                    token_record.token.token_id
                )
            })?;
        issue_bridge_grant(
            &mut wallet,
            bridge_session_id,
            token_record.token.method,
            &token_record.token.tx_digest,
            &token_record.token,
        )?
    };
    let record = SubmissionGrantRecordV1 {
        schema: "ziros-agent-submission-grant-v1".to_string(),
        grant_id: grant.grant_id.clone(),
        session_id: Some(session.session_id.clone()),
        created_at: zkf_command_surface::now_rfc3339(),
        approval_request_id: token_record.approval_request_id.clone(),
        token_id: Some(token_record.token.token_id.clone()),
        summary: serde_json::to_value(&grant).map_err(|error| error.to_string())?,
    };
    brain.store_submission_grant(&record)?;
    serde_json::to_value(&record).map_err(|error| error.to_string())
}

fn execute_subsystem_scaffold(
    session: &AgentSessionViewV1,
    workgraph: &WorkgraphV1,
) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    let manifest_path = project_root.join("02_manifest/subsystem_manifest.json");
    if manifest_path.exists() {
        return Ok(json!({
            "project_root": project_root.display().to_string(),
            "manifest_path": manifest_path.display().to_string(),
            "status": "existing-subsystem",
        }));
    }
    let style = intent_hints(workgraph)
        .and_then(|hints| hints.subsystem_style.as_deref())
        .unwrap_or_else(|| infer_subsystem_style(&workgraph.goal));
    let name = project_root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("ziros-subsystem-agent");
    let report = scaffold_subsystem_bundle(name, style, Some(&project_root), workspace_root())?;
    serde_json::to_value(report).map_err(|error| error.to_string())
}

fn execute_subsystem_verify_completeness(session: &AgentSessionViewV1) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    verify_subsystem_completeness(&project_root, workspace_root())
}

fn execute_subsystem_validate(session: &AgentSessionViewV1) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    validate_subsystem_bundle(&project_root, workspace_root())
}

fn execute_subsystem_prove(session: &AgentSessionViewV1) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    prove_subsystem_bundle(&project_root, workspace_root())
}

fn execute_subsystem_verify(session: &AgentSessionViewV1) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    verify_subsystem_bundle(&project_root, workspace_root())
}

fn execute_subsystem_bundle_public(session: &AgentSessionViewV1) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    bundle_subsystem_public(&project_root, workspace_root())
}

fn execute_subsystem_evm_export(session: &AgentSessionViewV1) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    export_subsystem_evm(&project_root, "ethereum", None, workspace_root())
}

fn execute_subsystem_verify_release_pin(session: &AgentSessionViewV1) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    let pin = project_root.join("20_release/zkf-release-pin.json");
    let binary = zkf_command_surface::shell::resolve_zkf_cli_binary()?;
    verify_subsystem_release_pin(&pin, &binary, workspace_root())
}

fn execute_midnight_scaffold(
    session: &AgentSessionViewV1,
    workgraph: &WorkgraphV1,
    options: &AgentRunOptionsV1,
) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    if resolve_compact_contract(&project_root)?.is_some() {
        return Ok(json!({
            "project_root": project_root.display().to_string(),
            "status": "existing-project",
        }));
    }

    let template = intent_hints(workgraph)
        .and_then(|hints| hints.midnight_template.as_deref())
        .unwrap_or_else(|| infer_midnight_template(&workgraph.goal));
    let name = project_root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("ziros-midnight-agent");
    let args = vec![
        "midnight".to_string(),
        "init".to_string(),
        "--name".to_string(),
        name.to_string(),
        "--template".to_string(),
        template.to_string(),
        "--out".to_string(),
        project_root.display().to_string(),
        "--network".to_string(),
        wallet_network_to_midnight_network(options.wallet_network)
            .as_str()
            .to_string(),
    ];
    let result = run_zkf_cli(&args, workspace_root())?;
    Ok(json!({
        "project_root": project_root.display().to_string(),
        "template": template,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }))
}

fn execute_midnight_compile(
    brain: &BrainStore,
    session: &AgentSessionViewV1,
    options: &AgentRunOptionsV1,
) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    let source = resolve_compact_contract(&project_root)?
        .ok_or_else(|| format!("no Compact contract was found under {}", project_root.display()))?;
    let out_dir = node_artifact_dir(brain, &session.session_id, "midnight-compile")?;
    let report = compile_contract(
        wallet_network_to_midnight_network(options.wallet_network),
        &source,
        &out_dir,
    )?;
    serde_json::to_value(report).map_err(|error| error.to_string())
}

fn execute_midnight_deploy_prepare(
    brain: &BrainStore,
    session: &AgentSessionViewV1,
    options: &AgentRunOptionsV1,
) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    let source = resolve_compact_contract(&project_root)?
        .ok_or_else(|| format!("no Compact contract was found under {}", project_root.display()))?;
    let out_dir = node_artifact_dir(brain, &session.session_id, "midnight-deploy-prepare")?;
    let out_path = out_dir.join("deploy-prepare.json");
    let report = deploy_prepare(
        wallet_network_to_midnight_network(options.wallet_network),
        &source,
        &out_path,
        None,
        None,
        Some(&project_root),
    )?;
    serde_json::to_value(report).map_err(|error| error.to_string())
}

fn execute_runtime_benchmark(
    brain: &BrainStore,
    session: &AgentSessionViewV1,
    workgraph: &WorkgraphV1,
) -> Result<Value, String> {
    let out_dir = node_artifact_dir(brain, &session.session_id, "runtime-benchmark")?;
    let out_path = out_dir.join("benchmark-report.json");
    let report = runtime_benchmark(
        &out_path,
        workspace_root(),
        benchmark_parallel(workgraph),
        benchmark_distributed(workgraph),
    )?;
    Ok(json!({
        "report": report.report,
        "stdout": report.stdout,
        "stderr": report.stderr,
        "out_path": report.out_path,
    }))
}

fn execute_app_scaffold(
    session: &AgentSessionViewV1,
    workgraph: &WorkgraphV1,
) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    let spec_path = project_root.join("zirapp.json");
    if spec_path.exists() {
        return Ok(json!({
            "project_root": project_root.display().to_string(),
            "spec_path": spec_path.display().to_string(),
            "status": "existing-project",
        }));
    }
    if project_root.exists()
        && fs::read_dir(&project_root)
            .map_err(|error| error.to_string())?
            .next()
            .is_some()
    {
        return Err(format!(
            "refusing to scaffold into non-empty directory '{}'",
            project_root.display()
        ));
    }
    let template = intent_hints(workgraph)
        .and_then(|hints| hints.app_template.as_deref())
        .unwrap_or_else(|| infer_app_template(&workgraph.goal));
    let name = project_root
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("ziros-proof-agent");
    let result = scaffold_app(template, name, &project_root, workspace_root())?;
    Ok(json!({
        "project_root": project_root.display().to_string(),
        "spec_path": spec_path.display().to_string(),
        "template": result.template,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }))
}

fn execute_proof_workflow(brain: &BrainStore, session: &AgentSessionViewV1) -> Result<Value, String> {
    let project_root = required_project_root(session)?;
    let spec_path = project_root.join("zirapp.json");
    let inputs_path = project_root.join("inputs.compliant.json");
    if !spec_path.exists() {
        return Err(format!("missing proof-app spec at {}", spec_path.display()));
    }
    if !inputs_path.exists() {
        return Err(format!("missing proof inputs at {}", inputs_path.display()));
    }
    let backend = infer_zirapp_backend(&spec_path)?;
    let out_dir = node_artifact_dir(brain, &session.session_id, "proof-workflow")?;
    let proof_path = out_dir.join("proof.json");
    let compiled_path = out_dir.join("compiled.json");

    let mut prove_args = vec![
        "prove".to_string(),
        "--program".to_string(),
        spec_path.display().to_string(),
        "--inputs".to_string(),
        inputs_path.display().to_string(),
        "--backend".to_string(),
        backend.clone(),
        "--out".to_string(),
        proof_path.display().to_string(),
        "--compiled-out".to_string(),
        compiled_path.display().to_string(),
    ];
    if backend == "arkworks-groth16" {
        prove_args.push("--allow-dev-deterministic-groth16".to_string());
    }
    let prove_result = run_zkf_cli(&prove_args, &project_root)?;

    let verify_args = vec![
        "verify".to_string(),
        "--program".to_string(),
        spec_path.display().to_string(),
        "--artifact".to_string(),
        proof_path.display().to_string(),
        "--backend".to_string(),
        backend.clone(),
        "--compiled".to_string(),
        compiled_path.display().to_string(),
    ];
    let verify_result = run_zkf_cli(&verify_args, &project_root)?;

    Ok(json!({
        "backend": backend,
        "project_root": project_root.display().to_string(),
        "spec_path": spec_path.display().to_string(),
        "inputs_path": inputs_path.display().to_string(),
        "proof_path": proof_path.display().to_string(),
        "compiled_path": compiled_path.display().to_string(),
        "prove_stdout": prove_result.stdout,
        "prove_stderr": prove_result.stderr,
        "verify_stdout": verify_result.stdout,
        "verify_stderr": verify_result.stderr,
    }))
}

fn execute_evidence_bundle(
    brain: &BrainStore,
    session: &AgentSessionViewV1,
) -> Result<Value, String> {
    let artifacts = brain.list_artifacts(Some(&session.session_id))?;
    let bundle = evidence_bundle(
        &session.session_id,
        &artifacts
            .iter()
            .map(|record| PathBuf::from(&record.artifact.path))
            .collect::<Vec<_>>(),
    );
    serde_json::to_value(bundle).map_err(|error| error.to_string())
}

fn required_project_root(session: &AgentSessionViewV1) -> Result<PathBuf, String> {
    session
        .project_root
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| format!("session '{}' has no project root", session.session_id))
}

fn node_artifact_dir(
    brain: &BrainStore,
    session_id: &str,
    label: &str,
) -> Result<PathBuf, String> {
    let path = brain.cache_root().join("runs").join(session_id).join(label);
    fs::create_dir_all(&path)
        .map_err(|error| format!("failed to create {}: {error}", path.display()))?;
    Ok(path)
}

fn resolve_compact_contract(project_root: &Path) -> Result<Option<PathBuf>, String> {
    if project_root.is_file() {
        return Ok(project_root
            .extension()
            .is_some_and(|extension| extension == "compact")
            .then(|| project_root.to_path_buf()));
    }

    for contracts_dir in [
        project_root.join("contracts").join("compact"),
        project_root.join("16_compact"),
    ] {
        if !contracts_dir.exists() {
            continue;
        }
        let mut contracts = fs::read_dir(&contracts_dir)
            .map_err(|error| format!("{}: {error}", contracts_dir.display()))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "compact"))
            .collect::<Vec<_>>();
        contracts.sort();
        if let Some(contract) = contracts.into_iter().next() {
            return Ok(Some(contract));
        }
    }
    Ok(None)
}

fn infer_midnight_template(goal: &str) -> &'static str {
    let lower = goal.to_ascii_lowercase();
    if lower.contains("treasury") {
        "cooperative-treasury"
    } else if lower.contains("vote") {
        "private-voting"
    } else if lower.contains("credential") || lower.contains("identity") {
        "credential-verification"
    } else if lower.contains("auction") {
        "private-auction"
    } else if lower.contains("supply") || lower.contains("provenance") {
        "supply-chain-provenance"
    } else {
        "token-transfer"
    }
}

fn intent_hints(workgraph: &WorkgraphV1) -> Option<&IntentHintsV1> {
    workgraph.intent.hints.as_ref()
}

fn infer_subsystem_style(goal: &str) -> &'static str {
    let lower = goal.to_ascii_lowercase();
    if lower.contains("dapp") || lower.contains("frontend") {
        "dapp"
    } else if lower.contains("rust only") || lower.contains("library") {
        "rust"
    } else {
        "full"
    }
}

fn infer_app_template(goal: &str) -> &'static str {
    let lower = goal.to_ascii_lowercase();
    if lower.contains("merkle") {
        "merkle-membership"
    } else if lower.contains("vote") {
        "private-vote"
    } else if lower.contains("identity") || lower.contains("credential") {
        "private-identity"
    } else {
        "range-proof"
    }
}

fn benchmark_parallel(workgraph: &WorkgraphV1) -> bool {
    intent_hints(workgraph)
        .and_then(|hints| hints.benchmark_parallel)
        .unwrap_or_else(|| workgraph.goal.to_ascii_lowercase().contains("parallel"))
}

fn benchmark_distributed(workgraph: &WorkgraphV1) -> bool {
    intent_hints(workgraph)
        .and_then(|hints| hints.benchmark_distributed)
        .unwrap_or_else(|| workgraph.goal.to_ascii_lowercase().contains("distributed"))
}

fn infer_zirapp_backend(spec_path: &Path) -> Result<String, String> {
    let payload = read_json_file(spec_path)?;
    let field = payload
        .get("program")
        .and_then(|program| program.get("field"))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{} is missing program.field", spec_path.display()))?;
    let backend = match field {
        "bn254" | "Bn254" => "arkworks-groth16",
        "goldilocks" | "Goldilocks" | "baby-bear" | "BabyBear" | "mersenne31" | "Mersenne31" => {
            "plonky3"
        }
        "pasta-fp" | "PastaFp" | "pasta-fq" | "PastaFq" => "halo2",
        "bls12-381" | "Bls12_381" | "Bls12-381" => "halo2-bls12381",
        other => {
            return Err(format!(
                "unsupported app-spec field '{other}' in {}",
                spec_path.display()
            ));
        }
    };
    Ok(backend.to_string())
}

fn wallet_network_to_midnight_network(network: WalletNetwork) -> MidnightNetworkV1 {
    match network {
        WalletNetwork::Preprod => MidnightNetworkV1::Preprod,
        WalletNetwork::Preview => MidnightNetworkV1::Preview,
    }
}

fn descriptor_for(node: &WorkgraphNodeV1) -> ActionDescriptorV1 {
    let family = node
        .action_name
        .split('.')
        .next()
        .unwrap_or("agent")
        .to_string();
    ActionDescriptorV1 {
        name: node.action_name.clone(),
        family,
        risk_class: node.risk_class,
        expected_artifacts: node.expected_artifacts.clone(),
    }
}

fn receipt_with_payload(
    session_id: &str,
    action: ActionDescriptorV1,
    status: &str,
    payload: Value,
) -> ActionReceiptV1 {
    ActionReceiptV1 {
        schema: "ziros-action-receipt-v1".to_string(),
        receipt_id: zkf_command_surface::new_operation_id("receipt"),
        session_id: session_id.to_string(),
        action_name: action.name.clone(),
        status: status.to_string(),
        created_at: zkf_command_surface::now_rfc3339(),
        action: Some(action),
        artifacts: extract_artifacts(&payload),
        metrics: extract_metrics(&payload),
        error_class: None,
        payload,
    }
}

fn receipt_from_envelope(session_id: &str, envelope: &ActionResultEnvelopeV1) -> ActionReceiptV1 {
    ActionReceiptV1 {
        schema: "ziros-action-receipt-v1".to_string(),
        receipt_id: zkf_command_surface::new_operation_id("receipt"),
        session_id: session_id.to_string(),
        action_name: envelope.action.name.clone(),
        status: envelope.status.clone(),
        created_at: zkf_command_surface::now_rfc3339(),
        action: Some(envelope.action.clone()),
        artifacts: envelope.artifacts.clone(),
        metrics: envelope.metrics.clone(),
        error_class: envelope.error_class,
        payload: envelope.payload.clone().unwrap_or_else(|| json!({})),
    }
}

trait ReceiptExt {
    fn with_error_class(self, error_class: CommandErrorClassV1) -> Self;
}

impl ReceiptExt for ActionReceiptV1 {
    fn with_error_class(mut self, error_class: CommandErrorClassV1) -> Self {
        self.error_class = Some(error_class);
        self
    }
}

fn extract_artifacts(payload: &Value) -> Vec<ArtifactRefV1> {
    let mut artifacts = Vec::new();
    collect_artifacts(None, payload, &mut artifacts);
    artifacts
}

fn collect_artifacts(prefix: Option<&str>, value: &Value, artifacts: &mut Vec<ArtifactRefV1>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let label = prefix
                    .map(|prefix| format!("{prefix}.{key}"))
                    .unwrap_or_else(|| key.clone());
                if let Some(path) = value.as_str()
                    && (key.ends_with("_path")
                        || key.ends_with("_dir")
                        || key == "project_root"
                        || key == "spec_path"
                        || key == "proof_path"
                        || key == "compiled_path"
                        || key == "out_path"
                        || key == "zkir_path")
                {
                    artifacts.push(ArtifactRefV1 {
                        label,
                        path: path.to_string(),
                        kind: infer_artifact_kind(key),
                    });
                } else {
                    collect_artifacts(Some(&label), value, artifacts);
                }
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let label = prefix
                    .map(|prefix| format!("{prefix}[{index}]"))
                    .unwrap_or_else(|| format!("item[{index}]"));
                collect_artifacts(Some(&label), item, artifacts);
            }
        }
        _ => {}
    }
}

fn infer_artifact_kind(key: &str) -> Option<String> {
    if key.contains("proof") {
        Some("proof".to_string())
    } else if key.contains("verify") {
        Some("verification".to_string())
    } else if key.contains("zkir") {
        Some("zkir".to_string())
    } else if key.contains("benchmark") {
        Some("benchmark".to_string())
    } else if key.contains("deploy") {
        Some("deployment".to_string())
    } else {
        Some("file".to_string())
    }
}

fn extract_metrics(payload: &Value) -> Vec<MetricRecordV1> {
    let mut metrics = Vec::new();
    collect_metrics(None, payload, &mut metrics);
    metrics
}

fn collect_metrics(prefix: Option<&str>, value: &Value, metrics: &mut Vec<MetricRecordV1>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                let label = prefix
                    .map(|prefix| format!("{prefix}.{key}"))
                    .unwrap_or_else(|| key.clone());
                if value.is_number()
                    || value.is_boolean()
                    || key.ends_with("_ms")
                    || key.ends_with("_bytes")
                {
                    metrics.push(MetricRecordV1 {
                        name: label,
                        value: value.clone(),
                        unit: infer_metric_unit(key),
                    });
                } else {
                    collect_metrics(Some(&label), value, metrics);
                }
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                let label = prefix
                    .map(|prefix| format!("{prefix}[{index}]"))
                    .unwrap_or_else(|| format!("item[{index}]"));
                collect_metrics(Some(&label), value, metrics);
            }
        }
        _ => {}
    }
}

fn infer_metric_unit(key: &str) -> Option<String> {
    if key.ends_with("_ms") {
        Some("ms".to_string())
    } else if key.ends_with("_bytes") {
        Some("bytes".to_string())
    } else {
        None
    }
}

fn classify_error(action_name: &str, error: &str) -> CommandErrorClassV1 {
    let lower = error.to_ascii_lowercase();
    if lower.contains("approval") {
        CommandErrorClassV1::ApprovalRequired
    } else if lower.contains("missing") || lower.contains("does not exist") {
        CommandErrorClassV1::MissingArtifact
    } else if lower.contains("blocked") {
        CommandErrorClassV1::DependencyBlocked
    } else if lower.contains("version mismatch") || lower.contains("not available") {
        CommandErrorClassV1::CapabilityBlocked
    } else if lower.contains("verify") {
        CommandErrorClassV1::VerificationFailure
    } else if lower.contains("proof server") || lower.contains("gateway") {
        CommandErrorClassV1::ExternalServiceFailure
    } else if action_name.starts_with("midnight.") || action_name.starts_with("proof.") {
        CommandErrorClassV1::RuntimeFailure
    } else {
        CommandErrorClassV1::Unknown
    }
}
