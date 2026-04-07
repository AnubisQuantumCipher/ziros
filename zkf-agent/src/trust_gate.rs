use crate::types::{TrustGateReportV1, WalletReadinessV1, WorkflowRequirementsV1};
use serde_json::Value;
use std::path::PathBuf;
use zkf_command_surface::midnight::{MidnightNetworkV1, status as midnight_status};
use zkf_command_surface::truth::collect_truth_snapshot;
use zkf_command_surface::wallet::{WalletContextV1, snapshot, sync_health};
use zkf_command_surface::{new_operation_id, now_rfc3339};

pub fn resolve_trust_gate(
    workflow_kind: &str,
    requirements: &WorkflowRequirementsV1,
    project_root: Option<PathBuf>,
) -> Result<TrustGateReportV1, String> {
    let truth_snapshot = collect_truth_snapshot()?;
    let truth_value = serde_json::to_value(&truth_snapshot).map_err(|error| error.to_string())?;
    let mut prerequisites = Vec::new();
    if requirements.strict && !truth_snapshot.strict_bn254_auto_route_ready {
        prerequisites.push("strict BN254 auto route is not ready on the current host".to_string());
    }
    if requirements.require_metal && !metal_ready(&truth_value) {
        prerequisites.push("Metal acceleration is not available on the current host".to_string());
    }

    let midnight_status = if requirements.require_midnight {
        let status = midnight_status(
            MidnightNetworkV1::Preprod,
            project_root.as_deref(),
            None,
            None,
        )?;
        if !status.ready {
            prerequisites.extend(
                status
                    .blocked_reasons
                    .iter()
                    .map(|reason| format!("midnight: {reason}")),
            );
        }
        Some(status)
    } else {
        None
    };

    let wallet = if requirements.require_wallet {
        let mut handle = WalletContextV1 {
            network: Some(requirements.wallet_network),
            ..WalletContextV1::default()
        }
        .open_handle()?;
        let readiness = match snapshot(&mut handle) {
            Ok(snapshot_view) => {
                let health = sync_health(&mut handle).ok();
                let health_value = health
                    .as_ref()
                    .map(serde_json::to_value)
                    .transpose()
                    .map_err(|error| error.to_string())?;
                let ready = snapshot_view.has_imported_seed
                    && health
                        .as_ref()
                        .map(|report| {
                            report.rpc.reachable
                                && report.indexer.reachable
                                && report.proof_server.reachable
                                && report.gateway.reachable
                        })
                        .unwrap_or(false);
                if !snapshot_view.has_imported_seed {
                    prerequisites.push("wallet: no imported seed material is present".to_string());
                }
                if !ready {
                    prerequisites.push("wallet: sync-health is not fully reachable".to_string());
                }
                WalletReadinessV1 {
                    network: snapshot_view.network.as_str().to_string(),
                    ready,
                    locked: snapshot_view.locked,
                    has_imported_seed: snapshot_view.has_imported_seed,
                    snapshot: Some(
                        serde_json::to_value(snapshot_view).map_err(|error| error.to_string())?,
                    ),
                    health: health_value,
                    error: None,
                }
            }
            Err(error) => {
                prerequisites.push(format!("wallet: {error}"));
                WalletReadinessV1 {
                    network: requirements.wallet_network.as_str().to_string(),
                    ready: false,
                    locked: true,
                    has_imported_seed: false,
                    snapshot: None,
                    health: None,
                    error: Some(error),
                }
            }
        };
        Some(readiness)
    } else {
        None
    };

    Ok(TrustGateReportV1 {
        schema: "ziros-trust-gate-v1".to_string(),
        gate_id: new_operation_id("trust-gate"),
        generated_at: now_rfc3339(),
        workflow_kind: workflow_kind.to_string(),
        strict: requirements.strict,
        compat_allowed: requirements.compat_allowed,
        blocked: !prerequisites.is_empty(),
        prerequisites,
        truth_snapshot: truth_value,
        midnight_status,
        wallet,
    })
}

fn metal_ready(truth_snapshot: &Value) -> bool {
    truth_snapshot
        .get("metal")
        .and_then(|metal| metal.get("metal_available"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
        && truth_snapshot
            .get("metal")
            .and_then(|metal| metal.get("metal_dispatch_circuit_open"))
            .and_then(Value::as_bool)
            .unwrap_or(false)
}
