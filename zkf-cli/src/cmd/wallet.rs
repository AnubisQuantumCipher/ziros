use crate::cli::{
    WalletCommands, WalletGrantCommands, WalletOriginCommands, WalletPendingCommands,
    WalletSessionCommands,
};
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use zkf_command_surface::{
    CommandEventKindV1, CommandEventV1, JsonlEventSink, new_operation_id,
};
use zkf_command_surface::wallet::{
    BridgePendingKindV1, WalletContextV1, approve_pending, begin_bridge, begin_native, grant_origin,
    issue_bridge_grant, issue_native_grant, lock, open_session, pending_review, reject_pending,
    revoke_origin, snapshot, sync_health, unlock,
};
use zkf_wallet::{ApprovalMethod, ApprovalToken, BridgeScope, SubmissionGrant, TxReviewPayload, WalletNetwork};

pub(crate) fn handle_wallet(
    network: String,
    persistent_root: Option<PathBuf>,
    cache_root: Option<PathBuf>,
    json_output: bool,
    events_jsonl: Option<PathBuf>,
    command: WalletCommands,
) -> Result<(), String> {
    let action_id = new_operation_id("wallet");
    let mut sink = JsonlEventSink::open(events_jsonl)?;
    emit(
        &mut sink,
        CommandEventKindV1::Started,
        &action_id,
        "wallet command started",
    )?;
    let network = WalletNetwork::parse(&network).map_err(|error| error.to_string())?;
    let context = WalletContextV1 {
        network: Some(network),
        persistent_root,
        cache_root,
    };
    let mut wallet = context.open_handle()?;
    match command {
        WalletCommands::Snapshot => print_output(json_output, &snapshot(&mut wallet)?)?,
        WalletCommands::Unlock { prompt } => print_output(json_output, &unlock(&mut wallet, &prompt)?)?,
        WalletCommands::Lock => print_output(json_output, &lock(&mut wallet)?)?,
        WalletCommands::SyncHealth => print_output(json_output, &sync_health(&mut wallet)?)?,
        WalletCommands::Origin { command } => match command {
            WalletOriginCommands::Grant { origin, scopes, note } => {
                let scopes = scopes
                    .into_iter()
                    .map(|scope| parse_scope(&scope))
                    .collect::<Result<BTreeSet<_>, _>>()?;
                print_output(json_output, &grant_origin(&mut wallet, origin, scopes, note)?)?
            }
            WalletOriginCommands::Revoke { origin } => {
                print_output(json_output, &revoke_origin(&mut wallet, &origin)?)?
            }
        },
        WalletCommands::Session { command } => match command {
            WalletSessionCommands::Open { origin } => {
                print_output(json_output, &open_session(&mut wallet, &origin)?)?
            }
        },
        WalletCommands::Pending { command } => match command {
            WalletPendingCommands::BeginNative { review } => {
                let review = read_json::<TxReviewPayload>(&review)?;
                print_output(json_output, &begin_native(&mut wallet, review)?)?
            }
            WalletPendingCommands::BeginBridge {
                session_id,
                kind,
                review,
            } => {
                let review = read_json::<TxReviewPayload>(&review)?;
                let kind = parse_pending_kind(&kind)?;
                print_output(json_output, &begin_bridge(&mut wallet, &session_id, kind, review)?)?
            }
            WalletPendingCommands::Review { pending_id } => {
                print_output(json_output, &pending_review(&wallet, &pending_id)?)?
            }
            WalletPendingCommands::Approve {
                pending_id,
                primary_prompt,
                secondary_prompt,
            } => print_output(
                json_output,
                &approve_pending(
                    &mut wallet,
                    &pending_id,
                    &primary_prompt,
                    secondary_prompt.as_deref(),
                )?,
            )?,
            WalletPendingCommands::Reject { pending_id, reason } => {
                reject_pending(&mut wallet, &pending_id, &reason)?;
                print_output(json_output, &json!({ "status": "ok" }))?
            }
        },
        WalletCommands::Grant { command } => match command {
            WalletGrantCommands::IssueNative {
                method,
                tx_digest,
                token,
            } => {
                let token = read_json::<ApprovalToken>(&token)?;
                let method = ApprovalMethod::parse(&method).map_err(|error| error.to_string())?;
                print_output(json_output, &issue_native_grant(&mut wallet, method, &tx_digest, &token)?)?
            }
            WalletGrantCommands::IssueBridge {
                session_id,
                method,
                tx_digest,
                token,
            } => {
                let token = read_json::<ApprovalToken>(&token)?;
                let method = ApprovalMethod::parse(&method).map_err(|error| error.to_string())?;
                print_output(
                    json_output,
                    &issue_bridge_grant(&mut wallet, &session_id, method, &tx_digest, &token)?,
                )?
            }
            WalletGrantCommands::ConsumeNative {
                method,
                tx_digest,
                grant,
            } => {
                let grant = read_json::<SubmissionGrant>(&grant)?;
                let method = ApprovalMethod::parse(&method).map_err(|error| error.to_string())?;
                zkf_command_surface::wallet::consume_native_grant(
                    &mut wallet,
                    method,
                    &tx_digest,
                    &grant,
                )?;
                print_output(json_output, &json!({ "status": "ok" }))?
            }
            WalletGrantCommands::ConsumeBridge {
                session_id,
                method,
                tx_digest,
                grant,
            } => {
                let grant = read_json::<SubmissionGrant>(&grant)?;
                let method = ApprovalMethod::parse(&method).map_err(|error| error.to_string())?;
                zkf_command_surface::wallet::consume_bridge_grant(
                    &mut wallet,
                    &session_id,
                    method,
                    &tx_digest,
                    &grant,
                )?;
                print_output(json_output, &json!({ "status": "ok" }))?
            }
        },
    }
    emit(
        &mut sink,
        CommandEventKindV1::Completed,
        &action_id,
        "wallet command completed",
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

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn print_output<T: Serialize>(json_output: bool, value: &T) -> Result<(), String> {
    let body = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    if json_output {
        println!("{body}");
    } else {
        println!("{body}");
    }
    Ok(())
}

fn parse_scope(raw: &str) -> Result<BridgeScope, String> {
    match raw {
        "read-config" => Ok(BridgeScope::ReadConfig),
        "read-balances" => Ok(BridgeScope::ReadBalances),
        "read-addresses" => Ok(BridgeScope::ReadAddresses),
        "read-history" => Ok(BridgeScope::ReadHistory),
        "transfer" => Ok(BridgeScope::Transfer),
        "intent" => Ok(BridgeScope::Intent),
        "submit" => Ok(BridgeScope::Submit),
        other => Err(format!("unsupported wallet bridge scope '{other}'")),
    }
}

fn parse_pending_kind(raw: &str) -> Result<BridgePendingKindV1, String> {
    match raw {
        "transfer" => Ok(BridgePendingKindV1::Transfer),
        "intent" => Ok(BridgePendingKindV1::Intent),
        other => Err(format!("unsupported bridge pending kind '{other}'")),
    }
}
