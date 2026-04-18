use actix_web::{App, HttpResponse, HttpServer, Responder, web};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zkf_agent::{AgentBrowserKindV1, AgentBrowserOpenRequestV1, browser_open_report};

use super::shared::{
    DEFAULT_GATEWAY_URL, DEFAULT_PROOF_SERVER_URL, MidnightNetwork,
    REQUIRED_COMPACT_MANAGER_VERSION, REQUIRED_COMPACTC_VERSION,
    REQUIRED_LEDGER_WIRE_COMPAT_VERSION, REQUIRED_NODE_MAJOR, compact_manager_version,
    compactc_version, compare_project_package_pins, current_timestamp_rfc3339ish,
    expected_midnight_package_lane_label, expected_midnight_package_total_label,
    locate_midnight_project_root, network_config, node_version, npm_version,
    resolve_compact_manager_binary, resolve_compactc_binary,
};

#[derive(Debug, Clone)]
pub(crate) struct DoctorArgs {
    pub(crate) json: bool,
    pub(crate) strict: bool,
    pub(crate) project: Option<PathBuf>,
    pub(crate) network: String,
    pub(crate) proof_server_url: Option<String>,
    pub(crate) gateway_url: Option<String>,
    pub(crate) browser_check: bool,
    pub(crate) no_browser_check: bool,
    pub(crate) require_wallet: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MidnightDoctorCheckStatusV1 {
    Pass,
    Warn,
    Fail,
    NotCheckableFromCli,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MidnightDoctorCheckV1 {
    id: String,
    label: String,
    required: bool,
    status: MidnightDoctorCheckStatusV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actual: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MidnightDoctorSummaryV1 {
    total: usize,
    passed: usize,
    warned: usize,
    failed: usize,
    not_checkable: usize,
    overall_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MidnightDoctorReportV1 {
    schema: String,
    generated_at: String,
    network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    project_root: Option<String>,
    summary: MidnightDoctorSummaryV1,
    checks: Vec<MidnightDoctorCheckV1>,
    #[serde(default)]
    recommended_fixes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BrowserWalletReport {
    #[serde(default)]
    lace_detected: bool,
    #[serde(default)]
    connected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wallet_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wallet_api_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dust_balance: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dust_cap: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HeadlessWalletReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spendable_dust_raw: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spendable_dust_coins: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registered_night_utxos: Option<u64>,
}

#[derive(Clone)]
struct BrowserReportState {
    report: Arc<Mutex<Option<BrowserWalletReport>>>,
    network: String,
}

pub(crate) fn handle_doctor(args: DoctorArgs) -> Result<(), String> {
    let report = build_doctor_report(&args)?;
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
        );
    } else {
        println!("{}", render_human_summary(&report));
        for fix in &report.recommended_fixes {
            println!("fix: {fix}");
        }
    }

    if args.strict && report_has_required_failures(&report) {
        return Err("Midnight doctor strict gate failed".to_string());
    }
    Ok(())
}

fn report_has_required_failures(report: &MidnightDoctorReportV1) -> bool {
    report
        .checks
        .iter()
        .any(|check| check.required && check.status == MidnightDoctorCheckStatusV1::Fail)
}

fn build_doctor_report(args: &DoctorArgs) -> Result<MidnightDoctorReportV1, String> {
    let network = MidnightNetwork::parse(&args.network)?;
    let network_config = network_config(
        network,
        args.proof_server_url.as_deref(),
        args.gateway_url.as_deref(),
    );
    let project_root = locate_midnight_project_root(args.project.as_deref());
    let proof_server_url = args
        .proof_server_url
        .clone()
        .unwrap_or_else(|| DEFAULT_PROOF_SERVER_URL.to_string());
    let gateway_url = args
        .gateway_url
        .clone()
        .unwrap_or_else(|| DEFAULT_GATEWAY_URL.to_string());

    let mut checks = vec![
        compactc_check(),
        compact_manager_check(),
        node_check(),
        npm_check(),
        package_pins_check(project_root.as_deref()),
        proof_server_check(&proof_server_url),
        gateway_check(&gateway_url),
        http_reachability_check(
            "rpc",
            "Midnight RPC",
            &network_config.rpc_url,
            true,
            "The selected Midnight RPC endpoint could not be reached.",
        ),
        http_reachability_check(
            "indexer",
            "Midnight Indexer",
            &network_config.indexer_url,
            true,
            "The selected Midnight indexer endpoint could not be reached.",
        ),
        http_reachability_check(
            "explorer",
            "Midnight Explorer",
            &network_config.explorer_url,
            false,
            "Explorer reachability is advisory; wallet and deployment flows do not depend on it.",
        ),
    ];

    let interactive_browser_allowed =
        !args.no_browser_check && std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    let wallet_env_present = std::env::var_os("MIDNIGHT_WALLET_SEED").is_some()
        || std::env::var_os("MIDNIGHT_WALLET_MNEMONIC").is_some()
        || std::env::var_os("MIDNIGHT_WALLET_NAME").is_some();

    if wallet_env_present {
        let (wallet_check, dust_check, lace_check) = headless_wallet_checks(
            project_root.as_deref(),
            &network.to_string(),
            args.require_wallet,
        );
        checks.push(lace_check);
        checks.push(wallet_check);
        checks.push(dust_check);
    } else if interactive_browser_allowed || args.browser_check {
        let (lace_check, wallet_check, dust_check) =
            browser_wallet_checks(network.as_str(), args.require_wallet);
        checks.push(lace_check);
        checks.push(wallet_check);
        checks.push(dust_check);
    } else {
        let status = if args.require_wallet {
            MidnightDoctorCheckStatusV1::Fail
        } else {
            MidnightDoctorCheckStatusV1::NotCheckableFromCli
        };
        checks.push(MidnightDoctorCheckV1 {
            id: "lace".to_string(),
            label: "Lace availability".to_string(),
            required: args.require_wallet,
            status: status.clone(),
            expected: Some("Midnight Lace extension available in a browser context".to_string()),
            actual: None,
            detail: Some(
                "CLI-only mode cannot honestly inspect window.midnight.mnLace.".to_string(),
            ),
            fix: Some(
                "Re-run with browser access enabled, or provide a project plus MIDNIGHT_WALLET_SEED, MIDNIGHT_WALLET_MNEMONIC, or MIDNIGHT_WALLET_NAME for headless wallet diagnostics.".to_string(),
            ),
        });
        checks.push(MidnightDoctorCheckV1 {
            id: "wallet".to_string(),
            label: "Wallet session".to_string(),
            required: args.require_wallet,
            status: status.clone(),
            expected: Some("A Midnight wallet session bound to the selected network".to_string()),
            actual: None,
            detail: Some(
                "No browser wallet session or headless operator wallet credentials were available."
                    .to_string(),
            ),
            fix: Some(
                "Provide MIDNIGHT_WALLET_SEED, MIDNIGHT_WALLET_MNEMONIC, or MIDNIGHT_WALLET_NAME, or allow the browser-assisted Lace check."
                    .to_string(),
            ),
        });
        checks.push(MidnightDoctorCheckV1 {
            id: "dust".to_string(),
            label: "Spendable tDUST".to_string(),
            required: args.require_wallet,
            status,
            expected: Some("A nonzero spendable tDUST balance".to_string()),
            actual: None,
            detail: Some("DUST balance is not checkable from a bare CLI process.".to_string()),
            fix: Some(
                "Run the browser-assisted Lace check or supply a project with installed Midnight dependencies and headless wallet credentials."
                    .to_string(),
            ),
        });
    }

    let summary = summarize_checks(&checks);
    let recommended_fixes = checks
        .iter()
        .filter_map(|check| {
            (check.status == MidnightDoctorCheckStatusV1::Fail
                || check.status == MidnightDoctorCheckStatusV1::Warn)
                .then(|| check.fix.clone())
                .flatten()
        })
        .collect::<Vec<_>>();

    Ok(MidnightDoctorReportV1 {
        schema: "zkf-midnight-doctor-report-v1".to_string(),
        generated_at: current_timestamp_rfc3339ish(),
        network: network_config.network,
        project_root: project_root.map(|path| path.display().to_string()),
        summary,
        checks,
        recommended_fixes,
    })
}

fn summarize_checks(checks: &[MidnightDoctorCheckV1]) -> MidnightDoctorSummaryV1 {
    let mut passed = 0usize;
    let mut warned = 0usize;
    let mut failed = 0usize;
    let mut not_checkable = 0usize;
    for check in checks {
        match check.status {
            MidnightDoctorCheckStatusV1::Pass => passed += 1,
            MidnightDoctorCheckStatusV1::Warn => warned += 1,
            MidnightDoctorCheckStatusV1::Fail => failed += 1,
            MidnightDoctorCheckStatusV1::NotCheckableFromCli => not_checkable += 1,
        }
    }
    MidnightDoctorSummaryV1 {
        total: checks.len(),
        passed,
        warned,
        failed,
        not_checkable,
        overall_status: if failed > 0 {
            "fail".to_string()
        } else if warned > 0 {
            "warn".to_string()
        } else {
            "pass".to_string()
        },
    }
}

fn render_human_summary(report: &MidnightDoctorReportV1) -> String {
    let mut fragments = Vec::new();
    for id in [
        "compactc",
        "node",
        "npm",
        "packages",
        "proof-server",
        "gateway",
        "rpc",
        "indexer",
        "lace",
        "wallet",
        "dust",
    ] {
        if let Some(check) = report.checks.iter().find(|check| check.id == id) {
            fragments.push(format!("{}={}", check.id, status_label(&check.status)));
        }
    }
    format!("midnight doctor: {}", fragments.join(" "))
}

fn status_label(status: &MidnightDoctorCheckStatusV1) -> &'static str {
    match status {
        MidnightDoctorCheckStatusV1::Pass => "ok",
        MidnightDoctorCheckStatusV1::Warn => "warn",
        MidnightDoctorCheckStatusV1::Fail => "fail",
        MidnightDoctorCheckStatusV1::NotCheckableFromCli => "not-checkable",
    }
}

fn compactc_check() -> MidnightDoctorCheckV1 {
    let expected = REQUIRED_COMPACTC_VERSION.to_string();
    match resolve_compactc_binary() {
        Some(path) => match compactc_version(&path) {
            Ok(version) if version == REQUIRED_COMPACTC_VERSION => MidnightDoctorCheckV1 {
                id: "compactc".to_string(),
                label: "Compact compiler".to_string(),
                required: true,
                status: MidnightDoctorCheckStatusV1::Pass,
                expected: Some(expected),
                actual: Some(format!("{} @ {}", version, path.display())),
                detail: None,
                fix: None,
            },
            Ok(version) => MidnightDoctorCheckV1 {
                id: "compactc".to_string(),
                label: "Compact compiler".to_string(),
                required: true,
                status: MidnightDoctorCheckStatusV1::Fail,
                expected: Some(expected),
                actual: Some(format!("{} @ {}", version, path.display())),
                detail: Some(format!(
                    "ZirOS Midnight support is pinned to compactc {REQUIRED_COMPACTC_VERSION}."
                )),
                fix: Some(format!(
                    "Install compactc {REQUIRED_COMPACTC_VERSION} and make sure COMPACTC_BIN or ~/.compact/versions points at that binary."
                )),
            },
            Err(error) => MidnightDoctorCheckV1 {
                id: "compactc".to_string(),
                label: "Compact compiler".to_string(),
                required: true,
                status: MidnightDoctorCheckStatusV1::Fail,
                expected: Some(expected),
                actual: Some(path.display().to_string()),
                detail: Some(error),
                fix: Some(format!(
                    "Install compactc {REQUIRED_COMPACTC_VERSION} and make sure the binary can be executed from this shell."
                )),
            },
        },
        None => MidnightDoctorCheckV1 {
            id: "compactc".to_string(),
            label: "Compact compiler".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Fail,
            expected: Some(expected),
            actual: None,
            detail: Some("No compactc binary was found.".to_string()),
            fix: Some(format!(
                "Install compactc {REQUIRED_COMPACTC_VERSION} or point COMPACTC_BIN at the exact compiler binary."
            )),
        },
    }
}

fn compact_manager_check() -> MidnightDoctorCheckV1 {
    match resolve_compact_manager_binary() {
        Some(path) => match compact_manager_version(&path) {
            Ok(version) => MidnightDoctorCheckV1 {
                id: "compact".to_string(),
                label: "Compact manager".to_string(),
                required: false,
                status: if version.trim() == REQUIRED_COMPACT_MANAGER_VERSION {
                    MidnightDoctorCheckStatusV1::Pass
                } else {
                    MidnightDoctorCheckStatusV1::Warn
                },
                expected: Some(REQUIRED_COMPACT_MANAGER_VERSION.to_string()),
                actual: Some(format!("{} @ {}", version, path.display())),
                detail: (version.trim() != REQUIRED_COMPACT_MANAGER_VERSION).then_some(
                        "The installed compact manager version does not match the pinned Midnight lane."
                            .to_string(),
                    ),
                fix: (version.trim() != REQUIRED_COMPACT_MANAGER_VERSION).then_some(format!(
                    "Install Compact manager {REQUIRED_COMPACT_MANAGER_VERSION} to match the pinned Midnight toolchain lane."
                )),
            },
            Err(error) => MidnightDoctorCheckV1 {
                id: "compact".to_string(),
                label: "Compact manager".to_string(),
                required: false,
                status: MidnightDoctorCheckStatusV1::Warn,
                expected: Some(REQUIRED_COMPACT_MANAGER_VERSION.to_string()),
                actual: Some(path.display().to_string()),
                detail: Some(error),
                fix: Some(format!(
                    "Install the Compact manager {REQUIRED_COMPACT_MANAGER_VERSION} lane if you want managed compactc installs."
                )),
            },
        },
        None => MidnightDoctorCheckV1 {
            id: "compact".to_string(),
            label: "Compact manager".to_string(),
            required: false,
            status: MidnightDoctorCheckStatusV1::Warn,
            expected: Some(REQUIRED_COMPACT_MANAGER_VERSION.to_string()),
            actual: None,
            detail: Some("The compact manager is not installed on PATH.".to_string()),
            fix: Some(format!(
                "Install the Compact manager {REQUIRED_COMPACT_MANAGER_VERSION} lane if you want managed compiler installs."
            )),
        },
    }
}

fn node_check() -> MidnightDoctorCheckV1 {
    match node_version() {
        Ok(version) => {
            let normalized = version.trim().trim_start_matches('v').to_string();
            let parsed = Version::parse(&normalized).ok();
            let status = if parsed
                .as_ref()
                .is_some_and(|version| version.major >= REQUIRED_NODE_MAJOR)
            {
                MidnightDoctorCheckStatusV1::Pass
            } else {
                MidnightDoctorCheckStatusV1::Fail
            };
            MidnightDoctorCheckV1 {
                id: "node".to_string(),
                label: "Node.js".to_string(),
                required: true,
                status,
                expected: Some(format!(">={REQUIRED_NODE_MAJOR}.0.0")),
                actual: Some(version),
                detail: parsed.is_none().then_some(format!(
                    "failed to parse a semantic version from node output: {}",
                    normalized
                )),
                fix: Some("Install Node.js 22.x or newer.".to_string()),
            }
        }
        Err(error) => MidnightDoctorCheckV1 {
            id: "node".to_string(),
            label: "Node.js".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Fail,
            expected: Some(format!(">={REQUIRED_NODE_MAJOR}.0.0")),
            actual: None,
            detail: Some(error),
            fix: Some("Install Node.js 22.x or newer.".to_string()),
        },
    }
}

fn npm_check() -> MidnightDoctorCheckV1 {
    match npm_version() {
        Ok(version) => MidnightDoctorCheckV1 {
            id: "npm".to_string(),
            label: "npm".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Pass,
            expected: None,
            actual: Some(version),
            detail: None,
            fix: None,
        },
        Err(error) => MidnightDoctorCheckV1 {
            id: "npm".to_string(),
            label: "npm".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Fail,
            expected: None,
            actual: None,
            detail: Some(error),
            fix: Some("Install npm and make sure it is on PATH.".to_string()),
        },
    }
}

fn package_pins_check(project_root: Option<&Path>) -> MidnightDoctorCheckV1 {
    let Some(project_root) = project_root else {
        return MidnightDoctorCheckV1 {
            id: "packages".to_string(),
            label: "Pinned Midnight packages".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::NotCheckableFromCli,
            expected: Some(expected_midnight_package_lane_label()),
            actual: None,
            detail: Some("No Midnight project root was supplied.".to_string()),
            fix: Some(
                "Re-run with --project <path> inside a scaffolded Midnight DApp.".to_string(),
            ),
        };
    };

    match compare_project_package_pins(project_root) {
        Ok(report)
            if report.missing.is_empty()
                && report.mismatched.is_empty()
                && report.lock_missing.is_empty()
                && report.lock_mismatched.is_empty() =>
        {
            MidnightDoctorCheckV1 {
                id: "packages".to_string(),
                label: "Pinned Midnight packages".to_string(),
                required: true,
                status: MidnightDoctorCheckStatusV1::Pass,
                expected: Some(format!("{} pinned packages", report.required_total)),
                actual: Some(format!("{} matched in {}", report.matched, project_root.display())),
                detail: None,
                fix: None,
            }
        }
        Ok(report) => MidnightDoctorCheckV1 {
            id: "packages".to_string(),
            label: "Pinned Midnight packages".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Fail,
            expected: Some(format!("{} pinned packages", report.required_total)),
            actual: Some(format!("{} matched in {}", report.matched, project_root.display())),
            detail: Some(format!(
                "missing={:?} mismatched={:?} lock_missing={:?} lock_mismatched={:?}",
                report.missing, report.mismatched, report.lock_missing, report.lock_mismatched
            )),
            fix: Some(
                "Regenerate the project with `zkf midnight init` or reinstall dependencies from the pinned package manifest.".to_string(),
            ),
        },
        Err(error) => MidnightDoctorCheckV1 {
            id: "packages".to_string(),
            label: "Pinned Midnight packages".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Fail,
            expected: Some(expected_midnight_package_total_label()),
            actual: Some(project_root.display().to_string()),
            detail: Some(error),
            fix: Some(
                "Make sure package.json and package-lock.json exist in the target Midnight project."
                    .to_string(),
            ),
        },
    }
}

fn proof_server_check(base_url: &str) -> MidnightDoctorCheckV1 {
    let health = http_probe_json(&format!("{base_url}/health"));
    let ready = http_probe_json(&format!("{base_url}/ready"));
    let version = http_probe_text(&format!("{base_url}/version"));
    match (health, ready, version) {
        (Ok((_health_status, Some(health_json))), Ok((ready_status, _)), Ok(version))
            if health_json
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status == "ok")
                && version.trim() == REQUIRED_LEDGER_WIRE_COMPAT_VERSION =>
        {
            MidnightDoctorCheckV1 {
                id: "proof-server".to_string(),
                label: "Midnight proof server".to_string(),
                required: true,
                status: if ready_status == 503 {
                    MidnightDoctorCheckStatusV1::Warn
                } else {
                    MidnightDoctorCheckStatusV1::Pass
                },
                expected: Some(format!("wire contract {}", REQUIRED_LEDGER_WIRE_COMPAT_VERSION)),
                actual: Some(format!("{version} @ {base_url}")),
                detail: (ready_status == 503)
                    .then(|| "The proof server is healthy but currently reports BUSY on /ready.".to_string()),
                fix: Some(
                    "Start or restart the native proof server with `zkf midnight proof-server serve --engine umpg`."
                        .to_string(),
                ),
            }
        }
        (Ok((_status, _)), Ok((_ready_status, _)), Ok(version)) => MidnightDoctorCheckV1 {
            id: "proof-server".to_string(),
            label: "Midnight proof server".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Fail,
            expected: Some(format!("wire contract {}", REQUIRED_LEDGER_WIRE_COMPAT_VERSION)),
            actual: Some(format!("{version} @ {base_url}")),
            detail: Some(
                "The proof server responded, but the health or compatibility contract was not correct."
                    .to_string(),
            ),
            fix: Some(
                format!(
                    "Start the ZirOS-native proof server and make sure /version returns {REQUIRED_LEDGER_WIRE_COMPAT_VERSION}."
                ),
            ),
        },
        _ => MidnightDoctorCheckV1 {
            id: "proof-server".to_string(),
            label: "Midnight proof server".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Fail,
            expected: Some(format!("wire contract {}", REQUIRED_LEDGER_WIRE_COMPAT_VERSION)),
            actual: Some(base_url.to_string()),
            detail: Some("The proof server endpoints /health, /ready, or /version were unreachable.".to_string()),
            fix: Some(
                "Start the native proof server: `zkf midnight proof-server serve --port 6300 --engine umpg`."
                    .to_string(),
            ),
        },
    }
}

fn gateway_check(base_url: &str) -> MidnightDoctorCheckV1 {
    match http_probe_json(&format!("{base_url}/ready")) {
        Ok((_status, Some(payload))) => {
            let ready = payload
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status == "ok");
            let compactc_ok = payload
                .get("compactcVersion")
                .and_then(Value::as_str)
                .is_some_and(|version| version == REQUIRED_COMPACTC_VERSION);
            let attestor_ready = payload
                .get("attestorPublicKeyPresent")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            MidnightDoctorCheckV1 {
                id: "gateway".to_string(),
                label: "Midnight Compact gateway".to_string(),
                required: true,
                status: if ready && compactc_ok && attestor_ready {
                    MidnightDoctorCheckStatusV1::Pass
                } else {
                    MidnightDoctorCheckStatusV1::Warn
                },
                expected: Some(format!(
                    "ready gateway with compactc {} and attestor key exposure",
                    REQUIRED_COMPACTC_VERSION
                )),
                actual: Some(base_url.to_string()),
                detail: Some(payload.to_string()),
                fix: Some(format!(
                    "Start the gateway with `zkf midnight gateway serve --port 6311` after installing compactc {REQUIRED_COMPACTC_VERSION}."
                )),
            }
        }
        Ok((_status, None)) => MidnightDoctorCheckV1 {
            id: "gateway".to_string(),
            label: "Midnight Compact gateway".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Warn,
            expected: Some(format!("gateway /ready JSON at {base_url}")),
            actual: Some(base_url.to_string()),
            detail: Some("The gateway responded without JSON.".to_string()),
            fix: Some(
                "Restart the gateway and verify that /ready returns a JSON readiness report."
                    .to_string(),
            ),
        },
        Err(error) => MidnightDoctorCheckV1 {
            id: "gateway".to_string(),
            label: "Midnight Compact gateway".to_string(),
            required: true,
            status: MidnightDoctorCheckStatusV1::Warn,
            expected: Some(format!("gateway /ready JSON at {base_url}")),
            actual: Some(base_url.to_string()),
            detail: Some(error),
            fix: Some(
                "Start the gateway with `zkf midnight gateway serve --port 6311`.".to_string(),
            ),
        },
    }
}

fn http_reachability_check(
    id: &str,
    label: &str,
    url: &str,
    required: bool,
    fix_detail: &str,
) -> MidnightDoctorCheckV1 {
    match http_probe_json(url) {
        Ok((status, _)) => MidnightDoctorCheckV1 {
            id: id.to_string(),
            label: label.to_string(),
            required,
            status: MidnightDoctorCheckStatusV1::Pass,
            expected: Some("reachable endpoint".to_string()),
            actual: Some(format!("HTTP {status} @ {url}")),
            detail: None,
            fix: None,
        },
        Err(error) => MidnightDoctorCheckV1 {
            id: id.to_string(),
            label: label.to_string(),
            required,
            status: if required {
                MidnightDoctorCheckStatusV1::Fail
            } else {
                MidnightDoctorCheckStatusV1::Warn
            },
            expected: Some("reachable endpoint".to_string()),
            actual: Some(url.to_string()),
            detail: Some(error),
            fix: Some(fix_detail.to_string()),
        },
    }
}

fn headless_wallet_checks(
    project_root: Option<&Path>,
    network: &str,
    require_wallet: bool,
) -> (
    MidnightDoctorCheckV1,
    MidnightDoctorCheckV1,
    MidnightDoctorCheckV1,
) {
    let lace_check = MidnightDoctorCheckV1 {
        id: "lace".to_string(),
        label: "Lace availability".to_string(),
        required: false,
        status: MidnightDoctorCheckStatusV1::Pass,
        expected: Some("browser-injected Lace wallet or accepted headless operator wallet mode".to_string()),
        actual: Some("headless-wallet-mode".to_string()),
        detail: Some(
            "Headless operator wallet credentials were supplied, so the CLI intentionally skipped browser extension probing.".to_string(),
        ),
        fix: Some(
            "Allow the browser-assisted Lace check if you need extension-specific diagnostics."
                .to_string(),
        ),
    };

    let Some(project_root) = project_root else {
        let status = if require_wallet {
            MidnightDoctorCheckStatusV1::Fail
        } else {
            MidnightDoctorCheckStatusV1::NotCheckableFromCli
        };
        return (
            MidnightDoctorCheckV1 {
                id: "wallet".to_string(),
                label: "Wallet session".to_string(),
                required: require_wallet,
                status: status.clone(),
                expected: Some("headless operator wallet check through project Midnight dependencies".to_string()),
                actual: None,
                detail: Some("No --project root was provided for the headless wallet probe.".to_string()),
                fix: Some(
                    "Re-run with --project <path> inside a scaffolded Midnight DApp with installed dependencies.".to_string(),
                ),
            },
            MidnightDoctorCheckV1 {
                id: "dust".to_string(),
                label: "Spendable tDUST".to_string(),
                required: require_wallet,
                status,
                expected: Some("nonzero spendable tDUST".to_string()),
                actual: None,
                detail: Some("The headless wallet probe needs a project-local Midnight runtime.".to_string()),
                fix: Some(
                    "Re-run with --project <path> after installing project dependencies.".to_string(),
                ),
            },
            lace_check,
        );
    };

    match run_headless_wallet_probe(project_root, network) {
        Ok(report) => {
            let dust_raw = report
                .spendable_dust_raw
                .clone()
                .unwrap_or_else(|| "0".to_string());
            let dust_positive = dust_raw.parse::<u128>().ok().is_some_and(|value| value > 0);
            (
                MidnightDoctorCheckV1 {
                    id: "wallet".to_string(),
                    label: "Wallet session".to_string(),
                    required: require_wallet,
                    status: MidnightDoctorCheckStatusV1::Pass,
                    expected: Some("headless operator wallet sync".to_string()),
                    actual: report.network.clone(),
                    detail: None,
                    fix: None,
                },
                MidnightDoctorCheckV1 {
                    id: "dust".to_string(),
                    label: "Spendable tDUST".to_string(),
                    required: require_wallet,
                    status: if dust_positive {
                        MidnightDoctorCheckStatusV1::Pass
                    } else if require_wallet {
                        MidnightDoctorCheckStatusV1::Fail
                    } else {
                        MidnightDoctorCheckStatusV1::Warn
                    },
                    expected: Some("nonzero spendable tDUST".to_string()),
                    actual: Some(format!(
                        "{} dust across {} coin(s)",
                        dust_raw,
                        report.spendable_dust_coins.unwrap_or_default()
                    )),
                    detail: report
                        .registered_night_utxos
                        .map(|count| format!("registered NIGHT UTXOs={count}")),
                    fix: Some(
                        "Fund the operator wallet with NIGHT, wait for registration, then poll until tDUST becomes spendable.".to_string(),
                    ),
                },
                lace_check,
            )
        }
        Err(error) => {
            let status = if require_wallet {
                MidnightDoctorCheckStatusV1::Fail
            } else {
                MidnightDoctorCheckStatusV1::Warn
            };
            (
                MidnightDoctorCheckV1 {
                    id: "wallet".to_string(),
                    label: "Wallet session".to_string(),
                    required: require_wallet,
                    status: status.clone(),
                    expected: Some("headless operator wallet sync".to_string()),
                    actual: Some(project_root.display().to_string()),
                    detail: Some(error.clone()),
                    fix: Some(
                        "Install the project dependencies and confirm MIDNIGHT_WALLET_SEED, MIDNIGHT_WALLET_MNEMONIC, or MIDNIGHT_WALLET_NAME resolves a wallet that is valid for the selected network.".to_string(),
                    ),
                },
                MidnightDoctorCheckV1 {
                    id: "dust".to_string(),
                    label: "Spendable tDUST".to_string(),
                    required: require_wallet,
                    status,
                    expected: Some("nonzero spendable tDUST".to_string()),
                    actual: Some(project_root.display().to_string()),
                    detail: Some(error),
                    fix: Some(
                        "Fix the headless wallet probe first, then re-run the DUST check.".to_string(),
                    ),
                },
                lace_check,
            )
        }
    }
}

fn browser_wallet_checks(
    network: &str,
    require_wallet: bool,
) -> (
    MidnightDoctorCheckV1,
    MidnightDoctorCheckV1,
    MidnightDoctorCheckV1,
) {
    match run_browser_lace_check(network, Duration::from_secs(45)) {
        Ok(report) => {
            let lace_status = if report.lace_detected {
                MidnightDoctorCheckStatusV1::Pass
            } else if require_wallet {
                MidnightDoctorCheckStatusV1::Fail
            } else {
                MidnightDoctorCheckStatusV1::Warn
            };
            let wallet_status = if report.connected {
                MidnightDoctorCheckStatusV1::Pass
            } else if require_wallet {
                MidnightDoctorCheckStatusV1::Fail
            } else {
                MidnightDoctorCheckStatusV1::Warn
            };
            let dust_positive = report
                .dust_balance
                .as_deref()
                .and_then(|value| value.replace(',', "").parse::<u128>().ok())
                .is_some_and(|value| value > 0);
            let dust_status = if dust_positive {
                MidnightDoctorCheckStatusV1::Pass
            } else if require_wallet {
                MidnightDoctorCheckStatusV1::Fail
            } else {
                MidnightDoctorCheckStatusV1::Warn
            };

            (
                MidnightDoctorCheckV1 {
                    id: "lace".to_string(),
                    label: "Lace availability".to_string(),
                    required: require_wallet,
                    status: lace_status,
                    expected: Some("window.midnight.mnLace present in a browser".to_string()),
                    actual: Some(
                        report
                            .wallet_name
                            .clone()
                            .unwrap_or_else(|| "not-detected".to_string()),
                    ),
                    detail: report.error.clone(),
                    fix: Some("Install Midnight Lace and allow this localhost page to inspect the wallet API.".to_string()),
                },
                MidnightDoctorCheckV1 {
                    id: "wallet".to_string(),
                    label: "Wallet session".to_string(),
                    required: require_wallet,
                    status: wallet_status,
                    expected: Some(format!("connected {} wallet session", network)),
                    actual: report.network.clone(),
                    detail: report.error.clone(),
                    fix: Some("Approve the Lace wallet connection request and select the expected network.".to_string()),
                },
                MidnightDoctorCheckV1 {
                    id: "dust".to_string(),
                    label: "Spendable tDUST".to_string(),
                    required: require_wallet,
                    status: dust_status,
                    expected: Some("nonzero spendable tDUST".to_string()),
                    actual: report.dust_balance.clone(),
                    detail: report.dust_cap.map(|value| format!("cap={value}")),
                    fix: Some("Fund the connected wallet and wait for tDUST to become spendable.".to_string()),
                },
            )
        }
        Err(error) => {
            let status = if require_wallet {
                MidnightDoctorCheckStatusV1::Fail
            } else {
                MidnightDoctorCheckStatusV1::Warn
            };
            (
                MidnightDoctorCheckV1 {
                    id: "lace".to_string(),
                    label: "Lace availability".to_string(),
                    required: require_wallet,
                    status: status.clone(),
                    expected: Some("window.midnight.mnLace present in a browser".to_string()),
                    actual: None,
                    detail: Some(error.clone()),
                    fix: Some("Allow the browser-assisted Lace check to open, then approve the connection request.".to_string()),
                },
                MidnightDoctorCheckV1 {
                    id: "wallet".to_string(),
                    label: "Wallet session".to_string(),
                    required: require_wallet,
                    status: status.clone(),
                    expected: Some(format!("connected {} wallet session", network)),
                    actual: None,
                    detail: Some(error.clone()),
                    fix: Some("Approve the connection request in Lace and keep the local check page open until it finishes.".to_string()),
                },
                MidnightDoctorCheckV1 {
                    id: "dust".to_string(),
                    label: "Spendable tDUST".to_string(),
                    required: require_wallet,
                    status,
                    expected: Some("nonzero spendable tDUST".to_string()),
                    actual: None,
                    detail: Some(error),
                    fix: Some("Reconnect the wallet and let the browser-assisted check query getDustBalance().".to_string()),
                },
            )
        }
    }
}

fn run_headless_wallet_probe(
    project_root: &Path,
    network: &str,
) -> Result<HeadlessWalletReport, String> {
    let project_root = std::fs::canonicalize(project_root).map_err(|error| {
        format!(
            "failed to resolve Midnight project root {}: {error}",
            project_root.display()
        )
    })?;
    let script_path = project_root.join(format!(
        ".zkf-midnight-wallet-doctor-{}-{}.ts",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default()
    ));
    let script = format!(
        r#"import {{ getRuntimeConfig }} from "./src/midnight/config.ts";
import {{ buildHeadlessWallet, collectDustDiagnostics }} from "./src/midnight/providers.ts";

(async () => {{
  const config = getRuntimeConfig({{ network: "{network}" as never }});
  const provider = await buildHeadlessWallet(config);
  try {{
    const diagnostics = await collectDustDiagnostics(provider);
    console.log(JSON.stringify({{
      network: config.network,
      spendable_dust_raw: diagnostics.spendableDustRaw.toString(),
      spendable_dust_coins: diagnostics.spendableDustCoins,
      registered_night_utxos: diagnostics.registeredNightUtxos
    }}));
  }} finally {{
    await provider.stop();
  }}
}})().catch((error) => {{
  console.error(error);
  process.exit(1);
}});
"#
    );
    fs_err_write(&script_path, script.as_bytes())?;

    let output = if project_root.join("node_modules").exists() {
        let tsx_cli = project_root.join("node_modules/tsx/dist/cli.mjs");
        if !tsx_cli.exists() {
            let _ = std::fs::remove_file(&script_path);
            return Err(format!(
                "project-local tsx CLI is missing at {}",
                tsx_cli.display()
            ));
        }
        Command::new("node")
            .arg(&tsx_cli)
            .arg(&script_path)
            .current_dir(project_root)
            .output()
            .map_err(|error| format!("failed to run headless wallet probe: {error}"))?
    } else {
        let _ = std::fs::remove_file(&script_path);
        return Err(format!(
            "project dependencies are not installed under {}",
            project_root.display()
        ));
    };

    let _ = std::fs::remove_file(&script_path);
    if !output.status.success() {
        return Err(format!(
            "headless wallet probe failed: stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json_line = stdout
        .lines()
        .rev()
        .find(|line| {
            let trimmed = line.trim();
            trimmed.starts_with('{') && trimmed.ends_with('}')
        })
        .ok_or_else(|| {
            format!(
                "failed to find headless wallet probe JSON in stdout: {}",
                stdout.trim()
            )
        })?;
    serde_json::from_str::<HeadlessWalletReport>(json_line)
        .map_err(|error| format!("failed to parse headless wallet probe JSON: {error}"))
}

fn run_browser_lace_check(network: &str, timeout: Duration) -> Result<BrowserWalletReport, String> {
    actix_web::rt::System::new().block_on(async move {
        let state = BrowserReportState {
            report: Arc::new(Mutex::new(None)),
            network: network.to_string(),
        };
        let shared_state = state.clone();
        let server = HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(shared_state.clone()))
                .route("/", web::get().to(browser_check_page))
                .route("/report", web::post().to(browser_check_report))
        })
        .bind(("127.0.0.1", 0))
        .map_err(|error| format!("failed to bind browser wallet check server: {error}"))?;
        let port = server.addrs()[0].port();
        let server = server.run();
        let handle = server.handle();
        actix_web::rt::spawn(server);

        open_browser(&format!("http://127.0.0.1:{port}/"))?;
        let deadline = Instant::now() + timeout;
        let result = loop {
            if let Some(report) = state
                .report
                .lock()
                .map_err(|_| "browser check mutex was poisoned".to_string())?
                .take()
            {
                break Ok(report);
            }
            if Instant::now() >= deadline {
                break Err("timed out waiting for the browser-assisted Lace report".to_string());
            }
            actix_web::rt::time::sleep(Duration::from_millis(250)).await;
        };
        handle.stop(true).await;
        result
    })
}

async fn browser_check_page(state: web::Data<BrowserReportState>) -> impl Responder {
    let html = format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>ZirOS Midnight Lace Check</title>
  </head>
  <body>
    <pre id="status">Checking Midnight Lace...</pre>
    <script>
      const status = document.getElementById("status");
      const report = {{
        lace_detected: Boolean(window.midnight && window.midnight.mnLace),
        connected: false
      }};
      async function submit() {{
        try {{
          if (report.lace_detected) {{
            const wallet = window.midnight.mnLace;
            report.wallet_name = wallet.name ?? null;
            report.wallet_api_version = wallet.apiVersion ?? null;
            const connection = await wallet.connect("{network}");
            await connection.hintUsage([
              "getConnectionStatus",
              "getConfiguration",
              "getDustBalance"
            ]);
            const connectionStatus = await connection.getConnectionStatus();
            const dust = await connection.getDustBalance();
            report.connected = connectionStatus.status === "connected";
            report.network = connectionStatus.networkId ?? null;
            report.dust_balance = dust.balance != null ? String(dust.balance) : null;
            report.dust_cap = dust.cap != null ? String(dust.cap) : null;
            status.textContent = "Midnight Lace check completed.";
          }} else {{
            report.error = "Midnight Lace was not detected in this browser.";
            status.textContent = report.error;
          }}
        }} catch (error) {{
          report.error = error instanceof Error ? error.message : String(error);
          status.textContent = report.error;
        }}
        await fetch("/report", {{
          method: "POST",
          headers: {{ "content-type": "application/json" }},
          body: JSON.stringify(report)
        }});
      }}
      submit();
    </script>
  </body>
</html>"#,
        network = state.network
    );
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

async fn browser_check_report(
    state: web::Data<BrowserReportState>,
    report: web::Json<BrowserWalletReport>,
) -> impl Responder {
    if let Ok(mut slot) = state.report.lock() {
        *slot = Some(report.into_inner());
    }
    HttpResponse::Ok().json(serde_json::json!({ "status": "ok" }))
}

fn open_browser(url: &str) -> Result<(), String> {
    browser_open_report(AgentBrowserOpenRequestV1 {
        url: url.to_string(),
        browser: Some(AgentBrowserKindV1::Default),
        activate: Some(true),
        new_window: Some(false),
    })
    .map(|_| ())
    .map_err(|error| format!("failed to open browser for Lace check: {error}"))
}

fn http_probe_text(url: &str) -> Result<String, String> {
    let request = ureq::get(url).timeout(Duration::from_secs(5));
    match request.call() {
        Ok(response) => response
            .into_string()
            .map_err(|error| format!("failed to read {url}: {error}")),
        Err(ureq::Error::Status(_, response)) => response
            .into_string()
            .map_err(|error| format!("failed to read {url}: {error}")),
        Err(error) => Err(format!("{url}: {error}")),
    }
}

fn http_probe_json(url: &str) -> Result<(u16, Option<Value>), String> {
    let request = ureq::get(url).timeout(Duration::from_secs(5));
    match request.call() {
        Ok(response) => {
            let status = response.status();
            let body = response
                .into_string()
                .map_err(|error| format!("failed to read {url}: {error}"))?;
            Ok((status, serde_json::from_str(&body).ok()))
        }
        Err(ureq::Error::Status(status, response)) => {
            let body = response
                .into_string()
                .map_err(|error| format!("failed to read {url}: {error}"))?;
            Ok((status, serde_json::from_str(&body).ok()))
        }
        Err(error) => Err(format!("{url}: {error}")),
    }
}

fn fs_err_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))
}

impl std::fmt::Display for MidnightNetwork {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(
        id: &str,
        required: bool,
        status: MidnightDoctorCheckStatusV1,
    ) -> MidnightDoctorCheckV1 {
        MidnightDoctorCheckV1 {
            id: id.to_string(),
            label: id.to_string(),
            required,
            status,
            expected: None,
            actual: None,
            detail: None,
            fix: None,
        }
    }

    #[test]
    fn summarize_checks_tracks_all_status_buckets() {
        let summary = summarize_checks(&[
            check("pass", true, MidnightDoctorCheckStatusV1::Pass),
            check("warn", true, MidnightDoctorCheckStatusV1::Warn),
            check("fail", true, MidnightDoctorCheckStatusV1::Fail),
            check(
                "unknown",
                false,
                MidnightDoctorCheckStatusV1::NotCheckableFromCli,
            ),
        ]);

        assert_eq!(summary.total, 4);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.warned, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.not_checkable, 1);
        assert_eq!(summary.overall_status, "fail");
    }

    #[test]
    fn report_has_required_failures_ignores_optional_failures() {
        let optional_fail_report = MidnightDoctorReportV1 {
            schema: "zkf-midnight-doctor-report-v1".to_string(),
            generated_at: "0Z".to_string(),
            network: "preprod".to_string(),
            project_root: None,
            summary: MidnightDoctorSummaryV1 {
                total: 1,
                passed: 0,
                warned: 0,
                failed: 1,
                not_checkable: 0,
                overall_status: "fail".to_string(),
            },
            checks: vec![check("optional", false, MidnightDoctorCheckStatusV1::Fail)],
            recommended_fixes: Vec::new(),
        };
        assert!(!report_has_required_failures(&optional_fail_report));

        let required_fail_report = MidnightDoctorReportV1 {
            checks: vec![check("required", true, MidnightDoctorCheckStatusV1::Fail)],
            ..optional_fail_report
        };
        assert!(report_has_required_failures(&required_fail_report));
    }

    #[test]
    fn package_pins_without_project_remains_not_checkable() {
        let check = package_pins_check(None);
        let expected = expected_midnight_package_lane_label();

        assert_eq!(
            check.status,
            MidnightDoctorCheckStatusV1::NotCheckableFromCli
        );
        assert_eq!(check.expected.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn headless_wallet_without_project_stays_honest_when_optional() {
        let (wallet, dust, lace) = headless_wallet_checks(None, "preprod", false);

        assert_eq!(
            wallet.status,
            MidnightDoctorCheckStatusV1::NotCheckableFromCli
        );
        assert_eq!(
            dust.status,
            MidnightDoctorCheckStatusV1::NotCheckableFromCli
        );
        assert_eq!(lace.status, MidnightDoctorCheckStatusV1::Pass);
        assert_eq!(lace.actual.as_deref(), Some("headless-wallet-mode"));
    }
}
