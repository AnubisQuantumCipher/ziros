use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use zkf_backends::foundry_test::generate_foundry_test_from_artifact;
use zkf_core::{BackendKind, ProofArtifact};
use zkf_lib::app::evidence::ensure_foundry_layout;

use crate::cli::{EvmCommands, EvmFoundryCommands, EvmVerifierCommands};
use crate::cmd::{deploy, estimate_gas};
use crate::solidity::parse_evm_target;
use crate::util::{parse_backend, read_json, write_text};

const DEFAULT_ANVIL_RPC_URL: &str = "http://127.0.0.1:8545";
const DEFAULT_ANVIL_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

pub(crate) fn handle_evm(command: EvmCommands) -> Result<(), String> {
    match command {
        EvmCommands::Verifier { command } => match command {
            EvmVerifierCommands::Export {
                artifact,
                backend,
                out,
                contract_name,
                evm_target,
                json,
            } => deploy::handle_deploy(artifact, backend, out, contract_name, evm_target, json),
        },
        EvmCommands::EstimateGas {
            backend,
            artifact,
            proof_size,
            evm_target,
            json,
        } => estimate_gas::handle_estimate_gas(backend, artifact, proof_size, evm_target, json),
        EvmCommands::Foundry { command } => match command {
            EvmFoundryCommands::Init {
                solidity,
                out,
                contract_name,
                artifact,
                backend,
                json,
            } => handle_foundry_init(solidity, out, contract_name, artifact, backend, json),
        },
        EvmCommands::Deploy {
            project,
            contract,
            rpc_url,
            private_key,
            constructor_arg,
            json,
        } => handle_deploy(
            project,
            contract,
            rpc_url,
            private_key,
            constructor_arg,
            json,
        ),
        EvmCommands::Call {
            rpc_url,
            to,
            signature,
            arg,
            private_key,
            send,
            json,
        } => handle_call(rpc_url, to, signature, arg, private_key, send, json),
        EvmCommands::Test { project, json } => handle_test(project, json),
        EvmCommands::Diagnose { project, json } => handle_diagnose(project, json),
    }
}

#[derive(Debug, Serialize)]
struct EvmFoundryProjectBundleV1 {
    schema: String,
    generated_at: String,
    project_root: String,
    solidity_path: String,
    contract_name: String,
    foundry_toml_path: String,
    verifier_contract_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    test_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backend: Option<String>,
}

#[derive(Debug, Serialize)]
struct EvmToolStatusV1 {
    tool: String,
    available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct EvmDiagnoseReportV1 {
    schema: String,
    generated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_root: Option<String>,
    ready: bool,
    forge: EvmToolStatusV1,
    anvil: EvmToolStatusV1,
    cast: EvmToolStatusV1,
    blockers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct EvmForgeRunReportV1 {
    schema: String,
    generated_at: String,
    project_root: String,
    action: String,
    command: Vec<String>,
    ok: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct EvmDeployReportV1 {
    schema: String,
    generated_at: String,
    project_root: String,
    contract: String,
    rpc_url: String,
    used_private_key_profile: String,
    constructor_args: Vec<String>,
    ok: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct EvmCallReportV1 {
    schema: String,
    generated_at: String,
    rpc_url: String,
    to: String,
    signature: String,
    args: Vec<String>,
    send: bool,
    ok: bool,
    stdout: String,
    stderr: String,
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn handle_foundry_init(
    solidity: PathBuf,
    out: PathBuf,
    contract_name: Option<String>,
    artifact: Option<PathBuf>,
    backend: Option<String>,
    json: bool,
) -> Result<(), String> {
    if !solidity.is_file() {
        return Err(format!(
            "solidity source does not exist: {}",
            solidity.display()
        ));
    }
    let project_root = out.join("foundry");
    ensure_foundry_layout(&project_root).map_err(|error| error.to_string())?;

    let contract_name = contract_name.unwrap_or_else(|| {
        solidity
            .file_stem()
            .and_then(|value| value.to_str())
            .unwrap_or("Verifier")
            .to_string()
    });
    let verifier_contract_path = project_root
        .join("src")
        .join(format!("{contract_name}.sol"));
    fs::copy(&solidity, &verifier_contract_path).map_err(|error| {
        format!(
            "failed to copy {} -> {}: {error}",
            solidity.display(),
            verifier_contract_path.display()
        )
    })?;

    let test_path = if let (Some(artifact_path), Some(backend_name)) =
        (artifact.as_ref(), backend.as_deref())
    {
        let backend_kind = parse_backend(backend_name)?;
        if backend_kind == BackendKind::ArkworksGroth16 {
            let artifact_data: ProofArtifact = read_json(artifact_path)?;
            let output = generate_foundry_test_from_artifact(
                &artifact_data.proof,
                &artifact_data.public_inputs,
                &format!("../src/{contract_name}.sol"),
                &contract_name,
            )?;
            let path = project_root
                .join("test")
                .join(format!("{contract_name}.t.sol"));
            write_text(&path, &output.source)?;
            Some(path)
        } else {
            None
        }
    } else {
        None
    };

    let report = EvmFoundryProjectBundleV1 {
        schema: "zkf-evm-foundry-project-v1".to_string(),
        generated_at: now_rfc3339(),
        project_root: project_root.display().to_string(),
        solidity_path: solidity.display().to_string(),
        contract_name: contract_name.clone(),
        foundry_toml_path: project_root.join("foundry.toml").display().to_string(),
        verifier_contract_path: verifier_contract_path.display().to_string(),
        test_path: test_path.map(|path| path.display().to_string()),
        artifact_path: artifact.map(|path| path.display().to_string()),
        backend,
    };
    print_json_or_human(
        json,
        &report,
        &format!(
            "evm foundry bundle: contract={} -> {}",
            contract_name,
            project_root.display()
        ),
    )
}

fn handle_diagnose(project: Option<PathBuf>, json: bool) -> Result<(), String> {
    let forge = tool_status("forge", &["--version"]);
    let anvil = tool_status("anvil", &["--version"]);
    let cast = tool_status("cast", &["--version"]);
    let mut blockers = Vec::new();
    for tool in [&forge, &anvil, &cast] {
        if !tool.available {
            blockers.push(format!("{} is not available on PATH", tool.tool));
        }
    }
    if let Some(project_root) = project.as_ref() {
        if !project_root.join("foundry.toml").is_file() {
            blockers.push(format!(
                "{} is missing foundry.toml",
                project_root.display()
            ));
        }
        if !project_root.join("src").is_dir() {
            blockers.push(format!("{} is missing src/", project_root.display()));
        }
        if !project_root.join("test").is_dir() {
            blockers.push(format!("{} is missing test/", project_root.display()));
        }
    }
    let report = EvmDiagnoseReportV1 {
        schema: "zkf-evm-diagnose-v1".to_string(),
        generated_at: now_rfc3339(),
        project_root: project.as_ref().map(|path| path.display().to_string()),
        ready: blockers.is_empty(),
        forge,
        anvil,
        cast,
        blockers,
    };
    print_json_or_human(
        json,
        &report,
        &format!(
            "evm diagnose: {}",
            if report.ready { "ready" } else { "blocked" }
        ),
    )
}

fn handle_test(project: PathBuf, json: bool) -> Result<(), String> {
    let report = run_forge_command(&project, "test", &["test"])?;
    print_json_or_human(
        json,
        &report,
        &format!("evm test: {} -> {}", report.action, project.display()),
    )
}

fn handle_deploy(
    project: PathBuf,
    contract: String,
    rpc_url: Option<String>,
    private_key: Option<String>,
    constructor_args: Vec<String>,
    json: bool,
) -> Result<(), String> {
    ensure_foundry_project(&project)?;
    let rpc_url = rpc_url.unwrap_or_else(|| DEFAULT_ANVIL_RPC_URL.to_string());
    let (resolved_private_key, private_key_profile) =
        resolve_private_key(private_key.as_deref(), &rpc_url)?;
    let mut command = Command::new("forge");
    command
        .current_dir(&project)
        .arg("create")
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg("--private-key")
        .arg(&resolved_private_key)
        .arg(&contract);
    if !constructor_args.is_empty() {
        command.arg("--constructor-args").args(&constructor_args);
    }
    let output = command
        .output()
        .map_err(|error| format!("failed to run forge create: {error}"))?;
    let report = EvmDeployReportV1 {
        schema: "zkf-evm-deploy-v1".to_string(),
        generated_at: now_rfc3339(),
        project_root: project.display().to_string(),
        contract,
        rpc_url,
        used_private_key_profile: private_key_profile,
        constructor_args,
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    };
    if !report.ok {
        let payload = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        return Err(payload);
    }
    print_json_or_human(
        json,
        &report,
        &format!("evm deploy: {} -> {}", report.contract, report.project_root),
    )
}

fn handle_call(
    rpc_url: String,
    to: String,
    signature: String,
    args: Vec<String>,
    private_key: Option<String>,
    send: bool,
    json: bool,
) -> Result<(), String> {
    let mut command = if send {
        Command::new("cast")
    } else {
        Command::new("cast")
    };
    command.arg(if send { "send" } else { "call" });
    command
        .arg("--rpc-url")
        .arg(&rpc_url)
        .arg(&to)
        .arg(&signature);
    for value in &args {
        command.arg(value);
    }
    if send {
        let (resolved_private_key, _) = resolve_private_key(private_key.as_deref(), &rpc_url)?;
        command.arg("--private-key").arg(resolved_private_key);
    }
    let output = command.output().map_err(|error| {
        format!(
            "failed to run cast {}: {error}",
            if send { "send" } else { "call" }
        )
    })?;
    let report = EvmCallReportV1 {
        schema: "zkf-evm-call-v1".to_string(),
        generated_at: now_rfc3339(),
        rpc_url,
        to,
        signature,
        args,
        send,
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    };
    if !report.ok {
        let payload = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
        return Err(payload);
    }
    print_json_or_human(
        json,
        &report,
        &format!("evm call: {} {}", report.to, report.signature),
    )
}

fn tool_status(tool: &str, args: &[&str]) -> EvmToolStatusV1 {
    match Command::new(tool).args(args).output() {
        Ok(output) if output.status.success() => EvmToolStatusV1 {
            tool: tool.to_string(),
            available: true,
            version: Some(first_line(&output.stdout)),
            note: None,
        },
        Ok(output) => EvmToolStatusV1 {
            tool: tool.to_string(),
            available: false,
            version: None,
            note: Some(String::from_utf8_lossy(&output.stderr).trim().to_string()),
        },
        Err(error) => EvmToolStatusV1 {
            tool: tool.to_string(),
            available: false,
            version: None,
            note: Some(error.to_string()),
        },
    }
}

fn first_line(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

fn run_forge_command(
    project: &Path,
    action: &str,
    args: &[&str],
) -> Result<EvmForgeRunReportV1, String> {
    ensure_foundry_project(project)?;
    let output = Command::new("forge")
        .current_dir(project)
        .args(args)
        .output()
        .map_err(|error| format!("failed to run forge {}: {error}", args.join(" ")))?;
    let report = EvmForgeRunReportV1 {
        schema: "zkf-evm-forge-run-v1".to_string(),
        generated_at: now_rfc3339(),
        project_root: project.display().to_string(),
        action: action.to_string(),
        command: std::iter::once("forge".to_string())
            .chain(args.iter().map(|value| (*value).to_string()))
            .collect(),
        ok: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    };
    if report.ok {
        Ok(report)
    } else {
        Err(serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?)
    }
}

fn ensure_foundry_project(project: &Path) -> Result<(), String> {
    if !project.join("foundry.toml").is_file() {
        return Err(format!(
            "{} is not a Foundry project (missing foundry.toml)",
            project.display()
        ));
    }
    Ok(())
}

fn resolve_private_key(
    private_key: Option<&str>,
    rpc_url: &str,
) -> Result<(String, String), String> {
    if let Some(value) = private_key {
        return Ok((value.to_string(), "explicit".to_string()));
    }
    if rpc_url == DEFAULT_ANVIL_RPC_URL {
        return Ok((
            DEFAULT_ANVIL_PRIVATE_KEY.to_string(),
            "anvil-default".to_string(),
        ));
    }
    Err("live EVM deploy/call requires --private-key unless targeting the default local Anvil harness".to_string())
}

fn print_json_or_human<T: Serialize>(json: bool, value: &T, human: &str) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(value).map_err(|error| error.to_string())?
        );
    } else {
        println!("{human}");
    }
    Ok(())
}

#[allow(dead_code)]
fn _parse_evm_target_guard(value: &str) -> Result<(), String> {
    parse_evm_target(Some(value)).map(|_| ())
}
