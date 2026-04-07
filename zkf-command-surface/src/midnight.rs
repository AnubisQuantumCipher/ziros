use crate::types::now_rfc3339;
use crate::truth::{SupportMatrixRowV1, collect_truth_snapshot};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const REQUIRED_COMPACT_MANAGER_VERSION: &str = "0.5.1";
pub const REQUIRED_COMPACTC_VERSION: &str = "0.30.0";
pub const DEFAULT_PROOF_SERVER_URL: &str = "http://127.0.0.1:6300";
pub const DEFAULT_GATEWAY_URL: &str = "http://127.0.0.1:6311";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MidnightNetworkV1 {
    Preprod,
    Preview,
    Local,
    Offline,
}

impl MidnightNetworkV1 {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw {
            "preprod" => Ok(Self::Preprod),
            "preview" => Ok(Self::Preview),
            "local" => Ok(Self::Local),
            "offline" => Ok(Self::Offline),
            other => Err(format!(
                "unknown Midnight network '{other}' (expected preprod, preview, local, or offline)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Preprod => "preprod",
            Self::Preview => "preview",
            Self::Local => "local",
            Self::Offline => "offline",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryStatusV1 {
    pub binary: String,
    pub expected_version: String,
    pub available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointStatusV1 {
    pub url: String,
    pub reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MidnightStatusReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
    pub proof_server: EndpointStatusV1,
    pub gateway: EndpointStatusV1,
    pub compactc: BinaryStatusV1,
    pub compact_manager: BinaryStatusV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub support_matrix_row: Option<SupportMatrixRowV1>,
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_package_summary: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MidnightContractCompileResultV1 {
    pub schema: String,
    pub generated_at: String,
    pub network: String,
    pub source_path: String,
    pub out_dir: String,
    pub zkir_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MidnightContractPrepareReportV1 {
    pub schema: String,
    pub generated_at: String,
    pub network: String,
    pub kind: String,
    pub source_path: String,
    pub out_path: String,
    pub zkir_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inputs_path: Option<String>,
    pub proof_server_url: String,
    pub gateway_url: String,
}

pub fn status(
    network: MidnightNetworkV1,
    project: Option<&Path>,
    proof_server_url: Option<&str>,
    gateway_url: Option<&str>,
) -> Result<MidnightStatusReportV1, String> {
    let project_root = locate_midnight_project_root(project);
    let proof_server_url = proof_server_url.unwrap_or(DEFAULT_PROOF_SERVER_URL);
    let gateway_url = gateway_url.unwrap_or(DEFAULT_GATEWAY_URL);
    let proof_server = probe_endpoint(proof_server_url);
    let gateway = probe_endpoint(gateway_url);
    let compactc = binary_status("compactc", REQUIRED_COMPACTC_VERSION, resolve_compactc_binary());
    let compact_manager = binary_status(
        "compact",
        REQUIRED_COMPACT_MANAGER_VERSION,
        resolve_compact_manager_binary(),
    );
    let support_matrix_row = collect_truth_snapshot()?.support_matrix_midnight_compact;
    let project_package_summary = project_root
        .as_deref()
        .map(compare_project_package_pins)
        .transpose()?;
    let mut blocked_reasons = Vec::new();
    if !proof_server.reachable {
        blocked_reasons.push(format!("proof server is unreachable at {}", proof_server.url));
    }
    if !gateway.reachable {
        blocked_reasons.push(format!("gateway is unreachable at {}", gateway.url));
    }
    if !compactc.available {
        blocked_reasons.push(format!(
            "compactc {} is not available",
            REQUIRED_COMPACTC_VERSION
        ));
    } else if compactc.version.as_deref() != Some(REQUIRED_COMPACTC_VERSION) {
        blocked_reasons.push(format!(
            "compactc version mismatch (expected {}, found {})",
            REQUIRED_COMPACTC_VERSION,
            compactc.version.as_deref().unwrap_or("unknown")
        ));
    }
    if !compact_manager.available {
        blocked_reasons.push(format!(
            "compact manager {} is not available",
            REQUIRED_COMPACT_MANAGER_VERSION
        ));
    } else if compact_manager.version.as_deref() != Some(REQUIRED_COMPACT_MANAGER_VERSION) {
        blocked_reasons.push(format!(
            "compact manager version mismatch (expected {}, found {})",
            REQUIRED_COMPACT_MANAGER_VERSION,
            compact_manager.version.as_deref().unwrap_or("unknown")
        ));
    }
    if let Some(summary) = project_package_summary.as_ref() {
        let matched = summary
            .get("matched")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        let required = summary
            .get("required_total")
            .and_then(Value::as_u64)
            .unwrap_or_default();
        if matched < required {
            blocked_reasons.push(format!(
                "project package pins are incomplete ({matched}/{required} matched)"
            ));
        }
    }
    if let Some(row) = support_matrix_row.as_ref()
        && row.status != "ready"
    {
        blocked_reasons.push(format!(
            "support-matrix marks {} as {}",
            row.id, row.status
        ));
    }
    Ok(MidnightStatusReportV1 {
        schema: "zkf-midnight-status-v1".to_string(),
        generated_at: now_rfc3339(),
        network: network.as_str().to_string(),
        project_root: project_root.map(|path| path.display().to_string()),
        proof_server,
        gateway,
        compactc,
        compact_manager,
        support_matrix_row,
        ready: blocked_reasons.is_empty(),
        blocked_reasons,
        project_package_summary,
    })
}

pub fn compile_contract(
    network: MidnightNetworkV1,
    source_path: &Path,
    out_dir: &Path,
) -> Result<MidnightContractCompileResultV1, String> {
    let compactc = resolve_compactc_binary().ok_or_else(|| {
        format!("compactc was not found; install compactc {REQUIRED_COMPACTC_VERSION} first")
    })?;
    let version = binary_version(&compactc, ["--version"])?;
    if version != REQUIRED_COMPACTC_VERSION {
        return Err(format!(
            "compactc {} is installed at {}, but {} is required",
            version,
            compactc.display(),
            REQUIRED_COMPACTC_VERSION
        ));
    }
    fs::create_dir_all(out_dir)
        .map_err(|error| format!("failed to create {}: {error}", out_dir.display()))?;
    let output = Command::new(&compactc)
        .arg(source_path)
        .arg(out_dir)
        .output()
        .map_err(|error| format!("failed to run {}: {error}", compactc.display()))?;
    if !output.status.success() {
        return Err(format!(
            "compactc failed for {}: stdout={}; stderr={}",
            source_path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let zkir_path = discover_first_zkir(out_dir).ok_or_else(|| {
        format!(
            "compactc succeeded for {} but no .zkir file was emitted under {}",
            source_path.display(),
            out_dir.display()
        )
    })?;
    Ok(MidnightContractCompileResultV1 {
        schema: "zkf-midnight-contract-compile-v1".to_string(),
        generated_at: now_rfc3339(),
        network: network.as_str().to_string(),
        source_path: source_path.display().to_string(),
        out_dir: out_dir.display().to_string(),
        zkir_path: zkir_path.display().to_string(),
    })
}

pub fn deploy_prepare(
    network: MidnightNetworkV1,
    source_path: &Path,
    out_path: &Path,
    proof_server_url: Option<&str>,
    gateway_url: Option<&str>,
    project: Option<&Path>,
) -> Result<MidnightContractPrepareReportV1, String> {
    let status = status(network, project, proof_server_url, gateway_url)?;
    if !status.ready {
        return Err(format!(
            "Midnight deploy-prepare blocked: {}",
            status.blocked_reasons.join("; ")
        ));
    }
    let compile = compile_contract(
        network,
        source_path,
        out_path.parent().unwrap_or_else(|| Path::new(".")),
    )?;
    let report = MidnightContractPrepareReportV1 {
        schema: "zkf-midnight-contract-deploy-prepare-v1".to_string(),
        generated_at: now_rfc3339(),
        network: network.as_str().to_string(),
        kind: "deploy-prepare".to_string(),
        source_path: source_path.display().to_string(),
        out_path: out_path.display().to_string(),
        zkir_path: compile.zkir_path,
        call_name: None,
        inputs_path: None,
        proof_server_url: status.proof_server.url,
        gateway_url: status.gateway.url,
    };
    write_json(out_path, &report)?;
    Ok(report)
}

pub fn call_prepare(
    network: MidnightNetworkV1,
    source_path: &Path,
    call_name: &str,
    inputs_path: &Path,
    out_path: &Path,
    proof_server_url: Option<&str>,
    gateway_url: Option<&str>,
    project: Option<&Path>,
) -> Result<MidnightContractPrepareReportV1, String> {
    if !inputs_path.exists() {
        return Err(format!("call inputs file does not exist: {}", inputs_path.display()));
    }
    let status = status(network, project, proof_server_url, gateway_url)?;
    if !status.ready {
        return Err(format!(
            "Midnight call-prepare blocked: {}",
            status.blocked_reasons.join("; ")
        ));
    }
    let compile = compile_contract(
        network,
        source_path,
        out_path.parent().unwrap_or_else(|| Path::new(".")),
    )?;
    let report = MidnightContractPrepareReportV1 {
        schema: "zkf-midnight-contract-call-prepare-v1".to_string(),
        generated_at: now_rfc3339(),
        network: network.as_str().to_string(),
        kind: "call-prepare".to_string(),
        source_path: source_path.display().to_string(),
        out_path: out_path.display().to_string(),
        zkir_path: compile.zkir_path,
        call_name: Some(call_name.to_string()),
        inputs_path: Some(inputs_path.display().to_string()),
        proof_server_url: status.proof_server.url,
        gateway_url: status.gateway.url,
    };
    write_json(out_path, &report)?;
    Ok(report)
}

pub fn locate_midnight_project_root(provided: Option<&Path>) -> Option<PathBuf> {
    if let Some(path) = provided {
        let normalized = if path.is_file() {
            path.parent().unwrap_or(path).to_path_buf()
        } else {
            path.to_path_buf()
        };
        return find_ancestor_with_file(&normalized, "package.json");
    }
    env::current_dir()
        .ok()
        .and_then(|cwd| find_ancestor_with_file(&cwd, "package.json"))
}

fn find_ancestor_with_file(start: &Path, file_name: &str) -> Option<PathBuf> {
    let mut current = Some(start);
    while let Some(path) = current {
        if path.join(file_name).exists() {
            return Some(path.to_path_buf());
        }
        current = path.parent();
    }
    None
}

fn compare_project_package_pins(project_root: &Path) -> Result<Value, String> {
    let package_json_path = project_root.join("package.json");
    let value = read_json(&package_json_path)?;
    let versions = collect_package_versions(&value);
    let required = [
        ("@midnight-ntwrk/compact-js", "2.5.0"),
        ("@midnight-ntwrk/compact-runtime", "0.15.0"),
        ("@midnight-ntwrk/ledger-v8", "8.0.3"),
        ("@midnight-ntwrk/midnight-js-network-id", "4.0.2"),
    ];
    let mut matched = 0u64;
    let mut missing = Vec::new();
    let mut mismatched = Vec::new();
    for (name, version) in required {
        match versions.get(name) {
            Some(found) if found == version => matched += 1,
            Some(found) => mismatched.push(format!("{name} expected {version}, found {found}")),
            None => missing.push(name.to_string()),
        }
    }
    Ok(json!({
        "required_total": required.len(),
        "matched": matched,
        "missing": missing,
        "mismatched": mismatched,
    }))
}

fn collect_package_versions(value: &Value) -> BTreeMap<String, String> {
    let mut versions = BTreeMap::new();
    for section in ["dependencies", "devDependencies"] {
        if let Some(map) = value.get(section).and_then(Value::as_object) {
            for (name, version) in map {
                if let Some(version) = version.as_str() {
                    versions.insert(name.clone(), version.to_string());
                }
            }
        }
    }
    versions
}

fn probe_endpoint(url: &str) -> EndpointStatusV1 {
    match ureq::get(url).call() {
        Ok(response) => EndpointStatusV1 {
            url: url.to_string(),
            reachable: true,
            status_code: Some(response.status()),
            error: None,
        },
        Err(ureq::Error::Status(status, _)) => EndpointStatusV1 {
            url: url.to_string(),
            reachable: true,
            status_code: Some(status),
            error: None,
        },
        Err(error) => EndpointStatusV1 {
            url: url.to_string(),
            reachable: false,
            status_code: None,
            error: Some(error.to_string()),
        },
    }
}

fn binary_status(
    binary: &str,
    expected_version: &str,
    resolved_path: Option<PathBuf>,
) -> BinaryStatusV1 {
    match resolved_path {
        Some(path) => match binary_version(&path, version_args(binary)) {
            Ok(version) => BinaryStatusV1 {
                binary: binary.to_string(),
                expected_version: expected_version.to_string(),
                available: true,
                resolved_path: Some(path.display().to_string()),
                version: Some(version),
                error: None,
            },
            Err(error) => BinaryStatusV1 {
                binary: binary.to_string(),
                expected_version: expected_version.to_string(),
                available: true,
                resolved_path: Some(path.display().to_string()),
                version: None,
                error: Some(error),
            },
        },
        None => BinaryStatusV1 {
            binary: binary.to_string(),
            expected_version: expected_version.to_string(),
            available: false,
            resolved_path: None,
            version: None,
            error: Some("binary not found on PATH".to_string()),
        },
    }
}

fn version_args(binary: &str) -> [&str; 2] {
    match binary {
        "compact" => ["compile", "--version"],
        _ => ["--version", ""],
    }
}

fn resolve_compactc_binary() -> Option<PathBuf> {
    search_path_for_binary("compactc")
}

fn resolve_compact_manager_binary() -> Option<PathBuf> {
    search_path_for_binary("compact")
}

fn search_path_for_binary(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|entry| entry.join(name))
        .find(|candidate| candidate.is_file())
}

fn binary_version<I, S>(binary: &Path, args: I) -> Result<String, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(binary)
        .args(args.into_iter().filter(|arg| !arg.as_ref().is_empty()))
        .output()
        .map_err(|error| format!("failed to run {}: {error}", binary.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} exited with status {}",
            binary.display(),
            output.status
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|error| format!("{} returned non-utf8 output: {error}", binary.display()))?;
    extract_semver_token(&stdout).ok_or_else(|| {
        format!(
            "failed to parse a semantic version from {} output: {}",
            binary.display(),
            stdout.trim()
        )
    })
}

fn extract_semver_token(raw: &str) -> Option<String> {
    raw.split_whitespace()
        .find(|token| {
            token
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_digit())
                && token.contains('.')
        })
        .map(|token| token.trim().trim_matches(',').to_string())
}

fn discover_first_zkir(root: &Path) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        if path.is_dir() {
            for entry in fs::read_dir(&path).ok()?.filter_map(Result::ok) {
                stack.push(entry.path());
            }
            continue;
        }
        if path.extension().is_some_and(|extension| extension == "zkir") {
            return Some(path);
        }
    }
    None
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| error.to_string())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    fs::write(path, bytes).map_err(|error| format!("{}: {error}", path.display()))
}
