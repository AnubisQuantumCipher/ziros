use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

use super::shared::{
    MidnightNetwork, MidnightPackageManifestV1, REQUIRED_COMPACTC_VERSION, compactc_version,
    compile_compact_contract, locate_midnight_project_root, midnight_package_manifest,
    network_config, resolve_compactc_binary,
};

const MIDNIGHT_RESOLVE_SCHEMA_V1: &str = "zkf-midnight-resolve-report-v1";
const MIDNIGHT_RESOLVE_FAMILY: &str = "v4-stable";
const MAX_COMMAND_OUTPUT_CHARS: usize = 240;

#[derive(Debug, Clone)]
pub(crate) struct ResolveArgs {
    pub(crate) network: String,
    pub(crate) project: Option<PathBuf>,
    pub(crate) dry_run: bool,
    pub(crate) skip_install: bool,
    pub(crate) skip_compile: bool,
    pub(crate) skip_test: bool,
    pub(crate) json: bool,
    pub(crate) verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PackageMismatch {
    pub package: String,
    pub installed: String,
    pub required: String,
    pub section: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResolveStepStatus {
    Passed,
    Failed,
    Skipped,
}

impl ResolveStepStatus {
    fn as_human(self) -> &'static str {
        match self {
            Self::Passed => "PASSED",
            Self::Failed => "FAILED",
            Self::Skipped => "SKIPPED",
        }
    }

    fn is_failed(self) -> bool {
        matches!(self, Self::Failed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolveStepReportV1 {
    status: ResolveStepStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolveCompileStepReportV1 {
    status: ResolveStepStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    compactc_version: Option<String>,
    contracts_compiled: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolveTestStepReportV1 {
    status: ResolveStepStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strategy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResolveReportV1 {
    schema: String,
    network: String,
    project_root: String,
    family: String,
    mismatches_found: usize,
    mismatches_fixed: usize,
    mismatches: Vec<PackageMismatch>,
    dry_run: bool,
    npm_install: ResolveStepReportV1,
    compile: ResolveCompileStepReportV1,
    test: ResolveTestStepReportV1,
}

impl ResolveReportV1 {
    fn has_failures(&self) -> bool {
        self.npm_install.status.is_failed()
            || self.compile.status.is_failed()
            || self.test.status.is_failed()
    }
}

#[derive(Debug, Clone)]
struct ResolveExecution {
    report: ResolveReportV1,
    terminal_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectPackageVersion {
    section: String,
    version: String,
}

pub(crate) fn handle_resolve(args: ResolveArgs) -> Result<(), String> {
    let json = args.json;
    let execution = execute_resolve(&args)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&execution.report).map_err(|error| error.to_string())?
        );
    } else {
        print!("{}", render_human_report(&execution.report)?);
    }
    if let Some(error) = execution.terminal_error {
        return Err(error);
    }
    Ok(())
}

fn execute_resolve(args: &ResolveArgs) -> Result<ResolveExecution, String> {
    let network = MidnightNetwork::parse(&args.network)?;
    let project_root = locate_midnight_project_root(args.project.as_deref()).ok_or_else(|| {
        "failed to locate a Midnight project root (no package.json found from --project or cwd)"
            .to_string()
    })?;
    let manifest = midnight_package_manifest()?;
    let package_json_path = project_root.join("package.json");
    let mut package_json = load_package_json(&package_json_path)?;
    let mismatches = detect_package_mismatches(&manifest, &package_json)?;

    let mut report = ResolveReportV1 {
        schema: MIDNIGHT_RESOLVE_SCHEMA_V1.to_string(),
        network: network.as_str().to_string(),
        project_root: project_root.display().to_string(),
        family: MIDNIGHT_RESOLVE_FAMILY.to_string(),
        mismatches_found: mismatches.len(),
        mismatches_fixed: 0,
        mismatches,
        dry_run: args.dry_run,
        npm_install: skipped_step("dry run"),
        compile: skipped_compile_step("dry run"),
        test: skipped_test_step("dry run"),
    };

    if args.dry_run {
        return Ok(ResolveExecution {
            report,
            terminal_error: None,
        });
    }

    if !report.mismatches.is_empty() {
        rewrite_package_json_versions(&mut package_json, &report.mismatches)?;
        write_package_json(&package_json_path, &package_json)?;
        report.mismatches_fixed = report.mismatches.len();
    }

    if args.skip_install {
        report.npm_install = skipped_step("--skip-install");
    } else {
        report.npm_install = run_npm_install(&project_root, args.verbose);
        if report.npm_install.status.is_failed() {
            report.compile = skipped_compile_step("not run because npm install failed");
            report.test = skipped_test_step("not run because npm install failed");
            return Ok(ResolveExecution {
                report,
                terminal_error: Some(
                    "midnight resolve failed: npm install step failed".to_string(),
                ),
            });
        }
    }

    if args.skip_compile {
        report.compile = skipped_compile_step("--skip-compile");
    } else {
        report.compile = run_compile_step(&project_root, args.verbose);
        if report.compile.status.is_failed() {
            report.test = skipped_test_step("not run because compile step failed");
            return Ok(ResolveExecution {
                report,
                terminal_error: Some("midnight resolve failed: compile step failed".to_string()),
            });
        }
    }

    if args.skip_test {
        report.test = skipped_test_step("--skip-test");
    } else {
        let config = network_config(network, None, None);
        report.test = run_validation_step(&project_root, &network, &config, args.verbose);
        if report.test.status.is_failed() {
            return Ok(ResolveExecution {
                report,
                terminal_error: Some("midnight resolve failed: validation step failed".to_string()),
            });
        }
    }

    Ok(ResolveExecution {
        report,
        terminal_error: None,
    })
}

fn load_package_json(path: &Path) -> Result<Value, String> {
    let raw = fs::read_to_string(path)
        .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    let value: Value = serde_json::from_str(&raw)
        .map_err(|error| format!("failed to parse {}: {error}", path.display()))?;
    if !value.is_object() {
        return Err(format!(
            "{} must contain a top-level JSON object",
            path.display()
        ));
    }
    Ok(value)
}

fn detect_package_mismatches(
    manifest: &MidnightPackageManifestV1,
    package_json: &Value,
) -> Result<Vec<PackageMismatch>, String> {
    let package_versions = collect_package_json_versions(package_json)?;
    let mut mismatches = Vec::new();
    for pin in &manifest.packages {
        let Some(found) = package_versions.get(&pin.name) else {
            continue;
        };
        if found.version != pin.version {
            mismatches.push(PackageMismatch {
                package: pin.name.clone(),
                installed: found.version.clone(),
                required: pin.version.clone(),
                section: found.section.clone(),
            });
        }
    }
    Ok(mismatches)
}

fn collect_package_json_versions(
    package_json: &Value,
) -> Result<BTreeMap<String, ProjectPackageVersion>, String> {
    let mut versions = BTreeMap::new();
    for section in ["dependencies", "devDependencies"] {
        let Some(raw_section) = package_json.get(section) else {
            continue;
        };
        let map = raw_section
            .as_object()
            .ok_or_else(|| format!("package.json section '{section}' must be an object"))?;
        for (name, version) in map {
            if !name.starts_with("@midnight-ntwrk/") {
                continue;
            }
            let version = version.as_str().ok_or_else(|| {
                format!("package.json entry '{name}' in '{section}' must be a string version")
            })?;
            if versions.contains_key(name) {
                return Err(format!(
                    "package.json entry '{name}' is duplicated across dependency sections"
                ));
            }
            versions.insert(
                name.clone(),
                ProjectPackageVersion {
                    section: section.to_string(),
                    version: version.to_string(),
                },
            );
        }
    }
    Ok(versions)
}

fn rewrite_package_json_versions(
    package_json: &mut Value,
    mismatches: &[PackageMismatch],
) -> Result<(), String> {
    let root = package_json
        .as_object_mut()
        .ok_or_else(|| "package.json root must be an object".to_string())?;
    for mismatch in mismatches {
        let section = root
            .get_mut(&mismatch.section)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| {
                format!(
                    "package.json section '{}' is missing or invalid",
                    mismatch.section
                )
            })?;
        let entry = section
            .get_mut(&mismatch.package)
            .ok_or_else(|| format!("package.json entry '{}' is missing", mismatch.package))?;
        *entry = Value::String(mismatch.required.clone());
    }
    Ok(())
}

fn write_package_json(path: &Path, package_json: &Value) -> Result<(), String> {
    let content = serde_json::to_vec_pretty(package_json).map_err(|error| error.to_string())?;
    fs::write(path, content).map_err(|error| format!("failed to write {}: {error}", path.display()))
}

fn run_npm_install(project_root: &Path, verbose: bool) -> ResolveStepReportV1 {
    let start = Instant::now();
    let output = match Command::new("npm")
        .arg("install")
        .current_dir(project_root)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return failed_step(
                format!(
                    "failed to run npm install in {}: {error}",
                    project_root.display()
                ),
                start.elapsed().as_millis(),
            );
        }
    };
    log_command_output(
        verbose,
        "npm install",
        project_root,
        &output.stdout,
        &output.stderr,
    );
    if output.status.success() {
        ResolveStepReportV1 {
            status: ResolveStepStatus::Passed,
            duration_ms: Some(start.elapsed().as_millis()),
            detail: Some("npm install completed".to_string()),
        }
    } else {
        failed_step(
            format!(
                "npm install exited with {} ({})",
                output.status,
                summarize_output(&output)
            ),
            start.elapsed().as_millis(),
        )
    }
}

fn run_compile_step(project_root: &Path, verbose: bool) -> ResolveCompileStepReportV1 {
    let contracts_dir = project_root.join("contracts").join("compact");
    if !contracts_dir.exists() {
        return skipped_compile_step("no contracts/compact directory found");
    }

    let mut contract_paths = match direct_compact_contracts(&contracts_dir) {
        Ok(paths) => paths,
        Err(error) => return failed_compile_step(error, None, 0, None),
    };
    if contract_paths.is_empty() {
        return skipped_compile_step("no .compact contracts found");
    }
    contract_paths.sort();

    let compactc = match resolve_compactc_binary() {
        Some(path) => path,
        None => {
            return failed_compile_step(
                format!(
                    "compactc was not found; install compactc {REQUIRED_COMPACTC_VERSION} first"
                ),
                None,
                0,
                None,
            );
        }
    };
    let compactc_version = match compactc_version(&compactc) {
        Ok(version) => version,
        Err(error) => return failed_compile_step(error, None, 0, None),
    };

    let start = Instant::now();
    let compiled_root = project_root.join("contracts").join("compiled");
    let mut compiled = 0usize;
    for contract_path in contract_paths {
        let Some(stem) = contract_path.file_stem().and_then(|value| value.to_str()) else {
            return failed_compile_step(
                format!(
                    "failed to derive a contract name from {}",
                    contract_path.display()
                ),
                Some(compactc_version),
                compiled,
                Some(start.elapsed().as_millis()),
            );
        };
        let out_dir = compiled_root.join(stem);
        if verbose {
            eprintln!(
                "[midnight resolve] compiling {} -> {}",
                contract_path.display(),
                out_dir.display()
            );
        }
        if let Err(error) = compile_compact_contract(&contract_path, &out_dir) {
            return failed_compile_step(
                error,
                Some(compactc_version),
                compiled,
                Some(start.elapsed().as_millis()),
            );
        }
        compiled += 1;
    }

    ResolveCompileStepReportV1 {
        status: ResolveStepStatus::Passed,
        duration_ms: Some(start.elapsed().as_millis()),
        detail: Some(format!("compiled {compiled} contract(s)")),
        compactc_version: Some(compactc_version),
        contracts_compiled: compiled,
    }
}

fn direct_compact_contracts(contracts_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for entry in fs::read_dir(contracts_dir)
        .map_err(|error| format!("failed to read {}: {error}", contracts_dir.display()))?
    {
        let entry = entry
            .map_err(|error| format!("failed to iterate {}: {error}", contracts_dir.display()))?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "compact")
        {
            paths.push(path);
        }
    }
    Ok(paths)
}

fn run_validation_step(
    project_root: &Path,
    network: &MidnightNetwork,
    network_cfg: &super::shared::MidnightNetworkConfig,
    verbose: bool,
) -> ResolveTestStepReportV1 {
    let start = Instant::now();
    let compactc = match resolve_compactc_binary() {
        Some(path) => path,
        None => {
            return failed_test_step(
                format!(
                    "compactc was not found; install compactc {REQUIRED_COMPACTC_VERSION} first"
                ),
                Some("local-structural-validation".to_string()),
                Some(start.elapsed().as_millis()),
            );
        }
    };
    let compactc_version = match compactc_version(&compactc) {
        Ok(version) => version,
        Err(error) => {
            return failed_test_step(
                error,
                Some("local-structural-validation".to_string()),
                Some(start.elapsed().as_millis()),
            );
        }
    };
    if compactc_version != REQUIRED_COMPACTC_VERSION {
        return failed_test_step(
            format!(
                "compactc {} is installed at {}, but {} is required",
                compactc_version,
                compactc.display(),
                REQUIRED_COMPACTC_VERSION
            ),
            Some("local-structural-validation".to_string()),
            Some(start.elapsed().as_millis()),
        );
    }

    if let Some(probe_binary) = resolve_midnight_probe_binary(project_root)
        && probe_supports_test_deploy(&probe_binary)
    {
        let output = Command::new(&probe_binary)
            .arg("test-deploy")
            .arg("--network")
            .arg(network.as_str())
            .env("MIDNIGHT_RPC_URL", &network_cfg.rpc_url)
            .env("MIDNIGHT_INDEXER_URL", &network_cfg.indexer_url)
            .env("MIDNIGHT_EXPLORER_URL", &network_cfg.explorer_url)
            .current_dir(project_root)
            .output();
        let elapsed = start.elapsed().as_millis();
        match output {
            Ok(output) => {
                log_command_output(
                    verbose,
                    "midnight-probe test-deploy",
                    project_root,
                    &output.stdout,
                    &output.stderr,
                );
                if output.status.success() {
                    return ResolveTestStepReportV1 {
                        status: ResolveStepStatus::Passed,
                        duration_ms: Some(elapsed),
                        detail: Some("midnight-probe test-deploy completed".to_string()),
                        strategy: Some("midnight-probe-test-deploy".to_string()),
                    };
                }
                return failed_test_step(
                    format!(
                        "midnight-probe test-deploy exited with {} ({})",
                        output.status,
                        summarize_output(&output)
                    ),
                    Some("midnight-probe-test-deploy".to_string()),
                    Some(elapsed),
                );
            }
            Err(error) => {
                return failed_test_step(
                    format!("failed to run {}: {error}", probe_binary.display()),
                    Some("midnight-probe-test-deploy".to_string()),
                    Some(elapsed),
                );
            }
        }
    }

    let compiled_root = project_root.join("contracts").join("compiled");
    let compiled_artifacts = discover_compiled_contract_artifacts(&compiled_root);
    if compiled_artifacts.is_empty() {
        return failed_test_step(
            format!(
                "no compiled .zkir artifacts were found under {}",
                compiled_root.display()
            ),
            Some("local-structural-validation".to_string()),
            Some(start.elapsed().as_millis()),
        );
    }

    ResolveTestStepReportV1 {
        status: ResolveStepStatus::Passed,
        duration_ms: Some(start.elapsed().as_millis()),
        detail: Some(format!(
            "validated {} compiled artifact(s) for {}",
            compiled_artifacts.len(),
            network_cfg.network
        )),
        strategy: Some("local-structural-validation".to_string()),
    }
}

fn resolve_midnight_probe_binary(project_root: &Path) -> Option<PathBuf> {
    let local = project_root
        .join("node_modules")
        .join(".bin")
        .join("midnight-probe");
    if is_executable_file(&local) {
        return Some(local);
    }
    search_path_for_binary("midnight-probe")
}

fn probe_supports_test_deploy(binary: &Path) -> bool {
    let output = Command::new(binary).arg("--help").output();
    let Ok(output) = output else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    stdout.contains("test-deploy") || stderr.contains("test-deploy")
}

fn discover_compiled_contract_artifacts(root: &Path) -> Vec<PathBuf> {
    let mut artifacts = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.is_dir() {
            let Ok(entries) = fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.filter_map(Result::ok) {
                stack.push(entry.path());
            }
            continue;
        }
        if path
            .extension()
            .is_some_and(|extension| extension == "zkir")
        {
            artifacts.push(path);
        }
    }
    artifacts.sort();
    artifacts
}

fn search_path_for_binary(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|entry| entry.join(name))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn log_command_output(verbose: bool, label: &str, cwd: &Path, stdout: &[u8], stderr: &[u8]) {
    if !verbose {
        return;
    }
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    eprintln!("[midnight resolve] {label} cwd={}", cwd.display());
    if !stdout.trim().is_empty() {
        eprintln!("[midnight resolve] stdout:\n{}", stdout.trim_end());
    }
    if !stderr.trim().is_empty() {
        eprintln!("[midnight resolve] stderr:\n{}", stderr.trim_end());
    }
}

fn summarize_output(output: &Output) -> String {
    let mut parts = Vec::new();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.trim().is_empty() {
        parts.push(format!(
            "stdout={}",
            truncate_for_detail(stdout.trim(), MAX_COMMAND_OUTPUT_CHARS)
        ));
    }
    if !stderr.trim().is_empty() {
        parts.push(format!(
            "stderr={}",
            truncate_for_detail(stderr.trim(), MAX_COMMAND_OUTPUT_CHARS)
        ));
    }
    if parts.is_empty() {
        "no command output".to_string()
    } else {
        parts.join("; ")
    }
}

fn truncate_for_detail(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    value.chars().take(max_chars).collect::<String>() + "..."
}

fn skipped_step(detail: impl Into<String>) -> ResolveStepReportV1 {
    ResolveStepReportV1 {
        status: ResolveStepStatus::Skipped,
        duration_ms: None,
        detail: Some(detail.into()),
    }
}

fn failed_step(detail: impl Into<String>, duration_ms: u128) -> ResolveStepReportV1 {
    ResolveStepReportV1 {
        status: ResolveStepStatus::Failed,
        duration_ms: Some(duration_ms),
        detail: Some(detail.into()),
    }
}

fn skipped_compile_step(detail: impl Into<String>) -> ResolveCompileStepReportV1 {
    ResolveCompileStepReportV1 {
        status: ResolveStepStatus::Skipped,
        duration_ms: None,
        detail: Some(detail.into()),
        compactc_version: None,
        contracts_compiled: 0,
    }
}

fn failed_compile_step(
    detail: impl Into<String>,
    compactc_version: Option<String>,
    contracts_compiled: usize,
    duration_ms: Option<u128>,
) -> ResolveCompileStepReportV1 {
    ResolveCompileStepReportV1 {
        status: ResolveStepStatus::Failed,
        duration_ms,
        detail: Some(detail.into()),
        compactc_version,
        contracts_compiled,
    }
}

fn skipped_test_step(detail: impl Into<String>) -> ResolveTestStepReportV1 {
    ResolveTestStepReportV1 {
        status: ResolveStepStatus::Skipped,
        duration_ms: None,
        detail: Some(detail.into()),
        strategy: None,
    }
}

fn failed_test_step(
    detail: impl Into<String>,
    strategy: Option<String>,
    duration_ms: Option<u128>,
) -> ResolveTestStepReportV1 {
    ResolveTestStepReportV1 {
        status: ResolveStepStatus::Failed,
        duration_ms,
        detail: Some(detail.into()),
        strategy,
    }
}

fn render_human_report(report: &ResolveReportV1) -> Result<String, String> {
    let mut out = String::new();
    let heading = if report.dry_run {
        "zkf midnight resolve - Dry Run"
    } else if report.has_failures() {
        "zkf midnight resolve - Failed"
    } else {
        "zkf midnight resolve - Complete"
    };
    writeln!(&mut out, "{heading}").map_err(|error| error.to_string())?;
    writeln!(&mut out, "==============================").map_err(|error| error.to_string())?;
    writeln!(&mut out, "Network:     {}", report.network).map_err(|error| error.to_string())?;
    writeln!(&mut out, "Project:     {}", report.project_root)
        .map_err(|error| error.to_string())?;
    writeln!(&mut out, "Family:      {}", report.family).map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Mismatches:  {} found, {} fixed",
        report.mismatches_found, report.mismatches_fixed
    )
    .map_err(|error| error.to_string())?;

    writeln!(&mut out).map_err(|error| error.to_string())?;
    if report.mismatches.is_empty() {
        writeln!(&mut out, "Fixed packages: none").map_err(|error| error.to_string())?;
    } else {
        writeln!(&mut out, "Fixed packages:").map_err(|error| error.to_string())?;
        for mismatch in &report.mismatches {
            writeln!(
                &mut out,
                "  {} [{}]: {} -> {}",
                mismatch.package, mismatch.section, mismatch.installed, mismatch.required
            )
            .map_err(|error| error.to_string())?;
        }
    }

    writeln!(&mut out).map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "npm install:  {}{}",
        report.npm_install.status.as_human(),
        render_detail_suffix(report.npm_install.detail.as_deref())
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Compile:      {}{}",
        report.compile.status.as_human(),
        render_compile_suffix(&report.compile)
    )
    .map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Test:         {}{}",
        report.test.status.as_human(),
        render_test_suffix(&report.test)
    )
    .map_err(|error| error.to_string())?;

    writeln!(&mut out).map_err(|error| error.to_string())?;
    if report.dry_run {
        writeln!(&mut out, "Dry run only. No files were changed.")
            .map_err(|error| error.to_string())?;
    } else if report.has_failures() {
        writeln!(&mut out, "Resolver stopped before the project was ready.")
            .map_err(|error| error.to_string())?;
    } else {
        writeln!(&mut out, "Your project is resolved and ready.")
            .map_err(|error| error.to_string())?;
    }

    Ok(out)
}

fn render_detail_suffix(detail: Option<&str>) -> String {
    detail
        .filter(|detail| !detail.is_empty())
        .map(|detail| format!(" ({detail})"))
        .unwrap_or_default()
}

fn render_compile_suffix(report: &ResolveCompileStepReportV1) -> String {
    let mut suffix = String::new();
    if let Some(version) = report.compactc_version.as_deref() {
        suffix.push_str(&format!(" (compactc {version}"));
        if report.contracts_compiled > 0 {
            suffix.push_str(&format!(", {} contract(s)", report.contracts_compiled));
        }
        suffix.push(')');
        if let Some(detail) = report.detail.as_deref()
            && !detail.is_empty()
            && !detail.contains("compiled")
        {
            suffix.push_str(&format!(" ({detail})"));
        }
        return suffix;
    }
    render_detail_suffix(report.detail.as_deref())
}

fn render_test_suffix(report: &ResolveTestStepReportV1) -> String {
    let mut parts = Vec::new();
    if let Some(strategy) = report.strategy.as_deref() {
        parts.push(strategy.to_string());
    }
    if let Some(detail) = report.detail.as_deref()
        && !detail.is_empty()
    {
        parts.push(detail.to_string());
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn write_project_files(root: &Path, package_json: &Value, package_lock: &Value) {
        fs::write(
            root.join("package.json"),
            serde_json::to_vec_pretty(package_json).expect("package.json"),
        )
        .expect("write package.json");
        fs::write(
            root.join("package-lock.json"),
            serde_json::to_vec_pretty(package_lock).expect("package-lock.json"),
        )
        .expect("write package-lock.json");
    }

    fn manifest_package_json(version_overrides: &[(&str, &str)]) -> Value {
        let manifest = midnight_package_manifest().expect("manifest");
        let mut dependencies = serde_json::Map::new();
        let mut dev_dependencies = serde_json::Map::new();
        let overrides = version_overrides
            .iter()
            .map(|(name, version)| (name.to_string(), version.to_string()))
            .collect::<BTreeMap<_, _>>();
        for pin in &manifest.packages {
            let version = overrides
                .get(&pin.name)
                .cloned()
                .unwrap_or_else(|| pin.version.clone());
            match pin.section.as_str() {
                "dependencies" => {
                    dependencies.insert(pin.name.clone(), Value::String(version));
                }
                "devDependencies" => {
                    dev_dependencies.insert(pin.name.clone(), Value::String(version));
                }
                other => panic!("unexpected section {other}"),
            }
        }
        json!({
            "name": "midnight-test-project",
            "version": "0.1.0",
            "dependencies": dependencies,
            "devDependencies": dev_dependencies,
        })
    }

    fn matching_package_lock() -> Value {
        let manifest = midnight_package_manifest().expect("manifest");
        let mut packages = serde_json::Map::new();
        packages.insert(String::new(), json!({ "name": "midnight-test-project" }));
        for pin in &manifest.packages {
            packages.insert(
                format!("node_modules/{}", pin.name),
                json!({ "version": pin.version }),
            );
        }
        json!({
            "name": "midnight-test-project",
            "lockfileVersion": 3,
            "packages": packages,
        })
    }

    #[test]
    fn dry_run_detects_mismatches_without_mutating_package_json() {
        let temp = tempfile::tempdir().expect("tempdir");
        let package_json = manifest_package_json(&[("@midnight-ntwrk/compact-runtime", "0.14.0")]);
        let package_lock = matching_package_lock();
        write_project_files(temp.path(), &package_json, &package_lock);
        let before = fs::read_to_string(temp.path().join("package.json")).expect("package.json");

        let execution = execute_resolve(&ResolveArgs {
            network: "preprod".to_string(),
            project: Some(temp.path().to_path_buf()),
            dry_run: true,
            skip_install: false,
            skip_compile: false,
            skip_test: false,
            json: false,
            verbose: false,
        })
        .expect("resolve execution");

        let after = fs::read_to_string(temp.path().join("package.json")).expect("package.json");
        assert_eq!(before, after);
        assert_eq!(execution.report.mismatches_found, 1);
        assert_eq!(execution.report.mismatches_fixed, 0);
        assert_eq!(
            execution.report.npm_install.status,
            ResolveStepStatus::Skipped
        );
        assert_eq!(execution.report.compile.status, ResolveStepStatus::Skipped);
        assert_eq!(execution.report.test.status, ResolveStepStatus::Skipped);
        assert!(execution.terminal_error.is_none());
    }

    #[test]
    fn rewrites_mismatched_dependencies_and_dev_dependencies() {
        let temp = tempfile::tempdir().expect("tempdir");
        let package_json = manifest_package_json(&[
            ("@midnight-ntwrk/compact-runtime", "0.14.0"),
            ("@midnight-ntwrk/midnight-js-compact", "4.0.1"),
        ]);
        let package_lock = matching_package_lock();
        write_project_files(temp.path(), &package_json, &package_lock);

        let execution = execute_resolve(&ResolveArgs {
            network: "preprod".to_string(),
            project: Some(temp.path().to_path_buf()),
            dry_run: false,
            skip_install: true,
            skip_compile: true,
            skip_test: true,
            json: false,
            verbose: false,
        })
        .expect("resolve execution");

        assert!(execution.terminal_error.is_none());
        let updated =
            load_package_json(&temp.path().join("package.json")).expect("updated package");
        assert_eq!(
            updated["dependencies"]["@midnight-ntwrk/compact-runtime"],
            Value::String("0.15.0".to_string())
        );
        assert_eq!(
            updated["devDependencies"]["@midnight-ntwrk/midnight-js-compact"],
            Value::String("4.0.2".to_string())
        );
        assert_eq!(execution.report.mismatches_fixed, 2);
    }

    #[test]
    fn skip_install_leaves_lockfile_untouched() {
        let temp = tempfile::tempdir().expect("tempdir");
        let package_json = manifest_package_json(&[("@midnight-ntwrk/compact-runtime", "0.14.0")]);
        let package_lock = json!({
            "name": "midnight-test-project",
            "lockfileVersion": 3,
            "packages": {
                "": { "name": "midnight-test-project" },
                "node_modules/@midnight-ntwrk/compact-runtime": { "version": "0.14.0" }
            }
        });
        write_project_files(temp.path(), &package_json, &package_lock);
        let before = fs::read_to_string(temp.path().join("package-lock.json")).expect("lockfile");

        let execution = execute_resolve(&ResolveArgs {
            network: "preprod".to_string(),
            project: Some(temp.path().to_path_buf()),
            dry_run: false,
            skip_install: true,
            skip_compile: true,
            skip_test: true,
            json: false,
            verbose: false,
        })
        .expect("resolve execution");

        let after = fs::read_to_string(temp.path().join("package-lock.json")).expect("lockfile");
        assert_eq!(before, after);
        assert_eq!(
            execution.report.npm_install.status,
            ResolveStepStatus::Skipped
        );
        assert_eq!(
            execution.report.npm_install.detail.as_deref(),
            Some("--skip-install")
        );
    }

    #[test]
    fn json_report_uses_schema_and_manifest_ordered_mismatches() {
        let temp = tempfile::tempdir().expect("tempdir");
        let package_json = manifest_package_json(&[
            ("@midnight-ntwrk/midnight-js-contracts", "4.0.1"),
            ("@midnight-ntwrk/compact-runtime", "0.14.0"),
        ]);
        let package_lock = matching_package_lock();
        write_project_files(temp.path(), &package_json, &package_lock);

        let execution = execute_resolve(&ResolveArgs {
            network: "preview".to_string(),
            project: Some(temp.path().to_path_buf()),
            dry_run: true,
            skip_install: false,
            skip_compile: false,
            skip_test: false,
            json: true,
            verbose: false,
        })
        .expect("resolve execution");

        let value = serde_json::to_value(&execution.report).expect("serialize report");
        assert_eq!(
            value["schema"],
            Value::String(MIDNIGHT_RESOLVE_SCHEMA_V1.to_string())
        );
        assert_eq!(
            value["family"],
            Value::String(MIDNIGHT_RESOLVE_FAMILY.to_string())
        );
        assert_eq!(value["network"], Value::String("preview".to_string()));
        assert_eq!(
            execution
                .report
                .mismatches
                .iter()
                .map(|entry| entry.package.as_str())
                .collect::<Vec<_>>(),
            vec![
                "@midnight-ntwrk/compact-runtime",
                "@midnight-ntwrk/midnight-js-contracts",
            ]
        );
    }

    #[test]
    fn compile_step_skips_when_no_contracts_exist() {
        let temp = tempfile::tempdir().expect("tempdir");
        let report = run_compile_step(temp.path(), false);
        assert_eq!(report.status, ResolveStepStatus::Skipped);
        assert_eq!(
            report.detail.as_deref(),
            Some("no contracts/compact directory found")
        );
        assert_eq!(report.contracts_compiled, 0);
    }
}
