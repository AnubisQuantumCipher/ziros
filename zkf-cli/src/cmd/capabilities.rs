use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

use crate::cmd::runtime::installed_strict_certification_match;
use zkf_backends::{
    backend_for, capabilities_report, metal_runtime::capability_notes, metal_runtime_report,
    runtime_hardware_profile, strict_bn254_auto_route_ready_with_runtime,
    strict_bn254_gpu_stage_coverage,
};
use zkf_core::{BackendCapabilityMatrix, BackendKind, SupportClass, ToolRequirement};
use zkf_frontends::{FrontendKind, frontend_capabilities_matrix, frontend_for};
use zkf_gadgets::registry::{AuditStatus, GadgetSpec, all_gadget_specs};

pub(crate) fn handle_capabilities() -> Result<(), String> {
    let matrix = capabilities_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&matrix).map_err(|e| e.to_string())?
    );
    Ok(())
}

pub(crate) fn handle_frontends() -> Result<(), String> {
    let matrix = frontend_capabilities_matrix();
    println!(
        "{}",
        serde_json::to_string_pretty(&matrix).map_err(|e| e.to_string())?
    );
    Ok(())
}

pub(crate) fn handle_support_matrix(out: Option<PathBuf>) -> Result<(), String> {
    let matrix = build_support_matrix_report();
    let json = serde_json::to_string_pretty(&matrix).map_err(|e| e.to_string())?;
    if let Some(path) = out {
        std::fs::write(&path, json).map_err(|e| format!("{}: {e}", path.display()))?;
        println!("wrote support matrix: {}", path.display());
    } else {
        println!("{json}");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct SupportMatrixReport {
    schema_version: String,
    generated_for: String,
    backends: Vec<SupportMatrixBackend>,
    frontends: Vec<SupportMatrixFrontend>,
    gadgets: Vec<SupportMatrixGadget>,
    registry: SupportMatrixRegistry,
    roadmap_completion: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct SupportMatrixBackend {
    id: String,
    mode: String,
    status: String,
    assurance_lane: String,
    proof_semantics: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegates_to: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    fields: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    max_range_bits: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    gpu_stages: Vec<String>,
    gpu_coverage: String,
    notes: String,
}

#[derive(Debug, Serialize)]
struct SupportMatrixFrontend {
    id: String,
    status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    input_formats: Vec<String>,
    notes: String,
}

#[derive(Debug, Serialize)]
struct SupportMatrixGadget {
    id: String,
    status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    supported_fields: Vec<String>,
    audit_status: String,
    notes: String,
}

#[derive(Debug, Serialize)]
struct SupportMatrixRegistry {
    local: String,
    remote: String,
    version_resolution: String,
    security: String,
    notes: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    frontends: Vec<zkf_frontends::FrontendCapabilities>,
    backends: Vec<zkf_backends::CapabilityReport>,
    metal: zkf_backends::metal_runtime::MetalRuntimeReport,
    tools: Vec<ToolCheck>,
}

#[derive(Debug, Serialize)]
struct ToolCheck {
    tool: String,
    available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

pub(crate) fn handle_doctor() -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&build_doctor_report()).map_err(|e| e.to_string())?
    );
    Ok(())
}

#[derive(Debug, Serialize)]
struct MetalDoctorReport {
    runtime: zkf_backends::metal_runtime::MetalRuntimeReport,
    backends: Vec<zkf_backends::CapabilityReport>,
    tools: Vec<ToolCheck>,
    certified_hardware_profile: String,
    strict_bn254_ready: bool,
    strict_bn254_auto_route: bool,
    strict_gpu_stage_coverage: zkf_backends::GpuStageCoverage,
    strict_gpu_busy_ratio_peak: f64,
    strict_certification_present: bool,
    strict_certification_match: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strict_certified_at_unix_ms: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    strict_certification_report: Option<String>,
    production_ready: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    production_failures: Vec<String>,
}

pub(crate) fn handle_metal_doctor(_json: bool, strict: bool) -> Result<(), String> {
    let report = build_metal_doctor_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    if strict && !report.production_ready {
        return Err(format!(
            "metal-doctor strict gate failed: {}",
            report.production_failures.join("; ")
        ));
    }
    Ok(())
}

fn build_doctor_report() -> DoctorReport {
    let requirements = collect_doctor_requirements();
    let tools = requirements.iter().map(run_tool_check).collect::<Vec<_>>();

    DoctorReport {
        frontends: frontend_capabilities_matrix(),
        backends: capabilities_report(),
        metal: metal_runtime_report(),
        tools,
    }
}

fn build_support_matrix_report() -> SupportMatrixReport {
    SupportMatrixReport {
        schema_version: "2.0".to_string(),
        generated_for: env!("CARGO_PKG_VERSION").to_string(),
        backends: capabilities_report()
            .into_iter()
            .map(|report| {
                let required = report.gpu_stage_coverage.required_stages.len();
                let active = report.gpu_stage_coverage.metal_stages.len();
                SupportMatrixBackend {
                    id: report.capabilities.backend.to_string(),
                    mode: report.implementation_type.to_string(),
                    status: support_matrix_backend_status(&report).to_string(),
                    assurance_lane: report.assurance_lane.clone(),
                    proof_semantics: report.proof_semantics.clone(),
                    delegates_to: support_matrix_delegates_to(report.capabilities.backend),
                    fields: report
                        .supported_fields
                        .iter()
                        .map(|field| field.to_string())
                        .collect(),
                    max_range_bits: support_matrix_max_range_bits(report.capabilities.backend),
                    gpu_stages: report.gpu_stage_coverage.metal_stages.clone(),
                    gpu_coverage: format!("{active}/{required} GPU stages active on current host"),
                    notes: support_matrix_backend_notes(&report),
                }
            })
            .collect(),
        frontends: frontend_capabilities_matrix()
            .into_iter()
            .map(|frontend| SupportMatrixFrontend {
                id: frontend.frontend.to_string(),
                status: support_matrix_frontend_status(&frontend).to_string(),
                input_formats: frontend.input_formats,
                notes: frontend.notes,
            })
            .collect(),
        gadgets: all_gadget_specs()
            .into_iter()
            .map(|spec| SupportMatrixGadget {
                id: spec.name.clone(),
                status: support_matrix_gadget_status(&spec).to_string(),
                supported_fields: spec.supported_fields.clone(),
                audit_status: support_matrix_gadget_audit_status(&spec.audit_status).to_string(),
                notes: support_matrix_gadget_notes(&spec),
            })
            .collect(),
        registry: SupportMatrixRegistry {
            local: "ready".to_string(),
            remote: "ready".to_string(),
            version_resolution: "ready".to_string(),
            security: "ready".to_string(),
            notes: "Local + remote registries with CombinedRegistry fallback, SemVer resolution, and SHA-256 manifest/content integrity checks."
                .to_string(),
        },
        roadmap_completion: support_matrix_roadmap_completion(),
    }
}

fn support_matrix_frontend_status(frontend: &zkf_frontends::FrontendCapabilities) -> &'static str {
    match frontend.frontend {
        FrontendKind::Cairo => "limited",
        _ if frontend.can_compile_to_ir => "ready",
        _ => "limited",
    }
}

fn support_matrix_backend_status(report: &zkf_backends::CapabilityReport) -> &'static str {
    if matches!(
        report.implementation_type,
        SupportClass::Broken | SupportClass::Unsupported
    ) || report.readiness == "blocked"
    {
        "broken"
    } else if !report.production_ready
        || matches!(
            report.implementation_type,
            SupportClass::Adapted | SupportClass::Experimental
        )
    {
        "limited"
    } else {
        "ready"
    }
}

fn support_matrix_delegates_to(kind: BackendKind) -> Option<String> {
    BackendCapabilityMatrix::current()
        .entry_for(kind)
        .and_then(|entry| entry.delegates_to)
        .map(|backend| backend.to_string())
}

fn support_matrix_max_range_bits(kind: BackendKind) -> Option<u32> {
    BackendCapabilityMatrix::current()
        .entry_for(kind)
        .and_then(|entry| entry.max_range_bits)
}

fn support_matrix_backend_notes(report: &zkf_backends::CapabilityReport) -> String {
    capability_notes(report)
}

fn support_matrix_gadget_status(spec: &GadgetSpec) -> &'static str {
    if spec.is_experimental || !spec.is_production_safe {
        "limited"
    } else {
        "ready"
    }
}

fn support_matrix_gadget_audit_status(status: &AuditStatus) -> &'static str {
    match status {
        AuditStatus::Unaudited => "unaudited",
        AuditStatus::InformallyReviewed => "informally-reviewed",
        AuditStatus::Audited { .. } => "audited",
    }
}

fn support_matrix_gadget_notes(spec: &GadgetSpec) -> String {
    let mut notes = vec![spec.description.clone()];
    if !spec.blackbox_ops.is_empty() {
        notes.push(format!("blackbox_ops={}", spec.blackbox_ops.join(",")));
    }
    if let AuditStatus::Audited { auditor } = &spec.audit_status {
        notes.push(format!("auditor={auditor}"));
    }
    notes.join(" ")
}

fn support_matrix_roadmap_completion() -> BTreeMap<String, String> {
    [
        ("phase_1_acir_native_semantics", "ready"),
        ("phase_2_acvm_solver_completion", "ready"),
        ("phase_3_plonky3_multifield", "ready"),
        ("phase_4_nova_hypernova_native", "ready"),
        ("phase_5_sp1_native_sdk", "delegated"),
        ("phase_6_midnight_native_runtime", "delegated"),
        ("phase_7_attestation_composition", "ready"),
        ("phase_8_frontend_expansion", "ready"),
        ("phase_9_advanced_tooling", "in_progress"),
        ("phase_10_production_hardening", "in_progress"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_string(), value.to_string()))
    .collect()
}

fn build_metal_doctor_report() -> MetalDoctorReport {
    let requirements = collect_doctor_requirements();
    let runtime = metal_runtime_report();
    let strict_gpu_stage_coverage = strict_bn254_gpu_stage_coverage(&runtime);
    let strict_bn254_ready = strict_bn254_auto_route_ready_with_runtime(&runtime);
    let certified_hardware_profile = runtime_hardware_profile(&runtime).to_string();
    let certification = installed_strict_certification_match();
    let strict_gpu_busy_ratio_peak = certification
        .strict_gpu_busy_ratio_peak
        .unwrap_or(runtime.metal_gpu_busy_ratio);
    let production_failures = collect_metal_production_failures(&runtime, &certification);
    MetalDoctorReport {
        runtime,
        backends: capabilities_report(),
        tools: requirements.iter().map(run_tool_check).collect(),
        certified_hardware_profile,
        strict_bn254_ready,
        strict_bn254_auto_route: strict_bn254_ready,
        strict_gpu_stage_coverage,
        strict_gpu_busy_ratio_peak,
        strict_certification_present: certification.present,
        strict_certification_match: certification.matches_current,
        strict_certified_at_unix_ms: certification.certified_at_unix_ms,
        strict_certification_report: certification.report_path,
        production_ready: production_failures.is_empty(),
        production_failures,
    }
}

fn collect_metal_production_failures(
    runtime: &zkf_backends::metal_runtime::MetalRuntimeReport,
    certification: &crate::cmd::runtime::StrictCertificationMatch,
) -> Vec<String> {
    let mut failures = Vec::new();

    if !runtime.metal_compiled {
        failures.push("binary was not built with Metal support".to_string());
    }
    if !runtime.metal_available {
        failures.push("Metal runtime is unavailable on this host".to_string());
    }
    if runtime.metal_dispatch_circuit_open {
        failures.push(
            runtime
                .metal_dispatch_last_failure
                .as_ref()
                .map(|reason| format!("Metal dispatch circuit is open: {reason}"))
                .unwrap_or_else(|| "Metal dispatch circuit is open".to_string()),
        );
    }
    match runtime.metal_device.as_deref() {
        Some(device) if device.contains("M4 Max") => {}
        Some(device) => failures.push(format!(
            "certified strict-wrap profile requires Apple M4 Max, found {device}"
        )),
        None => failures.push("Metal device name is unavailable".to_string()),
    }
    if runtime
        .recommended_working_set_size_bytes
        .unwrap_or_default()
        == 0
    {
        failures.push("recommended Metal working-set budget is unavailable".to_string());
    }
    if runtime.working_set_headroom_bytes == Some(0) {
        failures.push("Metal working-set headroom is exhausted".to_string());
    }
    let strict_coverage = strict_bn254_gpu_stage_coverage(runtime);
    if !strict_bn254_auto_route_ready_with_runtime(runtime) {
        failures.push(format!(
            "strict BN254 certified lane is not ready for auto-routing (cpu stages: {})",
            if strict_coverage.cpu_stages.is_empty() {
                "not-claimed".to_string()
            } else {
                strict_coverage.cpu_stages.join(",")
            }
        ));
    }
    if !certification.present {
        failures.push(
            certification
                .failures
                .first()
                .cloned()
                .unwrap_or_else(|| "strict certification report is missing".to_string()),
        );
    } else if !certification.matches_current {
        failures.extend(certification.failures.clone());
    }

    failures
}

fn collect_doctor_requirements() -> Vec<ToolRequirement> {
    let mut requirements = vec![
        ToolRequirement {
            tool: "cargo".to_string(),
            args: vec!["--version".to_string()],
            note: Some("Core Rust build toolchain".to_string()),
            required: true,
        },
        ToolRequirement {
            tool: "rustc".to_string(),
            args: vec!["--version".to_string()],
            note: Some("Rust compiler".to_string()),
            required: true,
        },
    ];

    #[cfg(target_os = "macos")]
    requirements.push(ToolRequirement {
        tool: "xcrun".to_string(),
        args: vec![
            "-sdk".to_string(),
            "macosx".to_string(),
            "metal".to_string(),
            "--version".to_string(),
        ],
        note: Some("Metal shader compiler".to_string()),
        required: false,
    });

    for frontend in frontend_capabilities_matrix() {
        requirements.extend(frontend_for(frontend.frontend).doctor_requirements());
    }

    for backend in capabilities_report() {
        requirements.extend(backend_for(backend.capabilities.backend).doctor_requirements());
    }

    let mut dedup = std::collections::BTreeMap::<String, ToolRequirement>::new();
    for req in requirements {
        let key = format!("{}::{}", req.tool, req.args.join(" "));
        dedup
            .entry(key)
            .and_modify(|existing| {
                existing.required |= req.required;
                if existing.note.is_none() {
                    existing.note = req.note.clone();
                }
            })
            .or_insert(req);
    }

    dedup.into_values().collect()
}

#[cfg(not(target_arch = "wasm32"))]
fn run_tool_check(requirement: &ToolRequirement) -> ToolCheck {
    let probe_env = tool_probe_env();
    let mut last_failure = None;
    for executable in tool_probe_candidates(&requirement.tool) {
        for args in tool_probe_arg_sets(requirement) {
            match std::process::Command::new(&executable)
                .args(args.iter())
                .envs(probe_env.iter().cloned())
                .output()
            {
                Ok(output)
                    if output.status.success()
                        || tool_probe_accepts_nonzero_status(requirement, &output) =>
                {
                    let version = tool_probe_version_line(&output);
                    return ToolCheck {
                        tool: requirement.tool.clone(),
                        available: true,
                        version,
                        note: requirement.note.clone(),
                    };
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    last_failure = Some(if stderr.is_empty() {
                        format!("exit status {}", output.status)
                    } else {
                        stderr
                    });
                }
                Err(err) => {
                    last_failure = Some(err.to_string());
                }
            }
        }
    }

    ToolCheck {
        tool: requirement.tool.clone(),
        available: false,
        version: None,
        note: requirement
            .note
            .as_ref()
            .map(|note| {
                last_failure
                    .as_ref()
                    .map(|failure| format!("{note}; {failure}"))
                    .unwrap_or_else(|| note.clone())
            })
            .or(last_failure),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn tool_probe_candidates(tool: &str) -> Vec<PathBuf> {
    let mut candidates = vec![PathBuf::from(tool)];
    let Some(home) = std::env::var_os("HOME") else {
        return candidates;
    };

    let home = PathBuf::from(home);
    match tool {
        "sp1up" => candidates.push(home.join(".sp1/bin/sp1up")),
        "rzup" => candidates.push(home.join(".risc0/bin/rzup")),
        "nargo" => candidates.push(home.join(".nargo/bin/nargo")),
        "noirup" => candidates.push(home.join(".nargo/bin/noirup")),
        "node" | "npm" => {
            candidates.push(PathBuf::from("/opt/homebrew/bin").join(tool));
            candidates.push(PathBuf::from("/usr/local/bin").join(tool));
        }
        "snarkjs" | "circom2" | "bb" => {
            candidates.push(
                home.join(".zkf-competition-tools/node_modules/.bin")
                    .join(tool),
            );
        }
        "docker" => {
            #[cfg(target_os = "macos")]
            candidates.push(PathBuf::from(
                "/Applications/Docker.app/Contents/Resources/bin/docker",
            ));
        }
        _ => {}
    }

    candidates
}

#[cfg(not(target_arch = "wasm32"))]
fn tool_probe_arg_sets(requirement: &ToolRequirement) -> Vec<Vec<String>> {
    let mut variants = vec![requirement.args.clone()];
    if requirement.tool == "sp1up" && requirement.args == ["--version"] {
        variants.push(vec!["--help".to_string()]);
    }
    variants
}

#[cfg(not(target_arch = "wasm32"))]
fn tool_probe_version_line(output: &std::process::Output) -> Option<String> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .next()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .map(ToOwned::to_owned)
        })
}

#[cfg(not(target_arch = "wasm32"))]
fn tool_probe_accepts_nonzero_status(
    requirement: &ToolRequirement,
    output: &std::process::Output,
) -> bool {
    if requirement.tool == "snarkjs" && requirement.args == ["--version"] {
        return tool_probe_version_line(output)
            .as_deref()
            .is_some_and(|line| line.starts_with("snarkjs@"));
    }
    false
}

#[cfg(not(target_arch = "wasm32"))]
fn tool_probe_env() -> Vec<(String, String)> {
    let mut env = std::env::vars().collect::<Vec<_>>();
    let existing_path = std::env::var("PATH").unwrap_or_default();
    let mut path_entries = vec![
        "/opt/homebrew/bin".to_string(),
        "/usr/local/bin".to_string(),
    ];
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        path_entries.push(home.join(".sp1/bin").display().to_string());
        path_entries.push(home.join(".risc0/bin").display().to_string());
        path_entries.push(home.join(".nargo/bin").display().to_string());
        path_entries.push(
            home.join(".zkf-competition-tools/node_modules/.bin")
                .display()
                .to_string(),
        );
    }
    #[cfg(target_os = "macos")]
    path_entries.push("/Applications/Docker.app/Contents/Resources/bin".to_string());
    path_entries.push(existing_path);

    let joined = path_entries.join(":");
    if let Some((_, value)) = env.iter_mut().find(|(key, _)| key == "PATH") {
        *value = joined;
    } else {
        env.push(("PATH".to_string(), joined));
    }
    env
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;

    use super::{
        build_doctor_report, build_metal_doctor_report, build_support_matrix_report,
        collect_metal_production_failures, support_matrix_backend_notes,
    };
    use crate::cmd::runtime::StrictCertificationMatch;
    use zkf_backends::metal_runtime::MetalRuntimeReport;
    use zkf_core::{BackendKind, ToolRequirement};

    #[test]
    fn metal_doctor_report_includes_runtime_and_backend_semantics() {
        let report = build_metal_doctor_report();
        assert!(report.runtime.registered_accelerators.contains_key("msm"));
        assert!(!report.certified_hardware_profile.is_empty());
        assert!(
            report
                .backends
                .iter()
                .all(|backend| !backend.prover_acceleration_scope.is_empty())
        );
        assert!(
            report
                .backends
                .iter()
                .all(|backend| !backend.proof_engine.is_empty())
        );
        assert!(report.strict_gpu_stage_coverage.coverage_ratio >= 0.0);
        if report.production_ready {
            assert!(report.production_failures.is_empty());
        }
    }

    #[test]
    fn doctor_report_includes_metal_runtime_section() {
        let report = build_doctor_report();
        assert!(report.metal.metal_compiled || !report.metal.metal_available);
        assert!(!report.backends.is_empty());
        assert!(
            report
                .backends
                .iter()
                .all(|backend| backend.gpu_stage_coverage.coverage_ratio >= 0.0)
        );
    }

    #[test]
    fn support_matrix_notes_surface_implementation_type_and_compat_alias() {
        let report = zkf_backends::capability_report_for_backend(BackendKind::Sp1)
            .expect("sp1 capability report");
        let notes = support_matrix_backend_notes(&report);
        assert!(notes.contains(&format!(
            "implementation_type={}",
            report.implementation_type
        )));
        if let Some(alias) = report.explicit_compat_alias {
            assert!(notes.contains(&format!("explicit_compat_alias={alias}")));
        }
    }

    #[test]
    fn support_matrix_uses_live_backend_truth() {
        let report = build_support_matrix_report();
        let halo2_bls = report
            .backends
            .iter()
            .find(|backend| backend.id == "halo2-bls12-381")
            .expect("halo2-bls12-381 entry");
        assert_eq!(halo2_bls.mode, "native");
        assert_eq!(halo2_bls.status, "ready");
        assert_ne!(halo2_bls.status, "broken");
        assert_eq!(halo2_bls.assurance_lane, "native-cryptographic-proof");
        assert!(halo2_bls.fields.iter().any(|field| field == "bls12-381"));
    }

    #[test]
    fn support_matrix_includes_first_class_gadget_inventory() {
        let report = build_support_matrix_report();
        let sha256 = report
            .gadgets
            .iter()
            .find(|gadget| gadget.id == "sha256")
            .expect("sha256 gadget entry");
        assert_eq!(sha256.audit_status, "informally-reviewed");
        assert!(sha256.notes.contains("NIST"));
    }

    #[test]
    fn support_matrix_marks_cairo_as_limited() {
        let report = build_support_matrix_report();
        let cairo = report
            .frontends
            .iter()
            .find(|frontend| frontend.id == "cairo")
            .expect("cairo entry");
        assert_eq!(cairo.status, "limited");
    }

    #[test]
    fn support_matrix_marks_poseidon_gadget_as_ready() {
        let report = build_support_matrix_report();
        let poseidon = report
            .gadgets
            .iter()
            .find(|gadget| gadget.id == "poseidon")
            .expect("poseidon entry");
        assert_eq!(poseidon.status, "ready");
    }

    #[test]
    fn support_matrix_marks_arkworks_groth16_as_limited_under_production_disclaimer() {
        let report = build_support_matrix_report();
        let arkworks = report
            .backends
            .iter()
            .find(|backend| backend.id == "arkworks-groth16")
            .expect("arkworks-groth16 entry");

        assert_eq!(arkworks.status, "limited");
        assert!(arkworks.notes.contains("production_ready=false"));
        assert!(
            arkworks
                .notes
                .contains("readiness_reason=upstream-ark-groth16-production-disclaimer")
        );
    }

    #[test]
    fn tool_probe_candidates_include_known_user_tool_dirs() {
        let sp1 = super::tool_probe_candidates("sp1up");
        assert!(sp1.iter().any(|path| path.ends_with(".sp1/bin/sp1up")));

        let rz = super::tool_probe_candidates("rzup");
        assert!(rz.iter().any(|path| path.ends_with(".risc0/bin/rzup")));

        let snarkjs = super::tool_probe_candidates("snarkjs");
        assert!(
            snarkjs
                .iter()
                .any(|path| path.ends_with(".zkf-competition-tools/node_modules/.bin/snarkjs"))
        );
    }

    #[test]
    fn sp1up_probe_has_help_fallback() {
        let requirement = ToolRequirement {
            tool: "sp1up".to_string(),
            args: vec!["--version".to_string()],
            note: None,
            required: false,
        };
        let variants = super::tool_probe_arg_sets(&requirement);
        assert!(variants.iter().any(|args| args == &["--help".to_string()]));
    }

    #[test]
    fn tool_probe_env_adds_known_user_tool_paths() {
        let env = super::tool_probe_env();
        let path = env
            .iter()
            .find_map(|(key, value)| (key == "PATH").then_some(value.clone()))
            .expect("PATH present");
        assert!(path.contains("/opt/homebrew/bin"));
        assert!(path.contains(".sp1/bin"));
        assert!(path.contains(".risc0/bin"));
    }

    #[cfg(unix)]
    #[test]
    fn snarkjs_probe_accepts_version_banner_even_on_nonzero_exit() {
        let requirement = ToolRequirement {
            tool: "snarkjs".to_string(),
            args: vec!["--version".to_string()],
            note: None,
            required: false,
        };
        let output = std::process::Output {
            status: std::process::ExitStatus::from_raw(99 << 8),
            stdout: b"snarkjs@0.7.5\nUsage: snarkjs\n".to_vec(),
            stderr: Vec::new(),
        };
        assert!(super::tool_probe_accepts_nonzero_status(
            &requirement,
            &output
        ));
        assert_eq!(
            super::tool_probe_version_line(&output).as_deref(),
            Some("snarkjs@0.7.5")
        );
    }

    #[test]
    fn metal_production_gate_rejects_unhealthy_runtime() {
        let runtime = MetalRuntimeReport {
            metal_compiled: true,
            metal_available: true,
            metal_disabled_by_env: false,
            metal_device: Some("Apple M4 Max".to_string()),
            metallib_mode: Some("aot".to_string()),
            threshold_profile: Some("aggressive".to_string()),
            threshold_summary: Some("msm=1024".to_string()),
            recommended_working_set_size_bytes: Some(1),
            current_allocated_size_bytes: Some(0),
            working_set_headroom_bytes: Some(1),
            working_set_utilization_pct: Some(0.0),
            metal_dispatch_circuit_open: false,
            metal_dispatch_last_failure: None,
            prewarmed_pipelines: 0,
            metal_primary_queue_depth: 24,
            metal_secondary_queue_depth: 12,
            metal_pipeline_max_in_flight: 8,
            metal_scheduler_max_jobs: 16,
            metal_working_set_headroom_target_pct: 85,
            metal_gpu_busy_ratio: 0.0,
            metal_stage_breakdown: "{}".to_string(),
            metal_inflight_jobs: 0,
            metal_no_cpu_fallback: false,
            metal_counter_source: "not-measured".to_string(),
            active_accelerators: vec![
                ("ntt".to_string(), "metal-ntt".to_string()),
                ("msm".to_string(), "metal-msm-bn254".to_string()),
            ]
            .into_iter()
            .collect(),
            registered_accelerators: Default::default(),
            cpu_fallback_reasons: Default::default(),
        };
        let healthy_certification = StrictCertificationMatch {
            present: true,
            matches_current: true,
            failures: Vec::new(),
            report_path: Some("/tmp/strict-certification.json".to_string()),
            certified_at_unix_ms: Some(1),
            strict_gpu_busy_ratio_peak: Some(0.75),
        };
        assert!(collect_metal_production_failures(&runtime, &healthy_certification).is_empty());

        let mut unhealthy = runtime;
        unhealthy.metal_dispatch_circuit_open = true;
        unhealthy.metal_dispatch_last_failure = Some("watchdog timeout".to_string());
        let failures = collect_metal_production_failures(&unhealthy, &healthy_certification);
        assert!(
            failures
                .iter()
                .any(|failure| failure.contains("watchdog timeout"))
        );
    }
}

#[cfg(target_arch = "wasm32")]
fn run_tool_check(requirement: &ToolRequirement) -> ToolCheck {
    ToolCheck {
        tool: requirement.tool.clone(),
        available: false,
        version: None,
        note: Some(
            "tool detection is unavailable on wasm32 target (std::process not supported)"
                .to_string(),
        ),
    }
}
