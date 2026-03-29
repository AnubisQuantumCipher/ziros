use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::cli::{AppCommands, ReentryAssuranceArgs, ReentryAssuranceCommands};
use crate::util::{read_json, write_json, write_text};
use ed25519_dalek::{Signer, SigningKey};
use libcrux_ml_dsa::ml_dsa_87::{
    MLDSA87SigningKey, MLDSA87VerificationKey, generate_key_pair, sign as mldsa_sign,
};
use libcrux_ml_dsa::{KEY_GENERATION_RANDOMNESS_SIZE, SIGNING_RANDOMNESS_SIZE};
use owo_colors::OwoColorize;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zkf_backends::GROTH16_SETUP_BLOB_PATH_ENV;
use zkf_core::{FieldId, PublicKeyBundle, SignatureBundle, SignatureScheme};
use zkf_lib::PRIVATE_POWERED_DESCENT_DEFAULT_STEPS;
use zkf_lib::app::descent::PrivatePoweredDescentRequestV1;
use zkf_lib::app::reentry::{
    REENTRY_ASSURANCE_ML_DSA_CONTEXT, ReentryAssuranceReceiptV2, ReentryMissionPackV1,
    ReentryMissionPackV2, ReentryOracleComparisonV1, ReentrySignerManifestV1,
    SignedReentryMissionPackV1, build_private_reentry_thermal_accepted_program_for_mission_pack,
    build_reentry_assurance_receipt, build_reentry_assurance_receipt_v2,
    build_reentry_oracle_summary_v1, compare_reentry_receipt_to_oracle_v1,
    private_reentry_thermal_accepted_witness_from_mission_pack,
    private_reentry_thermal_showcase_with_steps, private_reentry_thermal_witness_with_steps,
    reentry_mission_pack_v2_digest, reentry_signer_manifest_digest,
    validate_signed_reentry_mission_pack,
};
use zkf_lib::app::reentry_ops::{
    ArtifactClassV1, ArtifactDescriptorV1, AssuranceTraceMatrixV1, DerivedModelPackageV1,
    DerivedModelRequestV1, MissionOpsBoundaryContractV1, NasaClassificationBoundaryV1,
    PROVENANCE_ASSURANCE_TRACE_MATRIX_DIGEST_KEY, PROVENANCE_DERIVED_MODEL_PACKAGE_DIGEST_KEY,
    PROVENANCE_NASA_CLASSIFICATION_KEY, PROVENANCE_SCENARIO_LIBRARY_MANIFEST_DIGEST_KEY,
    PROVENANCE_SOURCE_MODEL_MANIFEST_DIGESTS_JSON_KEY, REENTRY_NASA_TARGET_CLASSIFICATION,
    ScenarioLibraryManifestV1, SourceModelAdapterInputV1, SourceModelManifestV1,
    artifact_descriptor_v1, assurance_trace_matrix_digest,
    build_source_model_manifest_from_adapter_input, copy_ops_provenance_into_pack,
    derive_reentry_model_package, derived_model_package_digest, mission_ops_boundary_contract_v1,
    qualify_reentry_model_package, scenario_library_manifest_digest, source_model_manifest_digest,
    validate_derived_model_package, validate_mission_pack_ops_provenance,
    validate_scenario_library_manifest, validate_source_model_adapter_input,
    validate_source_model_manifest,
};
use zkf_lib::{
    FormalScriptSpec, collect_formal_evidence, exportable_artifacts, mission_ops_boundary_markdown,
    release_block_on_oracle_mismatch, scrub_public_export_text_tree,
};
use zkf_ui::ZkTheme;

const POWERED_DESCENT_PRODUCTION_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_PRODUCTION";
const POWERED_DESCENT_BUNDLE_MODE_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_BUNDLE_MODE";
const POWERED_DESCENT_TRUSTED_SETUP_MANIFEST_ENV: &str =
    "ZKF_PRIVATE_POWERED_DESCENT_TRUSTED_SETUP_MANIFEST";
const REENTRY_ASSURANCE_PRODUCTION_ENV: &str = "ZKF_REENTRY_ASSURANCE_PRODUCTION";
const REENTRY_FORMAL_SCRIPT_SPECS: [FormalScriptSpec; 1] = [FormalScriptSpec {
    name: "verus_reentry_assurance",
    script_relative_path: "scripts/run_verus_reentry_assurance_proofs.sh",
    log_file_name: "verus_reentry_assurance.log",
}];
const REENTRY_THEOREM_IDS: [&str; 17] = [
    "app.reentry_surface_constants",
    "app.reentry_accepted_profile_fits_goldilocks",
    "app.reentry_signed_bound_slack_soundness",
    "app.reentry_signed_residual_split_soundness",
    "app.reentry_floor_sqrt_bracketing",
    "app.reentry_exact_division_soundness",
    "app.reentry_heating_factorization_soundness",
    "app.reentry_running_max_monotonicity",
    "app.reentry_compliance_bit_boolean",
    "app.reentry_manifest_window_contains_signed_pack",
    "app.reentry_receipt_projection_preserves_signed_digests",
    "app.reentry_rk4_weighted_step_soundness",
    "app.reentry_interpolation_band_soundness",
    "app.reentry_cosine_closure_soundness",
    "app.reentry_abort_latch_monotonicity",
    "app.reentry_first_trigger_legality",
    "app.reentry_abort_branch_mode_selection",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReentryBundleManifestV1 {
    version: u32,
    schema: String,
    application: String,
    mission_id: String,
    mission_pack_digest: String,
    theorem_lane: String,
    boundary_contract: MissionOpsBoundaryContractV1,
    artifacts: Vec<ArtifactDescriptorV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PublishedAnnexManifestV2 {
    version: u32,
    schema: String,
    application: String,
    mission_id: String,
    mission_pack_digest: String,
    theorem_lane: String,
    boundary_contract: MissionOpsBoundaryContractV1,
    artifacts: Vec<ArtifactDescriptorV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DownstreamHandoffManifestV2 {
    version: u32,
    schema: String,
    target: String,
    mission_id: String,
    mission_pack_digest: String,
    signer_manifest_digest: String,
    theorem_lane: String,
    boundary_contract: MissionOpsBoundaryContractV1,
    artifacts: Vec<ArtifactDescriptorV1>,
    xtce_channels: Vec<Value>,
}

fn reentry_boundary_contract() -> MissionOpsBoundaryContractV1 {
    mission_ops_boundary_contract_v1()
}

fn reentry_artifact_descriptor(
    relative_path: impl Into<String>,
    artifact_class: ArtifactClassV1,
    trust_lane: &str,
    contains_private_data: bool,
    public_export_allowed: bool,
    notes: &[&str],
) -> ArtifactDescriptorV1 {
    artifact_descriptor_v1(
        relative_path,
        artifact_class,
        trust_lane,
        contains_private_data,
        public_export_allowed,
        notes.iter().map(|item| (*item).to_string()).collect(),
    )
}

fn bundle_manifest_from_parts(
    receipt: &ReentryAssuranceReceiptV2,
    artifacts: Vec<ArtifactDescriptorV1>,
) -> ReentryBundleManifestV1 {
    ReentryBundleManifestV1 {
        version: 1,
        schema: "zkf-reentry-bundle-manifest-v1".to_string(),
        application: "private-reentry-mission-assurance".to_string(),
        mission_id: receipt.mission_id.clone(),
        mission_pack_digest: receipt.mission_pack_digest.clone(),
        theorem_lane: receipt.theorem_lane.clone(),
        boundary_contract: reentry_boundary_contract(),
        artifacts,
    }
}

fn copy_described_artifacts(
    source_root: &Path,
    destination_root: &Path,
    artifacts: &[ArtifactDescriptorV1],
    include_private: bool,
) -> Result<(), String> {
    for artifact in exportable_artifacts(artifacts, include_private) {
        let source = source_root.join(&artifact.relative_path);
        if !source.exists() {
            return Err(format!(
                "bundle artifact {} is missing from {}",
                artifact.relative_path,
                source_root.display()
            ));
        }
        let destination = destination_root.join(&artifact.relative_path);
        if source.is_dir() {
            copy_bundle_dir_recursive(&source, &destination)?;
        } else {
            copy_bundle_file(&source, &destination)?;
        }
    }
    Ok(())
}

fn ensure_oracle_comparison_matched(bundle: &Path) -> Result<ReentryOracleComparisonV1, String> {
    let comparison: ReentryOracleComparisonV1 = read_json(&bundle.join("oracle_comparison.json"))?;
    release_block_on_oracle_mismatch("reentry bundle", comparison.matched, &comparison.mismatches)?;
    Ok(comparison)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ReentrySignerKeyFileV1 {
    version: u32,
    ed25519_seed: [u8; 32],
    ml_dsa87_signing_key: Vec<u8>,
    ml_dsa87_public_key: Vec<u8>,
}

impl ReentrySignerKeyFileV1 {
    fn public_key_bundle(&self) -> PublicKeyBundle {
        PublicKeyBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: SigningKey::from_bytes(&self.ed25519_seed)
                .verifying_key()
                .to_bytes()
                .to_vec(),
            ml_dsa87: self.ml_dsa87_public_key.clone(),
        }
    }

    fn signing_key(&self) -> Result<MLDSA87SigningKey, String> {
        let bytes: [u8; MLDSA87SigningKey::len()] = self
            .ml_dsa87_signing_key
            .clone()
            .try_into()
            .map_err(|_| "reentry signer ML-DSA signing key file is corrupt".to_string())?;
        Ok(MLDSA87SigningKey::new(bytes))
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(format!(
                "unsupported reentry signer key file version {}",
                self.version
            ));
        }
        if self.ml_dsa87_signing_key.len() != MLDSA87SigningKey::len() {
            return Err("reentry signer ML-DSA signing key file is corrupt".to_string());
        }
        if self.ml_dsa87_public_key.len() != MLDSA87VerificationKey::len() {
            return Err("reentry signer ML-DSA public key file is corrupt".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AppStyle {
    Minimal,
    Colored,
    Tui,
}

impl AppStyle {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "minimal" => Ok(Self::Minimal),
            "colored" => Ok(Self::Colored),
            "tui" => Ok(Self::Tui),
            other => Err(format!(
                "unknown app style '{other}' (expected minimal, colored, or tui)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Colored => "colored",
            Self::Tui => "tui",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Minimal => "Minimal",
            Self::Colored => "Colored",
            Self::Tui => "TUI",
        }
    }

    fn one_line_description(self) -> &'static str {
        match self {
            Self::Minimal => "Plain-text scaffold for scripts, CI, and low-noise terminals.",
            Self::Colored => {
                "Colorized scaffold with proof banners, audit output, and live progress."
            }
            Self::Tui => "Interactive dashboard scaffold with ratatui panels and prove modals.",
        }
    }

    fn audience(self) -> &'static str {
        match self {
            Self::Minimal => "Automation-first developers, CI lanes, and shell-heavy workflows.",
            Self::Colored => {
                "Default app developers who want a polished proving flow without a full TUI."
            }
            Self::Tui => {
                "Teams shipping terminal-native apps like AegisVault, SolvencyGuard, and operator consoles."
            }
        }
    }

    fn experience_summary(self) -> &'static str {
        match self {
            Self::Minimal => "Generates a lean `main.rs` with plain check/prove/verify output.",
            Self::Colored => {
                "Generates a styled `main.rs` that uses `zkf-ui` rendering plus progress reporting."
            }
            Self::Tui => {
                "Generates `main.rs` + `dashboard.rs` wired through `zkf-tui` and the local proof worker."
            }
        }
    }

    fn example_command(self) -> &'static str {
        match self {
            Self::Minimal => "zkf app init --name my-zk-app --template range-proof --style minimal",
            Self::Colored => "zkf app init --name my-zk-app --template range-proof --style colored",
            Self::Tui => "zkf app init --name my-zk-app --template range-proof --style tui",
        }
    }
}

fn gallery_paint(theme: &ZkTheme, style: AppStyle, text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    if !theme.colors_enabled {
        return text.to_string();
    }
    match style {
        AppStyle::Minimal => text.dimmed().to_string(),
        AppStyle::Colored => text.green().bold().to_string(),
        AppStyle::Tui => text.cyan().bold().to_string(),
    }
}

fn gallery_box_chars(
    theme: &ZkTheme,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    if theme.unicode_enabled {
        ("┌", "┐", "└", "┘", "│")
    } else {
        ("+", "+", "+", "+", "|")
    }
}

fn gallery_horizontal(theme: &ZkTheme, width: usize) -> String {
    if theme.unicode_enabled {
        "─".repeat(width)
    } else {
        "-".repeat(width)
    }
}

fn render_gallery_card(style: AppStyle, theme: &ZkTheme) -> String {
    let raw_title = format!("{} Style", style.display_name());
    let title = gallery_paint(theme, style, &raw_title);
    let lines = vec![
        style.one_line_description().to_string(),
        format!("Best for: {}", style.audience()),
        format!("Generated surface: {}", style.experience_summary()),
        format!("Try: {}", style.example_command()),
    ];
    let (tl, tr, bl, br, v) = gallery_box_chars(theme);
    let mut width = raw_title.len();
    for line in &lines {
        width = width.max(line.len());
    }
    let border = gallery_horizontal(theme, width + 2);
    let mut rendered = Vec::with_capacity(lines.len() + 3);
    rendered.push(format!("{tl}{border}{tr}"));
    rendered.push(format!("{v} {:width$} {v}", title, width = width));
    for line in lines {
        rendered.push(format!("{v} {:width$} {v}", line, width = width));
    }
    rendered.push(format!("{bl}{border}{br}"));
    rendered.join("\n")
}

fn render_gallery() -> String {
    let theme = ZkTheme::default();
    let intro = gallery_paint(&theme, AppStyle::Colored, "ZirOS App Gallery");
    [
        intro,
        "Choose the scaffold style that matches your app surface.".to_string(),
        render_gallery_card(AppStyle::Minimal, &theme),
        render_gallery_card(AppStyle::Colored, &theme),
        render_gallery_card(AppStyle::Tui, &theme),
        "Flagship example: cargo run -p zkf-tui --example aegisvault".to_string(),
    ]
    .join("\n\n")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zkf-cli lives under the workspace root")
        .to_path_buf()
}

fn parse_template_args(values: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut parsed = BTreeMap::new();
    for value in values {
        let (key, value) = value
            .split_once('=')
            .ok_or_else(|| format!("invalid --template-arg '{value}' (expected key=value)"))?;
        if key.trim().is_empty() {
            return Err(format!("invalid --template-arg '{value}' (empty key)"));
        }
        parsed.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(parsed)
}

fn template_spec(
    template: &str,
    template_args: &BTreeMap<String, String>,
) -> Result<zkf_lib::AppSpecV1, String> {
    zkf_lib::instantiate_template(template, template_args).map_err(|error| error.to_string())
}

fn render_templates(json: bool) -> Result<String, String> {
    let registry = zkf_lib::template_registry();
    if json {
        return serde_json::to_string_pretty(&registry)
            .map_err(|error| format!("failed to serialize template registry: {error}"));
    }

    Ok(registry
        .into_iter()
        .map(|entry| {
            let args = if entry.template_args.is_empty() {
                "args: none".to_string()
            } else {
                let rendered = entry
                    .template_args
                    .iter()
                    .map(|arg| {
                        let default = arg
                            .default_value
                            .as_deref()
                            .map(|value| format!(" default={value}"))
                            .unwrap_or_default();
                        format!("{}{}", arg.name, default)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("args: {rendered}")
            };
            format!("- {}: {} ({args})", entry.id, entry.description)
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn crate_name(name: &str) -> String {
    name.replace(' ', "-")
}

fn out_dir(name: &str, out: Option<PathBuf>) -> Result<PathBuf, String> {
    let path = match out {
        Some(path) => path,
        None => std::env::current_dir()
            .map_err(|error| format!("failed to read current directory: {error}"))?
            .join(name),
    };
    if path.exists() {
        let mut entries = path
            .read_dir()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if entries
            .next()
            .transpose()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err(format!(
                "refusing to scaffold into non-empty directory '{}'",
                path.display()
            ));
        }
    }
    Ok(path)
}

fn cargo_toml_content(package_name: &str, style: AppStyle) -> String {
    let root = repo_root();
    let mut dependencies = vec![
        format!(
            "zkf-lib = {{ path = \"{}\" }}",
            root.join("zkf-lib").display()
        ),
        format!(
            "zkf-backends = {{ path = \"{}\" }}",
            root.join("zkf-backends").display()
        ),
        "serde_json = \"1\"".to_string(),
    ];
    if matches!(style, AppStyle::Colored | AppStyle::Tui) {
        dependencies.push(format!(
            "zkf-ui = {{ path = \"{}\" }}",
            root.join("zkf-ui").display()
        ));
    }
    if style == AppStyle::Tui {
        dependencies.push(format!(
            "zkf-tui = {{ path = \"{}\" }}",
            root.join("zkf-tui").display()
        ));
        dependencies.push("crossterm = \"0.28\"".to_string());
        dependencies.push("ratatui = { version = \"0.29\", default-features = false, features = [\"crossterm\"] }".to_string());
    }

    format!(
        r#"[package]
name = "{package_name}"
version = "0.1.0"
edition = "2024"

[workspace]

[dependencies]
{}
"#,
        dependencies.join("\n")
    )
}

fn spec_rs_content() -> &'static str {
    r#"pub fn load_app_spec() -> Result<zkf_lib::AppSpecV1, Box<dyn std::error::Error>> {
    let spec_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("zirapp.json");
    let spec_json = std::fs::read_to_string(spec_path)?;
    let spec = serde_json::from_str(&spec_json)?;
    Ok(spec)
}

pub fn load_program() -> Result<(zkf_lib::AppSpecV1, zkf_lib::Program), Box<dyn std::error::Error>>
{
    let spec = load_app_spec()?;
    let program = zkf_lib::build_app_spec(&spec)?;
    Ok((spec, program))
}
"#
}

fn scaffold_backend(field: FieldId) -> &'static str {
    match field {
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => "plonky3",
        FieldId::PastaFp | FieldId::PastaFq => "halo2",
        FieldId::Bls12_381 => "halo2-bls12381",
        FieldId::Bn254 => "arkworks-groth16",
    }
}

fn is_aerospace_template(template: &str) -> bool {
    matches!(
        template,
        "gnc-6dof-core"
            | "tower-catch-geometry"
            | "barge-terminal-profile"
            | "planetary-terminal-profile"
            | "gust-robustness-batch"
            | "private-starship-flip-catch"
    )
}

fn backend_setup_note(backend: &str) -> &'static str {
    match backend {
        "plonky3" => "No trusted setup is required. This is the zero-friction starter lane.",
        "halo2" | "halo2-bls12381" => {
            "This scaffold uses an explicit Halo2 lane. Keep the backend explicit in production automation."
        }
        "arkworks-groth16" => {
            "This scaffold uses an explicit Groth16 lane. Import trusted setup material before production or switch to `range-proof` for the transparent starter path."
        }
        _ => "Keep the selected backend explicit in automation and CI.",
    }
}

fn aerospace_benchmark_script_content(template: &str, backend: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
cd "$ROOT"
mkdir -p artifacts/benchmarks

START="$(date +%s)"
cargo test --test smoke -- --nocapture
cargo run >/dev/null
END="$(date +%s)"
DURATION="$((END - START))"

cat > artifacts/benchmarks/latest.txt <<EOF
template={template}
backend={backend}
duration_seconds=$DURATION
mode=local-scaffold-smoke
production_posture=imported-crs-only final wrap; tcp-counted transport; neural-engine advisory only
EOF

echo "benchmark written to artifacts/benchmarks/latest.txt"
"#
    )
}

fn aerospace_report_script_content(template: &str, backend: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
cd "$ROOT"
mkdir -p artifacts/reports

cargo test --test smoke -- --nocapture

cat > artifacts/reports/latest.md <<EOF
# Aerospace Scaffold Report

- Template: \`{template}\`
- Backend: \`{backend}\`
- Proof posture: imported CRS only for regulator-facing Groth16 wrap
- Distributed transport: TCP counted; RDMA follow-on only
- Neural Engine: advisory only
- Generated from: standalone scaffold

## Files

- \`zirapp.json\`
- \`inputs.compliant.json\`
- \`inputs.violation.json\`
- \`tests/smoke.rs\`
- \`scripts/benchmark.sh\`
- \`scripts/generate_report.sh\`
- \`scripts/export_public_bundle.sh\`
EOF

echo "report written to artifacts/reports/latest.md"
"#
    )
}

fn aerospace_public_bundle_script_content(template: &str) -> String {
    format!(
        r#"#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${{BASH_SOURCE[0]}}")/.." && pwd)"
cd "$ROOT"
mkdir -p artifacts/public

cp README.md artifacts/public/README.md
cp zirapp.json artifacts/public/zirapp.json

if [[ -f artifacts/reports/latest.md ]]; then
  cp artifacts/reports/latest.md artifacts/public/report.md
fi

cat > artifacts/public/MANIFEST.txt <<EOF
template={template}
included=README.md,zirapp.json,report.md(optional)
excluded=inputs.compliant.json,inputs.violation.json,target,artifacts/private
sanitization=public-bundle-default
EOF

echo "public bundle written to artifacts/public"
"#
    )
}

fn append_aerospace_scaffold(root: &PathBuf, template: &str, backend: &str) -> Result<(), String> {
    std::fs::create_dir_all(root.join("scripts"))
        .map_err(|error| format!("{}: {error}", root.join("scripts").display()))?;
    std::fs::create_dir_all(root.join("artifacts/public"))
        .map_err(|error| format!("{}: {error}", root.join("artifacts/public").display()))?;
    std::fs::create_dir_all(root.join("artifacts/reports"))
        .map_err(|error| format!("{}: {error}", root.join("artifacts/reports").display()))?;
    std::fs::create_dir_all(root.join("artifacts/benchmarks"))
        .map_err(|error| format!("{}: {error}", root.join("artifacts/benchmarks").display()))?;

    write_text(
        &root.join("scripts/benchmark.sh"),
        &aerospace_benchmark_script_content(template, backend),
    )?;
    write_text(
        &root.join("scripts/generate_report.sh"),
        &aerospace_report_script_content(template, backend),
    )?;
    write_text(
        &root.join("scripts/export_public_bundle.sh"),
        &aerospace_public_bundle_script_content(template),
    )?;
    Ok(())
}

fn minimal_main_rs_content(backend: &str) -> String {
    r#"mod spec;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = "__BACKEND__";
    let (spec, program) = spec::load_program()?;
    let inputs_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
    let inputs = zkf_lib::load_inputs(inputs_path.to_str().expect("manifest path must be utf-8"))?;
    let checked = zkf_lib::check_with_backend(&program, &inputs, backend, None, None)?;
    let embedded = zkf_lib::compile_and_prove(&program, &inputs, backend, None, None)?;
    let verified = zkf_lib::verify(&embedded.compiled, &embedded.artifact)?;
    if !verified {
        return Err("verification failed".into());
    }

    println!(
        "template={} backend={} public_outputs={:?} checked_public_inputs={:?}",
        program.name,
        embedded.compiled.backend,
        spec.public_outputs,
        checked.public_inputs
    );
    Ok(())
}
 "#
    .replace("__BACKEND__", backend)
}

fn colored_main_rs_content(backend: &str) -> String {
    r#"mod spec;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = "__BACKEND__";
    let theme = zkf_ui::ZkTheme::default();
    let (spec, program) = spec::load_program()?;
    let inputs_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
    let inputs = zkf_lib::load_inputs(inputs_path.to_str().expect("manifest path must be utf-8"))?;

    println!(
        "{}",
        zkf_ui::render_proof_banner(
            &program.name,
            program.signals.len(),
            program.constraints.len(),
            &theme
        )
    );

    let checked = zkf_lib::check_with_backend(&program, &inputs, backend, None, None)?;
    println!("{}", zkf_ui::render_check_result(&checked, &theme));

    let mut reporter = zkf_ui::ProofProgressReporter::default();
    let embedded = zkf_lib::compile_and_prove_with_progress_backend(
        &program,
        &inputs,
        backend,
        None,
        None,
        |event| reporter.observe(event),
    )?;
    reporter.clear();

    println!("{}", zkf_ui::render_proof_result(&embedded, &theme));
    let verified = zkf_lib::verify(&embedded.compiled, &embedded.artifact)?;
    if !verified {
        return Err("verification failed".into());
    }

    let labels = spec
        .public_outputs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    println!(
        "{}",
        zkf_ui::render_credential(&embedded.artifact.public_inputs, &labels, &theme)
    );
    println!("Verification: {} VALID", theme.success_symbol);
    Ok(())
}
 "#
    .replace("__BACKEND__", backend)
}

fn tui_main_rs_content(backend: &str) -> String {
    r#"mod spec;
mod dashboard;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let inputs_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
    let inputs = zkf_lib::load_inputs(inputs_path.to_str().expect("manifest path must be utf-8"))?;
    let (_spec, program) = spec::load_program()?;
    dashboard::run(program, inputs, "__BACKEND__")
}
 "#
    .replace("__BACKEND__", backend)
}

fn tui_dashboard_rs_content() -> &'static str {
    r#"use std::time::Duration;

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use zkf_tui::{DashboardAction, DashboardState, ProofJobUpdate, VaultEntry, ZkDashboard};

fn sample_state() -> DashboardState {
    DashboardState {
        entries: vec![
            VaultEntry {
                id: "1".to_string(),
                site: "mail.zir".to_string(),
                username: "alice".to_string(),
                category: "email".to_string(),
                strength: 94,
                proof_status: "Ready".to_string(),
            },
            VaultEntry {
                id: "2".to_string(),
                site: "bank.zir".to_string(),
                username: "alice.reserve".to_string(),
                category: "finance".to_string(),
                strength: 88,
                proof_status: "Ready".to_string(),
            },
        ],
        selected: 0,
        health_score: 91,
        proof_percent: 0,
        proof_stage_label: "Idle".to_string(),
        proof_activity_samples: Vec::new(),
        proof_running: false,
        audit_lines: vec![
            "Audit pipeline: PASS".to_string(),
            "Constraint surface: tight".to_string(),
            "Swarm defense: active".to_string(),
        ],
        status_line: "Press P to prove the selected credential.".to_string(),
        proof_modal: Default::default(),
    }
}

pub fn run(
    program: zkf_lib::Program,
    sample_inputs: zkf_lib::WitnessInputs,
    backend: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let terminal_backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(terminal_backend)?;
    let dashboard = ZkDashboard::new();
    let mut state = sample_state();
    let mut receiver: Option<std::sync::mpsc::Receiver<ProofJobUpdate>> = None;

    let result = loop {
        terminal.draw(|frame| dashboard.draw(frame, &state))?;

        let mut clear_receiver = false;
        if let Some(active) = receiver.as_ref() {
            while let Ok(message) = active.try_recv() {
                match message {
                    ProofJobUpdate::Event(event) => {
                        state.apply_proof_event(&event);
                    }
                    ProofJobUpdate::Finished(result) => {
                        state.entries[state.selected].proof_status =
                            if result.verified { "Verified" } else { "Invalid" }.to_string();
                        state.finish_proof(result.verified);
                        state.open_modal(
                            "Proof Result",
                            result
                                .progress_lines
                                .into_iter()
                                .chain([
                                    String::new(),
                                    result.proof_summary,
                                    String::new(),
                                    result.credential,
                                ])
                                .collect(),
                        );
                        state.status_line = "Proof completed.".to_string();
                        clear_receiver = true;
                    }
                    ProofJobUpdate::Failed(message) => {
                        state.fail_proof(&message);
                        state.open_modal("Proof Failed", vec![message.clone()]);
                        clear_receiver = true;
                    }
                }
            }
        }
        if clear_receiver {
            receiver = None;
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match dashboard.handle_key(&mut state, key) {
                    DashboardAction::None => {}
                    DashboardAction::Quit => break Ok(()),
                    DashboardAction::TriggerProof => {
                        if receiver.is_none() {
                            state.begin_proof();
                            receiver = Some(zkf_tui::spawn_local_proof_job_with_backend(
                                program.clone(),
                                sample_inputs.clone(),
                                backend.to_string(),
                            ));
                        }
                    }
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}
"#
}

fn smoke_test_content(style: AppStyle, backend: &str) -> String {
    match style {
        AppStyle::Minimal => format!(
            r#"#[path = "../src/spec.rs"]
mod spec;

#[test]
fn template_proves_and_verifies_and_rejects_violation() {{
    let handle = std::thread::Builder::new()
        .name("scaffold-smoke".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {{
            let backend = "{backend}";
            let (_spec, program) = spec::load_program().expect("program");
            let inputs_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
            let inputs = zkf_lib::load_inputs(
                inputs_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("sample inputs should load");
            let checked = zkf_lib::check_with_backend(&program, &inputs, backend, None, None)
                .expect("template should validate without proving");
            assert!(!checked.public_inputs.is_empty());
            let embedded = zkf_lib::compile_and_prove(&program, &inputs, backend, None, None)
                .expect("template should compile and prove");

            assert!(zkf_lib::verify(&embedded.compiled, &embedded.artifact).expect("verify"));
            let violation_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.violation.json");
            let violation_inputs = zkf_lib::load_inputs(
                violation_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("violation inputs should load");
            zkf_lib::compile_and_prove(&program, &violation_inputs, backend, None, None)
                .expect_err("violation inputs must fail closed");
        }})
        .expect("spawn scaffold smoke thread");
    handle.join().expect("scaffold smoke should succeed");
}}
"#
        ),
        AppStyle::Colored => format!(
            r#"#[path = "../src/spec.rs"]
mod spec;

#[test]
fn template_proves_and_verifies_with_progress_and_rejects_violation() {{
    let handle = std::thread::Builder::new()
        .name("scaffold-colored-smoke".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {{
            let backend = "{backend}";
            let (_spec, program) = spec::load_program().expect("program");
            let inputs_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
            let inputs = zkf_lib::load_inputs(
                inputs_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("sample inputs should load");
            let checked = zkf_lib::check_with_backend(&program, &inputs, backend, None, None)
                .expect("template should validate without proving");
            assert!(!checked.public_inputs.is_empty());
            let mut reporter = zkf_ui::ProofProgressReporter::new(true);
            let embedded = zkf_lib::compile_and_prove_with_progress_backend(
                &program,
                &inputs,
                backend,
                None,
                None,
                |event| reporter.observe(event),
            )
            .expect("template should compile and prove");

            assert!(zkf_lib::verify(&embedded.compiled, &embedded.artifact).expect("verify"));
            assert_eq!(reporter.lines().len(), 4);
            let violation_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.violation.json");
            let violation_inputs = zkf_lib::load_inputs(
                violation_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("violation inputs should load");
            zkf_lib::compile_and_prove_with_progress_backend(
                &program,
                &violation_inputs,
                backend,
                None,
                None,
                |_| {{}},
            )
            .expect_err("violation inputs must fail closed");
        }})
        .expect("spawn scaffold smoke thread");
    handle.join().expect("scaffold smoke should succeed");
}}
"#
        ),
        AppStyle::Tui => format!(
            r#"#[path = "../src/spec.rs"]
mod spec;

#[test]
fn template_proves_and_verifies_through_tui_worker_and_rejects_violation() {{
    let handle = std::thread::Builder::new()
        .name("scaffold-tui-smoke".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {{
            let backend = "{backend}";
            let (_spec, program) = spec::load_program().expect("program");
            let compliant_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
            let compliant_inputs = zkf_lib::load_inputs(
                compliant_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("compliant inputs should load");
            let result = zkf_tui::run_local_proof_demo_with_backend(
                &program,
                &compliant_inputs,
                backend,
            )
            .expect("proof demo");
            assert!(result.verified);
            assert_eq!(result.progress_lines.len(), 4);
            let violation_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.violation.json");
            let violation_inputs = zkf_lib::load_inputs(
                violation_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("violation inputs should load");
            zkf_tui::run_local_proof_demo_with_backend(&program, &violation_inputs, backend)
                .expect_err("violation inputs must fail closed");
        }})
        .expect("spawn scaffold smoke thread");
    handle.join().expect("scaffold smoke should succeed");
}}
"#
        ),
    }
}

fn readme_content(
    name: &str,
    template: &str,
    style: AppStyle,
    spec: &zkf_lib::AppSpecV1,
) -> String {
    let root = repo_root();
    let backend = scaffold_backend(spec.program.field);
    let aerospace_extras = if is_aerospace_template(template) {
        r#"- `scripts/benchmark.sh`: benchmark hook that exercises the scaffold smoke flow and records a local timing artifact.
- `scripts/generate_report.sh`: emits a regulator-facing local report stub under `artifacts/reports/`.
- `scripts/export_public_bundle.sh`: emits a sanitized default public bundle under `artifacts/public/`.
- `artifacts/public/`: default sanitized export target for partner/regulator sharing.
- `artifacts/reports/`: local report/evidence output directory for the scaffold."#
    } else {
        ""
    };
    let extra = match style {
        AppStyle::Minimal => {
            "- `src/main.rs`: validates with `zkf_lib::check_with_backend(...)`, then proves and verifies in-process with `zkf-lib`."
        }
        AppStyle::Colored => {
            "- `src/main.rs`: uses `zkf-ui` plus explicit-backend progress proving to render a styled proof banner, audit surface, proof summary, and credential output."
        }
        AppStyle::Tui => {
            "- `src/dashboard.rs`: wires a ratatui-style dashboard shell through `zkf-tui` and the explicit-backend local proof worker surface."
        }
    };

    format!(
        r#"# {name}

This standalone app was scaffolded with `zkf app init` against the local ZirOS checkout.

Template: `{template}`
Style: `{style}`
Style description: {style_description}

## What You Got

- `zirapp.json`: canonical declarative app spec edited by default for app changes.
- `src/spec.rs`: generic loader that turns `zirapp.json` into a `zkf_lib::Program` at runtime.
{extra}
- `inputs.compliant.json`: known-good inputs that should compile, prove, and verify.
- `inputs.violation.json`: intentionally bad inputs that should fail closed.
- `tests/smoke.rs`: proves the compliant inputs and asserts that the violation inputs are rejected.
- Rust `ProgramBuilder` remains available as the escape hatch when you need advanced authoring.
{aerospace_extras}

## Start Here

```bash
cd {name}
cargo run
cargo test
```

Edit loop:

1. Change [`zirapp.json`](zirapp.json) when you want to change the statement being proven.
2. Keep [`inputs.compliant.json`](inputs.compliant.json) as your known-good sample.
3. Keep [`inputs.violation.json`](inputs.violation.json) as the fail-closed regression case.
4. Re-run `cargo run` for the fast proof flow and `cargo test` for the end-to-end smoke test.

When a proof fails:

- Start with the signal labels in `zirapp.json`.
- If the failure mentions nonlinear anchoring, read `{nonlinear_anchoring}`.
- For the full standalone-app workflow, read `{app_guide}`.
- For the declarative spec reference, read `{appspec_guide}`.

## Current Template Contract

- Backend: `{backend}`
- Backend note: {backend_note}
- Expected private inputs: {expected_inputs:?}
- Public outputs: {public_outputs:?}
- Description: {description}
- Template args: {template_args:?}
{aerospace_contract}

## Run

```bash
cargo run
cargo test
```

Explore other scaffold variants with `ziros app gallery` (or `zkf app gallery`).
List declarative templates with `ziros app templates`.
"#,
        style = style.as_str(),
        style_description = style.one_line_description(),
        backend = backend,
        backend_note = backend_setup_note(backend),
        expected_inputs = spec.expected_inputs,
        public_outputs = spec.public_outputs,
        description = spec.description.as_deref().unwrap_or("n/a"),
        template_args = spec.template_args,
        aerospace_extras = aerospace_extras,
        aerospace_contract = if is_aerospace_template(template) {
            "- Aerospace posture: imported CRS only for regulator-facing wrap; TCP counted distributed transport; Neural Engine advisory only.\n- Production target: reusable Nova/HyperNova fold lane plus Plonky3 batch reducer and Groth16 final wrap."
        } else {
            ""
        },
        nonlinear_anchoring = root.join("docs/NONLINEAR_ANCHORING.md").display(),
        app_guide = root.join("docs/APP_DEVELOPER_GUIDE.md").display(),
        appspec_guide = root.join("docs/APPSPEC_REFERENCE.md").display(),
    )
}

fn scaffold_app(
    name: &str,
    template_name: &str,
    template_args: &BTreeMap<String, String>,
    style: AppStyle,
    out: Option<PathBuf>,
) -> Result<PathBuf, String> {
    let spec = template_spec(template_name, template_args)?;
    zkf_lib::build_app_spec(&spec).map_err(|error| error.to_string())?;
    let backend = scaffold_backend(spec.program.field);
    let root = out_dir(name, out)?;
    std::fs::create_dir_all(root.join("src"))
        .map_err(|error| format!("{}: {error}", root.join("src").display()))?;
    std::fs::create_dir_all(root.join("tests"))
        .map_err(|error| format!("{}: {error}", root.join("tests").display()))?;

    write_text(
        &root.join("Cargo.toml"),
        &cargo_toml_content(&crate_name(name), style),
    )?;
    write_text(&root.join("src/spec.rs"), spec_rs_content())?;
    let main_rs = match style {
        AppStyle::Minimal => minimal_main_rs_content(backend),
        AppStyle::Colored => colored_main_rs_content(backend),
        AppStyle::Tui => tui_main_rs_content(backend),
    };
    write_text(&root.join("src/main.rs"), &main_rs)?;
    if style == AppStyle::Tui {
        write_text(&root.join("src/dashboard.rs"), tui_dashboard_rs_content())?;
    }
    let smoke_test = smoke_test_content(style, backend);
    write_text(&root.join("tests/smoke.rs"), &smoke_test)?;
    write_json(&root.join("zirapp.json"), &spec)?;
    write_json(&root.join("inputs.compliant.json"), &spec.sample_inputs)?;
    write_json(&root.join("inputs.violation.json"), &spec.violation_inputs)?;
    if is_aerospace_template(template_name) {
        append_aerospace_scaffold(&root, template_name, backend)?;
    }
    write_text(
        &root.join("README.md"),
        &readme_content(name, template_name, style, &spec),
    )?;

    Ok(root)
}

fn resolve_cli_path(path: PathBuf) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path)
    } else {
        let cwd = std::env::current_dir()
            .map_err(|error| format!("failed to read current directory: {error}"))?;
        let joined = cwd.join(path);
        match joined.canonicalize() {
            Ok(canonical) => Ok(canonical),
            Err(_) => Ok(joined),
        }
    }
}

fn cargo_target_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(path);
    }

    let config_path = repo_root().join(".cargo/config.toml");
    if let Ok(contents) = std::fs::read_to_string(&config_path) {
        for line in contents.lines() {
            let trimmed = line.trim();
            if let Some(value) = trimmed.strip_prefix("target-dir") {
                let configured = value
                    .split_once('=')
                    .map(|(_, value)| value.trim().trim_matches('"'));
                if let Some(configured) = configured.filter(|value| !value.is_empty()) {
                    return repo_root().join(configured);
                }
            }
        }
    }

    let target_local = repo_root().join("target-local");
    if target_local.exists() {
        target_local
    } else {
        repo_root().join("target")
    }
}

fn apply_toolchain_env(command: &mut Command) {
    if let Some(value) = std::env::var_os("CARGO_HOME") {
        command.env("CARGO_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("CARGO_HOME", PathBuf::from(home).join(".cargo"));
    }

    if let Some(value) = std::env::var_os("RUSTUP_HOME") {
        command.env("RUSTUP_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("RUSTUP_HOME", PathBuf::from(home).join(".rustup"));
    }

    if let Some(value) = std::env::var_os("OPAMROOT") {
        command.env("OPAMROOT", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("OPAMROOT", PathBuf::from(home).join(".opam"));
    }

    if let Some(value) = std::env::var_os("ELAN_HOME") {
        command.env("ELAN_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("ELAN_HOME", PathBuf::from(home).join(".elan"));
    }
}

fn unix_now_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("failed to read system clock: {error}"))
}

fn reentry_production_mode_requested(flag: bool) -> bool {
    flag || std::env::var_os(REENTRY_ASSURANCE_PRODUCTION_ENV).is_some()
}

fn secure_random_array<const N: usize>() -> Result<[u8; N], String> {
    let mut bytes = [0u8; N];
    zkf_core::secure_random::secure_random_bytes(&mut bytes).map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn load_or_create_reentry_signer_keys(path: &Path) -> Result<ReentrySignerKeyFileV1, String> {
    if path.exists() {
        let key_file: ReentrySignerKeyFileV1 = read_json(path)?;
        key_file.validate()?;
        return Ok(key_file);
    }

    let mut ed25519_seed = [0u8; 32];
    zkf_core::secure_random::secure_random_bytes(&mut ed25519_seed)
        .map_err(|error| error.to_string())?;
    let randomness = secure_random_array::<KEY_GENERATION_RANDOMNESS_SIZE>()?;
    let keypair = generate_key_pair(randomness);
    let key_file = ReentrySignerKeyFileV1 {
        version: 1,
        ed25519_seed,
        ml_dsa87_signing_key: keypair.signing_key.as_slice().to_vec(),
        ml_dsa87_public_key: keypair.verification_key.as_slice().to_vec(),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    write_json(path, &key_file)?;
    Ok(key_file)
}

fn sign_reentry_mission_pack(
    mission_pack: ReentryMissionPackV2,
    signer_keys: &ReentrySignerKeyFileV1,
    signer_identity: &str,
    not_before_unix_epoch_seconds: u64,
    not_after_unix_epoch_seconds: u64,
) -> Result<SignedReentryMissionPackV1, String> {
    if signer_identity.trim().is_empty() {
        return Err("reentry signer identity must not be empty".to_string());
    }
    if not_before_unix_epoch_seconds > not_after_unix_epoch_seconds {
        return Err("reentry signer validity window is inverted".to_string());
    }

    let payload_digest =
        reentry_mission_pack_v2_digest(&mission_pack).map_err(|e| e.to_string())?;
    let public_keys = signer_keys.public_key_bundle();
    let placeholder = SignedReentryMissionPackV1 {
        payload: mission_pack,
        payload_digest,
        signer_identity: signer_identity.to_string(),
        signer_public_keys: public_keys,
        signer_signature_bundle: SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: Vec::new(),
            ml_dsa87: Vec::new(),
        },
        not_before_unix_epoch_seconds,
        not_after_unix_epoch_seconds,
        provenance_metadata: BTreeMap::from([(
            "signature_bundle".to_string(),
            "hybrid-ed25519-ml-dsa-44".to_string(),
        )]),
    };
    let signing_message = placeholder.signing_message()?;
    let ed25519_signing_key = SigningKey::from_bytes(&signer_keys.ed25519_seed);
    let ed25519_signature = ed25519_signing_key
        .sign(&signing_message)
        .to_bytes()
        .to_vec();
    let ml_dsa_signing_key = signer_keys.signing_key()?;
    let randomness = secure_random_array::<SIGNING_RANDOMNESS_SIZE>()?;
    let ml_dsa_signature = mldsa_sign(
        &ml_dsa_signing_key,
        &signing_message,
        REENTRY_ASSURANCE_ML_DSA_CONTEXT,
        randomness,
    )
    .map_err(|error| format!("failed to sign reentry mission pack with ML-DSA-44: {error:?}"))?;

    Ok(SignedReentryMissionPackV1 {
        signer_signature_bundle: SignatureBundle {
            scheme: SignatureScheme::HybridEd25519MlDsa87,
            ed25519: ed25519_signature,
            ml_dsa87: ml_dsa_signature.as_slice().to_vec(),
        },
        ..placeholder
    })
}

fn reentry_report_markdown(
    receipt: &ReentryAssuranceReceiptV2,
    summary: &Value,
    evidence_manifest: &Value,
    bundle_manifest: &Value,
) -> String {
    let boundary_markdown = mission_ops_boundary_markdown(&reentry_boundary_contract());
    let theorem_hypotheses = receipt
        .theorem_hypotheses
        .iter()
        .map(|item| format!("- `{item}`"))
        .collect::<Vec<_>>()
        .join("\n");
    let minimal_tcb = receipt
        .minimal_tcb
        .iter()
        .map(|item| format!("- `{item}`"))
        .collect::<Vec<_>>()
        .join("\n");
    let theorem_ids = REENTRY_THEOREM_IDS
        .iter()
        .map(|item| format!("- `{item}`"))
        .collect::<Vec<_>>()
        .join("\n");
    let oracle_summary = summary
        .get("oracle_summary")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let oracle_comparison = summary
        .get("oracle_comparison")
        .cloned()
        .unwrap_or_else(|| json!({}));

    format!(
        r#"# ZirOS Reentry Mission Assurance Report

## Receipt

- Mission ID: `{mission_id}`
- Mission pack digest: `{mission_pack_digest}`
- Signer manifest digest: `{signer_manifest_digest}`
- Signer identity: `{signer_identity}`
- Backend: `{backend}`
- Theorem lane: `{theorem_lane}`
- Model revision: `{model_revision}`
- Horizon steps: `{horizon_steps}`
- Fixed-point scale: `{fixed_point_scale}`
- Compliance bit: `{compliance_bit}`
- Peak dynamic pressure: `{peak_dynamic_pressure}`
- Peak heating rate: `{peak_heating_rate}`

## Mathematical Scope

- Mathematical model: {mathematical_model}
- Public receipt projects only commitments, peak metrics, and the compliance bit.
- GPU, ANE, telemetry, security supervision, and distributed proving remain operational annexes and are not correctness-bearing in this receipt.
- The accepted proof lane is the shipped RK4/private-table/abort circuit on Plonky3 with the fixed-policy CPU-first theorem lane.

### Mission-Ops Boundary

{boundary_markdown}

### Theorem Hypotheses

{theorem_hypotheses}

### Minimal TCB

{minimal_tcb}

## Mechanized Coverage

The current app-owned mechanized rows exercised by this bundle are:

{theorem_ids}

The evidence manifest for this bundle is serialized in `evidence_manifest.json`.
The artifact class matrix for this bundle is serialized in `bundle_manifest.json`.
The formal proof subtree for this bundle is rooted at `formal/STATUS.md`.

## Deterministic Oracle

```json
{oracle_summary_json}
```

```json
{oracle_comparison_json}
```

## Summary

```json
{summary_json}
```

## Evidence Manifest

```json
{evidence_json}
```

## Bundle Manifest

```json
{bundle_manifest_json}
```
"#,
        mission_id = receipt.mission_id,
        mission_pack_digest = receipt.mission_pack_digest,
        signer_manifest_digest = receipt.signer_manifest_digest,
        signer_identity = receipt.signer_identity,
        backend = receipt.backend,
        theorem_lane = receipt.theorem_lane,
        model_revision = receipt.model_revision,
        horizon_steps = receipt.horizon_steps,
        fixed_point_scale = receipt.fixed_point_scale,
        compliance_bit = receipt.compliance_bit,
        peak_dynamic_pressure = receipt.peak_dynamic_pressure,
        peak_heating_rate = receipt.peak_heating_rate,
        mathematical_model = receipt.mathematical_model,
        boundary_markdown = boundary_markdown,
        theorem_hypotheses = theorem_hypotheses,
        minimal_tcb = minimal_tcb,
        theorem_ids = theorem_ids,
        oracle_summary_json =
            serde_json::to_string_pretty(&oracle_summary).unwrap_or_else(|_| "{}".to_string()),
        oracle_comparison_json =
            serde_json::to_string_pretty(&oracle_comparison).unwrap_or_else(|_| "{}".to_string()),
        summary_json = serde_json::to_string_pretty(summary).unwrap_or_else(|_| "{}".to_string()),
        evidence_json =
            serde_json::to_string_pretty(evidence_manifest).unwrap_or_else(|_| "{}".to_string()),
        bundle_manifest_json =
            serde_json::to_string_pretty(bundle_manifest).unwrap_or_else(|_| "{}".to_string()),
    )
}

fn reentry_mission_ops_provenance_from_pack(signed_pack: &SignedReentryMissionPackV1) -> Value {
    let metadata = &signed_pack.payload.provenance_metadata;
    let source_model_manifest_digests = metadata
        .get(PROVENANCE_SOURCE_MODEL_MANIFEST_DIGESTS_JSON_KEY)
        .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok())
        .unwrap_or_default();
    json!({
        "nasa_classification_boundary": NasaClassificationBoundaryV1::default(),
        "source_model_manifest_digests": source_model_manifest_digests,
        "derived_model_package_digest": metadata.get(PROVENANCE_DERIVED_MODEL_PACKAGE_DIGEST_KEY),
        "scenario_library_manifest_digest": metadata.get(PROVENANCE_SCENARIO_LIBRARY_MANIFEST_DIGEST_KEY),
        "assurance_trace_matrix_digest": metadata.get(PROVENANCE_ASSURANCE_TRACE_MATRIX_DIGEST_KEY),
        "target_classification": metadata.get(PROVENANCE_NASA_CLASSIFICATION_KEY).cloned().unwrap_or_else(|| REENTRY_NASA_TARGET_CLASSIFICATION.to_string()),
    })
}

fn write_reentry_verification_json(
    bundle: &Path,
    verified: bool,
    oracle_matched: bool,
) -> Result<(), String> {
    let verification = json!({
        "application": "private-reentry-mission-assurance",
        "verified": verified,
        "oracle_matched": oracle_matched,
        "verified_at_unix_epoch_seconds": unix_now_seconds()?,
    });
    write_json(&bundle.join("verification.json"), &verification)
}

fn build_reentry_evidence_manifest(
    signed_pack: &SignedReentryMissionPackV1,
    signer_manifest: &ReentrySignerManifestV1,
    receipt: &ReentryAssuranceReceiptV2,
    artifacts: &[ArtifactDescriptorV1],
) -> Result<Value, String> {
    Ok(json!({
        "application": "private-reentry-mission-assurance",
        "schema": "zkf-reentry-evidence-manifest-v2",
        "mission_pack_digest": signed_pack.payload_digest,
        "signer_manifest_digest": reentry_signer_manifest_digest(signer_manifest).map_err(|e| e.to_string())?,
        "signer_identity": signed_pack.signer_identity,
        "backend": receipt.backend,
        "theorem_lane": receipt.theorem_lane,
        "model_revision": receipt.model_revision,
        "verification_ledger": "zkf-ir-spec/verification-ledger.json",
        "formal_proof_script": "scripts/run_verus_reentry_assurance_proofs.sh",
        "theorem_ids": REENTRY_THEOREM_IDS,
        "nasa_classification_boundary": NasaClassificationBoundaryV1::default(),
        "boundary_contract": reentry_boundary_contract(),
        "artifacts": artifacts,
        "mission_ops_provenance": reentry_mission_ops_provenance_from_pack(signed_pack),
        "notes": [
            "signature-library verification remains a named theorem hypothesis / TCB boundary",
            "the accepted proof lane uses private atmosphere and sine tables with in-circuit selected-row interpolation support",
            "abort behavior is bound inside the accepted proof as nominal-or-valid-abort compliance without disclosing whether abort triggered",
            "the intended NASA process target is Class D ground-support mission operations assurance; any Class C+ decision-chain use requires independent program assessment outside ZirOS",
            "the mission-ops surface uses normalized-export-based ingestion and does not natively replace GMAT, SPICE, Dymos/OpenMDAO, Trick/JEOD, Basilisk, cFS, or F Prime"
        ]
    }))
}

fn load_source_model_manifests(paths: &[PathBuf]) -> Result<Vec<SourceModelManifestV1>, String> {
    paths
        .iter()
        .map(|path| {
            let path = resolve_cli_path(path.clone())?;
            let manifest: SourceModelManifestV1 = read_json(&path)?;
            validate_source_model_manifest(&manifest).map_err(|e| e.to_string())?;
            Ok(manifest)
        })
        .collect()
}

fn maybe_load_json<T, F>(path: Option<PathBuf>, validator: F) -> Result<Option<T>, String>
where
    T: serde::de::DeserializeOwned,
    F: Fn(&T) -> Result<(), String>,
{
    path.map(|path| {
        let path = resolve_cli_path(path)?;
        let value: T = read_json(&path)?;
        validator(&value)?;
        Ok(value)
    })
    .transpose()
}

fn write_json_if_present<T: Serialize>(path: &Path, value: Option<&T>) -> Result<(), String> {
    if let Some(value) = value {
        write_json(path, value)?;
    }
    Ok(())
}

fn reentry_bundle_artifacts(
    receipt: &ReentryAssuranceReceiptV2,
    source_model_manifests: &[SourceModelManifestV1],
    include_signed_pack_descriptor: bool,
    include_derived_model_package: bool,
    include_scenario_library_manifest: bool,
    include_assurance_trace_matrix: bool,
) -> Result<Vec<ArtifactDescriptorV1>, String> {
    let proof_lane = receipt.theorem_lane.as_str();
    let mut artifacts = vec![
        reentry_artifact_descriptor(
            "compiled.json",
            ArtifactClassV1::ProofBearing,
            proof_lane,
            false,
            true,
            &["compiled accepted theorem-lane artifact"],
        ),
        reentry_artifact_descriptor(
            "proof.json",
            ArtifactClassV1::ProofBearing,
            proof_lane,
            false,
            true,
            &["proof artifact for the accepted theorem lane"],
        ),
        reentry_artifact_descriptor(
            "receipt.json",
            ArtifactClassV1::ProofBearing,
            proof_lane,
            false,
            true,
            &["public receipt for the accepted theorem lane"],
        ),
        reentry_artifact_descriptor(
            "verification.json",
            ArtifactClassV1::ProofBearing,
            proof_lane,
            false,
            true,
            &["bundle verification status and oracle parity gate"],
        ),
        reentry_artifact_descriptor(
            "summary.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            proof_lane,
            false,
            true,
            &["operator summary of the accepted theorem-lane run"],
        ),
        reentry_artifact_descriptor(
            "evidence_manifest.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            proof_lane,
            false,
            true,
            &["bundle evidence manifest with artifact classifications"],
        ),
        reentry_artifact_descriptor(
            "bundle_manifest.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            proof_lane,
            false,
            true,
            &["machine-visible artifact class matrix for the bundle"],
        ),
        reentry_artifact_descriptor(
            "mission_pack_provenance.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            proof_lane,
            false,
            true,
            &["governed provenance summary without private mission payload"],
        ),
        reentry_artifact_descriptor(
            "signer_manifest.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            proof_lane,
            false,
            true,
            &["pinned signer authority manifest"],
        ),
        reentry_artifact_descriptor(
            "oracle_summary.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            "deterministic-rust-rk4-oracle",
            false,
            true,
            &["deterministic oracle summary for the accepted model"],
        ),
        reentry_artifact_descriptor(
            "oracle_comparison.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            "deterministic-rust-rk4-oracle",
            false,
            true,
            &["release-blocking oracle parity comparison against the theorem lane"],
        ),
        reentry_artifact_descriptor(
            "mission_assurance_report.md",
            ArtifactClassV1::HumanReadableReportOnly,
            proof_lane,
            false,
            true,
            &["operator-facing candid report"],
        ),
        reentry_artifact_descriptor(
            "formal/STATUS.md",
            ArtifactClassV1::ProofBearing,
            proof_lane,
            false,
            true,
            &["formal status surface"],
        ),
        reentry_artifact_descriptor(
            "formal/exercised_surfaces.json",
            ArtifactClassV1::ProofBearing,
            proof_lane,
            false,
            true,
            &["formal exercised surfaces manifest"],
        ),
        reentry_artifact_descriptor(
            "formal/verus_reentry_assurance.log",
            ArtifactClassV1::ProofBearing,
            proof_lane,
            false,
            true,
            &["mechanized local proof log for reentry assurance"],
        ),
    ];
    if include_signed_pack_descriptor {
        artifacts.push(reentry_artifact_descriptor(
            "signed_mission_pack.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            "signed-ingress-authority",
            true,
            false,
            &["private signed mission payload; excluded from public export by default"],
        ));
    }
    if include_derived_model_package {
        artifacts.push(reentry_artifact_descriptor(
            "derived_model_package.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            "governed-mission-ops-provenance",
            false,
            true,
            &["approved reduced-order package bound into the signed mission pack"],
        ));
    }
    if include_scenario_library_manifest {
        artifacts.push(reentry_artifact_descriptor(
            "scenario_library_manifest.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            "governed-mission-ops-provenance",
            false,
            true,
            &["qualified scenario library"],
        ));
    }
    if include_assurance_trace_matrix {
        artifacts.push(reentry_artifact_descriptor(
            "assurance_trace_matrix.json",
            ArtifactClassV1::GovernedUpstreamEvidence,
            "governed-mission-ops-provenance",
            false,
            true,
            &["requirements-to-theorem trace matrix"],
        ));
    }
    for manifest in source_model_manifests {
        let digest = source_model_manifest_digest(manifest).map_err(|e| e.to_string())?;
        artifacts.push(reentry_artifact_descriptor(
            format!("source_model_manifests/{digest}.json"),
            ArtifactClassV1::GovernedUpstreamEvidence,
            "governed-mission-ops-provenance",
            false,
            true,
            &["normalized upstream source manifest"],
        ));
    }
    Ok(artifacts)
}

fn ingest_source_model_manifest(
    input: PathBuf,
    out: PathBuf,
    expected_tool: &str,
) -> Result<(), String> {
    let input = resolve_cli_path(input)?;
    let out = resolve_cli_path(out)?;
    let adapter_input: SourceModelAdapterInputV1 = read_json(&input)?;
    validate_source_model_adapter_input(&adapter_input, expected_tool)
        .map_err(|e| e.to_string())?;
    let manifest_id = format!(
        "{}-{expected_tool}-source-manifest",
        adapter_input.mission_id
    );
    let manifest = build_source_model_manifest_from_adapter_input(&adapter_input, &manifest_id)
        .map_err(|e| e.to_string())?;
    write_json(&out, &manifest)?;
    println!(
        "reentry assurance source model manifest written to {} (tool={}, mission_id={})",
        out.display(),
        expected_tool,
        manifest.mission_id
    );
    Ok(())
}

fn handle_reentry_derive_model(request: PathBuf, out: PathBuf) -> Result<(), String> {
    let request = resolve_cli_path(request)?;
    let out = resolve_cli_path(out)?;
    let request: DerivedModelRequestV1 = read_json(&request)?;
    let output = derive_reentry_model_package(&request).map_err(|e| e.to_string())?;
    fs::create_dir_all(&out)
        .map_err(|error| format!("failed to create {}: {error}", out.display()))?;
    write_json(
        &out.join("derived_model_package.json"),
        &output.derived_model_package,
    )?;
    write_json(&out.join("mission_pack_v2.json"), &output.mission_pack)?;
    println!(
        "reentry assurance derived model package written to {} (mission_id={}, package_id={})",
        out.display(),
        output.derived_model_package.mission_id,
        output.derived_model_package.package_id
    );
    Ok(())
}

fn handle_reentry_qualify_model(
    package: PathBuf,
    scenario_library: PathBuf,
    out: PathBuf,
) -> Result<(), String> {
    let package = resolve_cli_path(package)?;
    let scenario_library = resolve_cli_path(scenario_library)?;
    let out = resolve_cli_path(out)?;
    let package: DerivedModelPackageV1 = read_json(&package)?;
    validate_derived_model_package(&package).map_err(|e| e.to_string())?;
    let scenario_library: ScenarioLibraryManifestV1 = read_json(&scenario_library)?;
    validate_scenario_library_manifest(&scenario_library).map_err(|e| e.to_string())?;
    let (matrix, report) =
        qualify_reentry_model_package(&package, &scenario_library, &REENTRY_THEOREM_IDS)
            .map_err(|e| e.to_string())?;
    fs::create_dir_all(&out)
        .map_err(|error| format!("failed to create {}: {error}", out.display()))?;
    write_json(&out.join("assurance_trace_matrix.json"), &matrix)?;
    write_json(&out.join("qualification_report.json"), &report)?;
    println!(
        "reentry assurance qualification artifacts written to {} (mission_id={}, approved={})",
        out.display(),
        report.mission_id,
        report.approved
    );
    Ok(())
}

fn copy_optional_artifact(
    label: &str,
    source: Option<PathBuf>,
    out: &Path,
    artifacts: &mut Vec<ArtifactDescriptorV1>,
) -> Result<(), String> {
    let Some(source) = source else {
        return Ok(());
    };
    let source = resolve_cli_path(source)?;
    let dest = out.join(label);
    if source.is_dir() {
        copy_bundle_dir_recursive(&source, &dest)?;
    } else {
        copy_bundle_file(&source, &dest)?;
    }
    artifacts.push(reentry_artifact_descriptor(
        label,
        ArtifactClassV1::OperationalAnnex,
        "operational-annex",
        false,
        true,
        &["annex evidence artifact"],
    ));
    Ok(())
}

fn handle_reentry_publish_annex(
    bundle: PathBuf,
    out: PathBuf,
    metal_doctor: Option<PathBuf>,
    runtime_policy: Option<PathBuf>,
    telemetry: Option<PathBuf>,
    security: Option<PathBuf>,
) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    let out = resolve_cli_path(out)?;
    fs::create_dir_all(&out)
        .map_err(|error| format!("failed to create {}: {error}", out.display()))?;
    let receipt: ReentryAssuranceReceiptV2 = read_json(&bundle.join("receipt.json"))?;
    let mut artifacts = Vec::new();
    copy_optional_artifact("metal_doctor", metal_doctor, &out, &mut artifacts)?;
    copy_optional_artifact("runtime_policy", runtime_policy, &out, &mut artifacts)?;
    copy_optional_artifact("telemetry", telemetry, &out, &mut artifacts)?;
    copy_optional_artifact("security", security, &out, &mut artifacts)?;
    artifacts.push(reentry_artifact_descriptor(
        "annex_manifest.json",
        ArtifactClassV1::OperationalAnnex,
        "operational-annex",
        false,
        true,
        &["annex artifact manifest"],
    ));
    let manifest = PublishedAnnexManifestV2 {
        version: 1,
        schema: "zkf-reentry-annex-manifest-v2".to_string(),
        application: "private-reentry-mission-assurance".to_string(),
        mission_id: receipt.mission_id.clone(),
        mission_pack_digest: receipt.mission_pack_digest.clone(),
        theorem_lane: receipt.theorem_lane.clone(),
        boundary_contract: reentry_boundary_contract(),
        artifacts,
    };
    write_json(&out.join("annex_manifest.json"), &manifest)?;
    println!(
        "reentry assurance annex written to {} (mission_id={})",
        out.display(),
        receipt.mission_id
    );
    Ok(())
}

fn handle_reentry_build_dashboard(
    bundle: PathBuf,
    annex: Option<PathBuf>,
    out: PathBuf,
) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    let out = resolve_cli_path(out)?;
    fs::create_dir_all(&out)
        .map_err(|error| format!("failed to create {}: {error}", out.display()))?;
    let receipt: ReentryAssuranceReceiptV2 = read_json(&bundle.join("receipt.json"))?;
    let summary: Value = read_json(&bundle.join("summary.json"))?;
    let annex_manifest = annex
        .map(resolve_cli_path)
        .transpose()?
        .map(|path| read_json::<Value>(&path.join("annex_manifest.json")))
        .transpose()?;
    let artifacts = vec![reentry_artifact_descriptor(
        "openmct_dashboard.json",
        ArtifactClassV1::DownstreamIntegrationArtifact,
        "openmct-dashboard",
        false,
        true,
        &["Open MCT-facing dashboard bundle"],
    )];
    let dashboard = json!({
        "schema": "zkf-reentry-openmct-dashboard-v2",
        "name": "ZirOS Reentry Mission Assurance",
        "mission_id": receipt.mission_id,
        "classification_boundary": NasaClassificationBoundaryV1::default(),
        "boundary_contract": reentry_boundary_contract(),
        "artifacts": artifacts,
        "openmct": {
            "root": "reentry-assurance",
            "composition": [
                {"id": "receipt", "type": "telemetry.table"},
                {"id": "peaks", "type": "telemetry.table"},
                {"id": "annex", "type": "folder"}
            ],
            "telemetry": {
                "receipt": [
                    {"key": "compliance_bit", "name": "Compliance Bit", "values": [{"key": "value"}]},
                    {"key": "theorem_lane", "name": "Theorem Lane", "values": [{"key": "value"}]},
                    {"key": "nasa_classification", "name": "NASA Target Classification", "values": [{"key": "value"}]}
                ],
                "peaks": [
                    {"key": "peak_dynamic_pressure", "name": "Peak Dynamic Pressure", "values": [{"key": "value", "units": "public-surface"}]},
                    {"key": "peak_heating_rate", "name": "Peak Heating Rate", "values": [{"key": "value", "units": "public-surface"}]}
                ]
            }
        },
        "receipt": receipt,
        "summary": summary,
        "annex_manifest": annex_manifest,
    });
    write_json(&out.join("openmct_dashboard.json"), &dashboard)?;
    println!(
        "reentry assurance dashboard bundle written to {}",
        out.display()
    );
    Ok(())
}

fn write_reentry_handoff(bundle: PathBuf, out: PathBuf, target: &str) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    let out = resolve_cli_path(out)?;
    fs::create_dir_all(&out)
        .map_err(|error| format!("failed to create {}: {error}", out.display()))?;
    let receipt: ReentryAssuranceReceiptV2 = read_json(&bundle.join("receipt.json"))?;
    let files = [
        "receipt.json",
        "summary.json",
        "proof.json",
        "verification.json",
        "oracle_summary.json",
        "oracle_comparison.json",
        "mission_assurance_report.md",
        "evidence_manifest.json",
    ];
    let mut artifacts = Vec::new();
    for file in files {
        let source = bundle.join(file);
        if source.exists() {
            copy_bundle_file(&source, &out.join(file))?;
            artifacts.push(reentry_artifact_descriptor(
                file,
                ArtifactClassV1::DownstreamIntegrationArtifact,
                target,
                false,
                true,
                &["downstream handoff artifact"],
            ));
        }
    }
    let xtce_channels = vec![
        json!({"name": "compliance_bit", "type": "boolean", "source": "receipt.json"}),
        json!({"name": "peak_dynamic_pressure", "type": "string", "source": "receipt.json"}),
        json!({"name": "peak_heating_rate", "type": "string", "source": "receipt.json"}),
        json!({"name": "theorem_lane", "type": "string", "source": "receipt.json"}),
    ];
    artifacts.push(reentry_artifact_descriptor(
        "handoff_manifest.json",
        ArtifactClassV1::DownstreamIntegrationArtifact,
        target,
        false,
        true,
        &["downstream handoff manifest"],
    ));
    let handoff = DownstreamHandoffManifestV2 {
        version: 1,
        schema: "zkf-reentry-handoff-manifest-v2".to_string(),
        target: target.to_string(),
        mission_id: receipt.mission_id.clone(),
        mission_pack_digest: receipt.mission_pack_digest.clone(),
        signer_manifest_digest: receipt.signer_manifest_digest.clone(),
        theorem_lane: receipt.theorem_lane.clone(),
        boundary_contract: reentry_boundary_contract(),
        artifacts,
        xtce_channels,
    };
    write_json(&out.join("handoff_manifest.json"), &handoff)?;
    println!(
        "reentry assurance {target} handoff written to {}",
        out.display()
    );
    Ok(())
}

fn handle_reentry_sign_pack(
    pack: PathBuf,
    signer_key: PathBuf,
    source_model_manifests: Vec<PathBuf>,
    derived_model_package: Option<PathBuf>,
    scenario_library_manifest: Option<PathBuf>,
    assurance_trace_matrix: Option<PathBuf>,
    signer_id: String,
    not_before_unix_epoch_seconds: u64,
    not_after_unix_epoch_seconds: u64,
    out: PathBuf,
) -> Result<(), String> {
    let pack = resolve_cli_path(pack)?;
    let signer_key = resolve_cli_path(signer_key)?;
    let out = resolve_cli_path(out)?;
    let _: Value = read_json(&pack)?;
    let mut mission_pack: ReentryMissionPackV2 = read_json(&pack)?;
    let source_model_manifests = load_source_model_manifests(&source_model_manifests)?;
    let derived_model_package: Option<DerivedModelPackageV1> =
        maybe_load_json(derived_model_package, |package| {
            validate_derived_model_package(package).map_err(|e| e.to_string())
        })?;
    let scenario_library_manifest: Option<ScenarioLibraryManifestV1> =
        maybe_load_json(scenario_library_manifest, |manifest| {
            validate_scenario_library_manifest(manifest).map_err(|e| e.to_string())
        })?;
    let assurance_trace_matrix: Option<AssuranceTraceMatrixV1> =
        maybe_load_json(assurance_trace_matrix, |matrix| {
            zkf_lib::app::reentry_ops::validate_assurance_trace_matrix(matrix)
                .map_err(|e| e.to_string())
        })?;
    if !source_model_manifests.is_empty()
        || derived_model_package.is_some()
        || scenario_library_manifest.is_some()
        || assurance_trace_matrix.is_some()
    {
        let Some(derived_model_package) = derived_model_package.as_ref() else {
            return Err(
                "mission-ops signing requires --derived-model-package whenever source/scenario/trace manifests are supplied"
                    .to_string(),
            );
        };
        let source_manifest_digests = source_model_manifests
            .iter()
            .map(source_model_manifest_digest)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let derived_digest =
            derived_model_package_digest(derived_model_package).map_err(|e| e.to_string())?;
        let scenario_digest = scenario_library_manifest
            .as_ref()
            .map(scenario_library_manifest_digest)
            .transpose()
            .map_err(|e| e.to_string())?;
        let trace_digest = assurance_trace_matrix
            .as_ref()
            .map(assurance_trace_matrix_digest)
            .transpose()
            .map_err(|e| e.to_string())?;
        copy_ops_provenance_into_pack(
            &mut mission_pack,
            &source_manifest_digests,
            &derived_digest,
            scenario_digest.as_deref(),
            trace_digest.as_deref(),
        )
        .map_err(|e| e.to_string())?;
    }
    let signer_keys = load_or_create_reentry_signer_keys(&signer_key)?;
    let signed_pack = sign_reentry_mission_pack(
        mission_pack,
        &signer_keys,
        &signer_id,
        not_before_unix_epoch_seconds,
        not_after_unix_epoch_seconds,
    )?;
    write_json(&out, &signed_pack)?;
    println!(
        "signed reentry mission pack written to {} (signer={}, payload_digest={})",
        out.display(),
        signer_id,
        signed_pack.payload_digest
    );
    Ok(())
}

fn handle_reentry_validate_pack(
    signed_pack: PathBuf,
    signer_manifest: PathBuf,
    unix_time: Option<u64>,
) -> Result<(), String> {
    let signed_pack = resolve_cli_path(signed_pack)?;
    let signer_manifest = resolve_cli_path(signer_manifest)?;
    let signed_pack: SignedReentryMissionPackV1 = read_json(&signed_pack)?;
    let signer_manifest: ReentrySignerManifestV1 = read_json(&signer_manifest)?;
    let unix_time = unix_time.unwrap_or(unix_now_seconds()?);
    validate_signed_reentry_mission_pack(&signed_pack, &signer_manifest, unix_time)
        .map_err(|e| e.to_string())?;
    println!(
        "signed reentry mission pack validated: signer={} payload_digest={} manifest_digest={}",
        signed_pack.signer_identity,
        signed_pack.payload_digest,
        reentry_signer_manifest_digest(&signer_manifest).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn handle_reentry_prove(
    signed_pack: PathBuf,
    signer_manifest: PathBuf,
    source_model_manifests: Vec<PathBuf>,
    derived_model_package: Option<PathBuf>,
    scenario_library_manifest: Option<PathBuf>,
    assurance_trace_matrix: Option<PathBuf>,
    out: PathBuf,
    unix_time: Option<u64>,
) -> Result<(), String> {
    let total_started = Instant::now();
    let signed_pack_path = resolve_cli_path(signed_pack)?;
    let signer_manifest_path = resolve_cli_path(signer_manifest)?;
    let out = resolve_cli_path(out)?;

    let stage_started = Instant::now();
    let signed_pack: SignedReentryMissionPackV1 = read_json(&signed_pack_path)?;
    let signer_manifest: ReentrySignerManifestV1 = read_json(&signer_manifest_path)?;
    eprintln!(
        "reentry assurance: loaded signed pack and signer manifest in {} ms",
        stage_started.elapsed().as_millis()
    );

    let unix_time = unix_time.unwrap_or(unix_now_seconds()?);
    let stage_started = Instant::now();
    validate_signed_reentry_mission_pack(&signed_pack, &signer_manifest, unix_time)
        .map_err(|e| e.to_string())?;
    eprintln!(
        "reentry assurance: validated signed ingress in {} ms",
        stage_started.elapsed().as_millis()
    );

    let stage_started = Instant::now();
    let source_model_manifests = load_source_model_manifests(&source_model_manifests)?;
    let derived_model_package: Option<DerivedModelPackageV1> =
        maybe_load_json(derived_model_package, |package| {
            validate_derived_model_package(package).map_err(|e| e.to_string())
        })?;
    let scenario_library_manifest: Option<ScenarioLibraryManifestV1> =
        maybe_load_json(scenario_library_manifest, |manifest| {
            validate_scenario_library_manifest(manifest).map_err(|e| e.to_string())
        })?;
    let assurance_trace_matrix: Option<AssuranceTraceMatrixV1> =
        maybe_load_json(assurance_trace_matrix, |matrix| {
            zkf_lib::app::reentry_ops::validate_assurance_trace_matrix(matrix)
                .map_err(|e| e.to_string())
        })?;
    validate_mission_pack_ops_provenance(
        &signed_pack.payload,
        &source_model_manifests,
        derived_model_package.as_ref(),
        scenario_library_manifest.as_ref(),
        assurance_trace_matrix.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    eprintln!(
        "reentry assurance: validated mission-ops provenance in {} ms",
        stage_started.elapsed().as_millis()
    );

    let stage_started = Instant::now();
    let program =
        build_private_reentry_thermal_accepted_program_for_mission_pack(&signed_pack.payload)
            .map_err(|e| e.to_string())?;
    eprintln!(
        "reentry assurance: built accepted program in {} ms (signals={}, constraints={})",
        stage_started.elapsed().as_millis(),
        program.signals.len(),
        program.constraints.len()
    );

    let stage_started = Instant::now();
    let witness = private_reentry_thermal_accepted_witness_from_mission_pack(&signed_pack.payload)
        .map_err(|e| e.to_string())?;
    eprintln!(
        "reentry assurance: built accepted witness in {} ms (values={})",
        stage_started.elapsed().as_millis(),
        witness.values.len()
    );

    let steps = signed_pack.payload.public_envelope.certified_horizon_steps;
    let stage_started = Instant::now();
    let compiled = zkf_lib::compile(&program, "plonky3", None).map_err(|e| e.to_string())?;
    eprintln!(
        "reentry assurance: compiled accepted lane in {} ms",
        stage_started.elapsed().as_millis()
    );

    let stage_started = Instant::now();
    let artifact = zkf_lib::prove(&compiled, &witness).map_err(|e| e.to_string())?;
    eprintln!(
        "reentry assurance: proved accepted lane in {} ms (proof_bytes={})",
        stage_started.elapsed().as_millis(),
        artifact.proof.len()
    );

    let stage_started = Instant::now();
    let verified = zkf_lib::verify(&compiled, &artifact).map_err(|e| e.to_string())?;
    eprintln!(
        "reentry assurance: verified proof in {} ms",
        stage_started.elapsed().as_millis()
    );
    if !verified {
        return Err("reentry assurance proof failed verification".to_string());
    }

    fs::create_dir_all(&out)
        .map_err(|error| format!("failed to create {}: {error}", out.display()))?;
    let receipt =
        build_reentry_assurance_receipt_v2(&signed_pack, &signer_manifest, &witness, "plonky3")
            .map_err(|e| e.to_string())?;
    let oracle_summary =
        build_reentry_oracle_summary_v1(&signed_pack.payload).map_err(|e| e.to_string())?;
    let oracle_comparison = compare_reentry_receipt_to_oracle_v1(&receipt, &oracle_summary);
    release_block_on_oracle_mismatch(
        "reentry proof bundle",
        oracle_comparison.matched,
        &oracle_comparison.mismatches,
    )?;
    let mission_pack_provenance = json!({
        "mission_pack_digest": receipt.mission_pack_digest,
        "signer_manifest_digest": receipt.signer_manifest_digest,
        "signer_identity": receipt.signer_identity,
        "nasa_classification_boundary": NasaClassificationBoundaryV1::default(),
        "boundary_contract": reentry_boundary_contract(),
        "mission_ops_provenance": reentry_mission_ops_provenance_from_pack(&signed_pack),
    });
    let exercised_surfaces = json!({
        "application": "private-reentry-mission-assurance",
        "schema": "zkf-reentry-formal-exercised-surfaces-v1",
        "backend": "plonky3",
        "theorem_lane": receipt.theorem_lane,
        "model_revision": receipt.model_revision,
        "mission_id": receipt.mission_id,
        "mission_pack_digest": signed_pack.payload_digest,
        "signer_manifest_digest": reentry_signer_manifest_digest(&signer_manifest).map_err(|e| e.to_string())?,
        "formal_proof_scripts": REENTRY_FORMAL_SCRIPT_SPECS.iter().map(|spec| json!({
            "name": spec.name,
            "script_relative_path": spec.script_relative_path,
            "log_file_name": spec.log_file_name,
        })).collect::<Vec<_>>(),
        "theorem_ids": REENTRY_THEOREM_IDS,
        "bundle_contract": [
            "signed_mission_pack.json",
            "signer_manifest.json",
            "compiled.json",
            "proof.json",
            "receipt.json",
            "summary.json",
            "evidence_manifest.json",
            "bundle_manifest.json",
            "verification.json",
            "mission_pack_provenance.json",
            "oracle_summary.json",
            "oracle_comparison.json",
            "mission_assurance_report.md",
            "formal/STATUS.md",
            "formal/exercised_surfaces.json",
            "formal/verus_reentry_assurance.log"
        ],
    });
    let formal_evidence =
        collect_formal_evidence(&out, &exercised_surfaces, &REENTRY_FORMAL_SCRIPT_SPECS)
            .map_err(|e| e.to_string())?;
    let bundle_artifacts = reentry_bundle_artifacts(
        &receipt,
        &source_model_manifests,
        true,
        derived_model_package.is_some(),
        scenario_library_manifest.is_some(),
        assurance_trace_matrix.is_some(),
    )?;
    let mut evidence_manifest = build_reentry_evidence_manifest(
        &signed_pack,
        &signer_manifest,
        &receipt,
        &bundle_artifacts,
    )?;
    if let Some(object) = evidence_manifest.as_object_mut() {
        object.insert("formal_evidence".to_string(), formal_evidence.clone());
        object.insert("oracle_summary".to_string(), json!(oracle_summary));
        object.insert("oracle_comparison".to_string(), json!(oracle_comparison));
    }
    let bundle_manifest = bundle_manifest_from_parts(&receipt, bundle_artifacts.clone());
    let summary = json!({
        "application": "private-reentry-mission-assurance",
        "backend": "plonky3",
        "verified": verified,
        "oracle_matched": true,
        "steps": steps,
        "program_digest": artifact.program_digest,
        "mission_pack_digest": signed_pack.payload_digest,
        "signer_manifest_digest": reentry_signer_manifest_digest(&signer_manifest).map_err(|e| e.to_string())?,
        "signer_identity": signed_pack.signer_identity,
        "theorem_lane": receipt.theorem_lane,
        "model_revision": receipt.model_revision,
        "mathematical_model": receipt.mathematical_model,
        "theorem_hypotheses": receipt.theorem_hypotheses,
        "minimal_tcb": receipt.minimal_tcb,
        "accepted_backend": compiled.backend.to_string(),
        "public_inputs_surface": "signed-reentry-mission-pack-v2",
        "formal_status": formal_evidence["status"],
        "nasa_target_classification": REENTRY_NASA_TARGET_CLASSIFICATION,
        "class_c_or_higher_requires_independent_assessment": true,
        "boundary_contract": reentry_boundary_contract(),
        "mission_ops_provenance": reentry_mission_ops_provenance_from_pack(&signed_pack),
        "oracle_summary": oracle_summary,
        "oracle_comparison": oracle_comparison,
    });
    let report = reentry_report_markdown(
        &receipt,
        &summary,
        &evidence_manifest,
        &json!(bundle_manifest),
    );

    write_json(&out.join("signed_mission_pack.json"), &signed_pack)?;
    write_json(&out.join("signer_manifest.json"), &signer_manifest)?;
    if !source_model_manifests.is_empty() {
        let manifest_dir = out.join("source_model_manifests");
        fs::create_dir_all(&manifest_dir)
            .map_err(|error| format!("failed to create {}: {error}", manifest_dir.display()))?;
        for manifest in &source_model_manifests {
            let digest = source_model_manifest_digest(manifest).map_err(|e| e.to_string())?;
            write_json(&manifest_dir.join(format!("{digest}.json")), manifest)?;
        }
    }
    write_json_if_present(
        &out.join("derived_model_package.json"),
        derived_model_package.as_ref(),
    )?;
    write_json_if_present(
        &out.join("scenario_library_manifest.json"),
        scenario_library_manifest.as_ref(),
    )?;
    write_json_if_present(
        &out.join("assurance_trace_matrix.json"),
        assurance_trace_matrix.as_ref(),
    )?;
    write_json(&out.join("compiled.json"), &compiled)?;
    write_json(&out.join("proof.json"), &artifact)?;
    write_json(&out.join("receipt.json"), &receipt)?;
    write_json(&out.join("oracle_summary.json"), &summary["oracle_summary"])?;
    write_json(
        &out.join("oracle_comparison.json"),
        &summary["oracle_comparison"],
    )?;
    write_json(&out.join("summary.json"), &summary)?;
    write_json(&out.join("evidence_manifest.json"), &evidence_manifest)?;
    write_json(&out.join("bundle_manifest.json"), &bundle_manifest)?;
    write_json(
        &out.join("mission_pack_provenance.json"),
        &mission_pack_provenance,
    )?;
    write_text(&out.join("mission_assurance_report.md"), &report)?;
    write_reentry_verification_json(&out, verified, true)?;

    println!(
        "reentry assurance bundle exported to {} (steps={}, backend=plonky3, theorem_lane={}, total_ms={})",
        out.display(),
        steps,
        receipt.theorem_lane,
        total_started.elapsed().as_millis()
    );
    Ok(())
}

fn handle_reentry_verify(bundle: PathBuf) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    let compiled = read_json(&bundle.join("compiled.json"))?;
    let artifact = read_json(&bundle.join("proof.json"))?;
    let verified = zkf_lib::verify(&compiled, &artifact).map_err(|e| e.to_string())?;
    if !verified {
        return Err(format!(
            "reentry assurance proof in {} failed verification",
            bundle.display()
        ));
    }
    ensure_oracle_comparison_matched(&bundle)?;
    write_reentry_verification_json(&bundle, true, true)?;
    println!("reentry assurance bundle verified: {}", bundle.display());
    Ok(())
}

fn handle_reentry_report(bundle: PathBuf, out: Option<PathBuf>) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    ensure_oracle_comparison_matched(&bundle)?;
    let receipt: ReentryAssuranceReceiptV2 = read_json(&bundle.join("receipt.json"))?;
    let summary: Value = read_json(&bundle.join("summary.json"))?;
    let evidence_manifest: Value = read_json(&bundle.join("evidence_manifest.json"))?;
    let bundle_manifest: Value = read_json(&bundle.join("bundle_manifest.json"))?;
    let report = reentry_report_markdown(&receipt, &summary, &evidence_manifest, &bundle_manifest);
    let out = out
        .map(resolve_cli_path)
        .transpose()?
        .unwrap_or_else(|| bundle.join("mission_assurance_report.md"));
    write_text(&out, &report)?;
    println!("reentry assurance report written to {}", out.display());
    Ok(())
}

fn copy_bundle_file(source: &Path, destination: &Path) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create {}: {error}", parent.display()))?;
    }
    fs::copy(source, destination).map_err(|error| {
        format!(
            "failed to copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(())
}

fn copy_bundle_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::metadata(source)
        .map_err(|error| format!("failed to stat {}: {error}", source.display()))?;
    if !metadata.is_dir() {
        return Err(format!(
            "expected directory at {} but found a non-directory entry",
            source.display()
        ));
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("failed to create {}: {error}", destination.display()))?;
    for entry in fs::read_dir(source)
        .map_err(|error| format!("failed to read {}: {error}", source.display()))?
    {
        let entry =
            entry.map_err(|error| format!("failed to iterate {}: {error}", source.display()))?;
        let entry_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry
            .file_type()
            .map_err(|error| format!("failed to stat {}: {error}", entry_path.display()))?
            .is_dir()
        {
            copy_bundle_dir_recursive(&entry_path, &destination_path)?;
        } else {
            copy_bundle_file(&entry_path, &destination_path)?;
        }
    }
    Ok(())
}

fn handle_reentry_export_bundle(
    bundle: PathBuf,
    out: PathBuf,
    include_private: bool,
) -> Result<(), String> {
    let bundle = resolve_cli_path(bundle)?;
    let out = resolve_cli_path(out)?;
    fs::create_dir_all(&out)
        .map_err(|error| format!("failed to create {}: {error}", out.display()))?;

    ensure_oracle_comparison_matched(&bundle)?;
    let bundle_manifest: ReentryBundleManifestV1 = read_json(&bundle.join("bundle_manifest.json"))?;
    copy_described_artifacts(&bundle, &out, &bundle_manifest.artifacts, include_private)?;
    let exported_bundle_artifacts =
        exportable_artifacts(&bundle_manifest.artifacts, include_private);
    let exported_bundle_manifest = ReentryBundleManifestV1 {
        artifacts: exported_bundle_artifacts.clone(),
        ..bundle_manifest.clone()
    };
    write_json(&out.join("bundle_manifest.json"), &exported_bundle_manifest)?;

    let mut exported_evidence_manifest: Value = read_json(&bundle.join("evidence_manifest.json"))?;
    if let Some(object) = exported_evidence_manifest.as_object_mut() {
        object.insert(
            "artifacts".to_string(),
            serde_json::to_value(&exported_bundle_artifacts).map_err(|error| {
                format!("failed to serialize exported artifact descriptors: {error}")
            })?,
        );
    }
    write_json(
        &out.join("evidence_manifest.json"),
        &exported_evidence_manifest,
    )?;

    let receipt: ReentryAssuranceReceiptV2 = read_json(&out.join("receipt.json"))?;
    let summary: Value = read_json(&out.join("summary.json"))?;
    let exported_report = reentry_report_markdown(
        &receipt,
        &summary,
        &exported_evidence_manifest,
        &json!(exported_bundle_manifest),
    );
    write_text(&out.join("mission_assurance_report.md"), &exported_report)?;

    let annex_manifest_path = bundle.join("annex/annex_manifest.json");
    if annex_manifest_path.exists() {
        let annex_manifest: PublishedAnnexManifestV2 = read_json(&annex_manifest_path)?;
        copy_described_artifacts(
            &bundle.join("annex"),
            &out.join("annex"),
            &annex_manifest.artifacts,
            include_private,
        )?;
    }
    let dashboard_manifest_path = bundle.join("dashboard/openmct_dashboard.json");
    if dashboard_manifest_path.exists() {
        let dashboard: Value = read_json(&dashboard_manifest_path)?;
        let artifacts: Vec<ArtifactDescriptorV1> = serde_json::from_value(
            dashboard
                .get("artifacts")
                .cloned()
                .unwrap_or_else(|| json!([])),
        )
        .map_err(|error| format!("invalid dashboard artifact descriptors: {error}"))?;
        copy_described_artifacts(
            &bundle.join("dashboard"),
            &out.join("dashboard"),
            &artifacts,
            include_private,
        )?;
    }
    for dir_name in ["handoff_cfs", "handoff_fprime"] {
        let handoff_manifest_path = bundle.join(dir_name).join("handoff_manifest.json");
        if handoff_manifest_path.exists() {
            let handoff_manifest: DownstreamHandoffManifestV2 = read_json(&handoff_manifest_path)?;
            copy_described_artifacts(
                &bundle.join(dir_name),
                &out.join(dir_name),
                &handoff_manifest.artifacts,
                include_private,
            )?;
            let exported_handoff_dir = out.join(dir_name);
            let handoff_evidence_manifest = exported_handoff_dir.join("evidence_manifest.json");
            if handoff_evidence_manifest.exists() {
                write_json(&handoff_evidence_manifest, &exported_evidence_manifest)?;
            }
            let handoff_report = exported_handoff_dir.join("mission_assurance_report.md");
            if handoff_report.exists() {
                write_text(&handoff_report, &exported_report)?;
            }
        }
    }

    write_text(
        &out.join("README.md"),
        if include_private {
            "This export includes the signed private mission pack. Handle it as restricted mission data. ZirOS targets ground-side mission assurance at the NASA Class D boundary, uses normalized-export-based ingestion, and does not natively replace GMAT, SPICE, Dymos/OpenMDAO, Trick/JEOD, Basilisk, cFS, or F Prime. Any Class C or higher decision-chain use requires independent assessment outside ZirOS.\n"
        } else {
            "This export is release-safe: it carries the correctness-bearing receipt/proof surface plus governed mission-ops provenance and any bundled annex/dashboard/handoff artifacts, while intentionally omitting the private mission pack and any witness material by default. ZirOS targets ground-side mission assurance at the NASA Class D boundary, uses normalized-export-based ingestion, and does not natively replace GMAT, SPICE, Dymos/OpenMDAO, Trick/JEOD, Basilisk, cFS, or F Prime. Any Class C or higher decision-chain use requires independent assessment outside ZirOS.\n"
        },
    )?;
    if !include_private {
        scrub_public_export_text_tree(&out)?;
    }
    println!(
        "reentry assurance release bundle exported to {} (include_private={})",
        out.display(),
        include_private
    );
    Ok(())
}

fn handle_reentry_assurance_legacy(
    inputs: PathBuf,
    out: PathBuf,
    production: bool,
) -> Result<(), String> {
    if reentry_production_mode_requested(production) {
        return Err(
            "production reentry assurance runs require `zkf app reentry-assurance prove --signed-pack ... --signer-manifest ...`; the legacy `--inputs/--out` alias is dev/test only"
                .to_string(),
        );
    }
    let inputs = resolve_cli_path(inputs)?;
    let out = resolve_cli_path(out)?;
    let _: Value = read_json(&inputs)?;
    let mission_pack: ReentryMissionPackV1 = read_json(&inputs)?;
    let request: zkf_lib::PrivateReentryThermalRequestV1 = mission_pack.clone().into();
    let steps = request.public.step_count;
    let template = private_reentry_thermal_showcase_with_steps(steps).map_err(|e| e.to_string())?;
    let witness_inputs =
        zkf_core::WitnessInputs::try_from(request.clone()).map_err(|e| e.to_string())?;
    let witness = private_reentry_thermal_witness_with_steps(&witness_inputs, steps)
        .map_err(|e| e.to_string())?;
    let compiled =
        zkf_lib::compile(&template.program, "plonky3", None).map_err(|e| e.to_string())?;
    let artifact = zkf_lib::prove(&compiled, &witness).map_err(|e| e.to_string())?;
    let verified = zkf_lib::verify(&compiled, &artifact).map_err(|e| e.to_string())?;
    if !verified {
        return Err("reentry assurance proof failed verification".to_string());
    }

    fs::create_dir_all(&out)
        .map_err(|error| format!("failed to create {}: {error}", out.display()))?;
    let receipt = build_reentry_assurance_receipt(&mission_pack, &witness, "plonky3")
        .map_err(|e| e.to_string())?;
    let summary = json!({
        "application": "private-reentry-mission-assurance",
        "backend": "plonky3",
        "verified": verified,
        "steps": steps,
        "program_digest": artifact.program_digest,
        "mission_pack_digest": receipt.mission_pack_digest,
        "theorem_lane": receipt.theorem_lane,
        "mathematical_model": receipt.mathematical_model,
        "theorem_hypotheses": receipt.theorem_hypotheses,
        "minimal_tcb": receipt.minimal_tcb,
        "accepted_backend": compiled.backend.to_string(),
        "public_inputs_surface": "legacy-unsigned-reentry-mission-pack-v1",
    });
    write_json(&out.join("mission_pack.json"), &mission_pack)?;
    write_json(&out.join("request.json"), &request)?;
    write_json(&out.join("compiled.json"), &compiled)?;
    write_json(&out.join("witness.json"), &witness)?;
    write_json(&out.join("proof.json"), &artifact)?;
    write_json(&out.join("receipt.json"), &receipt)?;
    write_json(&out.join("summary.json"), &summary)?;

    println!(
        "reentry assurance bundle exported to {} (steps={}, backend=plonky3, theorem_lane={})",
        out.display(),
        steps,
        receipt.theorem_lane
    );
    Ok(())
}

fn handle_powered_descent(
    inputs: PathBuf,
    out: PathBuf,
    full_audit: bool,
    bundle_mode: String,
    trusted_setup_blob: Option<PathBuf>,
    trusted_setup_manifest: Option<PathBuf>,
) -> Result<(), String> {
    let inputs = resolve_cli_path(inputs)?;
    let out = resolve_cli_path(out)?;
    let _: Value = read_json(&inputs)?;
    let request: PrivatePoweredDescentRequestV1 = read_json(&inputs)?;
    match bundle_mode.as_str() {
        "debug" | "public" => {}
        other => {
            return Err(format!(
                "unsupported --bundle-mode '{other}' (expected debug or public)"
            ));
        }
    }
    if trusted_setup_manifest.is_some() && trusted_setup_blob.is_none() {
        return Err(
            "--trusted-setup-manifest requires --trusted-setup-blob so the importer can bind both artifacts"
                .to_string(),
        );
    }
    let trusted_setup_blob = trusted_setup_blob.map(resolve_cli_path).transpose()?;
    let trusted_setup_manifest = trusted_setup_manifest.map(resolve_cli_path).transpose()?;

    let example_name = "private_powered_descent_showcase";
    let example_source = repo_root()
        .join("zkf-lib")
        .join("examples")
        .join(format!("{example_name}.rs"));
    if !example_source.is_file() {
        return Err(format!(
            "powered descent exporter is not available in this checkout yet (missing {})",
            example_source.display()
        ));
    }

    let debug_example = cargo_target_dir()
        .join("debug")
        .join("examples")
        .join(example_name);
    let release_example = cargo_target_dir()
        .join("release")
        .join("examples")
        .join(example_name);

    let prefer_release_example =
        full_audit || request.public.step_count >= PRIVATE_POWERED_DESCENT_DEFAULT_STEPS;

    let mut command = if prefer_release_example && release_example.is_file() {
        Command::new(release_example)
    } else if debug_example.is_file() {
        Command::new(debug_example)
    } else if release_example.is_file() {
        Command::new(release_example)
    } else {
        let mut cargo = Command::new("cargo");
        cargo
            .current_dir(repo_root())
            .arg("run")
            .arg("-p")
            .arg("zkf-lib")
            .arg("--example")
            .arg(example_name)
            .arg("--");
        cargo
    };
    command
        .current_dir(repo_root())
        .arg(&out)
        .env("ZKF_PRIVATE_POWERED_DESCENT_INPUTS_JSON", &inputs)
        .env(POWERED_DESCENT_BUNDLE_MODE_ENV, &bundle_mode)
        .env("ZKF_SWARM", "1")
        .env("ZKF_SWARM_KEY_BACKEND", "file")
        .env("ZKF_SECURITY_POLICY_MODE", "observe");
    apply_toolchain_env(&mut command);
    if cfg!(target_os = "macos") && prefer_release_example {
        command
            .env("MallocNanoZone", "0")
            .env("MallocSpaceEfficient", "1");
    }
    if full_audit {
        command.env("ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT", "1");
    }
    if let Some(path) = trusted_setup_blob.as_ref() {
        command
            .env(GROTH16_SETUP_BLOB_PATH_ENV, path)
            .env(POWERED_DESCENT_PRODUCTION_ENV, "1");
    }
    if let Some(path) = trusted_setup_manifest.as_ref() {
        command
            .env(POWERED_DESCENT_TRUSTED_SETUP_MANIFEST_ENV, path)
            .env(POWERED_DESCENT_PRODUCTION_ENV, "1");
    }

    let status = command
        .status()
        .map_err(|error| format!("failed to launch powered descent exporter: {error}"))?;
    if !status.success() {
        return Err(format!(
            "powered descent exporter failed via `cargo run -p zkf-lib --example {example_name}`"
        ));
    }

    println!(
        "powered descent bundle exported to {} (steps={}, circuit=private_powered_descent_showcase_{}_step, full_audit={}, bundle_mode={}, trusted_setup={})",
        out.display(),
        request.public.step_count,
        request.public.step_count,
        full_audit,
        bundle_mode,
        trusted_setup_blob.is_some()
    );
    Ok(())
}

fn handle_reentry_assurance_command(args: ReentryAssuranceArgs) -> Result<(), String> {
    match args.command {
        Some(ReentryAssuranceCommands::SignPack {
            pack,
            signer_key,
            source_model_manifests,
            derived_model_package,
            scenario_library_manifest,
            assurance_trace_matrix,
            signer_id,
            not_before_unix_epoch_seconds,
            not_after_unix_epoch_seconds,
            out,
        }) => handle_reentry_sign_pack(
            pack,
            signer_key,
            source_model_manifests,
            derived_model_package,
            scenario_library_manifest,
            assurance_trace_matrix,
            signer_id,
            not_before_unix_epoch_seconds,
            not_after_unix_epoch_seconds,
            out,
        ),
        Some(ReentryAssuranceCommands::ValidatePack {
            signed_pack,
            signer_manifest,
            unix_time,
        }) => handle_reentry_validate_pack(signed_pack, signer_manifest, unix_time),
        Some(ReentryAssuranceCommands::Prove {
            signed_pack,
            signer_manifest,
            source_model_manifests,
            derived_model_package,
            scenario_library_manifest,
            assurance_trace_matrix,
            out,
            unix_time,
        }) => handle_reentry_prove(
            signed_pack,
            signer_manifest,
            source_model_manifests,
            derived_model_package,
            scenario_library_manifest,
            assurance_trace_matrix,
            out,
            unix_time,
        ),
        Some(ReentryAssuranceCommands::Verify { bundle }) => handle_reentry_verify(bundle),
        Some(ReentryAssuranceCommands::Report { bundle, out }) => {
            handle_reentry_report(bundle, out)
        }
        Some(ReentryAssuranceCommands::ExportBundle {
            bundle,
            out,
            include_private,
        }) => handle_reentry_export_bundle(bundle, out, include_private),
        Some(ReentryAssuranceCommands::IngestGmat { input, out }) => {
            ingest_source_model_manifest(input, out, "gmat")
        }
        Some(ReentryAssuranceCommands::IngestSpice { input, out }) => {
            ingest_source_model_manifest(input, out, "spice")
        }
        Some(ReentryAssuranceCommands::IngestOpenMdao { input, out }) => {
            ingest_source_model_manifest(input, out, "openmdao")
        }
        Some(ReentryAssuranceCommands::IngestTrick { input, out }) => {
            ingest_source_model_manifest(input, out, "trick")
        }
        Some(ReentryAssuranceCommands::DeriveModel { request, out }) => {
            handle_reentry_derive_model(request, out)
        }
        Some(ReentryAssuranceCommands::QualifyModel {
            package,
            scenario_library,
            out,
        }) => handle_reentry_qualify_model(package, scenario_library, out),
        Some(ReentryAssuranceCommands::PublishAnnex {
            bundle,
            out,
            metal_doctor,
            runtime_policy,
            telemetry,
            security,
        }) => handle_reentry_publish_annex(
            bundle,
            out,
            metal_doctor,
            runtime_policy,
            telemetry,
            security,
        ),
        Some(ReentryAssuranceCommands::BuildDashboard { bundle, annex, out }) => {
            handle_reentry_build_dashboard(bundle, annex, out)
        }
        Some(ReentryAssuranceCommands::HandoffCfs { bundle, out }) => {
            write_reentry_handoff(bundle, out, "cFS")
        }
        Some(ReentryAssuranceCommands::HandoffFprime { bundle, out }) => {
            write_reentry_handoff(bundle, out, "F Prime")
        }
        None => {
            let inputs = args
                .inputs
                .ok_or_else(|| "legacy reentry-assurance alias requires --inputs".to_string())?;
            let out = args
                .out
                .ok_or_else(|| "legacy reentry-assurance alias requires --out".to_string())?;
            handle_reentry_assurance_legacy(inputs, out, args.production)
        }
    }
}

pub(crate) fn handle_app(command: AppCommands) -> Result<(), String> {
    match command {
        AppCommands::Init {
            name,
            name_positional,
            template,
            template_arg,
            style,
            out,
        } => {
            let name = name
                .or(name_positional)
                .ok_or_else(|| "app init requires a name".to_string())?;
            let template_args = parse_template_args(&template_arg)?;
            let style = AppStyle::parse(&style)?;
            let path = scaffold_app(&name, &template, &template_args, style, out)?;
            println!(
                "app scaffold created: template={} style={} -> {}\nnext:\n  cd {}\n  cargo run\n  cargo test\n  edit {}/zirapp.json\n  read {}/README.md",
                template,
                style.as_str(),
                path.display(),
                path.display(),
                path.display(),
                path.display(),
            );
            Ok(())
        }
        AppCommands::Gallery => {
            println!("{}", render_gallery());
            Ok(())
        }
        AppCommands::Templates { json } => {
            println!("{}", render_templates(json)?);
            Ok(())
        }
        AppCommands::PoweredDescent {
            inputs,
            out,
            full_audit,
            bundle_mode,
            trusted_setup_blob,
            trusted_setup_manifest,
        } => handle_powered_descent(
            inputs,
            out,
            full_audit,
            bundle_mode,
            trusted_setup_blob,
            trusted_setup_manifest,
        ),
        AppCommands::ReentryAssurance(args) => handle_reentry_assurance_command(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::CommandFactory;
    use std::panic;
    use std::thread;
    use tempfile::tempdir;

    const CLI_TEST_STACK_SIZE: usize = 128 * 1024 * 1024;

    fn run_cli_test_on_large_stack<F>(name: &str, test: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let handle = thread::Builder::new()
            .name(name.to_string())
            .stack_size(CLI_TEST_STACK_SIZE)
            .spawn(test)
            .unwrap_or_else(|error| panic!("spawn {name}: {error}"));
        match handle.join() {
            Ok(()) => {}
            Err(payload) => panic::resume_unwind(payload),
        }
    }

    fn assert_tree_lacks_forbidden_text(root: &Path, forbidden: &[&str]) {
        let mut stack = vec![root.to_path_buf()];
        while let Some(path) = stack.pop() {
            let metadata = fs::metadata(&path).expect("metadata");
            if metadata.is_dir() {
                for entry in fs::read_dir(&path).expect("read_dir") {
                    stack.push(entry.expect("entry").path());
                }
                continue;
            }
            if let Ok(text) = fs::read_to_string(&path) {
                for needle in forbidden {
                    assert!(
                        !text.contains(needle),
                        "found forbidden text `{needle}` in {}",
                        path.display()
                    );
                }
            }
        }
    }

    fn reentry_help_text() -> String {
        let mut command = Cli::command();
        let app = command.find_subcommand_mut("app").expect("app command");
        let command = app
            .find_subcommand_mut("reentry-assurance")
            .expect("reentry-assurance command");
        let mut bytes = Vec::new();
        command.write_long_help(&mut bytes).expect("render help");
        String::from_utf8(bytes).expect("utf8")
    }

    #[test]
    fn scaffold_creates_expected_files_for_all_styles() {
        let temp = tempfile::tempdir().expect("tempdir");

        for (style, needs_dashboard) in [
            (AppStyle::Minimal, false),
            (AppStyle::Colored, false),
            (AppStyle::Tui, true),
        ] {
            let root = scaffold_app(
                &format!("dx-smoke-{}", style.as_str()),
                "range-proof",
                &BTreeMap::new(),
                style,
                Some(temp.path().join(format!("dx-smoke-{}", style.as_str()))),
            )
            .expect("scaffold");

            for path in [
                root.join("Cargo.toml"),
                root.join("src/spec.rs"),
                root.join("src/main.rs"),
                root.join("tests/smoke.rs"),
                root.join("zirapp.json"),
                root.join("inputs.compliant.json"),
                root.join("inputs.violation.json"),
                root.join("README.md"),
            ] {
                assert!(path.exists(), "missing scaffold file {}", path.display());
            }
            if needs_dashboard {
                assert!(root.join("src/dashboard.rs").exists());
            }

            let cargo_toml =
                std::fs::read_to_string(root.join("Cargo.toml")).expect("cargo toml should exist");
            assert!(cargo_toml.contains("[workspace]"));
            assert!(cargo_toml.contains(&repo_root().join("zkf-lib").display().to_string()));
            match style {
                AppStyle::Minimal => {
                    assert!(!cargo_toml.contains("zkf-ui"));
                    assert!(!cargo_toml.contains("zkf-tui"));
                }
                AppStyle::Colored => {
                    assert!(cargo_toml.contains("zkf-ui"));
                    assert!(!cargo_toml.contains("zkf-tui"));
                }
                AppStyle::Tui => {
                    assert!(cargo_toml.contains("zkf-ui"));
                    assert!(cargo_toml.contains("zkf-tui"));
                }
            }
        }
    }

    #[test]
    fn gallery_output_lists_all_styles_and_commands() {
        let gallery = render_gallery();
        assert!(gallery.contains("Minimal Style"));
        assert!(gallery.contains("Colored Style"));
        assert!(gallery.contains("TUI Style"));
        assert!(gallery.contains("--style minimal"));
        assert!(gallery.contains("--style colored"));
        assert!(gallery.contains("--style tui"));
        assert!(gallery.contains("aegisvault"));
    }

    #[test]
    fn scaffolded_apps_run_smoke_tests_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        for style in [AppStyle::Minimal, AppStyle::Colored, AppStyle::Tui] {
            let root = scaffold_app(
                &format!("poseidon-{}", style.as_str()),
                "range-proof",
                &BTreeMap::new(),
                style,
                Some(temp.path().join(format!("poseidon-{}", style.as_str()))),
            )
            .expect("scaffold");

            let status = std::process::Command::new("cargo")
                .arg("test")
                .arg("--manifest-path")
                .arg(root.join("Cargo.toml"))
                .arg("--quiet")
                .status()
                .expect("cargo test should run");

            assert!(
                status.success(),
                "generated app smoke test failed for style={}",
                style.as_str()
            );
        }
    }

    #[test]
    fn template_registry_renders_json_and_text() {
        let text = render_templates(false).expect("text templates");
        assert!(text.contains("poseidon-commitment"));
        assert!(text.contains("private-vote"));

        let json = render_templates(true).expect("json templates");
        assert!(json.contains("\"private-identity\""));
    }

    fn sample_reentry_signer_manifest(
        signer_identity: &str,
        signer_keys: &ReentrySignerKeyFileV1,
    ) -> ReentrySignerManifestV1 {
        ReentrySignerManifestV1 {
            version: 1,
            manifest_id: "reentry-test-manifest".to_string(),
            authorized_signers: vec![zkf_lib::app::reentry::ReentryAuthorizedSignerV1 {
                signer_identity: signer_identity.to_string(),
                public_keys: signer_keys.public_key_bundle(),
                not_before_unix_epoch_seconds: Some(0),
                not_after_unix_epoch_seconds: Some(4_000_000_000),
                metadata: BTreeMap::from([("purpose".to_string(), "unit-test".to_string())]),
            }],
            metadata: BTreeMap::from([("environment".to_string(), "test".to_string())]),
        }
    }

    fn sample_source_adapter_input(
        source_tool: &str,
    ) -> zkf_lib::app::reentry_ops::SourceModelAdapterInputV1 {
        zkf_lib::app::reentry_ops::SourceModelAdapterInputV1 {
            version: 1,
            mission_id: "sample-reentry-v2-2-step".to_string(),
            source_tool: source_tool.to_string(),
            source_schema: "normalized-export-v1".to_string(),
            coordinate_frame: "LVLH".to_string(),
            time_system: "UTC".to_string(),
            units_system: "km-km_s".to_string(),
            primary_artifact: "trajectory.json".to_string(),
            trajectory_sample_count: 256,
            maneuver_segment_count: 8,
            source_files: vec![zkf_lib::app::reentry_ops::SourceArtifactFileRefV1 {
                logical_name: "trajectory".to_string(),
                relative_path: "trajectory.json".to_string(),
                sha256: "abc123".to_string(),
                bytes: 1024,
            }],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn reentry_assurance_exports_theorem_first_bundle() {
        run_cli_test_on_large_stack("reentry_assurance_exports_theorem_first_bundle", || {
            let temp = tempdir().expect("tempdir");
            let mission_pack = zkf_lib::app::reentry::reentry_mission_pack_sample_with_steps(2)
                .expect("mission pack");
            let inputs_path = temp.path().join("mission_pack.json");
            let out_path = temp.path().join("bundle");
            write_json(&inputs_path, &mission_pack).expect("mission pack json");

            handle_reentry_assurance_legacy(inputs_path, out_path.clone(), false)
                .expect("reentry assurance run");

            let summary: Value = read_json(&out_path.join("summary.json")).expect("summary");
            assert_eq!(summary["application"], "private-reentry-mission-assurance");
            assert_eq!(summary["backend"], "plonky3");
            assert_eq!(summary["theorem_lane"], "transparent-fixed-policy-cpu");
            assert_eq!(summary["verified"], true);
            assert!(summary["mission_pack_digest"].as_str().is_some());
            assert!(summary["mathematical_model"].as_str().is_some());

            let receipt: Value = read_json(&out_path.join("receipt.json")).expect("receipt");
            assert_eq!(receipt["theorem_lane"], "transparent-fixed-policy-cpu");
            assert!(receipt["theorem_hypotheses"].as_array().is_some());
            assert!(receipt["minimal_tcb"].as_array().is_some());
        });
    }

    #[test]
    fn reentry_assurance_signed_operator_roundtrip() {
        run_cli_test_on_large_stack("reentry_assurance_signed_operator_roundtrip", || {
            let temp = tempdir().expect("tempdir");
            let mission_pack = zkf_lib::app::reentry::reentry_mission_pack_v2_sample_with_steps(2)
                .expect("mission pack");
            let mission_pack_path = temp.path().join("mission_pack_v2.json");
            let signer_key_path = temp.path().join("reentry-signer-keys.json");
            let signed_pack_path = temp.path().join("signed_mission_pack.json");
            let manifest_path = temp.path().join("signer_manifest.json");
            let bundle_path = temp.path().join("bundle");
            let export_path = temp.path().join("public_bundle");
            write_json(&mission_pack_path, &mission_pack).expect("mission pack json");

            handle_reentry_sign_pack(
                mission_pack_path.clone(),
                signer_key_path.clone(),
                Vec::new(),
                None,
                None,
                None,
                "flight-authority".to_string(),
                0,
                4_000_000_000,
                signed_pack_path.clone(),
            )
            .expect("sign pack");

            let signer_keys: ReentrySignerKeyFileV1 =
                read_json(&signer_key_path).expect("signer keys");
            let manifest = sample_reentry_signer_manifest("flight-authority", &signer_keys);
            write_json(&manifest_path, &manifest).expect("manifest json");

            handle_reentry_validate_pack(
                signed_pack_path.clone(),
                manifest_path.clone(),
                Some(1_000),
            )
            .expect("validate pack");
            handle_reentry_prove(
                signed_pack_path.clone(),
                manifest_path.clone(),
                Vec::new(),
                None,
                None,
                None,
                bundle_path.clone(),
                Some(1_000),
            )
            .expect("prove");
            handle_reentry_verify(bundle_path.clone()).expect("verify");
            handle_reentry_report(bundle_path.clone(), None).expect("report");
            handle_reentry_export_bundle(bundle_path.clone(), export_path.clone(), false)
                .expect("export bundle");

            let receipt: Value = read_json(&bundle_path.join("receipt.json")).expect("receipt");
            assert_eq!(receipt["theorem_lane"], "transparent-fixed-policy-cpu");
            assert_eq!(receipt["signer_identity"], "flight-authority");
            assert!(bundle_path.join("mission_assurance_report.md").exists());
            assert!(bundle_path.join("verification.json").exists());
            assert!(bundle_path.join("formal/STATUS.md").exists());
            assert!(bundle_path.join("formal/exercised_surfaces.json").exists());
            assert!(export_path.join("mission_pack_provenance.json").exists());
            assert!(export_path.join("proof.json").exists());
            assert!(export_path.join("formal/STATUS.md").exists());
            assert!(export_path.join("formal/exercised_surfaces.json").exists());
            assert!(!export_path.join("signed_mission_pack.json").exists());
            assert!(!export_path.join("witness.json").exists());
        });
    }

    #[test]
    fn reentry_assurance_mission_ops_roundtrip_exports_manifests() {
        run_cli_test_on_large_stack(
            "reentry_assurance_mission_ops_roundtrip_exports_manifests",
            || {
                let temp = tempdir().expect("tempdir");
                let gmat_input = temp.path().join("gmat_input.json");
                let spice_input = temp.path().join("spice_input.json");
                let gmat_manifest = temp.path().join("gmat_manifest.json");
                let spice_manifest = temp.path().join("spice_manifest.json");
                let derive_request_path = temp.path().join("derive_request.json");
                let derive_out = temp.path().join("derived");
                let qualify_out = temp.path().join("qualified");
                let signer_key_path = temp.path().join("reentry-signer-keys.json");
                let signed_pack_path = temp.path().join("signed_mission_pack.json");
                let manifest_path = temp.path().join("signer_manifest.json");
                let bundle_path = temp.path().join("bundle");
                let export_path = temp.path().join("public_bundle");
                let annex_path = bundle_path.join("annex");
                let dashboard_path = bundle_path.join("dashboard");
                let cfs_handoff_path = bundle_path.join("handoff_cfs");
                let fprime_handoff_path = bundle_path.join("handoff_fprime");

                write_json(&gmat_input, &sample_source_adapter_input("gmat")).expect("gmat input");
                write_json(&spice_input, &sample_source_adapter_input("spice"))
                    .expect("spice input");
                ingest_source_model_manifest(gmat_input.clone(), gmat_manifest.clone(), "gmat")
                    .expect("ingest gmat");
                ingest_source_model_manifest(spice_input.clone(), spice_manifest.clone(), "spice")
                    .expect("ingest spice");

                let mission_pack =
                    zkf_lib::app::reentry::reentry_mission_pack_v2_sample_with_steps(2)
                        .expect("mission pack");
                let derive_request = zkf_lib::app::reentry_ops::DerivedModelRequestV1 {
                    version: 1,
                    package_id: "sample-package".to_string(),
                    mission_pack,
                    source_model_manifests: vec![
                        read_json(&gmat_manifest).expect("gmat manifest"),
                        read_json(&spice_manifest).expect("spice manifest"),
                    ],
                    approved_operating_domain:
                        zkf_lib::app::reentry_ops::ApprovedOperatingDomainV1 {
                            altitude_min: "0".to_string(),
                            altitude_max: "120".to_string(),
                            velocity_min: "0".to_string(),
                            velocity_max: "8".to_string(),
                            gamma_min: "-0.35".to_string(),
                            gamma_max: "0.35".to_string(),
                            certified_horizon_steps: 2,
                            cadence_seconds: 1,
                        },
                    residual_bounds: vec![],
                    uncertainty_metadata: BTreeMap::new(),
                    metadata: BTreeMap::new(),
                };
                write_json(&derive_request_path, &derive_request).expect("derive request");
                handle_reentry_derive_model(derive_request_path.clone(), derive_out.clone())
                    .expect("derive model");
                let derived_package: zkf_lib::app::reentry_ops::DerivedModelPackageV1 =
                    read_json(&derive_out.join("derived_model_package.json")).expect("package");
                let derived_mission_pack: zkf_lib::app::reentry::ReentryMissionPackV2 =
                    read_json(&derive_out.join("mission_pack_v2.json")).expect("mission pack");
                let package_digest =
                    zkf_lib::app::reentry_ops::derived_model_package_digest(&derived_package)
                        .expect("package digest");
                let scenario_library = zkf_lib::app::reentry_ops::ScenarioLibraryManifestV1 {
                    version: 1,
                    library_id: "sample-library".to_string(),
                    mission_id: derived_package.mission_id.clone(),
                    derived_model_package_digest: package_digest.clone(),
                    scenarios: vec![zkf_lib::app::reentry_ops::ScenarioDefinitionV1 {
                        scenario_id: "nominal".to_string(),
                        category: "nominal".to_string(),
                        mission_pack_digest: zkf_lib::app::reentry::reentry_mission_pack_v2_digest(
                            &derived_mission_pack,
                        )
                        .expect("mission pack digest"),
                        expected_outcome: "pass".to_string(),
                        expected_abort_mode: "nominal".to_string(),
                        metadata: BTreeMap::new(),
                    }],
                    nasa_classification_boundary:
                        zkf_lib::app::reentry_ops::NasaClassificationBoundaryV1::default(),
                    metadata: BTreeMap::new(),
                };
                let scenario_library_path = temp.path().join("scenario_library.json");
                write_json(&scenario_library_path, &scenario_library).expect("scenario library");
                handle_reentry_qualify_model(
                    derive_out.join("derived_model_package.json"),
                    scenario_library_path.clone(),
                    qualify_out.clone(),
                )
                .expect("qualify");

                let qualified_matrix_path = qualify_out.join("assurance_trace_matrix.json");
                handle_reentry_sign_pack(
                    derive_out.join("mission_pack_v2.json"),
                    signer_key_path.clone(),
                    vec![gmat_manifest.clone(), spice_manifest.clone()],
                    Some(derive_out.join("derived_model_package.json")),
                    Some(scenario_library_path.clone()),
                    Some(qualified_matrix_path.clone()),
                    "flight-authority".to_string(),
                    0,
                    4_000_000_000,
                    signed_pack_path.clone(),
                )
                .expect("sign pack");
                let signer_keys: ReentrySignerKeyFileV1 =
                    read_json(&signer_key_path).expect("signer keys");
                let manifest = sample_reentry_signer_manifest("flight-authority", &signer_keys);
                write_json(&manifest_path, &manifest).expect("manifest json");

                handle_reentry_prove(
                    signed_pack_path.clone(),
                    manifest_path.clone(),
                    vec![gmat_manifest.clone(), spice_manifest.clone()],
                    Some(derive_out.join("derived_model_package.json")),
                    Some(scenario_library_path.clone()),
                    Some(qualified_matrix_path.clone()),
                    bundle_path.clone(),
                    Some(1_000),
                )
                .expect("prove");
                handle_reentry_publish_annex(
                    bundle_path.clone(),
                    annex_path.clone(),
                    Some(bundle_path.join("formal")),
                    Some(bundle_path.join("summary.json")),
                    Some(bundle_path.join("verification.json")),
                    Some(bundle_path.join("evidence_manifest.json")),
                )
                .expect("publish annex");
                handle_reentry_build_dashboard(
                    bundle_path.clone(),
                    Some(annex_path.clone()),
                    dashboard_path.clone(),
                )
                .expect("dashboard");
                write_reentry_handoff(bundle_path.clone(), cfs_handoff_path.clone(), "cFS")
                    .expect("cfs handoff");
                write_reentry_handoff(bundle_path.clone(), fprime_handoff_path.clone(), "F Prime")
                    .expect("fprime handoff");
                handle_reentry_export_bundle(bundle_path.clone(), export_path.clone(), false)
                    .expect("export bundle");

                assert!(bundle_path.join("derived_model_package.json").exists());
                assert!(bundle_path.join("scenario_library_manifest.json").exists());
                assert!(bundle_path.join("assurance_trace_matrix.json").exists());
                assert!(bundle_path.join("source_model_manifests").is_dir());
                assert!(bundle_path.join("annex/annex_manifest.json").exists());
                assert!(
                    bundle_path
                        .join("dashboard/openmct_dashboard.json")
                        .exists()
                );
                assert!(
                    bundle_path
                        .join("handoff_cfs/handoff_manifest.json")
                        .exists()
                );
                assert!(
                    bundle_path
                        .join("handoff_fprime/handoff_manifest.json")
                        .exists()
                );
                assert!(export_path.join("derived_model_package.json").exists());
                assert!(export_path.join("scenario_library_manifest.json").exists());
                assert!(export_path.join("assurance_trace_matrix.json").exists());
                assert!(export_path.join("source_model_manifests").is_dir());
                assert!(export_path.join("annex/annex_manifest.json").exists());
                assert!(
                    export_path
                        .join("dashboard/openmct_dashboard.json")
                        .exists()
                );
                assert!(
                    export_path
                        .join("handoff_cfs/handoff_manifest.json")
                        .exists()
                );
                assert!(
                    export_path
                        .join("handoff_fprime/handoff_manifest.json")
                        .exists()
                );
                assert!(annex_path.join("annex_manifest.json").exists());
                assert!(dashboard_path.join("openmct_dashboard.json").exists());
                assert!(cfs_handoff_path.join("handoff_manifest.json").exists());
                assert!(fprime_handoff_path.join("handoff_manifest.json").exists());
                let annex_manifest: Value =
                    read_json(&bundle_path.join("annex/annex_manifest.json"))
                        .expect("annex manifest");
                assert!(
                    !annex_manifest.to_string().contains("/Users/"),
                    "annex manifest should not leak absolute paths"
                );
                let bundle_manifest: Value =
                    read_json(&bundle_path.join("bundle_manifest.json")).expect("bundle manifest");
                let evidence_manifest: Value =
                    read_json(&bundle_path.join("evidence_manifest.json"))
                        .expect("evidence manifest");
                let dashboard: Value =
                    read_json(&bundle_path.join("dashboard/openmct_dashboard.json"))
                        .expect("dashboard");
                let cfs_handoff: Value =
                    read_json(&bundle_path.join("handoff_cfs/handoff_manifest.json")).expect("cfs");
                let fprime_handoff: Value =
                    read_json(&bundle_path.join("handoff_fprime/handoff_manifest.json"))
                        .expect("fprime");
                let export_readme =
                    fs::read_to_string(export_path.join("README.md")).expect("export readme");
                assert!(export_readme.contains("NASA Class D"));
                assert!(export_readme.contains("normalized-export-based ingestion"));
                assert!(export_readme.contains("does not natively replace GMAT"));
                let provenance: Value =
                    read_json(&export_path.join("mission_pack_provenance.json"))
                        .expect("provenance");
                assert_eq!(
                    provenance["nasa_classification_boundary"]["target_classification"],
                    "NASA Class D ground-support mission-ops assurance"
                );
                assert_eq!(
                    bundle_manifest["boundary_contract"]["ingestion_mode"],
                    "normalized-export-based ingestion"
                );
                assert_eq!(
                    evidence_manifest["boundary_contract"]["nasa_classification_boundary"]["target_classification"],
                    "NASA Class D ground-support mission-ops assurance"
                );
                assert_eq!(
                    dashboard["boundary_contract"]["no_native_replacement_claim"],
                    true
                );
                assert_eq!(
                    cfs_handoff["boundary_contract"]["ingestion_mode"],
                    "normalized-export-based ingestion"
                );
                assert_eq!(
                    fprime_handoff["boundary_contract"]["nasa_classification_boundary"]["target_classification"],
                    "NASA Class D ground-support mission-ops assurance"
                );
                assert!(
                    bundle_manifest["artifacts"]
                        .as_array()
                        .expect("artifact array")
                        .iter()
                        .any(|item| item["relative_path"] == "proof.json"
                            && item["artifact_class"] == "proof_bearing")
                );
                assert!(
                    bundle_manifest["artifacts"]
                        .as_array()
                        .expect("artifact array")
                        .iter()
                        .any(|item| item["relative_path"] == "oracle_comparison.json"
                            && item["artifact_class"] == "governed_upstream_evidence")
                );
                assert!(
                    bundle_manifest["artifacts"]
                        .as_array()
                        .expect("artifact array")
                        .iter()
                        .any(
                            |item| item["relative_path"] == "mission_assurance_report.md"
                                && item["artifact_class"] == "human_readable_report_only"
                        )
                );
                let report_text =
                    fs::read_to_string(bundle_path.join("mission_assurance_report.md"))
                        .expect("report");
                assert!(report_text.contains("NASA Class D"));
                assert!(report_text.contains("normalized-export-based ingestion"));
                assert!(report_text.contains("does not natively replace GMAT"));

                let cli_doc = fs::read_to_string(repo_root().join("docs/CLI.md")).expect("cli doc");
                let ops_doc =
                    fs::read_to_string(repo_root().join("docs/REENTRY_MISSION_OPS_PLATFORM.md"))
                        .expect("ops doc");
                let help_text = reentry_help_text();
                for text in [&cli_doc, &ops_doc, &help_text] {
                    assert!(text.contains("NASA Class D"));
                    assert!(text.contains("normalized-export"));
                }
                assert!(help_text.contains("does not natively replace"));

                let summary: Value = read_json(&bundle_path.join("summary.json")).expect("summary");
                assert_eq!(
                    summary["nasa_target_classification"],
                    REENTRY_NASA_TARGET_CLASSIFICATION
                );
                assert_eq!(summary["oracle_comparison"]["matched"], true);

                assert_tree_lacks_forbidden_text(
                    &export_path,
                    &[
                        "/Users/",
                        "/private/var/",
                        "sicarii",
                        "\"signed_mission_pack.json\"",
                        "\"witness.json\"",
                    ],
                );
            },
        );
    }

    #[test]
    fn reentry_assurance_rejects_tampered_source_manifest() {
        let temp = tempdir().expect("tempdir");
        let gmat_input = temp.path().join("gmat_input.json");
        let spice_input = temp.path().join("spice_input.json");
        let gmat_manifest = temp.path().join("gmat_manifest.json");
        let spice_manifest = temp.path().join("spice_manifest.json");
        let derive_request_path = temp.path().join("derive_request.json");
        let derive_out = temp.path().join("derived");
        let qualify_out = temp.path().join("qualified");
        let signer_key_path = temp.path().join("reentry-signer-keys.json");
        let signed_pack_path = temp.path().join("signed_mission_pack.json");
        let manifest_path = temp.path().join("signer_manifest.json");

        write_json(&gmat_input, &sample_source_adapter_input("gmat")).expect("gmat input");
        write_json(&spice_input, &sample_source_adapter_input("spice")).expect("spice input");
        ingest_source_model_manifest(gmat_input.clone(), gmat_manifest.clone(), "gmat")
            .expect("ingest gmat");
        ingest_source_model_manifest(spice_input.clone(), spice_manifest.clone(), "spice")
            .expect("ingest spice");

        let mission_pack = zkf_lib::app::reentry::reentry_mission_pack_v2_sample_with_steps(2)
            .expect("mission pack");
        let derive_request = zkf_lib::app::reentry_ops::DerivedModelRequestV1 {
            version: 1,
            package_id: "sample-package".to_string(),
            mission_pack,
            source_model_manifests: vec![
                read_json(&gmat_manifest).expect("gmat manifest"),
                read_json(&spice_manifest).expect("spice manifest"),
            ],
            approved_operating_domain: zkf_lib::app::reentry_ops::ApprovedOperatingDomainV1 {
                altitude_min: "0".to_string(),
                altitude_max: "120".to_string(),
                velocity_min: "0".to_string(),
                velocity_max: "8".to_string(),
                gamma_min: "-0.35".to_string(),
                gamma_max: "0.35".to_string(),
                certified_horizon_steps: 2,
                cadence_seconds: 1,
            },
            residual_bounds: vec![],
            uncertainty_metadata: BTreeMap::new(),
            metadata: BTreeMap::new(),
        };
        write_json(&derive_request_path, &derive_request).expect("derive request");
        handle_reentry_derive_model(derive_request_path.clone(), derive_out.clone())
            .expect("derive model");
        let derived_package: zkf_lib::app::reentry_ops::DerivedModelPackageV1 =
            read_json(&derive_out.join("derived_model_package.json")).expect("package");
        let derived_mission_pack: zkf_lib::app::reentry::ReentryMissionPackV2 =
            read_json(&derive_out.join("mission_pack_v2.json")).expect("mission pack");
        let scenario_library = zkf_lib::app::reentry_ops::ScenarioLibraryManifestV1 {
            version: 1,
            library_id: "sample-library".to_string(),
            mission_id: derived_package.mission_id.clone(),
            derived_model_package_digest: zkf_lib::app::reentry_ops::derived_model_package_digest(
                &derived_package,
            )
            .expect("package digest"),
            scenarios: vec![zkf_lib::app::reentry_ops::ScenarioDefinitionV1 {
                scenario_id: "nominal".to_string(),
                category: "nominal".to_string(),
                mission_pack_digest: zkf_lib::app::reentry::reentry_mission_pack_v2_digest(
                    &derived_mission_pack,
                )
                .expect("mission pack digest"),
                expected_outcome: "pass".to_string(),
                expected_abort_mode: "nominal".to_string(),
                metadata: BTreeMap::new(),
            }],
            nasa_classification_boundary:
                zkf_lib::app::reentry_ops::NasaClassificationBoundaryV1::default(),
            metadata: BTreeMap::new(),
        };
        let scenario_library_path = temp.path().join("scenario_library.json");
        write_json(&scenario_library_path, &scenario_library).expect("scenario library");
        handle_reentry_qualify_model(
            derive_out.join("derived_model_package.json"),
            scenario_library_path.clone(),
            qualify_out.clone(),
        )
        .expect("qualify");
        handle_reentry_sign_pack(
            derive_out.join("mission_pack_v2.json"),
            signer_key_path.clone(),
            vec![gmat_manifest.clone(), spice_manifest.clone()],
            Some(derive_out.join("derived_model_package.json")),
            Some(scenario_library_path.clone()),
            Some(qualify_out.join("assurance_trace_matrix.json")),
            "flight-authority".to_string(),
            0,
            4_000_000_000,
            signed_pack_path.clone(),
        )
        .expect("sign pack");
        let signer_keys: ReentrySignerKeyFileV1 = read_json(&signer_key_path).expect("signer keys");
        let manifest = sample_reentry_signer_manifest("flight-authority", &signer_keys);
        write_json(&manifest_path, &manifest).expect("manifest");

        let mut tampered_manifest: Value = read_json(&gmat_manifest).expect("gmat manifest");
        tampered_manifest["metadata"]["tampered"] = json!("yes");
        write_json(&gmat_manifest, &tampered_manifest).expect("tampered manifest");

        let error = handle_reentry_prove(
            signed_pack_path,
            manifest_path,
            vec![gmat_manifest, spice_manifest],
            Some(derive_out.join("derived_model_package.json")),
            Some(scenario_library_path),
            Some(qualify_out.join("assurance_trace_matrix.json")),
            temp.path().join("bundle"),
            Some(1_000),
        )
        .expect_err("tampered source manifest must fail");
        assert!(error.contains("source model manifest digests do not match"));
    }

    #[test]
    fn reentry_assurance_oracle_mismatch_blocks_verify_report_and_export() {
        run_cli_test_on_large_stack(
            "reentry_assurance_oracle_mismatch_blocks_verify_report_and_export",
            || {
                let temp = tempdir().expect("tempdir");
                let mission_pack =
                    zkf_lib::app::reentry::reentry_mission_pack_v2_sample_with_steps(2)
                        .expect("mission pack");
                let mission_pack_path = temp.path().join("mission_pack_v2.json");
                let signer_key_path = temp.path().join("reentry-signer-keys.json");
                let signed_pack_path = temp.path().join("signed_mission_pack.json");
                let manifest_path = temp.path().join("signer_manifest.json");
                let bundle_path = temp.path().join("bundle");
                write_json(&mission_pack_path, &mission_pack).expect("mission pack json");

                handle_reentry_sign_pack(
                    mission_pack_path.clone(),
                    signer_key_path.clone(),
                    Vec::new(),
                    None,
                    None,
                    None,
                    "flight-authority".to_string(),
                    0,
                    4_000_000_000,
                    signed_pack_path.clone(),
                )
                .expect("sign pack");
                let signer_keys: ReentrySignerKeyFileV1 =
                    read_json(&signer_key_path).expect("signer keys");
                let manifest = sample_reentry_signer_manifest("flight-authority", &signer_keys);
                write_json(&manifest_path, &manifest).expect("manifest json");

                handle_reentry_prove(
                    signed_pack_path,
                    manifest_path,
                    Vec::new(),
                    None,
                    None,
                    None,
                    bundle_path.clone(),
                    Some(1_000),
                )
                .expect("prove");

                let mut comparison: Value =
                    read_json(&bundle_path.join("oracle_comparison.json")).expect("comparison");
                comparison["matched"] = json!(false);
                comparison["mismatches"] = json!({"peak_dynamic_pressure": "forced-test-mismatch"});
                write_json(&bundle_path.join("oracle_comparison.json"), &comparison)
                    .expect("rewrite comparison");

                let verify_error =
                    handle_reentry_verify(bundle_path.clone()).expect_err("verify must fail");
                assert!(verify_error.contains("deterministic oracle mismatch"));
                let report_error =
                    handle_reentry_report(bundle_path.clone(), None).expect_err("report must fail");
                assert!(report_error.contains("deterministic oracle mismatch"));
                let export_error = handle_reentry_export_bundle(
                    bundle_path,
                    temp.path().join("public_bundle"),
                    false,
                )
                .expect_err("export must fail");
                assert!(export_error.contains("deterministic oracle mismatch"));
            },
        );
    }

    #[test]
    fn reentry_assurance_legacy_alias_fails_closed_in_production_mode() {
        run_cli_test_on_large_stack(
            "reentry_assurance_legacy_alias_fails_closed_in_production_mode",
            || {
                let temp = tempdir().expect("tempdir");
                let mission_pack = zkf_lib::app::reentry::reentry_mission_pack_sample_with_steps(2)
                    .expect("mission pack");
                let inputs_path = temp.path().join("mission_pack.json");
                let out_path = temp.path().join("bundle");
                write_json(&inputs_path, &mission_pack).expect("mission pack json");

                let error = handle_reentry_assurance_legacy(inputs_path, out_path, true)
                    .expect_err("production legacy alias must fail closed");
                assert!(error.contains("signed-pack"));
            },
        );
    }
}
