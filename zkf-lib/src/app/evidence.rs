#![cfg_attr(not(test), allow(dead_code))]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zkf_core::{ZkfError, ZkfResult, json_from_slice, json_to_vec_pretty};
use zkf_storage::{
    FileClass, StorageGuardianConfig, archive_file, classify_path, current_utc_timestamp,
    icloud_archive_root, purge_ephemeral,
};

#[derive(Clone, Copy, Debug)]
pub struct FormalScriptSpec {
    pub name: &'static str,
    pub script_relative_path: &'static str,
    pub log_file_name: &'static str,
}

pub const DEFAULT_FORMAL_SCRIPT_SPECS: [FormalScriptSpec; 3] = [
    FormalScriptSpec {
        name: "rocq",
        script_relative_path: "scripts/run_rocq_proofs.sh",
        log_file_name: "rocq.log",
    },
    FormalScriptSpec {
        name: "protocol_lean",
        script_relative_path: "scripts/run_protocol_lean_proofs.sh",
        log_file_name: "protocol_lean.log",
    },
    FormalScriptSpec {
        name: "verus_orbital",
        script_relative_path: "scripts/run_verus_orbital_proofs.sh",
        log_file_name: "verus_orbital.log",
    },
];

const SATELLITE_FORMAL_SCRIPT_SPECS: [FormalScriptSpec; 4] = [
    FormalScriptSpec {
        name: "rocq",
        script_relative_path: "scripts/run_rocq_proofs.sh",
        log_file_name: "rocq.log",
    },
    FormalScriptSpec {
        name: "protocol_lean",
        script_relative_path: "scripts/run_protocol_lean_proofs.sh",
        log_file_name: "protocol_lean.log",
    },
    FormalScriptSpec {
        name: "verus_satellite",
        script_relative_path: "scripts/run_verus_satellite_conjunction_proofs.sh",
        log_file_name: "verus_satellite.log",
    },
    FormalScriptSpec {
        name: "kani_satellite",
        script_relative_path: "scripts/run_kani_satellite_conjunction_proofs.sh",
        log_file_name: "kani_satellite.log",
    },
];

const DESCENT_FORMAL_SCRIPT_SPECS: [FormalScriptSpec; 3] = [
    FormalScriptSpec {
        name: "rocq",
        script_relative_path: "scripts/run_rocq_proofs.sh",
        log_file_name: "rocq.log",
    },
    FormalScriptSpec {
        name: "protocol_lean",
        script_relative_path: "scripts/run_protocol_lean_proofs.sh",
        log_file_name: "protocol_lean.log",
    },
    FormalScriptSpec {
        name: "verus_powered_descent",
        script_relative_path: "scripts/run_verus_powered_descent_proofs.sh",
        log_file_name: "verus_powered_descent.log",
    },
];

pub const IMPLEMENTATION_CLOSURE_SUMMARY_RELATIVE_PATH: &str =
    "forensics/generated/implementation_closure_summary.json";
pub const GENERATED_APP_CLOSURE_DIR_RELATIVE_PATH: &str = "forensics/generated/app_closure";
pub const GENERATED_IMPLEMENTATION_CLOSURE_SCHEMA: &str = "zkf-implementation-closure-summary-v1";
pub const GENERATED_APP_CLOSURE_SCHEMA: &str = "zkf-generated-app-closure-v1";
pub const IMPLEMENTATION_CLOSURE_ASSURANCE_VOCABULARY: [&str; 7] = [
    "mechanized",
    "bounded",
    "model-only",
    "hypothesis-carried",
    "compatibility alias",
    "metadata-only",
    "explicit_tcb_adapter",
];

const ORBITAL_APP_ID: &str = "private_nbody_orbital_showcase";
const DESCENT_APP_ID: &str = "private_powered_descent_showcase";
const MULTI_SATELLITE_APP_ID: &str = "private_multi_satellite_conjunction_showcase";
const SATELLITE_APP_ID: &str = "private_satellite_conjunction_showcase";
const VOTING_APP_ID: &str = "private_voting_commitment_pipeline";

const MULTI_SATELLITE_FORMAL_SCRIPT_SPECS: [FormalScriptSpec; 2] = [
    FormalScriptSpec {
        name: "rocq",
        script_relative_path: "scripts/run_rocq_proofs.sh",
        log_file_name: "rocq.log",
    },
    FormalScriptSpec {
        name: "protocol_lean",
        script_relative_path: "scripts/run_protocol_lean_proofs.sh",
        log_file_name: "protocol_lean.log",
    },
];

#[derive(Debug, Deserialize)]
struct VerificationLedgerFile {
    entries: Vec<LedgerEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct LedgerEntry {
    theorem_id: String,
    title: String,
    scope: String,
    checker: String,
    status: String,
    assurance_class: String,
    evidence_path: String,
    #[serde(default)]
    trusted_assumptions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SupportMatrixFile {
    schema_version: String,
    #[serde(default)]
    backends: Vec<SupportMatrixBackend>,
}

#[derive(Clone, Debug, Deserialize)]
struct SupportMatrixBackend {
    id: String,
    status: String,
    assurance_lane: String,
    proof_semantics: String,
    notes: String,
}

#[derive(Debug, Deserialize)]
struct CompletionStatusFile {
    generated_from: String,
    authoritative_status_source: String,
    current_priority: String,
    release_grade_ready: bool,
    runtime_proof_coverage: RuntimeProofCoverage,
}

#[derive(Debug, Deserialize)]
struct RuntimeProofCoverage {
    total_files: usize,
    total_functions: usize,
    complete_files: usize,
    complete_functions: usize,
    #[serde(default)]
    file_counts: BTreeMap<String, usize>,
    #[serde(default)]
    function_counts: BTreeMap<String, usize>,
}

struct LedgerSurfaceSpec {
    surface_id: &'static str,
    label: &'static str,
    source_path: &'static str,
    claims: &'static [LedgerClaimSpec],
    extraction_paths: &'static [&'static str],
}

struct LedgerClaimSpec {
    theorem_id: &'static str,
    expected_scope: &'static str,
}

struct AppClosureSpec {
    app_id: &'static str,
    application: serde_json::Value,
    surface_ids: &'static [&'static str],
}

pub fn generated_app_closure_relative_path(app_id: &str) -> String {
    format!("{GENERATED_APP_CLOSURE_DIR_RELATIVE_PATH}/{app_id}.json")
}

fn implementation_closure_summary_path() -> PathBuf {
    repo_root().join(IMPLEMENTATION_CLOSURE_SUMMARY_RELATIVE_PATH)
}

fn generated_app_closure_path(app_id: &str) -> PathBuf {
    repo_root().join(generated_app_closure_relative_path(app_id))
}

fn assurance_counts_template() -> BTreeMap<String, usize> {
    IMPLEMENTATION_CLOSURE_ASSURANCE_VOCABULARY
        .iter()
        .map(|classification| ((*classification).to_string(), 0))
        .collect()
}

fn classification_names(counts: &BTreeMap<String, usize>) -> Vec<String> {
    IMPLEMENTATION_CLOSURE_ASSURANCE_VOCABULARY
        .iter()
        .filter(|classification| counts.get(**classification).copied().unwrap_or_default() > 0)
        .map(|classification| (*classification).to_string())
        .collect()
}

fn increment_assurance_count(
    counts: &mut BTreeMap<String, usize>,
    classification: &str,
) -> ZkfResult<()> {
    let slot = counts.get_mut(classification).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "unknown implementation-closure classification `{classification}`"
        ))
    })?;
    *slot += 1;
    Ok(())
}

fn accumulate_claim_counts(claims: &[serde_json::Value]) -> ZkfResult<BTreeMap<String, usize>> {
    let mut counts = assurance_counts_template();
    for claim in claims {
        let classification = claim
            .get("classification")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "generated implementation-closure claim missing classification".to_string(),
                )
            })?;
        increment_assurance_count(&mut counts, classification)?;
    }
    Ok(counts)
}

fn ensure_repo_relative_path_exists(relative_path: &str) -> ZkfResult<()> {
    let path = repo_root().join(relative_path);
    if !path.exists() {
        return Err(ZkfError::InvalidArtifact(format!(
            "referenced implementation-closure path `{relative_path}` does not exist"
        )));
    }
    Ok(())
}

fn normalized_classification(entry: &LedgerEntry) -> &'static str {
    match entry.status.as_str() {
        "bounded_checked" => "bounded",
        _ => match entry.assurance_class.as_str() {
            "mechanized_implementation_claim" => "mechanized",
            "bounded_check" => "bounded",
            "model_only_claim" => "model-only",
            "hypothesis_carried_theorem" => "hypothesis-carried",
            "attestation_backed_lane" => "metadata-only",
            _ if entry.status == "assumed_external" => "hypothesis-carried",
            _ => "mechanized",
        },
    }
}

fn parse_explicit_compat_alias(notes: &str) -> Option<String> {
    let marker = "explicit_compat_alias=";
    let (_, suffix) = notes.split_once(marker)?;
    let alias = suffix.split_whitespace().next().unwrap_or_default().trim();
    if alias.is_empty() {
        None
    } else {
        Some(alias.to_string())
    }
}

fn bundle_files_for_scripts(scripts: &[FormalScriptSpec]) -> serde_json::Value {
    json!({
        "status": "formal/STATUS.md",
        "exercised_surfaces": "formal/exercised_surfaces.json",
        "logs": scripts
            .iter()
            .map(|script| format!("formal/{}", script.log_file_name))
            .collect::<Vec<_>>(),
    })
}

fn generated_app_formal_script_specs_internal(
    app_id: &str,
) -> ZkfResult<&'static [FormalScriptSpec]> {
    match app_id {
        ORBITAL_APP_ID | VOTING_APP_ID => Ok(&DEFAULT_FORMAL_SCRIPT_SPECS),
        DESCENT_APP_ID => Ok(&DESCENT_FORMAL_SCRIPT_SPECS),
        MULTI_SATELLITE_APP_ID => Ok(&MULTI_SATELLITE_FORMAL_SCRIPT_SPECS),
        SATELLITE_APP_ID => Ok(&SATELLITE_FORMAL_SCRIPT_SPECS),
        _ => Err(ZkfError::InvalidArtifact(format!(
            "unknown finished-app closure id `{app_id}`"
        ))),
    }
}

pub fn generated_app_formal_script_specs(app_id: &str) -> ZkfResult<Vec<FormalScriptSpec>> {
    Ok(generated_app_formal_script_specs_internal(app_id)?.to_vec())
}

fn canonical_truth_markers(canonical_truth: &str) -> ZkfResult<serde_json::Value> {
    let has_metadata_only = canonical_truth.contains("metadata-only");
    let has_compatibility_aliases = canonical_truth.contains("compatibility aliases");
    let has_strict_cryptographic = canonical_truth.contains("strict cryptographic");
    if !has_metadata_only || !has_compatibility_aliases || !has_strict_cryptographic {
        return Err(ZkfError::InvalidArtifact(
            "docs/CANONICAL_TRUTH.md no longer carries the expected implementation-closure markers"
                .to_string(),
        ));
    }
    Ok(json!({
        "metadata_only_marker": has_metadata_only,
        "compatibility_alias_marker": has_compatibility_aliases,
        "strict_cryptographic_marker": has_strict_cryptographic,
    }))
}

fn ledger_surface_specs() -> Vec<LedgerSurfaceSpec> {
    vec![
        LedgerSurfaceSpec {
            surface_id: "core.proof_witness_generation_spec",
            label: "Witness generation proof-facing core",
            source_path: "zkf-core/src/proof_witness_generation_spec.rs",
            claims: &[LedgerClaimSpec {
                theorem_id: "witness.generate_witness_non_blackbox_soundness",
                expected_scope: "zkf-core::proof_witness_generation_spec",
            }],
            extraction_paths: &[
                "zkf-core/proofs/rocq/WitnessGenerationProofs.v",
                "zkf-core/proofs/rocq/extraction/Zkf_core_Proof_witness_generation_spec.v",
                "zkf-core/proofs/fstar/extraction/Zkf_core.Proof_witness_generation_spec.fst",
            ],
        },
        LedgerSurfaceSpec {
            surface_id: "core.proof_constant_time_spec",
            label: "Constant-time proof-facing evaluator surface",
            source_path: "zkf-core/src/proof_constant_time_spec.rs",
            claims: &[
                LedgerClaimSpec {
                    theorem_id: "swarm.constant_time_eval_equivalence",
                    expected_scope: "zkf-core::proof_constant_time_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "security.constant_time_secret_independence",
                    expected_scope: "zkf-core::proof_constant_time_spec",
                },
            ],
            extraction_paths: &["zkf-core/proofs/fstar/ConstantTimeProofs.fst"],
        },
        LedgerSurfaceSpec {
            surface_id: "runtime.proof_runtime_spec",
            label: "Runtime proof-facing decision helpers",
            source_path: "zkf-runtime/src/proof_runtime_spec.rs",
            claims: &[
                LedgerClaimSpec {
                    theorem_id: "hybrid.and_verification_semantics_bounded",
                    expected_scope: "zkf-runtime::proof_runtime_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "hybrid.transcript_hash_binding_bounded",
                    expected_scope: "zkf-runtime::proof_runtime_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "hybrid.hardware_probe_rejection_bounded",
                    expected_scope: "zkf-runtime::proof_runtime_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "hybrid.primary_leg_outer_artifact_binding_bounded",
                    expected_scope: "zkf-runtime::proof_runtime_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "hybrid.replay_manifest_determinism_bounded",
                    expected_scope: "zkf-runtime::proof_runtime_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "pipeline.cli_runtime_path_composition",
                    expected_scope: "zkf-runtime::proof_runtime_spec",
                },
            ],
            extraction_paths: &["zkf-runtime/proofs/rocq/RuntimePipelineComposition.v"],
        },
        LedgerSurfaceSpec {
            surface_id: "lib.proof_embedded_app_spec",
            label: "Embedded application helper surface",
            source_path: "zkf-lib/src/proof_embedded_app_spec.rs",
            claims: &[
                LedgerClaimSpec {
                    theorem_id: "app.alias_resolution_correctness_bounded",
                    expected_scope: "zkf-lib::proof_embedded_app_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "app.digest_mismatch_rejection_bounded",
                    expected_scope: "zkf-lib::proof_embedded_app_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "app.error_propagation_completeness_bounded",
                    expected_scope: "zkf-lib::proof_embedded_app_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "app.default_backend_validity_bounded",
                    expected_scope: "zkf-lib::proof_embedded_app_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "pipeline.embedded_default_path_composition",
                    expected_scope: "zkf-lib::proof_embedded_app_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "private_identity.merkle_direction_fail_closed_bounded",
                    expected_scope: "zkf-lib::proof_embedded_app_spec",
                },
                LedgerClaimSpec {
                    theorem_id: "private_identity.public_input_arity_fail_closed_bounded",
                    expected_scope: "zkf-lib::proof_embedded_app_spec",
                },
            ],
            extraction_paths: &[
                "zkf-lib/proofs/rocq/EmbeddedPipelineComposition.v",
                "zkf-lib/proofs/rocq/extraction/Zkf_lib_Proof_embedded_app_spec.v",
            ],
        },
        LedgerSurfaceSpec {
            surface_id: "backend.audited_backend_boundary",
            label: "Audited backend digest-retention boundary",
            source_path: "zkf-backends/proofs/verus/audited_backend_verus.rs",
            claims: &[LedgerClaimSpec {
                theorem_id: "backend.audit_retains_original_on_digest_mismatch",
                expected_scope: "zkf-backends::audited_backend",
            }],
            extraction_paths: &[],
        },
        LedgerSurfaceSpec {
            surface_id: "backend.groth16_boundary_model",
            label: "Groth16 proof-facing boundary model",
            source_path: "zkf-backends/proofs/verus/groth16_boundary_verus.rs",
            claims: &[
                LedgerClaimSpec {
                    theorem_id: "aggregation.halo2_ipa_accumulation_bounded",
                    expected_scope: "zkf-backends::wrapping::halo2_ipa_accumulator",
                },
                LedgerClaimSpec {
                    theorem_id: "wrapping.groth16_cached_shape_matrix_free_fail_closed",
                    expected_scope: "zkf-backends::arkworks",
                },
                LedgerClaimSpec {
                    theorem_id: "backend.groth16_matrix_equivalence_bounded",
                    expected_scope: "zkf-backends::arkworks",
                },
            ],
            extraction_paths: &[],
        },
        LedgerSurfaceSpec {
            surface_id: "runtime.powered_descent_verus_surface",
            label: "Powered descent finished-app Verus surface",
            source_path: "zkf-runtime/proofs/verus/powered_descent_verus.rs",
            claims: &[
                LedgerClaimSpec {
                    theorem_id: "app.powered_descent_euler_step_determinism",
                    expected_scope: "zkf-runtime::proofs::verus::powered_descent_verus",
                },
                LedgerClaimSpec {
                    theorem_id: "app.powered_descent_thrust_magnitude_sq_nonnegative",
                    expected_scope: "zkf-runtime::proofs::verus::powered_descent_verus",
                },
                LedgerClaimSpec {
                    theorem_id: "app.powered_descent_glide_slope_squaring_soundness",
                    expected_scope: "zkf-runtime::proofs::verus::powered_descent_verus",
                },
                LedgerClaimSpec {
                    theorem_id: "app.powered_descent_mass_positivity_under_bounded_burn",
                    expected_scope: "zkf-runtime::proofs::verus::powered_descent_verus",
                },
                LedgerClaimSpec {
                    theorem_id: "app.powered_descent_running_min_monotonicity",
                    expected_scope: "zkf-runtime::proofs::verus::powered_descent_verus",
                },
            ],
            extraction_paths: &[],
        },
        LedgerSurfaceSpec {
            surface_id: "protocol.groth16_exact",
            label: "Groth16 exact shipped protocol surface",
            source_path: "zkf-protocol-proofs/ZkfProtocolProofs/Groth16Exact.lean",
            claims: &[
                LedgerClaimSpec {
                    theorem_id: "protocol.groth16_completeness",
                    expected_scope: "zkf-backends::arkworks",
                },
                LedgerClaimSpec {
                    theorem_id: "protocol.groth16_knowledge_soundness",
                    expected_scope: "zkf-backends::arkworks",
                },
                LedgerClaimSpec {
                    theorem_id: "protocol.groth16_zero_knowledge",
                    expected_scope: "zkf-backends::arkworks",
                },
            ],
            extraction_paths: &[],
        },
    ]
}

fn app_closure_specs() -> Vec<AppClosureSpec> {
    vec![
        AppClosureSpec {
            app_id: ORBITAL_APP_ID,
            application: json!({
                "name": ORBITAL_APP_ID,
                "backend": "arkworks-groth16",
                "execution_surface": "zkf-runtime strict-cryptographic lane",
                "parameterization": {
                    "body_count": 5,
                    "integration_steps": "export-time parameter (default 1000)",
                },
                "public_outputs": [
                    "commit_body_0",
                    "commit_body_1",
                    "commit_body_2",
                    "commit_body_3",
                    "commit_body_4",
                ],
            }),
            surface_ids: &[
                "truth.canonical_truth_active_boundaries",
                "truth.backend.arkworks_groth16",
                "truth.runtime_proof_coverage",
                "core.proof_witness_generation_spec",
                "core.proof_constant_time_spec",
                "runtime.proof_runtime_spec",
                "lib.proof_embedded_app_spec",
                "backend.audited_backend_boundary",
                "backend.groth16_boundary_model",
                "protocol.groth16_exact",
            ],
        },
        AppClosureSpec {
            app_id: DESCENT_APP_ID,
            application: json!({
                "name": DESCENT_APP_ID,
                "backend": "arkworks-groth16",
                "execution_surface": "zkf-runtime strict-cryptographic lane",
                "parameterization": {
                    "state_space": "translational 6-state",
                    "fixed_point_scale": "10^18",
                    "time_step_seconds": "0.2",
                    "integration_steps": "export-time parameter (default 200)",
                },
                "public_inputs": [
                    "thrust_min",
                    "thrust_max",
                    "glide_slope_tangent",
                    "max_landing_velocity",
                    "landing_zone_radius",
                    "landing_zone_center_x",
                    "landing_zone_center_y",
                    "g_z",
                ],
                "public_outputs": [
                    "trajectory_commitment",
                    "landing_position_commitment",
                    "constraint_satisfaction",
                    "final_mass",
                    "min_altitude",
                ],
            }),
            surface_ids: &[
                "truth.canonical_truth_active_boundaries",
                "truth.backend.arkworks_groth16",
                "truth.runtime_proof_coverage",
                "core.proof_witness_generation_spec",
                "core.proof_constant_time_spec",
                "runtime.proof_runtime_spec",
                "lib.proof_embedded_app_spec",
                "backend.audited_backend_boundary",
                "backend.groth16_boundary_model",
                "runtime.powered_descent_verus_surface",
                "protocol.groth16_exact",
            ],
        },
        AppClosureSpec {
            app_id: MULTI_SATELLITE_APP_ID,
            application: json!({
                "name": MULTI_SATELLITE_APP_ID,
                "backend": "arkworks-groth16",
                "execution_surface": "zkf-runtime strict-cryptographic lane",
                "parameterization": {
                    "base32": {
                        "satellite_count": 32,
                        "designated_pair_count": 64,
                        "integration_steps": 120,
                        "time_step_seconds": 60,
                        "pair_offsets": [1, 5],
                    },
                    "stress64": {
                        "satellite_count": 64,
                        "designated_pair_count": 256,
                        "integration_steps": 240,
                        "time_step_seconds": 60,
                        "pair_offsets": [1, 5, 9, 13],
                    },
                },
                "public_inputs": ["collision_threshold", "delta_v_budget"],
                "public_outputs": [
                    "sat{i}_final_state_commitment",
                    "pair{j}_minimum_separation",
                    "pair{j}_safe",
                    "mission_safety_commitment",
                ],
            }),
            surface_ids: &[
                "truth.canonical_truth_active_boundaries",
                "truth.backend.arkworks_groth16",
                "truth.runtime_proof_coverage",
                "core.proof_witness_generation_spec",
                "core.proof_constant_time_spec",
                "runtime.proof_runtime_spec",
                "lib.proof_embedded_app_spec",
                "backend.audited_backend_boundary",
                "backend.groth16_boundary_model",
                "protocol.groth16_exact",
            ],
        },
        AppClosureSpec {
            app_id: SATELLITE_APP_ID,
            application: json!({
                "name": SATELLITE_APP_ID,
                "backend": "arkworks-groth16",
                "execution_surface": "zkf-runtime strict-cryptographic lane",
                "parameterization": {
                    "spacecraft_count": 2,
                    "integration_steps": "export-time parameter (default 1440)",
                },
                "public_inputs": ["collision_threshold", "delta_v_budget"],
                "public_outputs": [
                    "sc0_final_state_commitment",
                    "sc1_final_state_commitment",
                    "minimum_separation",
                    "safe_indicator",
                    "maneuver_plan_commitment",
                ],
            }),
            surface_ids: &[
                "truth.canonical_truth_active_boundaries",
                "truth.backend.arkworks_groth16",
                "truth.runtime_proof_coverage",
                "core.proof_witness_generation_spec",
                "core.proof_constant_time_spec",
                "runtime.proof_runtime_spec",
                "lib.proof_embedded_app_spec",
                "backend.audited_backend_boundary",
                "backend.groth16_boundary_model",
                "protocol.groth16_exact",
            ],
        },
        AppClosureSpec {
            app_id: VOTING_APP_ID,
            application: json!({
                "name": VOTING_APP_ID,
                "backend": "arkworks-groth16",
                "execution_surface": "embedded compile/prove/verify helper path",
                "parameterization": {
                    "candidate_count": 3,
                },
                "public_outputs": ["vote_commitment"],
            }),
            surface_ids: &[
                "truth.canonical_truth_active_boundaries",
                "truth.backend.arkworks_groth16",
                "core.proof_witness_generation_spec",
                "core.proof_constant_time_spec",
                "lib.proof_embedded_app_spec",
                "backend.audited_backend_boundary",
                "backend.groth16_boundary_model",
                "protocol.groth16_exact",
            ],
        },
    ]
}

fn build_ledger_claim(
    entry: &LedgerEntry,
    surface_source_path: &str,
    extraction_paths: &[&str],
) -> ZkfResult<serde_json::Value> {
    ensure_repo_relative_path_exists(surface_source_path)?;
    ensure_repo_relative_path_exists(&entry.evidence_path)?;
    for extraction_path in extraction_paths {
        ensure_repo_relative_path_exists(extraction_path)?;
    }

    Ok(json!({
        "claim_id": entry.theorem_id,
        "title": entry.title,
        "classification": normalized_classification(entry),
        "source": "verification-ledger",
        "source_scope": entry.scope,
        "source_path": surface_source_path,
        "proof_path": entry.evidence_path,
        "checker": entry.checker,
        "status": entry.status,
        "source_assurance_class": entry.assurance_class,
        "trusted_assumptions": entry.trusted_assumptions,
    }))
}

fn build_ledger_surface(
    spec: &LedgerSurfaceSpec,
    ledger_by_theorem: &BTreeMap<String, LedgerEntry>,
) -> ZkfResult<serde_json::Value> {
    let mut claims = Vec::new();
    let mut evidence_paths = BTreeSet::new();
    for claim_spec in spec.claims {
        let theorem_id = claim_spec.theorem_id;
        let entry = ledger_by_theorem.get(theorem_id).ok_or_else(|| {
            ZkfError::InvalidArtifact(format!(
                "missing verification-ledger row for theorem `{theorem_id}`"
            ))
        })?;
        if entry.scope != claim_spec.expected_scope {
            return Err(ZkfError::InvalidArtifact(format!(
                "theorem `{theorem_id}` drifted from scope `{}` to `{}`",
                claim_spec.expected_scope, entry.scope
            )));
        }
        evidence_paths.insert(entry.evidence_path.clone());
        claims.push(build_ledger_claim(
            entry,
            spec.source_path,
            spec.extraction_paths,
        )?);
    }
    let counts = accumulate_claim_counts(&claims)?;
    Ok(json!({
        "surface_id": spec.surface_id,
        "label": spec.label,
        "path": spec.source_path,
        "source": "verification-ledger",
        "classification_counts": counts,
        "classifications": classification_names(&counts),
        "claims": claims,
        "supporting_paths": {
            "source_path": spec.source_path,
            "proof_paths": evidence_paths.into_iter().collect::<Vec<_>>(),
            "extraction_paths": spec.extraction_paths,
        },
    }))
}

fn build_backend_metadata_surface(
    support_matrix: &SupportMatrixFile,
) -> ZkfResult<serde_json::Value> {
    ensure_repo_relative_path_exists("support-matrix.json")?;
    let backend = support_matrix
        .backends
        .iter()
        .find(|backend| backend.id == "arkworks-groth16")
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "support-matrix.json no longer contains arkworks-groth16".to_string(),
            )
        })?;
    let claims = vec![json!({
        "claim_id": "support_matrix.backend.arkworks_groth16",
        "classification": "metadata-only",
        "source": "support-matrix",
        "path": "support-matrix.json",
        "backend_id": backend.id,
        "status": backend.status,
        "assurance_lane": backend.assurance_lane,
        "proof_semantics": backend.proof_semantics,
    })];
    let counts = accumulate_claim_counts(&claims)?;
    Ok(json!({
        "surface_id": "truth.backend.arkworks_groth16",
        "label": "Arkworks Groth16 backend readiness and trust metadata",
        "path": "support-matrix.json",
        "source": "support-matrix",
        "classification_counts": counts,
        "classifications": classification_names(&counts),
        "claims": claims,
    }))
}

fn build_compatibility_alias_surface(
    support_matrix: &SupportMatrixFile,
) -> ZkfResult<serde_json::Value> {
    ensure_repo_relative_path_exists("support-matrix.json")?;
    let claims = support_matrix
        .backends
        .iter()
        .filter_map(|backend| {
            parse_explicit_compat_alias(&backend.notes).map(|alias| {
                json!({
                    "claim_id": format!("support_matrix.compatibility_alias.{}", backend.id),
                    "classification": "compatibility alias",
                    "source": "support-matrix",
                    "path": "support-matrix.json",
                    "backend_id": backend.id,
                    "alias": alias,
                    "assurance_lane": backend.assurance_lane,
                })
            })
        })
        .collect::<Vec<_>>();
    let counts = accumulate_claim_counts(&claims)?;
    Ok(json!({
        "surface_id": "truth.support_matrix_compatibility_aliases",
        "label": "Support-matrix explicit compatibility aliases",
        "path": "support-matrix.json",
        "source": "support-matrix",
        "classification_counts": counts,
        "classifications": classification_names(&counts),
        "claims": claims,
    }))
}

fn build_canonical_truth_surface(canonical_truth: &str) -> ZkfResult<serde_json::Value> {
    ensure_repo_relative_path_exists("docs/CANONICAL_TRUTH.md")?;
    let markers = canonical_truth_markers(canonical_truth)?;
    let claims = vec![
        json!({
            "claim_id": "canonical_truth.strict_cryptographic_default",
            "classification": "metadata-only",
            "source": "canonical-truth",
            "path": "docs/CANONICAL_TRUTH.md",
            "boundary": "strict-cryptographic default",
        }),
        json!({
            "claim_id": "canonical_truth.metadata_only_and_alias_guidance",
            "classification": "metadata-only",
            "source": "canonical-truth",
            "path": "docs/CANONICAL_TRUTH.md",
            "boundary": "metadata-only and compatibility-alias guidance",
        }),
    ];
    let counts = accumulate_claim_counts(&claims)?;
    Ok(json!({
        "surface_id": "truth.canonical_truth_active_boundaries",
        "label": "Canonical trust and compatibility boundaries",
        "path": "docs/CANONICAL_TRUTH.md",
        "source": "canonical-truth",
        "classification_counts": counts,
        "classifications": classification_names(&counts),
        "claims": claims,
        "markers": markers,
    }))
}

fn build_runtime_proof_coverage_surface(
    completion_status: &CompletionStatusFile,
) -> ZkfResult<serde_json::Value> {
    ensure_repo_relative_path_exists(".zkf-completion-status.json")?;
    let explicit_tcb_files = completion_status
        .runtime_proof_coverage
        .file_counts
        .get("explicit_tcb_adapter")
        .copied()
        .unwrap_or_default();
    let explicit_tcb_functions = completion_status
        .runtime_proof_coverage
        .function_counts
        .get("explicit_tcb_adapter")
        .copied()
        .unwrap_or_default();
    let claims = vec![json!({
        "claim_id": "completion_status.runtime_proof_coverage.explicit_tcb_adapter",
        "classification": "explicit_tcb_adapter",
        "source": "completion-status",
        "path": ".zkf-completion-status.json",
        "explicit_tcb_files": explicit_tcb_files,
        "explicit_tcb_functions": explicit_tcb_functions,
        "complete_files": completion_status.runtime_proof_coverage.complete_files,
        "complete_functions": completion_status.runtime_proof_coverage.complete_functions,
        "total_files": completion_status.runtime_proof_coverage.total_files,
        "total_functions": completion_status.runtime_proof_coverage.total_functions,
    })];
    let counts = accumulate_claim_counts(&claims)?;
    Ok(json!({
        "surface_id": "truth.runtime_proof_coverage",
        "label": "Runtime proof-coverage explicit TCB inventory",
        "path": ".zkf-completion-status.json",
        "source": "completion-status",
        "classification_counts": counts,
        "classifications": classification_names(&counts),
        "claims": claims,
    }))
}

fn build_surface_inventory() -> ZkfResult<BTreeMap<String, serde_json::Value>> {
    let ledger: VerificationLedgerFile =
        read_json(&repo_root().join("zkf-ir-spec/verification-ledger.json"))?;
    let support_matrix: SupportMatrixFile = read_json(&repo_root().join("support-matrix.json"))?;
    let completion_status: CompletionStatusFile =
        read_json(&repo_root().join(".zkf-completion-status.json"))?;
    let canonical_truth = read_text(&repo_root().join("docs/CANONICAL_TRUTH.md"))?;

    if completion_status.authoritative_status_source != "zkf-ir-spec/verification-ledger.json"
        || completion_status.generated_from != "zkf-ir-spec/verification-ledger.json"
    {
        return Err(ZkfError::InvalidArtifact(
            ".zkf-completion-status.json drifted away from zkf-ir-spec/verification-ledger.json"
                .to_string(),
        ));
    }

    let ledger_by_theorem = ledger
        .entries
        .into_iter()
        .map(|entry| (entry.theorem_id.clone(), entry))
        .collect::<BTreeMap<_, _>>();

    let mut surfaces = BTreeMap::new();
    for spec in ledger_surface_specs() {
        surfaces.insert(
            spec.surface_id.to_string(),
            build_ledger_surface(&spec, &ledger_by_theorem)?,
        );
    }
    let backend_surface = build_backend_metadata_surface(&support_matrix)?;
    surfaces.insert(surface_id_string(&backend_surface)?, backend_surface);
    let compatibility_surface = build_compatibility_alias_surface(&support_matrix)?;
    surfaces.insert(
        surface_id_string(&compatibility_surface)?,
        compatibility_surface,
    );
    let canonical_surface = build_canonical_truth_surface(&canonical_truth)?;
    surfaces.insert(surface_id_string(&canonical_surface)?, canonical_surface);
    let runtime_surface = build_runtime_proof_coverage_surface(&completion_status)?;
    surfaces.insert(surface_id_string(&runtime_surface)?, runtime_surface);
    Ok(surfaces)
}

fn build_app_closure(
    spec: &AppClosureSpec,
    surface_inventory: &BTreeMap<String, serde_json::Value>,
) -> ZkfResult<serde_json::Value> {
    let selected_surfaces = spec
        .surface_ids
        .iter()
        .map(|surface_id| {
            surface_inventory.get(*surface_id).cloned().ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "missing surface `{surface_id}` for generated app closure `{}`",
                    spec.app_id
                ))
            })
        })
        .collect::<ZkfResult<Vec<_>>>()?;

    let mut counts = assurance_counts_template();
    for surface in &selected_surfaces {
        let surface_counts = surface
            .get("classification_counts")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "surface `{}` missing classification counts",
                    surface
                        .get("surface_id")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("unknown")
                ))
            })?;
        for (classification, value) in surface_counts {
            let amount = value.as_u64().ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "surface `{}` has non-numeric count for classification `{classification}`",
                    spec.app_id
                ))
            })? as usize;
            let slot = counts.get_mut(classification.as_str()).ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "surface `{}` emitted unsupported classification `{classification}`",
                    spec.app_id
                ))
            })?;
            *slot += amount;
        }
    }

    let scripts = generated_app_formal_script_specs_internal(spec.app_id)?;
    Ok(json!({
        "schema": GENERATED_APP_CLOSURE_SCHEMA,
        "app_id": spec.app_id,
        "generated_closure_path": generated_app_closure_relative_path(spec.app_id),
        "implementation_closure_summary_path": IMPLEMENTATION_CLOSURE_SUMMARY_RELATIVE_PATH,
        "generated_from": {
            "verification_ledger": "zkf-ir-spec/verification-ledger.json",
            "completion_status": ".zkf-completion-status.json",
            "canonical_truth": "docs/CANONICAL_TRUTH.md",
            "support_matrix": "support-matrix.json",
        },
        "assurance_vocabulary": IMPLEMENTATION_CLOSURE_ASSURANCE_VOCABULARY,
        "application": spec.application,
        "bundle_files": bundle_files_for_scripts(scripts),
        "formal_scripts": scripts.iter().map(|script| json!({
            "name": script.name,
            "script_relative_path": script.script_relative_path,
            "log_file_name": script.log_file_name,
        })).collect::<Vec<_>>(),
        "selected_surface_ids": spec.surface_ids,
        "selected_surfaces": selected_surfaces,
        "assurance_counts": counts,
        "classifications": classification_names(&counts),
    }))
}

fn build_implementation_closure_summary(
    surface_inventory: &BTreeMap<String, serde_json::Value>,
    app_closures: &BTreeMap<String, serde_json::Value>,
) -> ZkfResult<serde_json::Value> {
    let completion_status: CompletionStatusFile =
        read_json(&repo_root().join(".zkf-completion-status.json"))?;
    let support_matrix: SupportMatrixFile = read_json(&repo_root().join("support-matrix.json"))?;
    let mut counts = assurance_counts_template();
    for surface in surface_inventory.values() {
        let surface_counts = surface
            .get("classification_counts")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "generated surface missing classification counts".to_string(),
                )
            })?;
        for (classification, value) in surface_counts {
            let amount = value.as_u64().ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "generated surface count for `{classification}` is not numeric"
                ))
            })? as usize;
            let slot = counts.get_mut(classification.as_str()).ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "generated surface emitted unsupported classification `{classification}`"
                ))
            })?;
            *slot += amount;
        }
    }

    Ok(json!({
        "schema": GENERATED_IMPLEMENTATION_CLOSURE_SCHEMA,
        "generated_from": {
            "verification_ledger": "zkf-ir-spec/verification-ledger.json",
            "completion_status": ".zkf-completion-status.json",
            "canonical_truth": "docs/CANONICAL_TRUTH.md",
            "support_matrix": "support-matrix.json",
        },
        "assurance_vocabulary": IMPLEMENTATION_CLOSURE_ASSURANCE_VOCABULARY,
        "current_priority": completion_status.current_priority,
        "release_grade_ready": completion_status.release_grade_ready,
        "support_matrix_schema_version": support_matrix.schema_version,
        "assurance_counts": counts,
        "classifications": classification_names(&counts),
        "surface_inventory": surface_inventory.values().cloned().collect::<Vec<_>>(),
        "app_closures": app_closures
            .iter()
            .map(|(app_id, closure)| {
                (app_id.clone(), json!({
                    "path": generated_app_closure_relative_path(app_id),
                    "assurance_counts": closure["assurance_counts"],
                    "classifications": closure["classifications"],
                }))
            })
            .collect::<serde_json::Map<_, _>>(),
    }))
}

fn generated_truth_documents() -> ZkfResult<BTreeMap<String, serde_json::Value>> {
    let surface_inventory = build_surface_inventory()?;
    let app_closures = app_closure_specs()
        .into_iter()
        .map(|spec| {
            Ok((
                spec.app_id.to_string(),
                build_app_closure(&spec, &surface_inventory)?,
            ))
        })
        .collect::<ZkfResult<BTreeMap<_, _>>>()?;
    let summary = build_implementation_closure_summary(&surface_inventory, &app_closures)?;

    let mut documents = BTreeMap::new();
    documents.insert(
        IMPLEMENTATION_CLOSURE_SUMMARY_RELATIVE_PATH.to_string(),
        summary,
    );
    for (app_id, closure) in app_closures {
        documents.insert(generated_app_closure_relative_path(&app_id), closure);
    }
    Ok(documents)
}

fn write_generated_truth_document(path: &Path, value: &serde_json::Value) -> ZkfResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", parent.display())))?;
    }
    let bytes = json_to_vec_pretty(value).map_err(|error| {
        ZkfError::Serialization(format!("serialize {}: {error}", path.display()))
    })?;
    fs::write(path, bytes)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))
}

pub fn sync_generated_truth_documents() -> ZkfResult<Vec<String>> {
    let mut written = Vec::new();
    for (relative_path, value) in generated_truth_documents()? {
        write_generated_truth_document(&repo_root().join(&relative_path), &value)?;
        written.push(relative_path);
    }
    Ok(written)
}

fn ensure_generated_truth_documents_present() -> ZkfResult<()> {
    let mut missing = !implementation_closure_summary_path().exists();
    if !missing {
        missing = app_closure_specs()
            .into_iter()
            .any(|spec| !generated_app_closure_path(spec.app_id).exists());
    }
    if !missing {
        return Ok(());
    }

    let _ = sync_generated_truth_documents()?;
    Ok(())
}

fn validate_generated_surface(surface: &serde_json::Value) -> ZkfResult<()> {
    let claims = surface
        .get("claims")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("generated closure surface missing claims".to_string())
        })?;
    let counts = surface
        .get("classification_counts")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "generated closure surface missing classification counts".to_string(),
            )
        })?;
    for classification in counts.keys() {
        if !IMPLEMENTATION_CLOSURE_ASSURANCE_VOCABULARY.contains(&classification.as_str()) {
            return Err(ZkfError::InvalidArtifact(format!(
                "generated closure surface emitted unsupported classification `{classification}`"
            )));
        }
    }
    for claim in claims {
        let classification = claim
            .get("classification")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact("generated claim missing classification".to_string())
            })?;
        if !IMPLEMENTATION_CLOSURE_ASSURANCE_VOCABULARY.contains(&classification) {
            return Err(ZkfError::InvalidArtifact(format!(
                "generated claim uses unsupported classification `{classification}`"
            )));
        }
        if let Some(path) = claim.get("path").and_then(serde_json::Value::as_str) {
            ensure_repo_relative_path_exists(path)?;
        }
        if let Some(path) = claim.get("source_path").and_then(serde_json::Value::as_str) {
            ensure_repo_relative_path_exists(path)?;
        }
        if let Some(path) = claim.get("proof_path").and_then(serde_json::Value::as_str) {
            ensure_repo_relative_path_exists(path)?;
        }
    }
    Ok(())
}

fn validate_generated_app_closure_document(
    app_id: &str,
    value: &serde_json::Value,
) -> ZkfResult<()> {
    if value.get("schema").and_then(serde_json::Value::as_str) != Some(GENERATED_APP_CLOSURE_SCHEMA)
    {
        return Err(ZkfError::InvalidArtifact(format!(
            "generated app closure `{app_id}` has unexpected schema"
        )));
    }
    if value.get("app_id").and_then(serde_json::Value::as_str) != Some(app_id) {
        return Err(ZkfError::InvalidArtifact(format!(
            "generated app closure `{app_id}` has mismatched app_id"
        )));
    }
    if value
        .get("generated_closure_path")
        .and_then(serde_json::Value::as_str)
        != Some(generated_app_closure_relative_path(app_id).as_str())
    {
        return Err(ZkfError::InvalidArtifact(format!(
            "generated app closure `{app_id}` has mismatched path"
        )));
    }
    ensure_repo_relative_path_exists(
        value
            .get("implementation_closure_summary_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "generated app closure `{app_id}` missing implementation summary path"
                ))
            })?,
    )?;
    let surfaces = value
        .get("selected_surfaces")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(format!(
                "generated app closure `{app_id}` missing selected surfaces"
            ))
        })?;
    if surfaces.is_empty() {
        return Err(ZkfError::InvalidArtifact(format!(
            "generated app closure `{app_id}` selected no surfaces"
        )));
    }
    for surface in surfaces {
        validate_generated_surface(surface)?;
    }
    Ok(())
}

fn validate_generated_implementation_closure_summary_document(
    value: &serde_json::Value,
) -> ZkfResult<()> {
    if value.get("schema").and_then(serde_json::Value::as_str)
        != Some(GENERATED_IMPLEMENTATION_CLOSURE_SCHEMA)
    {
        return Err(ZkfError::InvalidArtifact(
            "implementation closure summary has unexpected schema".to_string(),
        ));
    }
    let surfaces = value
        .get("surface_inventory")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "implementation closure summary missing surface inventory".to_string(),
            )
        })?;
    for surface in surfaces {
        validate_generated_surface(surface)?;
    }
    let app_closures = value
        .get("app_closures")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(
                "implementation closure summary missing app closure map".to_string(),
            )
        })?;
    for (app_id, metadata) in app_closures {
        let path = metadata
            .get("path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "implementation closure summary missing path for `{app_id}`"
                ))
            })?;
        if path != generated_app_closure_relative_path(app_id) {
            return Err(ZkfError::InvalidArtifact(format!(
                "implementation closure summary path for `{app_id}` drifted to `{path}`"
            )));
        }
        ensure_repo_relative_path_exists(path)?;
    }
    Ok(())
}

pub fn load_generated_implementation_closure_summary() -> ZkfResult<serde_json::Value> {
    ensure_generated_truth_documents_present()?;
    let path = implementation_closure_summary_path();
    let value: serde_json::Value = read_json(&path)?;
    validate_generated_implementation_closure_summary_document(&value)?;
    Ok(value)
}

pub fn load_generated_app_closure(app_id: &str) -> ZkfResult<serde_json::Value> {
    ensure_generated_truth_documents_present()?;
    let path = generated_app_closure_path(app_id);
    let value: serde_json::Value = read_json(&path)?;
    validate_generated_app_closure_document(app_id, &value)?;
    Ok(value)
}

pub fn generated_app_closure_bundle_summary(app_id: &str) -> ZkfResult<serde_json::Value> {
    let closure = load_generated_app_closure(app_id)?;
    Ok(json!({
        "app_id": app_id,
        "extract_path": generated_app_closure_relative_path(app_id),
        "summary_path": IMPLEMENTATION_CLOSURE_SUMMARY_RELATIVE_PATH,
        "assurance_counts": closure["assurance_counts"],
        "classifications": closure["classifications"],
    }))
}

pub fn collect_formal_evidence_for_generated_app(
    out_dir: &Path,
    app_id: &str,
) -> ZkfResult<(serde_json::Value, serde_json::Value)> {
    let closure = load_generated_app_closure(app_id)?;
    let scripts = generated_app_formal_script_specs_internal(app_id)?;
    let formal_evidence = collect_formal_evidence(out_dir, &closure, scripts)?;
    Ok((closure, formal_evidence))
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")))
}

pub fn archive_showcase_artifacts(app_id: &str, artifacts: &[&Path]) -> ZkfResult<()> {
    let config = StorageGuardianConfig::from_env();
    if !(config.enabled && config.auto_archive_proofs && config.icloud_archive_enabled) {
        return Ok(());
    }

    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    let archive_root = match icloud_archive_root() {
        Some(path) => path,
        None if config.dry_run => expected_icloud_archive_root(&home),
        None => {
            return Err(ZkfError::Io(
                "iCloud Drive is not available at ~/Library/Mobile Documents/com~apple~CloudDocs/ZirOS_Archive"
                    .to_string(),
            ));
        }
    };
    let run_name = format!("{app_id}_{}", current_utc_timestamp());

    for artifact in artifacts {
        if !artifact.exists() || classify_path(artifact) != FileClass::Archivable {
            continue;
        }
        let archive_dest = archive_file(
            artifact,
            FileClass::Archivable,
            &run_name,
            &archive_root,
            true,
        )
        .map_err(storage_error_to_zkf)?;
        if config.dry_run {
            continue;
        }
        if let Some(parent) = archive_dest.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                ZkfError::Io(format!("create {}: {error}", parent.display()))
            })?;
        }
        fs::copy(artifact, &archive_dest).map_err(|error| {
            ZkfError::Io(format!(
                "copy {} -> {}: {error}",
                artifact.display(),
                archive_dest.display()
            ))
        })?;
    }

    Ok(())
}

pub fn purge_showcase_witness_artifacts(paths: &[&Path]) -> ZkfResult<()> {
    let config = StorageGuardianConfig::from_env();
    if !(config.enabled && config.purge_witness_after_prove) {
        return Ok(());
    }

    let purge_targets = paths
        .iter()
        .filter(|path| path.exists() && classify_path(path) == FileClass::Ephemeral)
        .map(|path| (*path).to_path_buf())
        .collect::<Vec<_>>();
    if purge_targets.is_empty() {
        return Ok(());
    }

    purge_ephemeral(&purge_targets, config.dry_run).map_err(storage_error_to_zkf)?;
    Ok(())
}

fn expected_icloud_archive_root(home: &Path) -> PathBuf {
    home.join("Library")
        .join("Mobile Documents")
        .join("com~apple~CloudDocs")
        .join("ZirOS_Archive")
}

fn storage_error_to_zkf(error: zkf_storage::StorageError) -> ZkfError {
    ZkfError::Io(error.to_string())
}

fn surface_id_string(surface: &serde_json::Value) -> ZkfResult<String> {
    surface
        .get("surface_id")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("generated evidence surface missing surface_id".to_string())
        })
}

pub fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", parent.display())))?;
    }
    let bytes = json_to_vec_pretty(value).map_err(|error| {
        ZkfError::Serialization(format!("serialize {}: {error}", path.display()))
    })?;
    fs::write(path, bytes)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

pub fn write_text(path: &Path, value: &str) -> ZkfResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", parent.display())))?;
    }
    fs::write(path, value)
        .map_err(|error| ZkfError::Io(format!("write {}: {error}", path.display())))?;
    Ok(())
}

pub fn read_json<T: DeserializeOwned>(path: &Path) -> ZkfResult<T> {
    let bytes = fs::read(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
    json_from_slice(&bytes)
        .map_err(|error| ZkfError::Serialization(format!("parse {}: {error}", path.display())))
}

pub fn read_text(path: &Path) -> ZkfResult<String> {
    fs::read_to_string(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))
}

pub fn ensure_file_exists(path: &Path) -> ZkfResult<()> {
    let metadata = fs::metadata(path)
        .map_err(|error| ZkfError::Io(format!("stat {}: {error}", path.display())))?;
    if !metadata.is_file() {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected {} to be a file",
            path.display()
        )));
    }
    Ok(())
}

pub fn ensure_dir_exists(path: &Path) -> ZkfResult<()> {
    let metadata = fs::metadata(path)
        .map_err(|error| ZkfError::Io(format!("stat {}: {error}", path.display())))?;
    if !metadata.is_dir() {
        return Err(ZkfError::InvalidArtifact(format!(
            "expected {} to be a directory",
            path.display()
        )));
    }
    Ok(())
}

pub fn foundry_project_dir(out_dir: &Path) -> PathBuf {
    out_dir.join("foundry")
}

pub fn ensure_foundry_layout(project_dir: &Path) -> ZkfResult<()> {
    fs::create_dir_all(project_dir.join("src"))
        .map_err(|error| ZkfError::Io(format!("create foundry src: {error}")))?;
    fs::create_dir_all(project_dir.join("test"))
        .map_err(|error| ZkfError::Io(format!("create foundry test: {error}")))?;
    write_text(
        &project_dir.join("foundry.toml"),
        "[profile.default]\nsrc = \"src\"\ntest = \"test\"\nout = \"out\"\nlibs = []\nsolc_version = \"0.8.26\"\n",
    )?;
    Ok(())
}

pub fn json_pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

pub fn canonicalize_for_determinism_hash(value: &serde_json::Value) -> serde_json::Value {
    const STRIPPED_KEYS: &[&str] = &[
        "timestamp_unix_ms",
        "telemetry_sequence_id",
        "telemetry_replay_guard",
        "start_timestamp",
        "end_timestamp",
        "duration_ms",
        "telemetry_paths",
        "generated_telemetry_paths",
        "telemetry_file_paths",
        "runtime_trace_path",
        "accelerator_trace_path",
    ];

    fn inner(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut ordered = BTreeMap::new();
                for (key, value) in map {
                    if STRIPPED_KEYS.contains(&key.as_str()) {
                        continue;
                    }
                    ordered.insert(key.clone(), inner(value));
                }
                let mut out = serde_json::Map::new();
                for (key, value) in ordered {
                    out.insert(key, value);
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(inner).collect())
            }
            _ => value.clone(),
        }
    }

    inner(value)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn hash_json_value(value: &serde_json::Value) -> ZkfResult<String> {
    let bytes = json_to_vec_pretty(value)
        .map_err(|error| ZkfError::Serialization(format!("serialize json for hashing: {error}")))?;
    Ok(sha256_hex(&bytes))
}

pub fn effective_gpu_attribution_summary(
    runtime_gpu_nodes: usize,
    runtime_gpu_busy_ratio: f64,
    artifact_metadata: &BTreeMap<String, String>,
) -> serde_json::Value {
    let mut evidence_sources = BTreeSet::new();
    let mut artifact_metadata_evidence = serde_json::Map::new();
    let mut effective_gpu_busy_ratio = runtime_gpu_busy_ratio.max(0.0);

    if runtime_gpu_nodes > 0 {
        evidence_sources.insert("runtime.gpu_nodes".to_string());
    }
    if runtime_gpu_busy_ratio > 0.0 {
        evidence_sources.insert("runtime.gpu_busy_ratio".to_string());
    }

    let metadata_keys = [
        "best_msm_accelerator",
        "gpu_stage_coverage",
        "groth16_msm_engine",
        "metal_available",
        "metal_compiled",
        "metal_complete",
        "metal_gpu_busy_ratio",
        "qap_witness_map_engine",
    ];
    for key in metadata_keys {
        if let Some(value) = artifact_metadata.get(key) {
            artifact_metadata_evidence.insert(key.to_string(), json!(value));
        }
    }

    let backend_uses_metal = [
        "best_msm_accelerator",
        "groth16_msm_engine",
        "qap_witness_map_engine",
    ]
    .iter()
    .any(|key| {
        artifact_metadata
            .get(*key)
            .map(|value| value.to_ascii_lowercase().contains("metal"))
            .unwrap_or(false)
    });
    if backend_uses_metal {
        evidence_sources.insert("artifact.metadata.backend_engine".to_string());
    }

    let gpu_stage_coverage_mentions_metal = artifact_metadata
        .get("gpu_stage_coverage")
        .map(|value| value.to_ascii_lowercase().contains("metal"))
        .unwrap_or(false);
    if gpu_stage_coverage_mentions_metal {
        evidence_sources.insert("artifact.metadata.gpu_stage_coverage".to_string());
    }

    let metal_stack_ready = ["metal_available", "metal_compiled", "metal_complete"]
        .iter()
        .all(|key| artifact_metadata.get(*key).map(String::as_str) == Some("true"));
    if metal_stack_ready {
        evidence_sources.insert("artifact.metadata.metal_ready".to_string());
    }

    let artifact_busy_ratio = artifact_metadata
        .get("metal_gpu_busy_ratio")
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(0.0)
        .max(0.0);
    if artifact_busy_ratio > 0.0 {
        effective_gpu_busy_ratio = effective_gpu_busy_ratio.max(artifact_busy_ratio);
        evidence_sources.insert("artifact.metadata.metal_gpu_busy_ratio".to_string());
    }

    let effective_gpu_participation = runtime_gpu_nodes > 0
        || runtime_gpu_busy_ratio > 0.0
        || artifact_busy_ratio > 0.0
        || backend_uses_metal
        || gpu_stage_coverage_mentions_metal;

    let classification = if runtime_gpu_nodes > 0 || runtime_gpu_busy_ratio > 0.0 {
        "runtime-direct"
    } else if effective_gpu_participation {
        "backend-delegated"
    } else {
        "none"
    };

    json!({
        "classification": classification,
        "runtime_gpu_nodes": runtime_gpu_nodes,
        "runtime_gpu_busy_ratio": runtime_gpu_busy_ratio,
        "artifact_metal_gpu_busy_ratio": artifact_busy_ratio,
        "effective_gpu_busy_ratio": effective_gpu_busy_ratio,
        "effective_gpu_participation": effective_gpu_participation,
        "evidence_sources": evidence_sources.into_iter().collect::<Vec<_>>(),
        "artifact_metadata_evidence": artifact_metadata_evidence,
    })
}

fn run_formal_script(
    repo_root: &Path,
    script_relative_path: &str,
    log_path: &Path,
) -> ZkfResult<serde_json::Value> {
    let mut log = String::new();
    let command_description = format!("bash {script_relative_path}");
    let timeout = std::env::var("ZKF_FORMAL_SCRIPT_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(30));
    let mut command = Command::new("bash");
    command
        .current_dir(repo_root)
        .arg(script_relative_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let child = command.spawn();

    let (status, exit_code) = match child {
        Ok(mut child) => {
            let start = Instant::now();
            let mut timed_out = false;
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) => {
                        if start.elapsed() >= timeout {
                            timed_out = true;
                            let _ = child.kill();
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                    Err(error) => {
                        log.push_str(&format!(
                            "failed to poll `{command_description}` from {}: {error}\n",
                            repo_root.display()
                        ));
                        write_text(log_path, &log)?;
                        return Ok(json!({
                            "command": command_description,
                            "status": "failed",
                            "exit_code": serde_json::Value::Null,
                            "log_path": format!(
                                "formal/{}",
                                log_path.file_name().and_then(|name| name.to_str()).unwrap_or_default()
                            ),
                        }));
                    }
                }
            }

            let output = match child.wait_with_output() {
                Ok(output) => output,
                Err(error) => {
                    log.push_str(&format!(
                        "failed to collect output from `{command_description}` in {}: {error}\n",
                        repo_root.display()
                    ));
                    write_text(log_path, &log)?;
                    return Ok(json!({
                        "command": command_description,
                        "status": "failed",
                        "exit_code": serde_json::Value::Null,
                        "log_path": format!(
                            "formal/{}",
                            log_path.file_name().and_then(|name| name.to_str()).unwrap_or_default()
                        ),
                    }));
                }
            };

            if !output.stdout.is_empty() {
                log.push_str(&String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                if !log.ends_with('\n') && !log.is_empty() {
                    log.push('\n');
                }
                log.push_str(&String::from_utf8_lossy(&output.stderr));
            }
            if timed_out {
                if !log.ends_with('\n') && !log.is_empty() {
                    log.push('\n');
                }
                log.push_str(&format!(
                    "{command_description} timed out after {} seconds and was terminated\n",
                    timeout.as_secs()
                ));
            }
            (
                if !timed_out && output.status.success() {
                    "passed"
                } else {
                    "failed"
                },
                if timed_out {
                    None
                } else {
                    output.status.code()
                },
            )
        }
        Err(error) => {
            log.push_str(&format!(
                "failed to spawn `{command_description}` from {}: {error}\n",
                repo_root.display()
            ));
            ("failed", None)
        }
    };

    if log.is_empty() {
        log.push_str(&format!("{command_description}\n"));
    }
    write_text(log_path, &log)?;

    Ok(json!({
        "command": command_description,
        "status": status,
        "exit_code": exit_code,
        "log_path": format!(
            "formal/{}",
            log_path.file_name().and_then(|name| name.to_str()).unwrap_or_default()
        ),
    }))
}

pub fn collect_formal_evidence(
    out_dir: &Path,
    exercised_surfaces: &serde_json::Value,
    scripts: &[FormalScriptSpec],
) -> ZkfResult<serde_json::Value> {
    let repo_root = repo_root();
    let formal_dir = out_dir.join("formal");
    let exercised_surfaces_path = formal_dir.join("exercised_surfaces.json");
    fs::create_dir_all(&formal_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", formal_dir.display())))?;

    write_json(&exercised_surfaces_path, exercised_surfaces)?;

    let mut runs = Vec::new();
    for script in scripts {
        let log_path = formal_dir.join(script.log_file_name);
        let mut run = run_formal_script(&repo_root, script.script_relative_path, &log_path)?;
        if let Some(object) = run.as_object_mut() {
            object.insert("name".to_string(), json!(script.name));
        }
        runs.push(run);
    }

    let overall_status = if runs
        .iter()
        .all(|run| run.get("status").and_then(serde_json::Value::as_str) == Some("passed"))
    {
        "included"
    } else {
        "failed"
    };

    let mut status_markdown = String::from("# Formal Evidence Status\n\n");
    status_markdown.push_str(&format!("- overall_status: `{overall_status}`\n"));
    status_markdown.push_str("- exercised_surfaces: `formal/exercised_surfaces.json`\n");
    for run in &runs {
        let name = run
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let status = run
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let command = run
            .get("command")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        let log_path = run
            .get("log_path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        status_markdown.push_str(&format!(
            "- {name}: `{status}` via `{command}` -> `{log_path}`\n"
        ));
    }
    write_text(&formal_dir.join("STATUS.md"), &status_markdown)?;

    // Keep the finished-app bundle fail-closed on shape: if a downstream tool or
    // race leaves one of the expected formal files missing, rewrite a minimal
    // placeholder so the exporter can still surface the actual run status in-bundle.
    if !exercised_surfaces_path.is_file() {
        write_json(&exercised_surfaces_path, exercised_surfaces)?;
    }
    for script in scripts {
        let log_path = formal_dir.join(script.log_file_name);
        if !log_path.is_file() {
            write_text(
                &log_path,
                &format!(
                    "formal runner `{}` did not leave a log on disk; see formal/STATUS.md for the recorded run status\n",
                    script.name
                ),
            )?;
        }
    }

    Ok(json!({
        "status": overall_status,
        "files": {
            "status": "formal/STATUS.md",
            "exercised_surfaces": "formal/exercised_surfaces.json",
            "logs": scripts.iter().map(|script| format!("formal/{}", script.log_file_name)).collect::<Vec<_>>(),
        },
        "runs": runs,
    }))
}

pub fn collect_default_formal_evidence(
    out_dir: &Path,
    exercised_surfaces: &serde_json::Value,
) -> ZkfResult<serde_json::Value> {
    collect_formal_evidence(out_dir, exercised_surfaces, &DEFAULT_FORMAL_SCRIPT_SPECS)
}

pub fn audit_entry_included(
    reason: &str,
    path: &str,
    producer: &str,
    summary: serde_json::Value,
) -> serde_json::Value {
    json!({
        "status": "included",
        "reason": reason,
        "path": path,
        "producer": producer,
        "summary": summary,
    })
}

pub fn audit_entry_omitted_by_default(reason: &str) -> serde_json::Value {
    json!({
        "status": "omitted-by-default",
        "reason": reason,
        "path": serde_json::Value::Null,
    })
}

pub fn two_tier_audit_record(
    mode: &str,
    structural_summary: serde_json::Value,
    full_source_audit: serde_json::Value,
    full_compiled_audit: serde_json::Value,
) -> serde_json::Value {
    json!({
        "mode": mode,
        "structural_summary": structural_summary,
        "full_source_audit": full_source_audit,
        "full_compiled_audit": full_compiled_audit,
    })
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn with_env<T>(pairs: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let old_values = pairs
            .iter()
            .map(|(key, _)| ((*key).to_string(), std::env::var_os(key)))
            .collect::<Vec<_>>();
        unsafe {
            for (key, value) in pairs {
                std::env::set_var(key, value);
            }
        }
        let result = f();
        unsafe {
            for (key, old_value) in old_values {
                match old_value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
        result
    }

    #[test]
    fn implementation_closure_generated_outputs_match_repo_files() {
        let expected = generated_truth_documents().expect("generate truth documents");
        for (relative_path, expected_value) in expected {
            let path = repo_root().join(&relative_path);
            let actual_value: serde_json::Value =
                read_json(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            assert_eq!(
                actual_value, expected_value,
                "generated truth surface drifted from {}",
                relative_path
            );
        }
    }

    #[test]
    fn implementation_closure_loader_rejects_missing_paths_and_unknown_classifications() {
        let bad = json!({
            "schema": GENERATED_APP_CLOSURE_SCHEMA,
            "app_id": ORBITAL_APP_ID,
            "generated_closure_path": generated_app_closure_relative_path(ORBITAL_APP_ID),
            "implementation_closure_summary_path": IMPLEMENTATION_CLOSURE_SUMMARY_RELATIVE_PATH,
            "selected_surfaces": [
                {
                    "surface_id": "bad.surface",
                    "classification_counts": {
                        "mechanized": 0,
                        "bounded": 0,
                        "model-only": 0,
                        "hypothesis-carried": 0,
                        "compatibility alias": 0,
                        "metadata-only": 0,
                        "explicit_tcb_adapter": 0
                    },
                    "claims": [
                        {
                            "classification": "unknown-classification",
                            "path": "does/not/exist"
                        }
                    ]
                }
            ]
        });
        let error = validate_generated_app_closure_document(ORBITAL_APP_ID, &bad)
            .expect_err("tampered closure should fail validation");
        assert!(
            error.to_string().contains("unsupported classification")
                || error.to_string().contains("does not exist"),
            "unexpected validation error: {error}"
        );
    }

    #[test]
    fn generated_app_closure_bundle_summary_matches_loaded_extract() {
        let closure = load_generated_app_closure(VOTING_APP_ID).expect("load voting closure");
        let summary =
            generated_app_closure_bundle_summary(VOTING_APP_ID).expect("generate bundle summary");
        assert_eq!(
            summary["extract_path"],
            json!(generated_app_closure_relative_path(VOTING_APP_ID))
        );
        assert_eq!(summary["assurance_counts"], closure["assurance_counts"]);
        assert_eq!(summary["classifications"], closure["classifications"]);
    }

    #[test]
    fn canonical_determinism_hash_strips_runtime_only_fields() {
        let left = json!({
            "timestamp_unix_ms": 1000,
            "nested": {
                "telemetry_sequence_id": "a",
                "duration_ms": 12.5,
                "kept": true,
            },
            "array": [
                {
                    "start_timestamp": "2026-01-01T00:00:00Z",
                    "end_timestamp": "2026-01-01T00:00:01Z",
                    "value": 7,
                }
            ],
            "runtime_trace_path": "/tmp/a.json",
        });
        let right = json!({
            "timestamp_unix_ms": 2000,
            "nested": {
                "telemetry_sequence_id": "b",
                "duration_ms": 99.0,
                "kept": true,
            },
            "array": [
                {
                    "start_timestamp": "2026-02-01T00:00:00Z",
                    "end_timestamp": "2026-02-01T00:00:01Z",
                    "value": 7,
                }
            ],
            "runtime_trace_path": "/tmp/b.json",
        });

        let left_canonical = canonicalize_for_determinism_hash(&left);
        let right_canonical = canonicalize_for_determinism_hash(&right);
        assert_eq!(left_canonical, right_canonical);
        assert_eq!(
            hash_json_value(&left_canonical).expect("hash left"),
            hash_json_value(&right_canonical).expect("hash right")
        );
    }

    #[test]
    fn evidence_write_helpers_create_missing_parent_directories() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zkf-evidence-test-{unique}"));
        let text_path = dir.join("nested/formal/STATUS.md");
        let json_path = dir.join("nested/formal/exercised_surfaces.json");

        write_text(&text_path, "ok").expect("write text");
        write_json(&json_path, &json!({ "status": "included" })).expect("write json");

        assert_eq!(fs::read_to_string(&text_path).expect("read text"), "ok");
        let written: serde_json::Value = read_json(&json_path).expect("read json");
        assert_eq!(written, json!({ "status": "included" }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn archive_showcase_artifacts_dry_run_preserves_local_bundle_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let home = temp.path().join("home");
        let artifact = temp.path().join("private_demo.runtime.proof.json");
        fs::create_dir_all(&home).expect("home");
        fs::write(&artifact, "{}").expect("artifact");
        with_env(
            &[
                ("HOME", home.to_str().expect("home path")),
                ("ZKF_STORAGE_ENABLED", "1"),
                ("ZKF_STORAGE_ARCHIVE_PROOFS", "1"),
                ("ZKF_STORAGE_DRY_RUN", "1"),
            ],
            || {
                archive_showcase_artifacts("private_demo", &[artifact.as_path()])
                    .expect("archive dry run");
            },
        );
        assert!(artifact.exists());
    }

    #[test]
    fn purge_showcase_witness_artifacts_removes_ephemeral_witness_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let witness_path = temp.path().join("private_demo.witness.prepared.json");
        fs::write(&witness_path, "{}").expect("witness");
        with_env(
            &[
                ("ZKF_STORAGE_ENABLED", "1"),
                ("ZKF_STORAGE_PURGE_WITNESS", "1"),
            ],
            || {
                purge_showcase_witness_artifacts(&[witness_path.as_path()])
                    .expect("purge witness");
            },
        );
        assert!(!witness_path.exists());
    }
}
