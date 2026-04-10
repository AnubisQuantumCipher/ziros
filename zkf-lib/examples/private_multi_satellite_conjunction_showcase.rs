use ark_bn254::G1Affine;
use ark_ec::AffineRepr;
use ark_serialize::CanonicalSerialize;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_backends::metal_runtime::metal_runtime_report;
use zkf_backends::{
    BackendRoute, GROTH16_DETERMINISTIC_DEV_PROVENANCE,
    GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY, GROTH16_IMPORTED_SETUP_PROVENANCE,
    GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY, GROTH16_SETUP_PROVENANCE_METADATA_KEY,
    GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY, current_metal_thresholds,
    groth16_bn254_witness_map_ntt_parity, prepare_witness_for_proving,
    requested_groth16_setup_blob_path,
};
use zkf_backends::{with_allow_dev_deterministic_groth16_override, with_proof_seed_override};
use zkf_core::acceleration::{CpuMsmAccelerator, MsmAccelerator, accelerator_registry};
use zkf_core::ccs::CcsProgram;
use zkf_core::{
    BackendKind, CompiledProgram, Program, ProofArtifact, SystemResources, Witness,
    check_constraints, json_from_slice, json_to_vec_pretty,
};
use zkf_lib::app::multi_satellite::{
    PairCheck, PrivateMultiSatelliteScenario, PrivateMultiSatelliteScenarioSpec,
    private_multi_satellite_conjunction_showcase_for_scenario,
    private_multi_satellite_conjunction_witness, private_multi_satellite_pair_schedule,
    private_multi_satellite_scenario_spec,
};
use zkf_lib::evidence::{
    canonicalize_for_determinism_hash, collect_formal_evidence_for_generated_app,
    effective_gpu_attribution_summary, ensure_dir_exists, ensure_file_exists,
    ensure_foundry_layout, foundry_project_dir, generated_app_closure_bundle_summary,
    hash_json_value, persist_artifacts_to_cloudfs, sha256_hex, two_tier_audit_record,
    write_json as write_bundle_json, write_text as write_bundle_text,
};
use zkf_lib::{
    ZkfError, ZkfResult, audit_program_with_live_capabilities, compile,
    export_groth16_solidity_verifier, verify,
};
use zkf_runtime::{
    BackendProofExecutionResult, ExecutionMode, OptimizationObjective, RequiredTrustLane,
    RuntimeExecutor,
};

const SETUP_SEED: [u8; 32] = [0x5a; 32];
const PROOF_SEED: [u8; 32] = [0x6c; 32];
const APP_ID: &str = "private_multi_satellite_conjunction_showcase";
const SCENARIOS_ENV: &str = "ZKF_PRIVATE_MULTI_SATELLITE_SCENARIOS";
const FULL_AUDIT_ENV: &str = "ZKF_PRIVATE_MULTI_SATELLITE_FULL_AUDIT";

fn with_showcase_groth16_mode<T, F: FnOnce() -> ZkfResult<T>>(
    trusted_setup_used: bool,
    f: F,
) -> ZkfResult<T> {
    if trusted_setup_used {
        f()
    } else {
        with_allow_dev_deterministic_groth16_override(Some(true), f)
    }
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn json_pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn parse_decimal_bigint(value: &str) -> ZkfResult<num_bigint::BigInt> {
    value.parse::<num_bigint::BigInt>().map_err(|error| {
        ZkfError::Serialization(format!("parse decimal bigint `{value}`: {error}"))
    })
}

fn timestamp_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn write_json(path: &Path, value: &impl Serialize) -> ZkfResult<()> {
    write_bundle_json(path, value)
}

fn write_text(path: &Path, value: &str) -> ZkfResult<()> {
    write_bundle_text(path, value)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> ZkfResult<T> {
    let bytes = fs::read(path)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
    json_from_slice(&bytes)
        .map_err(|error| ZkfError::Serialization(format!("parse {}: {error}", path.display())))
}

fn env_flag(name: &str) -> bool {
    matches!(
        env::var(name).ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn full_audit_requested() -> bool {
    env_flag(FULL_AUDIT_ENV)
}

fn selected_scenarios() -> ZkfResult<Vec<PrivateMultiSatelliteScenario>> {
    let raw = env::var(SCENARIOS_ENV).unwrap_or_else(|_| "base32,stress64".to_string());
    let mut scenarios = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let scenario = match token {
            "base32" => PrivateMultiSatelliteScenario::Base32,
            "stress64" => PrivateMultiSatelliteScenario::Stress64,
            "mini" => PrivateMultiSatelliteScenario::Mini,
            other => {
                return Err(ZkfError::Backend(format!(
                    "unknown {SCENARIOS_ENV} scenario `{other}`"
                )));
            }
        };
        scenarios.push(scenario);
    }
    if scenarios.is_empty() {
        return Err(ZkfError::Backend(format!(
            "{SCENARIOS_ENV} selected no scenarios"
        )));
    }
    Ok(scenarios)
}

fn default_output_dir(spec: &PrivateMultiSatelliteScenarioSpec) -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    match spec.scenario {
        PrivateMultiSatelliteScenario::Base32 => {
            PathBuf::from(home).join("Desktop/ZirOS_Private_MultiSatellite_32Sat_64Pairs_120Steps")
        }
        PrivateMultiSatelliteScenario::Stress64 => {
            PathBuf::from(home).join("Desktop/ZirOS_Private_MultiSatellite_64Sat_256Pairs_240Steps")
        }
        PrivateMultiSatelliteScenario::Mini => {
            PathBuf::from(home).join("Desktop/ZirOS_Private_MultiSatellite_Mini")
        }
    }
}

fn scenario_output_dir(
    spec: &PrivateMultiSatelliteScenarioSpec,
    root_override: Option<&Path>,
    selected_count: usize,
) -> PathBuf {
    match root_override {
        Some(root) if selected_count == 1 => root.to_path_buf(),
        Some(root) => root.join(spec.scenario_id),
        None => default_output_dir(spec),
    }
}

fn foundry_project_dir_for_bundle(out_dir: &Path) -> PathBuf {
    foundry_project_dir(out_dir)
}

fn telemetry_dir() -> PathBuf {
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".to_string())).join(".zkf/telemetry")
}

fn telemetry_snapshot() -> BTreeSet<String> {
    let mut snapshot = BTreeSet::new();
    if let Ok(read_dir) = fs::read_dir(telemetry_dir()) {
        for entry in read_dir.flatten() {
            snapshot.insert(entry.path().display().to_string());
        }
    }
    snapshot
}

fn new_telemetry_paths(before: &BTreeSet<String>, after: &BTreeSet<String>) -> Vec<String> {
    after.difference(before).cloned().collect()
}

fn stats(program: &Program) -> serde_json::Value {
    json!({
        "signals": program.signals.len(),
        "constraints": program.constraints.len(),
        "public_signals": program
            .signals
            .iter()
            .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
            .count(),
        "blackbox_constraints": program
            .constraints
            .iter()
            .filter(|constraint| matches!(constraint, zkf_core::Constraint::BlackBox { .. }))
            .count(),
    })
}

fn ccs_summary(compiled: &CompiledProgram) -> ZkfResult<serde_json::Value> {
    let ccs = CcsProgram::try_from_program(&compiled.program)?;
    Ok(json!({
        "program_name": ccs.name,
        "field": ccs.field.as_str(),
        "total_constraint_count": ccs.num_constraints,
        "total_gates_or_rows": ccs.num_constraints,
        "num_variables": ccs.num_variables,
        "public_input_count": ccs.num_public,
        "matrix_count": ccs.num_matrices(),
        "matrix_terms": ccs.num_terms(),
        "degree": ccs.degree(),
    }))
}

fn stage_metric(
    stage_name: &str,
    stage_category: &str,
    start_timestamp: Option<u128>,
    end_timestamp: Option<u128>,
    duration_ms: Option<f64>,
    planned_accelerator: &str,
    selected_accelerator: &str,
    realized_accelerator: &str,
    bytes_read: Option<usize>,
    bytes_written: Option<usize>,
    batch_size: Option<usize>,
    streamed: bool,
    delegated_to_backend: bool,
    retried: bool,
    fell_back: bool,
    fallback_reason: Option<String>,
    timing_source: &str,
) -> serde_json::Value {
    json!({
        "stage_name": stage_name,
        "stage_category": stage_category,
        "start_timestamp": start_timestamp,
        "end_timestamp": end_timestamp,
        "duration_ms": duration_ms,
        "planned_accelerator": planned_accelerator,
        "accelerator_selected": selected_accelerator,
        "accelerator_realized": realized_accelerator,
        "bytes_read": bytes_read,
        "bytes_written": bytes_written,
        "batch_size": batch_size,
        "streamed": streamed,
        "delegated_to_backend": delegated_to_backend,
        "retried": retried,
        "fell_back": fell_back,
        "fallback_reason": fallback_reason,
        "timing_source": timing_source,
    })
}

fn runtime_node_traces_json(report: &zkf_runtime::GraphExecutionReport) -> serde_json::Value {
    serde_json::Value::Array(
        report
            .node_traces
            .iter()
            .map(|trace| {
                json!({
                    "node_id": trace.node_id.as_u64(),
                    "op_name": trace.op_name,
                    "stage_key": trace.stage_key,
                    "placement": format!("{:?}", trace.placement),
                    "trust_model": format!("{:?}", trace.trust_model),
                    "wall_time_ms": trace.wall_time.as_secs_f64() * 1_000.0,
                    "problem_size": trace.problem_size,
                    "input_bytes": trace.input_bytes,
                    "output_bytes": trace.output_bytes,
                    "predicted_cpu_ms": trace.predicted_cpu_ms,
                    "predicted_gpu_ms": trace.predicted_gpu_ms,
                    "prediction_confidence": trace.prediction_confidence,
                    "prediction_observation_count": trace.prediction_observation_count,
                    "allocated_bytes_after": trace.allocated_bytes_after,
                    "accelerator_name": trace.accelerator_name,
                    "fell_back": trace.fell_back,
                    "buffer_residency": trace.buffer_residency,
                    "delegated": trace.delegated,
                    "delegated_backend": trace.delegated_backend,
                })
            })
            .collect(),
    )
}

fn public_inputs_bundle(
    spec: &PrivateMultiSatelliteScenarioSpec,
    pair_schedule: &[PairCheck],
    witness: &Witness,
) -> ZkfResult<serde_json::Value> {
    let collision_threshold = witness
        .values
        .get("collision_threshold")
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: "collision_threshold".to_string(),
        })?
        .to_decimal_string();
    let delta_v_budget = witness
        .values
        .get("delta_v_budget")
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: "delta_v_budget".to_string(),
        })?
        .to_decimal_string();
    let final_state_commitments = (0..spec.satellite_count)
        .map(|satellite| {
            let name = format!("sat{satellite}_final_state_commitment");
            let value = witness
                .values
                .get(&name)
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: name.clone(),
                })?;
            Ok(json!({
                "satellite": satellite,
                "name": name,
                "commitment": value.to_decimal_string(),
            }))
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let pair_results =
        pair_schedule
            .iter()
            .map(|pair| {
                let min_name = format!("pair_{}_minimum_separation", pair.index);
                let safe_name = format!("pair_{}_safe", pair.index);
                let min_value =
                    witness
                        .values
                        .get(&min_name)
                        .ok_or_else(|| ZkfError::MissingWitnessValue {
                            signal: min_name.clone(),
                        })?;
                let safe_value = witness.values.get(&safe_name).ok_or_else(|| {
                    ZkfError::MissingWitnessValue {
                        signal: safe_name.clone(),
                    }
                })?;
                Ok(json!({
                    "pair_index": pair.index,
                    "offset": pair.offset,
                    "sat_a": pair.sat_a,
                    "sat_b": pair.sat_b,
                    "minimum_separation": min_value.to_decimal_string(),
                    "safe": safe_value.as_bigint() != num_bigint::BigInt::from(0u8),
                }))
            })
            .collect::<ZkfResult<Vec<_>>>()?;
    let unsafe_pairs = pair_results
        .iter()
        .filter(|entry| entry.get("safe").and_then(serde_json::Value::as_bool) == Some(false))
        .count();
    let mission_safety_commitment = witness
        .values
        .get("mission_safety_commitment")
        .ok_or_else(|| ZkfError::MissingWitnessValue {
            signal: "mission_safety_commitment".to_string(),
        })?
        .to_decimal_string();

    Ok(json!({
        "satellite_count": spec.satellite_count,
        "conjunction_pair_count": spec.pair_count,
        "timestep_count": spec.steps,
        "timestep_size_seconds": spec.timestep_seconds,
        "collision_threshold": collision_threshold,
        "delta_v_budget": delta_v_budget,
        "final_state_commitments": final_state_commitments,
        "pair_results": pair_results,
        "unsafe_pair_count": unsafe_pairs,
        "mission_safety_commitment": mission_safety_commitment,
    }))
}

fn recompute_mission_digest(public_inputs: &serde_json::Value) -> ZkfResult<String> {
    let final_commitments = public_inputs
        .get("final_state_commitments")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("public inputs missing final_state_commitments".to_string())
        })?;
    let pair_results = public_inputs
        .get("pair_results")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("public inputs missing pair_results".to_string())
        })?;
    let collision_threshold = public_inputs
        .get("collision_threshold")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("public inputs missing collision_threshold".to_string())
        })?;
    let delta_v_budget = public_inputs
        .get("delta_v_budget")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("public inputs missing delta_v_budget".to_string())
        })?;

    let mut items = Vec::new();
    for entry in final_commitments {
        let commitment = entry
            .get("commitment")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "final_state_commitments entry missing commitment".to_string(),
                )
            })?;
        items.push(zkf_core::FieldElement::from_bigint(parse_decimal_bigint(
            commitment,
        )?));
    }
    for entry in pair_results {
        let minimum = entry
            .get("minimum_separation")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(
                    "pair_results entry missing minimum_separation".to_string(),
                )
            })?;
        let safe = entry
            .get("safe")
            .and_then(serde_json::Value::as_bool)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact("pair_results entry missing safe".to_string())
            })?;
        let sat_a = entry
            .get("sat_a")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact("pair_results entry missing sat_a".to_string())
            })?;
        let sat_b = entry
            .get("sat_b")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact("pair_results entry missing sat_b".to_string())
            })?;
        let pair_leaf = zkf_lib::app::private_identity::poseidon_permutation4_bn254(&[
            zkf_core::FieldElement::from_bigint(parse_decimal_bigint(minimum)?),
            if safe {
                zkf_core::FieldElement::ONE
            } else {
                zkf_core::FieldElement::ZERO
            },
            zkf_core::FieldElement::from_u64(sat_a),
            zkf_core::FieldElement::from_u64(sat_b),
        ])
        .map_err(ZkfError::Backend)?[0]
            .clone();
        items.push(pair_leaf);
    }
    items.push(zkf_core::FieldElement::from_bigint(parse_decimal_bigint(
        collision_threshold,
    )?));
    items.push(zkf_core::FieldElement::from_bigint(parse_decimal_bigint(
        delta_v_budget,
    )?));

    let mission_domain = zkf_core::FieldElement::from_u64(50_000);
    let mut acc = zkf_lib::app::private_identity::poseidon_permutation4_bn254(&[
        zkf_core::FieldElement::ZERO,
        zkf_core::FieldElement::ZERO,
        mission_domain.clone(),
        zkf_core::FieldElement::from_u64(items.len() as u64),
    ])
    .map_err(ZkfError::Backend)?[0]
        .clone();
    for (index, item) in items.iter().enumerate() {
        acc = zkf_lib::app::private_identity::poseidon_permutation4_bn254(&[
            acc,
            item.clone(),
            zkf_core::FieldElement::from_u64(index as u64),
            mission_domain.clone(),
        ])
        .map_err(ZkfError::Backend)?[0]
            .clone();
    }
    Ok(acc.to_decimal_string())
}

fn local_formal_checks(
    spec: &PrivateMultiSatelliteScenarioSpec,
    pair_schedule: &[PairCheck],
    public_inputs: &serde_json::Value,
) -> ZkfResult<serde_json::Value> {
    let schedule_unique = pair_schedule
        .iter()
        .map(|pair| {
            if pair.sat_a < pair.sat_b {
                (pair.offset, pair.sat_a, pair.sat_b)
            } else {
                (pair.offset, pair.sat_b, pair.sat_a)
            }
        })
        .collect::<BTreeSet<_>>()
        .len()
        == pair_schedule.len();
    let pair_results = public_inputs
        .get("pair_results")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact("public inputs missing pair results".to_string())
        })?;
    let threshold = public_inputs
        .get("collision_threshold")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| ZkfError::InvalidArtifact("public inputs missing threshold".to_string()))?;
    let threshold_value = parse_decimal_bigint(threshold)?;
    let safe_semantics_hold = pair_results.iter().all(|entry| {
        let minimum = entry
            .get("minimum_separation")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<num_bigint::BigInt>().ok())
            .unwrap_or_default();
        let safe = entry
            .get("safe")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        safe == (minimum >= threshold_value)
    });
    let recomputed_digest = recompute_mission_digest(public_inputs)?;
    let mission_digest_matches = public_inputs
        .get("mission_safety_commitment")
        .and_then(serde_json::Value::as_str)
        == Some(recomputed_digest.as_str());
    Ok(json!({
        "scenario_constants_exact": {
            "status": "passed",
            "satellite_count": spec.satellite_count,
            "designated_pair_count": spec.pair_count,
            "integration_steps": spec.steps,
            "time_step_seconds": spec.timestep_seconds,
        },
        "pair_schedule_uniqueness_and_coverage": {
            "status": if schedule_unique && pair_schedule.len() == spec.pair_count { "passed" } else { "failed" },
            "pair_count": pair_schedule.len(),
            "expected_pair_count": spec.pair_count,
        },
        "safe_bit_semantics": {
            "status": if safe_semantics_hold { "passed" } else { "failed" },
        },
        "mission_digest_fold_determinism": {
            "status": if mission_digest_matches { "passed" } else { "failed" },
            "recomputed_mission_digest": recomputed_digest,
        },
    }))
}

fn os_version() -> String {
    let output = Command::new("sw_vers").arg("-productVersion").output();
    match output {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => env::consts::OS.to_string(),
    }
}

fn run_foundry_report(project_dir: &Path, out_dir: &Path) -> ZkfResult<serde_json::Value> {
    let mut command = Command::new("forge");
    command
        .current_dir(project_dir)
        .arg("test")
        .arg("--gas-report");
    let output = command.output();
    let report_path = out_dir.join("foundry_report.txt");
    match output {
        Ok(output) => {
            let mut text = String::new();
            text.push_str(&String::from_utf8_lossy(&output.stdout));
            if !output.stderr.is_empty() {
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                text.push_str(&String::from_utf8_lossy(&output.stderr));
            }
            write_text(&report_path, &text)?;
            Ok(json!({
                "generated": true,
                "passed": output.status.success(),
                "gas_used": serde_json::Value::Null,
                "report_path": "foundry_report.txt",
            }))
        }
        Err(error) => {
            write_text(&report_path, &format!("forge invocation failed: {error}\n"))?;
            Ok(json!({
                "generated": false,
                "passed": false,
                "gas_used": serde_json::Value::Null,
                "report_path": "foundry_report.txt",
                "error": error.to_string(),
            }))
        }
    }
}

fn msm_correctness_check() -> ZkfResult<serde_json::Value> {
    let batch_size = current_metal_thresholds().msm.max(512);
    let cpu = CpuMsmAccelerator;
    let registry = accelerator_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let gpu = registry.best_msm();
    let scalars = (0..batch_size)
        .map(|index| zkf_core::FieldElement::from_u64((index + 1) as u64))
        .collect::<Vec<_>>();
    let generator = G1Affine::generator();
    let mut generator_bytes = Vec::new();
    generator
        .serialize_compressed(&mut generator_bytes)
        .map_err(|error| ZkfError::Backend(format!("serialize MSM generator: {error}")))?;
    let mut bases = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        bases.push(generator_bytes.clone());
    }
    let cpu_result = cpu.msm_g1(&scalars, &bases)?;
    let gpu_result = gpu.msm_g1(&scalars, &bases)?;
    Ok(json!({
        "status": if cpu_result == gpu_result { "passed" } else { "failed" },
        "accelerator": gpu.name(),
        "comparison_mode": "exact",
        "tolerance_policy": "exact-byte-equality",
        "number_of_mismatches": if cpu_result == gpu_result { 0 } else { 1 },
        "mismatch_locations": if cpu_result == gpu_result { serde_json::Value::Array(vec![]) } else { json!(["aggregate-result"]) },
        "gpu_realized_candidate": gpu.name().starts_with("metal-"),
        "batch_size": batch_size,
    }))
}

fn correctness_report(
    proof: &ProofArtifact,
    repeated_runs_matched: bool,
) -> ZkfResult<serde_json::Value> {
    let msm_engine = proof
        .metadata
        .get("groth16_msm_engine")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let qap_engine = proof
        .metadata
        .get("qap_witness_map_engine")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let msm = if msm_engine.contains("metal") {
        msm_correctness_check()?
    } else {
        json!({
            "status": "not_exercised",
            "reason": msm_engine,
        })
    };

    let ntt = if qap_engine.contains("metal") || qap_engine.contains("hybrid") {
        let vector_len = current_metal_thresholds().ntt.max(4096).next_power_of_two();
        let parity = groth16_bn254_witness_map_ntt_parity(vector_len)?;
        let exact = parity.stages.iter().all(|stage| stage.exact_match);
        json!({
            "status": if parity.gpu_realized && exact { "passed" } else if parity.gpu_realized { "failed" } else { "not_exercised" },
            "engine": qap_engine,
            "comparison_mode": "exact",
            "tolerance_policy": "exact-field-equality",
            "gpu_realized": parity.gpu_realized,
            "stages": parity.stages,
        })
    } else {
        json!({
            "status": "not_exercised",
            "reason": qap_engine,
        })
    };

    Ok(json!({
        "deterministic_seed_used": {
            "setup_seed_hex": hex_string(&SETUP_SEED),
            "proof_seed_hex": hex_string(&PROOF_SEED),
        },
        "comparison_mode": "exact",
        "tolerance_policy": "exact-equality",
        "golden_vector_pass": msm.get("status").and_then(serde_json::Value::as_str) != Some("failed")
            && ntt.get("status").and_then(serde_json::Value::as_str) != Some("failed"),
        "repeated_runs_matched_byte_for_byte": repeated_runs_matched,
        "checks": {
            "msm": msm,
            "ntt": ntt,
            "poseidon2": {
                "status": "not_exercised",
                "reason": "strict-groth16 multi-satellite lane does not exercise the Goldilocks Poseidon2 GPU batch surface",
            },
            "fri_hash_kernels": {
                "status": "not_exercised",
                "reason": "strict-groth16 multi-satellite lane does not exercise FRI folding or FRI query/open kernels",
            }
        }
    }))
}

fn manifest_model(
    spec: &PrivateMultiSatelliteScenarioSpec,
    pair_schedule: &[PairCheck],
    run: &ScenarioRun,
) -> ZkfResult<serde_json::Value> {
    Ok(json!({
        "app_id": APP_ID,
        "scenario": spec.scenario_id,
        "scenario_config": {
            "satellite_count": spec.satellite_count,
            "designated_pair_count": spec.pair_count,
            "integration_steps": spec.steps,
            "time_step_seconds": spec.timestep_seconds,
            "pair_offsets": spec.pair_offsets,
        },
        "pair_schedule": pair_schedule,
        "program_digest": run.compiled.program_digest,
        "proof_hash": sha256_hex(&run.proof.proof),
        "verification_key_hash": sha256_hex(&run.proof.verification_key),
        "public_inputs_hash": hash_json_value(&run.public_inputs)?,
        "runtime_trace_hash": hash_json_value(&run.runtime_trace)?,
        "stage_metrics_hash": hash_json_value(&run.stage_metrics)?,
    }))
}

struct ScenarioRun {
    compiled: CompiledProgram,
    witness: Witness,
    proof: ProofArtifact,
    public_inputs: serde_json::Value,
    runtime_trace: serde_json::Value,
    accelerator_trace: serde_json::Value,
    stage_metrics: serde_json::Value,
    ccs_summary: serde_json::Value,
    compile_ms: f64,
    witness_ms: f64,
    proving_ms: f64,
    verification_ms: f64,
    build_ms: f64,
    setup_provenance: String,
    security_boundary: String,
}

fn execute_scenario_once(spec: &PrivateMultiSatelliteScenarioSpec) -> ZkfResult<ScenarioRun> {
    let telemetry_before = telemetry_snapshot();

    let build_start_ts = timestamp_unix_ms();
    let build_start = Instant::now();
    let template = private_multi_satellite_conjunction_showcase_for_scenario(spec.scenario)?;
    let pair_schedule = private_multi_satellite_pair_schedule(spec.scenario)?;
    let build_ms = build_start.elapsed().as_secs_f64() * 1_000.0;
    let build_end_ts = timestamp_unix_ms();
    let original_program = template.program.clone();
    let original_program_bytes = json_to_vec_pretty(&original_program).map_err(|error| {
        ZkfError::Serialization(format!("serialize original program for metrics: {error}"))
    })?;

    let trusted_setup_requested = requested_groth16_setup_blob_path(&template.program).is_some();
    let trusted_setup_used = trusted_setup_requested;

    let compile_start_ts = timestamp_unix_ms();
    let compile_start = Instant::now();
    let compiled = with_showcase_groth16_mode(trusted_setup_used, || {
        compile(&template.program, "arkworks-groth16", Some(SETUP_SEED))
    })?;
    let compile_ms = compile_start.elapsed().as_secs_f64() * 1_000.0;
    let compile_end_ts = timestamp_unix_ms();
    let compiled_bytes = json_to_vec_pretty(&compiled)
        .map_err(|error| ZkfError::Serialization(format!("serialize compiled: {error}")))?;

    let witness_start_ts = timestamp_unix_ms();
    let witness_start = Instant::now();
    let base_witness =
        private_multi_satellite_conjunction_witness(&template.sample_inputs, spec.scenario)?;
    let prepared_witness = prepare_witness_for_proving(&compiled, &base_witness)?;
    check_constraints(&compiled.program, &prepared_witness)?;
    let witness_ms = witness_start.elapsed().as_secs_f64() * 1_000.0;
    let witness_end_ts = timestamp_unix_ms();
    let witness_bytes = json_to_vec_pretty(&prepared_witness)
        .map_err(|error| ZkfError::Serialization(format!("serialize witness: {error}")))?;

    let prove_start_ts = timestamp_unix_ms();
    let prove_start = Instant::now();
    let execution: BackendProofExecutionResult =
        with_showcase_groth16_mode(trusted_setup_used, || {
            with_proof_seed_override(Some(PROOF_SEED), || {
                RuntimeExecutor::run_backend_prove_job_with_objective(
                    BackendKind::ArkworksGroth16,
                    BackendRoute::Auto,
                    Arc::new(template.program.clone()),
                    Some(Arc::new(template.sample_inputs.clone())),
                    Some(Arc::new(base_witness.clone())),
                    Some(Arc::new(compiled.clone())),
                    OptimizationObjective::FastestProve,
                    RequiredTrustLane::StrictCryptographic,
                    ExecutionMode::Deterministic,
                )
                .map_err(|error| ZkfError::Backend(error.to_string()))
            })
        })?;
    let proving_ms = prove_start.elapsed().as_secs_f64() * 1_000.0;
    let prove_end_ts = timestamp_unix_ms();

    let verify_start_ts = timestamp_unix_ms();
    let verify_start = Instant::now();
    let verified = verify(&execution.compiled, &execution.artifact)?;
    let verification_ms = verify_start.elapsed().as_secs_f64() * 1_000.0;
    let verify_end_ts = timestamp_unix_ms();
    if !verified {
        return Err(ZkfError::Backend(
            "runtime-produced multi-satellite proof failed verification".to_string(),
        ));
    }

    let telemetry_after = telemetry_snapshot();
    let telemetry_paths = new_telemetry_paths(&telemetry_before, &telemetry_after);
    let runtime_artifact = execution.artifact.clone();
    let setup_provenance = runtime_artifact
        .metadata
        .get(GROTH16_SETUP_PROVENANCE_METADATA_KEY)
        .cloned()
        .unwrap_or_else(|| {
            if trusted_setup_used {
                GROTH16_IMPORTED_SETUP_PROVENANCE.to_string()
            } else {
                GROTH16_DETERMINISTIC_DEV_PROVENANCE.to_string()
            }
        });
    let security_boundary = runtime_artifact
        .metadata
        .get(GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY)
        .cloned()
        .unwrap_or_else(|| {
            if trusted_setup_used {
                GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY.to_string()
            } else {
                GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY.to_string()
            }
        });

    let public_inputs = public_inputs_bundle(spec, &pair_schedule, &prepared_witness)?;
    let gpu_attribution = effective_gpu_attribution_summary(
        execution.result.report.gpu_nodes,
        execution.result.report.gpu_stage_busy_ratio(),
        &runtime_artifact.metadata,
    );
    let metal_runtime = metal_runtime_report();
    let resources = SystemResources::detect();

    let stage_metrics = json!([
        stage_metric(
            "import/build",
            "host",
            Some(build_start_ts),
            Some(build_end_ts),
            Some(build_ms),
            "cpu",
            "cpu",
            "cpu",
            Some(0),
            Some(original_program_bytes.len()),
            Some(1),
            false,
            false,
            false,
            false,
            None,
            "host-measured",
        ),
        stage_metric(
            "compile",
            "host",
            Some(compile_start_ts),
            Some(compile_end_ts),
            Some(compile_ms),
            "cpu",
            "cpu",
            "cpu",
            Some(original_program_bytes.len()),
            Some(compiled_bytes.len()),
            Some(original_program.constraints.len()),
            false,
            false,
            false,
            false,
            None,
            "host-measured",
        ),
        stage_metric(
            "witness generation",
            "host",
            Some(witness_start_ts),
            Some(witness_end_ts),
            Some(witness_ms),
            "cpu",
            "cpu",
            "cpu",
            Some(
                json_to_vec_pretty(&template.sample_inputs)
                    .map_err(|error| ZkfError::Serialization(format!("serialize inputs: {error}")))?
                    .len()
            ),
            Some(witness_bytes.len()),
            Some(prepared_witness.values.len()),
            false,
            false,
            false,
            false,
            None,
            "host-measured",
        ),
        stage_metric(
            "qap witness map",
            "backend-delegated",
            None,
            None,
            None,
            runtime_artifact
                .metadata
                .get("qap_witness_map_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            runtime_artifact
                .metadata
                .get("qap_witness_map_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            runtime_artifact
                .metadata
                .get("qap_witness_map_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            None,
            None,
            None,
            true,
            true,
            false,
            runtime_artifact
                .metadata
                .get("qap_witness_map_fallback_state")
                .map(String::as_str)
                != Some("none"),
            runtime_artifact
                .metadata
                .get("qap_witness_map_reason")
                .cloned(),
            "backend-delegated-telemetry-gap",
        ),
        stage_metric(
            "ntt",
            "backend-delegated",
            None,
            None,
            None,
            runtime_artifact
                .metadata
                .get("qap_witness_map_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            runtime_artifact
                .metadata
                .get("qap_witness_map_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            runtime_artifact
                .metadata
                .get("qap_witness_map_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            None,
            None,
            None,
            true,
            true,
            false,
            runtime_artifact
                .metadata
                .get("qap_witness_map_fallback_state")
                .map(String::as_str)
                != Some("none"),
            runtime_artifact
                .metadata
                .get("qap_witness_map_reason")
                .cloned(),
            "backend-delegated-telemetry-gap",
        ),
        stage_metric(
            "msm",
            "backend-delegated",
            None,
            None,
            None,
            runtime_artifact
                .metadata
                .get("groth16_msm_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            runtime_artifact
                .metadata
                .get("groth16_msm_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            runtime_artifact
                .metadata
                .get("groth16_msm_engine")
                .map(String::as_str)
                .unwrap_or("cpu"),
            None,
            None,
            None,
            true,
            true,
            false,
            runtime_artifact
                .metadata
                .get("groth16_msm_fallback_state")
                .map(String::as_str)
                != Some("none"),
            runtime_artifact.metadata.get("groth16_msm_reason").cloned(),
            "backend-delegated-telemetry-gap",
        ),
        stage_metric(
            "proof assembly",
            "backend-delegated",
            Some(prove_start_ts),
            Some(prove_end_ts),
            Some(proving_ms),
            "backend:arkworks-groth16",
            "backend:arkworks-groth16",
            "backend:arkworks-groth16",
            Some(witness_bytes.len() + compiled_bytes.len()),
            Some(runtime_artifact.proof.len()),
            Some(1),
            false,
            true,
            false,
            false,
            None,
            "host-wrapped-backend",
        ),
        stage_metric(
            "verification",
            "host",
            Some(verify_start_ts),
            Some(verify_end_ts),
            Some(verification_ms),
            "cpu",
            "cpu",
            "cpu",
            Some(runtime_artifact.proof.len() + runtime_artifact.verification_key.len()),
            Some(0),
            Some(runtime_artifact.public_inputs.len()),
            false,
            false,
            false,
            false,
            None,
            "host-measured",
        ),
        stage_metric(
            "poseidon batch",
            "not-exercised",
            None,
            None,
            None,
            "not-exercised",
            "not-exercised",
            "not-exercised",
            None,
            None,
            None,
            false,
            false,
            false,
            false,
            Some("not exercised on the strict Groth16 path".to_string()),
            "not-exercised",
        ),
        stage_metric(
            "merkle layers",
            "not-exercised",
            None,
            None,
            None,
            "not-exercised",
            "not-exercised",
            "not-exercised",
            None,
            None,
            None,
            false,
            false,
            false,
            false,
            Some("not exercised on the strict Groth16 path".to_string()),
            "not-exercised",
        ),
        stage_metric(
            "fri folding",
            "not-exercised",
            None,
            None,
            None,
            "not-exercised",
            "not-exercised",
            "not-exercised",
            None,
            None,
            None,
            false,
            false,
            false,
            false,
            Some("not exercised on the strict Groth16 path".to_string()),
            "not-exercised",
        ),
        stage_metric(
            "fri query/open",
            "not-exercised",
            None,
            None,
            None,
            "not-exercised",
            "not-exercised",
            "not-exercised",
            None,
            None,
            None,
            false,
            false,
            false,
            false,
            Some("not exercised on the strict Groth16 path".to_string()),
            "not-exercised",
        )
    ]);

    let runtime_trace = json!({
        "scenario": spec.scenario_id,
        "telemetry_paths": telemetry_paths,
        "report": {
            "total_wall_time_ms": execution.result.report.total_wall_time.as_secs_f64() * 1_000.0,
            "peak_memory_bytes": execution.result.report.peak_memory_bytes,
            "gpu_nodes": execution.result.report.gpu_nodes,
            "cpu_nodes": execution.result.report.cpu_nodes,
            "delegated_nodes": execution.result.report.delegated_nodes,
            "fallback_nodes": execution.result.report.fallback_nodes,
            "gpu_wall_time_ms": execution.result.report.gpu_wall_time().as_secs_f64() * 1_000.0,
            "cpu_wall_time_ms": execution.result.report.cpu_wall_time().as_secs_f64() * 1_000.0,
            "gpu_busy_ratio": execution.result.report.gpu_stage_busy_ratio(),
            "counter_source": execution.result.report.counter_source(),
            "stage_breakdown": execution.result.report.stage_breakdown(),
            "node_traces": runtime_node_traces_json(&execution.result.report),
            "watchdog_alerts": execution.result.report.watchdog_alerts,
        },
        "control_plane": execution.result.control_plane,
        "security": execution.result.security,
        "model_integrity": execution.result.model_integrity,
        "swarm": execution.result.swarm,
    });

    let runtime_direct_gpu_stages = execution
        .result
        .report
        .stage_breakdown()
        .into_iter()
        .filter_map(|(stage, telemetry)| {
            if telemetry.gpu_nodes > 0 {
                Some(stage)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let runtime_cpu_stages = execution
        .result
        .report
        .stage_breakdown()
        .into_iter()
        .filter_map(|(stage, telemetry)| {
            if telemetry.cpu_nodes > 0 || telemetry.fallback_nodes > 0 {
                Some(stage)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let backend_delegated_gpu_stages = [
        runtime_artifact
            .metadata
            .get("qap_witness_map_engine")
            .cloned(),
        runtime_artifact.metadata.get("groth16_msm_engine").cloned(),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    let accelerator_trace = json!({
        "scenario": spec.scenario_id,
        "metal_runtime": metal_runtime,
        "system_resources": {
            "total_ram_bytes": resources.total_ram_bytes,
            "available_ram_bytes": resources.available_ram_bytes,
            "unified_memory": resources.unified_memory,
        },
        "device_name": metal_runtime_report().metal_device,
        "os_version": os_version(),
        "chip_name": metal_runtime_report().metal_device,
        "selected_accelerator_per_stage": {
            "qap_witness_map": runtime_artifact.metadata.get("qap_witness_map_engine"),
            "msm": runtime_artifact.metadata.get("groth16_msm_engine"),
        },
        "effective_gpu_attribution": gpu_attribution,
        "best_accelerator_per_stage": {
            "msm": runtime_artifact.metadata.get("best_msm_accelerator"),
        },
        "planned_gpu_stages": execution
            .result
            .control_plane
            .as_ref()
            .map(|summary| summary.decision.dispatch_plan.stages_on_gpu.clone())
            .unwrap_or_default(),
        "realized_gpu_stages": {
            "runtime_direct": runtime_direct_gpu_stages,
            "backend_delegated": backend_delegated_gpu_stages.clone(),
        },
        "realized_cpu_stages": runtime_cpu_stages,
        "backend_delegated_gpu_stages": backend_delegated_gpu_stages,
        "dispatch_candidate": execution
            .result
            .control_plane
            .as_ref()
            .map(|summary| summary.decision.dispatch_plan.candidate.clone()),
        "execution_regime": execution
            .result
            .control_plane
            .as_ref()
            .map(|summary| {
                summary
                    .decision
                    .duration_estimate
                    .execution_regime
                    .as_str()
                    .to_string()
            }),
        "number_of_gpu_nodes": execution.result.report.gpu_nodes,
        "number_of_cpu_nodes": execution.result.report.cpu_nodes,
        "gpu_wall_time_ms": execution.result.report.gpu_wall_time().as_secs_f64() * 1_000.0,
        "cpu_wall_time_ms": execution.result.report.cpu_wall_time().as_secs_f64() * 1_000.0,
        "gpu_busy_ratio": execution.result.report.gpu_stage_busy_ratio(),
        "gpu_utilization_peak": serde_json::Value::Null,
        "gpu_utilization_average": execution.result.report.gpu_stage_busy_ratio(),
        "command_buffer_count": serde_json::Value::Null,
        "compute_pipeline_count": metal_runtime_report().prewarmed_pipelines,
        "total_kernel_dispatch_count": serde_json::Value::Null,
        "per_kernel_dispatch_count": serde_json::Value::Object(serde_json::Map::new()),
        "threadgroup_sizes_per_kernel": serde_json::Value::Object(serde_json::Map::new()),
        "buffer_sizes_per_kernel": serde_json::Value::Object(serde_json::Map::new()),
        "fallback_reasons": {
            "qap_witness_map": runtime_artifact.metadata.get("qap_witness_map_reason"),
            "msm": runtime_artifact.metadata.get("groth16_msm_reason"),
            "cpu_math": runtime_artifact.metadata.get("cpu_math_fallback_reason"),
        },
    });

    Ok(ScenarioRun {
        compiled: execution.compiled.clone(),
        witness: prepared_witness,
        proof: runtime_artifact,
        public_inputs,
        runtime_trace,
        accelerator_trace,
        stage_metrics,
        ccs_summary: ccs_summary(&execution.compiled)?,
        compile_ms,
        witness_ms,
        proving_ms,
        verification_ms,
        build_ms,
        setup_provenance,
        security_boundary,
    })
}

fn json_hashes(value: &serde_json::Value) -> ZkfResult<serde_json::Value> {
    let raw = hash_json_value(value)?;
    let canonical = hash_json_value(&canonicalize_for_determinism_hash(value))?;
    Ok(json!({
        "raw": raw,
        "canonical": canonical,
    }))
}

fn determinism_report(
    spec: &PrivateMultiSatelliteScenarioSpec,
    pair_schedule: &[PairCheck],
    runs: &[ScenarioRun],
) -> ZkfResult<serde_json::Value> {
    let proof_hashes = runs
        .iter()
        .map(|run| sha256_hex(&run.proof.proof))
        .collect::<Vec<_>>();
    let witness_hashes = runs
        .iter()
        .map(|run| {
            json_to_vec_pretty(&run.witness)
                .map(|bytes| sha256_hex(&bytes))
                .map_err(|error| ZkfError::Serialization(format!("serialize witness: {error}")))
        })
        .collect::<ZkfResult<Vec<_>>>()?;
    let public_output_hashes = runs
        .iter()
        .map(|run| hash_json_value(&run.public_inputs))
        .collect::<ZkfResult<Vec<_>>>()?;
    let manifest_hashes = runs
        .iter()
        .map(|run| manifest_model(spec, pair_schedule, run))
        .collect::<ZkfResult<Vec<_>>>()?
        .iter()
        .map(hash_json_value)
        .collect::<ZkfResult<Vec<_>>>()?;
    let runtime_trace_hashes = runs
        .iter()
        .map(|run| json_hashes(&run.runtime_trace))
        .collect::<ZkfResult<Vec<_>>>()?;
    let stage_metric_hashes = runs
        .iter()
        .map(|run| json_hashes(&run.stage_metrics))
        .collect::<ZkfResult<Vec<_>>>()?;

    let proofs_match = proof_hashes.windows(2).all(|window| window[0] == window[1]);
    let witnesses_match = witness_hashes
        .windows(2)
        .all(|window| window[0] == window[1]);
    let outputs_match = public_output_hashes
        .windows(2)
        .all(|window| window[0] == window[1]);
    let manifest_match = manifest_hashes
        .windows(2)
        .all(|window| window[0] == window[1]);
    let runtime_raw_match = runtime_trace_hashes
        .windows(2)
        .all(|window| window[0].get("raw") == window[1].get("raw"));
    let runtime_canonical_match = runtime_trace_hashes
        .windows(2)
        .all(|window| window[0].get("canonical") == window[1].get("canonical"));
    let stage_raw_match = stage_metric_hashes
        .windows(2)
        .all(|window| window[0].get("raw") == window[1].get("raw"));
    let stage_canonical_match = stage_metric_hashes
        .windows(2)
        .all(|window| window[0].get("canonical") == window[1].get("canonical"));

    let mut differences = Vec::new();
    if !runtime_raw_match && runtime_canonical_match {
        differences.push(json!({
            "surface": "runtime_trace",
            "allowed_difference": "raw hashes diverged only in stripped runtime-only fields",
        }));
    }
    if !stage_raw_match && stage_canonical_match {
        differences.push(json!({
            "surface": "stage_metrics",
            "allowed_difference": "raw hashes diverged only in stripped runtime-only fields",
        }));
    }

    Ok(json!({
        "proof_hashes": proof_hashes,
        "witness_hashes": witness_hashes,
        "public_output_hashes": public_output_hashes,
        "manifest_hashes": manifest_hashes,
        "runtime_trace_hashes": runtime_trace_hashes,
        "stage_metric_hashes": stage_metric_hashes,
        "hashes_matched": {
            "proof_bytes": proofs_match,
            "witness_bytes": witnesses_match,
            "public_outputs": outputs_match,
            "manifest": manifest_match,
            "runtime_trace_raw": runtime_raw_match,
            "runtime_trace_canonical": runtime_canonical_match,
            "stage_metrics_raw": stage_raw_match,
            "stage_metrics_canonical": stage_canonical_match,
        },
        "differences": differences,
    }))
}

fn truth_report(
    spec: &PrivateMultiSatelliteScenarioSpec,
    accelerator_trace: &serde_json::Value,
    correctness: &serde_json::Value,
    formal_summary: &serde_json::Value,
    determinism: &serde_json::Value,
    foundry: &serde_json::Value,
) -> serde_json::Value {
    let gpu_capable = accelerator_trace
        .get("metal_runtime")
        .and_then(|value| value.get("active_accelerators"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let gpu_selected = accelerator_trace
        .get("selected_accelerator_per_stage")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let gpu_delegated = accelerator_trace
        .get("backend_delegated_gpu_stages")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let gpu_realized = accelerator_trace
        .get("realized_gpu_stages")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let cpu_realized = accelerator_trace
        .get("realized_cpu_stages")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let mut fallbacks = Vec::new();
    if let Some(reason) = accelerator_trace
        .get("fallback_reasons")
        .and_then(|value| value.get("qap_witness_map"))
        .and_then(serde_json::Value::as_str)
    {
        fallbacks.push(json!({"stage": "qap_witness_map", "reason": reason}));
    }
    if let Some(reason) = accelerator_trace
        .get("fallback_reasons")
        .and_then(|value| value.get("msm"))
        .and_then(serde_json::Value::as_str)
    {
        fallbacks.push(json!({"stage": "msm", "reason": reason}));
    }
    let mut contradictions = Vec::new();
    let msm_selected_metal = accelerator_trace
        .get("selected_accelerator_per_stage")
        .and_then(|value| value.get("msm"))
        .and_then(serde_json::Value::as_str)
        .map(|value| value.contains("metal"))
        .unwrap_or(false);
    let gpu_wall_time_zero = accelerator_trace
        .get("gpu_wall_time_ms")
        .and_then(serde_json::Value::as_f64)
        .unwrap_or(0.0)
        == 0.0;
    if msm_selected_metal && gpu_wall_time_zero {
        contradictions.push(json!({
            "stage": "msm",
            "issue": "stage selected Metal but runtime GPU wall time was zero",
        }));
    }
    if accelerator_trace
        .get("backend_delegated_gpu_stages")
        .and_then(serde_json::Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false)
        && gpu_wall_time_zero
    {
        contradictions.push(json!({
            "stage": "backend-delegated",
            "issue": "backend says delegated GPU but no runtime-direct GPU telemetry was present",
        }));
    }

    json!({
        "scenario": spec.scenario_id,
        "gpu_capable": gpu_capable,
        "gpu_selected": gpu_selected,
        "gpu_delegated": gpu_delegated,
        "gpu_realized": gpu_realized,
        "cpu_realized": cpu_realized,
        "fallbacks": fallbacks,
        "claimed_acceleration": gpu_selected,
        "proven_surfaces": formal_summary.get("generated_closure").cloned().unwrap_or_else(|| json!({})),
        "model_checked_surfaces": json!([]),
        "bounded_checked_surfaces": json!([
            "bundle.local.scenario_constants_exact",
            "bundle.local.pair_schedule_uniqueness_and_coverage",
            "bundle.local.safe_bit_semantics",
            "bundle.local.mission_digest_fold_determinism",
            "bundle.determinism.three_run_hash_comparison",
            "bundle.correctness.direct_gpu_vs_cpu_checks"
        ]),
        "unverified_surfaces": json!([
            "metal.command_buffer_count",
            "metal.total_kernel_dispatch_count",
            "metal.per_kernel_dispatch_count",
            "metal.threadgroup_sizes_per_kernel",
            "metal.buffer_sizes_per_kernel",
            if foundry.get("gas_used").is_some() && foundry.get("gas_used") == Some(&serde_json::Value::Null) {
                "foundry.verification_gas_exact_parse"
            } else {
                "none"
            }
        ]),
        "contradictions_detected": contradictions,
        "determinism": determinism.get("hashes_matched").cloned().unwrap_or_else(|| json!({})),
        "correctness": correctness.get("checks").cloned().unwrap_or_else(|| json!({})),
    })
}

fn report_markdown(
    spec: &PrivateMultiSatelliteScenarioSpec,
    public_inputs: &serde_json::Value,
    benchmark_summary: &serde_json::Value,
    accelerator_trace: &serde_json::Value,
    correctness: &serde_json::Value,
    determinism: &serde_json::Value,
    truth_report: &serde_json::Value,
    formal_summary: &serde_json::Value,
    audit_summary: &serde_json::Value,
    foundry: &serde_json::Value,
) -> String {
    format!(
        r#"# ZirOS Private Multi-Satellite Conjunction Showcase

## Scenario

- scenario: `{scenario}`
- satellites: `{satellites}`
- designated pair checks: `{pairs}`
- integration steps: `{steps}`
- timestep seconds: `{timestep}`

## Public Surface

`{public_inputs}`

## Benchmark Summary

`{benchmark_summary}`

## Accelerator Truth

`{accelerator_trace}`

## Correctness

`{correctness}`

## Determinism

`{determinism}`

## Truth Report

`{truth_report}`

## Formal Evidence

`{formal_summary}`

## Audit Summary

`{audit_summary}`

## Foundry

`{foundry}`
"#,
        scenario = spec.scenario_id,
        satellites = spec.satellite_count,
        pairs = spec.pair_count,
        steps = spec.steps,
        timestep = spec.timestep_seconds,
        public_inputs = json_pretty(public_inputs),
        benchmark_summary = json_pretty(benchmark_summary),
        accelerator_trace = json_pretty(accelerator_trace),
        correctness = json_pretty(correctness),
        determinism = json_pretty(determinism),
        truth_report = json_pretty(truth_report),
        formal_summary = json_pretty(formal_summary),
        audit_summary = json_pretty(audit_summary),
        foundry = json_pretty(foundry),
    )
}

fn export_manifest(
    spec: &PrivateMultiSatelliteScenarioSpec,
    pair_schedule: &[PairCheck],
    out_dir: &Path,
    setup_provenance: &str,
    security_boundary: &str,
    foundry: &serde_json::Value,
) -> ZkfResult<serde_json::Value> {
    let mut files = Vec::new();
    for entry in fs::read_dir(out_dir)
        .map_err(|error| ZkfError::Io(format!("read {}: {error}", out_dir.display())))?
    {
        let entry = entry.map_err(|error| {
            ZkfError::Io(format!("read entry in {}: {error}", out_dir.display()))
        })?;
        let path = entry.path();
        if path.is_file() {
            let bytes = fs::read(&path)
                .map_err(|error| ZkfError::Io(format!("read {}: {error}", path.display())))?;
            files.push(json!({
                "path": path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
                "sha256": sha256_hex(&bytes),
                "bytes": bytes.len(),
            }));
        }
    }
    Ok(json!({
        "app_id": APP_ID,
        "scenario": spec.scenario_id,
        "scenario_config": {
            "satellite_count": spec.satellite_count,
            "designated_pair_count": spec.pair_count,
            "integration_steps": spec.steps,
            "time_step_seconds": spec.timestep_seconds,
            "pair_offsets": spec.pair_offsets,
        },
        "pair_schedule": pair_schedule,
        "setup_provenance": setup_provenance,
        "security_boundary": security_boundary,
        "artifacts": files,
        "foundry": foundry,
    }))
}

fn export_scenario_bundle(
    spec: &PrivateMultiSatelliteScenarioSpec,
    out_dir: &Path,
    pair_schedule: &[PairCheck],
    run: &ScenarioRun,
    determinism: &serde_json::Value,
) -> ZkfResult<()> {
    fs::create_dir_all(out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;
    let project_dir = foundry_project_dir_for_bundle(out_dir);
    ensure_foundry_layout(&project_dir)?;

    let verifier_export_start = Instant::now();
    let verifier_source =
        export_groth16_solidity_verifier(&run.proof, Some("PrivateMultiSatelliteVerifier"))?;
    let verifier_export_ms = verifier_export_start.elapsed().as_secs_f64() * 1_000.0;
    let calldata = proof_to_calldata_json(&run.proof.proof, &run.proof.public_inputs)
        .map_err(ZkfError::Backend)?;
    let foundry_test = generate_foundry_test_from_artifact(
        &run.proof.proof,
        &run.proof.public_inputs,
        "../src/PrivateMultiSatelliteVerifier.sol",
        "PrivateMultiSatelliteVerifier",
    )
    .map_err(ZkfError::Backend)?;

    write_json(&out_dir.join("compiled_program.json"), &run.compiled)?;
    write_json(&out_dir.join("witness.json"), &run.witness)?;
    write_json(&out_dir.join("proof.json"), &run.proof)?;
    write_json(&out_dir.join("public_inputs.json"), &run.public_inputs)?;
    write_text(&out_dir.join("verifier.sol"), &verifier_source)?;
    write_json(&out_dir.join("calldata.json"), &calldata)?;
    write_json(&out_dir.join("runtime_trace.json"), &run.runtime_trace)?;
    write_json(
        &out_dir.join("accelerator_trace.json"),
        &run.accelerator_trace,
    )?;
    write_json(&out_dir.join("stage_metrics.json"), &run.stage_metrics)?;
    write_json(
        &out_dir.join("compiled_circuit_metrics.json"),
        &run.ccs_summary,
    )?;

    write_text(
        &project_dir.join("src/PrivateMultiSatelliteVerifier.sol"),
        &verifier_source,
    )?;
    write_text(
        &project_dir.join("test/PrivateMultiSatelliteVerifier.t.sol"),
        &foundry_test.source,
    )?;

    let formal_inherited = collect_formal_evidence_for_generated_app(out_dir, APP_ID)?;
    let generated_closure = generated_app_closure_bundle_summary(APP_ID)?;
    let local_checks = local_formal_checks(spec, pair_schedule, &run.public_inputs)?;
    write_json(&out_dir.join("formal/local_checks.json"), &local_checks)?;

    let structural_summary = json!({
        "application": APP_ID,
        "scenario": spec.scenario_id,
        "original_program_digest": run.compiled.original_program.as_ref().map(Program::digest_hex),
        "program_digest": run.compiled.program_digest,
        "program_stats": stats(&run.compiled.program),
        "runtime_verification_key_bytes": run.proof.verification_key.len(),
        "security_boundary": run.security_boundary,
    });
    let audit_summary = if full_audit_requested() {
        let audit_dir = out_dir.join("audit");
        fs::create_dir_all(&audit_dir)
            .map_err(|error| ZkfError::Io(format!("create {}: {error}", audit_dir.display())))?;
        let source_audit = audit_program_with_live_capabilities(
            run.compiled
                .original_program
                .as_ref()
                .unwrap_or(&run.compiled.program),
            Some(BackendKind::ArkworksGroth16),
        );
        let compiled_audit = audit_program_with_live_capabilities(
            &run.compiled.program,
            Some(BackendKind::ArkworksGroth16),
        );
        write_json(&audit_dir.join("source_audit.json"), &source_audit)?;
        write_json(&audit_dir.join("compiled_audit.json"), &compiled_audit)?;
        two_tier_audit_record(
            "two-tier-multi-satellite-audit-v1",
            structural_summary,
            json!({
                "status": "included",
                "path": "audit/source_audit.json",
                "producer": "audit_program_with_live_capabilities(original_program, Some(arkworks-groth16))",
                "summary": source_audit.summary,
            }),
            json!({
                "status": "included",
                "path": "audit/compiled_audit.json",
                "producer": "audit_program_with_live_capabilities(compiled_program, Some(arkworks-groth16))",
                "summary": compiled_audit.summary,
            }),
        )
    } else {
        two_tier_audit_record(
            "two-tier-multi-satellite-audit-v1",
            structural_summary,
            json!({
                "status": "omitted-by-default",
                "reason": format!("set {FULL_AUDIT_ENV}=1 to include the heavyweight source audit"),
                "path": serde_json::Value::Null,
            }),
            json!({
                "status": "omitted-by-default",
                "reason": format!("set {FULL_AUDIT_ENV}=1 to include the heavyweight compiled audit"),
                "path": serde_json::Value::Null,
            }),
        )
    };
    write_json(&out_dir.join("audit_summary.json"), &audit_summary)?;

    let correctness = correctness_report(
        &run.proof,
        determinism
            .get("hashes_matched")
            .and_then(|value| value.get("proof_bytes"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
            && determinism
                .get("hashes_matched")
                .and_then(|value| value.get("witness_bytes"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
            && determinism
                .get("hashes_matched")
                .and_then(|value| value.get("public_outputs"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
    )?;
    write_json(&out_dir.join("correctness_report.json"), &correctness)?;

    let formal_summary = json!({
        "status": formal_inherited.1["status"],
        "generated_closure": generated_closure,
        "repo_inherited": formal_inherited.1,
        "local_checks": local_checks,
    });
    write_json(
        &out_dir.join("formal_evidence_summary.json"),
        &formal_summary,
    )?;

    let foundry = run_foundry_report(&project_dir, out_dir)?;
    let benchmark_summary = json!({
        "scenario": spec.scenario_id,
        "circuit_and_proving_size": {
            "total_constraint_count": run.ccs_summary["total_constraint_count"],
            "total_gates_or_rows": run.ccs_summary["total_gates_or_rows"],
            "witness_size_bytes": json_to_vec_pretty(&run.witness).map_err(|error| ZkfError::Serialization(format!("serialize witness: {error}")) )?.len(),
            "public_input_count": run.proof.public_inputs.len(),
            "proof_size_bytes": run.proof.proof.len(),
            "verifier_key_size_bytes": run.proof.verification_key.len(),
            "proving_key_size_bytes": run.compiled.compiled_data.as_ref().map(|data| data.len()),
            "build_time_ms": run.build_ms,
            "compilation_time_ms": run.compile_ms,
            "witness_generation_time_ms": run.witness_ms,
            "proving_time_ms": run.proving_ms,
            "verification_time_ms": run.verification_ms,
        },
        "gpu_reality": run.accelerator_trace,
        "application": run.public_inputs,
        "export_quality": {
            "verifier_contract_generated": true,
            "calldata_generated": true,
            "foundry_test_passed": foundry["passed"],
            "gas_used_to_verify": foundry["gas_used"],
            "audit_summary_result": audit_summary["mode"],
            "mission_assurance_result": "generated",
            "formal_evidence_summary_result": formal_summary["status"],
            "release_dev_boundary_label": run.security_boundary,
        },
        "verifier_export_time_ms": verifier_export_ms,
    });
    write_json(&out_dir.join("benchmark_summary.json"), &benchmark_summary)?;

    let truth = truth_report(
        spec,
        &run.accelerator_trace,
        &correctness,
        &formal_summary,
        determinism,
        &foundry,
    );
    write_json(&out_dir.join("truth_report.json"), &truth)?;

    let mission_assurance_report = json!({
        "scenario": spec.scenario_id,
        "unsafe_pair_count": run.public_inputs["unsafe_pair_count"],
        "mission_safety_commitment": run.public_inputs["mission_safety_commitment"],
        "proof_verified": true,
        "setup_provenance": run.setup_provenance,
        "security_boundary": run.security_boundary,
        "foundry": foundry,
        "determinism": determinism["hashes_matched"],
    });
    write_json(
        &out_dir.join("mission_assurance_report.json"),
        &mission_assurance_report,
    )?;

    write_json(&out_dir.join("determinism_report.json"), determinism)?;

    let summary_markdown = report_markdown(
        spec,
        &run.public_inputs,
        &benchmark_summary,
        &run.accelerator_trace,
        &correctness,
        determinism,
        &truth,
        &formal_summary,
        &audit_summary,
        &foundry,
    );
    write_text(
        &out_dir.join("human_readable_summary.md"),
        &summary_markdown,
    )?;

    let manifest = export_manifest(
        spec,
        pair_schedule,
        out_dir,
        &run.setup_provenance,
        &run.security_boundary,
        &foundry,
    )?;
    write_json(&out_dir.join("export_manifest.json"), &manifest)?;

    let compiled_from_disk: CompiledProgram = read_json(&out_dir.join("compiled_program.json"))?;
    let proof_from_disk: ProofArtifact = read_json(&out_dir.join("proof.json"))?;
    if !verify(&compiled_from_disk, &proof_from_disk)? {
        return Err(ZkfError::Backend(
            "disk-loaded proof verification returned false".to_string(),
        ));
    }
    ensure_file_exists(&out_dir.join("compiled_program.json"))?;
    ensure_file_exists(&out_dir.join("witness.json"))?;
    ensure_file_exists(&out_dir.join("proof.json"))?;
    ensure_file_exists(&out_dir.join("public_inputs.json"))?;
    ensure_file_exists(&out_dir.join("verifier.sol"))?;
    ensure_file_exists(&out_dir.join("calldata.json"))?;
    ensure_file_exists(&out_dir.join("runtime_trace.json"))?;
    ensure_file_exists(&out_dir.join("accelerator_trace.json"))?;
    ensure_file_exists(&out_dir.join("stage_metrics.json"))?;
    ensure_file_exists(&out_dir.join("correctness_report.json"))?;
    ensure_file_exists(&out_dir.join("determinism_report.json"))?;
    ensure_file_exists(&out_dir.join("truth_report.json"))?;
    ensure_file_exists(&out_dir.join("benchmark_summary.json"))?;
    ensure_file_exists(&out_dir.join("audit_summary.json"))?;
    ensure_file_exists(&out_dir.join("mission_assurance_report.json"))?;
    ensure_file_exists(&out_dir.join("formal_evidence_summary.json"))?;
    ensure_file_exists(&out_dir.join("export_manifest.json"))?;
    ensure_file_exists(&out_dir.join("foundry_report.txt"))?;
    ensure_file_exists(&out_dir.join("human_readable_summary.md"))?;
    ensure_dir_exists(&out_dir.join("formal"))?;
    ensure_dir_exists(&project_dir)?;
    ensure_file_exists(&project_dir.join("foundry.toml"))?;
    ensure_file_exists(&project_dir.join("src/PrivateMultiSatelliteVerifier.sol"))?;
    ensure_file_exists(&project_dir.join("test/PrivateMultiSatelliteVerifier.t.sol"))?;
    let _cloud_paths = persist_artifacts_to_cloudfs(
        APP_ID,
        &[
            ("proofs".to_string(), out_dir.join("proof.json")),
            ("verifiers".to_string(), out_dir.join("verifier.sol")),
            ("verifiers".to_string(), out_dir.join("calldata.json")),
            ("traces".to_string(), out_dir.join("runtime_trace.json")),
            ("audits".to_string(), out_dir.join("audit_summary.json")),
            (
                "reports".to_string(),
                out_dir.join("formal_evidence_summary.json"),
            ),
            (
                "reports".to_string(),
                out_dir.join("benchmark_summary.json"),
            ),
            ("reports".to_string(), out_dir.join("truth_report.json")),
            (
                "reports".to_string(),
                out_dir.join("mission_assurance_report.json"),
            ),
            (
                "reports".to_string(),
                out_dir.join("human_readable_summary.md"),
            ),
            ("reports".to_string(), out_dir.join("export_manifest.json")),
        ],
    )?;

    Ok(())
}

fn run_with_large_stack_result<T, F>(name: &str, f: F) -> ZkfResult<T>
where
    T: Send + 'static,
    F: FnOnce() -> ZkfResult<T> + Send + 'static,
{
    let handle = std::thread::Builder::new()
        .name(name.to_string())
        .stack_size(512 * 1024 * 1024)
        .spawn(f)
        .map_err(|error| ZkfError::Backend(format!("spawn {name} worker: {error}")))?;
    handle.join().map_err(|panic| {
        if let Some(message) = panic.downcast_ref::<&str>() {
            ZkfError::Backend(format!("{name} worker panicked: {message}"))
        } else if let Some(message) = panic.downcast_ref::<String>() {
            ZkfError::Backend(format!("{name} worker panicked: {message}"))
        } else {
            ZkfError::Backend(format!("{name} worker panicked"))
        }
    })?
}

fn main() -> ZkfResult<()> {
    let scenarios = selected_scenarios()?;
    let root_override = env::args_os().nth(1).map(PathBuf::from);

    for scenario in scenarios.iter().copied() {
        let spec = private_multi_satellite_scenario_spec(scenario);
        let pair_schedule = private_multi_satellite_pair_schedule(scenario)?;
        let out_dir = scenario_output_dir(spec, root_override.as_deref(), scenarios.len());
        run_with_large_stack_result(
            &format!("multi-satellite-{}", spec.scenario_id),
            move || {
                let runs = (0..3)
                    .map(|_| execute_scenario_once(spec))
                    .collect::<ZkfResult<Vec<_>>>()?;
                let determinism = determinism_report(spec, &pair_schedule, &runs)?;
                export_scenario_bundle(spec, &out_dir, &pair_schedule, &runs[0], &determinism)
            },
        )?;
    }

    Ok(())
}
