use serde::Serialize;
use zkf_backends::{GpuSchedulerDecision, GpuStageCoverage, Groth16ExecutionSummary};
use zkf_core::SupportClass;

#[derive(Debug, Serialize)]
pub(crate) struct RunResult {
    pub(crate) manifest: String,
    pub(crate) run_id: String,
    pub(crate) witness_path: String,
    pub(crate) public_inputs_path: String,
    pub(crate) run_report_path: String,
    pub(crate) witness_values: usize,
    pub(crate) public_inputs: usize,
    pub(crate) solver: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RunArtifactReport {
    pub(crate) run_id: String,
    pub(crate) solver: String,
    pub(crate) solver_path: String,
    pub(crate) execution_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) attempted_solver_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) solver_attempt_errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) frontend_execution_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) fallback_reason: Option<String>,
    pub(crate) requires_execution: bool,
    pub(crate) requires_solver: bool,
    pub(crate) witness_values: usize,
    pub(crate) public_inputs: usize,
    pub(crate) constraints: usize,
    pub(crate) signals: usize,
    pub(crate) requires_hints: bool,
    #[serde(default)]
    pub(crate) prepared_witness_validated: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) prepared_witness_backends: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProveResult {
    pub(crate) manifest: String,
    pub(crate) backend: String,
    pub(crate) run_id: String,
    pub(crate) proof_path: String,
    pub(crate) report_path: String,
    pub(crate) proof_size_bytes: usize,
    pub(crate) public_inputs: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) proof_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prover_acceleration_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) proof_engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) gpu_stage_coverage: Option<GpuStageCoverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_execution_regime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_gpu_stage_busy_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_prover_acceleration_realized: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prover_acceleration_realization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cpu_math_fallback_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) export_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_gpu_busy_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_stage_breakdown: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_inflight_jobs: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_no_cpu_fallback: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_counter_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) groth16_execution: Option<Groth16ExecutionSummary>,
    #[serde(default)]
    pub(crate) hybrid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) security_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) replay_manifest_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) companion_backend: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProveAllResult {
    pub(crate) manifest: String,
    pub(crate) run_id: String,
    pub(crate) requested: usize,
    pub(crate) succeeded: usize,
    pub(crate) failed: usize,
    pub(crate) skipped: usize,
    pub(crate) parallel: bool,
    pub(crate) jobs_used: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) scheduler: Option<GpuSchedulerDecision>,
    pub(crate) results: Vec<ProveAllEntry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProveAllEntry {
    pub(crate) backend: String,
    pub(crate) status: String,
    pub(crate) ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) proof_size_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) public_inputs: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) proof_semantics: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prover_acceleration_scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) proof_engine: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) gpu_stage_coverage: Option<GpuStageCoverage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_complete: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_execution_regime: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_gpu_stage_busy_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) runtime_prover_acceleration_realized: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) prover_acceleration_realization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cpu_math_fallback_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) export_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_gpu_busy_ratio: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_stage_breakdown: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_inflight_jobs: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_no_cpu_fallback: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) metal_counter_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) groth16_execution: Option<Groth16ExecutionSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) implementation_type: Option<SupportClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) readiness: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) readiness_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) operator_action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) explicit_compat_alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyProofResult {
    pub(crate) manifest: String,
    pub(crate) backend: String,
    pub(crate) run_id: String,
    pub(crate) ok: bool,
    pub(crate) proof_path: String,
    pub(crate) report_path: String,
    #[serde(default)]
    pub(crate) hybrid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) solidity_verifier_path: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyProofReport {
    pub(crate) backend: String,
    pub(crate) run_id: String,
    pub(crate) ok: bool,
    pub(crate) program_digest: String,
    pub(crate) proof_digest: String,
    #[serde(default)]
    pub(crate) hybrid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) security_profile: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct GasEstimateReport {
    pub(crate) backend: String,
    pub(crate) evm_target: String,
    pub(crate) proof_size_bytes: usize,
    pub(crate) estimated_verify_gas: u64,
    pub(crate) model_source: String,
    pub(crate) model_note: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct DeployReport {
    pub(crate) backend: String,
    pub(crate) evm_target: String,
    pub(crate) artifact_path: String,
    pub(crate) solidity_path: String,
    pub(crate) contract_name: String,
    pub(crate) solidity_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) algebraic_binding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) trust_boundary_note: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CompileResult {
    pub(crate) manifest: String,
    pub(crate) backend: String,
    pub(crate) compiled_path: String,
    pub(crate) compiled_data_bytes: usize,
    pub(crate) metadata_entries: usize,
    pub(crate) program_digest: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub(crate) struct BundleEntry {
    pub(crate) backend: String,
    pub(crate) proof_path: String,
    pub(crate) proof_digest: String,
    pub(crate) program_digest: String,
    #[serde(default)]
    pub(crate) statement_digest: String,
    #[serde(default)]
    pub(crate) verification_key_digest: String,
    #[serde(default)]
    pub(crate) public_input_commitment: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub(crate) struct BundleArtifact {
    pub(crate) run_id: String,
    pub(crate) entries: Vec<BundleEntry>,
    pub(crate) aggregate_digest: String,
    pub(crate) scheme: String,
    #[serde(default = "default_metadata_binding_only")]
    pub(crate) proof_semantics: String,
    #[serde(default = "default_not_claimed_metadata_only")]
    pub(crate) prover_acceleration_scope: String,
    #[serde(default)]
    pub(crate) metal_gpu_busy_ratio: f64,
    #[serde(default = "default_metal_stage_breakdown")]
    pub(crate) metal_stage_breakdown: String,
    #[serde(default)]
    pub(crate) metal_inflight_jobs: usize,
    #[serde(default)]
    pub(crate) metal_no_cpu_fallback: bool,
    #[serde(default = "default_metal_counter_source")]
    pub(crate) metal_counter_source: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct BundleResult {
    pub(crate) manifest: String,
    pub(crate) run_id: String,
    pub(crate) artifact_path: String,
    pub(crate) entries: usize,
    pub(crate) aggregate_digest: String,
    pub(crate) proof_semantics: String,
    pub(crate) prover_acceleration_scope: String,
    pub(crate) metal_gpu_busy_ratio: f64,
    pub(crate) metal_stage_breakdown: String,
    pub(crate) metal_inflight_jobs: usize,
    pub(crate) metal_no_cpu_fallback: bool,
    pub(crate) metal_counter_source: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyBundleResult {
    pub(crate) manifest: String,
    pub(crate) run_id: String,
    pub(crate) ok: bool,
    pub(crate) entries: usize,
    pub(crate) artifact_path: String,
    pub(crate) report_path: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyBundleReport {
    pub(crate) run_id: String,
    pub(crate) ok: bool,
    pub(crate) entries: usize,
    pub(crate) aggregate_digest: String,
    pub(crate) proof_semantics: String,
    pub(crate) prover_acceleration_scope: String,
    pub(crate) metal_gpu_busy_ratio: f64,
    pub(crate) metal_stage_breakdown: String,
    pub(crate) metal_inflight_jobs: usize,
    pub(crate) metal_no_cpu_fallback: bool,
    pub(crate) metal_counter_source: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct AggregateResult {
    pub(crate) manifest: String,
    pub(crate) backend: String,
    pub(crate) run_id: String,
    pub(crate) input_run_ids: Vec<String>,
    pub(crate) artifact_path: String,
    pub(crate) proof_count: usize,
    pub(crate) scheme: String,
    pub(crate) trust_model: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyAggregateResult {
    pub(crate) manifest: String,
    pub(crate) backend: String,
    pub(crate) run_id: String,
    pub(crate) ok: bool,
    pub(crate) proof_count: usize,
    pub(crate) artifact_path: String,
    pub(crate) report_path: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyAggregateReport {
    pub(crate) backend: String,
    pub(crate) run_id: String,
    pub(crate) ok: bool,
    pub(crate) proof_count: usize,
    pub(crate) scheme: Option<String>,
    pub(crate) trust_model: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ComposeResult {
    pub(crate) manifest: String,
    pub(crate) run_id: String,
    pub(crate) backend: String,
    pub(crate) carried_entries: usize,
    pub(crate) composition_digest: String,
    pub(crate) composition_program_path: String,
    pub(crate) proof_path: String,
    pub(crate) report_path: String,
    pub(crate) proof_semantics: String,
    pub(crate) blackbox_semantics: String,
    pub(crate) prover_acceleration_scope: String,
    pub(crate) metal_gpu_busy_ratio: f64,
    pub(crate) metal_stage_breakdown: String,
    pub(crate) metal_inflight_jobs: usize,
    pub(crate) metal_no_cpu_fallback: bool,
    pub(crate) metal_counter_source: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub(crate) struct ComposeReport {
    pub(crate) run_id: String,
    pub(crate) backend: String,
    pub(crate) carried_entries: usize,
    pub(crate) aggregate_digest: String,
    pub(crate) composition_digest: String,
    #[serde(default = "default_compose_proof_semantics")]
    pub(crate) proof_semantics: String,
    #[serde(default = "default_compose_blackbox_semantics")]
    pub(crate) blackbox_semantics: String,
    #[serde(default = "default_compose_acceleration_scope")]
    pub(crate) prover_acceleration_scope: String,
    #[serde(default)]
    pub(crate) metal_gpu_busy_ratio: f64,
    #[serde(default = "default_metal_stage_breakdown")]
    pub(crate) metal_stage_breakdown: String,
    #[serde(default)]
    pub(crate) metal_inflight_jobs: usize,
    #[serde(default)]
    pub(crate) metal_no_cpu_fallback: bool,
    #[serde(default = "default_metal_counter_source")]
    pub(crate) metal_counter_source: String,
    pub(crate) carried_backends: Vec<String>,
    #[serde(default)]
    pub(crate) carried_statement_digests: Vec<String>,
    #[serde(default)]
    pub(crate) carried_verification_key_digests: Vec<String>,
    #[serde(default)]
    pub(crate) carried_public_input_commitments: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyComposeResult {
    pub(crate) manifest: String,
    pub(crate) run_id: String,
    pub(crate) backend: String,
    pub(crate) ok: bool,
    pub(crate) carried_entries: usize,
    pub(crate) report_path: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyComposeReport {
    pub(crate) run_id: String,
    pub(crate) backend: String,
    pub(crate) ok: bool,
    pub(crate) carried_entries: usize,
    pub(crate) carried_valid: bool,
    pub(crate) composition_proof_valid: bool,
    pub(crate) proof_binding_valid: bool,
    pub(crate) public_input_binding_valid: bool,
    pub(crate) aggregate_digest: String,
    pub(crate) composition_digest: String,
    pub(crate) proof_semantics: String,
    pub(crate) blackbox_semantics: String,
    pub(crate) prover_acceleration_scope: String,
    pub(crate) metal_gpu_busy_ratio: f64,
    pub(crate) metal_stage_breakdown: String,
    pub(crate) metal_inflight_jobs: usize,
    pub(crate) metal_no_cpu_fallback: bool,
    pub(crate) metal_counter_source: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub(crate) struct FoldStepEntry {
    pub(crate) step: usize,
    pub(crate) run_id: String,
    pub(crate) proof_path: String,
    pub(crate) proof_digest: String,
    pub(crate) public_inputs: usize,
}

#[derive(Debug, Serialize, serde::Deserialize)]
pub(crate) struct FoldArtifact {
    pub(crate) backend: String,
    pub(crate) steps: usize,
    pub(crate) step_mode: String,
    pub(crate) entries: Vec<FoldStepEntry>,
    pub(crate) fold_digest: String,
    pub(crate) scheme: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct FoldResult {
    pub(crate) manifest: String,
    pub(crate) backend: String,
    pub(crate) steps: usize,
    pub(crate) step_mode: String,
    pub(crate) run_ids: Vec<String>,
    pub(crate) artifact_path: String,
    pub(crate) fold_digest: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct PackageMigrateReport {
    pub(crate) manifest: String,
    pub(crate) from_version: u32,
    pub(crate) to_version: u32,
    pub(crate) updated_files: usize,
    pub(crate) warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PackageVerifyReport {
    pub(crate) manifest: String,
    pub(crate) ok: bool,
    pub(crate) program_digest_match: bool,
    pub(crate) translator_provenance_valid: bool,
    pub(crate) checked_files: Vec<PackageFileCheck>,
    pub(crate) warnings: Vec<String>,
}

fn default_metadata_binding_only() -> String {
    "metadata-binding-only".to_string()
}

fn default_not_claimed_metadata_only() -> String {
    "not-claimed-metadata-only".to_string()
}

fn default_compose_proof_semantics() -> String {
    "proof-enforced-digest-equality-plus-host-validated-markers".to_string()
}

fn default_compose_blackbox_semantics() -> String {
    "host-validated-recursive-markers".to_string()
}

fn default_compose_acceleration_scope() -> String {
    "composition-backend-prover-only".to_string()
}

fn default_metal_stage_breakdown() -> String {
    "{}".to_string()
}

fn default_metal_counter_source() -> String {
    "not-measured".to_string()
}

#[derive(Debug, Serialize)]
pub(crate) struct PackageFileCheck {
    pub(crate) path: String,
    pub(crate) exists: bool,
    pub(crate) hash_matches: bool,
}

pub(crate) type AggregateArtifact = BundleArtifact;
