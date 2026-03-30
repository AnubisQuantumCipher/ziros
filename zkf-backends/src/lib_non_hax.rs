pub mod aggregation;
#[cfg(not(target_arch = "wasm32"))]
mod arkworks;
mod audited_backend;
pub mod blackbox_gadgets;
#[cfg(not(target_arch = "wasm32"))]
mod blackbox_native;
#[cfg(not(target_arch = "wasm32"))]
pub mod ceremony;
mod compat;
pub mod execution_summary;
#[cfg(not(target_arch = "wasm32"))]
pub mod foundry_test;
#[cfg(not(target_arch = "wasm32"))]
pub mod groth16_hex;
#[cfg(not(target_arch = "wasm32"))]
pub mod groth16_proof;
#[cfg(not(target_arch = "wasm32"))]
pub mod groth16_vk;
#[cfg(not(target_arch = "wasm32"))]
mod halo2;
#[cfg(not(target_arch = "wasm32"))]
mod halo2_bls12_381;
#[cfg(not(target_arch = "wasm32"))]
mod hypernova;
pub mod lowering;
#[cfg(not(target_arch = "wasm32"))]
pub mod metal_runtime;
pub mod midnight;
#[cfg(not(target_arch = "wasm32"))]
pub mod midnight_client;
pub mod midnight_codegen;
#[cfg(not(target_arch = "wasm32"))]
mod midnight_native;
#[cfg(not(target_arch = "wasm32"))]
pub mod midnight_tx;
pub mod native_field;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-nova"))]
pub mod nova_native;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod plonky3;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod proof_blackbox_ecdsa_spec;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod proof_blackbox_hash_spec;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod proof_plonky3_spec;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod proof_plonky3_surface;
#[cfg(not(target_arch = "wasm32"))]
mod r1cs_lowering;
#[cfg(not(target_arch = "wasm32"))]
mod range_decomposition;
pub mod recursive_aggregation;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod risc_zero;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-risc-zero"))]
mod risc_zero_native;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-sp1"))]
mod sp1_native;
#[cfg(kani)]
mod verification_kani;
#[cfg(not(target_arch = "wasm32"))]
pub mod verifier_export;
pub mod wrapping;

#[cfg(not(target_arch = "wasm32"))]
use arkworks::ArkworksGroth16Backend;
#[cfg(not(target_arch = "wasm32"))]
pub use arkworks::{
    compile_and_prove_arkworks_unchecked_for_test_fixture, compile_arkworks_unchecked,
    groth16_bn254_witness_map_ntt_parity, synthetic_groth16_compiled_for_artifact,
};
pub use execution_summary::{
    Groth16ExecutionClassification, Groth16ExecutionSummary, Groth16MetalThresholdSummary,
    Groth16StageExecutionSummary, groth16_execution_summary_from_metadata,
};
#[cfg(not(target_arch = "wasm32"))]
use halo2::Halo2Backend;
#[cfg(not(target_arch = "wasm32"))]
use halo2_bls12_381::Halo2Bls12381Backend;
#[cfg(not(target_arch = "wasm32"))]
use hypernova::HyperNovaBackend;
#[cfg(not(target_arch = "wasm32"))]
use midnight_native::MidnightNativeBackend;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-nova"))]
use nova_native::NovaNativeBackend;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-nova"))]
pub use nova_native::compile_nova_unchecked;
use once_cell::sync::Lazy;
#[cfg(not(target_arch = "wasm32"))]
pub use r1cs_lowering::lower_program_for_backend;
use std::collections::{HashMap, VecDeque};
use std::sync::Once;
use zkf_core::SupportClass;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MetalThresholdConfig {
    pub msm: usize,
    pub ntt: usize,
    pub poseidon2: usize,
    pub field_ops: usize,
    pub merkle: usize,
}

impl MetalThresholdConfig {
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    fn into_metal(self) -> zkf_metal::ThresholdConfig {
        zkf_metal::ThresholdConfig {
            msm: self.msm,
            ntt: self.ntt,
            poseidon2: self.poseidon2,
            field_ops: self.field_ops,
            merkle: self.merkle,
        }
    }
}

pub fn current_metal_thresholds() -> MetalThresholdConfig {
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        let cfg = zkf_metal::current_thresholds();
        MetalThresholdConfig {
            msm: cfg.msm,
            ntt: cfg.ntt,
            poseidon2: cfg.poseidon2,
            field_ops: cfg.field_ops,
            merkle: cfg.merkle,
        }
    }

    #[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
    {
        MetalThresholdConfig {
            msm: 1 << 14,
            ntt: 1 << 12,
            poseidon2: 1_000,
            field_ops: 10_000,
            merkle: 2_048,
        }
    }
}

pub fn set_runtime_metal_threshold_override(_config: Option<MetalThresholdConfig>) {
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        if let Some(config) = _config {
            zkf_metal::set_runtime_threshold_override(config.into_metal());
        } else {
            zkf_metal::clear_runtime_threshold_override();
        }
    }
}

pub fn set_learned_metal_thresholds(_config: Option<MetalThresholdConfig>) {
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        if let Some(config) = _config {
            zkf_metal::set_learned_thresholds(config.into_metal());
        } else {
            zkf_metal::clear_learned_thresholds();
        }
    }
}

/// Initialize hardware accelerators (Metal GPU on macOS).
/// Called once on first backend instantiation.
pub fn init_accelerators() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
        {
            zkf_metal::register_metal_accelerators();
        }
    });
}

/// Trim reusable accelerator caches when the host is already under memory pressure.
pub fn harden_accelerators_for_current_pressure() {
    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    {
        let resources = zkf_core::SystemResources::detect();
        if let Some(ctx) = zkf_metal::global_context() {
            let _ = ctx.harden_for_pressure(resources.pressure.level);
        }
    }
}
#[cfg(all(not(target_arch = "wasm32"), not(feature = "native-nova")))]
use compat::NovaBackend;
#[cfg(all(not(target_arch = "wasm32"), not(feature = "native-sp1")))]
use compat::Sp1Backend;
#[cfg(target_arch = "wasm32")]
use compat::WasmUnavailableBackend;
#[cfg(not(target_arch = "wasm32"))]
use plonky3::Plonky3Backend;
#[cfg(all(not(target_arch = "wasm32"), not(feature = "native-risc-zero")))]
use risc_zero::RiscZeroBackend;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-risc-zero"))]
use risc_zero_native::RiscZeroNativeBackend;
#[cfg(all(not(target_arch = "wasm32"), feature = "native-sp1"))]
use sp1_native::Sp1NativeBackend;
use std::sync::Mutex;
use zkf_core::{
    BackendCapabilities, BackendKind, CompiledProgram, FieldId, Program, ProofArtifact,
    ToolRequirement, Witness, ZkfError, ZkfResult, program_zir_to_v2, zir_v1,
};

pub(crate) fn bounded_cache_limit(env_var: &str, default: usize) -> usize {
    std::env::var(env_var)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

#[derive(Debug, Clone)]
pub(crate) struct BoundedStringCache<V> {
    entries: HashMap<String, V>,
    order: VecDeque<String>,
    max_entries: usize,
}

impl<V> BoundedStringCache<V> {
    pub(crate) fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max_entries,
        }
    }

    fn touch(&mut self, key: &str) {
        if let Some(index) = self.order.iter().position(|entry| entry == key) {
            self.order.remove(index);
        }
        self.order.push_back(key.to_string());
    }

    pub(crate) fn insert(&mut self, key: String, value: V) {
        if self.max_entries == 0 {
            return;
        }

        self.entries.insert(key.clone(), value);
        self.touch(&key);

        while self.entries.len() > self.max_entries {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&evicted);
        }
    }

    pub(crate) fn remove(&mut self, key: &str) -> Option<V> {
        if let Some(index) = self.order.iter().position(|entry| entry == key) {
            self.order.remove(index);
        }
        self.entries.remove(key)
    }

    #[cfg(test)]
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }
}

impl<V: Clone> BoundedStringCache<V> {
    pub(crate) fn get_cloned(&mut self, key: &str) -> Option<V> {
        let value = self.entries.get(key).cloned()?;
        self.touch(key);
        Some(value)
    }
}

#[cfg(test)]
static HEAVY_BACKEND_TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

#[cfg(test)]
use std::cell::Cell;
#[cfg(test)]
thread_local! {
    static HEAVY_BACKEND_TEST_DEPTH: Cell<usize> = const { Cell::new(0) };
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
}

#[cfg(target_os = "macos")]
pub(crate) fn relieve_allocator_pressure() {
    unsafe {
        let _ = malloc_zone_pressure_relief(std::ptr::null_mut(), 0);
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn relieve_allocator_pressure() {}

#[cfg(test)]
struct HeavyBackendTestSection {
    _guard: Option<std::sync::MutexGuard<'static, ()>>,
    prior_metal_env: Option<std::ffi::OsString>,
}

#[cfg(test)]
impl HeavyBackendTestSection {
    fn enter() -> Self {
        let outermost = HEAVY_BACKEND_TEST_DEPTH.with(|depth| {
            let current = depth.get();
            depth.set(current + 1);
            current == 0
        });
        let guard = outermost.then(|| {
            HEAVY_BACKEND_TEST_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        });
        let prior_metal_env = outermost
            .then(|| {
                let prior = std::env::var_os("ZKF_METAL");
                // Tests serialize environment mutation behind the heavy-backend lock.
                unsafe {
                    std::env::set_var("ZKF_METAL", "0");
                }
                prior
            })
            .flatten();
        Self {
            _guard: guard,
            prior_metal_env,
        }
    }
}

#[cfg(test)]
impl Drop for HeavyBackendTestSection {
    fn drop(&mut self) {
        let outermost_complete = HEAVY_BACKEND_TEST_DEPTH.with(|depth| {
            let next = depth.get().saturating_sub(1);
            depth.set(next);
            next == 0
        });
        #[cfg(all(test, not(target_arch = "wasm32")))]
        if outermost_complete {
            halo2::clear_test_setup_cache();
            halo2_bls12_381::clear_test_setup_cache();
            wrapping::stark_to_groth16::clear_test_caches();
            wrapping::nova_stark_compress::clear_test_caches();
            wrapping::nova_universal_aggregator::clear_test_caches();
            match self.prior_metal_env.take() {
                Some(previous) => unsafe {
                    std::env::set_var("ZKF_METAL", previous);
                },
                None => unsafe {
                    std::env::remove_var("ZKF_METAL");
                },
            }
        }
        #[cfg(all(test, target_os = "macos"))]
        if outermost_complete {
            relieve_allocator_pressure();
        }
    }
}

pub(crate) fn with_serialized_heavy_backend_test<T>(f: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    {
        let _section = HeavyBackendTestSection::enter();
        f()
    }

    #[cfg(not(test))]
    {
        f()
    }
}

#[cfg(test)]
mod bounded_cache_tests {
    use super::BoundedStringCache;

    #[test]
    fn bounded_string_cache_evicts_oldest_entry() {
        let mut cache = BoundedStringCache::new(2);
        cache.insert("one".to_string(), 1);
        cache.insert("two".to_string(), 2);
        cache.insert("three".to_string(), 3);

        assert_eq!(cache.get_cloned("one"), None);
        assert_eq!(cache.get_cloned("two"), Some(2));
        assert_eq!(cache.get_cloned("three"), Some(3));
    }

    #[test]
    fn bounded_string_cache_promotes_recent_reads() {
        let mut cache = BoundedStringCache::new(2);
        cache.insert("one".to_string(), 1);
        cache.insert("two".to_string(), 2);
        assert_eq!(cache.get_cloned("one"), Some(1));
        cache.insert("three".to_string(), 3);

        assert_eq!(cache.get_cloned("one"), Some(1));
        assert_eq!(cache.get_cloned("two"), None);
        assert_eq!(cache.get_cloned("three"), Some(3));
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use metal_runtime::{
    CapabilityReport, GpuSchedulerDecision, GpuStage, GpuStageCoverage,
    aggregation_semantics_for_backend, append_backend_runtime_metadata,
    append_backend_runtime_metadata_for_field, append_default_metal_telemetry,
    assurance_lane_for_backend, backend_capability_matrix, blackbox_semantics_for_backend,
    capabilities_report, copy_standard_metal_metadata, cpu_math_fallback_reason_for_backend,
    export_scheme_for_backend, gpu_stage_coverage_for_backend,
    gpu_stage_coverage_for_backend_field, lookup_lowering_support_for_backend,
    lookup_semantics_for_backend, metal_complete_for_backend, metal_runtime_report,
    native_lookup_support_for_backend, proof_engine_for_backend, proof_semantics_for_backend,
    prover_acceleration_claimed_for_backend, prover_acceleration_scope_for_backend,
    recommend_gpu_jobs, runtime_hardware_profile, strict_bn254_auto_route_ready,
    strict_bn254_auto_route_ready_with_runtime, strict_bn254_gpu_stage_coverage,
};

pub trait BackendEngine: Send + Sync {
    fn kind(&self) -> BackendKind;
    fn capabilities(&self) -> BackendCapabilities;
    fn doctor_requirements(&self) -> Vec<ToolRequirement> {
        Vec::new()
    }
    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram>;
    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact>;
    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool>;

    /// Compile directly from ZIR, allowing backends to exploit rich constraint
    /// types (lookups, custom gates, memory ops) without lossy IR v2 conversion.
    /// Default: convert to IR v2 and delegate to `compile()`.
    fn compile_zir(&self, program: &zir_v1::Program) -> ZkfResult<CompiledProgram> {
        let v2 = program_zir_to_v2(program)?;
        self.compile(&v2)
    }

    /// Prove directly from a ZIR program and its compiled representation.
    /// Default: convert to IR v2 and delegate to `prove()`.
    fn prove_zir(
        &self,
        zir_program: &zir_v1::Program,
        compiled: &CompiledProgram,
        witness: &Witness,
    ) -> ZkfResult<ProofArtifact> {
        let _ = zir_program; // default ignores ZIR, uses v2 in compiled
        self.prove(compiled, witness)
    }

    /// Verify a proof produced from a ZIR program.
    /// Default: delegates to `verify()`.
    fn verify_zir(
        &self,
        zir_program: &zir_v1::Program,
        compiled: &CompiledProgram,
        artifact: &ProofArtifact,
    ) -> ZkfResult<bool> {
        let _ = zir_program;
        self.verify(compiled, artifact)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendRoute {
    Auto,
    ExplicitCompat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSelection {
    pub backend: BackendKind,
    pub route: BackendRoute,
    pub requested_name: String,
}

impl BackendSelection {
    pub fn native(backend: BackendKind) -> Self {
        Self {
            backend,
            route: BackendRoute::Auto,
            requested_name: backend.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSurfaceStatus {
    pub implementation_type: SupportClass,
    pub compiled_in: bool,
    pub compat_available: bool,
}

static SETUP_SEED_OVERRIDE: Lazy<Mutex<Option<[u8; 32]>>> = Lazy::new(|| Mutex::new(None));
static PROOF_SEED_OVERRIDE: Lazy<Mutex<Option<[u8; 32]>>> = Lazy::new(|| Mutex::new(None));
static ALLOW_DEV_DETERMINISTIC_GROTH16_OVERRIDE: Lazy<Mutex<Option<bool>>> =
    Lazy::new(|| Mutex::new(None));
static GROTH16_SETUP_BLOB_PATH_OVERRIDE: Lazy<Mutex<Option<String>>> =
    Lazy::new(|| Mutex::new(None));

pub const GROTH16_SETUP_BLOB_PATH_METADATA_KEY: &str = "groth16_setup_blob_path";
pub const GROTH16_SETUP_PROVENANCE_METADATA_KEY: &str = "groth16_setup_provenance";
pub const GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY: &str = "groth16_setup_security_boundary";
pub const GROTH16_STREAMED_SETUP_STORAGE_METADATA_KEY: &str = "groth16_setup_storage";
pub const GROTH16_STREAMED_SETUP_STORAGE_VALUE: &str = "streamed-disk";
pub const GROTH16_STREAMED_PK_PATH_METADATA_KEY: &str = "groth16_streamed_pk_path";
pub const GROTH16_STREAMED_SHAPE_PATH_METADATA_KEY: &str = "groth16_streamed_shape_path";
pub const GROTH16_CEREMONY_SUBSYSTEM_METADATA_KEY: &str = "groth16_ceremony_subsystem";
pub const GROTH16_CEREMONY_ID_METADATA_KEY: &str = "groth16_ceremony_id";
pub const GROTH16_CEREMONY_KIND_METADATA_KEY: &str = "groth16_ceremony_kind";
pub const GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY: &str = "groth16_ceremony_report_path";
pub const GROTH16_CEREMONY_REPORT_SHA256_METADATA_KEY: &str =
    "groth16_ceremony_report_sha256";
pub const GROTH16_CEREMONY_SEED_COMMITMENT_METADATA_KEY: &str =
    "groth16_ceremony_seed_commitment_sha256";
pub const GROTH16_IMPORTED_SETUP_PROVENANCE: &str = "trusted-imported-blob";
pub const GROTH16_DETERMINISTIC_DEV_PROVENANCE: &str = "deterministic-dev";
pub const GROTH16_LOCAL_CEREMONY_STREAMED_PROVENANCE: &str = "local-ceremony-phase2-streamed";
pub const GROTH16_AUTO_CEREMONY_PROVENANCE: &str = "auto-ceremony-cached-entropy";
pub const GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY: &str = "trusted-imported";
pub const GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY: &str = "development-only";
pub const GROTH16_LOCAL_CEREMONY_STREAMED_SECURITY_BOUNDARY: &str = "trusted-local-ceremony";
pub const GROTH16_AUTO_CEREMONY_SECURITY_BOUNDARY: &str = "auto-ceremony";
pub const GROTH16_SETUP_BLOB_PATH_ENV: &str = "ZKF_GROTH16_SETUP_BLOB_PATH";
pub const ALLOW_DEV_DETERMINISTIC_GROTH16_ENV: &str = "ZKF_ALLOW_DEV_DETERMINISTIC_GROTH16";

pub fn set_setup_seed_override(seed: Option<[u8; 32]>) {
    if let Ok(mut guard) = SETUP_SEED_OVERRIDE.lock() {
        *guard = seed;
    }
}

/// Temporarily set the setup seed override, run `f`, then restore the previous value.
pub fn with_setup_seed_override<T, F: FnOnce() -> T>(seed: Option<[u8; 32]>, f: F) -> T {
    let old = setup_seed_override();
    set_setup_seed_override(seed);
    let result = f();
    set_setup_seed_override(old);
    result
}

pub fn setup_seed_override() -> Option<[u8; 32]> {
    SETUP_SEED_OVERRIDE.lock().ok().and_then(|guard| *guard)
}

pub fn set_proof_seed_override(seed: Option<[u8; 32]>) {
    if let Ok(mut guard) = PROOF_SEED_OVERRIDE.lock() {
        *guard = seed;
    }
}

/// Temporarily set the proof seed override, run `f`, then restore the previous value.
pub fn with_proof_seed_override<T, F: FnOnce() -> T>(seed: Option<[u8; 32]>, f: F) -> T {
    let old = proof_seed_override();
    set_proof_seed_override(seed);
    let result = f();
    set_proof_seed_override(old);
    result
}

pub fn proof_seed_override() -> Option<[u8; 32]> {
    PROOF_SEED_OVERRIDE.lock().ok().and_then(|guard| *guard)
}

pub fn set_allow_dev_deterministic_groth16_override(value: Option<bool>) {
    if let Ok(mut guard) = ALLOW_DEV_DETERMINISTIC_GROTH16_OVERRIDE.lock() {
        *guard = value;
    }
}

pub fn with_allow_dev_deterministic_groth16_override<T, F: FnOnce() -> T>(
    value: Option<bool>,
    f: F,
) -> T {
    let old = allow_dev_deterministic_groth16_override();
    set_allow_dev_deterministic_groth16_override(value);
    let result = f();
    set_allow_dev_deterministic_groth16_override(old);
    result
}

pub fn allow_dev_deterministic_groth16_override() -> Option<bool> {
    ALLOW_DEV_DETERMINISTIC_GROTH16_OVERRIDE
        .lock()
        .ok()
        .and_then(|guard| *guard)
}

pub fn allow_dev_deterministic_groth16() -> bool {
    if let Some(value) = allow_dev_deterministic_groth16_override() {
        return value;
    }

    std::env::var(ALLOW_DEV_DETERMINISTIC_GROTH16_ENV)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub fn requested_groth16_setup_blob_path(program: &Program) -> Option<String> {
    if let Some(path) = groth16_setup_blob_path_override() {
        return Some(path);
    }

    program
        .metadata
        .get(GROTH16_SETUP_BLOB_PATH_METADATA_KEY)
        .cloned()
        .or_else(|| std::env::var(GROTH16_SETUP_BLOB_PATH_ENV).ok())
}

pub fn set_groth16_setup_blob_path_override(path: Option<String>) {
    if let Ok(mut guard) = GROTH16_SETUP_BLOB_PATH_OVERRIDE.lock() {
        *guard = path;
    }
}

pub fn with_groth16_setup_blob_path_override<T, F: FnOnce() -> T>(path: Option<String>, f: F) -> T {
    let old = groth16_setup_blob_path_override();
    set_groth16_setup_blob_path_override(path);
    let result = f();
    set_groth16_setup_blob_path_override(old);
    result
}

pub fn groth16_setup_blob_path_override() -> Option<String> {
    GROTH16_SETUP_BLOB_PATH_OVERRIDE
        .lock()
        .ok()
        .and_then(|guard| guard.clone())
}

pub fn compiled_uses_trusted_imported_groth16_setup(compiled: &CompiledProgram) -> bool {
    compiled.backend == BackendKind::ArkworksGroth16
        && compiled
            .metadata
            .get(GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY)
            .map(String::as_str)
            == Some(GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY)
        && compiled
            .metadata
            .get(GROTH16_SETUP_PROVENANCE_METADATA_KEY)
            .map(String::as_str)
            == Some(GROTH16_IMPORTED_SETUP_PROVENANCE)
}

pub fn compiled_uses_local_ceremony_streamed_groth16_setup(compiled: &CompiledProgram) -> bool {
    compiled.backend == BackendKind::ArkworksGroth16
        && compiled
            .metadata
            .get(GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY)
            .map(String::as_str)
            == Some(GROTH16_LOCAL_CEREMONY_STREAMED_SECURITY_BOUNDARY)
        && compiled
            .metadata
            .get(GROTH16_SETUP_PROVENANCE_METADATA_KEY)
            .map(String::as_str)
            == Some(GROTH16_LOCAL_CEREMONY_STREAMED_PROVENANCE)
        && compiled
            .metadata
            .get(GROTH16_STREAMED_SETUP_STORAGE_METADATA_KEY)
            .map(String::as_str)
            == Some(GROTH16_STREAMED_SETUP_STORAGE_VALUE)
        && compiled
            .metadata
            .contains_key(GROTH16_STREAMED_PK_PATH_METADATA_KEY)
        && compiled
            .metadata
            .contains_key(GROTH16_STREAMED_SHAPE_PATH_METADATA_KEY)
}

pub fn compiled_uses_auto_ceremony_groth16_setup(compiled: &CompiledProgram) -> bool {
    compiled.backend == BackendKind::ArkworksGroth16
        && compiled
            .metadata
            .get(GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY)
            .map(String::as_str)
            == Some(GROTH16_AUTO_CEREMONY_SECURITY_BOUNDARY)
        && compiled
            .metadata
            .get(GROTH16_SETUP_PROVENANCE_METADATA_KEY)
            .map(String::as_str)
            == Some(GROTH16_AUTO_CEREMONY_PROVENANCE)
        && compiled
            .metadata
            .contains_key(GROTH16_CEREMONY_SUBSYSTEM_METADATA_KEY)
        && compiled
            .metadata
            .contains_key(GROTH16_CEREMONY_ID_METADATA_KEY)
        && compiled
            .metadata
            .contains_key(GROTH16_CEREMONY_KIND_METADATA_KEY)
        && compiled
            .metadata
            .contains_key(GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY)
        && compiled
            .metadata
            .contains_key(GROTH16_CEREMONY_REPORT_SHA256_METADATA_KEY)
        && compiled
            .metadata
            .contains_key(GROTH16_CEREMONY_SEED_COMMITMENT_METADATA_KEY)
}

pub fn ensure_security_covered_groth16_setup(compiled: &CompiledProgram) -> ZkfResult<()> {
    if compiled.backend != BackendKind::ArkworksGroth16 {
        return Ok(());
    }

    if compiled_uses_trusted_imported_groth16_setup(compiled)
        || compiled_uses_local_ceremony_streamed_groth16_setup(compiled)
        || compiled_uses_auto_ceremony_groth16_setup(compiled)
        || allow_dev_deterministic_groth16()
    {
        return Ok(());
    }

    let boundary = compiled
        .metadata
        .get(GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY)
        .map(String::as_str)
        .unwrap_or("unspecified");
    let provenance = compiled
        .metadata
        .get(GROTH16_SETUP_PROVENANCE_METADATA_KEY)
        .map(String::as_str)
        .unwrap_or("unspecified");

    Err(ZkfError::Backend(format!(
        "security-covered Groth16 proving requires imported trusted CRS material, a fully reported subsystem auto-ceremony compile, or a streamed local-ceremony setup bound to the compiled program. Recompile with program metadata key '{}' (or env '{}') pointing to a trusted setup blob, or recompile without a setup override so the subsystem auto-ceremony report is materialized, or use the local-ceremony streamed setup lane, or set '{}' / the matching override only for explicit development testing. Current boundary={boundary}, provenance={provenance}.",
        GROTH16_SETUP_BLOB_PATH_METADATA_KEY,
        GROTH16_SETUP_BLOB_PATH_ENV,
        ALLOW_DEV_DETERMINISTIC_GROTH16_ENV,
    )))
}

pub fn parse_backend_selection(value: &str) -> Result<BackendSelection, String> {
    match value {
        "sp1-compat" | "sp1_compat" => Ok(BackendSelection {
            backend: BackendKind::Sp1,
            route: BackendRoute::ExplicitCompat,
            requested_name: "sp1-compat".to_string(),
        }),
        "risc-zero-compat" | "risc_zero_compat" | "risc0-compat" | "risc0_compat" => {
            Ok(BackendSelection {
                backend: BackendKind::RiscZero,
                route: BackendRoute::ExplicitCompat,
                requested_name: "risc-zero-compat".to_string(),
            })
        }
        other => Ok(BackendSelection {
            backend: other.parse::<BackendKind>()?,
            route: BackendRoute::Auto,
            requested_name: other.to_string(),
        }),
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub fn capability_report_for_backend(kind: BackendKind) -> Option<CapabilityReport> {
    let capabilities = crate::capabilities_matrix()
        .into_iter()
        .find(|capabilities| capabilities.backend == kind)?;
    Some(crate::metal_runtime::capability_report_with_runtime(
        capabilities,
        &crate::metal_runtime::metal_runtime_report(),
    ))
}

pub fn validate_backend_selection_identity(selection: &BackendSelection) -> Result<(), String> {
    if selection.route == BackendRoute::ExplicitCompat {
        if backend_surface_status(selection.backend).compat_available {
            return Ok(());
        }
        return Err(format!(
            "backend '{}' does not expose an explicit compatibility route in this build",
            selection.requested_name
        ));
    }

    let capabilities = backend_for(selection.backend).capabilities();
    if capabilities.mode != zkf_core::BackendMode::Compat {
        return Ok(());
    }

    let alias = match selection.backend {
        BackendKind::Sp1 => Some("sp1-compat"),
        BackendKind::RiscZero => Some("risc-zero-compat"),
        _ => None,
    };
    if let Some(alias) = alias {
        return Err(format!(
            "backend '{}' is reserved for the native backend, but this build only exposes the compatibility implementation. Request '{}' explicitly.",
            selection.requested_name, alias
        ));
    }

    Err(format!(
        "backend '{}' resolves to a compatibility backend in this build. Build with native support before using this public backend name.",
        selection.requested_name
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub fn ensure_backend_selection_production_ready(
    selection: &BackendSelection,
) -> Result<(), String> {
    if selection.route != BackendRoute::Auto {
        return Ok(());
    }

    let report = capability_report_for_backend(selection.backend).ok_or_else(|| {
        format!(
            "missing capability report for backend '{}'",
            selection.requested_name
        )
    })?;
    if report.production_ready {
        return Ok(());
    }

    Err(format!(
        "backend '{}' is not production-ready on this host (readiness={}, reason={}). {}",
        selection.requested_name,
        report.readiness,
        report.readiness_reason.as_deref().unwrap_or("not-ready"),
        report.operator_action.as_deref().unwrap_or(
            "Install the required native toolchain or choose a backend that is ready on this host."
        )
    ))
}

#[cfg(target_arch = "wasm32")]
pub fn ensure_backend_selection_production_ready(
    _selection: &BackendSelection,
) -> Result<(), String> {
    Ok(())
}

pub fn backend_for(kind: BackendKind) -> Box<dyn BackendEngine> {
    #[cfg(target_arch = "wasm32")]
    {
        Box::new(WasmUnavailableBackend::new(kind))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        init_accelerators();
        harden_accelerators_for_current_pressure();
        match kind {
            BackendKind::Plonky3 => Box::new(Plonky3Backend),
            BackendKind::Halo2 => Box::new(Halo2Backend),
            BackendKind::Halo2Bls12381 => Box::new(Halo2Bls12381Backend),
            BackendKind::ArkworksGroth16 => Box::new(ArkworksGroth16Backend),
            BackendKind::Sp1 => sp1_engine(),
            BackendKind::RiscZero => risc_zero_engine(),
            BackendKind::Nova => nova_engine(),
            BackendKind::HyperNova => Box::new(HyperNovaBackend),
            BackendKind::MidnightCompact => midnight_engine(),
        }
    }
}

#[allow(clippy::match_like_matches_macro)]
pub fn backend_surface_status(kind: BackendKind) -> BackendSurfaceStatus {
    let implementation_type = match kind {
        BackendKind::Sp1 if !cfg!(feature = "native-sp1") => SupportClass::Delegated,
        BackendKind::RiscZero if !cfg!(feature = "native-risc-zero") => SupportClass::Delegated,
        BackendKind::Nova if !cfg!(feature = "native-nova") => SupportClass::Delegated,
        BackendKind::HyperNova if !cfg!(feature = "native-nova") => SupportClass::Delegated,
        _ => SupportClass::Native,
    };

    let compiled_in = match kind {
        BackendKind::Sp1 => cfg!(feature = "native-sp1"),
        BackendKind::RiscZero => cfg!(feature = "native-risc-zero"),
        BackendKind::Nova | BackendKind::HyperNova => cfg!(feature = "native-nova"),
        _ => true,
    };

    let compat_available = matches!(kind, BackendKind::Sp1 | BackendKind::RiscZero);

    BackendSurfaceStatus {
        implementation_type,
        compiled_in,
        compat_available,
    }
}

pub fn backend_for_route(kind: BackendKind, route: BackendRoute) -> Box<dyn BackendEngine> {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = route;
        backend_for(kind)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        init_accelerators();
        harden_accelerators_for_current_pressure();
        match (kind, route) {
            (BackendKind::Sp1, BackendRoute::ExplicitCompat) => Box::new(compat::Sp1Backend),
            (BackendKind::RiscZero, BackendRoute::ExplicitCompat) => {
                Box::new(risc_zero::RiscZeroBackend)
            }
            _ => backend_for(kind),
        }
    }
}

pub fn backend_for_selection(
    selection: &BackendSelection,
) -> Result<Box<dyn BackendEngine>, String> {
    validate_backend_selection_identity(selection)?;
    Ok(backend_for_route(selection.backend, selection.route))
}

pub fn preferred_backend_for_program(program: &Program) -> BackendKind {
    preferred_backend_for_field(program.field)
}

pub fn prepare_witness_for_proving(
    compiled: &CompiledProgram,
    witness: &Witness,
) -> ZkfResult<Witness> {
    audited_backend::audited_witness_for_proving(compiled.backend, compiled, witness)
}

pub fn preferred_backend_for_field(field: FieldId) -> BackendKind {
    match field {
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => BackendKind::Plonky3,
        FieldId::PastaFp | FieldId::PastaFq => BackendKind::Halo2,
        FieldId::Bls12_381 => BackendKind::Halo2Bls12381,
        FieldId::Bn254 => BackendKind::ArkworksGroth16,
    }
}

pub fn metal_first_benchmark_backends() -> Vec<BackendKind> {
    let mut backends = vec![BackendKind::Plonky3];
    if strict_bn254_auto_route_ready() {
        backends.push(BackendKind::ArkworksGroth16);
    }
    backends
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-sp1"))]
fn sp1_engine() -> Box<dyn BackendEngine> {
    Box::new(Sp1NativeBackend)
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "native-sp1")))]
fn sp1_engine() -> Box<dyn BackendEngine> {
    Box::new(Sp1Backend)
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-risc-zero"))]
fn risc_zero_engine() -> Box<dyn BackendEngine> {
    Box::new(RiscZeroNativeBackend)
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "native-risc-zero")))]
fn risc_zero_engine() -> Box<dyn BackendEngine> {
    Box::new(RiscZeroBackend)
}

#[cfg(all(not(target_arch = "wasm32"), feature = "native-nova"))]
fn nova_engine() -> Box<dyn BackendEngine> {
    Box::new(NovaNativeBackend)
}

#[cfg(all(not(target_arch = "wasm32"), not(feature = "native-nova")))]
fn nova_engine() -> Box<dyn BackendEngine> {
    Box::new(NovaBackend)
}

#[cfg(not(target_arch = "wasm32"))]
fn midnight_engine() -> Box<dyn BackendEngine> {
    Box::new(MidnightNativeBackend)
}

#[derive(Debug, Clone)]
pub struct NativeFoldResult {
    pub steps: usize,
    pub compressed: bool,
    pub artifact: ProofArtifact,
}

/// Fold multiple witnesses through a compiled circuit using IVC when available.
///
/// When the `native-nova` feature is on and the backend is Nova, this uses
/// real Nova recursive folding via `prove_step` chaining. Otherwise, returns
/// `None` to signal the caller should use prove-per-step.
#[cfg(all(not(target_arch = "wasm32"), feature = "native-nova"))]
pub fn try_fold_native(
    compiled: &CompiledProgram,
    step_witnesses: &[Witness],
    compress: bool,
) -> Option<ZkfResult<NativeFoldResult>> {
    if compiled.backend != BackendKind::Nova {
        return None;
    }
    Some(
        nova_native::fold_native(compiled, step_witnesses, compress).map(|result| {
            NativeFoldResult {
                steps: result.steps,
                compressed: result.compressed,
                artifact: result.artifact,
            }
        }),
    )
}

#[cfg(any(target_arch = "wasm32", not(feature = "native-nova")))]
pub fn try_fold_native(
    _compiled: &CompiledProgram,
    _step_witnesses: &[Witness],
    _compress: bool,
) -> Option<ZkfResult<NativeFoldResult>> {
    None
}

/// Verify a folded Nova IVC proof produced by `try_fold_native`.
///
/// Returns `None` if native Nova is not available.
#[cfg(all(not(target_arch = "wasm32"), feature = "native-nova"))]
pub fn try_verify_fold_native(
    compiled: &CompiledProgram,
    artifact: &ProofArtifact,
) -> Option<ZkfResult<bool>> {
    if compiled.backend != BackendKind::Nova {
        return None;
    }
    Some(nova_native::verify_fold_native(compiled, artifact))
}

#[cfg(any(target_arch = "wasm32", not(feature = "native-nova")))]
pub fn try_verify_fold_native(
    _compiled: &CompiledProgram,
    _artifact: &ProofArtifact,
) -> Option<ZkfResult<bool>> {
    None
}

pub fn capabilities_matrix() -> Vec<BackendCapabilities> {
    [
        BackendKind::Plonky3,
        BackendKind::Halo2,
        BackendKind::Halo2Bls12381,
        BackendKind::ArkworksGroth16,
        BackendKind::Sp1,
        BackendKind::RiscZero,
        BackendKind::Nova,
        BackendKind::HyperNova,
        BackendKind::MidnightCompact,
    ]
    .iter()
    .map(|kind| backend_for(*kind).capabilities())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_explicit_compat_aliases() {
        let sp1 = parse_backend_selection("sp1-compat").expect("sp1 compat");
        assert_eq!(sp1.backend, BackendKind::Sp1);
        assert_eq!(sp1.route, BackendRoute::ExplicitCompat);

        let risc_zero = parse_backend_selection("risc-zero-compat").expect("risc0 compat");
        assert_eq!(risc_zero.backend, BackendKind::RiscZero);
        assert_eq!(risc_zero.route, BackendRoute::ExplicitCompat);
    }

    #[test]
    fn reserved_native_names_fail_closed_when_only_compat_exists() {
        let selection = parse_backend_selection("sp1").expect("sp1 selection");
        if backend_for(selection.backend).capabilities().mode == zkf_core::BackendMode::Compat {
            let err = validate_backend_selection_identity(&selection)
                .expect_err("compat should fail closed");
            assert!(err.contains("sp1-compat"));
        }
    }
}
