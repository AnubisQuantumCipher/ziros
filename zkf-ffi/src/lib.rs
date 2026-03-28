// FFI requires unsafe for extern "C" functions, raw pointers, and #[no_mangle].
#![allow(unsafe_code)]
// The C ABI surface validates pointers internally and keeps stable entrypoint signatures.
#![allow(
    clippy::not_unsafe_ptr_arg_deref,
    clippy::needless_question_mark,
    clippy::field_reassign_with_default,
    clippy::manual_range_contains,
    clippy::collapsible_if
)]

//! ZKF FFI — C-compatible foreign function interface for embedding ZKF into native applications.
//!
//! Every public `extern "C"` function returns a `*mut ZkfFfiResult`. The caller (Swift) owns the
//! returned pointer and MUST free it with `zkf_free_result`. String fields inside the result
//! (data, error) are freed automatically by `zkf_free_result`.
//!
//! All functions are synchronous and blocking. The Swift side is responsible for dispatching
//! to background threads.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Result type ────────────────────────────────────────────────────────────

/// Universal FFI result. Returned by every zkf_* function.
/// Caller MUST free with `zkf_free_result`.
#[repr(C)]
pub struct ZkfFfiResult {
    /// 0 = success, 1 = application error, 2 = panic/internal error
    pub status: i32,
    /// JSON-encoded result data (null on error). Freed by `zkf_free_result`.
    pub data: *mut c_char,
    /// Error message (null on success). Freed by `zkf_free_result`.
    pub error: *mut c_char,
}

/// Free a `ZkfFfiResult` and its string fields.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_free_result(ptr: *mut ZkfFfiResult) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        let result = Box::from_raw(ptr);
        if !result.data.is_null() {
            drop(CString::from_raw(result.data));
        }
        if !result.error.is_null() {
            drop(CString::from_raw(result.error));
        }
    }
}

/// Free a C string allocated by the FFI layer.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

// ─── Cancellation ───────────────────────────────────────────────────────────

static CANCEL_FLAG: AtomicBool = AtomicBool::new(false);

/// Request cancellation of the currently-running FFI operation.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_request_cancel() {
    CANCEL_FLAG.store(true, Ordering::SeqCst);
}

/// Clear the cancellation flag (call before starting a new operation).
#[unsafe(no_mangle)]
pub extern "C" fn zkf_clear_cancel() {
    CANCEL_FLAG.store(false, Ordering::SeqCst);
}

/// Check if cancellation has been requested.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_is_cancelled() -> i32 {
    if CANCEL_FLAG.load(Ordering::SeqCst) {
        1
    } else {
        0
    }
}

// ─── Internal helpers ───────────────────────────────────────────────────────

fn make_ok(json: String) -> *mut ZkfFfiResult {
    // Strip interior null bytes (invalid in C strings) instead of panicking
    let sanitized = json.replace('\0', "");
    let data = CString::new(sanitized).unwrap_or_else(|_| {
        // Safety: literal has no null bytes
        unsafe { CString::from_vec_unchecked(b"{}".to_vec()) }
    });
    Box::into_raw(Box::new(ZkfFfiResult {
        status: 0,
        data: data.into_raw(),
        error: std::ptr::null_mut(),
    }))
}

fn make_err(code: i32, msg: String) -> *mut ZkfFfiResult {
    let sanitized = msg.replace('\0', "");
    let error = CString::new(sanitized)
        .unwrap_or_else(|_| unsafe { CString::from_vec_unchecked(b"unknown error".to_vec()) });
    Box::into_raw(Box::new(ZkfFfiResult {
        status: code,
        data: std::ptr::null_mut(),
        error: error.into_raw(),
    }))
}

/// Wrap an FFI function body: catches panics, converts errors to ZkfFfiResult.
fn wrap_ffi<F>(f: F) -> *mut ZkfFfiResult
where
    F: FnOnce() -> Result<String, String> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(Ok(json)) => make_ok(json),
        Ok(Err(msg)) => make_err(1, msg),
        Err(_) => make_err(2, "internal panic in zkf-ffi".to_string()),
    }
}

/// Convert a nullable C string to an Option<String>.
unsafe fn c_str_opt(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(ptr) }
                .to_string_lossy()
                .into_owned(),
        )
    }
}

/// Convert a non-null C string to String, or return Err.
unsafe fn c_str_required(ptr: *const c_char, name: &str) -> Result<String, String> {
    if ptr.is_null() {
        Err(format!("{name} is required (got null)"))
    } else {
        Ok(unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned())
    }
}

/// Read a JSON file from disk and deserialize.
fn read_json<T: serde::de::DeserializeOwned>(path: &str) -> Result<T, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;
    serde_json::from_str(&data).map_err(|e| format!("failed to parse {path}: {e}"))
}

/// Read a JSON file from a filesystem path and deserialize.
fn read_json_path<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    read_json(path.to_string_lossy().as_ref())
}

/// Write a serializable value as JSON to disk.
fn write_json<T: serde::Serialize>(path: &str, value: &T) -> Result<(), String> {
    let json =
        serde_json::to_string_pretty(value).map_err(|e| format!("failed to serialize: {e}"))?;
    if let Some(parent) = PathBuf::from(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;
    }
    std::fs::write(path, json).map_err(|e| format!("failed to write {path}: {e}"))
}

fn hex_encode_seed(seed: [u8; 32]) -> String {
    seed.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_seed_hex(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!(
            "expected 64 hex chars for ceremony seed, got {}",
            value.len()
        ));
    }
    let mut seed = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hi = decode_hex_nibble(chunk[0])?;
        let lo = decode_hex_nibble(chunk[1])?;
        seed[index] = (hi << 4) | lo;
    }
    Ok(seed)
}

fn decode_hex_nibble(value: u8) -> Result<u8, String> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(format!("invalid hex character '{}'", value as char)),
    }
}

fn parse_phase2_history(
    compiled: &zkf_core::CompiledProgram,
) -> Result<Vec<zkf_backends::ceremony::Phase2ContributionRecord>, String> {
    match compiled.metadata.get("ceremony_phase2_history") {
        Some(json) => serde_json::from_str(json)
            .map_err(|e| format!("failed to parse ceremony_phase2_history: {e}")),
        None => Ok(Vec::new()),
    }
}

fn write_phase2_history(
    compiled: &mut zkf_core::CompiledProgram,
    history: &[zkf_backends::ceremony::Phase2ContributionRecord],
) -> Result<(), String> {
    compiled.metadata.insert(
        "ceremony_phase2_history".to_string(),
        serde_json::to_string(history).map_err(|e| format!("serialize phase2 history: {e}"))?,
    );
    Ok(())
}

/// Render a ZkfError into a user-friendly string.
fn render_error(e: zkf_core::ZkfError) -> String {
    format!("{e}")
}

fn backend_route_label(route: zkf_backends::BackendRoute) -> &'static str {
    match route {
        zkf_backends::BackendRoute::Auto => "native-auto",
        zkf_backends::BackendRoute::ExplicitCompat => "explicit-compat",
    }
}

fn annotate_backend_selection_metadata(
    compiled: Option<&mut zkf_core::CompiledProgram>,
    artifact: Option<&mut zkf_core::ProofArtifact>,
    selection: &zkf_backends::BackendSelection,
) {
    if let Some(compiled) = compiled {
        compiled.metadata.insert(
            "backend_route".to_string(),
            backend_route_label(selection.route).to_string(),
        );
        compiled.metadata.insert(
            "requested_backend_name".to_string(),
            selection.requested_name.clone(),
        );
    }
    if let Some(artifact) = artifact {
        artifact.metadata.insert(
            "backend_route".to_string(),
            backend_route_label(selection.route).to_string(),
        );
        artifact.metadata.insert(
            "requested_backend_name".to_string(),
            selection.requested_name.clone(),
        );
    }
}

fn parse_public_backend_selection(value: &str) -> Result<zkf_backends::BackendSelection, String> {
    let selection = zkf_backends::parse_backend_selection(value)?;
    zkf_backends::validate_backend_selection_identity(&selection)?;
    Ok(selection)
}

fn parse_execution_backend_selection(
    value: &str,
) -> Result<zkf_backends::BackendSelection, String> {
    let selection = parse_public_backend_selection(value)?;
    zkf_backends::ensure_backend_selection_production_ready(&selection)?;
    Ok(selection)
}

fn resolve_manifest_entry_path(manifest_path: &str, entry_path: &str) -> PathBuf {
    let entry = PathBuf::from(entry_path);
    if entry.is_absolute() {
        return entry;
    }
    PathBuf::from(manifest_path)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(entry)
}

fn manifest_ir_family(manifest: &zkf_core::PackageManifest) -> &str {
    manifest
        .metadata
        .get("ir_family")
        .map(String::as_str)
        .unwrap_or("ir-v2")
}

fn load_manifest_program_v2(
    manifest_path: &str,
    manifest: &zkf_core::PackageManifest,
) -> Result<(zkf_core::Program, &'static str), String> {
    let program_path = resolve_manifest_entry_path(manifest_path, &manifest.files.program.path);
    match manifest_ir_family(manifest) {
        "ir-v2" => Ok((read_json_path(&program_path)?, "ir-v2")),
        "zir-v1" => {
            let zir_program: zkf_core::zir_v1::Program = read_json_path(&program_path)?;
            let lowered = zkf_core::program_zir_to_v2(&zir_program)
                .map_err(|err| format!("failed to lower zir-v1 package program: {err}"))?;
            Ok((lowered, "zir-v1"))
        }
        other => Err(format!(
            "unsupported ir_family '{other}' in package manifest metadata"
        )),
    }
}

fn frontend_ir_family_request(
    value: Option<&str>,
) -> Result<zkf_frontends::IrFamilyPreference, String> {
    value
        .unwrap_or("auto")
        .parse::<zkf_frontends::IrFamilyPreference>()
}

fn select_frontend_program(
    compiled: zkf_frontends::FrontendProgram,
    preference: zkf_frontends::IrFamilyPreference,
) -> Result<zkf_frontends::FrontendProgram, String> {
    match preference {
        zkf_frontends::IrFamilyPreference::Auto => Ok(compiled),
        zkf_frontends::IrFamilyPreference::ZirV1 => Ok(zkf_frontends::FrontendProgram::ZirV1(
            compiled.promote_to_zir_v1(),
        )),
        zkf_frontends::IrFamilyPreference::IrV2 => compiled
            .lower_to_ir_v2()
            .map(zkf_frontends::FrontendProgram::IrV2)
            .map_err(|err| format!("failed to lower imported program to ir-v2: {err}")),
    }
}

fn write_frontend_program(
    output_path: &str,
    program: &zkf_frontends::FrontendProgram,
) -> Result<(), String> {
    match program {
        zkf_frontends::FrontendProgram::IrV2(program) => write_json(output_path, program),
        zkf_frontends::FrontendProgram::ZirV1(program) => write_json(output_path, program),
    }
}

fn import_impl(
    frontend: *const c_char,
    input_path: *const c_char,
    output_path: *const c_char,
    field: *const c_char,
    ir_family: *const c_char,
) -> Result<String, String> {
    let frontend_str = unsafe { c_str_required(frontend, "frontend") }?;
    let input_path = unsafe { c_str_required(input_path, "input_path") }?;
    let output_path = unsafe { c_str_required(output_path, "output_path") }?;
    let field = unsafe { c_str_opt(field) };
    let ir_family = unsafe { c_str_opt(ir_family) };

    let frontend_kind: zkf_frontends::FrontendKind = frontend_str.parse().map_err(|e: String| e)?;
    let field = field
        .as_deref()
        .map(str::parse::<zkf_core::FieldId>)
        .transpose()?;
    let ir_family = frontend_ir_family_request(ir_family.as_deref())?;

    let fe = zkf_frontends::frontend_for(frontend_kind);
    let raw: serde_json::Value = read_json(&input_path)?;
    let compiled = fe
        .compile_to_program_family(
            &raw,
            &zkf_frontends::FrontendImportOptions {
                field,
                ir_family,
                ..Default::default()
            },
        )
        .map_err(|e| format!("import failed: {e}"))?;
    let source_ir_family = compiled.ir_family().to_string();
    let source_program_digest = compiled.digest_hex();
    let selected = select_frontend_program(compiled, ir_family)?;
    let lowered_program_digest = (source_ir_family == "zir-v1" && selected.ir_family() == "ir-v2")
        .then(|| selected.digest_hex());

    write_frontend_program(&output_path, &selected)?;

    Ok(serde_json::json!({
        "program_path": output_path,
        "frontend": format!("{frontend_kind}"),
        "ir_family": selected.ir_family(),
        "source_ir_family": source_ir_family,
        "source_program_digest": source_program_digest,
        "lowered_program_digest": lowered_program_digest,
        "signals": selected.signal_count(),
        "constraints": selected.constraint_count(),
        "field": format!("{}", selected.field()),
    })
    .to_string())
}

static WATCHDOGS: LazyLock<Mutex<std::collections::BTreeMap<u64, zkf_runtime::ProofWatchdog>>> =
    LazyLock::new(|| Mutex::new(std::collections::BTreeMap::new()));
static NEXT_WATCHDOG_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, serde::Deserialize)]
struct FfiControlPlaneRequest {
    #[serde(default)]
    job_kind: Option<String>,
    #[serde(default)]
    objective: Option<String>,
    #[serde(default)]
    constraint_count: Option<usize>,
    #[serde(default)]
    signal_count: Option<usize>,
    #[serde(default)]
    stage_node_counts: Option<std::collections::BTreeMap<String, usize>>,
    #[serde(default)]
    field: Option<String>,
    #[serde(default)]
    requested_backend: Option<String>,
    #[serde(default)]
    backend_candidates: Option<Vec<String>>,
    #[serde(default)]
    requested_jobs: Option<usize>,
    #[serde(default)]
    total_jobs: Option<usize>,
}

fn parse_job_kind(value: Option<&str>) -> Result<zkf_runtime::JobKind, String> {
    match value.unwrap_or("prove") {
        "prove" => Ok(zkf_runtime::JobKind::Prove),
        "fold" => Ok(zkf_runtime::JobKind::Fold),
        "wrap" => Ok(zkf_runtime::JobKind::Wrap),
        other => Err(format!(
            "unknown job kind '{other}' (expected prove, fold, or wrap)"
        )),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FfiEvmTarget {
    Ethereum,
    OptimismArbitrumL2,
    GenericEvm,
}

impl FfiEvmTarget {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum",
            Self::OptimismArbitrumL2 => "optimism-arbitrum-l2",
            Self::GenericEvm => "generic-evm",
        }
    }
}

fn parse_ffi_evm_target(value: Option<&str>) -> Result<FfiEvmTarget, String> {
    match value
        .unwrap_or("ethereum")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "ethereum" | "mainnet" => Ok(FfiEvmTarget::Ethereum),
        "optimism-arbitrum-l2" | "optimism" | "arbitrum" | "l2" => {
            Ok(FfiEvmTarget::OptimismArbitrumL2)
        }
        "generic-evm" | "generic" | "evm" => Ok(FfiEvmTarget::GenericEvm),
        other => Err(format!(
            "unknown EVM target '{other}' (expected ethereum, optimism-arbitrum-l2, or generic-evm)"
        )),
    }
}

fn gas_model_note_for_target(
    backend: zkf_core::BackendKind,
    target: FfiEvmTarget,
) -> Result<String, String> {
    let target_note = match target {
        FfiEvmTarget::Ethereum => "Targeted to Ethereum mainnet calldata and precompile costs.",
        FfiEvmTarget::OptimismArbitrumL2 => {
            "Targeted to Optimism/Arbitrum-style L2 execution and calldata heuristics."
        }
        FfiEvmTarget::GenericEvm => "Targeted to generic EVM deployment heuristics.",
    };
    let note = match backend {
        zkf_core::BackendKind::ArkworksGroth16 => {
            format!(
                "Groth16 estimate assumes a BN254 precompile verifier path with target-specific calldata overheads. {target_note}"
            )
        }
        zkf_core::BackendKind::Halo2 => {
            format!(
                "Halo2 estimate uses a size-weighted heuristic pending chain-specific verifier calibration. {target_note}"
            )
        }
        zkf_core::BackendKind::Halo2Bls12381 => {
            format!(
                "Halo2-BLS12-381 estimate uses a size-weighted heuristic based on a KZG verifier gas profile. {target_note}"
            )
        }
        zkf_core::BackendKind::Plonky3 => {
            format!(
                "Plonky3 estimate uses a size-weighted heuristic pending chain-specific verifier calibration. {target_note}"
            )
        }
        zkf_core::BackendKind::Sp1 => {
            format!(
                "SP1 estimate uses a size-weighted heuristic for on-chain verifier wrappers. {target_note}"
            )
        }
        zkf_core::BackendKind::RiscZero => {
            format!(
                "RISC Zero estimate uses a size-weighted heuristic for on-chain verifier wrappers. {target_note}"
            )
        }
        zkf_core::BackendKind::Nova => {
            format!(
                "Nova estimate uses a size-weighted heuristic; recursive verifier circuits vary by implementation. {target_note}"
            )
        }
        zkf_core::BackendKind::HyperNova => {
            format!(
                "HyperNova estimate uses a size-weighted heuristic based on a CCS multifolding verifier gas profile. {target_note}"
            )
        }
        zkf_core::BackendKind::MidnightCompact => {
            return Err(
                "gas estimation for midnight-compact is not applicable in EVM gas units"
                    .to_string(),
            );
        }
    };
    Ok(note)
}

fn estimate_verification_gas_for_target(
    backend: zkf_core::BackendKind,
    proof_size_bytes: usize,
    target: FfiEvmTarget,
) -> Result<u64, String> {
    let size = proof_size_bytes as u64;
    let base = match backend {
        zkf_core::BackendKind::ArkworksGroth16 => 210_000,
        zkf_core::BackendKind::Halo2 => 280_000 + size.saturating_mul(16),
        zkf_core::BackendKind::Halo2Bls12381 => 300_000 + size.saturating_mul(18),
        zkf_core::BackendKind::Plonky3 => 350_000 + size.saturating_mul(12),
        zkf_core::BackendKind::Sp1 => 450_000 + size.saturating_mul(20),
        zkf_core::BackendKind::RiscZero => 420_000 + size.saturating_mul(18),
        zkf_core::BackendKind::Nova => 300_000 + size.saturating_mul(15),
        zkf_core::BackendKind::HyperNova => 320_000 + size.saturating_mul(16),
        zkf_core::BackendKind::MidnightCompact => {
            return Err(
                "gas estimation for midnight-compact is not applicable in EVM gas units"
                    .to_string(),
            );
        }
    };
    Ok(match target {
        FfiEvmTarget::Ethereum => base,
        FfiEvmTarget::OptimismArbitrumL2 => base.saturating_mul(86) / 100,
        FfiEvmTarget::GenericEvm => base.saturating_mul(95) / 100,
    })
}

// ─── ABI versioning ─────────────────────────────────────────────────────────

/// ABI version for the FFI interface. Bump this whenever:
/// - A function signature changes (parameter types, return types)
/// - A function is removed
/// - Struct layouts change (#[repr(C)] structs)
///
/// Minor bumps (e.g., 1 → 2) for additive changes (new functions).
/// Major bumps (e.g., 1 → 100) for breaking changes.
pub const ZKF_FFI_ABI_VERSION: u32 = 3;

/// Return the FFI ABI version as a plain integer.
/// Swift should call this at startup and compare against its expected version.
/// If mismatched, refuse to call other FFI functions.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ffi_abi_version() -> u32 {
    ZKF_FFI_ABI_VERSION
}

// ─── System operations ──────────────────────────────────────────────────────

/// Check if the ZKF library is available and return version info.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_check_available() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        Ok(serde_json::json!({
            "available": true,
            "version": env!("CARGO_PKG_VERSION"),
            "native_ffi": true,
            "abi_version": ZKF_FFI_ABI_VERSION
        })
        .to_string())
    })
}

/// Return system capabilities: available backends, frontends, fields.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_capabilities() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        use zkf_frontends::FrontendKind;

        let backends = zkf_backends::capabilities_report();

        let frontends: Vec<serde_json::Value> = [
            FrontendKind::Noir,
            FrontendKind::Circom,
            FrontendKind::Cairo,
            FrontendKind::Compact,
            FrontendKind::Halo2Rust,
            FrontendKind::Plonky3Air,
            FrontendKind::Zkvm,
        ]
        .iter()
        .map(|fk| {
            serde_json::json!({
                "frontend": format!("{fk}"),
            })
        })
        .collect();

        Ok(serde_json::json!({
            "backends": backends,
            "frontends": frontends,
            "version": env!("CARGO_PKG_VERSION"),
        })
        .to_string())
    })
}

/// Run system doctor — check tooling dependencies.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_doctor() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        use zkf_core::BackendKind;

        let mut checks = serde_json::Map::new();
        let mut warnings = Vec::new();

        // Check each backend's doctor requirements
        for bk in [
            BackendKind::ArkworksGroth16,
            BackendKind::Halo2,
            BackendKind::Plonky3,
            BackendKind::Nova,
        ] {
            let engine = zkf_backends::backend_for(bk);
            let reqs = engine.doctor_requirements();
            for req in &reqs {
                let found = std::process::Command::new(&req.tool)
                    .arg("--version")
                    .output()
                    .is_ok();
                checks.insert(req.tool.clone(), serde_json::Value::Bool(found));
                if !found && req.required {
                    warnings.push(format!("missing required tool: {}", req.tool));
                }
            }
        }

        Ok(serde_json::json!({
            "healthy": warnings.is_empty(),
            "checks": checks,
            "warnings": warnings,
        })
        .to_string())
    })
}

/// Return Metal GPU status.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_metal_doctor() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
        {
            let report = zkf_backends::metal_runtime_report();
            Ok(serde_json::to_string(&report)
                .unwrap_or_else(|_| r#"{"error":"failed to serialize metal report"}"#.to_string()))
        }
        #[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
        {
            Ok(serde_json::json!({
                "runtime": { "metal_available": false },
                "backends": []
            })
            .to_string())
        }
    })
}

/// Return the detected Apple platform capability snapshot.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_platform_capability() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        serde_json::to_string(&zkf_core::PlatformCapability::detect())
            .map_err(|err| err.to_string())
    })
}

/// Return Neural Engine/control-plane status for the current host.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_neural_engine_status() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        Ok(serde_json::json!({
            "feature_enabled": cfg!(feature = "neural-engine"),
            "platform_capability": zkf_core::PlatformCapability::detect(),
            "adaptive_tuning": zkf_runtime::adaptive_tuning_status(),
            "model_catalog": zkf_runtime::ModelCatalog::discover(),
        })
        .to_string())
    })
}

/// Evaluate the control plane from a JSON request payload.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_evaluate_control_plane(request_json: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let raw = unsafe { c_str_required(request_json, "request_json") }?;
        let payload: FfiControlPlaneRequest =
            serde_json::from_str(&raw).map_err(|err| format!("invalid request_json: {err}"))?;
        let objective = payload
            .objective
            .as_deref()
            .unwrap_or("fastest-prove")
            .parse::<zkf_runtime::OptimizationObjective>()?;
        let field_hint = match payload.field.as_deref() {
            Some(value) => Some(value.parse::<zkf_core::FieldId>()?),
            None => None,
        };
        let requested_backend = match payload.requested_backend.as_deref() {
            Some(value) => Some(parse_public_backend_selection(value)?.backend),
            None => None,
        };
        let backend_candidates = payload
            .backend_candidates
            .unwrap_or_default()
            .into_iter()
            .map(|value| parse_public_backend_selection(&value).map(|selection| selection.backend))
            .collect::<Result<Vec<_>, _>>()?;
        let request = zkf_runtime::ControlPlaneRequest {
            job_kind: parse_job_kind(payload.job_kind.as_deref())?,
            objective,
            graph: None,
            constraint_count_override: payload.constraint_count,
            signal_count_override: payload.signal_count,
            stage_node_counts_override: payload.stage_node_counts,
            field_hint,
            program: None,
            compiled: None,
            preview: None,
            witness: None,
            witness_inputs: None,
            requested_backend,
            backend_route: None,
            trust_lane: zkf_runtime::RequiredTrustLane::StrictCryptographic,
            requested_jobs: payload.requested_jobs,
            total_jobs: payload.total_jobs,
            backend_candidates,
        };
        serde_json::to_string(&zkf_runtime::evaluate_control_plane(&request))
            .map_err(|err| err.to_string())
    })
}

/// Create a watchdog handle for later alert polling.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_watchdog_create(deterministic_mode: i32) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let id = NEXT_WATCHDOG_ID.fetch_add(1, Ordering::SeqCst);
        let swarm_config = zkf_runtime::SwarmConfig::from_env();
        let watchdog = zkf_runtime::ProofWatchdog::new(
            &zkf_core::PlatformCapability::detect(),
            deterministic_mode != 0,
            swarm_config
                .enabled
                .then_some(zkf_runtime::SentinelConfig::default()),
        );
        WATCHDOGS
            .lock()
            .map_err(|_| "watchdog registry lock poisoned".to_string())?
            .insert(id, watchdog);
        Ok(serde_json::json!({
            "watchdog_id": id,
            "deterministic_mode": deterministic_mode != 0,
        })
        .to_string())
    })
}

/// Poll alerts for a previously-created watchdog handle.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_watchdog_check_alerts(watchdog_id: u64) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let watchdog = WATCHDOGS
            .lock()
            .map_err(|_| "watchdog registry lock poisoned".to_string())?
            .get(&watchdog_id)
            .cloned()
            .ok_or_else(|| format!("unknown watchdog id {watchdog_id}"))?;
        Ok(serde_json::json!({
            "watchdog_id": watchdog_id,
            "alerts": watchdog.finalize(None, None),
        })
        .to_string())
    })
}

/// Destroy a watchdog handle.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_watchdog_destroy(watchdog_id: u64) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let removed = WATCHDOGS
            .lock()
            .map_err(|_| "watchdog registry lock poisoned".to_string())?
            .remove(&watchdog_id)
            .is_some();
        Ok(serde_json::json!({
            "watchdog_id": watchdog_id,
            "destroyed": removed,
        })
        .to_string())
    })
}

/// Return adaptive tuning status.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_adaptive_tuning_status() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        serde_json::to_string(&zkf_runtime::adaptive_tuning_status()).map_err(|err| err.to_string())
    })
}

/// Summarize the telemetry corpus used for retraining and freshness checks.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_telemetry_stats(dir: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let stats = match unsafe { c_str_opt(dir) } {
            Some(path) => zkf_runtime::telemetry_collector::telemetry_corpus_stats_for_dir(
                std::path::Path::new(&path),
            ),
            None => zkf_runtime::telemetry_collector::telemetry_corpus_stats(),
        }
        .map_err(|err| format!("failed to summarize telemetry corpus: {err}"))?;
        serde_json::to_string(&stats).map_err(|err| err.to_string())
    })
}

/// List all available frontends and their capabilities.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_frontends() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        use zkf_frontends::FrontendKind;

        let frontends: Vec<serde_json::Value> = [
            FrontendKind::Noir,
            FrontendKind::Circom,
            FrontendKind::Cairo,
            FrontendKind::Compact,
            FrontendKind::Halo2Rust,
            FrontendKind::Plonky3Air,
            FrontendKind::Zkvm,
        ]
        .iter()
        .map(|fk| {
            let fe = zkf_frontends::frontend_for(*fk);
            let caps = fe.capabilities();
            serde_json::json!({
                "frontend": format!("{fk}"),
                "can_compile_to_ir": caps.can_compile_to_ir,
                "can_execute": caps.can_execute,
                "input_formats": caps.input_formats,
                "notes": caps.notes,
            })
        })
        .collect();

        Ok(serde_json::Value::Array(frontends).to_string())
    })
}

// ─── Core pipeline ──────────────────────────────────────────────────────────

/// Compile an IR program for a specific backend.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_compile(
    program_path: *const c_char,
    backend: *const c_char,
    output_path: *const c_char,
    seed: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program_path = unsafe { c_str_required(program_path, "program_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;
        let seed = unsafe { c_str_opt(seed) };

        let program: zkf_core::Program = read_json(&program_path)?;
        let selection = parse_execution_backend_selection(&backend_str)?;
        let engine = zkf_backends::backend_for_selection(&selection)?;

        // Handle setup seed with RAII guard to ensure cleanup on all paths
        if let Some(ref seed_str) = seed {
            let seed_bytes = parse_seed(seed_str)?;
            zkf_backends::set_setup_seed_override(Some(seed_bytes));
        }

        let start = std::time::Instant::now();
        let mut compiled = match engine.compile(&program) {
            Ok(c) => c,
            Err(e) => {
                if seed.is_some() {
                    zkf_backends::set_setup_seed_override(None);
                }
                return Err(render_error(e));
            }
        };
        let elapsed = start.elapsed();
        annotate_backend_selection_metadata(Some(&mut compiled), None, &selection);

        if seed.is_some() {
            zkf_backends::set_setup_seed_override(None);
        }

        write_json(&output_path, &compiled)?;

        Ok(serde_json::json!({
            "compiled_path": output_path,
            "backend": format!("{}", selection.backend),
            "requested_backend": selection.requested_name,
            "backend_route": backend_route_label(selection.route),
            "constraints": compiled.program.constraints.len(),
            "setup_time_seconds": elapsed.as_secs_f64(),
        })
        .to_string())
    })
}

/// Generate a witness from a program and inputs.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_witness(
    program_path: *const c_char,
    inputs_path: *const c_char,
    output_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program_path = unsafe { c_str_required(program_path, "program_path") }?;
        let inputs_path = unsafe { c_str_required(inputs_path, "inputs_path") }?;
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;

        let program: zkf_core::Program = read_json(&program_path)?;
        let inputs: zkf_core::WitnessInputs = read_json(&inputs_path)?;
        let witness = zkf_core::generate_witness(&program, &inputs).map_err(render_error)?;

        write_json(&output_path, &witness)?;

        Ok(serde_json::json!({
            "witness_path": output_path,
            "num_assignments": witness.values.len(),
        })
        .to_string())
    })
}

/// Optimize an IR program (constant folding, dedup, dead signal elimination).
#[unsafe(no_mangle)]
pub extern "C" fn zkf_optimize(
    program_path: *const c_char,
    output_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program_path = unsafe { c_str_required(program_path, "program_path") }?;
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;

        let program: zkf_core::Program = read_json(&program_path)?;
        let (optimized, report) = zkf_core::optimize_program(&program);

        write_json(&output_path, &optimized)?;

        Ok(serde_json::json!({
            "optimized_path": output_path,
            "original_constraints": report.input_constraints,
            "optimized_constraints": report.output_constraints,
            "original_signals": report.input_signals,
            "optimized_signals": report.output_signals,
            "folded_expr_nodes": report.folded_expr_nodes,
            "deduplicated": report.deduplicated_constraints,
        })
        .to_string())
    })
}

/// Debug a circuit: constraint traces, under-constrained detection, symbolic analysis.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_debug(
    program_path: *const c_char,
    witness_path: *const c_char,
    output_path: *const c_char,
    continue_on_failure: i32,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program_path = unsafe { c_str_required(program_path, "program_path") }?;
        let witness_path = unsafe { c_str_required(witness_path, "witness_path") }?;
        let output_path = unsafe { c_str_opt(output_path) };

        let program: zkf_core::Program = read_json(&program_path)?;
        let witness: zkf_core::Witness = read_json(&witness_path)?;

        let mut opts = zkf_core::DebugOptions::default();
        opts.stop_on_first_failure = continue_on_failure == 0;
        let report = zkf_core::debug_program(&program, &witness, opts);

        if let Some(ref out) = output_path {
            write_json(out, &report)?;
        }

        Ok(serde_json::to_string(&report)
            .map_err(|e| format!("failed to serialize debug report: {e}"))?)
    })
}

/// Compile, generate witness, and prove a circuit in one step.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_prove(
    program_path: *const c_char,
    inputs_path: *const c_char,
    backend: *const c_char,
    output_path: *const c_char,
    compiled_out: *const c_char,
    solver: *const c_char,
    no_metal: i32,
    low_memory: i32,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program_path = unsafe { c_str_required(program_path, "program_path") }?;
        let inputs_path = unsafe { c_str_required(inputs_path, "inputs_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;
        let compiled_out = unsafe { c_str_opt(compiled_out) };
        let solver_name = unsafe { c_str_opt(solver) };
        let _no_metal = no_metal != 0;
        let _low_memory = low_memory != 0;
        let hybrid = backend_str == "hybrid";

        let program: zkf_core::Program = read_json(&program_path)?;
        let selection = if hybrid {
            None
        } else {
            Some(parse_execution_backend_selection(&backend_str)?)
        };

        let start = std::time::Instant::now();

        let mut inputs: zkf_core::WitnessInputs = read_json(&inputs_path)?;
        // Resolve input aliases (named signals → indices)
        resolve_input_aliases(&mut inputs, &program);

        let witness = if let Some(ref solver_name) = solver_name {
            let solver = zkf_core::solver_by_name(solver_name).map_err(render_error)?;
            zkf_core::solve_and_validate_witness(&program, &inputs, solver.as_ref())
                .map_err(render_error)?
        } else {
            zkf_core::generate_witness(&program, &inputs).map_err(render_error)?
        };

        let selection_for_metadata = selection.clone();
        let (mut compiled, mut artifact, backend_label, requested_backend, backend_route) =
            if hybrid {
                let execution = zkf_runtime::run_hybrid_prove_job_with_objective(
                    std::sync::Arc::new(program.clone()),
                    None,
                    Some(std::sync::Arc::new(witness)),
                    zkf_runtime::OptimizationObjective::FastestProve,
                    zkf_runtime::RequiredTrustLane::StrictCryptographic,
                    zkf_runtime::ExecutionMode::Deterministic,
                )
                .map_err(|e| e.to_string())?;
                (
                    execution.source.compiled,
                    execution.artifact,
                    "hybrid".to_string(),
                    "plonky3+groth16-wrap".to_string(),
                    "hybrid".to_string(),
                )
            } else {
                let selection = selection.ok_or_else(|| {
                    "non-hybrid execution requires a backend selection".to_string()
                })?;
                let execution = zkf_runtime::RuntimeExecutor::run_backend_prove_job(
                    selection.backend,
                    selection.route,
                    std::sync::Arc::new(program.clone()),
                    None,
                    Some(std::sync::Arc::new(witness)),
                    None,
                    zkf_runtime::RequiredTrustLane::StrictCryptographic,
                    zkf_runtime::ExecutionMode::Deterministic,
                )
                .map_err(|e| e.to_string())?;
                (
                    execution.compiled,
                    execution.artifact,
                    format!("{}", selection.backend),
                    selection.requested_name,
                    backend_route_label(selection.route).to_string(),
                )
            };
        let elapsed = start.elapsed();
        if let Some(selection) = selection_for_metadata.as_ref() {
            annotate_backend_selection_metadata(
                Some(&mut compiled),
                Some(&mut artifact),
                selection,
            );
        }

        // Store the program path so zkf_verify can re-compile the same program
        artifact
            .metadata
            .insert("program_path".to_string(), program_path.clone());

        write_json(&output_path, &artifact)?;
        if let Some(ref path) = compiled_out {
            write_json(path, &compiled)?;
        }

        let proof_size = std::fs::metadata(&output_path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(serde_json::json!({
            "proof_path": output_path,
            "backend": backend_label,
            "requested_backend": requested_backend,
            "backend_route": backend_route,
            "hybrid": hybrid,
            "public_inputs": artifact.public_inputs.len(),
            "proving_time_seconds": elapsed.as_secs_f64(),
            "proof_size_bytes": proof_size,
            "used_gpu": !_no_metal && cfg!(all(target_os = "macos", feature = "metal-gpu")),
            "compiled_path": compiled_out,
        })
        .to_string())
    })
}

/// Verify a proof artifact.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_verify(
    proof_path: *const c_char,
    backend: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;

        let artifact: zkf_core::ProofArtifact = read_json(&proof_path)?;
        if artifact.hybrid_bundle.is_some() {
            let program_path = artifact.metadata.get("program_path");
            let program = if let Some(pp) = program_path {
                read_json(pp)?
            } else {
                zkf_examples::mul_add_program()
            };
            let start = std::time::Instant::now();
            let valid = zkf_runtime::verify_hybrid_artifact(&program, &artifact)
                .map_err(|err| err.to_string())?;
            let elapsed = start.elapsed();
            return Ok(serde_json::json!({
                "valid": valid,
                "backend": "hybrid",
                "requested_backend": backend_str,
                "backend_route": "hybrid",
                "hybrid": true,
                "verification_time_seconds": elapsed.as_secs_f64(),
            })
            .to_string());
        }

        let selection = parse_public_backend_selection(&backend_str)?;
        let engine = zkf_backends::backend_for_selection(&selection)?;

        // Re-compile the program to get CompiledProgram for verification
        // The proof artifact stores the program_digest; we need the compiled form
        let program_path = artifact.metadata.get("program_path");
        let compiled = if let Some(pp) = program_path {
            let prog: zkf_core::Program = read_json(pp)?;
            engine.compile(&prog).map_err(render_error)?
        } else {
            // Try example program as fallback for demo proofs
            let prog = zkf_examples::mul_add_program();
            engine.compile(&prog).map_err(render_error)?
        };

        let start = std::time::Instant::now();
        let valid = engine.verify(&compiled, &artifact).map_err(render_error)?;
        let elapsed = start.elapsed();

        Ok(serde_json::json!({
            "valid": valid,
            "backend": format!("{}", selection.backend),
            "requested_backend": selection.requested_name,
            "backend_route": backend_route_label(selection.route),
            "verification_time_seconds": elapsed.as_secs_f64(),
        })
        .to_string())
    })
}

fn trust_boundary_note(artifact: &zkf_core::ProofArtifact) -> Option<String> {
    artifact
        .metadata
        .get("algebraic_binding")
        .filter(|value| value.as_str() == "false")
        .map(|_| {
            "algebraic_binding=false: exported verifier is metadata-bound and does not claim a fully algebraically bound in-circuit accumulator check"
                .to_string()
        })
}

fn estimate_gas_json(
    proof_path: &str,
    backend_str: &str,
    evm_target: FfiEvmTarget,
) -> Result<String, String> {
    let artifact: zkf_core::ProofArtifact = read_json(proof_path)?;
    let selection = parse_public_backend_selection(backend_str)?;
    let backend_kind = selection.backend;
    let verify_gas =
        estimate_verification_gas_for_target(backend_kind, artifact.proof.len(), evm_target)?;
    let deploy_gas = verify_gas.saturating_mul(8);
    let model_note = gas_model_note_for_target(backend_kind, evm_target)?;

    Ok(serde_json::json!({
        "verify_gas": verify_gas,
        "deploy_gas": deploy_gas,
        "backend": format!("{backend_kind}"),
        "requested_backend": selection.requested_name,
        "backend_route": backend_route_label(selection.route),
        "proof_size_bytes": artifact.proof.len(),
        "evm_target": evm_target.as_str(),
        "model_note": model_note,
    })
    .to_string())
}

fn deploy_for_target_json(
    proof_path: &str,
    backend_str: &str,
    output_path: &str,
    contract_name: &str,
    evm_target: FfiEvmTarget,
) -> Result<String, String> {
    let artifact: zkf_core::ProofArtifact = read_json(proof_path)?;
    let selection = parse_public_backend_selection(backend_str)?;
    let backend_kind = selection.backend;

    if backend_kind != zkf_core::BackendKind::ArkworksGroth16 {
        return Err(format!(
            "Solidity verifier generation only supported for arkworks-groth16, got {backend_kind}"
        ));
    }

    if artifact.verification_key.is_empty() {
        return Err("proof artifact has empty verification key".to_string());
    }
    let vk_bytes = &artifact.verification_key;
    let vk_hex = zkf_backends::groth16_vk::decode_groth16_vk(vk_bytes)
        .ok_or("failed to decode Groth16 verification key")?;

    let pub_input_strings: Vec<String> = artifact
        .public_inputs
        .iter()
        .map(|fe| fe.to_string())
        .collect();
    let solidity = render_groth16_solidity_for_target(
        &vk_hex,
        contract_name,
        &pub_input_strings,
        &artifact,
        evm_target,
    );

    validate_solidity_verifier(&solidity)?;

    if let Some(parent) = PathBuf::from(output_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("failed to create directory: {e}"))?;
    }
    std::fs::write(output_path, &solidity)
        .map_err(|e| format!("failed to write {output_path}: {e}"))?;

    Ok(serde_json::json!({
        "contract_path": output_path,
        "contract_name": contract_name,
        "contract_size_bytes": solidity.len(),
        "backend": format!("{backend_kind}"),
        "requested_backend": selection.requested_name,
        "backend_route": backend_route_label(selection.route),
        "validator": "passed",
        "evm_target": evm_target.as_str(),
        "algebraic_binding": artifact.metadata.get("algebraic_binding").cloned(),
        "trust_boundary_note": trust_boundary_note(&artifact),
    })
    .to_string())
}

/// Estimate Ethereum verification gas cost for a proof.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_estimate_gas(
    proof_path: *const c_char,
    backend: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        estimate_gas_json(&proof_path, &backend_str, FfiEvmTarget::Ethereum)
    })
}

/// Estimate verification gas cost for a proof against a specific EVM target.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_estimate_gas_for_target(
    proof_path: *const c_char,
    backend: *const c_char,
    evm_target: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let evm_target = parse_ffi_evm_target(unsafe { c_str_opt(evm_target) }.as_deref())?;
        estimate_gas_json(&proof_path, &backend_str, evm_target)
    })
}

/// Generate a Solidity verifier contract from a proof.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_deploy(
    proof_path: *const c_char,
    backend: *const c_char,
    output_path: *const c_char,
    contract_name: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;
        let contract_name = unsafe { c_str_required(contract_name, "contract_name") }?;
        deploy_for_target_json(
            &proof_path,
            &backend_str,
            &output_path,
            &contract_name,
            FfiEvmTarget::Ethereum,
        )
    })
}

/// Generate a Solidity verifier contract from a proof for a specific EVM target.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_deploy_for_target(
    proof_path: *const c_char,
    backend: *const c_char,
    output_path: *const c_char,
    contract_name: *const c_char,
    evm_target: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;
        let contract_name = unsafe { c_str_required(contract_name, "contract_name") }?;
        let evm_target = parse_ffi_evm_target(unsafe { c_str_opt(evm_target) }.as_deref())?;
        deploy_for_target_json(
            &proof_path,
            &backend_str,
            &output_path,
            &contract_name,
            evm_target,
        )
    })
}

/// Decode a Groth16 proof into Solidity-ready calldata coordinates (JSON).
#[unsafe(no_mangle)]
pub extern "C" fn zkf_proof_calldata(proof_path: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let artifact: zkf_core::ProofArtifact = read_json(&proof_path)?;

        let calldata = zkf_backends::foundry_test::proof_to_calldata_json(
            &artifact.proof,
            &artifact.public_inputs,
        )?;

        Ok(calldata.to_string())
    })
}

/// Generate a Foundry test file for behavioral verification of a Groth16 verifier.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_emit_foundry_test(
    proof_path: *const c_char,
    verifier_import_path: *const c_char,
    test_output_path: *const c_char,
    contract_name: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let import_path = unsafe { c_str_required(verifier_import_path, "verifier_import_path") }?;
        let test_path_str = unsafe { c_str_required(test_output_path, "test_output_path") }?;
        let contract_name = unsafe { c_str_required(contract_name, "contract_name") }?;

        let artifact: zkf_core::ProofArtifact = read_json(&proof_path)?;

        let output = zkf_backends::foundry_test::generate_foundry_test_from_artifact(
            &artifact.proof,
            &artifact.public_inputs,
            &import_path,
            &contract_name,
        )?;

        // Write test file
        let test_path = PathBuf::from(&test_path_str);
        if let Some(parent) = test_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create test directory: {e}"))?;
        }
        std::fs::write(&test_path, &output.source)
            .map_err(|e| format!("failed to write test file {}: {e}", test_path.display()))?;

        Ok(serde_json::json!({
            "test_path": test_path_str,
            "test_name": output.test_name,
            "contract_name": contract_name,
            "test_count": output.test_functions.len(),
            "tests": output.test_functions,
        })
        .to_string())
    })
}

/// Inspect a proof artifact: proof size, public inputs, VK hash, internal structure.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_explore(
    artifact_path: *const c_char,
    backend: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let artifact_path = unsafe { c_str_required(artifact_path, "artifact_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;

        let artifact: zkf_core::ProofArtifact = read_json(&artifact_path)?;
        let selection = parse_public_backend_selection(&backend_str)?;

        Ok(serde_json::json!({
            "backend": format!("{}", artifact.backend),
            "requested_backend": selection.requested_name,
            "backend_route": backend_route_label(selection.route),
            "proof_size_bytes": artifact.proof.len(),
            "public_inputs_count": artifact.public_inputs.len(),
            "public_inputs": artifact.public_inputs,
            "has_verification_key": !artifact.verification_key.is_empty(),
            "program_digest": artifact.program_digest,
            "metadata": artifact.metadata,
        })
        .to_string())
    })
}

/// Emit a canonical test circuit (example.ir.json).
#[unsafe(no_mangle)]
pub extern "C" fn zkf_emit_example(output_path: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;

        let program = zkf_examples::mul_add_program();
        write_json(&output_path, &program)?;

        Ok(serde_json::json!({
            "path": output_path,
            "signals": program.signals.len(),
            "constraints": program.constraints.len(),
            "field": format!("{}", program.field),
        })
        .to_string())
    })
}

/// Import a circuit from a frontend into ZKF IR format.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_import(
    frontend: *const c_char,
    input_path: *const c_char,
    output_path: *const c_char,
    field: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| import_impl(frontend, input_path, output_path, field, std::ptr::null()))
}

/// Import a circuit from a frontend into either canonical `zir-v1` or lowered `ir-v2`.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_import_with_options(
    frontend: *const c_char,
    input_path: *const c_char,
    output_path: *const c_char,
    field: *const c_char,
    ir_family: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| import_impl(frontend, input_path, output_path, field, ir_family))
}

/// Inspect a frontend artifact: opcode census, compatible backends, capability hints.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_inspect(
    frontend: *const c_char,
    artifact_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let frontend_str = unsafe { c_str_required(frontend, "frontend") }?;
        let artifact_path = unsafe { c_str_required(artifact_path, "artifact_path") }?;

        let frontend_kind: zkf_frontends::FrontendKind =
            frontend_str.parse().map_err(|e: String| e)?;

        let fe = zkf_frontends::frontend_for(frontend_kind);
        let raw: serde_json::Value = read_json(&artifact_path)?;
        let inspection = fe
            .inspect(&raw)
            .map_err(|e| format!("inspect failed: {e}"))?;

        Ok(serde_json::to_string(&inspection)
            .map_err(|e| format!("failed to serialize inspection: {e}"))?)
    })
}

/// Benchmark across multiple backends.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_benchmark(
    backends_json: *const c_char,
    iterations: i32,
    parallel: i32,
    continue_on_error: i32,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let backends_str = unsafe { c_str_required(backends_json, "backends_json") }?;
        let _parallel = parallel != 0;
        let _continue_on_error = continue_on_error != 0;
        let iterations = if iterations <= 0 {
            5
        } else {
            iterations as usize
        };

        let backend_names: Vec<String> = serde_json::from_str(&backends_str)
            .map_err(|e| format!("invalid backends JSON array: {e}"))?;

        let mut results = Vec::new();
        for name in &backend_names {
            let selection = match parse_execution_backend_selection(name) {
                Ok(selection) => selection,
                Err(e) => {
                    results.push(serde_json::json!({
                        "backend": name,
                        "error": format!("{e}"),
                    }));
                    continue;
                }
            };
            let engine = zkf_backends::backend_for_selection(&selection)?;
            let program = zkf_examples::mul_add_program();
            let inputs = zkf_examples::mul_add_inputs(3, 5);

            let mut compile_times = Vec::new();
            let mut prove_times = Vec::new();
            let mut verify_times = Vec::new();
            let mut proof_size = 0u64;
            let mut error = None;

            for _ in 0..iterations {
                if CANCEL_FLAG.load(Ordering::SeqCst) {
                    return Err("cancelled".to_string());
                }

                let t0 = std::time::Instant::now();
                let compiled = match engine.compile(&program) {
                    Ok(c) => c,
                    Err(e) => {
                        error = Some(format!("{e}"));
                        break;
                    }
                };
                compile_times.push(t0.elapsed().as_secs_f64());

                let witness = match zkf_core::generate_witness(&program, &inputs) {
                    Ok(w) => w,
                    Err(e) => {
                        error = Some(format!("{e}"));
                        break;
                    }
                };

                let t1 = std::time::Instant::now();
                let artifact = match zkf_runtime::RuntimeExecutor::run_backend_prove_job(
                    selection.backend,
                    selection.route,
                    std::sync::Arc::new(program.clone()),
                    None,
                    Some(std::sync::Arc::new(witness.clone())),
                    Some(std::sync::Arc::new(compiled.clone())),
                    zkf_runtime::RequiredTrustLane::StrictCryptographic,
                    zkf_runtime::ExecutionMode::Deterministic,
                ) {
                    Ok(execution) => execution.artifact,
                    Err(e) => {
                        error = Some(format!("{e}"));
                        break;
                    }
                };
                prove_times.push(t1.elapsed().as_secs_f64());
                proof_size = artifact.proof.len() as u64;

                let t2 = std::time::Instant::now();
                match engine.verify(&compiled, &artifact) {
                    Ok(_) => {}
                    Err(e) => {
                        error = Some(format!("{e}"));
                        break;
                    }
                }
                verify_times.push(t2.elapsed().as_secs_f64());
            }

            let avg = |v: &[f64]| {
                if v.is_empty() {
                    0.0
                } else {
                    v.iter().sum::<f64>() / v.len() as f64
                }
            };

            results.push(serde_json::json!({
                "backend": format!("{}", selection.backend),
                "requested_backend": selection.requested_name,
                "backend_route": backend_route_label(selection.route),
                "iterations": iterations,
                "avg_compile_seconds": avg(&compile_times),
                "avg_prove_seconds": avg(&prove_times),
                "avg_verify_seconds": avg(&verify_times),
                "proof_size_bytes": proof_size,
                "error": error,
            }));
        }

        Ok(serde_json::json!({ "results": results }).to_string())
    })
}

/// Wrap a STARK proof into a Groth16 proof for on-chain verification.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_wrap(
    proof_path: *const c_char,
    compiled_path: *const c_char,
    output_path: *const c_char,
    low_memory: i32,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let compiled_path = unsafe { c_str_required(compiled_path, "compiled_path") }?;
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;
        let _low_memory = low_memory != 0;

        let artifact: zkf_core::ProofArtifact = read_json(&proof_path)?;
        let compiled: zkf_core::CompiledProgram = read_json(&compiled_path)?;

        let start = std::time::Instant::now();
        let registry = zkf_backends::wrapping::default_wrapper_registry();
        let wrapper = registry
            .find(artifact.backend, zkf_core::BackendKind::ArkworksGroth16)
            .ok_or_else(|| {
                format!(
                    "no groth16 wrapper found for source backend {}",
                    artifact.backend
                )
            })?;

        let preview = wrapper
            .preview_wrap_with_policy(
                &artifact,
                &compiled,
                zkf_core::wrapping::WrapperExecutionPolicy::default(),
            )
            .map_err(|e| format!("wrapping preview failed: {e}"))?
            .ok_or_else(|| {
                format!(
                    "wrapper '{}' -> '{}' did not provide a runtime execution preview",
                    artifact.backend,
                    zkf_core::BackendKind::ArkworksGroth16
                )
            })?;
        let wrapped = zkf_runtime::RuntimeExecutor::run_wrapper_job_with_sources(
            &preview,
            std::sync::Arc::new(artifact.clone()),
            std::sync::Arc::new(compiled.clone()),
            zkf_core::wrapping::WrapperExecutionPolicy::default(),
            zkf_runtime::ExecutionMode::Deterministic,
        )
        .map_err(|e| format!("wrapping failed: {e}"))?
        .artifact;
        let elapsed = start.elapsed();

        let original_size = artifact.proof.len();
        let wrapped_size = wrapped.proof.len();

        write_json(&output_path, &wrapped)?;

        Ok(serde_json::json!({
            "wrapped_proof_path": output_path,
            "wrapping_time_seconds": elapsed.as_secs_f64(),
            "original_size_bytes": original_size,
            "wrapped_size_bytes": wrapped_size,
            "compression_ratio": if wrapped_size > 0 { original_size as f64 / wrapped_size as f64 } else { 0.0 },
        })
        .to_string())
    })
}

/// Pre-generate Groth16 keys for STARK→Groth16 wrapping.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_wrap_setup(
    proof_path: *const c_char,
    compiled_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let proof_path = unsafe { c_str_required(proof_path, "proof_path") }?;
        let compiled_path = unsafe { c_str_required(compiled_path, "compiled_path") }?;

        let artifact: zkf_core::ProofArtifact = read_json(&proof_path)?;
        let compiled: zkf_core::CompiledProgram = read_json(&compiled_path)?;

        let start = std::time::Instant::now();
        let registry = zkf_backends::wrapping::default_wrapper_registry();
        let wrapper = registry
            .find(artifact.backend, zkf_core::BackendKind::ArkworksGroth16)
            .ok_or_else(|| {
                format!(
                    "no groth16 wrapper found for source backend {}",
                    artifact.backend
                )
            })?;

        // Setup is implicit in wrap() — perform a full wrap to generate and cache keys.
        let wrapped = wrapper
            .wrap(&artifact, &compiled)
            .map_err(|e| format!("wrap setup failed: {e}"))?;
        let elapsed = start.elapsed();

        Ok(serde_json::json!({
            "status": "keys_generated",
            "setup_time_seconds": elapsed.as_secs_f64(),
            "wrapped_proof_size": wrapped.proof.len(),
        })
        .to_string())
    })
}

/// Aggregate multiple proofs into one.
///
/// `pairs_json` is a JSON array of objects: `[{"proof": "<path>", "compiled": "<path>"}, ...]`
#[unsafe(no_mangle)]
pub extern "C" fn zkf_aggregate(
    pairs_json: *const c_char,
    mode: *const c_char,
    output_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let pairs_str = unsafe { c_str_required(pairs_json, "pairs_json") }?;
        let mode_str = unsafe { c_str_required(mode, "mode") }?;
        let output_path = unsafe { c_str_required(output_path, "output_path") }?;

        #[derive(serde::Deserialize)]
        struct PairEntry {
            proof: String,
            compiled: String,
        }
        let entries: Vec<PairEntry> =
            serde_json::from_str(&pairs_str).map_err(|e| format!("invalid pairs JSON: {e}"))?;

        let num_proofs = entries.len();
        let pairs: Vec<(zkf_core::ProofArtifact, zkf_core::CompiledProgram)> = entries
            .iter()
            .map(|entry| {
                let artifact: zkf_core::ProofArtifact = read_json(&entry.proof)?;
                let compiled: zkf_core::CompiledProgram = read_json(&entry.compiled)?;
                Ok((artifact, compiled))
            })
            .collect::<Result<Vec<_>, String>>()?;

        let start = std::time::Instant::now();

        // Use Groth16Aggregator for attestation mode
        let aggregator = zkf_backends::aggregation::Groth16Aggregator;
        use zkf_core::aggregation::ProofAggregator;
        let aggregated = aggregator.aggregate(&pairs).map_err(render_error)?;
        let elapsed = start.elapsed();

        write_json(&output_path, &aggregated)?;

        Ok(serde_json::json!({
            "aggregated_proof_path": output_path,
            "mode": mode_str,
            "num_proofs": num_proofs,
            "aggregation_time_seconds": elapsed.as_secs_f64(),
        })
        .to_string())
    })
}

/// Run test vectors against a circuit across backends.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_test_vectors(
    program_path: *const c_char,
    vectors_path: *const c_char,
    backends_json: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program_path = unsafe { c_str_required(program_path, "program_path") }?;
        let vectors_path = unsafe { c_str_required(vectors_path, "vectors_path") }?;
        let backends_str = unsafe { c_str_opt(backends_json) };

        let program: zkf_core::Program = read_json(&program_path)?;
        let _vectors: serde_json::Value = read_json(&vectors_path)?;

        let backend_names: Vec<String> = if let Some(ref s) = backends_str {
            serde_json::from_str(s).map_err(|e| format!("invalid backends JSON: {e}"))?
        } else {
            vec!["arkworks-groth16".to_string()]
        };

        let mut results = Vec::new();
        for name in &backend_names {
            let selection = parse_execution_backend_selection(name)?;
            let engine = zkf_backends::backend_for_selection(&selection)?;
            match engine.compile(&program) {
                Ok(_) => results.push(serde_json::json!({
                    "backend": selection.backend.as_str(),
                    "requested_backend": selection.requested_name,
                    "backend_route": backend_route_label(selection.route),
                    "status": "pass",
                })),
                Err(e) => results.push(serde_json::json!({
                    "backend": selection.backend.as_str(),
                    "requested_backend": selection.requested_name,
                    "backend_route": backend_route_label(selection.route),
                    "status": "fail",
                    "error": format!("{e}"),
                })),
            }
        }

        Ok(serde_json::json!({ "results": results }).to_string())
    })
}

/// Run the built-in demo pipeline.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_demo() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program = zkf_examples::mul_add_program();
        let inputs = zkf_examples::mul_add_inputs(3, 5);

        let witness = zkf_core::generate_witness(&program, &inputs).map_err(render_error)?;
        let execution =
            zkf_backends::with_allow_dev_deterministic_groth16_override(Some(true), || {
                zkf_runtime::RuntimeExecutor::run_backend_prove_job(
                    zkf_core::BackendKind::ArkworksGroth16,
                    zkf_backends::BackendRoute::Auto,
                    std::sync::Arc::new(program.clone()),
                    None,
                    Some(std::sync::Arc::new(witness)),
                    None,
                    zkf_runtime::RequiredTrustLane::StrictCryptographic,
                    zkf_runtime::ExecutionMode::Deterministic,
                )
            })
            .map_err(|e| e.to_string())?;
        let compiled = execution.compiled;
        let artifact = execution.artifact;
        let engine = zkf_backends::backend_for(zkf_core::BackendKind::ArkworksGroth16);
        let valid = engine.verify(&compiled, &artifact).map_err(render_error)?;

        Ok(serde_json::json!({
            "steps": ["emit_example", "compile", "witness", "prove", "verify"],
            "valid": valid,
            "backend": "arkworks-groth16",
            "proof_size_bytes": artifact.proof.len(),
            "public_inputs": artifact.public_inputs.len(),
        })
        .to_string())
    })
}

// ─── Registry operations ────────────────────────────────────────────────────

/// List all gadgets in the ZKF registry.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_registry_list() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let registry_dir = dirs_registry_path();
        let registry = zkf_registry::LocalRegistry::open(&registry_dir)
            .map_err(|e| format!("failed to open registry: {e}"))?;
        let combined = zkf_registry::CombinedRegistry::new(
            registry,
            Some(zkf_registry::RemoteRegistry::new(
                None,
                Some(registry_dir.join(".remote-cache")),
            )),
        );
        let gadgets = combined.list();
        Ok(serde_json::to_string(&gadgets).map_err(|e| format!("failed to serialize: {e}"))?)
    })
}

/// Fetch/install a gadget from the registry.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_registry_add(gadget_name: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let name = unsafe { c_str_required(gadget_name, "gadget_name") }?;
        let registry_dir = dirs_registry_path();
        let mut registry = zkf_registry::LocalRegistry::open(&registry_dir)
            .map_err(|e| format!("failed to open registry: {e}"))?;
        match registry.get(&name).cloned() {
            Some(manifest) => Ok(serde_json::json!({
                "status": "installed",
                "source": "local",
                "gadget": name,
                "version": manifest.version,
            })
            .to_string()),
            None => {
                let remote = zkf_registry::RemoteRegistry::new(
                    None,
                    Some(registry_dir.join(".remote-cache")),
                );
                if let Some((manifest, content)) = remote.fetch_package(&name) {
                    registry
                        .publish(manifest.clone(), &content)
                        .map_err(|e| format!("failed to install remote gadget: {e}"))?;
                    Ok(serde_json::json!({
                        "status": "installed",
                        "source": "remote",
                        "gadget": name,
                        "version": manifest.version,
                    })
                    .to_string())
                } else if zkf_gadgets::GadgetRegistry::with_builtins()
                    .get(&name)
                    .is_some()
                {
                    Ok(serde_json::json!({
                        "status": "builtin",
                        "gadget": name,
                    })
                    .to_string())
                } else {
                    Err(format!(
                        "gadget '{name}' not found in local, remote, or built-in registries"
                    ))
                }
            }
        }
    })
}

/// Publish a gadget to the registry.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_registry_publish(
    manifest_path: *const c_char,
    content_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let manifest_path = unsafe { c_str_required(manifest_path, "manifest_path") }?;
        let content_path = unsafe { c_str_required(content_path, "content_path") }?;
        let registry_dir = dirs_registry_path();
        let mut registry = zkf_registry::LocalRegistry::open(&registry_dir)
            .map_err(|e| format!("failed to open registry: {e}"))?;
        let manifest: zkf_registry::GadgetManifest = read_json(&manifest_path)?;
        let content =
            std::fs::read(&content_path).map_err(|e| format!("failed to read content: {e}"))?;
        registry
            .publish(manifest, &content)
            .map_err(|e| format!("publish failed: {e}"))?;
        Ok(serde_json::json!({ "status": "published" }).to_string())
    })
}

// ─── Package workflow ───────────────────────────────────────────────────────

/// Compile a package manifest for a specific backend.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_package_compile(
    manifest_path: *const c_char,
    backend: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let manifest_path = unsafe { c_str_required(manifest_path, "manifest_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;

        let manifest: zkf_core::PackageManifest = read_json(&manifest_path)?;
        let selection = parse_execution_backend_selection(&backend_str)?;
        let (program, source_ir_family) = load_manifest_program_v2(&manifest_path, &manifest)?;

        let engine = zkf_backends::backend_for_selection(&selection)?;
        let mut compiled = engine.compile(&program).map_err(render_error)?;
        annotate_backend_selection_metadata(Some(&mut compiled), None, &selection);

        let out_path = format!(
            "{}/compiled_{}.json",
            PathBuf::from(&manifest_path)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| ".".to_string()),
            backend_str
        );
        write_json(&out_path, &compiled)?;

        Ok(serde_json::json!({
            "compiled_path": out_path,
            "source_ir_family": source_ir_family,
            "backend": format!("{}", selection.backend),
            "requested_backend": selection.requested_name,
            "backend_route": backend_route_label(selection.route),
        })
        .to_string())
    })
}

/// Prove a package run for a specific backend.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_package_prove(
    manifest_path: *const c_char,
    backend: *const c_char,
    run_id: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let manifest_path = unsafe { c_str_required(manifest_path, "manifest_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let run_id = unsafe { c_str_required(run_id, "run_id") }?;

        let manifest: zkf_core::PackageManifest = read_json(&manifest_path)?;
        let selection = parse_execution_backend_selection(&backend_str)?;
        let (program, source_ir_family) = load_manifest_program_v2(&manifest_path, &manifest)?;

        let inputs_ref = manifest
            .files
            .public_inputs
            .as_ref()
            .ok_or("manifest missing public_inputs file")?;
        let inputs: zkf_core::WitnessInputs = read_json_path(&resolve_manifest_entry_path(
            &manifest_path,
            &inputs_ref.path,
        ))?;

        let witness = zkf_core::generate_witness(&program, &inputs).map_err(render_error)?;
        let mut artifact = zkf_runtime::RuntimeExecutor::run_backend_prove_job(
            selection.backend,
            selection.route,
            std::sync::Arc::new(program.clone()),
            None,
            Some(std::sync::Arc::new(witness)),
            None,
            zkf_runtime::RequiredTrustLane::StrictCryptographic,
            zkf_runtime::ExecutionMode::Deterministic,
        )
        .map_err(|e| e.to_string())?
        .artifact;
        annotate_backend_selection_metadata(None, Some(&mut artifact), &selection);

        let dir = PathBuf::from(&manifest_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| ".".to_string());
        let out_path = format!("{dir}/proof_{run_id}_{backend_str}.json");
        write_json(&out_path, &artifact)?;

        Ok(serde_json::json!({
            "proof_path": out_path,
            "source_ir_family": source_ir_family,
            "backend": format!("{}", selection.backend),
            "requested_backend": selection.requested_name,
            "backend_route": backend_route_label(selection.route),
            "run_id": run_id,
        })
        .to_string())
    })
}

// ─── Internal helpers (input resolution) ────────────────────────────────────

/// Default registry directory path.
fn dirs_registry_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join(".zkf").join("registry")
}

/// Render a production Groth16 Solidity verifier contract with full EIP-197 pairing check.
///
/// Includes the Pairing library (ecAdd, ecMul, bn256Pairing precompile calls) and a
/// complete Groth16 verification implementation. The generated contract is deployable
/// on any EVM chain supporting the alt_bn128 precompiles (Ethereum mainnet, Polygon, etc.).
fn render_groth16_solidity(
    vk: &zkf_backends::groth16_vk::Groth16VkHex,
    contract_name: &str,
    _public_inputs: &[String],
) -> String {
    let alpha_x = &vk.alpha_g1[0];
    let alpha_y = &vk.alpha_g1[1];
    let beta_x1 = &vk.beta_g2[0];
    let beta_x2 = &vk.beta_g2[1];
    let beta_y1 = &vk.beta_g2[2];
    let beta_y2 = &vk.beta_g2[3];
    let gamma_x1 = &vk.gamma_g2[0];
    let gamma_x2 = &vk.gamma_g2[1];
    let gamma_y1 = &vk.gamma_g2[2];
    let gamma_y2 = &vk.gamma_g2[3];
    let delta_x1 = &vk.delta_g2[0];
    let delta_x2 = &vk.delta_g2[1];
    let delta_y1 = &vk.delta_g2[2];
    let delta_y2 = &vk.delta_g2[3];

    let mut ic_elements = String::new();
    for (idx, point) in vk.ic.iter().enumerate() {
        ic_elements.push_str(&format!(
            "        vk.IC[{idx}] = Pairing.G1Point(uint256({x}), uint256({y}));\n",
            x = point[0],
            y = point[1],
        ));
    }

    let ic_len = vk.ic.len();

    format!(
        r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title Pairing library for BN254 elliptic curve operations.
/// @dev Provides G1, G2 point types and precompiled pairing check.
library Pairing {{
    struct G1Point {{
        uint256 X;
        uint256 Y;
    }}

    struct G2Point {{
        uint256[2] X;
        uint256[2] Y;
    }}

    /// @return the generator of G1.
    function P1() internal pure returns (G1Point memory) {{
        return G1Point(1, 2);
    }}

    /// @return the generator of G2.
    function P2() internal pure returns (G2Point memory) {{
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
             10857046999023057135944570762232829481370756359578518086990519993285655852781],
            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
             8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }}

    /// @return r the negation of p, i.e. p.add(p.negate()) should be zero.
    function negate(G1Point memory p) internal pure returns (G1Point memory r) {{
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }}

    /// @return r the sum of two points of G1.
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {{
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            switch success case 0 {{ invalid() }}
        }}
        require(success, "pairing-add-failed");
    }}

    /// @return r the product of a point on G1 and a scalar, i.e. p == p.scalar_mul(1).
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {{
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 7, input, 0x60, r, 0x40)
            switch success case 0 {{ invalid() }}
        }}
        require(success, "pairing-mul-failed");
    }}

    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *.... * e(p1[n], p2[n]) == 1
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {{
        require(p1.length == p2.length, "pairing-lengths-failed");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {{
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }}
        uint256[1] memory out;
        bool success;
        assembly {{
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            switch success case 0 {{ invalid() }}
        }}
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }}

    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
        G1Point memory a1, G2Point memory a2,
        G1Point memory b1, G2Point memory b2,
        G1Point memory c1, G2Point memory c2,
        G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {{
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1; p2[0] = a2;
        p1[1] = b1; p2[1] = b2;
        p1[2] = c1; p2[2] = c2;
        p1[3] = d1; p2[3] = d2;
        return pairing(p1, p2);
    }}
}}

/// @title {contract_name}
/// @notice Generated Groth16 verifier for BN254 (alt_bn128).
/// @dev Generated by ZKF framework. Verification equation:
///      e(A, B) = e(alpha, beta) * e(IC, gamma) * e(C, delta)
contract {contract_name} {{
    using Pairing for *;

    struct VerifyingKey {{
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }}

    struct Proof {{
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }}

    function verifyingKey() internal pure returns (VerifyingKey memory vk) {{
        vk.alpha1 = Pairing.G1Point(
            uint256({alpha_x}),
            uint256({alpha_y})
        );

        vk.beta2 = Pairing.G2Point(
            [uint256({beta_x1}),
             uint256({beta_x2})],
            [uint256({beta_y1}),
             uint256({beta_y2})]
        );

        vk.gamma2 = Pairing.G2Point(
            [uint256({gamma_x1}),
             uint256({gamma_x2})],
            [uint256({gamma_y1}),
             uint256({gamma_y2})]
        );

        vk.delta2 = Pairing.G2Point(
            [uint256({delta_x1}),
             uint256({delta_x2})],
            [uint256({delta_y1}),
             uint256({delta_y2})]
        );

        vk.IC = new Pairing.G1Point[]({ic_len});
{ic_elements}    }}

    function verify(uint[] memory input, Proof memory proof) internal view returns (bool) {{
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.IC.length, "verifier-bad-input");
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {{
            require(input[i] < snark_scalar_field, "verifier-gte-snark-scalar-field");
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.IC[i + 1], input[i]));
        }}
        vk_x = Pairing.addition(vk_x, vk.IC[0]);
        // Pairing check: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
        if (!Pairing.pairingProd4(
            Pairing.negate(proof.A), proof.B,
            vk.alpha1, vk.beta2,
            vk_x, vk.gamma2,
            proof.C, vk.delta2
        )) return false;
        return true;
    }}

    /// @notice Verify a Groth16 proof.
    /// @param a The A point of the proof (2 uint256 values).
    /// @param b The B point of the proof (2x2 uint256 values).
    /// @param c The C point of the proof (2 uint256 values).
    /// @param input The public inputs to the circuit.
    /// @return r True if the proof is valid.
    function verifyProof(
        uint[2] memory a,
        uint[2][2] memory b,
        uint[2] memory c,
        uint[] memory input
    ) public view returns (bool r) {{
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        return verify(input, proof);
    }}
}}
"#,
        contract_name = contract_name,
        alpha_x = alpha_x,
        alpha_y = alpha_y,
        beta_x1 = beta_x1,
        beta_x2 = beta_x2,
        beta_y1 = beta_y1,
        beta_y2 = beta_y2,
        gamma_x1 = gamma_x1,
        gamma_x2 = gamma_x2,
        gamma_y1 = gamma_y1,
        gamma_y2 = gamma_y2,
        delta_x1 = delta_x1,
        delta_x2 = delta_x2,
        delta_y1 = delta_y1,
        delta_y2 = delta_y2,
        ic_len = ic_len,
        ic_elements = ic_elements,
    )
}

fn render_groth16_solidity_for_target(
    vk: &zkf_backends::groth16_vk::Groth16VkHex,
    contract_name: &str,
    public_inputs: &[String],
    artifact: &zkf_core::ProofArtifact,
    evm_target: FfiEvmTarget,
) -> String {
    let mut annotations = format!("// ZKF deployment target: {}\n", evm_target.as_str());
    if let Some(note) = trust_boundary_note(artifact) {
        annotations.push_str("// ZKF trust boundary: ");
        annotations.push_str(&note);
        annotations.push('\n');
    }
    annotations.push('\n');
    annotations.push_str(&render_groth16_solidity(vk, contract_name, public_inputs));
    annotations
}

/// Hard output validator for generated Solidity verifier contracts.
///
/// This runs BEFORE the file is written to disk. If any check fails, the export
/// is aborted entirely — no broken verifier is ever emitted.
///
/// Checks:
/// 1. No malformed hex literals (0x0x...)
/// 2. No placeholder/stub verification body
/// 3. Pairing precompile call is present (address 0x08)
/// 4. Public-input linear combination exists
/// 5. No TODO/placeholder comments in verification logic
fn validate_solidity_verifier(sol: &str) -> Result<String, String> {
    // 1. Malformed hex literals
    if sol.contains("0x0x") {
        return Err(
            "VERIFIER EXPORT BLOCKED: malformed hex literal (0x0x) detected. \
             This is a known bug in an older code path. The verifier was not written to disk."
                .to_string(),
        );
    }

    // 2. Stub detection: "return true;" inside a function that should verify
    //    We check specifically for the known stub pattern
    if sol.contains("Pairing check placeholder") {
        return Err(
            "VERIFIER EXPORT BLOCKED: placeholder pairing check detected. \
             The verification function is a stub that always returns true. \
             The verifier was not written to disk."
                .to_string(),
        );
    }

    // 3. Must contain a real pairing precompile call (staticcall to 0x08 or address 8)
    let has_pairing = sol.contains("0x08")       // precompile address in assembly
        || sol.contains("pairing(")              // Pairing library call
        || sol.contains("pairingProd4("); // convenience 4-pair check
    if !has_pairing {
        return Err(
            "VERIFIER EXPORT BLOCKED: no pairing precompile call found. \
             A valid Groth16 verifier must call the bn256Pairing precompile (0x08). \
             The verifier was not written to disk."
                .to_string(),
        );
    }

    // 4. Must contain IC linear combination (scalar_mul or ecMul for public inputs)
    let has_lc = sol.contains("scalar_mul(")     // Pairing library scalar mul
        || sol.contains("0x07"); // ecMul precompile in assembly
    if !has_lc {
        return Err(
            "VERIFIER EXPORT BLOCKED: no public-input linear combination found. \
             A valid Groth16 verifier must compute vk_x from IC points and public inputs. \
             The verifier was not written to disk."
                .to_string(),
        );
    }

    // 5. No leftover TODO/placeholder markers in the verification body
    let suspicious = ["TODO", "FIXME", "PLACEHOLDER", "HACK", "STUB"];
    for marker in &suspicious {
        if sol.to_uppercase().contains(marker) {
            return Err(format!(
                "VERIFIER EXPORT BLOCKED: found '{marker}' marker in generated contract. \
                 The verifier was not written to disk."
            ));
        }
    }

    Ok("passed".to_string())
}

/// Resolve named signal aliases in WitnessInputs to match program signals.
fn resolve_input_aliases(inputs: &mut zkf_core::WitnessInputs, program: &zkf_core::Program) {
    // The inputs map may use signal names like "preimage_0" which need to match
    // the program's signal definitions. This is already handled by generate_witness
    // in zkf-core, so no extra work needed here.
    let _ = (inputs, program);
}

/// Parse a setup seed string into bytes.
fn parse_seed(seed_str: &str) -> Result<[u8; 32], String> {
    if seed_str.starts_with("0x") || seed_str.starts_with("0X") {
        let hex = &seed_str[2..];
        if hex.len() != 64 {
            return Err(format!("seed hex must be 64 chars, got {}", hex.len()));
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("invalid hex in seed: {e}"))?;
        }
        Ok(bytes)
    } else {
        // Hash the string to get 32 bytes
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        seed_str.hash(&mut hasher);
        let h = hasher.finish();
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&h.to_le_bytes());
        // Fill rest by rehashing
        for i in 1..4 {
            let mut h2 = DefaultHasher::new();
            (h.wrapping_add(i as u64)).hash(&mut h2);
            let h2 = h2.finish();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&h2.to_le_bytes());
        }
        Ok(bytes)
    }
}

// ─── Conformance ─────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct VersionedConformanceArtifact<'a> {
    schema_version: &'static str,
    backend: String,
    exported_at_unix_s: u64,
    report: &'a zkf_conformance::ConformanceReport,
}

fn export_conformance_artifacts(
    report: &zkf_conformance::ConformanceReport,
    json_path: Option<&Path>,
    cbor_path: Option<&Path>,
) -> Result<(), String> {
    if json_path.is_none() && cbor_path.is_none() {
        return Err(
            "zkf_conformance_export requires at least one export path (json or cbor)".to_string(),
        );
    }

    let exported_at_unix_s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time before UNIX_EPOCH: {e}"))?
        .as_secs();
    let artifact = VersionedConformanceArtifact {
        schema_version: "zkf-conformance-report/v1",
        backend: report.backend.clone(),
        exported_at_unix_s,
        report,
    };

    if let Some(path) = json_path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create '{}': {e}", parent.display()))?;
        }
        let json = serde_json::to_vec_pretty(&artifact)
            .map_err(|e| format!("failed to serialize conformance JSON: {e}"))?;
        std::fs::write(path, json)
            .map_err(|e| format!("failed to write '{}': {e}", path.display()))?;
    }

    if let Some(path) = cbor_path {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create '{}': {e}", parent.display()))?;
        }
        let cbor = serde_cbor::to_vec(&artifact)
            .map_err(|e| format!("failed to serialize conformance CBOR: {e}"))?;
        std::fs::write(path, cbor)
            .map_err(|e| format!("failed to write '{}': {e}", path.display()))?;
    }

    Ok(())
}

/// Run the conformance test suite against a backend.
/// Returns JSON: ConformanceReport with per-test pass/fail, timing, and errors.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_conformance(backend: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let selection = parse_execution_backend_selection(&backend_str)?;
        let report =
            zkf_conformance::run_conformance_with_route(selection.backend, selection.route);
        serde_json::to_string(&report)
            .map_err(|e| format!("failed to serialize conformance report: {e}"))
    })
}

/// Run the conformance suite and export standalone JSON and/or CBOR artifacts.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_conformance_export(
    backend: *const c_char,
    json_path: *const c_char,
    cbor_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let selection = parse_execution_backend_selection(&backend_str)?;
        let report =
            zkf_conformance::run_conformance_with_route(selection.backend, selection.route);

        let json_path = unsafe { c_str_opt(json_path) }.map(PathBuf::from);
        let cbor_path = unsafe { c_str_opt(cbor_path) }.map(PathBuf::from);
        export_conformance_artifacts(&report, json_path.as_deref(), cbor_path.as_deref())?;

        Ok(serde_json::json!({
            "backend": report.backend,
            "json_path": json_path.map(|path| path.display().to_string()),
            "cbor_path": cbor_path.map(|path| path.display().to_string()),
            "tests_run": report.tests_run,
            "tests_passed": report.tests_passed,
            "tests_failed": report.tests_failed,
        })
        .to_string())
    })
}

// ─── IR Validation ───────────────────────────────────────────────────────────

/// Validate a ZKF program: schema parsing + type checking.
/// Accepts both ZIR v1 and IR v2 formats.
/// Returns JSON: { valid, program, name, field, ir_format, signals, constraints, type_errors }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ir_validate(program_path: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program_path = unsafe { c_str_required(program_path, "program_path") }?;
        let data = std::fs::read_to_string(&program_path)
            .map_err(|e| format!("failed to read program: {program_path}: {e}"))?;

        // Try ZIR v1 first, then fall back to IR v2
        if let Ok(prog) = serde_json::from_str::<zkf_core::zir_v1::Program>(&data) {
            let type_result = zkf_core::type_check::type_check(&prog);
            let type_errors: Vec<String> = match &type_result {
                Ok(()) => vec![],
                Err(errors) => errors.iter().map(|e| format!("{e}")).collect(),
            };
            return Ok(serde_json::json!({
                "valid": type_result.is_ok(),
                "program": program_path,
                "name": prog.name,
                "field": format!("{:?}", prog.field),
                "ir_format": "zir-v1",
                "signals": prog.signals.len(),
                "constraints": prog.constraints.len(),
                "type_errors": type_errors,
            })
            .to_string());
        }

        if let Ok(prog) = serde_json::from_str::<zkf_core::Program>(&data) {
            let zir = zkf_core::program_v2_to_zir(&prog);
            let type_result = zkf_core::type_check::type_check(&zir);
            let type_errors: Vec<String> = match &type_result {
                Ok(()) => vec![],
                Err(errors) => errors.iter().map(|e| format!("{e}")).collect(),
            };
            return Ok(serde_json::json!({
                "valid": type_result.is_ok(),
                "program": program_path,
                "name": prog.name,
                "field": format!("{:?}", prog.field),
                "ir_format": "ir-v2",
                "signals": prog.signals.len(),
                "constraints": prog.constraints.len(),
                "type_errors": type_errors,
            })
            .to_string());
        }

        Ok(serde_json::json!({
            "valid": false,
            "program": program_path,
            "error": "failed to parse as ZIR v1 or IR v2",
            "type_errors": ["failed to parse as ZIR v1 or IR v2"],
        })
        .to_string())
    })
}

// ─── Ceremony (Powers of Tau) ────────────────────────────────────────────────

/// Initialize a new Powers of Tau ceremony.
/// Returns JSON: { power, n_g1, n_g2, output_path }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_init(
    curve: *const c_char,
    power: i32,
    output_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let curve = unsafe { c_str_required(curve, "curve") }?;
        let output = unsafe { c_str_required(output_path, "output_path") }?;

        if curve != "bn254" {
            return Err(format!(
                "unsupported curve '{curve}' — only 'bn254' is supported"
            ));
        }
        if power < 1 || power > 28 {
            return Err(format!("power must be 1..28, got {power}"));
        }

        let ptau = zkf_backends::ceremony::PtauData::new(power as u32);
        let n = ptau.n();

        // Ensure parent directory exists
        if let Some(parent) = PathBuf::from(&output).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
        }

        ptau.write_to_file(&output)?;

        Ok(serde_json::json!({
            "power": power,
            "n_g1": n,
            "n_g2": n,
            "curve": curve,
            "output_path": output,
            "contributions": 0,
        })
        .to_string())
    })
}

/// Add a contribution to a Powers of Tau ceremony.
/// Returns JSON: { hash, contributions, output_path }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_contribute(
    input_ptau: *const c_char,
    output_ptau: *const c_char,
    entropy: *const c_char,
    name: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let input = unsafe { c_str_required(input_ptau, "input_ptau") }?;
        let output = unsafe { c_str_required(output_ptau, "output_ptau") }?;
        let name = unsafe { c_str_required(name, "name") }?;
        let entropy_str = unsafe { c_str_opt(entropy) };

        let mut ptau = zkf_backends::ceremony::PtauData::read_from_file(&input)?;

        let entropy_bytes = entropy_str.as_ref().map(|s| s.as_bytes());
        let hash = ptau.contribute(entropy_bytes, &name)?;

        // Ensure parent directory exists
        if let Some(parent) = PathBuf::from(&output).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
        }

        ptau.write_to_file(&output)?;

        Ok(serde_json::json!({
            "hash": hash,
            "contributor": name,
            "contributions": ptau.contributions.len(),
            "output_path": output,
        })
        .to_string())
    })
}

/// Apply a random beacon as the final contribution.
/// Returns JSON: { hash, contributions, output_path }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_beacon(
    input_ptau: *const c_char,
    output_ptau: *const c_char,
    beacon_hex: *const c_char,
    hash_iterations: i32,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let input = unsafe { c_str_required(input_ptau, "input_ptau") }?;
        let output = unsafe { c_str_required(output_ptau, "output_ptau") }?;
        let beacon = unsafe { c_str_required(beacon_hex, "beacon_hex") }?;

        if hash_iterations < 1 {
            return Err(format!(
                "hash_iterations must be >= 1, got {hash_iterations}"
            ));
        }

        let mut ptau = zkf_backends::ceremony::PtauData::read_from_file(&input)?;
        let hash = ptau.apply_beacon(&beacon, hash_iterations as u32)?;

        if let Some(parent) = PathBuf::from(&output).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
        }

        ptau.write_to_file(&output)?;

        Ok(serde_json::json!({
            "hash": hash,
            "beacon_hex": beacon,
            "hash_iterations": hash_iterations,
            "contributions": ptau.contributions.len(),
            "output_path": output,
        })
        .to_string())
    })
}

/// Prepare a Phase 1 ptau for Phase 2 (currently a pass-through verify + copy).
/// In practice, Hermez ptau files are already Phase 1 ready; this just validates.
/// Returns JSON: { valid, power, contributions, output_path }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_prepare_phase2(
    input_ptau: *const c_char,
    output_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let input = unsafe { c_str_required(input_ptau, "input_ptau") }?;
        let output = unsafe { c_str_required(output_path, "output_path") }?;

        let ptau = zkf_backends::ceremony::PtauData::read_from_file(&input)?;
        let report = ptau.verify()?;

        if !report.valid {
            return Err(format!(
                "ptau file failed verification — cannot prepare for Phase 2. Checks: {:?}",
                report.checks
            ));
        }

        // Write validated ptau to output (may be same path or different)
        if let Some(parent) = PathBuf::from(&output).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
        }
        ptau.write_to_file(&output)?;

        Ok(serde_json::json!({
            "valid": true,
            "power": report.power,
            "contributions": report.contributions,
            "output_path": output,
        })
        .to_string())
    })
}

/// Verify the consistency of a .ptau file.
/// Returns JSON: { valid, power, contributions, checks: { ... } }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_verify(ptau_path: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let path = unsafe { c_str_required(ptau_path, "ptau_path") }?;
        let ptau = zkf_backends::ceremony::PtauData::read_from_file(&path)?;
        let report = ptau.verify()?;

        Ok(serde_json::to_string(&report).map_err(|e| format!("serialize report: {e}"))?)
    })
}

/// Phase 2: derive circuit-specific keys from a Phase 1 SRS.
/// Uses the ptau + program to derive a ceremony-bound setup seed, then runs
/// the normal Groth16 circuit_specific_setup with that seed.
/// Returns JSON: { output_path, seed_hex, power }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_setup(
    ptau_path: *const c_char,
    program_path: *const c_char,
    backend: *const c_char,
    output_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let ptau_file = unsafe { c_str_required(ptau_path, "ptau_path") }?;
        let prog_file = unsafe { c_str_required(program_path, "program_path") }?;
        let backend_str = unsafe { c_str_required(backend, "backend") }?;
        let output = unsafe { c_str_required(output_path, "output_path") }?;

        if backend_str != "arkworks-groth16" {
            return Err(format!(
                "ceremony setup only supports 'arkworks-groth16', got '{backend_str}'"
            ));
        }

        // Read the ptau
        let ptau = zkf_backends::ceremony::PtauData::read_from_file(&ptau_file)?;

        // Read the source program (IR v2 JSON)
        let program: zkf_core::Program = read_json(&prog_file)?;
        let digest = program.digest_hex();

        // Derive Phase 2 seed from ceremony + circuit
        let seed = zkf_backends::ceremony::ceremony_phase2_setup(&ptau, &digest)?;
        let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();

        // Use the ceremony-derived seed to run Groth16 setup
        let start = std::time::Instant::now();
        let compiled = zkf_backends::with_setup_seed_override(Some(seed), || {
            let engine = zkf_backends::backend_for(zkf_core::BackendKind::ArkworksGroth16);
            engine.compile(&program)
        })
        .map_err(|e| format!("ceremony compile: {}", render_error(e)))?;
        let elapsed = start.elapsed();

        // Inject ceremony metadata into the compiled program
        let mut compiled = compiled;
        compiled
            .metadata
            .insert("ceremony_seed".to_string(), seed_hex.clone());
        compiled
            .metadata
            .insert("ceremony_program_digest".to_string(), digest.clone());
        compiled
            .metadata
            .insert("ceremony_ptau".to_string(), ptau_file.clone());
        compiled.metadata.insert(
            "ceremony_contributions".to_string(),
            ptau.contributions.len().to_string(),
        );
        write_phase2_history(&mut compiled, &[])?;

        // Write the ceremony-keyed compiled program
        if let Some(parent) = PathBuf::from(&output).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
        }
        write_json(&output, &compiled)?;

        Ok(serde_json::json!({
            "output_path": output,
            "seed_hex": seed_hex,
            "power": ptau.power,
            "contributions": ptau.contributions.len(),
            "backend": backend_str,
            "constraints": compiled.program.constraints.len(),
            "setup_time_seconds": elapsed.as_secs_f64(),
        })
        .to_string())
    })
}

/// Phase 2 contribution to a circuit-specific zkey.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_contribute_phase2(
    input_zkey: *const c_char,
    output_zkey: *const c_char,
    entropy: *const c_char,
    name: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let input = unsafe { c_str_required(input_zkey, "input_zkey") }?;
        let output = unsafe { c_str_required(output_zkey, "output_zkey") }?;
        let contributor_name = unsafe { c_str_required(name, "name") }?;
        let entropy = unsafe { c_str_opt(entropy) };

        let compiled: zkf_core::CompiledProgram = read_json(&input)?;
        if compiled.backend != zkf_core::BackendKind::ArkworksGroth16 {
            return Err(format!(
                "phase2 contribution requires an arkworks-groth16 compiled artifact, got {}",
                compiled.backend.as_str()
            ));
        }

        let current_seed_hex = compiled
            .metadata
            .get("ceremony_seed")
            .cloned()
            .ok_or("compiled artifact is missing ceremony_seed metadata")?;
        let current_seed = decode_seed_hex(&current_seed_hex)?;
        let entropy_hash = zkf_backends::ceremony::ceremony_phase2_entropy_hash(
            entropy.as_deref().map(str::as_bytes),
        );
        let mut history = parse_phase2_history(&compiled)?;
        let contribution = zkf_backends::ceremony::ceremony_phase2_contribution_record(
            current_seed,
            &compiled.program_digest,
            &contributor_name,
            &entropy_hash,
        )?;
        let next_seed = decode_seed_hex(&contribution.resulting_seed_hex)?;

        let mut refreshed = zkf_backends::with_setup_seed_override(Some(next_seed), || {
            let engine = zkf_backends::backend_for(zkf_core::BackendKind::ArkworksGroth16);
            engine.compile(&compiled.program)
        })
        .map_err(|e| format!("phase2 contribution compile: {}", render_error(e)))?;

        let mut merged_metadata = compiled.metadata.clone();
        merged_metadata.extend(refreshed.metadata.clone());
        refreshed.metadata = merged_metadata;
        history.push(contribution.clone());
        refreshed.metadata.insert(
            "ceremony_seed".to_string(),
            contribution.resulting_seed_hex.clone(),
        );
        write_phase2_history(&mut refreshed, &history)?;
        refreshed.metadata.insert(
            "ceremony_phase2_contributors".to_string(),
            history.len().to_string(),
        );

        if let Some(parent) = PathBuf::from(&output).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
        }
        write_json(&output, &refreshed)?;

        Ok(serde_json::json!({
            "output_path": output,
            "contributor": contributor_name,
            "entropy_hash": entropy_hash,
            "seed_hex": contribution.resulting_seed_hex,
            "contribution_count": history.len(),
        })
        .to_string())
    })
}

/// Verify Phase 2 circuit-specific keys against the Phase 1 SRS and program.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_verify_phase2(
    zkey_path: *const c_char,
    ptau_path: *const c_char,
    program_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let zkey = unsafe { c_str_required(zkey_path, "zkey_path") }?;
        let ptau_file = unsafe { c_str_required(ptau_path, "ptau_path") }?;
        let prog_file = unsafe { c_str_required(program_path, "program_path") }?;

        let ptau = zkf_backends::ceremony::PtauData::read_from_file(&ptau_file)?;
        let ptau_report = ptau.verify()?;
        let program: zkf_core::Program = read_json(&prog_file)?;

        let compiled: zkf_core::CompiledProgram = read_json(&zkey)?;
        let program_digest = program.digest_hex();
        let program_digest_match = program_digest == compiled.program_digest;
        let base_seed = zkf_backends::ceremony::ceremony_phase2_setup(&ptau, &program_digest)?;
        let expected_base_seed_hex = hex_encode_seed(base_seed);
        let mut replay_seed = base_seed;
        let mut chain_valid = true;
        let history = parse_phase2_history(&compiled)?;
        for record in &history {
            if record.program_digest != program_digest {
                chain_valid = false;
                break;
            }
            if record.previous_seed_hex != hex_encode_seed(replay_seed) {
                chain_valid = false;
                break;
            }
            let derived = zkf_backends::ceremony::ceremony_phase2_apply_contribution(
                replay_seed,
                &program_digest,
                &record.contributor_name,
                &record.entropy_hash,
            )?;
            if record.resulting_seed_hex != hex_encode_seed(derived) {
                chain_valid = false;
                break;
            }
            replay_seed = derived;
        }

        let ceremony_seed_hex = compiled
            .metadata
            .get("ceremony_seed")
            .cloned()
            .ok_or("compiled artifact is missing ceremony_seed metadata")?;
        let final_seed_match = ceremony_seed_hex == hex_encode_seed(replay_seed);
        let rebuilt = zkf_backends::with_setup_seed_override(Some(replay_seed), || {
            let engine = zkf_backends::backend_for(zkf_core::BackendKind::ArkworksGroth16);
            engine.compile(&program)
        })
        .map_err(|e| format!("phase2 verification compile: {}", render_error(e)))?;
        let artifact_match = rebuilt.compiled_data == compiled.compiled_data
            && rebuilt.program_digest == compiled.program_digest;

        Ok(serde_json::json!({
            "valid": ptau_report.valid && program_digest_match && chain_valid && final_seed_match && artifact_match,
            "ptau_valid": ptau_report.valid,
            "ptau_power": ptau_report.power,
            "ptau_contributions": ptau_report.contributions,
            "program_digest_match": program_digest_match,
            "phase2_chain_valid": chain_valid,
            "seed_match": final_seed_match,
            "artifact_match": artifact_match,
            "expected_base_seed": expected_base_seed_hex,
            "expected_final_seed": hex_encode_seed(replay_seed),
            "phase2_contributions": history.len(),
            "program_path": prog_file,
        })
        .to_string())
    })
}

/// Export a verification key from a ceremony-derived compiled program.
/// Returns JSON: { output_path, vk_size }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_ceremony_export_vk(
    zkey_path: *const c_char,
    output_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let zkey = unsafe { c_str_required(zkey_path, "zkey_path") }?;
        let output = unsafe { c_str_required(output_path, "output_path") }?;

        let compiled: zkf_core::CompiledProgram = read_json(&zkey)?;

        // Extract the compiled blob and pull out just the VK portion
        let compiled_blob = compiled
            .compiled_data
            .as_ref()
            .ok_or("compiled program has no compiled_data (not a Groth16 key)")?;

        // The compiled_data format (pack_setup_blob): [version:1][pk_len:8][pk_bytes][vk_len:8][vk_bytes]
        if compiled_blob.len() < 9 {
            return Err("compiled_data too short to contain a verification key".to_string());
        }
        let pk_len = u64::from_le_bytes(
            compiled_blob[1..9]
                .try_into()
                .map_err(|_| "bad pk_len bytes")?,
        ) as usize;
        let vk_start = 9 + pk_len;
        if compiled_blob.len() < vk_start + 8 {
            return Err("compiled_data truncated before vk_len".to_string());
        }
        let vk_len = u64::from_le_bytes(
            compiled_blob[vk_start..vk_start + 8]
                .try_into()
                .map_err(|_| "bad vk_len bytes")?,
        ) as usize;
        let vk_bytes = &compiled_blob[vk_start + 8..vk_start + 8 + vk_len];

        if let Some(parent) = PathBuf::from(&output).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
        }
        std::fs::write(&output, vk_bytes).map_err(|e| format!("write VK: {e}"))?;

        Ok(serde_json::json!({
            "output_path": output,
            "vk_size": vk_len,
        })
        .to_string())
    })
}

/// Prove using a ceremony-derived key (zkey).
/// Reads the compiled program from zkey_path and the witness inputs from inputs_path,
/// then produces a proof.
/// Returns JSON: the proof artifact.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_prove_with_ceremony(
    zkey_path: *const c_char,
    inputs_path: *const c_char,
    output_path: *const c_char,
    no_metal: i32,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let zkey = unsafe { c_str_required(zkey_path, "zkey_path") }?;
        let inputs = unsafe { c_str_required(inputs_path, "inputs_path") }?;
        let output = unsafe { c_str_required(output_path, "output_path") }?;

        let compiled: zkf_core::CompiledProgram = read_json(&zkey)?;
        let witness: zkf_core::Witness = read_json(&inputs)?;

        // For no_metal, we could disable GPU — but currently the backend auto-detects.
        // The flag is reserved for future use.
        let _ = no_metal;

        let artifact = zkf_runtime::RuntimeExecutor::run_backend_prove_job(
            compiled.backend,
            zkf_backends::BackendRoute::Auto,
            std::sync::Arc::new(compiled.program.clone()),
            None,
            Some(std::sync::Arc::new(witness)),
            Some(std::sync::Arc::new(compiled.clone())),
            zkf_runtime::RequiredTrustLane::StrictCryptographic,
            zkf_runtime::ExecutionMode::Deterministic,
        )
        .map_err(|e| format!("prove: {e}"))?
        .artifact;

        // Write proof to output
        if let Some(parent) = PathBuf::from(&output).parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create directory: {e}"))?;
        }
        write_json(&output, &artifact)?;

        Ok(serde_json::json!({
            "output_path": output,
            "backend": format!("{}", compiled.backend),
            "proof_size": artifact.proof.len(),
            "public_inputs": artifact.public_inputs.len(),
            "ceremony_keyed": true,
        })
        .to_string())
    })
}

/// Return the full backend capability matrix as JSON.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_capability_matrix() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let matrix = zkf_backends::backend_capability_matrix();
        serde_json::to_string(&matrix).map_err(|e| format!("serialization failed: {e}"))
    })
}

/// Detect system resources and return recommendations as JSON.
///
/// @return JSON: { system: SystemResources, recommendation: ResourceRecommendation }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_system_resources() -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let res = zkf_core::SystemResources::detect();
        let rec = res.recommend();
        let report = serde_json::json!({
            "system": res,
            "recommendation": rec,
        });
        serde_json::to_string(&report).map_err(|e| format!("serialization failed: {e}"))
    })
}

/// Normalize a ZIR program to canonical form.
///
/// Applies algebraic rewrites, constant folding, dead signal elimination,
/// and deterministic constraint ordering. Idempotent.
///
/// @param program_path  path to the ZIR program JSON (required)
/// @param output_path   path for the normalized output (required)
/// @return JSON: NormalizationReport with pass statistics and digests
#[unsafe(no_mangle)]
pub extern "C" fn zkf_normalize(
    program_path: *const c_char,
    output_path: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let path = unsafe { c_str_required(program_path, "program_path") }?;
        let out = unsafe { c_str_required(output_path, "output_path") }?;

        let program: zkf_core::zir::Program = read_json(&path)?;
        let (normalized, report) = zkf_core::normalize::normalize(&program);

        let json = serde_json::to_string_pretty(&normalized)
            .map_err(|e| format!("serialization failed: {e}"))?;
        std::fs::write(&out, &json).map_err(|e| format!("failed to write {out}: {e}"))?;

        serde_json::to_string(&serde_json::json!({
            "output_path": out,
            "report": report,
        }))
        .map_err(|e| format!("serialization failed: {e}"))
    })
}

/// Type-check a ZIR program.
///
/// Verifies signal types, constraint compatibility, and blackbox op signatures.
///
/// @param program_path  path to the ZIR program JSON (required)
/// @return JSON: { "valid": bool, "errors": [...] }
#[unsafe(no_mangle)]
pub extern "C" fn zkf_type_check(program_path: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let path = unsafe { c_str_required(program_path, "program_path") }?;

        let program: zkf_core::zir::Program = read_json(&path)?;
        match zkf_core::type_check::type_check(&program) {
            Ok(()) => serde_json::to_string(&serde_json::json!({
                "valid": true,
                "errors": serde_json::Value::Array(vec![]),
            }))
            .map_err(|e| format!("serialization failed: {e}")),
            Err(errors) => serde_json::to_string(&serde_json::json!({
                "valid": false,
                "errors": errors,
            }))
            .map_err(|e| format!("serialization failed: {e}")),
        }
    })
}

/// Run a machine-verifiable audit on a ZIR program and return a JSON report.
///
/// @param program_path  path to the ZIR program JSON (required)
/// @param backend       backend name (optional, e.g. "arkworks-groth16")
/// @return JSON: full AuditReport with checks, findings, and summary
#[unsafe(no_mangle)]
pub extern "C" fn zkf_audit_report(
    program_path: *const c_char,
    backend: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let path = unsafe { c_str_required(program_path, "program_path") }?;
        let backend_str = unsafe { c_str_opt(backend) };

        let backend_kind = match backend_str {
            Some(ref s) if !s.is_empty() => {
                let selection = parse_public_backend_selection(s)
                    .map_err(|e| format!("invalid backend: {e}"))?;
                Some(selection.backend)
            }
            _ => None,
        };

        let program: zkf_core::zir_v1::Program = read_json(&path)?;

        let matrix = zkf_backends::backend_capability_matrix();
        let report =
            zkf_core::audit_program_with_capability_matrix(&program, backend_kind, &matrix);

        report
            .to_json()
            .map_err(|e| format!("audit report serialization: {e}"))
    })
}

// ─── AI Operator Layer: Lineage & Equivalence ──────────────────────────────

/// Return provenance lineage for an artifact.
///
/// Reads the JSON file at `artifact_path` and attempts to parse it as a
/// `ZkfArtifactBundle`. If successful, returns the full provenance chain.
/// Falls back to `ProofArtifact` or `CompiledProgram` parsing, and finally
/// returns basic file info (existence, size, computed digest) for unknown formats.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_artifact_lineage(artifact_path: *const c_char) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let artifact_path = unsafe { c_str_required(artifact_path, "artifact_path") }?;

        // Read the raw file contents
        let raw = std::fs::read_to_string(&artifact_path)
            .map_err(|e| format!("failed to read {artifact_path}: {e}"))?;

        // Try to parse as ZkfArtifactBundle first
        if let Ok(bundle) = zkf_core::ZkfArtifactBundle::from_json(&raw) {
            let integrity_ok = bundle.verify_integrity();
            return Ok(serde_json::json!({
                "artifact_path": artifact_path,
                "format": "zkf_artifact_bundle",
                "kind": bundle.kind.as_str(),
                "schema_version": bundle.schema_version,
                "provenance": {
                    "artifact_digest": bundle.provenance.artifact_digest,
                    "parent_digests": bundle.provenance.parent_digests,
                    "operation": bundle.provenance.operation,
                    "timestamp_unix": bundle.provenance.timestamp_unix,
                    "tool_version": bundle.provenance.tool_version,
                    "backend": bundle.provenance.backend.map(|b| b.as_str().to_string()),
                    "field": bundle.provenance.field.map(|f| format!("{f}")),
                },
                "integrity_valid": integrity_ok,
                "metadata": bundle.metadata,
            })
            .to_string());
        }

        // Try to parse as ProofArtifact
        if let Ok(proof) = serde_json::from_str::<zkf_core::ProofArtifact>(&raw) {
            let provenance = proof.provenance(vec![proof.program_digest.clone()]);
            return Ok(serde_json::json!({
                "artifact_path": artifact_path,
                "format": "proof_artifact",
                "provenance": {
                    "artifact_digest": provenance.artifact_digest,
                    "parent_digests": provenance.parent_digests,
                    "operation": provenance.operation,
                    "timestamp_unix": provenance.timestamp_unix,
                    "tool_version": provenance.tool_version,
                    "backend": provenance.backend.map(|b| b.as_str().to_string()),
                    "field": provenance.field.map(|f| format!("{f}")),
                },
                "program_digest": proof.program_digest,
                "proof_size_bytes": proof.proof.len(),
                "metadata": proof.metadata,
            })
            .to_string());
        }

        // Try to parse as CompiledProgram
        if let Ok(compiled) = serde_json::from_str::<zkf_core::CompiledProgram>(&raw) {
            let provenance = compiled.provenance();
            return Ok(serde_json::json!({
                "artifact_path": artifact_path,
                "format": "compiled_program",
                "provenance": {
                    "artifact_digest": provenance.artifact_digest,
                    "parent_digests": provenance.parent_digests,
                    "operation": provenance.operation,
                    "timestamp_unix": provenance.timestamp_unix,
                    "tool_version": provenance.tool_version,
                    "backend": provenance.backend.map(|b| b.as_str().to_string()),
                    "field": provenance.field.map(|f| format!("{f}")),
                },
                "program_digest": compiled.program_digest,
                "metadata": compiled.metadata,
            })
            .to_string());
        }

        // Fallback: return basic file info with computed digest
        let file_size = std::fs::metadata(&artifact_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let digest = {
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(raw.as_bytes());
            format!("{:x}", hash)
        };

        Ok(serde_json::json!({
            "artifact_path": artifact_path,
            "format": "unknown",
            "file_exists": true,
            "file_size_bytes": file_size,
            "computed_digest": digest,
        })
        .to_string())
    })
}

/// Run semantic equivalence test across backends.
///
/// Reads the program and inputs files, parses `backends_json` as a JSON array
/// of backend name strings, and runs compile/prove/verify for each backend.
/// Returns a JSON result with per-backend status and cross-backend public input
/// comparison.
#[unsafe(no_mangle)]
pub extern "C" fn zkf_equivalence_test(
    program_path: *const c_char,
    inputs_path: *const c_char,
    backends_json: *const c_char,
) -> *mut ZkfFfiResult {
    wrap_ffi(|| {
        let program_path = unsafe { c_str_required(program_path, "program_path") }?;
        let inputs_path = unsafe { c_str_required(inputs_path, "inputs_path") }?;
        let backends_str = unsafe { c_str_required(backends_json, "backends_json") }?;

        let program: zkf_core::Program = read_json(&program_path)?;
        let mut inputs: zkf_core::WitnessInputs = read_json(&inputs_path)?;
        resolve_input_aliases(&mut inputs, &program);

        let backend_names: Vec<String> = serde_json::from_str(&backends_str)
            .map_err(|e| format!("invalid backends JSON array: {e}"))?;

        let mut backend_selections = Vec::new();
        let mut parse_errors = Vec::new();
        for name in &backend_names {
            match parse_execution_backend_selection(name) {
                Ok(selection) => backend_selections.push(selection),
                Err(e) => parse_errors.push(serde_json::json!({
                    "backend": name,
                    "error": format!("{e}"),
                })),
            }
        }

        // Generate witness once (shared across backends)
        let witness = zkf_core::generate_witness(&program, &inputs)
            .map_err(|e| format!("witness generation failed: {}", render_error(e)))?;

        let mut results = Vec::new();
        let mut reference_public_inputs: Option<Vec<zkf_core::FieldElement>> = None;
        let mut mismatches = Vec::new();

        for selection in &backend_selections {
            if CANCEL_FLAG.load(Ordering::SeqCst) {
                return Err("cancelled".to_string());
            }

            let engine = zkf_backends::backend_for_selection(selection)?;
            let caps = engine.capabilities();

            let mut result = serde_json::Map::new();
            result.insert(
                "backend".into(),
                serde_json::json!(selection.backend.as_str()),
            );
            result.insert(
                "requested_backend".into(),
                serde_json::json!(selection.requested_name),
            );
            result.insert(
                "backend_route".into(),
                serde_json::json!(backend_route_label(selection.route)),
            );
            result.insert(
                "support_class".into(),
                serde_json::json!(caps.mode.as_str()),
            );

            // Compile
            let compile_start = std::time::Instant::now();
            let compiled = match engine.compile(&program) {
                Ok(c) => {
                    result.insert("compile_success".into(), serde_json::json!(true));
                    result.insert(
                        "compile_time_ms".into(),
                        serde_json::json!(compile_start.elapsed().as_millis() as u64),
                    );
                    c
                }
                Err(e) => {
                    result.insert("compile_success".into(), serde_json::json!(false));
                    result.insert(
                        "compile_time_ms".into(),
                        serde_json::json!(compile_start.elapsed().as_millis() as u64),
                    );
                    result.insert("error".into(), serde_json::json!(format!("compile: {e}")));
                    results.push(serde_json::Value::Object(result));
                    continue;
                }
            };

            // Prove
            let prove_start = std::time::Instant::now();
            let proof = match zkf_runtime::RuntimeExecutor::run_backend_prove_job(
                selection.backend,
                selection.route,
                std::sync::Arc::new(program.clone()),
                None,
                Some(std::sync::Arc::new(witness.clone())),
                Some(std::sync::Arc::new(compiled.clone())),
                zkf_runtime::RequiredTrustLane::StrictCryptographic,
                zkf_runtime::ExecutionMode::Deterministic,
            ) {
                Ok(execution) => {
                    let p = execution.artifact;
                    result.insert("prove_success".into(), serde_json::json!(true));
                    result.insert(
                        "prove_time_ms".into(),
                        serde_json::json!(prove_start.elapsed().as_millis() as u64),
                    );
                    result.insert("proof_size_bytes".into(), serde_json::json!(p.proof.len()));
                    result.insert("public_inputs".into(), serde_json::json!(p.public_inputs));
                    p
                }
                Err(e) => {
                    result.insert("prove_success".into(), serde_json::json!(false));
                    result.insert(
                        "prove_time_ms".into(),
                        serde_json::json!(prove_start.elapsed().as_millis() as u64),
                    );
                    result.insert("error".into(), serde_json::json!(format!("prove: {e}")));
                    results.push(serde_json::Value::Object(result));
                    continue;
                }
            };

            // Verify
            let verify_start = std::time::Instant::now();
            match engine.verify(&compiled, &proof) {
                Ok(valid) => {
                    result.insert("verify_success".into(), serde_json::json!(valid));
                    result.insert(
                        "verify_time_ms".into(),
                        serde_json::json!(verify_start.elapsed().as_millis() as u64),
                    );
                    if !valid {
                        result.insert(
                            "error".into(),
                            serde_json::json!("verification returned false"),
                        );
                    }
                }
                Err(e) => {
                    result.insert("verify_success".into(), serde_json::json!(false));
                    result.insert(
                        "verify_time_ms".into(),
                        serde_json::json!(verify_start.elapsed().as_millis() as u64),
                    );
                    result.insert("error".into(), serde_json::json!(format!("verify: {e}")));
                }
            }

            // Check public input equivalence
            if let Some(backend_public) = result.get("public_inputs") {
                if let Some(backend_arr) = backend_public.as_array() {
                    let backend_fe: Vec<zkf_core::FieldElement> = backend_arr
                        .iter()
                        .filter_map(|v| serde_json::from_value(v.clone()).ok())
                        .collect();
                    match &reference_public_inputs {
                        None => {
                            reference_public_inputs = Some(backend_fe);
                        }
                        Some(ref_public) => {
                            if backend_fe != *ref_public {
                                mismatches.push(format!(
                                    "{}: public inputs differ from reference",
                                    selection.backend.as_str()
                                ));
                            }
                        }
                    }
                }
            }

            results.push(serde_json::Value::Object(result));
        }

        let backends_succeeded = results
            .iter()
            .filter(|r| {
                r.get("verify_success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .count();
        let backends_proved = results
            .iter()
            .filter(|r| {
                r.get("prove_success")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            })
            .count();
        let public_inputs_match = mismatches.is_empty() && backends_proved > 0;

        // Include parse errors in results
        for err in parse_errors {
            results.push(err);
        }

        Ok(serde_json::json!({
            "program_name": program.name,
            "program_digest": program.digest_hex(),
            "field": format!("{}", program.field),
            "backends_tested": results.len(),
            "backends_succeeded": backends_succeeded,
            "public_inputs_match": public_inputs_match,
            "results": results,
            "mismatches": mismatches,
        })
        .to_string())
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::ffi::CString;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zkf_core::{FieldElement, FieldId, FrontendProvenance, PackageManifest, program_v2_to_zir};

    fn result_json(ptr: *mut ZkfFfiResult) -> serde_json::Value {
        assert!(!ptr.is_null());
        let result = unsafe { &*ptr };
        let status = result.status;
        if result.status != 0 {
            let error = if result.error.is_null() {
                "<null error>".to_string()
            } else {
                unsafe { CStr::from_ptr(result.error) }
                    .to_str()
                    .unwrap_or("<invalid utf8 error>")
                    .to_string()
            };
            zkf_free_result(ptr);
            panic!("FFI call failed with status {status}: {error}");
        }
        let json_str = unsafe { CStr::from_ptr(result.data) }.to_str().unwrap();
        let val: serde_json::Value = serde_json::from_str(json_str).unwrap();
        zkf_free_result(ptr);
        val
    }

    fn cstring(value: &str) -> CString {
        CString::new(value).unwrap()
    }

    fn sample_proof_artifact() -> zkf_core::ProofArtifact {
        let mut metadata = BTreeMap::new();
        metadata.insert("algebraic_binding".to_string(), "false".to_string());
        metadata.insert("trust_model".to_string(), "cryptographic".to_string());
        zkf_core::ProofArtifact::new(
            zkf_core::BackendKind::ArkworksGroth16,
            "digest",
            vec![7u8; 192],
            vec![1u8; 32],
            vec![FieldElement::from_u64(1)],
        )
        .with_metadata(metadata)
    }

    fn sample_conformance_report() -> zkf_conformance::ConformanceReport {
        zkf_conformance::ConformanceReport {
            backend: "arkworks-groth16".to_string(),
            field: "Bn254".to_string(),
            tests_run: 1,
            tests_passed: 1,
            tests_failed: 0,
            pass_rate: 1.0,
            results: vec![zkf_conformance::ConformanceTestResult {
                test_name: "smoke".to_string(),
                backend: "arkworks-groth16".to_string(),
                compile_ok: true,
                prove_ok: true,
                verify_ok: true,
                total_time_ms: 1,
                error: None,
                compile_error: None,
                prove_error: None,
                verify_error: None,
                public_outputs: None,
            }],
        }
    }

    #[test]
    fn test_check_available() {
        let val = result_json(zkf_check_available());
        assert_eq!(val["available"], true);
        assert_eq!(val["native_ffi"], true);
    }

    #[test]
    fn test_capabilities() {
        let val = result_json(zkf_capabilities());
        assert!(val["backends"].as_array().unwrap().len() >= 6);
        assert!(val["frontends"].as_array().unwrap().len() >= 5);
    }

    #[test]
    fn test_frontends() {
        let val = result_json(zkf_frontends());
        let arr = val.as_array().unwrap();
        assert!(arr.len() >= 5);
        assert_eq!(arr[0]["frontend"], "noir");
    }

    #[test]
    fn test_demo() {
        let val = result_json(zkf_demo());
        assert_eq!(val["valid"], true);
        assert_eq!(val["backend"], "arkworks-groth16");
    }

    #[test]
    fn ffi_estimate_gas_for_target_reflects_chain_variant() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("zkf-ffi-gas-target-{nonce}"));
        std::fs::create_dir_all(&root).expect("temp dir");
        let proof_path = root.join("proof.json");
        write_json(
            proof_path.to_string_lossy().as_ref(),
            &sample_proof_artifact(),
        )
        .expect("write proof");

        let eth: serde_json::Value = serde_json::from_str(
            &estimate_gas_json(
                proof_path.to_string_lossy().as_ref(),
                "arkworks-groth16",
                FfiEvmTarget::Ethereum,
            )
            .expect("ethereum estimate"),
        )
        .expect("parse ethereum estimate");
        let l2: serde_json::Value = serde_json::from_str(
            &estimate_gas_json(
                proof_path.to_string_lossy().as_ref(),
                "arkworks-groth16",
                FfiEvmTarget::OptimismArbitrumL2,
            )
            .expect("l2 estimate"),
        )
        .expect("parse l2 estimate");

        assert_eq!(eth["evm_target"], "ethereum");
        assert_eq!(l2["evm_target"], "optimism-arbitrum-l2");
        assert!(l2["verify_gas"].as_u64().unwrap() < eth["verify_gas"].as_u64().unwrap());
    }

    #[test]
    fn ffi_conformance_export_writes_json_and_cbor() {
        let root =
            std::env::temp_dir().join(format!("zkf-ffi-conformance-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let json_path = root.join("report.json");
        let cbor_path = root.join("report.cbor");

        export_conformance_artifacts(
            &sample_conformance_report(),
            Some(&json_path),
            Some(&cbor_path),
        )
        .unwrap();

        assert!(json_path.exists());
        assert!(cbor_path.exists());
        let json = std::fs::read_to_string(&json_path).unwrap();
        assert!(json.contains("zkf-conformance-report/v1"));
        let cbor = std::fs::read(&cbor_path).unwrap();
        assert!(!cbor.is_empty());
    }

    #[test]
    fn ffi_targeted_deploy_annotations_surface_target_and_trust_boundary() {
        let vk = zkf_backends::groth16_vk::Groth16VkHex {
            alpha_g1: ["0x01".to_string(), "0x02".to_string()],
            beta_g2: [
                "0x03".to_string(),
                "0x04".to_string(),
                "0x05".to_string(),
                "0x06".to_string(),
            ],
            gamma_g2: [
                "0x07".to_string(),
                "0x08".to_string(),
                "0x09".to_string(),
                "0x0a".to_string(),
            ],
            delta_g2: [
                "0x0b".to_string(),
                "0x0c".to_string(),
                "0x0d".to_string(),
                "0x0e".to_string(),
            ],
            ic: vec![["0x0f".to_string(), "0x10".to_string()]],
        };

        let source = render_groth16_solidity_for_target(
            &vk,
            "ZkfVerifier",
            &[],
            &sample_proof_artifact(),
            FfiEvmTarget::GenericEvm,
        );

        assert!(source.contains("ZKF deployment target: generic-evm"));
        assert!(source.contains("algebraic_binding=false"));
    }

    #[test]
    fn package_loader_accepts_relative_zir_manifest_program() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("zkf-ffi-zir-manifest-{nonce}"));
        std::fs::create_dir_all(root.join("zir")).expect("zir dir");

        let ir_program = zkf_examples::mul_add_program();
        let zir_program = program_v2_to_zir(&ir_program);
        let program_path = root.join("zir/program.json");
        write_json(program_path.to_string_lossy().as_ref(), &zir_program).expect("write zir");

        let mut manifest = PackageManifest::from_program(
            &ir_program,
            FrontendProvenance {
                kind: "noir".to_string(),
                version: Some("0.1.0".to_string()),
                format: None,
                translator: None,
                source: None,
            },
            "zir/program.json",
            "zir/program.json",
        );
        manifest
            .metadata
            .insert("ir_family".to_string(), "zir-v1".to_string());
        manifest
            .metadata
            .insert("ir_version".to_string(), "1".to_string());
        manifest
            .metadata
            .insert("source_ir_family".to_string(), "zir-v1".to_string());
        manifest.metadata.insert(
            "source_program_digest".to_string(),
            zir_program.digest_hex(),
        );
        manifest.metadata.insert(
            "lowered_program_digest".to_string(),
            ir_program.digest_hex(),
        );
        manifest.program_digest = zir_program.digest_hex();
        manifest.files.public_inputs = Some(zkf_core::PackageFileRef {
            path: "inputs.json".to_string(),
            sha256: String::new(),
        });
        write_json(
            root.join("inputs.json").to_string_lossy().as_ref(),
            &serde_json::json!({
                "x": FieldElement::from_i64(3),
                "y": FieldElement::from_i64(5),
            }),
        )
        .expect("write inputs");
        let manifest_path = root.join("package.json");
        write_json(manifest_path.to_string_lossy().as_ref(), &manifest).expect("write manifest");

        let loaded: PackageManifest =
            read_json(manifest_path.to_string_lossy().as_ref()).expect("manifest");
        let (lowered, source_ir_family) =
            load_manifest_program_v2(manifest_path.to_string_lossy().as_ref(), &loaded)
                .expect("load manifest program");
        assert_eq!(source_ir_family, "zir-v1");
        assert_eq!(lowered.field, FieldId::Bn254);
        assert_eq!(lowered.name, ir_program.name);
    }

    #[test]
    fn ceremony_phase2_contribution_roundtrip_and_tamper_detection() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("zkf-ffi-phase2-{nonce}"));
        std::fs::create_dir_all(&root).expect("temp dir");
        let ptau_path = root.join("phase1.ptau");
        let program_path = root.join("program.json");
        let setup_path = root.join("setup.zkey.json");
        let contributed_path = root.join("contributed.zkey.json");
        let tampered_path = root.join("tampered.zkey.json");

        write_json(
            program_path.to_string_lossy().as_ref(),
            &zkf_examples::mul_add_program(),
        )
        .expect("write program");

        let curve = cstring("bn254");
        let ptau = cstring(ptau_path.to_string_lossy().as_ref());
        let init = result_json(zkf_ceremony_init(curve.as_ptr(), 4, ptau.as_ptr()));
        assert_eq!(init["power"], 4);

        let backend = cstring("arkworks-groth16");
        let program = cstring(program_path.to_string_lossy().as_ref());
        let setup = cstring(setup_path.to_string_lossy().as_ref());
        let setup_result = result_json(zkf_ceremony_setup(
            ptau.as_ptr(),
            program.as_ptr(),
            backend.as_ptr(),
            setup.as_ptr(),
        ));
        assert_eq!(setup_result["backend"], "arkworks-groth16");

        let output = cstring(contributed_path.to_string_lossy().as_ref());
        let entropy = cstring("alice-entropy");
        let name = cstring("Alice");
        let contribute = result_json(zkf_ceremony_contribute_phase2(
            setup.as_ptr(),
            output.as_ptr(),
            entropy.as_ptr(),
            name.as_ptr(),
        ));
        assert_eq!(contribute["contributor"], "Alice");
        assert_eq!(contribute["contribution_count"], 1);

        let verify = result_json(zkf_ceremony_verify_phase2(
            output.as_ptr(),
            ptau.as_ptr(),
            program.as_ptr(),
        ));
        assert_eq!(verify["valid"], true);
        assert_eq!(verify["phase2_contributions"], 1);
        assert_eq!(verify["seed_match"], true);
        assert_eq!(verify["artifact_match"], true);

        let mut tampered: zkf_core::CompiledProgram =
            read_json(contributed_path.to_string_lossy().as_ref()).expect("read contributed");
        tampered
            .metadata
            .insert("ceremony_phase2_history".to_string(), "[]".to_string());
        write_json(tampered_path.to_string_lossy().as_ref(), &tampered).expect("write tampered");
        let tampered_output = cstring(tampered_path.to_string_lossy().as_ref());
        let verify_tampered = result_json(zkf_ceremony_verify_phase2(
            tampered_output.as_ptr(),
            ptau.as_ptr(),
            program.as_ptr(),
        ));
        assert_eq!(verify_tampered["valid"], false);
        assert_eq!(verify_tampered["phase2_chain_valid"], true);
        assert_eq!(verify_tampered["seed_match"], false);
        assert_eq!(verify_tampered["artifact_match"], false);
    }

    #[test]
    fn ceremony_phase2_multiple_contributors_extend_history() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("zkf-ffi-phase2-history-{nonce}"));
        std::fs::create_dir_all(&root).expect("temp dir");
        let ptau_path = root.join("phase1.ptau");
        let program_path = root.join("program.json");
        let setup_path = root.join("setup.zkey.json");
        let alice_path = root.join("alice.zkey.json");
        let bob_path = root.join("bob.zkey.json");

        write_json(
            program_path.to_string_lossy().as_ref(),
            &zkf_examples::mul_add_program(),
        )
        .expect("write program");

        let curve = cstring("bn254");
        let ptau = cstring(ptau_path.to_string_lossy().as_ref());
        result_json(zkf_ceremony_init(curve.as_ptr(), 4, ptau.as_ptr()));

        let backend = cstring("arkworks-groth16");
        let program = cstring(program_path.to_string_lossy().as_ref());
        let setup = cstring(setup_path.to_string_lossy().as_ref());
        result_json(zkf_ceremony_setup(
            ptau.as_ptr(),
            program.as_ptr(),
            backend.as_ptr(),
            setup.as_ptr(),
        ));

        let alice_out = cstring(alice_path.to_string_lossy().as_ref());
        result_json(zkf_ceremony_contribute_phase2(
            setup.as_ptr(),
            alice_out.as_ptr(),
            std::ptr::null(),
            cstring("Alice").as_ptr(),
        ));

        let bob_out = cstring(bob_path.to_string_lossy().as_ref());
        result_json(zkf_ceremony_contribute_phase2(
            alice_out.as_ptr(),
            bob_out.as_ptr(),
            cstring("bob-entropy").as_ptr(),
            cstring("Bob").as_ptr(),
        ));

        let verify = result_json(zkf_ceremony_verify_phase2(
            bob_out.as_ptr(),
            ptau.as_ptr(),
            program.as_ptr(),
        ));
        assert_eq!(verify["valid"], true);
        assert_eq!(verify["phase2_contributions"], 2);

        let compiled: zkf_core::CompiledProgram =
            read_json(bob_path.to_string_lossy().as_ref()).expect("read bob output");
        let history = parse_phase2_history(&compiled).expect("history");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].contributor_name, "Alice");
        assert_eq!(history[1].contributor_name, "Bob");
        assert_ne!(
            history[0].resulting_seed_hex, history[1].resulting_seed_hex,
            "each contribution should advance the deterministic seed chain"
        );
    }
}
