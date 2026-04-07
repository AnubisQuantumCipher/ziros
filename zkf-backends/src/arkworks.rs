use crate::audited_backend::{
    attach_r1cs_lowering_metadata, audited_witness_for_proving, build_audited_compiled_program,
    remember_unchecked_compile_gate_bypass,
};
use crate::blackbox_native::supported_blackbox_ops;
use crate::blackbox_native::validate_blackbox_constraints;
use crate::metal_runtime::append_backend_runtime_metadata;
use crate::r1cs_lowering::lower_program_for_backend;
use crate::{
    BackendEngine, GROTH16_AUTO_CEREMONY_PROVENANCE, GROTH16_AUTO_CEREMONY_SECURITY_BOUNDARY,
    GROTH16_CEREMONY_ID_METADATA_KEY, GROTH16_CEREMONY_KIND_METADATA_KEY,
    GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY, GROTH16_CEREMONY_REPORT_SHA256_METADATA_KEY,
    GROTH16_CEREMONY_SEED_COMMITMENT_METADATA_KEY, GROTH16_CEREMONY_SUBSYSTEM_METADATA_KEY,
    GROTH16_DETERMINISTIC_DEV_PROVENANCE, GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY,
    GROTH16_IMPORTED_SETUP_PROVENANCE, GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY,
    GROTH16_SETUP_BLOB_PATH_METADATA_KEY, GROTH16_SETUP_PROVENANCE_METADATA_KEY,
    GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY, GROTH16_STREAMED_PK_PATH_METADATA_KEY,
    GROTH16_STREAMED_SETUP_STORAGE_METADATA_KEY, GROTH16_STREAMED_SETUP_STORAGE_VALUE,
    GROTH16_STREAMED_SHAPE_PATH_METADATA_KEY, allow_dev_deterministic_groth16, proof_seed_override,
    requested_groth16_setup_blob_path, setup_seed_override,
};
use ark_bn254::{Bn254, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM, scalar_mul::BatchMulPreprocessing};
use ark_ff::{
    BigInteger, FftField, Field, One, PrimeField, UniformRand, Zero, fields::batch_inversion,
};
use ark_groth16::{
    Groth16, Proof, ProvingKey, VerifyingKey,
    r1cs_to_qap::{LibsnarkReduction, R1CSToQAP},
};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{
    ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef,
    LinearCombination, OptimizationGoal, SynthesisError, SynthesisMode, Variable,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use zkf_core::acceleration::accelerator_registry;
use zkf_core::{
    BackendCapabilities, BackendKind, BackendMode, CompiledProgram, Constraint, Expr, FieldElement,
    FieldId, PressureLevel, Program, ProofArtifact, SystemResources, Visibility, Witness,
    WitnessInputs, ZkfError, ZkfResult, check_constraints, collect_public_inputs, generate_witness,
};

const SETUP_BLOB_VERSION: u8 = 1;
const ATOMIC_TEMP_STALE_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const LARGE_GROTH16_SETUP_SIGNAL_THRESHOLD: usize = 1_000;
const LARGE_GROTH16_SETUP_CONSTRAINT_THRESHOLD: usize = 1_000;
const FORTY_EIGHT_GIB: u64 = 48 * 1024 * 1024 * 1024;
const SIXTY_FOUR_GIB: u64 = 64 * 1024 * 1024 * 1024;

pub struct ArkworksGroth16Backend;

#[derive(Debug, Clone)]
struct ImportedSetupBlob {
    path: String,
    blob: Vec<u8>,
}

#[derive(Debug, Clone)]
struct StreamedSetupBlob {
    blob: Vec<u8>,
    pk_path: PathBuf,
    shape_path: PathBuf,
}

#[derive(Debug, Clone, Copy)]
enum AutoCeremonySeedSource {
    ExistingCache,
    Generated,
    MigratedLegacyCache,
}

impl AutoCeremonySeedSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::ExistingCache => "existing-cache",
            Self::Generated => "generated-os-rng",
            Self::MigratedLegacyCache => "migrated-legacy-cache",
        }
    }
}

#[derive(Debug, Clone)]
struct AutoCeremonyContext {
    subsystem_id: String,
    ceremony_id: String,
    seed_path: PathBuf,
    report_path: PathBuf,
    seed: [u8; 32],
    seed_source: AutoCeremonySeedSource,
}

#[derive(Debug, Serialize, Deserialize)]
struct AutoCeremonySubsystemManifest {
    schema: String,
    backend: String,
    subsystem_id: String,
    created_at_unix: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct AutoCeremonyProgramReport {
    schema: String,
    backend: String,
    subsystem_id: String,
    ceremony_id: String,
    ceremony_kind: String,
    program_name: String,
    program_digest: String,
    created_at_unix: u64,
    seed_source: String,
    seed_commitment_sha256: String,
    seed_path: String,
    setup_storage: String,
    setup_blob_version: u8,
    setup_blob_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    streamed_pk_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    streamed_shape_path: Option<String>,
    security_boundary: String,
}

fn unix_timestamp_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sanitize_ceremony_path_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    sanitized
        .trim_matches('-')
        .chars()
        .take(96)
        .collect::<String>()
}

fn groth16_auto_ceremony_subsystem_id(program: &Program) -> String {
    [
        "subsystem_id",
        "subsystem",
        "application",
        "app_id",
        "app",
        "owner",
    ]
    .iter()
    .find_map(|key| program.metadata.get(*key))
    .filter(|value| !value.trim().is_empty())
    .cloned()
    .unwrap_or_else(|| program.name.clone())
}

fn ensure_auto_ceremony_subsystem_manifest(cache_dir: &Path, subsystem_id: &str) -> ZkfResult<()> {
    let manifest_path = cache_dir.join("subsystem.json");
    if manifest_path.exists() {
        return Ok(());
    }
    let manifest = AutoCeremonySubsystemManifest {
        schema: "zkf-groth16-auto-ceremony-subsystem-v1".to_string(),
        backend: BackendKind::ArkworksGroth16.as_str().to_string(),
        subsystem_id: subsystem_id.to_string(),
        created_at_unix: unix_timestamp_now(),
    };
    let bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
    fs::write(&manifest_path, bytes).map_err(|err| {
        ZkfError::Io(format!(
            "failed to write Groth16 auto-ceremony subsystem manifest '{}': {err}",
            manifest_path.display()
        ))
    })
}

fn legacy_auto_ceremony_seed_path(program_digest: &str) -> PathBuf {
    groth16_auto_ceremony_cache_dir().join(format!("{program_digest}.seed"))
}

fn auto_ceremony_context(
    program: &Program,
    program_digest: &str,
) -> ZkfResult<AutoCeremonyContext> {
    let subsystem_id = groth16_auto_ceremony_subsystem_id(program);
    let subsystem_slug = sanitize_ceremony_path_component(&subsystem_id);
    let subsystem_dir = groth16_auto_ceremony_cache_dir().join(subsystem_slug);
    let program_dir = subsystem_dir.join("programs").join(program_digest);
    fs::create_dir_all(&program_dir).map_err(|err| {
        ZkfError::Io(format!(
            "failed to create Groth16 auto-ceremony cache dir '{}': {err}",
            program_dir.display()
        ))
    })?;
    ensure_auto_ceremony_subsystem_manifest(&subsystem_dir, &subsystem_id)?;

    let seed_path = program_dir.join("phase2.seed");
    let report_path = program_dir.join("report.json");

    if let Ok(bytes) = fs::read(&seed_path)
        && bytes.len() == 32
    {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok(AutoCeremonyContext {
            subsystem_id: subsystem_id.clone(),
            ceremony_id: format!("{}/{}", subsystem_id, program_digest),
            seed_path,
            report_path,
            seed,
            seed_source: AutoCeremonySeedSource::ExistingCache,
        });
    }

    let legacy_seed_path = legacy_auto_ceremony_seed_path(program_digest);
    if let Ok(bytes) = fs::read(&legacy_seed_path)
        && bytes.len() == 32
    {
        fs::write(&seed_path, &bytes).map_err(|err| {
            ZkfError::Io(format!(
                "failed to migrate Groth16 legacy auto-ceremony seed to '{}': {err}",
                seed_path.display()
            ))
        })?;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        return Ok(AutoCeremonyContext {
            subsystem_id: subsystem_id.clone(),
            ceremony_id: format!("{}/{}", subsystem_id, program_digest),
            seed_path,
            report_path,
            seed,
            seed_source: AutoCeremonySeedSource::MigratedLegacyCache,
        });
    }

    let mut seed = [0u8; 32];
    StdRng::from_entropy().fill(&mut seed);
    fs::write(&seed_path, seed).map_err(|err| {
        ZkfError::Io(format!(
            "failed to write Groth16 auto-ceremony seed to '{}': {err}",
            seed_path.display()
        ))
    })?;
    Ok(AutoCeremonyContext {
        subsystem_id: subsystem_id.clone(),
        ceremony_id: format!("{}/{}", subsystem_id, program_digest),
        seed_path,
        report_path,
        seed,
        seed_source: AutoCeremonySeedSource::Generated,
    })
}

fn write_auto_ceremony_report(
    context: &AutoCeremonyContext,
    program: &Program,
    program_digest: &str,
    setup_blob: &[u8],
    streamed_setup: Option<&StreamedSetupBlob>,
) -> ZkfResult<String> {
    let report = AutoCeremonyProgramReport {
        schema: "zkf-groth16-auto-ceremony-report-v1".to_string(),
        backend: BackendKind::ArkworksGroth16.as_str().to_string(),
        subsystem_id: context.subsystem_id.clone(),
        ceremony_id: context.ceremony_id.clone(),
        ceremony_kind: "subsystem-scoped-auto-phase2".to_string(),
        program_name: program.name.clone(),
        program_digest: program_digest.to_string(),
        created_at_unix: unix_timestamp_now(),
        seed_source: context.seed_source.as_str().to_string(),
        seed_commitment_sha256: sha256_hex(&context.seed),
        seed_path: context.seed_path.display().to_string(),
        setup_storage: if streamed_setup.is_some() {
            GROTH16_STREAMED_SETUP_STORAGE_VALUE.to_string()
        } else {
            "compiled-blob".to_string()
        },
        setup_blob_version: SETUP_BLOB_VERSION,
        setup_blob_sha256: sha256_hex(setup_blob),
        streamed_pk_path: streamed_setup.map(|value| value.pk_path.display().to_string()),
        streamed_shape_path: streamed_setup.map(|value| value.shape_path.display().to_string()),
        security_boundary: GROTH16_AUTO_CEREMONY_SECURITY_BOUNDARY.to_string(),
    };
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
    fs::write(&context.report_path, &bytes).map_err(|err| {
        ZkfError::Io(format!(
            "failed to write Groth16 auto-ceremony report '{}': {err}",
            context.report_path.display()
        ))
    })?;
    Ok(sha256_hex(&bytes))
}

fn load_requested_setup_blob(path: impl AsRef<Path>) -> ZkfResult<Vec<u8>> {
    let path = path.as_ref();
    let blob = fs::read(path).map_err(|err| {
        ZkfError::Io(format!(
            "failed to read Groth16 setup blob '{}': {err}",
            path.display()
        ))
    })?;
    let (pk_bytes, vk_bytes) = unpack_setup_blob(&blob)?;
    ProvingKey::<Bn254>::deserialize_compressed(pk_bytes.as_slice()).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize Groth16 proving key from setup blob '{}': {err}",
            path.display()
        ))
    })?;
    VerifyingKey::<Bn254>::deserialize_compressed(vk_bytes.as_slice()).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize Groth16 verification key from setup blob '{}': {err}",
            path.display()
        ))
    })?;
    Ok(blob)
}

fn imported_setup_blob_for_program(program: &Program) -> ZkfResult<Option<ImportedSetupBlob>> {
    requested_groth16_setup_blob_path(program)
        .map(|path| {
            Ok(ImportedSetupBlob {
                blob: load_requested_setup_blob(&path)?,
                path,
            })
        })
        .transpose()
}

fn recommended_groth16_setup_thread_cap(
    signal_count: usize,
    constraint_count: usize,
    resources: &SystemResources,
) -> Option<usize> {
    if !resources.unified_memory {
        return None;
    }

    if signal_count < LARGE_GROTH16_SETUP_SIGNAL_THRESHOLD
        && constraint_count < LARGE_GROTH16_SETUP_CONSTRAINT_THRESHOLD
    {
        return None;
    }

    Some(match resources.pressure.level {
        PressureLevel::Critical | PressureLevel::High => 1,
        PressureLevel::Elevated => 2,
        PressureLevel::Normal => {
            if resources.total_ram_bytes <= FORTY_EIGHT_GIB {
                4
            } else if resources.total_ram_bytes <= SIXTY_FOUR_GIB {
                6
            } else {
                8
            }
        }
    })
}

fn configure_large_groth16_setup_parallelism(program: &Program) {
    if std::env::var_os("RAYON_NUM_THREADS").is_some() {
        return;
    }

    let requested_threads = std::env::var("ZKF_GROTH16_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|threads| threads.max(1))
        .or_else(|| {
            let resources = SystemResources::detect();
            recommended_groth16_setup_thread_cap(
                program.signals.len(),
                program.constraints.len(),
                &resources,
            )
        });

    let Some(threads) = requested_threads else {
        return;
    };

    // Rayon reads this before the global pool is initialized. Respect an
    // explicit `RAYON_NUM_THREADS` override, but default large Groth16 setup on
    // unified-memory hosts to a smaller footprint.
    unsafe {
        std::env::set_var("RAYON_NUM_THREADS", threads.to_string());
    }
}

fn trace_arkworks_compile_enabled() -> bool {
    std::env::var_os("ZKF_TRACE_ARK_GROTH16_COMPILE").is_some()
}

fn should_use_streamed_groth16_setup(
    signal_count: usize,
    constraint_count: usize,
    resources: &SystemResources,
) -> bool {
    let large_program = resources.unified_memory
        && resources.total_ram_bytes <= SIXTY_FOUR_GIB
        && (signal_count >= LARGE_GROTH16_SETUP_SIGNAL_THRESHOLD
            || constraint_count >= LARGE_GROTH16_SETUP_CONSTRAINT_THRESHOLD);

    if let Ok(value) = std::env::var("ZKF_GROTH16_STREAMED_SETUP") {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => return large_program,
            "0" | "false" | "no" | "off" => return false,
            _ => {}
        }
    }

    large_program
}

fn streamed_groth16_cache_paths(program_digest: &str, setup_seed: &[u8; 32]) -> (PathBuf, PathBuf) {
    let root = std::env::var_os("ZKF_GROTH16_STREAMED_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("zkf-groth16-streamed"));
    let cache_dir = root.join(format!("{program_digest}-{}", hex_seed(setup_seed)));
    (cache_dir.join("outer.pk"), cache_dir.join("outer.shape"))
}

fn streamed_groth16_path_is_ready(
    path: &Path,
    readiness_check: impl Fn(&Path) -> ZkfResult<bool>,
) -> bool {
    match readiness_check(path) {
        Ok(true) => true,
        Ok(false) | Err(_) => {
            let _ = fs::remove_file(path);
            false
        }
    }
}

fn streamed_groth16_pk_header_is_ready(path: &Path) -> ZkfResult<bool> {
    Ok(ensure_streamed_groth16_pk_header_ready(path).is_ok())
}

fn streamed_groth16_shape_header_is_ready(path: &Path) -> ZkfResult<bool> {
    Ok(ensure_streamed_groth16_shape_header_ready(path).is_ok())
}

fn load_streamed_groth16_vk_bytes(pk_path: &Path) -> ZkfResult<Vec<u8>> {
    ensure_streamed_groth16_pk_header_ready(pk_path)?;
    let file = File::open(pk_path).map_err(|err| {
        ZkfError::Backend(format!(
            "failed to open streamed Groth16 proving key {}: {err}",
            pk_path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let vk =
        VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize streamed Groth16 verifying key {}: {err}",
                pk_path.display()
            ))
        })?;
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
    Ok(vk_bytes)
}

fn maybe_build_streamed_groth16_setup(
    lowered_program: &Program,
    program_digest: &str,
    setup_seed: [u8; 32],
) -> ZkfResult<Option<StreamedSetupBlob>> {
    let resources = SystemResources::detect();
    if !should_use_streamed_groth16_setup(
        lowered_program.signals.len(),
        lowered_program.constraints.len(),
        &resources,
    ) {
        return Ok(None);
    }

    let (pk_path, shape_path) = streamed_groth16_cache_paths(program_digest, &setup_seed);
    if trace_arkworks_compile_enabled() {
        eprintln!(
            "[arkworks-groth16-compile] streamed setup candidate pk={} shape={}",
            pk_path.display(),
            shape_path.display()
        );
    }
    if let Some(parent) = pk_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            ZkfError::Io(format!(
                "failed to create streamed Groth16 cache directory '{}': {err}",
                parent.display()
            ))
        })?;
    }

    let pk_ready = streamed_groth16_path_is_ready(&pk_path, streamed_groth16_pk_header_is_ready);
    let shape_ready =
        streamed_groth16_path_is_ready(&shape_path, streamed_groth16_shape_header_is_ready);
    if trace_arkworks_compile_enabled() {
        eprintln!(
            "[arkworks-groth16-compile] streamed setup cache status pk_ready={pk_ready} shape_ready={shape_ready}"
        );
    }
    if !(pk_ready && shape_ready) {
        let setup_circuit = IrCircuit::zeroed(lowered_program.clone())?;
        let mut rng = StdRng::from_seed(setup_seed);
        write_local_groth16_setup_with_shape_path(setup_circuit, &mut rng, &pk_path, &shape_path)?;
        if trace_arkworks_compile_enabled() {
            eprintln!("[arkworks-groth16-compile] streamed setup cache materialized");
        }
    }

    let vk_bytes = load_streamed_groth16_vk_bytes(&pk_path)?;
    if trace_arkworks_compile_enabled() {
        eprintln!(
            "[arkworks-groth16-compile] loaded streamed vk bytes len={}",
            vk_bytes.len()
        );
    }
    Ok(Some(StreamedSetupBlob {
        blob: pack_setup_blob(&[], &vk_bytes)?,
        pk_path,
        shape_path,
    }))
}

fn annotate_streamed_setup_metadata(
    compiled: &mut CompiledProgram,
    streamed_setup: Option<&StreamedSetupBlob>,
) {
    if let Some(streamed_setup) = streamed_setup {
        compiled.metadata.insert(
            GROTH16_STREAMED_SETUP_STORAGE_METADATA_KEY.to_string(),
            GROTH16_STREAMED_SETUP_STORAGE_VALUE.to_string(),
        );
        compiled.metadata.insert(
            GROTH16_STREAMED_PK_PATH_METADATA_KEY.to_string(),
            streamed_setup.pk_path.display().to_string(),
        );
        compiled.metadata.insert(
            GROTH16_STREAMED_SHAPE_PATH_METADATA_KEY.to_string(),
            streamed_setup.shape_path.display().to_string(),
        );
    } else {
        compiled
            .metadata
            .remove(GROTH16_STREAMED_SETUP_STORAGE_METADATA_KEY);
        compiled
            .metadata
            .remove(GROTH16_STREAMED_PK_PATH_METADATA_KEY);
        compiled
            .metadata
            .remove(GROTH16_STREAMED_SHAPE_PATH_METADATA_KEY);
    }
}

fn compiled_streamed_setup_paths(compiled: &CompiledProgram) -> Option<(PathBuf, PathBuf)> {
    let storage = compiled
        .metadata
        .get(GROTH16_STREAMED_SETUP_STORAGE_METADATA_KEY)?;
    if storage != GROTH16_STREAMED_SETUP_STORAGE_VALUE {
        return None;
    }
    let pk_path = compiled
        .metadata
        .get(GROTH16_STREAMED_PK_PATH_METADATA_KEY)
        .map(PathBuf::from)?;
    let shape_path = compiled
        .metadata
        .get(GROTH16_STREAMED_SHAPE_PATH_METADATA_KEY)
        .map(PathBuf::from)?;
    Some((pk_path, shape_path))
}

fn annotate_setup_metadata(
    compiled: &mut CompiledProgram,
    imported_path: Option<&str>,
    setup_seed: Option<[u8; 32]>,
    used_seed_override: bool,
    auto_ceremony: Option<(&AutoCeremonyContext, &str)>,
) {
    let clear_auto_ceremony_metadata = |metadata: &mut BTreeMap<String, String>| {
        metadata.remove(GROTH16_CEREMONY_SUBSYSTEM_METADATA_KEY);
        metadata.remove(GROTH16_CEREMONY_ID_METADATA_KEY);
        metadata.remove(GROTH16_CEREMONY_KIND_METADATA_KEY);
        metadata.remove(GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY);
        metadata.remove(GROTH16_CEREMONY_REPORT_SHA256_METADATA_KEY);
        metadata.remove(GROTH16_CEREMONY_SEED_COMMITMENT_METADATA_KEY);
    };

    match imported_path {
        Some(path) => {
            compiled
                .metadata
                .insert("setup_deterministic".to_string(), "false".to_string());
            compiled.metadata.insert(
                "setup_seed_source".to_string(),
                "imported-setup-blob".to_string(),
            );
            compiled.metadata.remove("setup_seed_hex");
            compiled.metadata.insert(
                GROTH16_SETUP_PROVENANCE_METADATA_KEY.to_string(),
                GROTH16_IMPORTED_SETUP_PROVENANCE.to_string(),
            );
            compiled.metadata.insert(
                GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY.to_string(),
                GROTH16_IMPORTED_SETUP_SECURITY_BOUNDARY.to_string(),
            );
            compiled.metadata.insert(
                GROTH16_SETUP_BLOB_PATH_METADATA_KEY.to_string(),
                path.to_string(),
            );
            clear_auto_ceremony_metadata(&mut compiled.metadata);
        }
        None => {
            let setup_seed = setup_seed.expect("deterministic setup seed must be present");
            compiled
                .metadata
                .insert("setup_deterministic".to_string(), "true".to_string());
            if let Some((context, report_sha256)) = auto_ceremony {
                compiled
                    .metadata
                    .insert("setup_seed_source".to_string(), "auto-ceremony".to_string());
                compiled.metadata.remove("setup_seed_hex");
                compiled.metadata.insert(
                    GROTH16_SETUP_PROVENANCE_METADATA_KEY.to_string(),
                    GROTH16_AUTO_CEREMONY_PROVENANCE.to_string(),
                );
                compiled.metadata.insert(
                    GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY.to_string(),
                    GROTH16_AUTO_CEREMONY_SECURITY_BOUNDARY.to_string(),
                );
                compiled.metadata.insert(
                    GROTH16_CEREMONY_SUBSYSTEM_METADATA_KEY.to_string(),
                    context.subsystem_id.clone(),
                );
                compiled.metadata.insert(
                    GROTH16_CEREMONY_ID_METADATA_KEY.to_string(),
                    context.ceremony_id.clone(),
                );
                compiled.metadata.insert(
                    GROTH16_CEREMONY_KIND_METADATA_KEY.to_string(),
                    "subsystem-scoped-auto-phase2".to_string(),
                );
                compiled.metadata.insert(
                    GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY.to_string(),
                    context.report_path.display().to_string(),
                );
                compiled.metadata.insert(
                    GROTH16_CEREMONY_REPORT_SHA256_METADATA_KEY.to_string(),
                    report_sha256.to_string(),
                );
                compiled.metadata.insert(
                    GROTH16_CEREMONY_SEED_COMMITMENT_METADATA_KEY.to_string(),
                    sha256_hex(&context.seed),
                );
            } else {
                compiled.metadata.insert(
                    "setup_seed_source".to_string(),
                    if used_seed_override {
                        "override".to_string()
                    } else {
                        "program-digest".to_string()
                    },
                );
                compiled
                    .metadata
                    .insert("setup_seed_hex".to_string(), hex_seed(&setup_seed));
                compiled.metadata.insert(
                    GROTH16_SETUP_PROVENANCE_METADATA_KEY.to_string(),
                    GROTH16_DETERMINISTIC_DEV_PROVENANCE.to_string(),
                );
                compiled.metadata.insert(
                    GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY.to_string(),
                    GROTH16_DETERMINISTIC_DEV_SECURITY_BOUNDARY.to_string(),
                );
                clear_auto_ceremony_metadata(&mut compiled.metadata);
            }
            compiled
                .metadata
                .remove(GROTH16_SETUP_BLOB_PATH_METADATA_KEY);
        }
    }
}

fn propagate_setup_metadata_to_proof(
    compiled: &CompiledProgram,
    metadata: &mut BTreeMap<String, String>,
) {
    for key in [
        "setup_deterministic",
        "setup_seed_source",
        GROTH16_SETUP_PROVENANCE_METADATA_KEY,
        GROTH16_SETUP_SECURITY_BOUNDARY_METADATA_KEY,
        GROTH16_CEREMONY_SUBSYSTEM_METADATA_KEY,
        GROTH16_CEREMONY_ID_METADATA_KEY,
        GROTH16_CEREMONY_KIND_METADATA_KEY,
        GROTH16_CEREMONY_REPORT_PATH_METADATA_KEY,
        GROTH16_CEREMONY_REPORT_SHA256_METADATA_KEY,
        GROTH16_CEREMONY_SEED_COMMITMENT_METADATA_KEY,
    ] {
        if let Some(value) = compiled.metadata.get(key) {
            metadata.insert(key.to_string(), value.clone());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofSeedSource {
    ExplicitSeed,
    DerivedDevSeed,
    SystemRng,
}

impl ProofSeedSource {
    fn as_metadata_str(self) -> &'static str {
        match self {
            Self::ExplicitSeed => "explicit-seed",
            Self::DerivedDevSeed => "derived-dev-seed",
            Self::SystemRng => "system-rng",
        }
    }

    fn is_deterministic(self) -> bool {
        !matches!(self, Self::SystemRng)
    }
}

fn canonical_witness_digest(witness: &Witness, field: FieldId) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-arkworks-proof-witness-v1");
    hasher.update(field.as_str().as_bytes());
    for (name, value) in &witness.values {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        let normalized = value
            .normalized_bigint(field)
            .unwrap_or_default()
            .to_signed_bytes_be();
        hasher.update((normalized.len() as u64).to_le_bytes());
        hasher.update(&normalized);
    }
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn deterministic_proof_seed(program_digest: &str, witness: &Witness, field: FieldId) -> [u8; 32] {
    let witness_digest = canonical_witness_digest(witness, field);
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-arkworks-proof-seed-v1");
    hasher.update(program_digest.as_bytes());
    hasher.update(field.as_str().as_bytes());
    hasher.update(witness_digest);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn proof_rng_for_witness(
    compiled: &CompiledProgram,
    witness: &Witness,
) -> (StdRng, ProofSeedSource, Option<[u8; 32]>) {
    if let Some(seed) = proof_seed_override() {
        return (
            StdRng::from_seed(seed),
            ProofSeedSource::ExplicitSeed,
            Some(seed),
        );
    }

    if allow_dev_deterministic_groth16() {
        let seed =
            deterministic_proof_seed(&compiled.program_digest, witness, compiled.program.field);
        return (
            StdRng::from_seed(seed),
            ProofSeedSource::DerivedDevSeed,
            Some(seed),
        );
    }

    (StdRng::from_entropy(), ProofSeedSource::SystemRng, None)
}

fn annotate_proof_metadata(
    metadata: &mut BTreeMap<String, String>,
    source: ProofSeedSource,
    seed: Option<[u8; 32]>,
) {
    metadata.insert(
        "prove_deterministic".to_string(),
        source.is_deterministic().to_string(),
    );
    metadata.insert(
        "prove_seed_source".to_string(),
        source.as_metadata_str().to_string(),
    );
    match seed {
        Some(seed) if source.is_deterministic() => {
            metadata.insert("prove_seed_hex".to_string(), hex_seed(&seed));
        }
        _ => {
            metadata.remove("prove_seed_hex");
        }
    }
}

impl BackendEngine for ArkworksGroth16Backend {
    fn kind(&self) -> BackendKind {
        BackendKind::ArkworksGroth16
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: BackendKind::ArkworksGroth16,
            mode: BackendMode::Native,
            trusted_setup: true,
            recursion_ready: false,
            transparent_setup: false,
            zkvm_mode: false,
            network_target: None,
            supported_blackbox_ops: supported_blackbox_ops(),
            supported_constraint_kinds: vec![
                "equal".to_string(),
                "boolean".to_string(),
                "range".to_string(),
                "blackbox".to_string(),
            ],
            native_profiles: vec!["groth16".to_string()],
            notes: "Groth16 on BN254 for smallest proof size and cheap on-chain verification."
                .to_string(),
        }
    }

    fn compile(&self, program: &Program) -> ZkfResult<CompiledProgram> {
        crate::with_serialized_heavy_backend_test(|| {
            if program.field != FieldId::Bn254 {
                return Err(ZkfError::UnsupportedBackend {
                    backend: self.kind().to_string(),
                    message: "arkworks-groth16 adapter currently supports BN254 field only"
                        .to_string(),
                });
            }
            configure_large_groth16_setup_parallelism(program);
            crate::harden_accelerators_for_current_pressure();
            let lowered = lower_program_for_backend(program, self.kind())?;
            let lowered_program = lowered.program.clone();

            let imported_setup = imported_setup_blob_for_program(program)?;
            let program_digest = lowered_program.digest_hex();
            let (setup_seed, used_seed_override, auto_ceremony_context) =
                if imported_setup.is_some() {
                    (None, false, None)
                } else if let Some(seed) = setup_seed_override() {
                    (Some(seed), true, None)
                } else {
                    match auto_ceremony_context(program, &program_digest) {
                        Ok(context) => (Some(context.seed), true, Some(context)),
                        Err(_) => (Some(deterministic_setup_seed(&program_digest)), false, None),
                    }
                };
            if trace_arkworks_compile_enabled() {
                eprintln!(
                    "[arkworks-groth16-compile] program={} signals={} constraints={} imported_setup={} seed_present={}",
                    lowered_program.name,
                    lowered_program.signals.len(),
                    lowered_program.constraints.len(),
                    imported_setup.is_some(),
                    setup_seed.is_some()
                );
            }
            let streamed_setup = match (imported_setup.as_ref(), setup_seed) {
                (None, Some(seed)) => {
                    maybe_build_streamed_groth16_setup(&lowered_program, &program_digest, seed)?
                }
                _ => None,
            };
            if trace_arkworks_compile_enabled() {
                eprintln!(
                    "[arkworks-groth16-compile] streamed_setup={}",
                    streamed_setup.is_some()
                );
            }

            let setup_blob = if let Some(imported_setup) = imported_setup.as_ref() {
                imported_setup.blob.clone()
            } else if let Some(streamed_setup) = streamed_setup.as_ref() {
                streamed_setup.blob.clone()
            } else {
                let mut rng = StdRng::from_seed(
                    setup_seed
                        .expect("deterministic setup seed must exist when no blob is imported"),
                );
                let setup_circuit = IrCircuit::zeroed(lowered_program.clone())?;
                let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng)
                    .map_err(|err| ZkfError::Backend(err.to_string()))?;

                let mut pk_bytes = Vec::new();
                pk.serialize_compressed(&mut pk_bytes)
                    .map_err(|err| ZkfError::Serialization(err.to_string()))?;

                let mut vk_bytes = Vec::new();
                vk.serialize_compressed(&mut vk_bytes)
                    .map_err(|err| ZkfError::Serialization(err.to_string()))?;
                pack_setup_blob(&pk_bytes, &vk_bytes)?
            };
            let auto_ceremony_report_sha256 = auto_ceremony_context
                .as_ref()
                .map(|context| {
                    write_auto_ceremony_report(
                        context,
                        program,
                        &program_digest,
                        &setup_blob,
                        streamed_setup.as_ref(),
                    )
                })
                .transpose()?;

            let mut compiled =
                build_audited_compiled_program(self.kind(), program, lowered_program)?;
            if trace_arkworks_compile_enabled() {
                eprintln!("[arkworks-groth16-compile] built audited compiled program");
            }
            compiled.compiled_data = Some(setup_blob);
            compiled
                .metadata
                .insert("curve".to_string(), "bn254".to_string());
            compiled
                .metadata
                .insert("scheme".to_string(), "groth16".to_string());
            compiled.metadata.insert(
                "setup_blob_version".to_string(),
                SETUP_BLOB_VERSION.to_string(),
            );
            annotate_setup_metadata(
                &mut compiled,
                imported_setup.as_ref().map(|setup| setup.path.as_str()),
                setup_seed,
                used_seed_override,
                auto_ceremony_context
                    .as_ref()
                    .zip(auto_ceremony_report_sha256.as_deref()),
            );
            annotate_streamed_setup_metadata(&mut compiled, streamed_setup.as_ref());
            attach_r1cs_lowering_metadata(&mut compiled, &lowered);

            crate::metal_runtime::append_trust_metadata(
                &mut compiled.metadata,
                "native",
                "cryptographic",
                1,
            );
            if trace_arkworks_compile_enabled() {
                eprintln!("[arkworks-groth16-compile] compile complete");
            }

            Ok(compiled)
        })
    }

    fn prove(&self, compiled: &CompiledProgram, witness: &Witness) -> ZkfResult<ProofArtifact> {
        crate::with_serialized_heavy_backend_test(|| {
            if compiled.backend != self.kind() {
                return Err(ZkfError::InvalidArtifact(format!(
                    "compiled backend is {}, expected {}",
                    compiled.backend,
                    self.kind()
                )));
            }

            let setup_blob = compiled
                .compiled_data
                .as_deref()
                .ok_or(ZkfError::MissingCompiledData)?;

            let enriched = audited_witness_for_proving(self.kind(), compiled, witness)?;

            let proving_circuit =
                IrCircuit::from_witness(compiled.program.clone(), &enriched.values)?;
            let (mut rng, proof_seed_source, proof_seed) =
                proof_rng_for_witness(compiled, &enriched);
            let (proof, verification_key_bytes, msm_dispatch) = if let Some((pk_path, shape_path)) =
                compiled_streamed_setup_paths(compiled)
            {
                let prove_shape = load_streamed_groth16_prove_shape(&shape_path)?;
                let (proof, vk, msm_dispatch) = create_local_groth16_proof_with_streamed_pk_path(
                    &pk_path,
                    proving_circuit,
                    &mut rng,
                    &prove_shape,
                )?;
                let mut vk_bytes = Vec::new();
                vk.serialize_compressed(&mut vk_bytes)
                    .map_err(|err| ZkfError::Serialization(err.to_string()))?;
                (proof, vk_bytes, msm_dispatch)
            } else {
                let (pk_bytes, vk_bytes) = unpack_setup_blob(setup_blob)?;
                let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes.as_slice())
                    .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
                let (proof, msm_dispatch) =
                    create_local_groth16_proof(&pk, proving_circuit, &mut rng)?;
                (proof, vk_bytes, msm_dispatch)
            };

            let public_inputs = collect_public_inputs(&compiled.program, &enriched)?;

            let mut proof_bytes = Vec::new();
            proof
                .serialize_compressed(&mut proof_bytes)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;

            let mut metadata = BTreeMap::new();
            metadata.insert("curve".to_string(), "bn254".to_string());
            metadata.insert("scheme".to_string(), "groth16".to_string());
            annotate_proof_metadata(&mut metadata, proof_seed_source, proof_seed);
            propagate_setup_metadata_to_proof(compiled, &mut metadata);
            append_groth16_metal_metadata(&mut metadata, msm_dispatch);
            append_backend_runtime_metadata(&mut metadata, self.kind());

            Ok(ProofArtifact {
                backend: self.kind(),
                program_digest: compiled.program_digest.clone(),
                proof: proof_bytes,
                verification_key: verification_key_bytes,
                public_inputs,
                metadata,
                security_profile: None,
                hybrid_bundle: None,
                credential_bundle: None,
                archive_metadata: None,
                proof_origin_signature: None,
                proof_origin_public_keys: None,
            })
        })
    }

    fn verify(&self, compiled: &CompiledProgram, artifact: &ProofArtifact) -> ZkfResult<bool> {
        if compiled.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "compiled backend is {}, expected {}",
                compiled.backend,
                self.kind()
            )));
        }

        if artifact.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "artifact backend is {}, expected {}",
                artifact.backend,
                self.kind()
            )));
        }

        if artifact.program_digest != compiled.program_digest {
            return Err(ZkfError::ProgramMismatch {
                expected: compiled.program_digest.clone(),
                found: artifact.program_digest.clone(),
            });
        }

        let setup_blob = compiled
            .compiled_data
            .as_deref()
            .ok_or(ZkfError::MissingCompiledData)?;
        let (_, expected_vk_bytes) = unpack_setup_blob(setup_blob)?;

        if artifact.verification_key != expected_vk_bytes {
            return Err(ZkfError::InvalidArtifact(
                "Groth16 verification key mismatch: artifact does not match compiled program"
                    .to_string(),
            ));
        }

        let vk = VerifyingKey::<Bn254>::deserialize_compressed(expected_vk_bytes.as_slice())
            .map_err(|err| {
                ZkfError::InvalidArtifact(format!(
                    "failed to deserialize Groth16 verification key from compiled program: {err}"
                ))
            })?;

        let proof =
            Proof::<Bn254>::deserialize_compressed(artifact.proof.as_slice()).map_err(|err| {
                ZkfError::InvalidArtifact(format!("failed to deserialize Groth16 proof: {err}"))
            })?;

        let public_inputs = artifact
            .public_inputs
            .iter()
            .map(parse_fr)
            .collect::<ZkfResult<Vec<_>>>()?;

        Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
            .map_err(|err| ZkfError::Backend(err.to_string()))
    }

    fn compile_zir(&self, program: &zkf_core::zir_v1::Program) -> ZkfResult<CompiledProgram> {
        use crate::lowering::ZirLowering;
        use crate::lowering::arkworks_lowering::ArkworksLowering;

        if program.field != FieldId::Bn254 {
            return Err(ZkfError::UnsupportedBackend {
                backend: self.kind().to_string(),
                message: "arkworks-groth16 adapter currently supports BN254 field only".to_string(),
            });
        }

        let v2_raw = zkf_core::program_zir_to_v2(program)?;
        let requires_safe_v2_path = program
            .constraints
            .iter()
            .any(zir_constraint_requires_safe_v2_path);
        if requires_safe_v2_path {
            return self.compile(&v2_raw);
        }

        let lowered = ArkworksLowering.lower(program)?;

        // Apply BlackBox lowering to the v2 program so BlackBox constraints
        // are enforced as arithmetic constraints in the circuit.
        let v2 = crate::blackbox_gadgets::lower_blackbox_program(&v2_raw)?;

        // Build Groth16 setup directly from ZIR-lowered R1CS constraints
        // instead of re-lowering from v2.
        let imported_setup = imported_setup_blob_for_program(&v2_raw)?;
        let program_digest = v2.digest_hex();
        let (setup_seed, used_seed_override, auto_ceremony_context) = if imported_setup.is_some() {
            (None, false, None)
        } else if let Some(seed) = setup_seed_override() {
            (Some(seed), true, None)
        } else {
            match auto_ceremony_context(&v2_raw, &program_digest) {
                Ok(context) => (Some(context.seed), true, Some(context)),
                Err(_) => (Some(deterministic_setup_seed(&program_digest)), false, None),
            }
        };
        let setup_blob = if let Some(imported_setup) = imported_setup.as_ref() {
            imported_setup.blob.clone()
        } else {
            let mut rng = StdRng::from_seed(
                setup_seed.expect("deterministic setup seed must exist when no blob is imported"),
            );
            let setup_circuit = ZirR1csCircuit::zeroed(&lowered)?;
            let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng)
                .map_err(|err| ZkfError::Backend(err.to_string()))?;

            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            let mut vk_bytes = Vec::new();
            vk.serialize_compressed(&mut vk_bytes)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            pack_setup_blob(&pk_bytes, &vk_bytes)?
        };
        let auto_ceremony_report_sha256 = auto_ceremony_context
            .as_ref()
            .map(|context| {
                write_auto_ceremony_report(context, &v2_raw, &program_digest, &setup_blob, None)
            })
            .transpose()?;

        let mut compiled = build_audited_compiled_program(self.kind(), &v2_raw, v2)?;
        compiled.compiled_data = Some(setup_blob);
        compiled
            .metadata
            .insert("curve".to_string(), "bn254".to_string());
        compiled
            .metadata
            .insert("scheme".to_string(), "groth16".to_string());
        compiled.metadata.insert(
            "setup_blob_version".to_string(),
            SETUP_BLOB_VERSION.to_string(),
        );
        annotate_setup_metadata(
            &mut compiled,
            imported_setup.as_ref().map(|setup| setup.path.as_str()),
            setup_seed,
            used_seed_override,
            auto_ceremony_context
                .as_ref()
                .zip(auto_ceremony_report_sha256.as_deref()),
        );
        compiled.metadata.insert(
            "zir_r1cs_constraints".to_string(),
            lowered.r1cs_constraints.len().to_string(),
        );
        compiled.metadata.insert(
            "zir_aux_variables".to_string(),
            lowered.aux_variables.len().to_string(),
        );
        compiled
            .metadata
            .insert("zir_lowered".to_string(), "true".to_string());
        compiled
            .metadata
            .insert("zir_native_compile".to_string(), "true".to_string());
        Ok(compiled)
    }

    fn prove_zir(
        &self,
        zir_program: &zkf_core::zir_v1::Program,
        compiled: &CompiledProgram,
        witness: &Witness,
    ) -> ZkfResult<ProofArtifact> {
        use crate::lowering::ZirLowering;
        use crate::lowering::arkworks_lowering::ArkworksLowering;

        // Only use ZIR-native path when compile used it
        if compiled
            .metadata
            .get("zir_native_compile")
            .map(|v| v.as_str())
            != Some("true")
        {
            return self.prove(compiled, witness);
        }

        if compiled.backend != self.kind() {
            return Err(ZkfError::InvalidArtifact(format!(
                "compiled backend is {}, expected {}",
                compiled.backend,
                self.kind()
            )));
        }

        let setup_blob = compiled
            .compiled_data
            .as_deref()
            .ok_or(ZkfError::MissingCompiledData)?;
        let (pk_bytes, _vk_bytes) = unpack_setup_blob(setup_blob)?;
        let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes.as_slice())
            .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;

        let enriched = audited_witness_for_proving(self.kind(), compiled, witness)?;

        let lowered = ArkworksLowering.lower(zir_program)?;
        let proving_circuit = ZirR1csCircuit::from_witness(&lowered, &enriched.values)?;

        let (mut rng, proof_seed_source, proof_seed) = proof_rng_for_witness(compiled, &enriched);
        let (proof, msm_dispatch) = create_local_groth16_proof(&pk, proving_circuit, &mut rng)?;

        let public_inputs = collect_public_inputs(&compiled.program, &enriched)?;

        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|err| ZkfError::Serialization(err.to_string()))?;

        let mut metadata = BTreeMap::new();
        metadata.insert("curve".to_string(), "bn254".to_string());
        metadata.insert("scheme".to_string(), "groth16".to_string());
        annotate_proof_metadata(&mut metadata, proof_seed_source, proof_seed);
        propagate_setup_metadata_to_proof(compiled, &mut metadata);
        metadata.insert("zir_native_prove".to_string(), "true".to_string());
        append_groth16_metal_metadata(&mut metadata, msm_dispatch);
        append_backend_runtime_metadata(&mut metadata, self.kind());

        // Get VK bytes from setup blob for the artifact
        let (_, vk_bytes) = unpack_setup_blob(setup_blob)?;

        Ok(ProofArtifact {
            backend: self.kind(),
            program_digest: compiled.program_digest.clone(),
            proof: proof_bytes,
            verification_key: vk_bytes,
            public_inputs,
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        })
    }
}

/// Internal-style helper for library tests that need a valid Arkworks proof artifact
/// without paying the full audited app-layer compile gate on every fixture build.
///
/// This still lowers the program, enforces witness preparation and constraint checks,
/// and produces the same compiled/program digest semantics as the production backend.
#[doc(hidden)]
pub fn compile_arkworks_unchecked(program: &Program) -> ZkfResult<CompiledProgram> {
    crate::with_serialized_heavy_backend_test(|| {
        if program.field != FieldId::Bn254 {
            return Err(ZkfError::UnsupportedBackend {
                backend: BackendKind::ArkworksGroth16.to_string(),
                message: "arkworks-groth16 adapter currently supports BN254 field only".to_string(),
            });
        }

        configure_large_groth16_setup_parallelism(program);
        crate::harden_accelerators_for_current_pressure();
        let lowered = lower_program_for_backend(program, BackendKind::ArkworksGroth16)?;
        let lowered_program = lowered.program.clone();
        let imported_setup = imported_setup_blob_for_program(program)?;
        let program_digest = lowered_program.digest_hex();
        let (setup_seed, used_seed_override, auto_ceremony_context) = if imported_setup.is_some() {
            (None, false, None)
        } else if let Some(seed) = setup_seed_override() {
            (Some(seed), true, None)
        } else {
            match auto_ceremony_context(program, &program_digest) {
                Ok(context) => (Some(context.seed), true, Some(context)),
                Err(_) => (Some(deterministic_setup_seed(&program_digest)), false, None),
            }
        };
        let streamed_setup = match (imported_setup.as_ref(), setup_seed) {
            (None, Some(seed)) => {
                maybe_build_streamed_groth16_setup(&lowered_program, &program_digest, seed)?
            }
            _ => None,
        };

        let setup_blob = if let Some(imported_setup) = imported_setup.as_ref() {
            imported_setup.blob.clone()
        } else if let Some(streamed_setup) = streamed_setup.as_ref() {
            streamed_setup.blob.clone()
        } else {
            let mut rng = StdRng::from_seed(
                setup_seed.expect("deterministic setup seed must exist when no blob is imported"),
            );
            let setup_circuit = IrCircuit::zeroed(lowered_program.clone())?;
            let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng)
                .map_err(|err| ZkfError::Backend(err.to_string()))?;

            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;

            let mut vk_bytes = Vec::new();
            vk.serialize_compressed(&mut vk_bytes)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            pack_setup_blob(&pk_bytes, &vk_bytes)?
        };
        let auto_ceremony_report_sha256 = auto_ceremony_context
            .as_ref()
            .map(|context| {
                write_auto_ceremony_report(
                    context,
                    program,
                    &program_digest,
                    &setup_blob,
                    streamed_setup.as_ref(),
                )
            })
            .transpose()?;

        let mut compiled = CompiledProgram::new(BackendKind::ArkworksGroth16, lowered_program);
        if program.digest_hex() != compiled.program_digest {
            compiled.original_program = Some(program.clone());
        }
        compiled.compiled_data = Some(setup_blob);
        compiled
            .metadata
            .insert("curve".to_string(), "bn254".to_string());
        compiled
            .metadata
            .insert("scheme".to_string(), "groth16".to_string());
        compiled.metadata.insert(
            "setup_blob_version".to_string(),
            SETUP_BLOB_VERSION.to_string(),
        );
        annotate_setup_metadata(
            &mut compiled,
            imported_setup.as_ref().map(|setup| setup.path.as_str()),
            setup_seed,
            used_seed_override,
            auto_ceremony_context
                .as_ref()
                .zip(auto_ceremony_report_sha256.as_deref()),
        );
        annotate_streamed_setup_metadata(&mut compiled, streamed_setup.as_ref());
        attach_r1cs_lowering_metadata(&mut compiled, &lowered);
        crate::metal_runtime::append_trust_metadata(
            &mut compiled.metadata,
            "native",
            "cryptographic",
            1,
        );
        remember_unchecked_compile_gate_bypass(
            BackendKind::ArkworksGroth16,
            program,
            &compiled.program,
        );

        Ok(compiled)
    })
}

#[doc(hidden)]
pub fn synthetic_groth16_compiled_for_artifact(
    artifact: &ProofArtifact,
    name: impl Into<String>,
) -> ZkfResult<CompiledProgram> {
    if artifact.backend != BackendKind::ArkworksGroth16 {
        return Err(ZkfError::InvalidArtifact(format!(
            "synthetic groth16 compiled helper requires arkworks-groth16 artifact, got {}",
            artifact.backend
        )));
    }

    let mut compiled = CompiledProgram::new(
        BackendKind::ArkworksGroth16,
        Program {
            name: name.into(),
            field: FieldId::Bn254,
            ..Program::default()
        },
    );
    compiled.program_digest = artifact.program_digest.clone();
    compiled.compiled_data = Some(pack_setup_blob(&[], &artifact.verification_key)?);
    compiled
        .metadata
        .insert("synthetic_wrapper_compiled".to_string(), "true".to_string());
    if let Some(wrapper) = artifact.metadata.get("wrapper") {
        compiled
            .metadata
            .insert("wrapper".to_string(), wrapper.clone());
    }
    Ok(compiled)
}

/// Internal-style helper for library tests that need a valid Arkworks proof artifact
/// without paying the full audited app-layer compile gate on every fixture build.
///
/// This still lowers the program, enforces witness preparation and constraint checks,
/// and produces the same compiled/program digest semantics as the production backend.
#[doc(hidden)]
pub fn compile_and_prove_arkworks_unchecked_for_test_fixture(
    program: &Program,
    inputs: &WitnessInputs,
) -> ZkfResult<(CompiledProgram, ProofArtifact)> {
    crate::with_serialized_heavy_backend_test(|| {
        let compiled = compile_arkworks_unchecked(program)?;

        let witness = generate_witness(&compiled.program, inputs).or_else(|_| {
            let base_witness = generate_witness(program, inputs)?;
            Ok::<Witness, ZkfError>(base_witness)
        })?;
        let enriched = crate::blackbox_gadgets::enrich_witness_for_proving(&compiled, &witness)?;
        if let Some(original_program) = &compiled.original_program {
            validate_blackbox_constraints(
                BackendKind::ArkworksGroth16,
                original_program,
                &enriched,
            )?;
        }
        check_constraints(&compiled.program, &enriched)?;
        validate_blackbox_constraints(BackendKind::ArkworksGroth16, &compiled.program, &enriched)?;

        let setup_blob = compiled
            .compiled_data
            .as_deref()
            .ok_or(ZkfError::MissingCompiledData)?;

        let proving_circuit = IrCircuit::from_witness(compiled.program.clone(), &enriched.values)?;
        let (mut rng, proof_seed_source, proof_seed) = proof_rng_for_witness(&compiled, &enriched);
        let (proof, verification_key_bytes, msm_dispatch) = if let Some((pk_path, shape_path)) =
            compiled_streamed_setup_paths(&compiled)
        {
            let prove_shape = load_streamed_groth16_prove_shape(&shape_path)?;
            let (proof, vk, msm_dispatch) = create_local_groth16_proof_with_streamed_pk_path(
                &pk_path,
                proving_circuit,
                &mut rng,
                &prove_shape,
            )?;
            let mut vk_bytes = Vec::new();
            vk.serialize_compressed(&mut vk_bytes)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            (proof, vk_bytes, msm_dispatch)
        } else {
            let (pk_bytes, vk_bytes) = unpack_setup_blob(setup_blob)?;
            let pk = ProvingKey::<Bn254>::deserialize_compressed(pk_bytes.as_slice())
                .map_err(|err| ZkfError::InvalidArtifact(err.to_string()))?;
            let (proof, msm_dispatch) = create_local_groth16_proof(&pk, proving_circuit, &mut rng)?;
            (proof, vk_bytes, msm_dispatch)
        };
        let public_inputs = collect_public_inputs(&compiled.program, &enriched)?;

        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|err| ZkfError::Serialization(err.to_string()))?;

        let mut metadata = BTreeMap::new();
        metadata.insert("curve".to_string(), "bn254".to_string());
        metadata.insert("scheme".to_string(), "groth16".to_string());
        annotate_proof_metadata(&mut metadata, proof_seed_source, proof_seed);
        propagate_setup_metadata_to_proof(&compiled, &mut metadata);
        append_groth16_metal_metadata(&mut metadata, msm_dispatch);
        append_backend_runtime_metadata(&mut metadata, BackendKind::ArkworksGroth16);

        Ok((
            compiled.clone(),
            ProofArtifact {
                backend: BackendKind::ArkworksGroth16,
                program_digest: compiled.program_digest.clone(),
                proof: proof_bytes,
                verification_key: verification_key_bytes,
                public_inputs,
                metadata,
                security_profile: None,
                hybrid_bundle: None,
                credential_bundle: None,
                archive_metadata: None,
                proof_origin_signature: None,
                proof_origin_public_keys: None,
            },
        ))
    })
}

type ScalarBigInt = <Fr as PrimeField>::BigInt;

#[derive(Clone, Debug, Serialize)]
struct Groth16StageTelemetry {
    accelerator: String,
    duration_ms: f64,
    inflight_jobs: usize,
    no_cpu_fallback: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fallback_reason: Option<String>,
}

impl Groth16StageTelemetry {
    fn new(
        accelerator: impl Into<String>,
        duration_ms: f64,
        inflight_jobs: usize,
        no_cpu_fallback: bool,
        fallback_reason: Option<String>,
    ) -> Self {
        Self {
            accelerator: accelerator.into(),
            duration_ms,
            inflight_jobs,
            no_cpu_fallback,
            fallback_reason,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Groth16MsmDispatch {
    used_metal: bool,
    metal_available: bool,
    saw_below_threshold: bool,
    saw_unavailable: bool,
    saw_dispatch_failed: bool,
    dispatch_failure_detail: Option<String>,
    segment_count: Option<usize>,
    points_per_segment: Option<usize>,
    segment_bucket_bytes: Option<usize>,
    total_msm_invocations: usize,
    eligible_msm_invocations: usize,
    metal_msm_invocations: usize,
    max_inflight_jobs: usize,
    counter_source: &'static str,
    witness_map_engine: &'static str,
    witness_map_reason: &'static str,
    witness_map_parallelism: usize,
    stage_breakdown: BTreeMap<String, Groth16StageTelemetry>,
}

impl Groth16MsmDispatch {
    fn merge(&mut self, other: Self) {
        self.used_metal |= other.used_metal;
        self.metal_available |= other.metal_available;
        self.saw_below_threshold |= other.saw_below_threshold;
        self.saw_unavailable |= other.saw_unavailable;
        self.saw_dispatch_failed |= other.saw_dispatch_failed;
        if self.dispatch_failure_detail.is_none() {
            self.dispatch_failure_detail = other.dispatch_failure_detail;
        }
        if self.segment_count.is_none() {
            self.segment_count = other.segment_count;
        }
        if self.points_per_segment.is_none() {
            self.points_per_segment = other.points_per_segment;
        }
        if self.segment_bucket_bytes.is_none() {
            self.segment_bucket_bytes = other.segment_bucket_bytes;
        }
        self.total_msm_invocations += other.total_msm_invocations;
        self.eligible_msm_invocations += other.eligible_msm_invocations;
        self.metal_msm_invocations += other.metal_msm_invocations;
        self.max_inflight_jobs = self.max_inflight_jobs.max(other.max_inflight_jobs);
        if self.counter_source.is_empty() {
            self.counter_source = other.counter_source;
        }
        if self.witness_map_engine.is_empty() {
            self.witness_map_engine = other.witness_map_engine;
        }
        if self.witness_map_reason.is_empty() {
            self.witness_map_reason = other.witness_map_reason;
        }
        self.witness_map_parallelism = self
            .witness_map_parallelism
            .max(other.witness_map_parallelism);
        self.stage_breakdown.extend(other.stage_breakdown);
    }

    fn no_cpu_fallback(&self) -> bool {
        self.used_metal
            && !self.saw_unavailable
            && !self.saw_dispatch_failed
            && self.eligible_msm_invocations > 0
            && self.eligible_msm_invocations == self.metal_msm_invocations
    }

    fn gpu_busy_ratio(&self) -> f64 {
        if !self.used_metal || self.eligible_msm_invocations == 0 {
            return 0.0;
        }
        let inflight = self.max_inflight_jobs.max(1) as f64;
        let total = self.eligible_msm_invocations as f64;
        ((self.metal_msm_invocations as f64 / total) * (inflight / total)).clamp(0.0, 1.0)
    }

    fn fallback_reason(&self) -> Option<&'static str> {
        if self.saw_dispatch_failed {
            Some("metal-dispatch-failed")
        } else if self.saw_unavailable || !self.metal_available {
            Some("metal-unavailable")
        } else if self.saw_below_threshold
            && self.eligible_msm_invocations == 0
            && self.total_msm_invocations > 0
        {
            Some("below-threshold")
        } else if self.eligible_msm_invocations > self.metal_msm_invocations || !self.used_metal {
            Some("cpu-selected")
        } else {
            None
        }
    }

    fn finalized_msm_fallback_state(&self) -> &'static str {
        if self.no_cpu_fallback() {
            "none"
        } else if self.used_metal {
            "partial-cpu-fallback"
        } else {
            "cpu-only"
        }
    }

    fn finalized_msm_engine(&self) -> &'static str {
        if self.no_cpu_fallback() {
            "metal-bn254-msm"
        } else {
            "cpu-bn254-msm"
        }
    }

    fn finalized_msm_reason(&self) -> &'static str {
        if self.no_cpu_fallback() {
            "bn254-groth16-metal-msm"
        } else {
            self.fallback_reason().unwrap_or("cpu-selected")
        }
    }

    fn finalized_msm_parallelism(&self) -> usize {
        if self.no_cpu_fallback() {
            self.max_inflight_jobs.max(1)
        } else {
            1
        }
    }

    fn finalized_witness_map_fallback_state(&self) -> &'static str {
        if self.witness_map_engine.starts_with("metal-") {
            "none"
        } else if self.witness_map_engine.starts_with("hybrid-") {
            "partial-cpu-fallback"
        } else {
            "cpu-only"
        }
    }
}

#[cfg_attr(not(all(target_os = "macos", feature = "metal-gpu")), allow(dead_code))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Bn254MetalMsmTelemetry {
    segment_count: usize,
    points_per_segment: usize,
    segment_bucket_bytes: usize,
}

#[cfg_attr(not(all(target_os = "macos", feature = "metal-gpu")), allow(dead_code))]
#[derive(Debug)]
enum Bn254MetalMsmDispatch {
    Metal {
        projective: G1Projective,
        telemetry: Bn254MetalMsmTelemetry,
    },
    BelowThreshold,
    Unavailable,
    DispatchFailed {
        detail: String,
        telemetry: Option<Bn254MetalMsmTelemetry>,
    },
}

#[cfg_attr(not(all(target_os = "macos", feature = "metal-gpu")), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Bn254WitnessMapNttDispatch {
    Metal,
    BelowThreshold,
    Unavailable,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct Groth16WitnessMapParityStage {
    pub stage: String,
    pub dispatch: String,
    pub exact_match: bool,
    pub mismatch_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mismatch_locations: Vec<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Groth16Bn254WitnessMapParityReport {
    pub vector_len: usize,
    pub gpu_realized: bool,
    pub stages: Vec<Groth16WitnessMapParityStage>,
}

fn bn254_witness_map_dispatch_name(dispatch: Bn254WitnessMapNttDispatch) -> &'static str {
    match dispatch {
        Bn254WitnessMapNttDispatch::Metal => "metal",
        Bn254WitnessMapNttDispatch::BelowThreshold => "below-threshold",
        Bn254WitnessMapNttDispatch::Unavailable => "unavailable",
        Bn254WitnessMapNttDispatch::Failed => "failed",
    }
}

#[derive(Default)]
struct Bn254WitnessMapTelemetry {
    total_steps: usize,
    metal_steps: usize,
    metal_available: bool,
    saw_dispatch_failed: bool,
}

impl Bn254WitnessMapTelemetry {
    fn record(&mut self, dispatch: Bn254WitnessMapNttDispatch) {
        self.total_steps += 1;
        match dispatch {
            Bn254WitnessMapNttDispatch::Metal => {
                self.metal_steps += 1;
                self.metal_available = true;
            }
            Bn254WitnessMapNttDispatch::BelowThreshold => {
                self.metal_available = true;
            }
            Bn254WitnessMapNttDispatch::Unavailable => {}
            Bn254WitnessMapNttDispatch::Failed => {
                self.metal_available = true;
                self.saw_dispatch_failed = true;
            }
        }
    }

    fn engine(&self) -> &'static str {
        if self.metal_steps == self.total_steps && self.total_steps > 0 {
            "metal-bn254-ntt+streamed-reduction"
        } else if self.metal_steps > 0 {
            "hybrid-bn254-ntt+streamed-reduction"
        } else {
            "ark-streamed-reduction"
        }
    }

    fn reason(&self) -> &'static str {
        if self.metal_steps == self.total_steps && self.total_steps > 0 {
            "bn254-witness-map-metal-ntt"
        } else if self.metal_steps > 0 {
            "bn254-witness-map-partial-metal-ntt"
        } else if self.saw_dispatch_failed {
            "bn254-witness-map-metal-dispatch-failed"
        } else if self.metal_available {
            "bn254-witness-map-below-threshold"
        } else {
            "bn254-witness-map-cpu-engine"
        }
    }

    fn parallelism(&self) -> usize {
        if self.metal_steps > 0 {
            bn254_witness_map_parallelism_hint()
        } else {
            1
        }
    }
}

const STREAMED_SHAPE_MAGIC: &[u8; 8] = b"ZKFSH03\n";
const STREAMED_SHAPE_LAGRANGE_CHUNK_LEN: usize = 1 << 20;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct StreamedGroth16ShapeHeader {
    num_instance_variables: u64,
    num_witness_variables: u64,
    num_constraints: u64,
    a_num_non_zero: u64,
    b_num_non_zero: u64,
    c_num_non_zero: u64,
}

impl StreamedGroth16ShapeHeader {
    fn from_usize(
        num_instance_variables: usize,
        num_witness_variables: usize,
        num_constraints: usize,
        a_num_non_zero: usize,
        b_num_non_zero: usize,
        c_num_non_zero: usize,
    ) -> ZkfResult<Self> {
        Ok(Self {
            num_instance_variables: u64::try_from(num_instance_variables).map_err(|_| {
                ZkfError::Backend(
                    "Groth16 streamed shape has too many instance variables".to_string(),
                )
            })?,
            num_witness_variables: u64::try_from(num_witness_variables).map_err(|_| {
                ZkfError::Backend(
                    "Groth16 streamed shape has too many witness variables".to_string(),
                )
            })?,
            num_constraints: u64::try_from(num_constraints).map_err(|_| {
                ZkfError::Backend("Groth16 streamed shape has too many constraints".to_string())
            })?,
            a_num_non_zero: u64::try_from(a_num_non_zero).map_err(|_| {
                ZkfError::Backend("Groth16 streamed shape has too many A entries".to_string())
            })?,
            b_num_non_zero: u64::try_from(b_num_non_zero).map_err(|_| {
                ZkfError::Backend("Groth16 streamed shape has too many B entries".to_string())
            })?,
            c_num_non_zero: u64::try_from(c_num_non_zero).map_err(|_| {
                ZkfError::Backend("Groth16 streamed shape has too many C entries".to_string())
            })?,
        })
    }

    fn num_instance_variables(self) -> ZkfResult<usize> {
        usize::try_from(self.num_instance_variables).map_err(|_| {
            ZkfError::Backend("Groth16 streamed shape instance count overflow".to_string())
        })
    }

    fn num_witness_variables(self) -> ZkfResult<usize> {
        usize::try_from(self.num_witness_variables).map_err(|_| {
            ZkfError::Backend("Groth16 streamed shape witness count overflow".to_string())
        })
    }

    fn num_constraints(self) -> ZkfResult<usize> {
        usize::try_from(self.num_constraints).map_err(|_| {
            ZkfError::Backend("Groth16 streamed shape constraint count overflow".to_string())
        })
    }
}

#[derive(Clone)]
#[allow(dead_code)]
enum Groth16ProveShapeStorage {
    InMemory(Arc<ConstraintMatrices<Fr>>),
    Streamed(Arc<StreamedGroth16ProveShape>),
}

#[derive(Clone)]
struct StreamedGroth16ProveShape {
    path: Arc<PathBuf>,
    header: StreamedGroth16ShapeHeader,
}

#[derive(Clone)]
pub(crate) struct Groth16ProveShape {
    storage: Groth16ProveShapeStorage,
    pub(crate) num_inputs: usize,
    pub(crate) num_constraints: usize,
}

impl Groth16ProveShape {
    #[allow(dead_code)]
    fn in_memory(
        matrices: Arc<ConstraintMatrices<Fr>>,
        num_inputs: usize,
        num_constraints: usize,
    ) -> Self {
        Self {
            storage: Groth16ProveShapeStorage::InMemory(matrices),
            num_inputs,
            num_constraints,
        }
    }

    fn streamed(path: PathBuf, header: StreamedGroth16ShapeHeader) -> ZkfResult<Self> {
        Ok(Self {
            storage: Groth16ProveShapeStorage::Streamed(Arc::new(StreamedGroth16ProveShape {
                path: Arc::new(path),
                header,
            })),
            num_inputs: header.num_instance_variables()?,
            num_constraints: header.num_constraints()?,
        })
    }
}

const FR_COMPRESSED_BYTES: usize = 32;

struct ChunkedLagrangeCoefficients {
    size: usize,
    emitted: usize,
    tau: Fr,
    group_gen: Fr,
    group_gen_inv: Fr,
    current_negative_element: Fr,
    current_l_inverse: Fr,
    chunk: Vec<Fr>,
    chunk_offset: usize,
}

impl ChunkedLagrangeCoefficients {
    fn new(domain: &GeneralEvaluationDomain<Fr>, tau: Fr) -> ZkfResult<Self> {
        let size = domain.size();
        let z_h_at_tau = domain.evaluate_vanishing_polynomial(tau);
        if z_h_at_tau.is_zero() {
            return Err(ZkfError::Backend(
                "Groth16 setup sampled a point inside the evaluation domain".to_string(),
            ));
        }

        let offset = domain.coset_offset();
        let v0_inverse = domain.size_as_field_element() * offset.pow([size as u64 - 1]);
        let z_h_inverse = z_h_at_tau.inverse().ok_or_else(|| {
            ZkfError::Backend("Groth16 setup failed to invert vanishing polynomial".to_string())
        })?;

        Ok(Self {
            size,
            emitted: 0,
            tau,
            group_gen: domain.group_gen(),
            group_gen_inv: domain.group_gen_inv(),
            current_negative_element: -offset,
            current_l_inverse: z_h_inverse * v0_inverse,
            chunk: Vec::new(),
            chunk_offset: 0,
        })
    }

    fn next_coeff(&mut self) -> ZkfResult<Option<Fr>> {
        if self.emitted >= self.size {
            return Ok(None);
        }
        if self.chunk_offset >= self.chunk.len() {
            self.refill_chunk()?;
        }
        let coeff = self.chunk[self.chunk_offset];
        self.chunk_offset += 1;
        self.emitted += 1;
        Ok(Some(coeff))
    }

    fn refill_chunk(&mut self) -> ZkfResult<()> {
        let chunk_len = STREAMED_SHAPE_LAGRANGE_CHUNK_LEN.min(self.size - self.emitted);
        self.chunk.clear();
        self.chunk.reserve(chunk_len);

        for _ in 0..chunk_len {
            self.chunk
                .push(self.current_l_inverse * (self.tau + self.current_negative_element));
            self.current_l_inverse *= self.group_gen_inv;
            self.current_negative_element *= self.group_gen;
        }

        batch_inversion(&mut self.chunk);
        self.chunk_offset = 0;
        Ok(())
    }
}

struct StreamedGroth16ShapeWriter {
    final_path: PathBuf,
    temp_path: PathBuf,
    writer: Option<BufWriter<File>>,
    num_instance_variables: usize,
    num_witness_variables: usize,
    num_constraints: usize,
    a_num_non_zero: usize,
    b_num_non_zero: usize,
    c_num_non_zero: usize,
    finished: bool,
}

impl StreamedGroth16ShapeWriter {
    fn new(
        path: &Path,
        num_instance_variables: usize,
        num_witness_variables: usize,
        num_constraints: usize,
    ) -> ZkfResult<Self> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to create Groth16 streamed shape dir {}: {err}",
                parent.display()
            ))
        })?;
        cleanup_stale_atomic_temp_siblings(path);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("shape.bin");
        let pid = std::process::id();

        for attempt in 0..16 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| {
                    ZkfError::Backend(format!(
                        "Failed to read clock for streamed shape write: {err}"
                    ))
                })?
                .as_nanos();
            let temp_path = parent.join(format!(".{file_name}.tmp-{pid}-{nanos}-{attempt}"));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => {
                    let mut writer = BufWriter::new(file);
                    writer.write_all(STREAMED_SHAPE_MAGIC).map_err(|err| {
                        ZkfError::Backend(format!(
                            "Failed to write streamed shape header {}: {err}",
                            temp_path.display()
                        ))
                    })?;
                    let placeholder = StreamedGroth16ShapeHeader::from_usize(
                        num_instance_variables,
                        num_witness_variables,
                        num_constraints,
                        0,
                        0,
                        0,
                    )?;
                    bincode::serialize_into(&mut writer, &placeholder).map_err(|err| {
                        ZkfError::Serialization(format!(
                            "Failed to write streamed shape placeholder {}: {err}",
                            temp_path.display()
                        ))
                    })?;
                    return Ok(Self {
                        final_path: path.to_path_buf(),
                        temp_path,
                        writer: Some(writer),
                        num_instance_variables,
                        num_witness_variables,
                        num_constraints,
                        a_num_non_zero: 0,
                        b_num_non_zero: 0,
                        c_num_non_zero: 0,
                        finished: false,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(ZkfError::Backend(format!(
                        "Failed to create streamed shape temp file {}: {err}",
                        temp_path.display()
                    )));
                }
            }
        }

        Err(ZkfError::Backend(format!(
            "Failed to create streamed shape temp file for {}",
            path.display()
        )))
    }

    fn write_row(
        &mut self,
        a_row: &[(Fr, usize)],
        b_row: &[(Fr, usize)],
        c_row: &[(Fr, usize)],
    ) -> ZkfResult<()> {
        self.a_num_non_zero += a_row.len();
        self.b_num_non_zero += b_row.len();
        self.c_num_non_zero += c_row.len();
        let writer = self.writer.as_mut().ok_or_else(|| {
            ZkfError::Backend("streamed Groth16 shape writer was already finalized".to_string())
        })?;
        write_streamed_shape_row(writer, a_row)?;
        write_streamed_shape_row(writer, b_row)?;
        write_streamed_shape_row(writer, c_row)?;
        Ok(())
    }

    fn finish(mut self) -> ZkfResult<Groth16ProveShape> {
        let header = StreamedGroth16ShapeHeader::from_usize(
            self.num_instance_variables,
            self.num_witness_variables,
            self.num_constraints,
            self.a_num_non_zero,
            self.b_num_non_zero,
            self.c_num_non_zero,
        )?;
        self.writer
            .as_mut()
            .ok_or_else(|| {
                ZkfError::Backend("streamed Groth16 shape writer was already finalized".to_string())
            })?
            .flush()
            .map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to flush streamed Groth16 shape {}: {err}",
                    self.temp_path.display()
                ))
            })?;
        let mut file = self
            .writer
            .take()
            .ok_or_else(|| {
                ZkfError::Backend("streamed Groth16 shape writer was already finalized".to_string())
            })?
            .into_inner()
            .map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to finalize streamed Groth16 shape {}: {err}",
                    self.temp_path.display()
                ))
            })?;
        file.seek(SeekFrom::Start(STREAMED_SHAPE_MAGIC.len() as u64))
            .map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to rewind streamed Groth16 shape {}: {err}",
                    self.temp_path.display()
                ))
            })?;
        bincode::serialize_into(&mut file, &header).map_err(|err| {
            ZkfError::Serialization(format!(
                "Failed to write streamed Groth16 shape header {}: {err}",
                self.temp_path.display()
            ))
        })?;
        file.sync_all().map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to sync streamed Groth16 shape {}: {err}",
                self.temp_path.display()
            ))
        })?;
        drop(file);
        fs::rename(&self.temp_path, &self.final_path).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to atomically install streamed Groth16 shape {}: {err}",
                self.final_path.display()
            ))
        })?;
        if let Ok(dir) = File::open(self.final_path.parent().unwrap_or_else(|| Path::new("."))) {
            let _ = dir.sync_all();
        }
        cleanup_stale_atomic_temp_siblings(&self.final_path);
        self.finished = true;
        Groth16ProveShape::streamed(self.final_path.clone(), header)
    }
}

impl Drop for StreamedGroth16ShapeWriter {
    fn drop(&mut self) {
        if !self.finished {
            let _ = fs::remove_file(&self.temp_path);
        }
    }
}

fn cleanup_stale_atomic_temp_siblings(path: &Path) {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        None => return,
    };
    let prefix = format!(".{file_name}.tmp-");
    let baseline_modified = fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .ok();
    let now = SystemTime::now();
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let entry_name = entry.file_name();
        let entry_name = entry_name.to_string_lossy();
        if !entry_name.starts_with(&prefix) {
            continue;
        }
        let entry_modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok();
        let is_stale = entry_modified
            .and_then(|modified| now.duration_since(modified).ok())
            .map(|age| age >= ATOMIC_TEMP_STALE_AGE)
            .unwrap_or(false);
        if !is_stale {
            continue;
        }
        let should_remove = if let Some(baseline) = baseline_modified {
            entry_modified
                .map(|modified| modified <= baseline)
                .unwrap_or(false)
        } else {
            true
        };
        if should_remove {
            let _ = fs::remove_file(entry.path());
        }
    }
}

fn open_atomic_temp_file(
    path: &Path,
    fallback_name: &str,
    subject: &str,
) -> ZkfResult<(PathBuf, File)> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to create Groth16 streamed {subject} dir {}: {err}",
            parent.display()
        ))
    })?;
    cleanup_stale_atomic_temp_siblings(path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(fallback_name);
    let pid = std::process::id();

    for attempt in 0..16 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to read clock for streamed Groth16 {subject} write: {err}"
                ))
            })?
            .as_nanos();
        let temp_path = parent.join(format!(".{file_name}.tmp-{pid}-{nanos}-{attempt}"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(ZkfError::Backend(format!(
                    "Failed to create streamed Groth16 {subject} temp file {}: {err}",
                    temp_path.display()
                )));
            }
        }
    }

    Err(ZkfError::Backend(format!(
        "Failed to create streamed Groth16 {subject} temp file for {}",
        path.display()
    )))
}

fn write_streamed_shape_row(writer: &mut impl Write, row: &[(Fr, usize)]) -> ZkfResult<()> {
    write_u64(writer, row.len() as u64)?;
    let mut coeff_bytes = [0u8; FR_COMPRESSED_BYTES];
    for (coeff, index) in row {
        write_u64(writer, *index as u64)?;
        coeff_bytes.fill(0);
        let mut slice = &mut coeff_bytes[..];
        coeff.serialize_compressed(&mut slice).map_err(|err| {
            ZkfError::Serialization(format!(
                "Failed to serialize streamed Groth16 coefficient: {err}"
            ))
        })?;
        writer.write_all(&coeff_bytes).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to write streamed Groth16 coefficient row: {err}"
            ))
        })?;
    }
    Ok(())
}

fn read_streamed_shape_row(reader: &mut impl Read) -> ZkfResult<Vec<(Fr, usize)>> {
    let row_len = read_u64(reader)?;
    let row_len = usize::try_from(row_len)
        .map_err(|_| ZkfError::Backend("streamed Groth16 row length overflow".to_string()))?;
    let mut row = Vec::with_capacity(row_len);
    let mut coeff_bytes = [0u8; FR_COMPRESSED_BYTES];
    for _ in 0..row_len {
        let index = usize::try_from(read_u64(reader)?)
            .map_err(|_| ZkfError::Backend("streamed Groth16 row index overflow".to_string()))?;
        reader.read_exact(&mut coeff_bytes).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to read streamed Groth16 coefficient row: {err}"
            ))
        })?;
        let coeff = Fr::deserialize_compressed(&coeff_bytes[..]).map_err(|err| {
            ZkfError::Serialization(format!(
                "Failed to deserialize streamed Groth16 coefficient: {err}"
            ))
        })?;
        row.push((coeff, index));
    }
    Ok(row)
}

fn write_u64(writer: &mut impl Write, value: u64) -> ZkfResult<()> {
    writer.write_all(&value.to_le_bytes()).map_err(|err| {
        ZkfError::Backend(format!("Failed to write Groth16 streamed integer: {err}"))
    })
}

fn read_u64(reader: &mut impl Read) -> ZkfResult<u64> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes).map_err(|err| {
        ZkfError::Backend(format!("Failed to read Groth16 streamed integer: {err}"))
    })?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_streamed_shape_header(reader: &mut impl Read) -> ZkfResult<StreamedGroth16ShapeHeader> {
    let mut magic = [0u8; STREAMED_SHAPE_MAGIC.len()];
    reader.read_exact(&mut magic).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to read streamed Groth16 shape magic: {err}"
        ))
    })?;
    if magic != *STREAMED_SHAPE_MAGIC {
        return Err(ZkfError::InvalidArtifact(
            "unexpected Groth16 streamed shape magic".to_string(),
        ));
    }
    bincode::deserialize_from(reader).map_err(|err| {
        ZkfError::Serialization(format!(
            "Failed to deserialize streamed Groth16 shape header: {err}"
        ))
    })
}

fn evaluate_constraint_row(terms: &[(Fr, usize)], assignment: &[Fr]) -> Fr {
    let mut acc = Fr::zero();
    for (coeff, index) in terms {
        acc += assignment[*index] * coeff;
    }
    acc
}

fn streamed_groth16_witness_map(
    shape: &StreamedGroth16ProveShape,
    num_inputs: usize,
    num_constraints: usize,
    full_assignment: &[Fr],
    msm_dispatch: &mut Groth16MsmDispatch,
) -> ZkfResult<Vec<Fr>> {
    let file = File::open(shape.path.as_ref()).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to open streamed Groth16 prove shape {}: {err}",
            shape.path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let header = read_streamed_shape_header(&mut reader)?;
    if header.num_instance_variables()? != shape.header.num_instance_variables()?
        || header.num_witness_variables()? != shape.header.num_witness_variables()?
        || header.num_constraints()? != shape.header.num_constraints()?
        || shape.header.num_instance_variables()? != num_inputs
        || shape.header.num_constraints()? != num_constraints
        || shape.header.num_witness_variables()? + num_inputs != full_assignment.len()
    {
        return Err(ZkfError::InvalidArtifact(
            "streamed Groth16 prove shape metadata does not match the proving assignment"
                .to_string(),
        ));
    }

    let domain =
        GeneralEvaluationDomain::<Fr>::new(num_constraints + num_inputs).ok_or_else(|| {
            ZkfError::Backend("Groth16 witness-map polynomial degree is too large".to_string())
        })?;
    let domain_size = domain.size();
    let zero = Fr::zero();

    let mut a = vec![zero; domain_size];
    let mut b = vec![zero; domain_size];
    for row_index in 0..num_constraints {
        let a_row = read_streamed_shape_row(&mut reader)?;
        let b_row = read_streamed_shape_row(&mut reader)?;
        let _ = read_streamed_shape_row(&mut reader)?;
        a[row_index] = evaluate_constraint_row(&a_row, full_assignment);
        b[row_index] = evaluate_constraint_row(&b_row, full_assignment);
    }
    let start = num_constraints;
    let end = start + num_inputs;
    a[start..end].clone_from_slice(&full_assignment[..num_inputs]);

    let coset_domain = domain
        .get_coset(Fr::GENERATOR)
        .ok_or_else(|| ZkfError::Backend("Groth16 witness-map coset is unavailable".to_string()))?;
    let mut ntt_telemetry = Bn254WitnessMapTelemetry::default();

    let a_ifft_dispatch = try_bn254_witness_map_ntt_in_place(&mut a, Fr::one(), true);
    ntt_telemetry.record(a_ifft_dispatch);
    if a_ifft_dispatch != Bn254WitnessMapNttDispatch::Metal {
        domain.ifft_in_place(&mut a);
    }

    let b_ifft_dispatch = try_bn254_witness_map_ntt_in_place(&mut b, Fr::one(), true);
    ntt_telemetry.record(b_ifft_dispatch);
    if b_ifft_dispatch != Bn254WitnessMapNttDispatch::Metal {
        domain.ifft_in_place(&mut b);
    }

    let a_fft_dispatch = try_bn254_witness_map_ntt_in_place(&mut a, Fr::GENERATOR, false);
    ntt_telemetry.record(a_fft_dispatch);
    if a_fft_dispatch != Bn254WitnessMapNttDispatch::Metal {
        coset_domain.fft_in_place(&mut a);
    }

    let b_fft_dispatch = try_bn254_witness_map_ntt_in_place(&mut b, Fr::GENERATOR, false);
    ntt_telemetry.record(b_fft_dispatch);
    if b_fft_dispatch != Bn254WitnessMapNttDispatch::Metal {
        coset_domain.fft_in_place(&mut b);
    }

    let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
    drop(a);
    drop(b);
    crate::relieve_allocator_pressure();

    let file = File::open(shape.path.as_ref()).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to reopen streamed Groth16 prove shape {}: {err}",
            shape.path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let _ = read_streamed_shape_header(&mut reader)?;
    let mut c = vec![zero; domain_size];
    for slot in c.iter_mut().take(num_constraints) {
        let _ = read_streamed_shape_row(&mut reader)?;
        let _ = read_streamed_shape_row(&mut reader)?;
        let c_row = read_streamed_shape_row(&mut reader)?;
        *slot = evaluate_constraint_row(&c_row, full_assignment);
    }

    let c_ifft_dispatch = try_bn254_witness_map_ntt_in_place(&mut c, Fr::one(), true);
    ntt_telemetry.record(c_ifft_dispatch);
    if c_ifft_dispatch != Bn254WitnessMapNttDispatch::Metal {
        domain.ifft_in_place(&mut c);
    }

    let c_fft_dispatch = try_bn254_witness_map_ntt_in_place(&mut c, Fr::GENERATOR, false);
    ntt_telemetry.record(c_fft_dispatch);
    if c_fft_dispatch != Bn254WitnessMapNttDispatch::Metal {
        coset_domain.fft_in_place(&mut c);
    }

    let vanishing_polynomial_over_coset = domain
        .evaluate_vanishing_polynomial(Fr::GENERATOR)
        .inverse()
        .ok_or_else(|| {
            ZkfError::Backend(
                "Groth16 witness-map failed to invert vanishing polynomial".to_string(),
            )
        })?;
    for (ab_i, c_i) in ab.iter_mut().zip(c.into_iter()) {
        *ab_i -= &c_i;
        *ab_i *= &vanishing_polynomial_over_coset;
    }

    let ab_ifft_dispatch = try_bn254_witness_map_ntt_in_place(&mut ab, Fr::GENERATOR, true);
    ntt_telemetry.record(ab_ifft_dispatch);
    if ab_ifft_dispatch != Bn254WitnessMapNttDispatch::Metal {
        coset_domain.ifft_in_place(&mut ab);
    }

    msm_dispatch.witness_map_engine = ntt_telemetry.engine();
    msm_dispatch.witness_map_reason = ntt_telemetry.reason();
    msm_dispatch.witness_map_parallelism = ntt_telemetry.parallelism();

    Ok(ab)
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
fn try_bn254_witness_map_ntt_in_place(
    values: &mut [Fr],
    offset: Fr,
    inverse: bool,
) -> Bn254WitnessMapNttDispatch {
    if values.len() < zkf_metal::current_thresholds().ntt.max(2) {
        return Bn254WitnessMapNttDispatch::BelowThreshold;
    }

    let Some(accelerator) = zkf_metal::MetalBn254Ntt::new() else {
        return Bn254WitnessMapNttDispatch::Unavailable;
    };

    let dispatched = if inverse {
        accelerator.ifft_in_place(values, offset)
    } else {
        accelerator.fft_in_place(values, offset)
    };

    if dispatched.is_some() {
        Bn254WitnessMapNttDispatch::Metal
    } else {
        Bn254WitnessMapNttDispatch::Failed
    }
}

#[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
fn try_bn254_witness_map_ntt_in_place(
    _values: &mut [Fr],
    _offset: Fr,
    _inverse: bool,
) -> Bn254WitnessMapNttDispatch {
    Bn254WitnessMapNttDispatch::Unavailable
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
fn bn254_witness_map_parallelism_hint() -> usize {
    zkf_metal::current_throughput_config()
        .pipeline_max_in_flight
        .max(1)
}

#[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
fn bn254_witness_map_parallelism_hint() -> usize {
    1
}

pub fn groth16_bn254_witness_map_ntt_parity(
    vector_len: usize,
) -> ZkfResult<Groth16Bn254WitnessMapParityReport> {
    if vector_len == 0 || !vector_len.is_power_of_two() {
        return Err(ZkfError::Backend(format!(
            "Groth16 witness-map parity requires a non-zero power-of-two vector length, got {vector_len}"
        )));
    }

    let domain = GeneralEvaluationDomain::<Fr>::new(vector_len).ok_or_else(|| {
        ZkfError::Backend(format!(
            "failed to create BN254 witness-map domain for vector length {vector_len}"
        ))
    })?;
    let coset_domain = domain.get_coset(Fr::GENERATOR).ok_or_else(|| {
        ZkfError::Backend("failed to create BN254 witness-map coset domain".to_string())
    })?;
    let input = (0..vector_len)
        .map(|index| Fr::from((index as u64) + 1))
        .collect::<Vec<_>>();

    let mut stages = Vec::new();
    let mut gpu_realized = false;

    let mut realized_standard_ifft = input.clone();
    let dispatch_standard_ifft =
        try_bn254_witness_map_ntt_in_place(&mut realized_standard_ifft, Fr::one(), true);
    if dispatch_standard_ifft != Bn254WitnessMapNttDispatch::Metal {
        domain.ifft_in_place(&mut realized_standard_ifft);
    } else {
        gpu_realized = true;
    }
    let mut reference_standard_ifft = input.clone();
    domain.ifft_in_place(&mut reference_standard_ifft);
    let mismatch_locations = realized_standard_ifft
        .iter()
        .zip(reference_standard_ifft.iter())
        .enumerate()
        .filter_map(|(index, (realized, reference))| {
            if realized == reference {
                None
            } else {
                Some(index)
            }
        })
        .collect::<Vec<_>>();
    stages.push(Groth16WitnessMapParityStage {
        stage: "domain_ifft".to_string(),
        dispatch: bn254_witness_map_dispatch_name(dispatch_standard_ifft).to_string(),
        exact_match: mismatch_locations.is_empty(),
        mismatch_count: mismatch_locations.len(),
        mismatch_locations,
    });

    let mut realized_coset_fft = input.clone();
    let dispatch_coset_fft =
        try_bn254_witness_map_ntt_in_place(&mut realized_coset_fft, Fr::GENERATOR, false);
    if dispatch_coset_fft != Bn254WitnessMapNttDispatch::Metal {
        coset_domain.fft_in_place(&mut realized_coset_fft);
    } else {
        gpu_realized = true;
    }
    let mut reference_coset_fft = input.clone();
    coset_domain.fft_in_place(&mut reference_coset_fft);
    let mismatch_locations = realized_coset_fft
        .iter()
        .zip(reference_coset_fft.iter())
        .enumerate()
        .filter_map(|(index, (realized, reference))| {
            if realized == reference {
                None
            } else {
                Some(index)
            }
        })
        .collect::<Vec<_>>();
    stages.push(Groth16WitnessMapParityStage {
        stage: "coset_fft".to_string(),
        dispatch: bn254_witness_map_dispatch_name(dispatch_coset_fft).to_string(),
        exact_match: mismatch_locations.is_empty(),
        mismatch_count: mismatch_locations.len(),
        mismatch_locations,
    });

    let mut realized_coset_ifft = input.clone();
    let dispatch_coset_ifft =
        try_bn254_witness_map_ntt_in_place(&mut realized_coset_ifft, Fr::GENERATOR, true);
    if dispatch_coset_ifft != Bn254WitnessMapNttDispatch::Metal {
        coset_domain.ifft_in_place(&mut realized_coset_ifft);
    } else {
        gpu_realized = true;
    }
    let mut reference_coset_ifft = input;
    coset_domain.ifft_in_place(&mut reference_coset_ifft);
    let mismatch_locations = realized_coset_ifft
        .iter()
        .zip(reference_coset_ifft.iter())
        .enumerate()
        .filter_map(|(index, (realized, reference))| {
            if realized == reference {
                None
            } else {
                Some(index)
            }
        })
        .collect::<Vec<_>>();
    stages.push(Groth16WitnessMapParityStage {
        stage: "coset_ifft".to_string(),
        dispatch: bn254_witness_map_dispatch_name(dispatch_coset_ifft).to_string(),
        exact_match: mismatch_locations.is_empty(),
        mismatch_count: mismatch_locations.len(),
        mismatch_locations,
    });

    Ok(Groth16Bn254WitnessMapParityReport {
        vector_len,
        gpu_realized,
        stages,
    })
}

fn accumulate_qap_row(target: &mut [Fr], scale: Fr, row: &[(Fr, usize)]) {
    for (coeff, index) in row {
        target[*index] += scale * coeff;
    }
}

fn constraint_matrices<F: PrimeField>(
    cs: &ConstraintSystemRef<F>,
    error_message: &str,
) -> ZkfResult<ConstraintMatrices<F>> {
    cs.to_matrices()
        .ok_or_else(|| ZkfError::Backend(error_message.to_string()))
}

fn for_each_matrix_row<F: PrimeField, G>(
    matrices: &ConstraintMatrices<F>,
    mut visitor: G,
) -> ZkfResult<()>
where
    G: FnMut(usize, &[(F, usize)], &[(F, usize)], &[(F, usize)]) -> ZkfResult<()>,
{
    for (row_index, ((a_row, b_row), c_row)) in matrices
        .a
        .iter()
        .zip(matrices.b.iter())
        .zip(matrices.c.iter())
        .enumerate()
    {
        visitor(row_index, a_row, b_row, c_row)?;
    }
    Ok(())
}

pub(crate) fn load_streamed_groth16_prove_shape(path: &Path) -> ZkfResult<Groth16ProveShape> {
    cleanup_stale_atomic_temp_siblings(path);
    let file = File::open(path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to open streamed Groth16 prove shape {}: {err}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let header = read_streamed_shape_header(&mut reader)?;
    Groth16ProveShape::streamed(path.to_path_buf(), header)
}

fn ensure_streamed_groth16_pk_header_ready(path: &Path) -> ZkfResult<()> {
    cleanup_stale_atomic_temp_siblings(path);
    let file = File::open(path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to open streamed Groth16 proving key {}: {err}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let _ =
        VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize streamed Groth16 verifying key {}: {err}",
                path.display()
            ))
        })?;
    let _ = G1Affine::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 beta_g1 {}: {err}",
            path.display()
        ))
    })?;
    let _ = G1Affine::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 delta_g1 {}: {err}",
            path.display()
        ))
    })?;
    Ok(())
}

fn ensure_streamed_groth16_shape_header_ready(path: &Path) -> ZkfResult<()> {
    cleanup_stale_atomic_temp_siblings(path);
    let file = File::open(path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to open streamed Groth16 prove shape {}: {err}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let _ = read_streamed_shape_header(&mut reader)?;
    Ok(())
}

fn drain_streamed_g1_query(reader: &mut impl Read, path: &Path, label: &str) -> ZkfResult<()> {
    let len = read_streamed_query_len(reader, label)?;
    for _ in 0..len {
        let _ = G1Affine::deserialize_uncompressed_unchecked(&mut *reader).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize streamed Groth16 {label} base while validating {}: {err}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn drain_streamed_g2_query(reader: &mut impl Read, path: &Path, label: &str) -> ZkfResult<()> {
    let len = read_streamed_query_len(reader, label)?;
    for _ in 0..len {
        let _ = G2Affine::deserialize_uncompressed_unchecked(&mut *reader).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize streamed Groth16 {label} base while validating {}: {err}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn ensure_streamed_groth16_pk_file_ready(path: &Path) -> ZkfResult<()> {
    cleanup_stale_atomic_temp_siblings(path);
    let file = File::open(path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to open streamed Groth16 proving key {}: {err}",
            path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let _ =
        VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize streamed Groth16 verifying key {}: {err}",
                path.display()
            ))
        })?;
    let _ = G1Affine::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 beta_g1 {}: {err}",
            path.display()
        ))
    })?;
    let _ = G1Affine::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 delta_g1 {}: {err}",
            path.display()
        ))
    })?;
    drain_streamed_g1_query(&mut reader, path, "a_query")?;
    drain_streamed_g1_query(&mut reader, path, "b_g1_query")?;
    drain_streamed_g2_query(&mut reader, path, "b_g2_query")?;
    drain_streamed_g1_query(&mut reader, path, "h_query")?;
    drain_streamed_g1_query(&mut reader, path, "l_query")?;

    let mut trailing = [0u8; 1];
    match reader.read_exact(&mut trailing) {
        Ok(()) => Err(ZkfError::InvalidArtifact(format!(
            "streamed Groth16 proving key {} has trailing bytes",
            path.display()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
        Err(err) => Err(ZkfError::Backend(format!(
            "Failed to finalize streamed Groth16 proving key validation {}: {err}",
            path.display()
        ))),
    }
}

fn ensure_streamed_groth16_shape_file_ready(path: &Path) -> ZkfResult<()> {
    cleanup_stale_atomic_temp_siblings(path);
    let file = File::open(path).map_err(|err| {
        ZkfError::Backend(format!(
            "Failed to open streamed Groth16 prove shape {}: {err}",
            path.display()
        ))
    })?;
    let file_len = file
        .metadata()
        .map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to stat streamed Groth16 prove shape {}: {err}",
                path.display()
            ))
        })?
        .len();
    let mut reader = BufReader::new(file);
    let header = read_streamed_shape_header(&mut reader)?;
    let num_constraints = header.num_constraints()?;
    let expected_a = usize::try_from(header.a_num_non_zero).map_err(|_| {
        ZkfError::Backend("Groth16 streamed shape A non-zero count overflow".to_string())
    })?;
    let expected_b = usize::try_from(header.b_num_non_zero).map_err(|_| {
        ZkfError::Backend("Groth16 streamed shape B non-zero count overflow".to_string())
    })?;
    let expected_c = usize::try_from(header.c_num_non_zero).map_err(|_| {
        ZkfError::Backend("Groth16 streamed shape C non-zero count overflow".to_string())
    })?;

    let mut seen_a = 0usize;
    let mut seen_b = 0usize;
    let mut seen_c = 0usize;
    let mut skip_row = |label: &str| -> ZkfResult<usize> {
        let row_len_u64 = read_u64(&mut reader)?;
        let row_len = usize::try_from(row_len_u64).map_err(|_| {
            ZkfError::InvalidArtifact(format!(
                "streamed Groth16 prove shape {} {label} row length overflow",
                path.display()
            ))
        })?;
        let payload_bytes = row_len_u64
            .checked_mul((8 + FR_COMPRESSED_BYTES) as u64)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "streamed Groth16 prove shape {} {label} row byte length overflow",
                    path.display()
                ))
            })?;
        let next = reader
            .stream_position()
            .map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to read streamed Groth16 prove shape offset {}: {err}",
                    path.display()
                ))
            })?
            .checked_add(payload_bytes)
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "streamed Groth16 prove shape {} {label} offset overflow",
                    path.display()
                ))
            })?;
        if next > file_len {
            return Err(ZkfError::InvalidArtifact(format!(
                "streamed Groth16 prove shape {} is truncated in {label}",
                path.display()
            )));
        }
        reader.seek(SeekFrom::Start(next)).map_err(|err| {
            ZkfError::Backend(format!(
                "Failed to seek streamed Groth16 prove shape {} while validating {label}: {err}",
                path.display()
            ))
        })?;
        Ok(row_len)
    };

    for _ in 0..num_constraints {
        seen_a += skip_row("A")?;
        seen_b += skip_row("B")?;
        seen_c += skip_row("C")?;
    }

    if seen_a != expected_a || seen_b != expected_b || seen_c != expected_c {
        return Err(ZkfError::InvalidArtifact(format!(
            "streamed Groth16 prove shape {} row counts do not match header",
            path.display()
        )));
    }

    let mut trailing = [0u8; 1];
    match reader.read_exact(&mut trailing) {
        Ok(()) => Err(ZkfError::InvalidArtifact(format!(
            "streamed Groth16 prove shape {} has trailing bytes",
            path.display()
        ))),
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
        Err(err) => Err(ZkfError::Backend(format!(
            "Failed to finalize streamed Groth16 prove shape validation {}: {err}",
            path.display()
        ))),
    }
}

pub(crate) fn streamed_groth16_pk_file_is_ready(path: &Path) -> ZkfResult<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    Ok(ensure_streamed_groth16_pk_file_ready(path).is_ok())
}

pub(crate) fn streamed_groth16_shape_file_is_ready(path: &Path) -> ZkfResult<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    Ok(ensure_streamed_groth16_shape_file_ready(path).is_ok())
}

pub(crate) fn build_groth16_prove_shape_to_path<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
    path: &Path,
) -> ZkfResult<Groth16ProveShape> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .map_err(|err| ZkfError::Backend(err.to_string()))?;

    let mut writer = StreamedGroth16ShapeWriter::new(
        path,
        cs.num_instance_variables(),
        cs.num_witness_variables(),
        cs.num_constraints(),
    )?;
    let matrices = constraint_matrices(
        &cs,
        "failed to stream Groth16 prove-shape rows because matrices were disabled",
    )?;
    for_each_matrix_row(&matrices, |_, a_row, b_row, c_row| {
        writer.write_row(a_row, b_row, c_row)
    })?;
    writer.finish()
}

pub(crate) fn create_local_groth16_setup_with_shape_path<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
    rng: &mut StdRng,
    shape_path: &Path,
) -> ZkfResult<(ProvingKey<Bn254>, Groth16ProveShape)> {
    crate::with_serialized_heavy_backend_test(|| {
        let alpha = Fr::rand(rng);
        let beta = Fr::rand(rng);
        let gamma = Fr::rand(rng);
        let delta = Fr::rand(rng);

        let g1_generator = G1Projective::rand(rng);
        let g2_generator = G2Projective::rand(rng);

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit
            .generate_constraints(cs.clone())
            .map_err(|err| ZkfError::Backend(err.to_string()))?;

        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();
        let num_constraints = cs.num_constraints();
        let qap_num_variables = (num_instance_variables - 1) + num_witness_variables;

        let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_instance_variables)
            .ok_or_else(|| {
            ZkfError::Backend("Groth16 setup polynomial degree is too large".to_string())
        })?;
        let t = domain.sample_element_outside_domain(rng);
        let zt = domain.evaluate_vanishing_polynomial(t);
        let domain_size = domain.size();

        let mut a = vec![Fr::zero(); qap_num_variables + 1];
        let mut b = vec![Fr::zero(); qap_num_variables + 1];
        let mut c = vec![Fr::zero(); qap_num_variables + 1];
        let mut lagrange = ChunkedLagrangeCoefficients::new(&domain, t)?;
        let mut writer = StreamedGroth16ShapeWriter::new(
            shape_path,
            num_instance_variables,
            num_witness_variables,
            num_constraints,
        )?;
        let matrices = constraint_matrices(
            &cs,
            "failed to stream Groth16 setup rows because matrices were disabled",
        )?;
        for_each_matrix_row(&matrices, |_, a_row, b_row, c_row| {
            let u_i = lagrange.next_coeff()?.ok_or_else(|| {
                ZkfError::Backend(
                    "Groth16 lagrange stream ended before constraint rows were consumed"
                        .to_string(),
                )
            })?;
            writer.write_row(a_row, b_row, c_row)?;
            accumulate_qap_row(&mut a, u_i, a_row);
            accumulate_qap_row(&mut b, u_i, b_row);
            accumulate_qap_row(&mut c, u_i, c_row);
            Ok(())
        })?;

        for a_value in a.iter_mut().take(num_instance_variables) {
            *a_value += lagrange.next_coeff()?.ok_or_else(|| {
                ZkfError::Backend(
                    "Groth16 lagrange stream ended before instance rows were consumed".to_string(),
                )
            })?;
        }

        let gamma_inverse = gamma
            .inverse()
            .ok_or_else(|| ZkfError::Backend("Groth16 setup hit gamma=0".to_string()))?;
        let delta_inverse = delta
            .inverse()
            .ok_or_else(|| ZkfError::Backend("Groth16 setup hit delta=0".to_string()))?;

        let non_zero_a = a.iter().filter(|coeff| !coeff.is_zero()).count();
        let non_zero_b = b.iter().filter(|coeff| !coeff.is_zero()).count();

        let gamma_abc = a[..num_instance_variables]
            .iter()
            .zip(&b[..num_instance_variables])
            .zip(&c[..num_instance_variables])
            .map(|((a_i, b_i), c_i)| (beta * a_i + alpha * b_i + c_i) * gamma_inverse)
            .collect::<Vec<_>>();
        let l_query_scalars = a[num_instance_variables..]
            .iter()
            .zip(&b[num_instance_variables..])
            .zip(&c[num_instance_variables..])
            .map(|((a_i, b_i), c_i)| (beta * a_i + alpha * b_i + c_i) * delta_inverse)
            .collect::<Vec<_>>();
        drop(c);
        crate::relieve_allocator_pressure();

        let beta_g1 = (g1_generator * beta).into_affine();
        let delta_g1 = (g1_generator * delta).into_affine();
        let alpha_g1 = (g1_generator * alpha).into_affine();
        let beta_g2 = (g2_generator * beta).into_affine();
        let gamma_g2 = (g2_generator * gamma).into_affine();
        let delta_g2 = (g2_generator * delta).into_affine();

        let g2_table = BatchMulPreprocessing::new(g2_generator, non_zero_b);
        let b_g2_query = g2_table.batch_mul(&b);
        drop(g2_table);

        let num_scalars = non_zero_a + non_zero_b + qap_num_variables + domain_size + 1;
        let g1_table = BatchMulPreprocessing::new(g1_generator, num_scalars);
        let a_query = g1_table.batch_mul(&a);
        let b_g1_query = g1_table.batch_mul(&b);
        let h_scalars = LibsnarkReduction::h_query_scalars::<Fr, GeneralEvaluationDomain<Fr>>(
            domain_size - 1,
            t,
            zt,
            delta_inverse,
        )
        .map_err(|err| ZkfError::Backend(err.to_string()))?;
        let h_query = g1_table.batch_mul(&h_scalars);
        let l_query = g1_table.batch_mul(&l_query_scalars);
        let gamma_abc_g1 = g1_table.batch_mul(&gamma_abc);

        let vk = VerifyingKey::<Bn254> {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        };
        let pk = ProvingKey::<Bn254> {
            vk,
            beta_g1,
            delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };
        let prove_shape = writer.finish()?;

        Ok((pk, prove_shape))
    })
}

pub(crate) fn write_local_groth16_setup_with_shape_path<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
    rng: &mut StdRng,
    pk_path: &Path,
    shape_path: &Path,
) -> ZkfResult<Groth16ProveShape> {
    crate::with_serialized_heavy_backend_test(|| {
        let alpha = Fr::rand(rng);
        let beta = Fr::rand(rng);
        let gamma = Fr::rand(rng);
        let delta = Fr::rand(rng);

        let g1_generator = G1Projective::rand(rng);
        let g2_generator = G2Projective::rand(rng);

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit
            .generate_constraints(cs.clone())
            .map_err(|err| ZkfError::Backend(err.to_string()))?;

        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();
        let num_constraints = cs.num_constraints();
        let qap_num_variables = (num_instance_variables - 1) + num_witness_variables;

        let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_instance_variables)
            .ok_or_else(|| {
            ZkfError::Backend("Groth16 setup polynomial degree is too large".to_string())
        })?;
        let t = domain.sample_element_outside_domain(rng);
        let zt = domain.evaluate_vanishing_polynomial(t);
        let domain_size = domain.size();

        let mut a = vec![Fr::zero(); qap_num_variables + 1];
        let mut b = vec![Fr::zero(); qap_num_variables + 1];
        let mut c = vec![Fr::zero(); qap_num_variables + 1];
        let mut lagrange = ChunkedLagrangeCoefficients::new(&domain, t)?;
        let mut shape_writer = StreamedGroth16ShapeWriter::new(
            shape_path,
            num_instance_variables,
            num_witness_variables,
            num_constraints,
        )?;
        let matrices = constraint_matrices(
            &cs,
            "failed to stream Groth16 setup rows because matrices were disabled",
        )?;
        for_each_matrix_row(&matrices, |_, a_row, b_row, c_row| {
            let u_i = lagrange.next_coeff()?.ok_or_else(|| {
                ZkfError::Backend(
                    "Groth16 lagrange stream ended before constraint rows were consumed"
                        .to_string(),
                )
            })?;
            shape_writer.write_row(a_row, b_row, c_row)?;
            accumulate_qap_row(&mut a, u_i, a_row);
            accumulate_qap_row(&mut b, u_i, b_row);
            accumulate_qap_row(&mut c, u_i, c_row);
            Ok(())
        })?;

        for a_value in a.iter_mut().take(num_instance_variables) {
            *a_value += lagrange.next_coeff()?.ok_or_else(|| {
                ZkfError::Backend(
                    "Groth16 lagrange stream ended before instance rows were consumed".to_string(),
                )
            })?;
        }

        let gamma_inverse = gamma
            .inverse()
            .ok_or_else(|| ZkfError::Backend("Groth16 setup hit gamma=0".to_string()))?;
        let delta_inverse = delta
            .inverse()
            .ok_or_else(|| ZkfError::Backend("Groth16 setup hit delta=0".to_string()))?;

        let non_zero_a = a.iter().filter(|coeff| !coeff.is_zero()).count();
        let non_zero_b = b.iter().filter(|coeff| !coeff.is_zero()).count();

        let gamma_abc = a[..num_instance_variables]
            .iter()
            .zip(&b[..num_instance_variables])
            .zip(&c[..num_instance_variables])
            .map(|((a_i, b_i), c_i)| (beta * a_i + alpha * b_i + c_i) * gamma_inverse)
            .collect::<Vec<_>>();
        let l_query_scalars = a[num_instance_variables..]
            .iter()
            .zip(&b[num_instance_variables..])
            .zip(&c[num_instance_variables..])
            .map(|((a_i, b_i), c_i)| (beta * a_i + alpha * b_i + c_i) * delta_inverse)
            .collect::<Vec<_>>();

        let beta_g1 = (g1_generator * beta).into_affine();
        let delta_g1 = (g1_generator * delta).into_affine();
        let alpha_g1 = (g1_generator * alpha).into_affine();
        let beta_g2 = (g2_generator * beta).into_affine();
        let gamma_g2 = (g2_generator * gamma).into_affine();
        let delta_g2 = (g2_generator * delta).into_affine();

        let num_scalars = non_zero_a + non_zero_b + qap_num_variables + domain_size + 1;
        let g1_table = BatchMulPreprocessing::new(g1_generator, num_scalars);
        let gamma_abc_g1 = g1_table.batch_mul(&gamma_abc);
        drop(gamma_abc);
        crate::relieve_allocator_pressure();

        let prove_shape = shape_writer.finish()?;
        crate::relieve_allocator_pressure();
        let (pk_temp_path, pk_file) = open_atomic_temp_file(pk_path, "pk.bin", "proving key")?;
        let pk_parent = pk_path.parent().unwrap_or_else(|| Path::new("."));
        let pk_write_result = (|| -> ZkfResult<()> {
            let mut pk_writer = BufWriter::new(pk_file);
            let g1_chunk_size = streamed_groth16_query_chunk_size();
            let g2_chunk_size = streamed_groth16_query_chunk_size();

            let vk = VerifyingKey::<Bn254> {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            };
            vk.serialize_uncompressed(&mut pk_writer)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            beta_g1
                .serialize_uncompressed(&mut pk_writer)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            delta_g1
                .serialize_uncompressed(&mut pk_writer)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;

            let len = u64::try_from(a.len()).map_err(|_| {
                ZkfError::Backend(
                    "streamed Groth16 a_query length overflow during setup".to_string(),
                )
            })?;
            len.serialize_uncompressed(&mut pk_writer)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            for chunk in a.chunks(g1_chunk_size) {
                let chunk_query = g1_table.batch_mul(chunk);
                for point in chunk_query {
                    point
                        .serialize_uncompressed(&mut pk_writer)
                        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
                }
                crate::relieve_allocator_pressure();
            }
            drop(a);
            crate::relieve_allocator_pressure();

            let len = u64::try_from(b.len()).map_err(|_| {
                ZkfError::Backend(
                    "streamed Groth16 b_g1_query length overflow during setup".to_string(),
                )
            })?;
            len.serialize_uncompressed(&mut pk_writer)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            for chunk in b.chunks(g1_chunk_size) {
                let chunk_query = g1_table.batch_mul(chunk);
                for point in chunk_query {
                    point
                        .serialize_uncompressed(&mut pk_writer)
                        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
                }
                crate::relieve_allocator_pressure();
            }
            crate::relieve_allocator_pressure();

            let g2_table = BatchMulPreprocessing::new(g2_generator, non_zero_b);
            let len = u64::try_from(b.len()).map_err(|_| {
                ZkfError::Backend(
                    "streamed Groth16 b_g2_query length overflow during setup".to_string(),
                )
            })?;
            len.serialize_uncompressed(&mut pk_writer)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            for chunk in b.chunks(g2_chunk_size) {
                let chunk_query = g2_table.batch_mul(chunk);
                for point in chunk_query {
                    point
                        .serialize_uncompressed(&mut pk_writer)
                        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
                }
                crate::relieve_allocator_pressure();
            }
            drop(g2_table);
            drop(b);
            crate::relieve_allocator_pressure();

            let h_scalars = LibsnarkReduction::h_query_scalars::<Fr, GeneralEvaluationDomain<Fr>>(
                domain_size - 1,
                t,
                zt,
                delta_inverse,
            )
            .map_err(|err| ZkfError::Backend(err.to_string()))?;
            let len = u64::try_from(h_scalars.len()).map_err(|_| {
                ZkfError::Backend(
                    "streamed Groth16 h_query length overflow during setup".to_string(),
                )
            })?;
            len.serialize_uncompressed(&mut pk_writer)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            for chunk in h_scalars.chunks(g1_chunk_size) {
                let chunk_query = g1_table.batch_mul(chunk);
                for point in chunk_query {
                    point
                        .serialize_uncompressed(&mut pk_writer)
                        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
                }
                crate::relieve_allocator_pressure();
            }
            drop(h_scalars);
            crate::relieve_allocator_pressure();

            let len = u64::try_from(l_query_scalars.len()).map_err(|_| {
                ZkfError::Backend(
                    "streamed Groth16 l_query length overflow during setup".to_string(),
                )
            })?;
            len.serialize_uncompressed(&mut pk_writer)
                .map_err(|err| ZkfError::Serialization(err.to_string()))?;
            for chunk in l_query_scalars.chunks(g1_chunk_size) {
                let chunk_query = g1_table.batch_mul(chunk);
                for point in chunk_query {
                    point
                        .serialize_uncompressed(&mut pk_writer)
                        .map_err(|err| ZkfError::Serialization(err.to_string()))?;
                }
                crate::relieve_allocator_pressure();
            }
            drop(l_query_scalars);
            drop(g1_table);
            crate::relieve_allocator_pressure();

            pk_writer.flush().map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to flush streamed Groth16 proving key {}: {err}",
                    pk_temp_path.display()
                ))
            })?;
            let pk_file = pk_writer.into_inner().map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to finalize streamed Groth16 proving key {}: {err}",
                    pk_temp_path.display()
                ))
            })?;
            pk_file.sync_all().map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to sync streamed Groth16 proving key {}: {err}",
                    pk_temp_path.display()
                ))
            })?;
            drop(pk_file);
            fs::rename(&pk_temp_path, pk_path).map_err(|err| {
                ZkfError::Backend(format!(
                    "Failed to atomically install streamed Groth16 proving key {}: {err}",
                    pk_path.display()
                ))
            })?;
            if let Ok(dir) = File::open(pk_parent) {
                let _ = dir.sync_all();
            }
            cleanup_stale_atomic_temp_siblings(pk_path);
            Ok(())
        })();
        if let Err(err) = pk_write_result {
            let _ = fs::remove_file(&pk_temp_path);
            return Err(err);
        }

        Ok(prove_shape)
    })
}

pub(crate) fn create_local_groth16_proof<C: ConstraintSynthesizer<Fr>>(
    pk: &ProvingKey<Bn254>,
    circuit: C,
    rng: &mut StdRng,
) -> ZkfResult<(Proof<Bn254>, Groth16MsmDispatch)> {
    create_local_groth16_proof_with_shape(pk, circuit, rng, None)
}

pub(crate) fn create_local_groth16_proof_with_cached_shape<C: ConstraintSynthesizer<Fr>>(
    pk: &ProvingKey<Bn254>,
    circuit: C,
    rng: &mut StdRng,
    prove_shape: &Groth16ProveShape,
) -> ZkfResult<(Proof<Bn254>, Groth16MsmDispatch)> {
    create_local_groth16_proof_with_shape(pk, circuit, rng, Some(prove_shape))
}

pub(crate) fn create_local_groth16_proof_with_streamed_pk_path<C: ConstraintSynthesizer<Fr>>(
    pk_path: &Path,
    circuit: C,
    rng: &mut StdRng,
    prove_shape: &Groth16ProveShape,
) -> ZkfResult<(Proof<Bn254>, VerifyingKey<Bn254>, Groth16MsmDispatch)> {
    crate::with_serialized_heavy_backend_test(|| {
        crate::init_accelerators();
        crate::harden_accelerators_for_current_pressure();
        ensure_streamed_groth16_pk_header_ready(pk_path)?;

        let synthesis_start = Instant::now();
        let r = Fr::rand(rng);
        let s = Fr::rand(rng);

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Prove {
            construct_matrices: false,
        });
        circuit
            .generate_constraints(cs.clone())
            .map_err(|err| ZkfError::Backend(err.to_string()))?;
        if should_debug_check_constraint_system(&cs) {
            debug_assert!(cs.is_satisfied().unwrap_or(false));
        }
        let synthesis_ms = synthesis_start.elapsed().as_secs_f64() * 1_000.0;

        let witness_map_start = Instant::now();
        let prover = cs.borrow().ok_or_else(|| {
            ZkfError::Backend("failed to borrow Groth16 constraint system".to_string())
        })?;
        if prover.num_instance_variables != prove_shape.num_inputs
            || prover.num_constraints != prove_shape.num_constraints
        {
            return Err(ZkfError::Backend(format!(
                "cached Groth16 shape mismatch: expected {} inputs / {} constraints, got {} inputs / {} constraints",
                prove_shape.num_inputs,
                prove_shape.num_constraints,
                prover.num_instance_variables,
                prover.num_constraints
            )));
        }
        let full_assignment = [
            prover.instance_assignment.as_slice(),
            prover.witness_assignment.as_slice(),
        ]
        .concat();
        let input_assignment = prover.instance_assignment[1..].to_vec();
        let aux_assignment = prover.witness_assignment.clone();
        drop(prover);

        let mut msm_dispatch = Groth16MsmDispatch {
            counter_source: "streamed-pk-sequential-msm",
            ..Default::default()
        };
        let h = match &prove_shape.storage {
            Groth16ProveShapeStorage::InMemory(matrices) => {
                msm_dispatch.witness_map_engine = "ark-libsnark-reduction";
                msm_dispatch.witness_map_reason = "bn254-witness-map-cpu-engine";
                msm_dispatch.witness_map_parallelism = 1;
                LibsnarkReduction::witness_map_from_matrices::<Fr, GeneralEvaluationDomain<Fr>>(
                    matrices.as_ref(),
                    prove_shape.num_inputs,
                    prove_shape.num_constraints,
                    &full_assignment,
                )
                .map_err(|err| ZkfError::Backend(err.to_string()))?
            }
            Groth16ProveShapeStorage::Streamed(shape) => streamed_groth16_witness_map(
                shape.as_ref(),
                prove_shape.num_inputs,
                prove_shape.num_constraints,
                &full_assignment,
                &mut msm_dispatch,
            )?,
        };
        let witness_map_ms = witness_map_start.elapsed().as_secs_f64() * 1_000.0;
        crate::relieve_allocator_pressure();

        let prove_core_start = Instant::now();
        let (proof, vk) = create_local_groth16_proof_with_assignment_from_streamed_pk(
            pk_path,
            r,
            s,
            &h,
            &input_assignment,
            &aux_assignment,
            &mut msm_dispatch,
        )?;
        let prove_core_ms = prove_core_start.elapsed().as_secs_f64() * 1_000.0;
        crate::relieve_allocator_pressure();

        msm_dispatch.stage_breakdown.insert(
            "constraint_synthesis".to_string(),
            Groth16StageTelemetry::new(
                "cpu",
                synthesis_ms,
                1,
                false,
                Some("bn254-circuit-synthesis-not-metal".to_string()),
            ),
        );
        msm_dispatch.stage_breakdown.insert(
            "witness_map".to_string(),
            Groth16StageTelemetry::new(
                msm_dispatch.witness_map_engine,
                witness_map_ms,
                msm_dispatch.witness_map_parallelism.max(1),
                msm_dispatch
                    .witness_map_engine
                    .starts_with("metal-bn254-ntt"),
                if msm_dispatch.witness_map_reason.is_empty() {
                    None
                } else {
                    Some(msm_dispatch.witness_map_reason.to_string())
                },
            ),
        );
        msm_dispatch.stage_breakdown.insert(
            "groth16_prove_core".to_string(),
            Groth16StageTelemetry::new(
                if msm_dispatch.used_metal {
                    "metal"
                } else {
                    "cpu"
                },
                prove_core_ms,
                if msm_dispatch.used_metal {
                    msm_dispatch.max_inflight_jobs.max(1)
                } else {
                    0
                },
                msm_dispatch.no_cpu_fallback(),
                msm_dispatch.fallback_reason().map(str::to_string),
            ),
        );
        let no_cpu_fallback = msm_dispatch.no_cpu_fallback();
        let fallback_reason = msm_dispatch.fallback_reason().map(str::to_string);
        if let Some(msm_window) = msm_dispatch.stage_breakdown.get_mut("msm_window") {
            msm_window.duration_ms = prove_core_ms;
            msm_window.inflight_jobs = if msm_dispatch.used_metal {
                msm_dispatch.max_inflight_jobs.max(1)
            } else {
                0
            };
            msm_window.no_cpu_fallback = no_cpu_fallback;
            msm_window.fallback_reason = fallback_reason;
        }

        Ok((proof, vk, msm_dispatch))
    })
}

#[allow(dead_code)]
pub(crate) fn build_groth16_prove_shape<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
) -> ZkfResult<Groth16ProveShape> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    circuit
        .generate_constraints(cs.clone())
        .map_err(|err| ZkfError::Backend(err.to_string()))?;

    let matrices = Arc::new(constraint_matrices(
        &cs,
        "failed to materialize cached Groth16 constraint matrices",
    )?);
    let prover = cs.borrow().ok_or_else(|| {
        ZkfError::Backend("failed to borrow Groth16 setup constraint system".to_string())
    })?;

    Ok(Groth16ProveShape::in_memory(
        matrices,
        prover.num_instance_variables,
        prover.num_constraints,
    ))
}

#[allow(dead_code)]
pub(crate) fn create_local_groth16_setup_with_shape<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
    rng: &mut StdRng,
) -> ZkfResult<(ProvingKey<Bn254>, Groth16ProveShape)> {
    crate::with_serialized_heavy_backend_test(|| {
        let alpha = Fr::rand(rng);
        let beta = Fr::rand(rng);
        let gamma = Fr::rand(rng);
        let delta = Fr::rand(rng);

        let g1_generator = G1Projective::rand(rng);
        let g2_generator = G2Projective::rand(rng);

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        cs.set_mode(SynthesisMode::Setup);
        circuit
            .generate_constraints(cs.clone())
            .map_err(|err| ZkfError::Backend(err.to_string()))?;

        let num_instance_variables = cs.num_instance_variables();
        let num_witness_variables = cs.num_witness_variables();
        let num_constraints = cs.num_constraints();
        let matrices = Arc::new(constraint_matrices(
            &cs,
            "failed to materialize Groth16 constraint matrices during setup",
        )?);

        let domain = GeneralEvaluationDomain::<Fr>::new(num_constraints + num_instance_variables)
            .ok_or_else(|| {
            ZkfError::Backend("Groth16 setup polynomial degree is too large".to_string())
        })?;
        let t = domain.sample_element_outside_domain(rng);
        let zt = domain.evaluate_vanishing_polynomial(t);
        let lagrange = domain.evaluate_all_lagrange_coefficients(t);
        let qap_num_variables = (num_instance_variables - 1) + num_witness_variables;
        let domain_size = domain.size();

        let mut a = vec![Fr::zero(); qap_num_variables + 1];
        let mut b = vec![Fr::zero(); qap_num_variables + 1];
        let mut c = vec![Fr::zero(); qap_num_variables + 1];

        a[..num_instance_variables].copy_from_slice(
            &lagrange[num_constraints..(num_constraints + num_instance_variables)],
        );
        for (i, u_i) in lagrange.iter().enumerate().take(num_constraints) {
            for (coeff, index) in &matrices.a[i] {
                a[*index] += *u_i * coeff;
            }
            for (coeff, index) in &matrices.b[i] {
                b[*index] += *u_i * coeff;
            }
            for (coeff, index) in &matrices.c[i] {
                c[*index] += *u_i * coeff;
            }
        }

        let gamma_inverse = gamma
            .inverse()
            .ok_or_else(|| ZkfError::Backend("Groth16 setup hit gamma=0".to_string()))?;
        let delta_inverse = delta
            .inverse()
            .ok_or_else(|| ZkfError::Backend("Groth16 setup hit delta=0".to_string()))?;

        let non_zero_a = a.iter().filter(|coeff| !coeff.is_zero()).count();
        let non_zero_b = b.iter().filter(|coeff| !coeff.is_zero()).count();

        let gamma_abc = a[..num_instance_variables]
            .iter()
            .zip(&b[..num_instance_variables])
            .zip(&c[..num_instance_variables])
            .map(|((a_i, b_i), c_i)| (beta * a_i + alpha * b_i + c_i) * gamma_inverse)
            .collect::<Vec<_>>();
        let l_query_scalars = a[num_instance_variables..]
            .iter()
            .zip(&b[num_instance_variables..])
            .zip(&c[num_instance_variables..])
            .map(|((a_i, b_i), c_i)| (beta * a_i + alpha * b_i + c_i) * delta_inverse)
            .collect::<Vec<_>>();

        let beta_g1 = (g1_generator * beta).into_affine();
        let delta_g1 = (g1_generator * delta).into_affine();
        let alpha_g1 = (g1_generator * alpha).into_affine();
        let beta_g2 = (g2_generator * beta).into_affine();
        let gamma_g2 = (g2_generator * gamma).into_affine();
        let delta_g2 = (g2_generator * delta).into_affine();

        let g2_table = BatchMulPreprocessing::new(g2_generator, non_zero_b);
        let b_g2_query = g2_table.batch_mul(&b);
        drop(g2_table);

        let num_scalars = non_zero_a + non_zero_b + qap_num_variables + domain_size + 1;
        let g1_table = BatchMulPreprocessing::new(g1_generator, num_scalars);
        let a_query = g1_table.batch_mul(&a);
        let b_g1_query = g1_table.batch_mul(&b);
        let h_scalars = LibsnarkReduction::h_query_scalars::<Fr, GeneralEvaluationDomain<Fr>>(
            domain_size - 1,
            t,
            zt,
            delta_inverse,
        )
        .map_err(|err| ZkfError::Backend(err.to_string()))?;
        let h_query = g1_table.batch_mul(&h_scalars);
        let l_query = g1_table.batch_mul(&l_query_scalars);
        let gamma_abc_g1 = g1_table.batch_mul(&gamma_abc);

        let vk = VerifyingKey::<Bn254> {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        };
        let pk = ProvingKey::<Bn254> {
            vk,
            beta_g1,
            delta_g1,
            a_query,
            b_g1_query,
            b_g2_query,
            h_query,
            l_query,
        };
        let prove_shape =
            Groth16ProveShape::in_memory(matrices, num_instance_variables, num_constraints);

        Ok((pk, prove_shape))
    })
}

fn create_local_groth16_proof_with_shape<C: ConstraintSynthesizer<Fr>>(
    pk: &ProvingKey<Bn254>,
    circuit: C,
    rng: &mut StdRng,
    prove_shape: Option<&Groth16ProveShape>,
) -> ZkfResult<(Proof<Bn254>, Groth16MsmDispatch)> {
    crate::with_serialized_heavy_backend_test(|| {
        // Wrapper/runtime callers can invoke the low-level Groth16 prove helpers
        // directly without going through backend_for(), so make accelerator
        // registration explicit here before consulting the MSM registry.
        crate::init_accelerators();
        crate::harden_accelerators_for_current_pressure();

        let synthesis_start = Instant::now();
        let r = Fr::rand(rng);
        let s = Fr::rand(rng);

        let cs = ConstraintSystem::new_ref();
        cs.set_optimization_goal(OptimizationGoal::Constraints);
        if prove_shape.is_some() {
            cs.set_mode(SynthesisMode::Prove {
                construct_matrices: false,
            });
        }
        circuit
            .generate_constraints(cs.clone())
            .map_err(|err| ZkfError::Backend(err.to_string()))?;
        if should_debug_check_constraint_system(&cs) {
            debug_assert!(cs.is_satisfied().unwrap_or(false));
        }
        let synthesis_ms = synthesis_start.elapsed().as_secs_f64() * 1_000.0;

        let witness_map_start = Instant::now();
        let prover = cs.borrow().ok_or_else(|| {
            ZkfError::Backend("failed to borrow Groth16 constraint system".to_string())
        })?;
        let (num_inputs, num_constraints) = if let Some(shape) = prove_shape {
            if prover.num_instance_variables != shape.num_inputs
                || prover.num_constraints != shape.num_constraints
            {
                return Err(ZkfError::Backend(format!(
                    "cached Groth16 shape mismatch: expected {} inputs / {} constraints, got {} inputs / {} constraints",
                    shape.num_inputs,
                    shape.num_constraints,
                    prover.num_instance_variables,
                    prover.num_constraints
                )));
            }
            (shape.num_inputs, shape.num_constraints)
        } else {
            (prover.num_instance_variables, prover.num_constraints)
        };
        let full_assignment = [
            prover.instance_assignment.as_slice(),
            prover.witness_assignment.as_slice(),
        ]
        .concat();
        let input_assignment = prover.instance_assignment[1..].to_vec();
        let aux_assignment = prover.witness_assignment.clone();
        drop(prover);

        let mut msm_dispatch = Groth16MsmDispatch::default();
        let h = match prove_shape {
            Some(shape) => match &shape.storage {
                Groth16ProveShapeStorage::InMemory(matrices) => {
                    msm_dispatch.witness_map_engine = "ark-libsnark-reduction";
                    msm_dispatch.witness_map_reason = "bn254-witness-map-cpu-engine";
                    msm_dispatch.witness_map_parallelism = 1;
                    LibsnarkReduction::witness_map_from_matrices::<
                        Fr,
                        ark_poly::GeneralEvaluationDomain<Fr>,
                    >(
                        matrices.as_ref(),
                        num_inputs,
                        num_constraints,
                        &full_assignment,
                    )
                    .map_err(|err| ZkfError::Backend(err.to_string()))?
                }
                Groth16ProveShapeStorage::Streamed(shape) => streamed_groth16_witness_map(
                    shape.as_ref(),
                    num_inputs,
                    num_constraints,
                    &full_assignment,
                    &mut msm_dispatch,
                )?,
            },
            None => {
                msm_dispatch.witness_map_engine = "ark-libsnark-reduction";
                msm_dispatch.witness_map_reason = "bn254-witness-map-cpu-engine";
                msm_dispatch.witness_map_parallelism = 1;
                let matrices = Arc::new(constraint_matrices(
                    &cs,
                    "failed to materialize Groth16 constraint matrices",
                )?);
                LibsnarkReduction::witness_map_from_matrices::<
                    Fr,
                    ark_poly::GeneralEvaluationDomain<Fr>,
                >(
                    matrices.as_ref(),
                    num_inputs,
                    num_constraints,
                    &full_assignment,
                )
                .map_err(|err| ZkfError::Backend(err.to_string()))?
            }
        };
        let witness_map_ms = witness_map_start.elapsed().as_secs_f64() * 1_000.0;
        crate::relieve_allocator_pressure();
        let prove_core_start = Instant::now();
        let proof = create_local_groth16_proof_with_assignment(
            pk,
            r,
            s,
            &h,
            &input_assignment,
            &aux_assignment,
            &mut msm_dispatch,
        )?;
        let prove_core_ms = prove_core_start.elapsed().as_secs_f64() * 1_000.0;
        crate::relieve_allocator_pressure();

        msm_dispatch.stage_breakdown.insert(
            "constraint_synthesis".to_string(),
            Groth16StageTelemetry::new(
                "cpu",
                synthesis_ms,
                1,
                false,
                Some("bn254-circuit-synthesis-not-metal".to_string()),
            ),
        );
        msm_dispatch.stage_breakdown.insert(
            "witness_map".to_string(),
            Groth16StageTelemetry::new(
                msm_dispatch.witness_map_engine,
                witness_map_ms,
                msm_dispatch.witness_map_parallelism.max(1),
                msm_dispatch
                    .witness_map_engine
                    .starts_with("metal-bn254-ntt"),
                if msm_dispatch.witness_map_reason.is_empty() {
                    None
                } else {
                    Some(msm_dispatch.witness_map_reason.to_string())
                },
            ),
        );
        msm_dispatch.stage_breakdown.insert(
            "groth16_prove_core".to_string(),
            Groth16StageTelemetry::new(
                if msm_dispatch.used_metal {
                    "metal"
                } else {
                    "cpu"
                },
                prove_core_ms,
                if msm_dispatch.used_metal {
                    msm_dispatch.max_inflight_jobs.max(1)
                } else {
                    0
                },
                msm_dispatch.no_cpu_fallback(),
                msm_dispatch.fallback_reason().map(str::to_string),
            ),
        );
        let no_cpu_fallback = msm_dispatch.no_cpu_fallback();
        let fallback_reason = msm_dispatch.fallback_reason().map(str::to_string);
        if let Some(msm_window) = msm_dispatch.stage_breakdown.get_mut("msm_window") {
            msm_window.duration_ms = prove_core_ms;
            msm_window.inflight_jobs = if msm_dispatch.used_metal {
                msm_dispatch.max_inflight_jobs.max(1)
            } else {
                0
            };
            msm_window.no_cpu_fallback = no_cpu_fallback;
            msm_window.fallback_reason = fallback_reason;
        }

        Ok((proof, msm_dispatch))
    })
}

pub(crate) fn should_debug_check_constraint_system_mode(
    debug_build: bool,
    construct_matrices: bool,
    env_forced: bool,
    num_constraints: usize,
) -> bool {
    debug_build && construct_matrices && (env_forced || num_constraints <= 50_000)
}

fn should_debug_check_constraint_system(cs: &ConstraintSystemRef<Fr>) -> bool {
    should_debug_check_constraint_system_mode(
        cfg!(debug_assertions),
        cs.should_construct_matrices(),
        std::env::var_os("ZKF_ASSERT_GROTH16_CS").is_some(),
        cs.num_constraints(),
    )
}

fn create_local_groth16_proof_with_assignment(
    pk: &ProvingKey<Bn254>,
    r: Fr,
    s: Fr,
    h: &[Fr],
    input_assignment: &[Fr],
    aux_assignment: &[Fr],
    msm_dispatch: &mut Groth16MsmDispatch,
) -> ZkfResult<Proof<Bn254>> {
    let h_assignment = h
        .iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();

    let aux_assignment = aux_assignment
        .iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();

    let r_s_delta_g1 = pk.delta_g1 * (r * s);

    let input_assignment = input_assignment
        .iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();
    let assignment = [&input_assignment[..], &aux_assignment[..]].concat();

    let parallel_jobs = parallel_msm_job_count([
        pk.h_query.len().min(h_assignment.len()),
        pk.l_query.len().min(aux_assignment.len()),
        pk.a_query.len().saturating_sub(1).min(assignment.len()),
        if r.is_zero() {
            0
        } else {
            pk.b_g1_query.len().saturating_sub(1).min(assignment.len())
        },
    ])?;

    let (h_acc, l_aux_acc, g_a, g1_b, g2_b) = if parallel_jobs >= 2 {
        msm_dispatch.max_inflight_jobs = parallel_jobs;
        msm_dispatch.counter_source = "parallel-msm-estimate";
        let r_for_ga = r;
        let s_for_g1b = s;
        let s_for_g2 = s;

        std::thread::scope(|scope| {
            let h_handle = scope.spawn(|| {
                let mut dispatch = Groth16MsmDispatch::default();
                let acc = msm_g1_bigint(&pk.h_query, &h_assignment, &mut dispatch);
                (acc, dispatch)
            });
            let l_handle = scope.spawn(|| {
                let mut dispatch = Groth16MsmDispatch::default();
                let acc = msm_g1_bigint(&pk.l_query, &aux_assignment, &mut dispatch);
                (acc, dispatch)
            });
            let ga_handle = scope.spawn(|| {
                let mut dispatch = Groth16MsmDispatch::default();
                let acc = calculate_g1_coeff(
                    pk.delta_g1 * r_for_ga,
                    &pk.a_query,
                    pk.vk.alpha_g1,
                    &assignment,
                    &mut dispatch,
                );
                (acc, dispatch)
            });
            let g1b_handle = (!r.is_zero()).then(|| {
                scope.spawn(|| {
                    let mut dispatch = Groth16MsmDispatch::default();
                    let acc = calculate_g1_coeff(
                        pk.delta_g1 * s_for_g1b,
                        &pk.b_g1_query,
                        pk.beta_g1,
                        &assignment,
                        &mut dispatch,
                    );
                    (acc, dispatch)
                })
            });
            let g2_handle = scope.spawn(|| {
                calculate_g2_coeff(
                    pk.vk.delta_g2 * s_for_g2,
                    &pk.b_g2_query,
                    pk.vk.beta_g2,
                    &assignment,
                )
            });

            let (h_acc, h_dispatch) = h_handle.join().expect("h_query worker panicked");
            let (l_acc, l_dispatch) = l_handle.join().expect("l_query worker panicked");
            let (g_a, g_a_dispatch) = ga_handle.join().expect("a_query worker panicked");
            let (g1_b, g1_b_dispatch) = match g1b_handle {
                Some(handle) => {
                    let (acc, dispatch) = handle.join().expect("b_g1_query worker panicked");
                    (acc?, dispatch)
                }
                None => (G1Projective::zero(), Groth16MsmDispatch::default()),
            };
            let g2_b = g2_handle.join().expect("b_g2_query worker panicked")?;

            msm_dispatch.merge(h_dispatch);
            msm_dispatch.merge(l_dispatch);
            msm_dispatch.merge(g_a_dispatch);
            msm_dispatch.merge(g1_b_dispatch);

            Ok::<_, ZkfError>((h_acc?, l_acc?, g_a?, g1_b, g2_b))
        })?
    } else {
        msm_dispatch.counter_source = "sequential-msm-estimate";
        let h_acc = msm_g1_bigint(&pk.h_query, &h_assignment, msm_dispatch)?;
        let l_aux_acc = msm_g1_bigint(&pk.l_query, &aux_assignment, msm_dispatch)?;
        let g_a = calculate_g1_coeff(
            pk.delta_g1 * r,
            &pk.a_query,
            pk.vk.alpha_g1,
            &assignment,
            msm_dispatch,
        )?;
        let g1_b = if !r.is_zero() {
            calculate_g1_coeff(
                pk.delta_g1 * s,
                &pk.b_g1_query,
                pk.beta_g1,
                &assignment,
                msm_dispatch,
            )?
        } else {
            G1Projective::zero()
        };
        let g2_b = calculate_g2_coeff(
            pk.vk.delta_g2 * s,
            &pk.b_g2_query,
            pk.vk.beta_g2,
            &assignment,
        )?;
        if msm_dispatch.used_metal {
            msm_dispatch.max_inflight_jobs = 1;
        }
        (h_acc, l_aux_acc, g_a, g1_b, g2_b)
    };

    msm_dispatch.stage_breakdown.insert(
        "msm_window".to_string(),
        Groth16StageTelemetry::new(
            if msm_dispatch.used_metal {
                "metal"
            } else {
                "cpu"
            },
            0.0,
            if msm_dispatch.used_metal {
                msm_dispatch.max_inflight_jobs.max(1)
            } else {
                0
            },
            msm_dispatch.no_cpu_fallback(),
            msm_dispatch.fallback_reason().map(str::to_string),
        ),
    );

    let r_g1_b = g1_b * r;
    let s_g_a = g_a * s;

    let mut g_c = s_g_a;
    g_c += r_g1_b;
    g_c -= r_s_delta_g1;
    g_c += l_aux_acc;
    g_c += h_acc;

    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}

fn create_local_groth16_proof_with_assignment_from_streamed_pk(
    pk_path: &Path,
    r: Fr,
    s: Fr,
    h: &[Fr],
    input_assignment: &[Fr],
    aux_assignment: &[Fr],
    msm_dispatch: &mut Groth16MsmDispatch,
) -> ZkfResult<(Proof<Bn254>, VerifyingKey<Bn254>)> {
    let file = File::open(pk_path).map_err(|err| {
        ZkfError::Backend(format!(
            "failed to open streamed Groth16 proving key {}: {err}",
            pk_path.display()
        ))
    })?;
    let mut reader = BufReader::new(file);
    let vk =
        VerifyingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize streamed Groth16 verifying key {}: {err}",
                pk_path.display()
            ))
        })?;
    let beta_g1 = G1Affine::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 beta_g1 {}: {err}",
            pk_path.display()
        ))
    })?;
    let delta_g1 = G1Affine::deserialize_uncompressed_unchecked(&mut reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 delta_g1 {}: {err}",
            pk_path.display()
        ))
    })?;

    let h_assignment = h
        .iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();
    let aux_assignment = aux_assignment
        .iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();
    let input_assignment = input_assignment
        .iter()
        .map(|scalar| scalar.into_bigint())
        .collect::<Vec<_>>();
    let assignment = [&input_assignment[..], &aux_assignment[..]].concat();

    let g_a = calculate_g1_coeff_streaming(
        &mut reader,
        delta_g1 * r,
        vk.alpha_g1,
        &assignment,
        msm_dispatch,
        "a_query",
    )?;
    crate::relieve_allocator_pressure();
    let g1_b = calculate_g1_coeff_streaming(
        &mut reader,
        delta_g1 * s,
        beta_g1,
        &assignment,
        msm_dispatch,
        "b_g1_query",
    )?;
    crate::relieve_allocator_pressure();
    let g2_b = calculate_g2_coeff_streaming(
        &mut reader,
        vk.delta_g2 * s,
        vk.beta_g2,
        &assignment,
        "b_g2_query",
    )?;
    crate::relieve_allocator_pressure();
    let h_acc = msm_g1_vec_streaming(&mut reader, &h_assignment, msm_dispatch, "h_query")?;
    crate::relieve_allocator_pressure();
    let l_aux_acc = msm_g1_vec_streaming(&mut reader, &aux_assignment, msm_dispatch, "l_query")?;

    msm_dispatch.stage_breakdown.insert(
        "msm_window".to_string(),
        Groth16StageTelemetry::new(
            if msm_dispatch.used_metal {
                "metal"
            } else {
                "cpu"
            },
            0.0,
            if msm_dispatch.used_metal {
                msm_dispatch.max_inflight_jobs.max(1)
            } else {
                0
            },
            msm_dispatch.no_cpu_fallback(),
            msm_dispatch.fallback_reason().map(str::to_string),
        ),
    );

    let r_s_delta_g1 = delta_g1 * (r * s);
    let r_g1_b = g1_b * r;
    let s_g_a = g_a * s;

    let mut g_c = s_g_a;
    g_c += r_g1_b;
    g_c -= r_s_delta_g1;
    g_c += l_aux_acc;
    g_c += h_acc;

    Ok((
        Proof {
            a: g_a.into_affine(),
            b: g2_b.into_affine(),
            c: g_c.into_affine(),
        },
        vk,
    ))
}

fn calculate_g1_coeff(
    initial: G1Projective,
    query: &[G1Affine],
    vk_param: G1Affine,
    assignment: &[ScalarBigInt],
    msm_dispatch: &mut Groth16MsmDispatch,
) -> ZkfResult<G1Projective> {
    let (el, tail) = query.split_first().ok_or_else(|| {
        ZkfError::Backend("Groth16 proving key is missing a G1 query base".to_string())
    })?;
    let acc = msm_g1_bigint(tail, assignment, msm_dispatch)?;

    let mut result = initial;
    result += el.into_group();
    result += acc;
    result += vk_param.into_group();
    Ok(result)
}

fn streamed_groth16_query_chunk_size() -> usize {
    std::env::var("ZKF_STREAMED_GROTH16_QUERY_CHUNK")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1 << 16)
}

fn read_streamed_query_len<R: Read>(reader: &mut R, label: &str) -> ZkfResult<usize> {
    let len = u64::deserialize_uncompressed_unchecked(reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 {label} length: {err}"
        ))
    })?;
    usize::try_from(len)
        .map_err(|_| ZkfError::InvalidArtifact(format!("streamed Groth16 {label} is too large")))
}

fn msm_g1_vec_streaming<R: Read>(
    reader: &mut R,
    assignment: &[ScalarBigInt],
    msm_dispatch: &mut Groth16MsmDispatch,
    label: &str,
) -> ZkfResult<G1Projective> {
    let len = read_streamed_query_len(reader, label)?;
    msm_g1_bigint_streaming(reader, len, assignment, msm_dispatch, label)
}

fn msm_g1_bigint_streaming<R: Read>(
    reader: &mut R,
    len: usize,
    assignment: &[ScalarBigInt],
    msm_dispatch: &mut Groth16MsmDispatch,
    label: &str,
) -> ZkfResult<G1Projective> {
    let mut acc = G1Projective::zero();
    let chunk_size = streamed_groth16_query_chunk_size();
    let usable = len.min(assignment.len());

    let mut processed = 0usize;
    while processed < usable {
        let take = (usable - processed).min(chunk_size);
        let mut bases = Vec::with_capacity(take);
        for _ in 0..take {
            let base =
                G1Affine::deserialize_uncompressed_unchecked(&mut *reader).map_err(|err| {
                    ZkfError::InvalidArtifact(format!(
                        "failed to deserialize streamed Groth16 {label} base: {err}"
                    ))
                })?;
            bases.push(base);
        }
        let chunk_acc = msm_g1_bigint(
            &bases,
            &assignment[processed..processed + take],
            msm_dispatch,
        )?;
        acc += chunk_acc;
        processed += take;
        crate::relieve_allocator_pressure();
    }

    for _ in processed..len {
        let _ = G1Affine::deserialize_uncompressed_unchecked(&mut *reader).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize streamed Groth16 trailing {label} base: {err}"
            ))
        })?;
    }

    Ok(acc)
}

fn calculate_g1_coeff_streaming<R: Read>(
    reader: &mut R,
    initial: G1Projective,
    vk_param: G1Affine,
    assignment: &[ScalarBigInt],
    msm_dispatch: &mut Groth16MsmDispatch,
    label: &str,
) -> ZkfResult<G1Projective> {
    let len = read_streamed_query_len(reader, label)?;
    if len == 0 {
        return Err(ZkfError::Backend(format!(
            "streamed Groth16 proving key is missing {label}"
        )));
    }
    let el = G1Affine::deserialize_uncompressed_unchecked(&mut *reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 {label} head: {err}"
        ))
    })?;
    let acc = msm_g1_bigint_streaming(reader, len - 1, assignment, msm_dispatch, label)?;

    let mut result = initial;
    result += el.into_group();
    result += acc;
    result += vk_param.into_group();
    Ok(result)
}

fn calculate_g2_coeff(
    initial: G2Projective,
    query: &[G2Affine],
    vk_param: G2Affine,
    assignment: &[ScalarBigInt],
) -> ZkfResult<G2Projective> {
    let (el, tail) = query.split_first().ok_or_else(|| {
        ZkfError::Backend("Groth16 proving key is missing a G2 query base".to_string())
    })?;
    let size = tail.len().min(assignment.len());

    let acc = if size == 0 {
        G2Projective::zero()
    } else {
        G2Projective::msm_bigint(&tail[..size], &assignment[..size])
    };

    let mut result = initial;
    result += el.into_group();
    result += acc;
    result += vk_param.into_group();
    Ok(result)
}

fn calculate_g2_coeff_streaming<R: Read>(
    reader: &mut R,
    initial: G2Projective,
    vk_param: G2Affine,
    assignment: &[ScalarBigInt],
    label: &str,
) -> ZkfResult<G2Projective> {
    let len = read_streamed_query_len(reader, label)?;
    if len == 0 {
        return Err(ZkfError::Backend(format!(
            "streamed Groth16 proving key is missing {label}"
        )));
    }
    let el = G2Affine::deserialize_uncompressed_unchecked(&mut *reader).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to deserialize streamed Groth16 {label} head: {err}"
        ))
    })?;

    let usable = len.saturating_sub(1).min(assignment.len());
    let chunk_size = streamed_groth16_query_chunk_size();
    let mut acc = G2Projective::zero();
    let mut processed = 0usize;
    while processed < usable {
        let take = (usable - processed).min(chunk_size);
        let mut bases = Vec::with_capacity(take);
        for _ in 0..take {
            let base =
                G2Affine::deserialize_uncompressed_unchecked(&mut *reader).map_err(|err| {
                    ZkfError::InvalidArtifact(format!(
                        "failed to deserialize streamed Groth16 {label} base: {err}"
                    ))
                })?;
            bases.push(base);
        }
        acc += G2Projective::msm_bigint(&bases, &assignment[processed..processed + take]);
        processed += take;
        crate::relieve_allocator_pressure();
    }

    for _ in (processed + 1)..len {
        let _ = G2Affine::deserialize_uncompressed_unchecked(&mut *reader).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to deserialize streamed Groth16 trailing {label} base: {err}"
            ))
        })?;
    }

    let mut result = initial;
    result += el.into_group();
    result += acc;
    result += vk_param.into_group();
    Ok(result)
}

fn parallel_msm_job_count<const N: usize>(job_sizes: [usize; N]) -> ZkfResult<usize> {
    let registry = accelerator_registry()
        .lock()
        .map_err(|_| ZkfError::Backend("accelerator registry lock poisoned".to_string()))?;
    let accelerator = registry.best_msm();
    if !accelerator.is_available() {
        return Ok(0);
    }
    if accelerator.name().starts_with("metal-") {
        // The Metal MSM path already parallelizes internally and is more reliable
        // when the Groth16 MSM windows are dispatched serially.
        return Ok(0);
    }
    let min_batch = accelerator.min_batch_size();
    Ok(job_sizes
        .into_iter()
        .filter(|size| *size >= min_batch)
        .count())
}

fn groth16_metal_no_cpu_fallback_enabled() -> bool {
    matches!(
        std::env::var("ZKF_GROTH16_METAL_NO_CPU_FALLBACK").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES") | Ok("on") | Ok("ON")
    )
}

fn msm_g1_bigint(
    query: &[G1Affine],
    assignment: &[ScalarBigInt],
    _msm_dispatch: &mut Groth16MsmDispatch,
) -> ZkfResult<G1Projective> {
    _msm_dispatch.total_msm_invocations += 1;
    let size = query.len().min(assignment.len());

    if size == 0 {
        return Ok(G1Projective::zero());
    }
    let (accelerator_name, min_batch_size, metal_available) = {
        let registry = accelerator_registry()
            .lock()
            .map_err(|_| ZkfError::Backend("accelerator registry lock poisoned".to_string()))?;
        let metal_available = registry
            .msm_accelerators()
            .iter()
            .any(|acc| acc.is_available() && acc.name().starts_with("metal-"));
        let accelerator = registry.best_msm();
        (
            accelerator.name().to_string(),
            accelerator.min_batch_size(),
            metal_available,
        )
    };
    _msm_dispatch.metal_available = metal_available;
    let no_cpu_fallback = groth16_metal_no_cpu_fallback_enabled();

    if accelerator_name.starts_with("metal-") {
        match dispatch_metal_msm_affine(&query[..size], &assignment[..size]) {
            Bn254MetalMsmDispatch::Metal {
                projective,
                telemetry,
            } => {
                _msm_dispatch.metal_available = true;
                _msm_dispatch.eligible_msm_invocations += 1;
                _msm_dispatch.used_metal = true;
                _msm_dispatch.metal_msm_invocations += 1;
                _msm_dispatch.segment_count = Some(telemetry.segment_count);
                _msm_dispatch.points_per_segment = Some(telemetry.points_per_segment);
                _msm_dispatch.segment_bucket_bytes = Some(telemetry.segment_bucket_bytes);
                return Ok(projective);
            }
            Bn254MetalMsmDispatch::BelowThreshold => {
                _msm_dispatch.metal_available = true;
                _msm_dispatch.saw_below_threshold = true;
                if no_cpu_fallback {
                    return Err(ZkfError::Backend(format!(
                        "Groth16 MSM requires the certified Metal path, but the batch of {size} points fell below the Metal threshold"
                    )));
                }
            }
            Bn254MetalMsmDispatch::Unavailable => {
                _msm_dispatch.saw_unavailable = true;
                if no_cpu_fallback {
                    return Err(ZkfError::Backend(
                        "Groth16 MSM requires the certified Metal path, but Metal MSM is unavailable on this host".to_string(),
                    ));
                }
            }
            Bn254MetalMsmDispatch::DispatchFailed { detail, telemetry } => {
                _msm_dispatch.metal_available = true;
                _msm_dispatch.eligible_msm_invocations += 1;
                _msm_dispatch.saw_dispatch_failed = true;
                if let Some(telemetry) = telemetry {
                    _msm_dispatch.segment_count = Some(telemetry.segment_count);
                    _msm_dispatch.points_per_segment = Some(telemetry.points_per_segment);
                    _msm_dispatch.segment_bucket_bytes = Some(telemetry.segment_bucket_bytes);
                }
                if _msm_dispatch.dispatch_failure_detail.is_none() {
                    _msm_dispatch.dispatch_failure_detail = Some(detail.clone());
                }
                if no_cpu_fallback {
                    return Err(ZkfError::Backend(format!(
                        "Groth16 MSM requires the certified Metal path, but Metal dispatch failed: {detail}"
                    )));
                }
            }
        }
    } else {
        let scalars = assignment[..size]
            .iter()
            .map(|scalar| FieldElement::from_le_bytes(&scalar.to_bytes_le()))
            .collect::<Vec<_>>();
        let bases = query[..size]
            .iter()
            .map(|base| {
                let mut bytes = Vec::new();
                base.serialize_compressed(&mut bytes)
                    .map_err(|err| ZkfError::Serialization(err.to_string()))?;
                Ok(bytes)
            })
            .collect::<ZkfResult<Vec<_>>>()?;
        let registry = accelerator_registry()
            .lock()
            .map_err(|_| ZkfError::Backend("accelerator registry lock poisoned".to_string()))?;
        let accelerator = registry.best_msm();
        if size < min_batch_size {
            return Ok(G1Projective::msm_bigint(
                &query[..size],
                &assignment[..size],
            ));
        }
        return accelerator.msm_g1(&scalars, &bases).and_then(|bytes| {
            let affine = G1Affine::deserialize_compressed(bytes.as_slice())
                .map_err(|err| ZkfError::Backend(format!("invalid MSM result: {err}")))?;
            Ok(affine.into_group())
        });
    }

    Ok(G1Projective::msm_bigint(
        &query[..size],
        &assignment[..size],
    ))
}

#[cfg(all(target_os = "macos", feature = "metal-gpu"))]
fn dispatch_metal_msm_affine(
    bases: &[G1Affine],
    assignment: &[ScalarBigInt],
) -> Bn254MetalMsmDispatch {
    use ark_bn254::Fr;
    use ark_ec::CurveGroup;
    use ark_ff::PrimeField;

    let Some(ctx) = zkf_metal::global_context() else {
        return Bn254MetalMsmDispatch::Unavailable;
    };
    let scalars = assignment
        .iter()
        .map(|scalar| Fr::from_le_bytes_mod_order(&scalar.to_bytes_le()))
        .collect::<Vec<_>>();

    fn validate_projective(label: &str, projective: G1Projective) -> Result<G1Projective, String> {
        let affine = projective.into_affine();
        if affine.is_on_curve() && affine.is_in_correct_subgroup_assuming_on_curve() {
            Ok(affine.into_group())
        } else {
            Err(format!("{label} produced an invalid BN254 point"))
        }
    }

    match zkf_metal::msm::pippenger::metal_msm_dispatch(ctx, &scalars, bases) {
        zkf_metal::msm::pippenger::Bn254MsmDispatch::Metal {
            projective,
            telemetry,
        } => match validate_projective("metal-msm-bn254", projective) {
            Ok(valid) => Bn254MetalMsmDispatch::Metal {
                projective: valid,
                telemetry: Bn254MetalMsmTelemetry {
                    segment_count: telemetry.segment_count,
                    points_per_segment: telemetry.points_per_segment,
                    segment_bucket_bytes: telemetry.segment_bucket_bytes,
                },
            },
            Err(reason) => Bn254MetalMsmDispatch::DispatchFailed {
                detail: reason,
                telemetry: Some(Bn254MetalMsmTelemetry {
                    segment_count: telemetry.segment_count,
                    points_per_segment: telemetry.points_per_segment,
                    segment_bucket_bytes: telemetry.segment_bucket_bytes,
                }),
            },
        },
        zkf_metal::msm::pippenger::Bn254MsmDispatch::BelowThreshold => {
            Bn254MetalMsmDispatch::BelowThreshold
        }
        zkf_metal::msm::pippenger::Bn254MsmDispatch::Unavailable => {
            Bn254MetalMsmDispatch::Unavailable
        }
        zkf_metal::msm::pippenger::Bn254MsmDispatch::DispatchFailed { detail, telemetry } => {
            Bn254MetalMsmDispatch::DispatchFailed {
                detail,
                telemetry: telemetry.map(|telemetry| Bn254MetalMsmTelemetry {
                    segment_count: telemetry.segment_count,
                    points_per_segment: telemetry.points_per_segment,
                    segment_bucket_bytes: telemetry.segment_bucket_bytes,
                }),
            }
        }
    }
}

#[cfg(not(all(target_os = "macos", feature = "metal-gpu")))]
fn dispatch_metal_msm_affine(
    _bases: &[G1Affine],
    _assignment: &[ScalarBigInt],
) -> Bn254MetalMsmDispatch {
    Bn254MetalMsmDispatch::Unavailable
}

pub(crate) fn append_groth16_metal_metadata(
    metadata: &mut BTreeMap<String, String>,
    msm_dispatch: Groth16MsmDispatch,
) {
    let finalized_msm_engine = msm_dispatch.finalized_msm_engine().to_string();
    let finalized_msm_reason = msm_dispatch.finalized_msm_reason().to_string();
    let finalized_msm_parallelism = msm_dispatch.finalized_msm_parallelism();
    let finalized_msm_fallback_state = msm_dispatch.finalized_msm_fallback_state().to_string();
    let finalized_witness_map_fallback_state = msm_dispatch
        .finalized_witness_map_fallback_state()
        .to_string();
    let gpu_stage_busy_ratio = msm_dispatch.gpu_busy_ratio();
    metadata.insert(
        "msm_accelerator".to_string(),
        if msm_dispatch.used_metal {
            "metal"
        } else {
            "cpu"
        }
        .to_string(),
    );
    metadata.insert("groth16_msm_engine".to_string(), finalized_msm_engine);
    metadata.insert("groth16_msm_reason".to_string(), finalized_msm_reason);
    metadata.insert(
        "groth16_msm_parallelism".to_string(),
        finalized_msm_parallelism.to_string(),
    );
    metadata.insert(
        "groth16_msm_fallback_state".to_string(),
        finalized_msm_fallback_state,
    );
    if let Some(detail) = msm_dispatch.dispatch_failure_detail.clone() {
        metadata.insert("groth16_msm_dispatch_failure".to_string(), detail);
    }
    if let Some(segment_count) = msm_dispatch.segment_count {
        metadata.insert(
            "groth16_msm_segment_count".to_string(),
            segment_count.to_string(),
        );
    }
    if let Some(points_per_segment) = msm_dispatch.points_per_segment {
        metadata.insert(
            "groth16_msm_points_per_segment".to_string(),
            points_per_segment.to_string(),
        );
    }
    if let Some(segment_bucket_bytes) = msm_dispatch.segment_bucket_bytes {
        metadata.insert(
            "groth16_msm_segment_bucket_bytes".to_string(),
            segment_bucket_bytes.to_string(),
        );
    }
    metadata.insert(
        "metal_gpu_busy_ratio".to_string(),
        format!("{:.3}", gpu_stage_busy_ratio),
    );
    metadata.insert(
        "gpu_stage_busy_ratio".to_string(),
        format!("{:.3}", gpu_stage_busy_ratio),
    );
    metadata.insert(
        "metal_inflight_jobs".to_string(),
        if msm_dispatch.used_metal {
            msm_dispatch.max_inflight_jobs.max(1)
        } else {
            0
        }
        .to_string(),
    );
    metadata.insert(
        "metal_no_cpu_fallback".to_string(),
        msm_dispatch.no_cpu_fallback().to_string(),
    );
    metadata.insert(
        "metal_counter_source".to_string(),
        if msm_dispatch.counter_source.is_empty() {
            "not-measured"
        } else {
            msm_dispatch.counter_source
        }
        .to_string(),
    );
    metadata.insert(
        "metal_stage_breakdown".to_string(),
        serde_json::to_string(&msm_dispatch.stage_breakdown).unwrap_or_else(|_| "{}".to_string()),
    );
    metadata.insert(
        "qap_witness_map_engine".to_string(),
        if msm_dispatch.witness_map_engine.is_empty() {
            "unknown"
        } else {
            msm_dispatch.witness_map_engine
        }
        .to_string(),
    );
    metadata.insert(
        "qap_witness_map_parallelism".to_string(),
        msm_dispatch.witness_map_parallelism.max(1).to_string(),
    );
    metadata.insert(
        "qap_witness_map_reason".to_string(),
        if msm_dispatch.witness_map_reason.is_empty() {
            "unknown"
        } else {
            msm_dispatch.witness_map_reason
        }
        .to_string(),
    );
    metadata.insert(
        "qap_witness_map_fallback_state".to_string(),
        finalized_witness_map_fallback_state,
    );

    if cfg!(all(target_os = "macos", feature = "metal-gpu"))
        && let Some(reason) = msm_dispatch.fallback_reason()
    {
        metadata.insert("msm_fallback_reason".to_string(), reason.to_string());
    }
}

#[derive(Clone)]
struct IrCircuit {
    program: Program,
    values: BTreeMap<String, Fr>,
}

impl IrCircuit {
    fn from_witness(
        program: Program,
        witness_values: &BTreeMap<String, FieldElement>,
    ) -> ZkfResult<Self> {
        let mut values = BTreeMap::new();

        for signal in &program.signals {
            let value = witness_values
                .get(&signal.name)
                .or(signal.constant.as_ref())
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: signal.name.clone(),
                })?;
            values.insert(signal.name.clone(), parse_fr(value)?);
        }

        Ok(Self { program, values })
    }

    fn zeroed(program: Program) -> ZkfResult<Self> {
        let mut values = BTreeMap::new();
        for signal in &program.signals {
            let value = if let Some(constant) = &signal.constant {
                parse_fr(constant)?
            } else {
                Fr::zero()
            };
            values.insert(signal.name.clone(), value);
        }

        Ok(Self { program, values })
    }
}

impl ConstraintSynthesizer<Fr> for IrCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut variables = BTreeMap::<String, Variable>::new();

        for signal in &self.program.signals {
            let value = self
                .values
                .get(&signal.name)
                .cloned()
                .ok_or(SynthesisError::AssignmentMissing)?;

            let var = match signal.visibility {
                Visibility::Public => cs.new_input_variable(|| Ok(value))?,
                Visibility::Private | Visibility::Constant => {
                    cs.new_witness_variable(|| Ok(value))?
                }
            };

            variables.insert(signal.name.clone(), var);
        }

        for constraint in &self.program.constraints {
            match constraint {
                Constraint::Equal { lhs, rhs, .. } => {
                    let lhs_lc = expr_to_lc(cs.clone(), lhs, &variables, &self.values)?;
                    let rhs_lc = expr_to_lc(cs.clone(), rhs, &variables, &self.values)?;
                    cs.enforce_constraint(lhs_lc, lc_one(), rhs_lc)?;
                }
                Constraint::Boolean { signal, .. } => {
                    let signal_var = *variables
                        .get(signal)
                        .ok_or(SynthesisError::AssignmentMissing)?;
                    enforce_boolean(cs.clone(), signal_var)?;
                }
                Constraint::Range { signal, bits, .. } => {
                    enforce_range(cs.clone(), signal, *bits, &variables, &self.values)?;
                }
                Constraint::BlackBox { .. } => {}
                Constraint::Lookup { .. } => {
                    return Err(SynthesisError::Unsatisfiable);
                }
            }
        }

        Ok(())
    }
}

fn expr_to_lc(
    cs: ConstraintSystemRef<Fr>,
    expr: &Expr,
    variables: &BTreeMap<String, Variable>,
    values: &BTreeMap<String, Fr>,
) -> Result<LinearCombination<Fr>, SynthesisError> {
    let allow_placeholder_division = cs.is_in_setup_mode();
    match expr {
        Expr::Const(value) => {
            let constant = parse_fr(value).map_err(|_| SynthesisError::AssignmentMissing)?;
            let mut lc = LinearCombination::zero();
            lc += (constant, Variable::One);
            Ok(lc)
        }
        Expr::Signal(name) => {
            let var = *variables
                .get(name)
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(lc_from_var(var))
        }
        Expr::Add(items) => {
            let mut total = LinearCombination::zero();
            for item in items {
                total = total + expr_to_lc(cs.clone(), item, variables, values)?;
            }
            Ok(total)
        }
        Expr::Sub(a, b) => Ok(expr_to_lc(cs.clone(), a, variables, values)?
            - expr_to_lc(cs.clone(), b, variables, values)?),
        Expr::Mul(a, b) => {
            let left_lc = expr_to_lc(cs.clone(), a, variables, values)?;
            let right_lc = expr_to_lc(cs.clone(), b, variables, values)?;

            let left_value = eval_expr_fr(a, values, allow_placeholder_division)?;
            let right_value = eval_expr_fr(b, values, allow_placeholder_division)?;
            let output_value = left_value * right_value;

            let output_var = cs.new_witness_variable(|| Ok(output_value))?;
            let output_lc = lc_from_var(output_var);

            cs.enforce_constraint(left_lc, right_lc, output_lc.clone())?;
            Ok(output_lc)
        }
        Expr::Div(a, b) => {
            let numerator_lc = expr_to_lc(cs.clone(), a, variables, values)?;
            let denominator_lc = expr_to_lc(cs.clone(), b, variables, values)?;

            let numerator_value = eval_expr_fr(a, values, allow_placeholder_division)?;
            let denominator_value = eval_expr_fr(b, values, allow_placeholder_division)?;
            let inv = denominator_value
                .inverse()
                .or_else(|| {
                    if allow_placeholder_division {
                        Some(Fr::zero())
                    } else {
                        None
                    }
                })
                .ok_or(SynthesisError::AssignmentMissing)?;
            let output_value = numerator_value * inv;

            let output_var = cs.new_witness_variable(|| Ok(output_value))?;
            let output_lc = lc_from_var(output_var);

            cs.enforce_constraint(denominator_lc, output_lc.clone(), numerator_lc)?;
            Ok(output_lc)
        }
    }
}

fn enforce_boolean(cs: ConstraintSystemRef<Fr>, var: Variable) -> Result<(), SynthesisError> {
    let var_lc = lc_from_var(var);
    let mut one_minus_var = lc_one();
    one_minus_var = one_minus_var - var_lc.clone();
    cs.enforce_constraint(var_lc, one_minus_var, lc_zero())?;
    Ok(())
}

fn enforce_range(
    cs: ConstraintSystemRef<Fr>,
    signal: &str,
    bits: u32,
    variables: &BTreeMap<String, Variable>,
    values: &BTreeMap<String, Fr>,
) -> Result<(), SynthesisError> {
    let signal_var = *variables
        .get(signal)
        .ok_or(SynthesisError::AssignmentMissing)?;
    let signal_value = values
        .get(signal)
        .cloned()
        .ok_or(SynthesisError::AssignmentMissing)?;

    let bit_values = signal_value.into_bigint().to_bits_le();
    let bit_len = usize::try_from(bits).map_err(|_| SynthesisError::AssignmentMissing)?;

    let mut acc = LinearCombination::zero();
    let mut coeff = Fr::one();

    for i in 0..bit_len {
        let bit = bit_values.get(i).copied().unwrap_or(false);
        let bit_field = if bit { Fr::one() } else { Fr::zero() };
        let bit_var = cs.new_witness_variable(|| Ok(bit_field))?;
        enforce_boolean(cs.clone(), bit_var)?;

        acc += (coeff, bit_var);
        coeff += coeff;
    }

    cs.enforce_constraint(lc_from_var(signal_var), lc_one(), acc)?;
    Ok(())
}

fn eval_expr_fr(
    expr: &Expr,
    values: &BTreeMap<String, Fr>,
    allow_placeholder_division: bool,
) -> Result<Fr, SynthesisError> {
    match expr {
        Expr::Const(value) => parse_fr(value).map_err(|_| SynthesisError::AssignmentMissing),
        Expr::Signal(name) => values
            .get(name)
            .cloned()
            .ok_or(SynthesisError::AssignmentMissing),
        Expr::Add(items) => {
            let mut total = Fr::zero();
            for item in items {
                total += eval_expr_fr(item, values, allow_placeholder_division)?;
            }
            Ok(total)
        }
        Expr::Sub(a, b) => Ok(eval_expr_fr(a, values, allow_placeholder_division)?
            - eval_expr_fr(b, values, allow_placeholder_division)?),
        Expr::Mul(a, b) => Ok(eval_expr_fr(a, values, allow_placeholder_division)?
            * eval_expr_fr(b, values, allow_placeholder_division)?),
        Expr::Div(a, b) => {
            let numerator = eval_expr_fr(a, values, allow_placeholder_division)?;
            let denominator = eval_expr_fr(b, values, allow_placeholder_division)?;
            if allow_placeholder_division && denominator.is_zero() {
                return Ok(Fr::zero());
            }
            let inv = denominator
                .inverse()
                .ok_or(SynthesisError::AssignmentMissing)?;
            Ok(numerator * inv)
        }
    }
}

fn lc_zero() -> LinearCombination<Fr> {
    LinearCombination::zero()
}

fn lc_one() -> LinearCombination<Fr> {
    let mut one = LinearCombination::zero();
    one += (Fr::one(), Variable::One);
    one
}

fn lc_from_var(var: Variable) -> LinearCombination<Fr> {
    let mut lc = LinearCombination::zero();
    lc += (Fr::one(), var);
    lc
}

fn parse_fr(value: &FieldElement) -> ZkfResult<Fr> {
    let s = value.to_decimal_string();
    if let Some(unsigned) = s.strip_prefix('-') {
        let parsed =
            Fr::from_str(unsigned).map_err(|_| ZkfError::ParseField { value: s.clone() })?;
        Ok(-parsed)
    } else {
        Fr::from_str(&s).map_err(|_| ZkfError::ParseField { value: s })
    }
}

fn zir_constraint_requires_safe_v2_path(constraint: &zkf_core::zir_v1::Constraint) -> bool {
    match constraint {
        zkf_core::zir_v1::Constraint::Equal { lhs, rhs, .. } => {
            zir_expr_requires_safe_v2_path(lhs) || zir_expr_requires_safe_v2_path(rhs)
        }
        zkf_core::zir_v1::Constraint::Boolean { .. }
        | zkf_core::zir_v1::Constraint::Range { .. } => false,
        _ => true,
    }
}

fn zir_expr_requires_safe_v2_path(expr: &zkf_core::zir_v1::Expr) -> bool {
    match expr {
        zkf_core::zir_v1::Expr::Const(_) | zkf_core::zir_v1::Expr::Signal(_) => false,
        zkf_core::zir_v1::Expr::Add(values) => values.iter().any(zir_expr_requires_safe_v2_path),
        zkf_core::zir_v1::Expr::Sub(left, right) => {
            zir_expr_requires_safe_v2_path(left) || zir_expr_requires_safe_v2_path(right)
        }
        zkf_core::zir_v1::Expr::Mul(_, _) | zkf_core::zir_v1::Expr::Div(_, _) => true,
    }
}

fn pack_setup_blob(pk_bytes: &[u8], vk_bytes: &[u8]) -> ZkfResult<Vec<u8>> {
    let pk_len = u64::try_from(pk_bytes.len())
        .map_err(|_| ZkfError::Serialization("proving key too large".to_string()))?;
    let vk_len = u64::try_from(vk_bytes.len())
        .map_err(|_| ZkfError::Serialization("verification key too large".to_string()))?;

    let mut out = Vec::with_capacity(1 + 8 + pk_bytes.len() + 8 + vk_bytes.len());
    out.push(SETUP_BLOB_VERSION);
    out.extend(pk_len.to_le_bytes());
    out.extend(pk_bytes);
    out.extend(vk_len.to_le_bytes());
    out.extend(vk_bytes);
    Ok(out)
}

fn unpack_setup_blob(data: &[u8]) -> ZkfResult<(Vec<u8>, Vec<u8>)> {
    if data.is_empty() {
        return Err(ZkfError::InvalidArtifact("empty setup blob".to_string()));
    }

    let version = data[0];
    if version != SETUP_BLOB_VERSION {
        return Err(ZkfError::InvalidArtifact(format!(
            "unsupported setup blob version {version}"
        )));
    }

    let mut cursor = 1usize;

    let pk_len = read_len(data, &mut cursor)?;
    if data.len() < cursor + pk_len {
        return Err(ZkfError::InvalidArtifact(
            "setup blob truncated while reading proving key".to_string(),
        ));
    }
    let pk_bytes = data[cursor..cursor + pk_len].to_vec();
    cursor += pk_len;

    let vk_len = read_len(data, &mut cursor)?;
    if data.len() < cursor + vk_len {
        return Err(ZkfError::InvalidArtifact(
            "setup blob truncated while reading verification key".to_string(),
        ));
    }
    let vk_bytes = data[cursor..cursor + vk_len].to_vec();
    cursor += vk_len;

    if cursor != data.len() {
        return Err(ZkfError::InvalidArtifact(
            "setup blob has trailing bytes".to_string(),
        ));
    }

    Ok((pk_bytes, vk_bytes))
}

fn read_len(data: &[u8], cursor: &mut usize) -> ZkfResult<usize> {
    if data.len() < *cursor + 8 {
        return Err(ZkfError::InvalidArtifact(
            "setup blob truncated while reading length".to_string(),
        ));
    }

    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[*cursor..*cursor + 8]);
    *cursor += 8;

    let len = u64::from_le_bytes(bytes);
    usize::try_from(len)
        .map_err(|_| ZkfError::InvalidArtifact("setup blob length overflow".to_string()))
}

fn deterministic_setup_seed(program_digest: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"zkf-arkworks-setup-seed-v1");
    hasher.update(program_digest.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn groth16_auto_ceremony_cache_dir() -> PathBuf {
    std::env::var_os("ZKF_GROTH16_CEREMONY_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            home.join(".zkf").join("groth16-ceremony")
        })
}

fn hex_seed(seed: &[u8; 32]) -> String {
    seed.iter().map(|byte| format!("{byte:02x}")).collect()
}

// --- ZIR-native R1CS circuit synthesizer ---

/// Circuit synthesizer that works directly from ZIR-lowered R1CS constraints,
/// bypassing the IR v2 conversion path.
#[derive(Clone)]
struct ZirR1csCircuit {
    signals: Vec<zkf_core::zir_v1::Signal>,
    r1cs_constraints: Vec<crate::lowering::arkworks_lowering::R1csConstraint>,
    aux_variables: Vec<crate::lowering::arkworks_lowering::AuxVariable>,
    values: BTreeMap<String, Fr>,
}

impl ZirR1csCircuit {
    fn zeroed(lowered: &crate::lowering::arkworks_lowering::ArkworksLoweredIr) -> ZkfResult<Self> {
        let mut values = BTreeMap::new();
        for signal in &lowered.signals {
            let value = if let Some(constant) = &signal.constant {
                parse_fr(constant)?
            } else {
                Fr::zero()
            };
            values.insert(signal.name.clone(), value);
        }
        // Zero-init aux variables
        for aux in &lowered.aux_variables {
            values.insert(aux.name.clone(), Fr::zero());
        }

        Ok(Self {
            signals: lowered.signals.clone(),
            r1cs_constraints: lowered.r1cs_constraints.clone(),
            aux_variables: lowered.aux_variables.clone(),
            values,
        })
    }

    fn from_witness(
        lowered: &crate::lowering::arkworks_lowering::ArkworksLoweredIr,
        witness_values: &BTreeMap<String, FieldElement>,
    ) -> ZkfResult<Self> {
        let mut values = BTreeMap::new();

        for signal in &lowered.signals {
            let value = witness_values
                .get(&signal.name)
                .or(signal.constant.as_ref())
                .ok_or_else(|| ZkfError::MissingWitnessValue {
                    signal: signal.name.clone(),
                })?;
            values.insert(signal.name.clone(), parse_fr(value)?);
        }

        // Compute aux variable values from witness
        for aux in &lowered.aux_variables {
            let val = match &aux.computation {
                crate::lowering::arkworks_lowering::AuxComputation::Division {
                    numerator,
                    denominator,
                } => {
                    let num =
                        values
                            .get(numerator)
                            .cloned()
                            .ok_or(ZkfError::MissingWitnessValue {
                                signal: numerator.clone(),
                            })?;
                    let den =
                        values
                            .get(denominator)
                            .cloned()
                            .ok_or(ZkfError::MissingWitnessValue {
                                signal: denominator.clone(),
                            })?;
                    den.inverse().map(|inv| num * inv).unwrap_or(Fr::zero())
                }
                crate::lowering::arkworks_lowering::AuxComputation::RangeBit { source, bit } => {
                    let source_val =
                        values
                            .get(source)
                            .cloned()
                            .ok_or(ZkfError::MissingWitnessValue {
                                signal: source.clone(),
                            })?;
                    let bits = source_val.into_bigint().to_bits_le();
                    let bit_val = bits.get(*bit as usize).copied().unwrap_or(false);
                    if bit_val { Fr::one() } else { Fr::zero() }
                }
            };
            values.insert(aux.name.clone(), val);
        }

        Ok(Self {
            signals: lowered.signals.clone(),
            r1cs_constraints: lowered.r1cs_constraints.clone(),
            aux_variables: lowered.aux_variables.clone(),
            values,
        })
    }
}

impl ConstraintSynthesizer<Fr> for ZirR1csCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        use crate::lowering::arkworks_lowering::LinearCombination as ZirLC;

        let mut variables = BTreeMap::<String, Variable>::new();

        // Allocate signal variables
        for signal in &self.signals {
            let value = self
                .values
                .get(&signal.name)
                .cloned()
                .ok_or(SynthesisError::AssignmentMissing)?;

            let var = match signal.visibility {
                Visibility::Public => cs.new_input_variable(|| Ok(value))?,
                Visibility::Private | Visibility::Constant => {
                    cs.new_witness_variable(|| Ok(value))?
                }
            };
            variables.insert(signal.name.clone(), var);
        }

        // Allocate aux variables as witnesses
        for aux in &self.aux_variables {
            let value = self
                .values
                .get(&aux.name)
                .cloned()
                .ok_or(SynthesisError::AssignmentMissing)?;
            let var = cs.new_witness_variable(|| Ok(value))?;
            variables.insert(aux.name.clone(), var);
        }

        // Convert ZIR linear combination to arkworks LC
        let to_ark_lc = |zir_lc: &ZirLC| -> Result<LinearCombination<Fr>, SynthesisError> {
            let mut lc = LinearCombination::zero();
            // Add constant term
            let constant =
                parse_fr(&zir_lc.constant).map_err(|_| SynthesisError::AssignmentMissing)?;
            if !constant.is_zero() {
                lc += (constant, Variable::One);
            }
            // Add variable terms
            for (coeff_fe, name) in &zir_lc.terms {
                let coeff = parse_fr(coeff_fe).map_err(|_| SynthesisError::AssignmentMissing)?;
                let var = variables
                    .get(name)
                    .copied()
                    .ok_or(SynthesisError::AssignmentMissing)?;
                lc += (coeff, var);
            }
            Ok(lc)
        };

        // Enforce each R1CS constraint: A * B = C
        for r1cs in &self.r1cs_constraints {
            let a = to_ark_lc(&r1cs.a)?;
            let b = to_ark_lc(&r1cs.b)?;
            let c = to_ark_lc(&r1cs.c)?;
            cs.enforce_constraint(a, b, c)?;
        }

        Ok(())
    }
}

// --- NativeField implementation for Arkworks BN254 Fr ---

impl crate::native_field::NativeField for Fr {
    fn from_field_element(fe: &FieldElement, field: FieldId) -> ZkfResult<Self> {
        if field != FieldId::Bn254 {
            return Err(ZkfError::UnsupportedBackend {
                backend: "arkworks-groth16".to_string(),
                message: format!("expected bn254 field, got {:?}", field),
            });
        }
        parse_fr(fe)
    }

    fn to_field_element(&self) -> FieldElement {
        let repr = self.into_bigint();
        let le_bytes = repr.to_bytes_le();
        FieldElement::from_le_bytes(&le_bytes)
    }

    fn field_id() -> FieldId {
        FieldId::Bn254
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::{
        ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, SynthesisError,
    };

    #[derive(Clone)]
    struct TinyStreamedShapeCircuit;

    impl ConstraintSynthesizer<Fr> for TinyStreamedShapeCircuit {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let public = cs.new_input_variable(|| Ok(Fr::one()))?;
            let witness = cs.new_witness_variable(|| Ok(Fr::one()))?;
            cs.enforce_constraint(
                LinearCombination::from(public),
                LinearCombination::from(witness),
                LinearCombination::from(witness),
            )?;
            Ok(())
        }
    }

    #[test]
    fn streamed_shape_writer_cleans_stale_temp_siblings() {
        let base = std::env::temp_dir().join(format!(
            "zkf-streamed-shape-cleanup-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&base).expect("temp dir");
        let shape_path = base.join("shape.bin");
        fs::write(&shape_path, b"existing-shape").expect("seed shape");
        let stale_path = base.join(".shape.bin.tmp-999999-1-0");
        fs::write(&stale_path, b"stale").expect("stale temp");
        std::process::Command::new("touch")
            .args([
                "-t",
                "200001010000",
                stale_path.to_str().expect("utf8 path"),
            ])
            .status()
            .expect("touch stale temp");

        let writer = StreamedGroth16ShapeWriter::new(&shape_path, 1, 1, 1).expect("writer");
        writer.finish().expect("finish");

        assert!(!stale_path.exists(), "stale temp file should be removed");

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn streamed_shape_cleanup_keeps_fresh_temp_siblings() {
        let base = std::env::temp_dir().join(format!(
            "zkf-streamed-shape-fresh-temp-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&base).expect("temp dir");
        let shape_path = base.join("shape.bin");
        fs::write(&shape_path, b"existing-shape").expect("seed shape");
        let fresh_temp = base.join(".shape.bin.tmp-999999-1-0");
        fs::write(&fresh_temp, b"fresh temp").expect("fresh temp");

        cleanup_stale_atomic_temp_siblings(&shape_path);

        assert!(
            fresh_temp.exists(),
            "fresh concurrent temp sibling must not be removed"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn streamed_groth16_pk_readiness_rejects_truncated_file() {
        let base = std::env::temp_dir().join(format!(
            "zkf-streamed-pk-readiness-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&base).expect("temp dir");
        let pk_path = base.join("outer.pk");
        fs::write(&pk_path, b"not-a-valid-pk").expect("write truncated pk");

        assert!(
            !streamed_groth16_pk_file_is_ready(&pk_path).expect("pk readiness"),
            "truncated streamed PK must fail closed"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn streamed_groth16_shape_readiness_rejects_corrupt_file() {
        let base = std::env::temp_dir().join(format!(
            "zkf-streamed-shape-readiness-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&base).expect("temp dir");
        let shape_path = base.join("outer.shape");
        fs::write(&shape_path, b"not-a-valid-shape").expect("write corrupt shape");

        assert!(
            !streamed_groth16_shape_file_is_ready(&shape_path).expect("shape readiness"),
            "corrupt streamed shape must fail closed"
        );
        assert!(
            load_streamed_groth16_prove_shape(&shape_path).is_err(),
            "corrupt streamed shape must not deserialize"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn streamed_groth16_shape_readiness_rejects_truncated_rows() {
        let base = std::env::temp_dir().join(format!(
            "zkf-streamed-shape-truncated-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&base).expect("temp dir");
        let shape_path = base.join("outer.shape");
        build_groth16_prove_shape_to_path(TinyStreamedShapeCircuit, &shape_path)
            .expect("write valid shape");

        let mut bytes = fs::read(&shape_path).expect("read shape");
        bytes.truncate(bytes.len().saturating_sub(1));
        fs::write(&shape_path, &bytes).expect("truncate shape");

        assert!(
            !streamed_groth16_shape_file_is_ready(&shape_path).expect("shape readiness"),
            "truncated streamed shape rows must fail closed"
        );
        assert!(
            ensure_streamed_groth16_shape_file_ready(&shape_path).is_err(),
            "explicit streamed shape validation must reject truncated rows"
        );

        let _ = fs::remove_dir_all(base);
    }

    #[cfg(all(target_os = "macos", feature = "metal-gpu"))]
    #[test]
    fn streamed_bn254_gpu_ntt_matches_cpu_coset_fft() {
        if zkf_metal::MetalBn254Ntt::new().is_none() {
            eprintln!("No Metal GPU, skipping");
            return;
        }

        let n = zkf_metal::current_thresholds().ntt.max(1 << 10);
        let mut gpu_values: Vec<Fr> = (0..n).map(|i| Fr::from((i + 5) as u64)).collect();
        let mut cpu_values = gpu_values.clone();
        let dispatch = try_bn254_witness_map_ntt_in_place(&mut gpu_values, Fr::GENERATOR, false);

        if dispatch != Bn254WitnessMapNttDispatch::Metal {
            eprintln!("BN254 Metal NTT dispatch unavailable ({dispatch:?}), skipping");
            return;
        }

        GeneralEvaluationDomain::<Fr>::new(n)
            .expect("domain")
            .get_coset(Fr::GENERATOR)
            .expect("coset")
            .fft_in_place(&mut cpu_values);

        assert_eq!(gpu_values, cpu_values);
    }

    #[test]
    fn append_groth16_metal_metadata_prefers_final_msm_outcome() {
        let mut metadata = BTreeMap::new();
        append_groth16_metal_metadata(
            &mut metadata,
            Groth16MsmDispatch {
                used_metal: true,
                metal_available: true,
                saw_below_threshold: false,
                saw_unavailable: false,
                saw_dispatch_failed: true,
                dispatch_failure_detail: Some(
                    "metal MSM dispatch failed after pure-GPU retries".to_string(),
                ),
                segment_count: Some(46),
                points_per_segment: Some(1_464_843),
                segment_bucket_bytes: Some(144_703_488),
                total_msm_invocations: 4,
                eligible_msm_invocations: 4,
                metal_msm_invocations: 1,
                max_inflight_jobs: 4,
                counter_source: "parallel-msm-estimate",
                witness_map_engine: "metal-bn254-ntt+streamed-reduction",
                witness_map_reason: "bn254-witness-map-metal-ntt",
                witness_map_parallelism: 8,
                stage_breakdown: BTreeMap::new(),
            },
        );

        assert_eq!(
            metadata.get("groth16_msm_engine").map(String::as_str),
            Some("cpu-bn254-msm")
        );
        assert_eq!(
            metadata.get("groth16_msm_reason").map(String::as_str),
            Some("metal-dispatch-failed")
        );
        assert_eq!(
            metadata.get("groth16_msm_parallelism").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            metadata
                .get("groth16_msm_fallback_state")
                .map(String::as_str),
            Some("partial-cpu-fallback")
        );
        assert_eq!(
            metadata
                .get("qap_witness_map_fallback_state")
                .map(String::as_str),
            Some("none")
        );
        assert_eq!(
            metadata
                .get("groth16_msm_segment_count")
                .map(String::as_str),
            Some("46")
        );
        assert_eq!(
            metadata
                .get("groth16_msm_points_per_segment")
                .map(String::as_str),
            Some("1464843")
        );
        assert_eq!(
            metadata
                .get("groth16_msm_segment_bucket_bytes")
                .map(String::as_str),
            Some("144703488")
        );
    }

    #[test]
    fn append_groth16_metal_metadata_marks_below_threshold_cpu_fallback() {
        let mut metadata = BTreeMap::new();
        append_groth16_metal_metadata(
            &mut metadata,
            Groth16MsmDispatch {
                used_metal: false,
                metal_available: true,
                saw_below_threshold: true,
                saw_unavailable: false,
                saw_dispatch_failed: false,
                dispatch_failure_detail: None,
                segment_count: None,
                points_per_segment: None,
                segment_bucket_bytes: None,
                total_msm_invocations: 4,
                eligible_msm_invocations: 0,
                metal_msm_invocations: 0,
                max_inflight_jobs: 0,
                counter_source: "sequential-msm-estimate",
                witness_map_engine: "ark-libsnark-reduction",
                witness_map_reason: "bn254-witness-map-cpu-engine",
                witness_map_parallelism: 1,
                stage_breakdown: BTreeMap::new(),
            },
        );

        assert_eq!(
            metadata.get("groth16_msm_engine").map(String::as_str),
            Some("cpu-bn254-msm")
        );
        assert_eq!(
            metadata.get("groth16_msm_reason").map(String::as_str),
            Some("below-threshold")
        );
        assert_eq!(
            metadata
                .get("groth16_msm_fallback_state")
                .map(String::as_str),
            Some("cpu-only")
        );
        assert!(!metadata.contains_key("groth16_msm_dispatch_failure"));
    }

    #[test]
    fn below_threshold_msm_does_not_poison_eligible_metal_success() {
        let dispatch = Groth16MsmDispatch {
            used_metal: true,
            metal_available: true,
            saw_below_threshold: true,
            saw_unavailable: false,
            saw_dispatch_failed: false,
            dispatch_failure_detail: None,
            segment_count: Some(4),
            points_per_segment: Some(256),
            segment_bucket_bytes: Some(393_216),
            total_msm_invocations: 4,
            eligible_msm_invocations: 3,
            metal_msm_invocations: 3,
            max_inflight_jobs: 3,
            counter_source: "parallel-msm-estimate",
            witness_map_engine: "metal-bn254-ntt+streamed-reduction",
            witness_map_reason: "bn254-witness-map-metal-ntt",
            witness_map_parallelism: 8,
            stage_breakdown: BTreeMap::new(),
        };

        assert!(dispatch.no_cpu_fallback());
        assert_eq!(dispatch.finalized_msm_engine(), "metal-bn254-msm");
        assert_eq!(dispatch.finalized_msm_fallback_state(), "none");
    }

    #[test]
    fn recommended_groth16_setup_thread_cap_skips_small_circuits() {
        let resources = SystemResources {
            total_ram_bytes: FORTY_EIGHT_GIB,
            available_ram_bytes: 40 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(FORTY_EIGHT_GIB),
            pressure: zkf_core::MemoryPressure::default(),
        };

        assert_eq!(
            recommended_groth16_setup_thread_cap(128, 256, &resources),
            None
        );
    }

    #[test]
    fn recommended_groth16_setup_thread_cap_throttles_large_48g_unified_hosts() {
        let resources = SystemResources {
            total_ram_bytes: FORTY_EIGHT_GIB,
            available_ram_bytes: 40 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(FORTY_EIGHT_GIB),
            pressure: zkf_core::MemoryPressure::default(),
        };

        assert_eq!(
            recommended_groth16_setup_thread_cap(55_571, 62_075, &resources),
            Some(4)
        );
    }

    #[test]
    fn recommended_groth16_setup_thread_cap_drops_to_single_thread_under_high_pressure() {
        let resources = SystemResources {
            total_ram_bytes: FORTY_EIGHT_GIB,
            available_ram_bytes: 4 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(FORTY_EIGHT_GIB),
            pressure: zkf_core::MemoryPressure {
                level: PressureLevel::High,
                utilization_pct: 88.0,
                ..zkf_core::MemoryPressure::default()
            },
        };

        assert_eq!(
            recommended_groth16_setup_thread_cap(55_571, 62_075, &resources),
            Some(1)
        );
    }
}
