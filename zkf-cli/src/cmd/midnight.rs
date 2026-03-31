use actix_cors::Cors;
use actix_web::error::{
    ErrorBadRequest, ErrorInternalServerError, ErrorServiceUnavailable, ErrorTooManyRequests,
};
use actix_web::http::StatusCode;
use actix_web::rt::System;
use actix_web::web::{self, Bytes, BytesMut, Data, Json, Payload};
use actix_web::{App, Error, HttpResponse, HttpResponseBuilder, HttpServer, Responder};
use base64::Engine;
use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use base_crypto::signatures::Signature;
use chrono::{DateTime, Utc};
use futures::StreamExt;
use futures::future::{join, join_all};
use introspection::Introspection;
use ledger::dust::DustResolver;
use ledger::prove::Resolver;
use ledger::structure::{
    INITIAL_TRANSACTION_COST_MODEL, ProofPreimageMarker, ProofPreimageVersioned, ProofVersioned,
    Transaction,
};
use libcrux_ml_dsa::SIGNING_RANDOMNESS_SIZE;
use libcrux_ml_dsa::ml_dsa_87::{
    MLDSA87SigningKey, MLDSA87VerificationKey, sign as mldsa_sign,
};
use num_bigint::BigInt;
use num_traits::Zero;
use midnight_proof_server::endpoints::PUBLIC_PARAMS;
use midnight_proof_server::worker_pool::{JobStatus, WorkError, WorkerPool};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serialize::{tagged_deserialize, tagged_serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;
use storage::db::InMemoryDB;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    KeyLocation, ProvingKeyMaterial, Resolver as ResolverT, WrappedIr, Zkir,
};
use zkf_backends::backend_capability_matrix;
use zkf_core::{
    AuditCategory, AuditReport, AuditStatus, BackendKind, FieldElement, Program,
    UnderconstrainedAnalysis, Visibility, program_v2_to_zir,
};
use zkf_frontends::{FrontendImportOptions, FrontendKind, frontend_for};
use zkf_lib::{
    generate_witness, poseidon_hash4_bn254, resolve_input_aliases, witness_inputs_from_json_map,
};
use zkir as zkir_v2;

use crate::cli::{
    MidnightCommands, MidnightGatewayCommands, MidnightProofServerCommands,
};
use crate::util::sha256_hex;

const DEFAULT_KEY_LOCATIONS: [&str; 4] = [
    "midnight/zswap/spend",
    "midnight/zswap/output",
    "midnight/zswap/sign",
    "midnight/dust/spend",
];
const MIDNIGHT_PROOF_SERVER_COMPAT_VERSION: &str = "8.0.3";
const MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION: &str = "0.30.0";
const MIDNIGHT_GATEWAY_ATTESTATION_CONTEXT: &[u8] = b"zkf-midnight-gateway-attestation-v1";
const MIDNIGHT_GATEWAY_MAX_SOURCE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CompatibilityJobKind {
    MidnightCheck,
    MidnightProve,
    MidnightProveTx,
    GatewayVerify,
}

impl CompatibilityJobKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::MidnightCheck => "midnight-check",
            Self::MidnightProve => "midnight-prove",
            Self::MidnightProveTx => "midnight-prove-tx",
            Self::GatewayVerify => "midnight-gateway-verify",
        }
    }
}

#[derive(Debug, Clone)]
struct CompatibilityRuntimeConfig {
    num_workers: usize,
    job_capacity: usize,
    job_timeout: Duration,
}

#[derive(Debug, Clone)]
enum CompatibilityRuntimeError {
    JobQueueFull,
    RuntimeClosed,
    BadInput(String),
    Internal(String),
    TimedOut(String),
}

impl CompatibilityRuntimeError {
    fn bad_input(message: impl Into<String>) -> Self {
        Self::BadInput(message.into())
    }

    fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

impl std::fmt::Display for CompatibilityRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JobQueueFull => f.write_str("compatibility runtime queue is full"),
            Self::RuntimeClosed => f.write_str("compatibility runtime is closed"),
            Self::BadInput(message) => f.write_str(message),
            Self::Internal(message) => f.write_str(message),
            Self::TimedOut(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for CompatibilityRuntimeError {}

#[derive(Debug, Clone, Default)]
struct CompatibilityRuntimeSnapshot {
    jobs_processing: usize,
    jobs_pending: usize,
    job_capacity: usize,
    total_submitted: usize,
    completed_midnight_check: usize,
    completed_midnight_prove: usize,
    completed_midnight_prove_tx: usize,
    completed_gateway_verify: usize,
    last_completed_kind: Option<&'static str>,
}

struct CompatibilityRuntimeJob {
    kind: CompatibilityJobKind,
    task: Box<dyn FnOnce() -> Result<Vec<u8>, CompatibilityRuntimeError> + Send + 'static>,
    result_tx: mpsc::Sender<Result<Vec<u8>, CompatibilityRuntimeError>>,
}

#[derive(Clone)]
struct CompatibilityRuntime {
    inner: Arc<CompatibilityRuntimeInner>,
}

struct CompatibilityRuntimeInner {
    sender: mpsc::Sender<CompatibilityRuntimeJob>,
    metrics: Arc<Mutex<CompatibilityRuntimeSnapshot>>,
    job_timeout: Duration,
}

#[derive(Clone)]
struct CompatibilityJobHandle {
    result_rx: Arc<Mutex<mpsc::Receiver<Result<Vec<u8>, CompatibilityRuntimeError>>>>,
    job_timeout: Duration,
}

impl CompatibilityJobHandle {
    fn wait(self) -> Result<Vec<u8>, CompatibilityRuntimeError> {
        let receiver = self
            .result_rx
            .lock()
            .map_err(|_| CompatibilityRuntimeError::internal("compatibility runtime result lock poisoned"))?;
        receiver.recv_timeout(self.job_timeout).map_err(|_| {
            CompatibilityRuntimeError::TimedOut(format!(
                "compatibility job exceeded {:.1}s timeout",
                self.job_timeout.as_secs_f64()
            ))
        })?
    }
}

impl CompatibilityRuntime {
    fn new(config: CompatibilityRuntimeConfig) -> Self {
        let (sender, receiver) = mpsc::channel::<CompatibilityRuntimeJob>();
        let receiver = Arc::new(Mutex::new(receiver));
        let metrics = Arc::new(Mutex::new(CompatibilityRuntimeSnapshot {
            job_capacity: config.job_capacity,
            ..CompatibilityRuntimeSnapshot::default()
        }));
        for index in 0..config.num_workers.max(1) {
            let receiver = Arc::clone(&receiver);
            let metrics = Arc::clone(&metrics);
            thread::Builder::new()
                .name(format!("midnight-compat-worker-{index}"))
                .spawn(move || {
                    loop {
                        let job = {
                            let guard = match receiver.lock() {
                                Ok(guard) => guard,
                                Err(_) => return,
                            };
                            guard.recv()
                        };
                        let Ok(job) = job else {
                            return;
                        };
                        if let Ok(mut snapshot) = metrics.lock() {
                            snapshot.jobs_pending = snapshot.jobs_pending.saturating_sub(1);
                            snapshot.jobs_processing += 1;
                        }
                        let result = (job.task)();
                        if let Ok(mut snapshot) = metrics.lock() {
                            snapshot.jobs_processing = snapshot.jobs_processing.saturating_sub(1);
                            match job.kind {
                                CompatibilityJobKind::MidnightCheck => {
                                    snapshot.completed_midnight_check += 1;
                                }
                                CompatibilityJobKind::MidnightProve => {
                                    snapshot.completed_midnight_prove += 1;
                                }
                                CompatibilityJobKind::MidnightProveTx => {
                                    snapshot.completed_midnight_prove_tx += 1;
                                }
                                CompatibilityJobKind::GatewayVerify => {
                                    snapshot.completed_gateway_verify += 1;
                                }
                            }
                            snapshot.last_completed_kind = Some(job.kind.as_str());
                        }
                        let _ = job.result_tx.send(result);
                    }
                })
                .expect("spawn midnight compatibility worker");
        }
        Self {
            inner: Arc::new(CompatibilityRuntimeInner {
                sender,
                metrics,
                job_timeout: config.job_timeout,
            }),
        }
    }

    fn submit<F>(
        &self,
        kind: CompatibilityJobKind,
        task: F,
    ) -> Result<CompatibilityJobHandle, CompatibilityRuntimeError>
    where
        F: FnOnce() -> Result<Vec<u8>, CompatibilityRuntimeError> + Send + 'static,
    {
        let (result_tx, result_rx) = mpsc::channel();
        {
            let mut snapshot = self
                .inner
                .metrics
                .lock()
                .map_err(|_| CompatibilityRuntimeError::internal("compatibility runtime metrics lock poisoned"))?;
            let inflight = snapshot.jobs_pending + snapshot.jobs_processing;
            if snapshot.job_capacity != 0 && inflight >= snapshot.job_capacity {
                return Err(CompatibilityRuntimeError::JobQueueFull);
            }
            snapshot.jobs_pending += 1;
            snapshot.total_submitted += 1;
        }
        self.inner
            .sender
            .send(CompatibilityRuntimeJob {
                kind,
                task: Box::new(task),
                result_tx,
            })
            .map_err(|_| CompatibilityRuntimeError::RuntimeClosed)?;
        Ok(CompatibilityJobHandle {
            result_rx: Arc::new(Mutex::new(result_rx)),
            job_timeout: self.inner.job_timeout,
        })
    }

    fn snapshot(&self) -> CompatibilityRuntimeSnapshot {
        self.inner
            .metrics
            .lock()
            .map(|snapshot| snapshot.clone())
            .unwrap_or_default()
    }

    fn is_full(&self) -> bool {
        let snapshot = self.snapshot();
        snapshot.job_capacity != 0
            && snapshot.jobs_pending + snapshot.jobs_processing >= snapshot.job_capacity
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum MidnightProofServerEngine {
    Umpg,
    Upstream,
}

impl MidnightProofServerEngine {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "umpg" => Ok(Self::Umpg),
            "upstream" => Ok(Self::Upstream),
            other => Err(format!(
                "unknown Midnight proof-server engine '{other}' (expected umpg or upstream)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Umpg => "umpg",
            Self::Upstream => "upstream",
        }
    }

    fn execution_path(self) -> &'static str {
        match self {
            Self::Umpg => "zkf-runtime-midnight-compatibility",
            Self::Upstream => "midnight-upstream-worker-pool",
        }
    }
}

#[derive(Debug, Serialize)]
struct MidnightProofServerStartedV1 {
    schema: &'static str,
    mode: &'static str,
    compatibility_contract: &'static str,
    port: u16,
    base_url: String,
    job_capacity: usize,
    num_workers: usize,
    job_timeout_seconds: f64,
    fetch_params: bool,
    execution_engine: &'static str,
    execution_path: &'static str,
    compatibility_mode: &'static str,
    cpu_fallback_policy: &'static str,
}

#[derive(Clone)]
enum ProofServerExecution {
    Upstream { pool: Arc<WorkerPool> },
    Umpg { runtime: Arc<CompatibilityRuntime> },
}

#[derive(Clone)]
struct MidnightProofServerState {
    execution: ProofServerExecution,
}

impl MidnightProofServerState {
    fn new(
        engine: MidnightProofServerEngine,
        job_capacity: usize,
        num_workers: usize,
        job_timeout: f64,
    ) -> (Arc<Self>, Option<Arc<CompatibilityRuntime>>) {
        match engine {
            MidnightProofServerEngine::Upstream => {
                let pool = Arc::new(WorkerPool::new(num_workers, job_capacity, job_timeout));
                (
                    Arc::new(Self {
                        execution: ProofServerExecution::Upstream { pool },
                    }),
                    None,
                )
            }
            MidnightProofServerEngine::Umpg => {
                let runtime = Arc::new(CompatibilityRuntime::new(CompatibilityRuntimeConfig {
                    num_workers,
                    job_capacity,
                    job_timeout: std::time::Duration::from_secs_f64(job_timeout),
                }));
                (
                    Arc::new(Self {
                        execution: ProofServerExecution::Umpg {
                            runtime: Arc::clone(&runtime),
                        },
                    }),
                    Some(runtime),
                )
            }
        }
    }

    async fn readiness(&self) -> ReadySnapshot {
        match &self.execution {
            ProofServerExecution::Upstream { pool } => {
                let requests = pool.requests.clone();
                let jobs_processing = requests.processing_count().await;
                let jobs_pending = requests.pending_count().await;
                ReadySnapshot {
                    jobs_processing,
                    jobs_pending,
                    job_capacity: requests.capacity,
                    is_busy: requests.capacity != 0 && jobs_pending >= requests.capacity,
                }
            }
            ProofServerExecution::Umpg { runtime } => {
                let snapshot = runtime.snapshot();
                ReadySnapshot {
                    jobs_processing: snapshot.jobs_processing,
                    jobs_pending: snapshot.jobs_pending,
                    job_capacity: snapshot.job_capacity,
                    is_busy: runtime.is_full(),
                }
            }
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn umpg_runtime(&self) -> Option<Arc<CompatibilityRuntime>> {
        match &self.execution {
            ProofServerExecution::Upstream { .. } => None,
            ProofServerExecution::Umpg { runtime } => Some(Arc::clone(runtime)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ReadySnapshot {
    jobs_processing: usize,
    jobs_pending: usize,
    job_capacity: usize,
    is_busy: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    status: &'static str,
    timestamp: DateTime<Utc>,
}

#[derive(Clone, Copy, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
enum ReadyStatus {
    Ok,
    Busy,
}

impl From<ReadyStatus> for StatusCode {
    fn from(value: ReadyStatus) -> Self {
        match value {
            ReadyStatus::Ok => StatusCode::OK,
            ReadyStatus::Busy => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReadyResponse {
    status: ReadyStatus,
    jobs_processing: usize,
    jobs_pending: usize,
    job_capacity: usize,
    timestamp: DateTime<Utc>,
}

type TransactionProvePayload<S> = (
    Transaction<S, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
    HashMap<String, ProvingKeyMaterial>,
);

#[derive(Debug, Serialize)]
struct MidnightGatewayStartedV1 {
    schema: &'static str,
    mode: &'static str,
    port: u16,
    base_url: String,
    job_capacity: usize,
    num_workers: usize,
    job_timeout_seconds: f64,
    compactc_required_version: &'static str,
    compactc_path: String,
    attestor_public_key_sha256: String,
}

#[derive(Debug, Clone)]
struct GatewayCompactcConfig {
    bin_path: PathBuf,
    required_version: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum GatewayCompactcProbeStatus {
    Ok,
    Missing,
    WrongVersion,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayCompactcStatus {
    required_version: &'static str,
    detected_version: String,
    status: GatewayCompactcProbeStatus,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayAttestorInfo {
    scheme: &'static str,
    public_key_base64: String,
    public_key_sha256: String,
}

#[derive(Debug, Clone)]
struct GatewayAttestor {
    signing_key_bytes: Vec<u8>,
    info: GatewayAttestorInfo,
}

#[derive(Clone)]
struct MidnightGatewayState {
    runtime: Arc<CompatibilityRuntime>,
    compactc: Arc<GatewayCompactcConfig>,
    attestor: Arc<GatewayAttestor>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
enum GatewayVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum GatewayReadyStatus {
    Ok,
    Busy,
    Misconfigured,
}

impl From<GatewayReadyStatus> for StatusCode {
    fn from(value: GatewayReadyStatus) -> Self {
        match value {
            GatewayReadyStatus::Ok => StatusCode::OK,
            GatewayReadyStatus::Busy | GatewayReadyStatus::Misconfigured => {
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct GatewayReadyResponse {
    status: GatewayReadyStatus,
    jobs_processing: usize,
    jobs_pending: usize,
    job_capacity: usize,
    timestamp: DateTime<Utc>,
    compactc: GatewayCompactcStatus,
    attestor: GatewayAttestorInfo,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct GatewayDiagnostic {
    code: String,
    stage: String,
    message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    circuit: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct GatewaySampleCheck {
    label: String,
    verdict: GatewayVerdict,
    input_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct GatewayCircuitReport {
    name: String,
    verdict: GatewayVerdict,
    stage: String,
    program_digest: String,
    compact_compiler_version: String,
    diagnostics: Vec<GatewayDiagnostic>,
    sample_checks: Vec<GatewaySampleCheck>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    audit_report: Option<AuditReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    underconstraint_analysis: Option<UnderconstrainedAnalysis>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct GatewayUnsignedAttestation {
    schema: &'static str,
    verdict: GatewayVerdict,
    contract_name: String,
    source_sha256: String,
    report_sha256: String,
    compactc: GatewayCompactcStatus,
    attestor: GatewayAttestorInfo,
    poseidon_commitment: String,
    timestamp: DateTime<Utc>,
    diagnostics: Vec<GatewayDiagnostic>,
    circuits: Vec<GatewayCircuitReport>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct GatewaySignedAttestation {
    #[serde(flatten)]
    attestation: GatewayUnsignedAttestation,
    signature_base64: String,
}

#[derive(Debug, Deserialize)]
struct GatewayVerifyRequest {
    compact_source: String,
    #[serde(default)]
    contract_name: Option<String>,
    samples: BTreeMap<String, Vec<serde_json::Map<String, serde_json::Value>>>,
}

pub(crate) fn handle_midnight(command: MidnightCommands) -> Result<(), String> {
    match command {
        MidnightCommands::ProofServer { command } => match command {
            MidnightProofServerCommands::Serve {
                port,
                job_capacity,
                num_workers,
                engine,
                job_timeout,
                no_fetch_params,
                json,
            } => serve_midnight_proof_server(
                port,
                job_capacity,
                num_workers,
                &engine,
                job_timeout,
                no_fetch_params,
                json,
            ),
        },
        MidnightCommands::Gateway { command } => match command {
            MidnightGatewayCommands::Serve {
                port,
                job_capacity,
                num_workers,
                job_timeout,
                compactc_bin,
                attestor_key_path,
                json,
            } => serve_midnight_gateway(
                port,
                job_capacity,
                num_workers,
                job_timeout,
                compactc_bin,
                attestor_key_path,
                json,
            ),
        },
    }
}

fn serve_midnight_proof_server(
    port: u16,
    job_capacity: usize,
    num_workers: usize,
    engine_raw: &str,
    job_timeout: f64,
    no_fetch_params: bool,
    json: bool,
) -> Result<(), String> {
    let engine = MidnightProofServerEngine::parse(engine_raw)?;
    System::new().block_on(async move {
        if !no_fetch_params {
            ensure_midnight_params_ready().await?;
        }

        let (state, _runtime) =
            MidnightProofServerState::new(engine, job_capacity, num_workers, job_timeout);
        let (srv, bound_port) = bind_midnight_http_server(port, !no_fetch_params, state)
            .map_err(|error| format!("failed to bind Midnight proof server: {error}"))?;

        let started = MidnightProofServerStartedV1 {
            schema: "zkf-midnight-proof-server-started-v1",
            mode: "midnight-proof-server",
            compatibility_contract: "official-midnight-proof-server",
            port: bound_port,
            base_url: format!("http://127.0.0.1:{bound_port}"),
            job_capacity,
            num_workers,
            job_timeout_seconds: job_timeout,
            fetch_params: !no_fetch_params,
            execution_engine: engine.as_str(),
            execution_path: engine.execution_path(),
            compatibility_mode: "midnight-byte-compatible",
            cpu_fallback_policy: "preserve-midnight-cpu-semantics",
        };

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&started).map_err(|error| error.to_string())?
            );
        } else {
            println!(
                "Midnight proof server listening on {} (/prove, /check, /health) [engine={}]",
                started.base_url, started.execution_engine
            );
        }

        srv.await
            .map_err(|error| format!("Midnight proof server exited with error: {error}"))
    })
}

fn serve_midnight_gateway(
    port: u16,
    job_capacity: usize,
    num_workers: usize,
    job_timeout: f64,
    compactc_bin: Option<PathBuf>,
    attestor_key_path: Option<PathBuf>,
    json: bool,
) -> Result<(), String> {
    let compactc = Arc::new(resolve_gateway_compactc(compactc_bin.as_deref())?);
    let attestor = Arc::new(load_gateway_attestor(attestor_key_path.as_deref())?);
    System::new().block_on(async move {
        let runtime = Arc::new(CompatibilityRuntime::new(CompatibilityRuntimeConfig {
            num_workers,
            job_capacity,
            job_timeout: Duration::from_secs_f64(job_timeout),
        }));
        let state = Arc::new(MidnightGatewayState {
            runtime,
            compactc: Arc::clone(&compactc),
            attestor: Arc::clone(&attestor),
        });
        let (srv, bound_port) = bind_midnight_gateway_http_server(port, state)
            .map_err(|error| format!("failed to bind Midnight gateway: {error}"))?;
        let started = MidnightGatewayStartedV1 {
            schema: "zkf-midnight-gateway-started-v1",
            mode: "midnight-gateway",
            port: bound_port,
            base_url: format!("http://127.0.0.1:{bound_port}"),
            job_capacity,
            num_workers,
            job_timeout_seconds: job_timeout,
            compactc_required_version: compactc.required_version,
            compactc_path: compactc.bin_path.display().to_string(),
            attestor_public_key_sha256: attestor.info.public_key_sha256.clone(),
        };
        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&started).map_err(|error| error.to_string())?
            );
        } else {
            println!(
                "Midnight gateway listening on {} (/v1/verify-compact, /ready, /health)",
                started.base_url
            );
        }
        srv.await
            .map_err(|error| format!("Midnight gateway exited with error: {error}"))
    })
}

fn bind_midnight_http_server(
    port: u16,
    fetch_params: bool,
    state: Arc<MidnightProofServerState>,
) -> std::io::Result<(actix_web::dev::Server, u16)> {
    let http_server = HttpServer::new(move || {
        let app = App::new()
            .app_data(Data::from(Arc::clone(&state)))
            .route("/prove-tx", web::post().to(prove_transaction))
            .route("/prove", web::post().to(prove))
            .route("/check", web::post().to(check))
            .route("/k", web::post().to(get_k))
            .route("/version", web::get().to(version))
            .route("/proof-versions", web::get().to(proof_versions))
            .route("/ready", web::get().to(ready))
            .route("/", web::get().to(health))
            .route("/health", web::get().to(health))
            .wrap(Cors::permissive());
        if fetch_params {
            app.route("/fetch-params/{k}", web::get().to(fetch_k))
        } else {
            app
        }
    })
    .bind(("0.0.0.0", port))?;
    let bound_port = http_server.addrs()[0].port();
    let srv = http_server.run();
    Ok((srv, bound_port))
}

fn bind_midnight_gateway_http_server(
    port: u16,
    state: Arc<MidnightGatewayState>,
) -> std::io::Result<(actix_web::dev::Server, u16)> {
    let http_server = HttpServer::new(move || {
        App::new()
            .app_data(Data::from(Arc::clone(&state)))
            .app_data(
                web::JsonConfig::default().limit(MIDNIGHT_GATEWAY_MAX_SOURCE_BYTES * 2),
            )
            .route("/v1/verify-compact", web::post().to(gateway_verify_compact))
            .route("/version", web::get().to(gateway_version))
            .route("/ready", web::get().to(gateway_ready))
            .route("/", web::get().to(health))
            .route("/health", web::get().to(health))
            .wrap(Cors::permissive())
    })
    .bind(("0.0.0.0", port))?;
    let bound_port = http_server.addrs()[0].port();
    let srv = http_server.run();
    Ok((srv, bound_port))
}

async fn payload_to_bytes(mut payload: Payload) -> Result<Bytes, Error> {
    let mut body = BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

async fn version() -> impl Responder {
    MIDNIGHT_PROOF_SERVER_COMPAT_VERSION
}

async fn fetch_k(path: web::Path<u8>) -> Result<HttpResponse, Error> {
    let k = path.into_inner();
    if !(0..=25).contains(&k) {
        return Err(ErrorBadRequest(format!("k={k} out of range")));
    }
    PUBLIC_PARAMS
        .0
        .fetch_k(k)
        .await
        .map_err(ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().body("success"))
}

async fn health() -> Result<web::Json<HealthResponse>, Error> {
    Ok(web::Json(HealthResponse {
        status: "ok",
        timestamp: Utc::now(),
    }))
}

async fn ready(state: Data<MidnightProofServerState>) -> Result<HttpResponse, Error> {
    let snapshot = state.readiness().await;
    let status = ReadyResponse {
        status: if snapshot.is_busy {
            ReadyStatus::Busy
        } else {
            ReadyStatus::Ok
        },
        jobs_processing: snapshot.jobs_processing,
        jobs_pending: snapshot.jobs_pending,
        job_capacity: snapshot.job_capacity,
        timestamp: Utc::now(),
    };
    Ok(HttpResponseBuilder::new(status.status.into()).json(status))
}

async fn gateway_version() -> impl Responder {
    env!("CARGO_PKG_VERSION")
}

async fn gateway_ready(state: Data<MidnightGatewayState>) -> Result<HttpResponse, Error> {
    let snapshot = state.runtime.snapshot();
    let compactc = probe_gateway_compactc(&state.compactc);
    let status = if compactc.status != GatewayCompactcProbeStatus::Ok {
        GatewayReadyStatus::Misconfigured
    } else if state.runtime.is_full() {
        GatewayReadyStatus::Busy
    } else {
        GatewayReadyStatus::Ok
    };
    let response = GatewayReadyResponse {
        status,
        jobs_processing: snapshot.jobs_processing,
        jobs_pending: snapshot.jobs_pending,
        job_capacity: snapshot.job_capacity,
        timestamp: Utc::now(),
        compactc,
        attestor: state.attestor.info.clone(),
    };
    Ok(HttpResponseBuilder::new(status.into()).json(response))
}

async fn gateway_verify_compact(
    state: Data<MidnightGatewayState>,
    request: Json<GatewayVerifyRequest>,
) -> Result<HttpResponse, Error> {
    if request.compact_source.len() > MIDNIGHT_GATEWAY_MAX_SOURCE_BYTES {
        return Err(actix_web::error::ErrorPayloadTooLarge(format!(
            "compact source exceeds {} bytes",
            MIDNIGHT_GATEWAY_MAX_SOURCE_BYTES
        )));
    }

    let compactc_status = probe_gateway_compactc(&state.compactc);
    if compactc_status.status != GatewayCompactcProbeStatus::Ok {
        return Err(ErrorServiceUnavailable(
            "midnight gateway compactc toolchain is misconfigured",
        ));
    }

    let request = request.into_inner();
    let compactc = Arc::clone(&state.compactc);
    let attestor = Arc::clone(&state.attestor);
    let handle = state.runtime.submit(CompatibilityJobKind::GatewayVerify, move || {
        execute_gateway_verify_job(request, compactc.as_ref(), attestor.as_ref())
    });
    let response = wait_for_umpg_job(handle).await?;
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(response))
}

async fn proof_versions() -> impl Responder {
    let mut fields = ProofVersioned::introspection().fields;
    fields.retain(|value| value != "Dummy");
    format!("{fields:?}")
}

async fn get_k(payload: Payload) -> Result<HttpResponse, Error> {
    let request = payload_to_bytes(payload).await?;
    let k = k_from_ir_bytes(&request).map_err(ErrorBadRequest)?;
    Ok(HttpResponse::Ok().body(format!("{k}")))
}

async fn check(
    state: Data<MidnightProofServerState>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    let request = payload_to_bytes(payload).await?;
    let (ppi, ir): (ProofPreimageVersioned, Option<WrappedIr>) =
        tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let response = submit_check_job(state.get_ref(), ppi, ir).await?;
    Ok(HttpResponse::Ok().body(response))
}

async fn prove(
    state: Data<MidnightProofServerState>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    let request = payload_to_bytes(payload).await?;
    let (ppi, data, binding_input): (
        ProofPreimageVersioned,
        Option<ProvingKeyMaterial>,
        Option<Fr>,
    ) = tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let response = submit_prove_job(state.get_ref(), ppi, data, binding_input).await?;
    Ok(HttpResponse::Ok().body(response))
}

async fn prove_transaction(
    state: Data<MidnightProofServerState>,
    payload: Payload,
) -> Result<HttpResponse, Error> {
    let request = payload_to_bytes(payload).await?;
    let (tx, keys): TransactionProvePayload<Signature> =
        tagged_deserialize(&request[..]).map_err(ErrorBadRequest)?;
    let response = submit_prove_tx_job(state.get_ref(), tx, keys).await?;
    Ok(HttpResponse::Ok().body(response))
}

async fn submit_check_job(
    state: &MidnightProofServerState,
    ppi: ProofPreimageVersioned,
    ir: Option<WrappedIr>,
) -> Result<Vec<u8>, Error> {
    match &state.execution {
        ProofServerExecution::Upstream { pool } => {
            let (_id, updates) = pool
                .submit_and_subscribe(move || {
                    System::new().block_on(async move { execute_check_job(ppi, ir).await })
                })
                .await?;
            JobStatus::wait_for_success(&updates)
                .await
                .map_err(Into::into)
        }
        ProofServerExecution::Umpg { runtime } => {
            let handle = runtime.submit(CompatibilityJobKind::MidnightCheck, move || {
                System::new()
                    .block_on(async move { execute_check_job(ppi, ir).await })
                    .map_err(runtime_error_from_work_error)
            });
            wait_for_umpg_job(handle).await
        }
    }
}

async fn submit_prove_job(
    state: &MidnightProofServerState,
    ppi: ProofPreimageVersioned,
    data: Option<ProvingKeyMaterial>,
    binding_input: Option<Fr>,
) -> Result<Vec<u8>, Error> {
    match &state.execution {
        ProofServerExecution::Upstream { pool } => {
            let (_id, updates) = pool
                .submit_and_subscribe(move || {
                    System::new()
                        .block_on(async move { execute_prove_job(ppi, data, binding_input).await })
                })
                .await?;
            JobStatus::wait_for_success(&updates)
                .await
                .map_err(Into::into)
        }
        ProofServerExecution::Umpg { runtime } => {
            let handle = runtime.submit(CompatibilityJobKind::MidnightProve, move || {
                System::new()
                    .block_on(async move { execute_prove_job(ppi, data, binding_input).await })
                    .map_err(runtime_error_from_work_error)
            });
            wait_for_umpg_job(handle).await
        }
    }
}

async fn submit_prove_tx_job(
    state: &MidnightProofServerState,
    tx: Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
    keys: HashMap<String, ProvingKeyMaterial>,
) -> Result<Vec<u8>, Error> {
    match &state.execution {
        ProofServerExecution::Upstream { pool } => {
            let (_id, updates) = pool
                .submit_and_subscribe(move || {
                    System::new().block_on(async move { execute_prove_tx_job(tx, keys).await })
                })
                .await?;
            JobStatus::wait_for_success(&updates)
                .await
                .map_err(Into::into)
        }
        ProofServerExecution::Umpg { runtime } => {
            let handle = runtime.submit(CompatibilityJobKind::MidnightProveTx, move || {
                System::new()
                    .block_on(async move { execute_prove_tx_job(tx, keys).await })
                    .map_err(runtime_error_from_work_error)
            });
            wait_for_umpg_job(handle).await
        }
    }
}

async fn wait_for_umpg_job(
    handle: Result<CompatibilityJobHandle, CompatibilityRuntimeError>,
) -> Result<Vec<u8>, Error> {
    let handle = handle.map_err(runtime_error_to_actix)?;
    let joined = web::block(move || handle.wait())
        .await
        .map_err(ErrorInternalServerError)?;
    joined.map_err(runtime_error_to_actix)
}

fn runtime_error_from_work_error(error: WorkError) -> CompatibilityRuntimeError {
    match error {
        WorkError::BadInput(message) => CompatibilityRuntimeError::bad_input(message),
        WorkError::InternalError(message) => CompatibilityRuntimeError::internal(message),
        WorkError::CancelledUnexpectedly => {
            CompatibilityRuntimeError::internal("compatibility job cancelled unexpectedly")
        }
        WorkError::JoinError => CompatibilityRuntimeError::internal("compatibility job join error"),
    }
}

fn runtime_error_to_actix(error: CompatibilityRuntimeError) -> Error {
    match error {
        CompatibilityRuntimeError::JobQueueFull => ErrorTooManyRequests(error),
        CompatibilityRuntimeError::RuntimeClosed => ErrorInternalServerError(error),
        CompatibilityRuntimeError::BadInput(_) => ErrorBadRequest(error),
        CompatibilityRuntimeError::Internal(_) => ErrorInternalServerError(error),
        CompatibilityRuntimeError::TimedOut(_) => ErrorServiceUnavailable(error),
    }
}

async fn execute_check_job(
    ppi: ProofPreimageVersioned,
    ir: Option<WrappedIr>,
) -> Result<Vec<u8>, WorkError> {
    let ir = match ir {
        Some(ir) => ir.0,
        None => {
            let resolver = Resolver::new(
                PUBLIC_PARAMS.clone(),
                DustResolver(
                    MidnightDataProvider::new(
                        FetchMode::OnDemand,
                        OutputMode::Log,
                        ledger::dust::DUST_EXPECTED_FILES.to_owned(),
                    )
                    .map_err(|error| WorkError::InternalError(error.to_string()))?,
                ),
                Box::new(move |_: KeyLocation| Box::pin(std::future::ready(Ok(None)))),
            );
            let proof_data = resolver
                .resolve_key(ppi.key_location().clone())
                .await
                .map_err(|error| WorkError::BadInput(error.to_string()))?;
            proof_data
                .ok_or_else(|| {
                    WorkError::BadInput(format!(
                        "couldn't find built-in key {}",
                        &ppi.key_location().0
                    ))
                })?
                .ir_source
        }
    };
    let result = match ppi {
        ProofPreimageVersioned::V2(ppi) => check_ir_v2(ppi, &ir)?,
        _ => unreachable!(),
    };
    let result = result
        .into_iter()
        .map(|value| value.map(|value| value as u64))
        .collect::<Vec<_>>();
    let mut response = Vec::new();
    tagged_serialize(&result, &mut response)
        .map_err(|error| WorkError::InternalError(error.to_string()))?;
    Ok(response)
}

async fn execute_prove_job(
    ppi: ProofPreimageVersioned,
    data: Option<ProvingKeyMaterial>,
    binding_input: Option<Fr>,
) -> Result<Vec<u8>, WorkError> {
    let data_resolver = data.clone();
    let resolver = Resolver::new(
        PUBLIC_PARAMS.clone(),
        DustResolver(
            MidnightDataProvider::new(
                FetchMode::OnDemand,
                OutputMode::Log,
                ledger::dust::DUST_EXPECTED_FILES.to_owned(),
            )
            .map_err(|error| WorkError::InternalError(error.to_string()))?,
        ),
        Box::new(move |_: KeyLocation| Box::pin(std::future::ready(Ok(data_resolver.clone())))),
    );

    let proof = match ppi {
        ProofPreimageVersioned::V2(mut ppi) => {
            if let Some(binding_input) = binding_input {
                let mut inner = (*ppi).clone();
                inner.binding_input = binding_input;
                ppi = Arc::new(inner);
            }
            let proving_data = match data {
                Some(pkm) => pkm,
                None => resolver
                    .resolve_key(ppi.key_location.clone())
                    .await
                    .map_err(|error| WorkError::BadInput(error.to_string()))?
                    .ok_or_else(|| {
                        WorkError::BadInput(format!("couldn't find key {}", &ppi.key_location.0))
                    })?,
            };

            let proof = prove_ir_v2(ppi, &proving_data.ir_source, &resolver)
                .await
                .map_err(|error| WorkError::BadInput(error.to_string()))?
                .0;
            ProofVersioned::V2(proof)
        }
        _ => unreachable!(),
    };

    let mut response = Vec::new();
    tagged_serialize(&proof, &mut response)
        .map_err(|error| WorkError::InternalError(error.to_string()))?;
    Ok(response)
}

async fn execute_prove_tx_job(
    tx: Transaction<Signature, ProofPreimageMarker, PedersenRandomness, InMemoryDB>,
    keys: HashMap<String, ProvingKeyMaterial>,
) -> Result<Vec<u8>, WorkError> {
    let resolver = Resolver::new(
        PUBLIC_PARAMS.clone(),
        DustResolver(
            MidnightDataProvider::new(
                FetchMode::OnDemand,
                OutputMode::Log,
                ledger::dust::DUST_EXPECTED_FILES.to_owned(),
            )
            .map_err(|error| WorkError::InternalError(error.to_string()))?,
        ),
        Box::new(move |loc| Box::pin(std::future::ready(Ok(keys.get(loc.0.as_ref()).cloned())))),
    );
    let provider = zkir_v2::LocalProvingProvider {
        rng: OsRng,
        params: &resolver,
        resolver: &resolver,
    };
    let proof = tx
        .prove(provider, &INITIAL_TRANSACTION_COST_MODEL.runtime_cost_model)
        .await
        .map_err(|error| WorkError::BadInput(error.to_string()))?;
    let mut response = Vec::new();
    tagged_serialize(&proof, &mut response)
        .map_err(|error| WorkError::InternalError(error.to_string()))?;
    Ok(response)
}

async fn ensure_midnight_params_ready() -> Result<(), String> {
    let resolver = Resolver::new(
        PUBLIC_PARAMS.clone(),
        DustResolver(
            MidnightDataProvider::new(
                FetchMode::OnDemand,
                OutputMode::Log,
                ledger::dust::DUST_EXPECTED_FILES.to_owned(),
            )
            .map_err(|error| format!("failed to initialize Midnight data provider: {error}"))?,
        ),
        Box::new(move |_: KeyLocation| Box::pin(std::future::ready(Ok(None)))),
    );

    let ks = join_all((10..=15).map(|k| PUBLIC_PARAMS.0.fetch_k(k)));
    let keys = join_all(
        DEFAULT_KEY_LOCATIONS
            .into_iter()
            .map(|name| resolver.resolve_key(KeyLocation(name.into()))),
    );
    let (ks, keys) = join(ks, keys).await;

    ks.into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to fetch Midnight public parameters: {error}"))?;
    keys.into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to resolve Midnight proving keys: {error}"))?;

    Ok(())
}

fn k_from_ir_bytes(request: &[u8]) -> Result<u8, &'static str> {
    if let Ok(ir_v2) = tagged_deserialize::<zkir_v2::IrSource>(&mut &request[..]) {
        Ok(ir_v2.k())
    } else {
        Err("Unsupported ZKIR version")
    }
}

fn check_ir_v2(
    ppi: Arc<transient_crypto::proofs::ProofPreimage>,
    ir: &[u8],
) -> Result<Vec<Option<usize>>, WorkError> {
    let ir_v2 = tagged_deserialize::<zkir_v2::IrSource>(&mut &ir[..])
        .map_err(|_| WorkError::BadInput("Unsupported ZKIR version".to_string()))?;
    ppi.check(&ir_v2)
        .map_err(|error| WorkError::BadInput(error.to_string()))
}

async fn prove_ir_v2(
    ppi: Arc<transient_crypto::proofs::ProofPreimage>,
    ir_source: &[u8],
    resolver: &Resolver,
) -> Result<(transient_crypto::proofs::Proof, Vec<Option<usize>>), WorkError> {
    tagged_deserialize::<zkir_v2::IrSource>(&mut &ir_source[..])
        .map_err(|_| WorkError::BadInput("Unsupported ZKIR version".to_string()))?;
    ppi.prove::<zkir_v2::IrSource>(OsRng, &*PUBLIC_PARAMS, resolver)
        .await
        .map_err(|error| WorkError::BadInput(error.to_string()))
}

#[derive(Debug, Clone, Deserialize)]
struct GatewayCompactContractInfo {
    #[serde(rename = "compiler-version")]
    compiler_version: String,
    #[serde(default)]
    circuits: Vec<GatewayCompactCircuitInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct GatewayCompactCircuitInfo {
    name: String,
    #[serde(default)]
    arguments: Vec<GatewayCompactCircuitArgument>,
}

#[derive(Debug, Clone, Deserialize)]
struct GatewayCompactCircuitArgument {
    name: String,
    #[serde(rename = "type")]
    ty: serde_json::Value,
}

#[derive(Debug)]
struct GatewayCompiledCircuit {
    name: String,
    program: Program,
    contract_info: GatewayCompactCircuitInfo,
    compiler_version: String,
    contract_types_path: PathBuf,
}

#[derive(Debug)]
struct GatewayCompiledContract {
    _workspace: TempDir,
    circuits: Vec<GatewayCompiledCircuit>,
}

fn resolve_gateway_compactc(bin_override: Option<&Path>) -> Result<GatewayCompactcConfig, String> {
    let bin_path = bin_override
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("COMPACTC_BIN").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("HOME").map(|home| {
                PathBuf::from(home)
                    .join(".compact")
                    .join("versions")
                    .join(MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION)
                    .join("aarch64-darwin")
                    .join("compactc")
            })
        })
        .unwrap_or_else(|| PathBuf::from("compactc"));
    let config = GatewayCompactcConfig {
        bin_path,
        required_version: MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION,
    };
    let status = probe_gateway_compactc(&config);
    if status.status != GatewayCompactcProbeStatus::Ok {
        return Err(format!(
            "midnight gateway requires compactc {} but detected '{}' ({:?})",
            config.required_version, status.detected_version, status.status
        ));
    }
    Ok(config)
}

fn probe_gateway_compactc(config: &GatewayCompactcConfig) -> GatewayCompactcStatus {
    let output = Command::new(&config.bin_path).arg("--version").output();
    match output {
        Ok(output) => {
            let detected = String::from_utf8(output.stdout)
                .ok()
                .map(|stdout| stdout.trim().to_string())
                .filter(|stdout| !stdout.is_empty())
                .or_else(|| {
                    String::from_utf8(output.stderr)
                        .ok()
                        .map(|stderr| stderr.trim().to_string())
                        .filter(|stderr| !stderr.is_empty())
                })
                .unwrap_or_default();
            let status = if detected.is_empty() {
                GatewayCompactcProbeStatus::Missing
            } else if detected == config.required_version {
                GatewayCompactcProbeStatus::Ok
            } else {
                GatewayCompactcProbeStatus::WrongVersion
            };
            GatewayCompactcStatus {
                required_version: config.required_version,
                detected_version: detected,
                status,
            }
        }
        Err(_) => GatewayCompactcStatus {
            required_version: config.required_version,
            detected_version: String::new(),
            status: GatewayCompactcProbeStatus::Missing,
        },
    }
}

fn default_gateway_attestor_key_path() -> Result<PathBuf, String> {
    let home = std::env::var_os("HOME").ok_or_else(|| {
        "MIDNIGHT_GATEWAY_ATTESTOR_KEY_PATH is not set and HOME is unavailable".to_string()
    })?;
    Ok(PathBuf::from(home)
        .join(".zkf")
        .join("midnight-gateway")
        .join("gateway_attestor.mldsa87"))
}

fn gateway_attestor_public_key_path(path: &Path) -> PathBuf {
    let mut public = path.to_path_buf();
    public.set_extension("mldsa87.pub");
    public
}

fn verify_gateway_private_key_permissions(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path)
            .map_err(|err| format!("failed to stat gateway attestor key {}: {err}", path.display()))?;
        let mode = metadata.mode() & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "gateway attestor key {} has insecure permissions {:o}",
                path.display(),
                mode
            ));
        }
    }
    Ok(())
}

fn load_gateway_attestor(path_override: Option<&Path>) -> Result<GatewayAttestor, String> {
    let signing_path = path_override
        .map(Path::to_path_buf)
        .unwrap_or(default_gateway_attestor_key_path()?);
    let public_path = gateway_attestor_public_key_path(&signing_path);
    verify_gateway_private_key_permissions(&signing_path)?;
    let signing_bytes = fs::read(&signing_path)
        .map_err(|err| format!("failed to read gateway attestor key {}: {err}", signing_path.display()))?;
    let signing_key: [u8; MLDSA87SigningKey::len()] = signing_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "gateway attestor private key is corrupt".to_string())?;
    let public_bytes = fs::read(&public_path)
        .map_err(|err| format!("failed to read gateway attestor public key {}: {err}", public_path.display()))?;
    let verification_key: [u8; MLDSA87VerificationKey::len()] = public_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "gateway attestor public key is corrupt".to_string())?;
    let public_key_bytes = verification_key.to_vec();
    Ok(GatewayAttestor {
        signing_key_bytes: signing_key.to_vec(),
        info: GatewayAttestorInfo {
            scheme: "ml-dsa-87",
            public_key_base64: base64::engine::general_purpose::STANDARD.encode(&public_key_bytes),
            public_key_sha256: sha256_hex(&public_key_bytes),
        },
    })
}

impl GatewayAttestor {
    fn sign_base64(&self, bytes: &[u8]) -> Result<String, String> {
        let signing_key: [u8; MLDSA87SigningKey::len()] = self
            .signing_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "gateway attestor private key is corrupt".to_string())?;
        let signing_key = MLDSA87SigningKey::new(signing_key);
        let mut randomness = [0u8; SIGNING_RANDOMNESS_SIZE];
        zkf_core::secure_random::secure_random_bytes(&mut randomness)?;
        let signature = mldsa_sign(
            &signing_key,
            bytes,
            MIDNIGHT_GATEWAY_ATTESTATION_CONTEXT,
            randomness,
        )
        .map_err(|_| "gateway attestation signing failed".to_string())?;
        Ok(base64::engine::general_purpose::STANDARD.encode(signature.as_slice()))
    }
}

fn execute_gateway_verify_job(
    request: GatewayVerifyRequest,
    compactc: &GatewayCompactcConfig,
    attestor: &GatewayAttestor,
) -> Result<Vec<u8>, CompatibilityRuntimeError> {
    let compactc_status = probe_gateway_compactc(compactc);
    if compactc_status.status != GatewayCompactcProbeStatus::Ok {
        return Err(CompatibilityRuntimeError::internal(
            "midnight gateway compactc toolchain drifted out of the pinned version",
        ));
    }

    let contract_name = sanitize_gateway_contract_name(
        request
            .contract_name
            .as_deref()
            .unwrap_or("contract"),
    );
    let source_sha256 = sha256_hex(request.compact_source.as_bytes());
    let timestamp = Utc::now();

    let compiled = match compile_gateway_contract(&request.compact_source, &contract_name, compactc)
    {
        Ok(compiled) => compiled,
        Err(message) => {
            let response = build_signed_gateway_attestation(
                &contract_name,
                &source_sha256,
                compactc_status,
                attestor,
                timestamp,
                vec![GatewayDiagnostic {
                    code: "compile_failure".to_string(),
                    stage: "compile".to_string(),
                    message,
                    circuit: None,
                }],
                Vec::new(),
            )?;
            return serde_json::to_vec_pretty(&response)
                .map_err(|error| CompatibilityRuntimeError::internal(error.to_string()));
        }
    };

    let missing_samples = compiled
        .circuits
        .iter()
        .filter(|circuit| {
            request
                .samples
                .get(&circuit.name)
                .is_none_or(|samples| samples.is_empty())
        })
        .map(|circuit| circuit.name.clone())
        .collect::<Vec<_>>();
    if !missing_samples.is_empty() {
        return Err(CompatibilityRuntimeError::bad_input(format!(
            "samples are required for emitted circuits: {}",
            missing_samples.join(", ")
        )));
    }

    let circuits = compiled
        .circuits
        .iter()
        .map(|circuit| verify_gateway_circuit(circuit, request.samples.get(&circuit.name).unwrap()))
        .collect::<Result<Vec<_>, _>>()?;

    let response = build_signed_gateway_attestation(
        &contract_name,
        &source_sha256,
        compactc_status,
        attestor,
        timestamp,
        Vec::new(),
        circuits,
    )?;
    serde_json::to_vec_pretty(&response)
        .map_err(|error| CompatibilityRuntimeError::internal(error.to_string()))
}

fn compile_gateway_contract(
    compact_source: &str,
    contract_name: &str,
    compactc: &GatewayCompactcConfig,
) -> Result<GatewayCompiledContract, String> {
    let workspace = TempDir::new().map_err(|error| error.to_string())?;
    let source_path = workspace.path().join(format!("{contract_name}.compact"));
    let out_dir = workspace.path().join("compact-out");
    fs::write(&source_path, compact_source)
        .map_err(|error| format!("failed to write Compact source: {error}"))?;

    let output = Command::new(&compactc.bin_path)
        .arg("--skip-zk")
        .arg(&source_path)
        .arg(&out_dir)
        .output()
        .map_err(|error| format!("failed to launch compactc: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "compactc failed: stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let contract_info_path = out_dir.join("compiler").join("contract-info.json");
    let contract_info: GatewayCompactContractInfo = serde_json::from_str(
        &fs::read_to_string(&contract_info_path).map_err(|error| {
            format!(
                "failed to read Compact contract-info sidecar {}: {error}",
                contract_info_path.display()
            )
        })?,
    )
    .map_err(|error| {
        format!(
            "failed to parse Compact contract-info sidecar {}: {error}",
            contract_info_path.display()
        )
    })?;
    let contract_types_path = out_dir.join("contract").join("index.d.ts");
    if !contract_types_path.is_file() {
        return Err(format!(
            "missing Compact contract type sidecar {}",
            contract_types_path.display()
        ));
    }

    let mut zkir_paths = fs::read_dir(out_dir.join("zkir"))
        .map_err(|error| format!("failed to read Compact zkir output directory: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "zkir"))
        .collect::<Vec<_>>();
    zkir_paths.sort();
    if zkir_paths.is_empty() {
        return Err("compactc produced no zkir circuits".to_string());
    }

    let mut circuits = Vec::with_capacity(zkir_paths.len());
    for zkir_path in zkir_paths {
        let circuit_name = zkir_path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| format!("invalid Compact zkir filename {}", zkir_path.display()))?
            .to_string();
        let program = import_gateway_compact_circuit(&zkir_path, &circuit_name)?;
        let circuit_info = contract_info
            .circuits
            .iter()
            .find(|candidate| candidate.name == circuit_name)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "contract-info sidecar does not describe emitted circuit '{circuit_name}'"
                )
            })?;
        circuits.push(GatewayCompiledCircuit {
            name: circuit_name,
            program,
            contract_info: circuit_info,
            compiler_version: contract_info.compiler_version.clone(),
            contract_types_path: contract_types_path.clone(),
        });
    }

    Ok(GatewayCompiledContract {
        _workspace: workspace,
        circuits,
    })
}

fn import_gateway_compact_circuit(zkir_path: &Path, circuit_name: &str) -> Result<Program, String> {
    let descriptor = serde_json::json!({
        "zkir_path": zkir_path.display().to_string(),
        "circuit_name": circuit_name,
    });
    frontend_for(FrontendKind::Compact)
        .compile_to_ir(
            &descriptor,
            &FrontendImportOptions {
                source_path: Some(zkir_path.to_path_buf()),
                program_name: Some(circuit_name.to_string()),
                ..Default::default()
            },
        )
        .map_err(|error| error.to_string())
}

fn verify_gateway_circuit(
    circuit: &GatewayCompiledCircuit,
    samples: &[serde_json::Map<String, serde_json::Value>],
) -> Result<GatewayCircuitReport, CompatibilityRuntimeError> {
    let mut diagnostics = validate_gateway_compact_metadata(circuit);
    let zir = program_v2_to_zir(&circuit.program);
    let audit_report = zkf_core::audit_program_with_capability_matrix(
        &zir,
        Some(BackendKind::Halo2Bls12381),
        &backend_capability_matrix(),
    );
    let underconstraint_analysis = if audit_report
        .checks
        .iter()
        .any(|check| check.status == AuditStatus::Fail && check.category == AuditCategory::UnderconstrainedSignals)
    {
        Some(zkf_core::analyze_underconstrained(&circuit.program))
    } else {
        None
    };
    if audit_report.summary.failed > 0 {
        diagnostics.push(GatewayDiagnostic {
            code: "audit_failure".to_string(),
            stage: "audit".to_string(),
            message: format!("audit failed with {} failing checks", audit_report.summary.failed),
            circuit: Some(circuit.name.clone()),
        });
    }

    let mut sample_checks = Vec::new();
    for (index, sample) in samples.iter().enumerate() {
        sample_checks.push(run_gateway_sample_check(
            &circuit.program,
            &circuit.name,
            &format!("caller-{index}"),
            sample,
            &mut diagnostics,
        )?);
    }
    for (label, sample) in gateway_smoke_samples(&circuit.program) {
        sample_checks.push(run_gateway_sample_check(
            &circuit.program,
            &circuit.name,
            &label,
            &sample,
            &mut diagnostics,
        )?);
    }

    let verdict = if diagnostics.is_empty()
        && sample_checks
            .iter()
            .all(|check| check.verdict == GatewayVerdict::Pass)
    {
        GatewayVerdict::Pass
    } else {
        GatewayVerdict::Fail
    };
    let stage = if diagnostics.iter().any(|diag| diag.stage == "validation") {
        "validation"
    } else if diagnostics.iter().any(|diag| diag.stage == "audit") {
        "audit"
    } else if diagnostics.iter().any(|diag| diag.stage == "samples") {
        "samples"
    } else {
        "pass"
    };
    Ok(GatewayCircuitReport {
        name: circuit.name.clone(),
        verdict,
        stage: stage.to_string(),
        program_digest: circuit.program.digest_hex(),
        compact_compiler_version: circuit.compiler_version.clone(),
        diagnostics,
        sample_checks,
        audit_report: Some(audit_report),
        underconstraint_analysis,
    })
}

fn validate_gateway_compact_metadata(circuit: &GatewayCompiledCircuit) -> Vec<GatewayDiagnostic> {
    let mut diagnostics = Vec::new();
    if circuit.compiler_version != MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION {
        diagnostics.push(GatewayDiagnostic {
            code: "schema_failure".to_string(),
            stage: "validation".to_string(),
            message: format!(
                "Compact compiler version {} does not match pinned gateway version {}",
                circuit.compiler_version, MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION
            ),
            circuit: Some(circuit.name.clone()),
        });
    }

    if !circuit.contract_types_path.is_file()
        || fs::read_to_string(&circuit.contract_types_path)
            .map(|content| !content.contains(&circuit.name))
            .unwrap_or(true)
    {
        diagnostics.push(GatewayDiagnostic {
            code: "types_failure".to_string(),
            stage: "validation".to_string(),
            message: format!(
                "Compact contract type sidecar {} is missing or does not mention circuit {}",
                circuit.contract_types_path.display(),
                circuit.name
            ),
            circuit: Some(circuit.name.clone()),
        });
    }

    let compiler_metadata = circuit
        .program
        .metadata
        .get("compact_compiler_version")
        .cloned()
        .unwrap_or_default();
    if compiler_metadata != circuit.compiler_version {
        diagnostics.push(GatewayDiagnostic {
            code: "schema_failure".to_string(),
            stage: "validation".to_string(),
            message: format!(
                "imported program compiler version '{}' does not match sidecar '{}'",
                compiler_metadata, circuit.compiler_version
            ),
            circuit: Some(circuit.name.clone()),
        });
    }

    match circuit
        .program
        .metadata
        .get("compact_public_transcript_json")
        .map(|value| serde_json::from_str::<Vec<String>>(value))
    {
        Some(Ok(transcript)) => {
            for signal_name in transcript {
                let Some(signal) = circuit.program.signal(&signal_name) else {
                    diagnostics.push(GatewayDiagnostic {
                        code: "disclose_failure".to_string(),
                        stage: "validation".to_string(),
                        message: format!(
                            "public transcript references missing signal '{}'",
                            signal_name
                        ),
                        circuit: Some(circuit.name.clone()),
                    });
                    continue;
                };
                if signal.visibility != Visibility::Public {
                    diagnostics.push(GatewayDiagnostic {
                        code: "disclose_failure".to_string(),
                        stage: "validation".to_string(),
                        message: format!(
                            "public transcript signal '{}' is not public",
                            signal_name
                        ),
                        circuit: Some(circuit.name.clone()),
                    });
                }
            }
        }
        _ => diagnostics.push(GatewayDiagnostic {
            code: "disclose_failure".to_string(),
            stage: "validation".to_string(),
            message: "compact public transcript metadata is missing or invalid".to_string(),
            circuit: Some(circuit.name.clone()),
        }),
    }

    match circuit
        .program
        .metadata
        .get("compact_pi_skip_json")
        .map(|value| serde_json::from_str::<Vec<String>>(value))
    {
        Some(Ok(events)) => {
            for event in events {
                let Some((guard, tail)) = event.split_once(':') else {
                    diagnostics.push(GatewayDiagnostic {
                        code: "disclose_failure".to_string(),
                        stage: "validation".to_string(),
                        message: format!("compact pi_skip entry '{event}' is malformed"),
                        circuit: Some(circuit.name.clone()),
                    });
                    continue;
                };
                let Some((count, guard_var)) = tail.split_once(':') else {
                    diagnostics.push(GatewayDiagnostic {
                        code: "disclose_failure".to_string(),
                        stage: "validation".to_string(),
                        message: format!("compact pi_skip entry '{event}' is malformed"),
                        circuit: Some(circuit.name.clone()),
                    });
                    continue;
                };
                if guard != "true" && guard != "false" {
                    diagnostics.push(GatewayDiagnostic {
                        code: "disclose_failure".to_string(),
                        stage: "validation".to_string(),
                        message: format!(
                            "compact pi_skip entry '{event}' is not backed by a static boolean guard"
                        ),
                        circuit: Some(circuit.name.clone()),
                    });
                }
                if count.parse::<u64>().ok().is_none_or(|count| count == 0) {
                    diagnostics.push(GatewayDiagnostic {
                        code: "disclose_failure".to_string(),
                        stage: "validation".to_string(),
                        message: format!("compact pi_skip entry '{event}' has invalid count"),
                        circuit: Some(circuit.name.clone()),
                    });
                }
                if guard_var.parse::<usize>().is_err() {
                    diagnostics.push(GatewayDiagnostic {
                        code: "disclose_failure".to_string(),
                        stage: "validation".to_string(),
                        message: format!(
                            "compact pi_skip entry '{event}' has invalid guard provenance"
                        ),
                        circuit: Some(circuit.name.clone()),
                    });
                }
            }
        }
        _ => diagnostics.push(GatewayDiagnostic {
            code: "disclose_failure".to_string(),
            stage: "validation".to_string(),
            message: "compact pi_skip metadata is missing or invalid".to_string(),
            circuit: Some(circuit.name.clone()),
        }),
    }

    if circuit.program.witness_plan.input_aliases.len() != circuit.contract_info.arguments.len() {
        diagnostics.push(GatewayDiagnostic {
            code: "witness_failure".to_string(),
            stage: "validation".to_string(),
            message: format!(
                "witness alias count {} does not match contract-info argument count {}",
                circuit.program.witness_plan.input_aliases.len(),
                circuit.contract_info.arguments.len()
            ),
            circuit: Some(circuit.name.clone()),
        });
    }

    for argument in &circuit.contract_info.arguments {
        let Some(signal_name) = circuit.program.witness_plan.input_aliases.get(&argument.name) else {
            diagnostics.push(GatewayDiagnostic {
                code: "witness_failure".to_string(),
                stage: "validation".to_string(),
                message: format!(
                    "contract-info argument '{}' is missing from witness aliases",
                    argument.name
                ),
                circuit: Some(circuit.name.clone()),
            });
            continue;
        };
        let Some(signal) = circuit.program.signal(signal_name) else {
            diagnostics.push(GatewayDiagnostic {
                code: "witness_failure".to_string(),
                stage: "validation".to_string(),
                message: format!(
                    "witness alias '{}' resolves to missing signal '{}'",
                    argument.name, signal_name
                ),
                circuit: Some(circuit.name.clone()),
            });
            continue;
        };
        if signal.visibility != Visibility::Private {
            diagnostics.push(GatewayDiagnostic {
                code: "witness_failure".to_string(),
                stage: "validation".to_string(),
                message: format!(
                    "witness alias '{}' resolves to non-private signal '{}'",
                    argument.name, signal_name
                ),
                circuit: Some(circuit.name.clone()),
            });
        }
        let expected_ty = compact_type_label(&argument.ty).unwrap_or_default();
        let actual_ty = signal.ty.clone().unwrap_or_default();
        if expected_ty != actual_ty {
            diagnostics.push(GatewayDiagnostic {
                code: "types_failure".to_string(),
                stage: "validation".to_string(),
                message: format!(
                    "argument '{}' type mismatch: expected '{}' but imported '{}'",
                    argument.name, expected_ty, actual_ty
                ),
                circuit: Some(circuit.name.clone()),
            });
        }
    }

    diagnostics
}

fn run_gateway_sample_check(
    program: &Program,
    circuit_name: &str,
    label: &str,
    sample: &serde_json::Map<String, serde_json::Value>,
    diagnostics: &mut Vec<GatewayDiagnostic>,
) -> Result<GatewaySampleCheck, CompatibilityRuntimeError> {
    let input_bytes = serde_json::to_vec(sample)
        .map_err(|error| CompatibilityRuntimeError::internal(error.to_string()))?;
    let input_sha256 = sha256_hex(&input_bytes);
    let mut inputs = witness_inputs_from_json_map(sample)
        .map_err(|error| CompatibilityRuntimeError::internal(error.to_string()))?;
    resolve_input_aliases(&mut inputs, program);
    match generate_witness(program, &inputs) {
        Ok(witness) => match zkf_core::check_constraints(program, &witness) {
            Ok(()) => Ok(GatewaySampleCheck {
                label: label.to_string(),
                verdict: GatewayVerdict::Pass,
                input_sha256,
                message: None,
            }),
            Err(error) => {
                let message = error.to_string();
                diagnostics.push(GatewayDiagnostic {
                    code: "sample_failure".to_string(),
                    stage: "samples".to_string(),
                    message: format!("{label} constraint check failed: {message}"),
                    circuit: Some(circuit_name.to_string()),
                });
                Ok(GatewaySampleCheck {
                    label: label.to_string(),
                    verdict: GatewayVerdict::Fail,
                    input_sha256,
                    message: Some(message),
                })
            }
        },
        Err(error) => {
            let message = error.to_string();
            diagnostics.push(GatewayDiagnostic {
                code: "sample_failure".to_string(),
                stage: "samples".to_string(),
                message: format!("{label} witness generation failed: {message}"),
                circuit: Some(circuit_name.to_string()),
            });
            Ok(GatewaySampleCheck {
                label: label.to_string(),
                verdict: GatewayVerdict::Fail,
                input_sha256,
                message: Some(message),
            })
        }
    }
}

fn gateway_smoke_samples(program: &Program) -> Vec<(String, serde_json::Map<String, serde_json::Value>)> {
    if program.witness_plan.input_aliases.is_empty() {
        return vec![("smoke-empty".to_string(), serde_json::Map::new())];
    }

    let mut zero = serde_json::Map::new();
    let mut one = serde_json::Map::new();
    for (alias, signal_name) in &program.witness_plan.input_aliases {
        let Some(signal) = program.signal(signal_name) else {
            return Vec::new();
        };
        let Some(ty) = signal.ty.as_deref() else {
            return Vec::new();
        };
        let Some((zero_value, one_value)) = smoke_values_for_type(ty) else {
            return Vec::new();
        };
        zero.insert(alias.clone(), zero_value);
        one.insert(alias.clone(), one_value);
    }

    let mut samples = vec![("smoke-zero".to_string(), zero)];
    if samples[0].1 != one {
        samples.push(("smoke-one".to_string(), one));
    }
    samples
}

fn smoke_values_for_type(ty: &str) -> Option<(serde_json::Value, serde_json::Value)> {
    if ty.eq_ignore_ascii_case("bool") || ty.eq_ignore_ascii_case("boolean") {
        return Some((serde_json::Value::Bool(false), serde_json::Value::Bool(true)));
    }
    if ty.starts_with("Uint<") && ty.ends_with('>') {
        return Some((
            serde_json::Value::Number(serde_json::Number::from(0u64)),
            serde_json::Value::Number(serde_json::Number::from(1u64)),
        ));
    }
    None
}

fn build_signed_gateway_attestation(
    contract_name: &str,
    source_sha256: &str,
    compactc: GatewayCompactcStatus,
    attestor: &GatewayAttestor,
    timestamp: DateTime<Utc>,
    diagnostics: Vec<GatewayDiagnostic>,
    circuits: Vec<GatewayCircuitReport>,
) -> Result<GatewaySignedAttestation, CompatibilityRuntimeError> {
    let verdict = if diagnostics.is_empty()
        && circuits
            .iter()
            .all(|circuit| circuit.verdict == GatewayVerdict::Pass)
    {
        GatewayVerdict::Pass
    } else {
        GatewayVerdict::Fail
    };
    let mut unsigned = GatewayUnsignedAttestation {
        schema: "zkf-midnight-gateway-attestation-v1",
        verdict,
        contract_name: contract_name.to_string(),
        source_sha256: source_sha256.to_string(),
        report_sha256: String::new(),
        compactc,
        attestor: attestor.info.clone(),
        poseidon_commitment: String::new(),
        timestamp,
        diagnostics,
        circuits,
    };
    let report_bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| CompatibilityRuntimeError::internal(error.to_string()))?;
    unsigned.report_sha256 = sha256_hex(&report_bytes);
    unsigned.poseidon_commitment = poseidon_commitment_from_sha256(&unsigned.report_sha256)
        .map_err(CompatibilityRuntimeError::internal)?;
    let signature_bytes = serde_json::to_vec(&unsigned)
        .map_err(|error| CompatibilityRuntimeError::internal(error.to_string()))?;
    let signature_base64 = attestor
        .sign_base64(&signature_bytes)
        .map_err(CompatibilityRuntimeError::internal)?;
    Ok(GatewaySignedAttestation {
        attestation: unsigned,
        signature_base64,
    })
}

fn poseidon_commitment_from_sha256(digest_hex: &str) -> Result<String, String> {
    let digest = hex_to_bytes(digest_hex)?;
    if digest.len() != 32 {
        return Err(format!(
            "expected 32-byte sha256 digest, found {} bytes",
            digest.len()
        ));
    }
    let lanes = [
        FieldElement::from_u64(u64::from_be_bytes(digest[0..8].try_into().unwrap())),
        FieldElement::from_u64(u64::from_be_bytes(digest[8..16].try_into().unwrap())),
        FieldElement::from_u64(u64::from_be_bytes(digest[16..24].try_into().unwrap())),
        FieldElement::from_u64(u64::from_be_bytes(digest[24..32].try_into().unwrap())),
    ];
    Ok(poseidon_hash4_bn254(&lanes)?.to_string())
}

fn sanitize_gateway_contract_name(raw: &str) -> String {
    let mut name = raw
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if name.is_empty() {
        name = "contract".to_string();
    }
    name
}

fn compact_type_label(value: &serde_json::Value) -> Option<String> {
    let object = value.as_object()?;
    let type_name = object.get("type-name")?.as_str()?;
    if type_name == "Uint" {
        let maxval = object.get("maxval")?;
        let maxval = if let Some(text) = maxval.as_str() {
            BigInt::parse_bytes(text.as_bytes(), 10)?
        } else if let Some(number) = maxval.as_u64() {
            BigInt::from(number)
        } else {
            return None;
        };
        let mut bits = 0usize;
        let mut limit = maxval;
        while limit > BigInt::zero() {
            limit >>= 1usize;
            bits += 1;
        }
        if bits == 0 {
            bits = 1;
        }
        return Some(format!("Uint<{bits}>"));
    }
    Some(type_name.to_string())
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return Err("hex digest must have even length".to_string());
    }
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).map_err(|error| error.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::dev::ServerHandle;
    use base64::Engine;
    use coin_structure::coin;
    use libcrux_ml_dsa::KEY_GENERATION_RANDOMNESS_SIZE;
    use libcrux_ml_dsa::ml_dsa_87::generate_key_pair;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use reqwest::Client;
    use std::sync::mpsc;
    use std::time::Duration;
    #[cfg(unix)]
    use std::{fs::Permissions, os::unix::fs::PermissionsExt};

    const DEFAULT_JOB_CAPACITY: usize = 2;
    const DEFAULT_NUM_WORKERS: usize = 2;
    const REQUEST_TIMEOUT_SECS: u64 = 5;
    const LONG_REQUEST_TIMEOUT_SECS: u64 = 30;

    struct TestServer {
        handle: ServerHandle,
        port: u16,
        umpg_runtime: Option<Arc<CompatibilityRuntime>>,
    }

    impl TestServer {
        fn base_url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }
    }

    struct GatewayTestServer {
        handle: ServerHandle,
        port: u16,
        runtime: Arc<CompatibilityRuntime>,
        version_path: PathBuf,
        attestor_info: GatewayAttestorInfo,
        _workspace: TempDir,
    }

    impl GatewayTestServer {
        fn base_url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }
    }

    fn build_client(timeout_secs: u64) -> Client {
        Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("reqwest client")
    }

    fn gateway_fixture_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../zkf-frontends/tests/fixtures/compact_zkir/contracts")
    }

    #[cfg(unix)]
    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, Permissions::from_mode(mode)).expect("set file permissions");
    }

    #[cfg(not(unix))]
    fn chmod(_path: &Path, _mode: u32) {}

    fn create_gateway_attestor_fixture(root: &Path) -> (PathBuf, GatewayAttestorInfo) {
        let keypair = generate_key_pair([7u8; KEY_GENERATION_RANDOMNESS_SIZE]);
        let private_path = root.join("gateway_attestor.mldsa87");
        let public_path = gateway_attestor_public_key_path(&private_path);
        fs::write(&private_path, keypair.signing_key.as_slice()).expect("write private key");
        chmod(&private_path, 0o600);
        fs::write(&public_path, keypair.verification_key.as_slice()).expect("write public key");
        let attestor = load_gateway_attestor(Some(&private_path)).expect("load gateway attestor");
        (private_path, attestor.info)
    }

    fn create_fake_compactc(root: &Path) -> (PathBuf, PathBuf) {
        let fixtures_root = gateway_fixture_root();
        let version_path = root.join("compactc.version");
        let script_path = root.join("compactc");
        fs::write(&version_path, format!("{MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION}\n"))
            .expect("write compactc version");
        fs::write(
            &script_path,
            format!(
                "#!/bin/sh\nset -eu\nVERSION_FILE='{}'\nFIXTURES_ROOT='{}'\nif [ \"${{1:-}}\" = \"--version\" ]; then\n  cat \"$VERSION_FILE\"\n  exit 0\nfi\nif [ \"${{1:-}}\" != \"--skip-zk\" ]; then\n  echo \"unsupported args: $*\" >&2\n  exit 1\nfi\nSOURCE_PATH=\"$2\"\nOUT_DIR=\"$3\"\nmkdir -p \"$OUT_DIR/zkir\" \"$OUT_DIR/compiler\" \"$OUT_DIR/contract\"\nif grep -q \"publish_sum\" \"$SOURCE_PATH\"; then\n  CONTRACT='failing'\n  CIRCUIT='publish_sum'\nelse\n  CONTRACT='passing'\n  CIRCUIT='set'\nfi\ncp \"$FIXTURES_ROOT/$CONTRACT/zkir/$CIRCUIT.zkir\" \"$OUT_DIR/zkir/$CIRCUIT.zkir\"\ncp \"$FIXTURES_ROOT/$CONTRACT/compiler/contract-info.json\" \"$OUT_DIR/compiler/contract-info.json\"\nprintf 'export declare function %s(input: unknown): unknown;\\n' \"$CIRCUIT\" > \"$OUT_DIR/contract/index.d.ts\"\n",
                version_path.display(),
                fixtures_root.display()
            ),
        )
        .expect("write fake compactc");
        chmod(&script_path, 0o755);
        (script_path, version_path)
    }

    fn start_gateway_server_with_capacity(job_capacity: usize, num_workers: usize) -> GatewayTestServer {
        let workspace = tempfile::tempdir().expect("gateway tempdir");
        let (compactc_path, version_path) = create_fake_compactc(workspace.path());
        let (attestor_key_path, attestor_info) = create_gateway_attestor_fixture(workspace.path());
        let compactc =
            Arc::new(resolve_gateway_compactc(Some(&compactc_path)).expect("resolve compactc"));
        let attestor =
            Arc::new(load_gateway_attestor(Some(&attestor_key_path)).expect("load attestor"));
        let runtime = Arc::new(CompatibilityRuntime::new(CompatibilityRuntimeConfig {
            num_workers,
            job_capacity,
            job_timeout: Duration::from_secs(5),
        }));
        let state = Arc::new(MidnightGatewayState {
            runtime: Arc::clone(&runtime),
            compactc,
            attestor,
        });
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            System::new().block_on(async move {
                let (srv, port) =
                    bind_midnight_gateway_http_server(0, state).expect("start gateway server");
                tx.send((srv.handle(), port)).expect("send gateway handle");
                srv.await.expect("gateway server");
            });
        });
        let (handle, port) = rx.recv().expect("receive gateway handle");
        GatewayTestServer {
            handle,
            port,
            runtime,
            version_path,
            attestor_info,
            _workspace: workspace,
        }
    }

    async fn stop_gateway_server(server: GatewayTestServer) {
        server.handle.stop(false).await;
    }

    fn passing_gateway_source() -> &'static str {
        r#"
pragma language_version >= 0.21.0;

import CompactStandardLibrary;

ledger counter: Uint<64>;

constructor() {
  counter = 0;
}

export circuit set(value: Uint<64>): [] {
  counter = disclose(value);
}
"#
    }

    fn failing_gateway_source() -> &'static str {
        r#"
pragma language_version >= 0.21.0;

import CompactStandardLibrary;

export circuit publish_sum(a: Uint<64>, b: Uint<64>): [] {
  disclose(a + b);
}
"#
    }

    fn start_server(engine: MidnightProofServerEngine, warm_params: bool) -> TestServer {
        start_server_with_capacity(
            engine,
            warm_params,
            DEFAULT_JOB_CAPACITY,
            DEFAULT_NUM_WORKERS,
        )
    }

    fn start_server_with_capacity(
        engine: MidnightProofServerEngine,
        warm_params: bool,
        job_capacity: usize,
        num_workers: usize,
    ) -> TestServer {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            System::new().block_on(async move {
                if warm_params {
                    ensure_midnight_params_ready()
                        .await
                        .expect("warm Midnight params");
                }
                let (state, runtime) =
                    MidnightProofServerState::new(engine, job_capacity, num_workers, 600.0);
                let (srv, port) =
                    bind_midnight_http_server(0, false, state).expect("start proof server");
                tx.send((srv.handle(), port, runtime))
                    .expect("send server handle");
                srv.await.expect("proof server");
            });
        });

        let (handle, port, umpg_runtime) = rx.recv().expect("receive server handle");
        TestServer {
            handle,
            port,
            umpg_runtime,
        }
    }

    async fn stop_server(server: TestServer) {
        server.handle.stop(false).await;
    }

    fn create_zswap_output_proof_preimage() -> ProofPreimageVersioned {
        let mut rng = StdRng::seed_from_u64(0x42);
        let sks = zswap::keys::SecretKeys::from_rng_seed(&mut rng);
        let coin = coin::Info::new(&mut rng, 100, Default::default());

        let output = zswap::Output::<_, InMemoryDB>::new(
            &mut rng,
            &coin,
            None,
            &sks.coin_public_key(),
            Some(sks.enc_public_key()),
        )
        .expect("create zswap output");

        let ppi = (*output.proof).clone();
        ProofPreimageVersioned::V2(std::sync::Arc::new(ppi))
    }

    #[tokio::test]
    async fn health_returns_ok_status() {
        let server = start_server(MidnightProofServerEngine::Umpg, false);

        let response = build_client(REQUEST_TIMEOUT_SECS)
            .get(format!("{}/health", server.base_url()))
            .send()
            .await
            .expect("health request");

        assert_eq!(response.status(), 200);
        let json: serde_json::Value = response.json().await.expect("health json");
        assert_eq!(json["status"], "ok");

        stop_server(server).await;
    }

    #[tokio::test]
    async fn check_rejects_invalid_format() {
        let server = start_server(MidnightProofServerEngine::Umpg, false);

        let response = build_client(REQUEST_TIMEOUT_SECS)
            .post(format!("{}/check", server.base_url()))
            .body(vec![0u8; 64])
            .send()
            .await
            .expect("check request");

        assert_eq!(response.status(), 400);

        stop_server(server).await;
    }

    #[tokio::test]
    async fn prove_rejects_invalid_format() {
        let server = start_server(MidnightProofServerEngine::Umpg, false);

        let response = build_client(REQUEST_TIMEOUT_SECS)
            .post(format!("{}/prove", server.base_url()))
            .body(vec![0u8; 64])
            .send()
            .await
            .expect("prove request");

        assert_eq!(response.status(), 400);

        stop_server(server).await;
    }

    #[tokio::test]
    async fn check_processes_valid_request() {
        let server = start_server(MidnightProofServerEngine::Umpg, true);

        let versioned_ppi = create_zswap_output_proof_preimage();
        let ir: Option<WrappedIr> = None;
        let mut body = Vec::new();
        tagged_serialize(&(versioned_ppi, ir), &mut body).expect("serialize check request");

        let response = build_client(LONG_REQUEST_TIMEOUT_SECS)
            .post(format!("{}/check", server.base_url()))
            .body(body)
            .send()
            .await
            .expect("check request");

        assert_eq!(response.status(), 200);

        stop_server(server).await;
    }

    #[tokio::test]
    async fn prove_processes_valid_request() {
        let server = start_server(MidnightProofServerEngine::Umpg, true);

        let versioned_ppi = create_zswap_output_proof_preimage();
        let data: Option<ProvingKeyMaterial> = None;
        let binding_input: Option<transient_crypto::curve::Fr> = None;
        let mut body = Vec::new();
        tagged_serialize(&(versioned_ppi, data, binding_input), &mut body)
            .expect("serialize prove request");

        let response = build_client(LONG_REQUEST_TIMEOUT_SECS)
            .post(format!("{}/prove", server.base_url()))
            .body(body)
            .send()
            .await
            .expect("prove request");

        assert_eq!(response.status(), 200);

        let bytes = response.bytes().await.expect("prove response bytes");
        let _: ProofVersioned = tagged_deserialize(&bytes[..]).expect("deserialize proof");

        stop_server(server).await;
    }

    #[tokio::test]
    async fn prove_route_is_semantically_compatible_between_upstream_and_umpg() {
        let upstream = start_server(MidnightProofServerEngine::Upstream, true);
        let umpg = start_server(MidnightProofServerEngine::Umpg, true);

        let versioned_ppi = create_zswap_output_proof_preimage();
        let data: Option<ProvingKeyMaterial> = None;
        let binding_input: Option<transient_crypto::curve::Fr> = None;
        let mut body = Vec::new();
        tagged_serialize(&(versioned_ppi, data, binding_input), &mut body)
            .expect("serialize prove request");

        let client = build_client(LONG_REQUEST_TIMEOUT_SECS);
        let upstream_response = client
            .post(format!("{}/prove", upstream.base_url()))
            .body(body.clone())
            .send()
            .await
            .expect("upstream prove request");
        let umpg_response = client
            .post(format!("{}/prove", umpg.base_url()))
            .body(body)
            .send()
            .await
            .expect("umpg prove request");

        assert_eq!(upstream_response.status(), 200);
        assert_eq!(umpg_response.status(), 200);
        let upstream_bytes = upstream_response.bytes().await.expect("upstream bytes");
        let umpg_bytes = umpg_response.bytes().await.expect("umpg bytes");
        // Midnight proving remains randomized, so the two valid proofs need not
        // be byte-identical even when they are produced from the same request.
        let upstream_proof: ProofVersioned =
            tagged_deserialize(&upstream_bytes[..]).expect("deserialize upstream proof");
        let umpg_proof: ProofVersioned =
            tagged_deserialize(&umpg_bytes[..]).expect("deserialize umpg proof");
        assert!(matches!(upstream_proof, ProofVersioned::V2(_)));
        assert!(matches!(umpg_proof, ProofVersioned::V2(_)));
        assert_ne!(
            upstream_bytes.len(),
            0,
            "upstream compatibility proof payload should not be empty"
        );
        assert_ne!(
            umpg_bytes.len(),
            0,
            "umpg compatibility proof payload should not be empty"
        );

        stop_server(upstream).await;
        stop_server(umpg).await;
    }

    #[tokio::test]
    async fn check_route_is_byte_equivalent_between_upstream_and_umpg() {
        let upstream = start_server(MidnightProofServerEngine::Upstream, true);
        let umpg = start_server(MidnightProofServerEngine::Umpg, true);

        let versioned_ppi = create_zswap_output_proof_preimage();
        let ir: Option<WrappedIr> = None;
        let mut body = Vec::new();
        tagged_serialize(&(versioned_ppi, ir), &mut body).expect("serialize check request");

        let client = build_client(LONG_REQUEST_TIMEOUT_SECS);
        let upstream_response = client
            .post(format!("{}/check", upstream.base_url()))
            .body(body.clone())
            .send()
            .await
            .expect("upstream check request");
        let umpg_response = client
            .post(format!("{}/check", umpg.base_url()))
            .body(body)
            .send()
            .await
            .expect("umpg check request");

        assert_eq!(upstream_response.status(), 200);
        assert_eq!(umpg_response.status(), 200);
        assert_eq!(
            upstream_response.bytes().await.expect("upstream bytes"),
            umpg_response.bytes().await.expect("umpg bytes")
        );

        stop_server(upstream).await;
        stop_server(umpg).await;
    }

    #[tokio::test]
    async fn umpg_engine_records_runtime_owned_prove_jobs() {
        let server = start_server(MidnightProofServerEngine::Umpg, true);

        let versioned_ppi = create_zswap_output_proof_preimage();
        let data: Option<ProvingKeyMaterial> = None;
        let binding_input: Option<transient_crypto::curve::Fr> = None;
        let mut body = Vec::new();
        tagged_serialize(&(versioned_ppi, data, binding_input), &mut body)
            .expect("serialize prove request");

        let response = build_client(LONG_REQUEST_TIMEOUT_SECS)
            .post(format!("{}/prove", server.base_url()))
            .body(body)
            .send()
            .await
            .expect("prove request");

        assert_eq!(response.status(), 200);
        let runtime = server.umpg_runtime.as_ref().expect("umpg runtime");
        let snapshot = runtime.snapshot();
        assert!(snapshot.total_submitted >= 1);
        assert!(snapshot.completed_midnight_prove >= 1);
        assert_eq!(snapshot.last_completed_kind, Some("midnight-prove"));

        stop_server(server).await;
    }

    #[tokio::test]
    async fn ready_reflects_umpg_queue_state() {
        let server = start_server_with_capacity(MidnightProofServerEngine::Umpg, false, 1, 1);
        let runtime = server.umpg_runtime.as_ref().expect("umpg runtime").clone();

        let handle = runtime
            .submit(CompatibilityJobKind::MidnightCheck, || {
                std::thread::sleep(Duration::from_millis(250));
                Ok(vec![1])
            })
            .expect("submit blocking job");

        tokio::time::sleep(Duration::from_millis(30)).await;

        let response = build_client(REQUEST_TIMEOUT_SECS)
            .get(format!("{}/ready", server.base_url()))
            .send()
            .await
            .expect("ready request");
        let json: serde_json::Value = response.json().await.expect("ready json");
        assert_eq!(json["jobCapacity"], 1);
        assert!(
            json["jobsPending"].as_u64().unwrap_or(0)
                + json["jobsProcessing"].as_u64().unwrap_or(0)
                >= 1
        );

        let _ = handle.wait();
        stop_server(server).await;
    }

    #[test]
    fn gateway_startup_rejects_missing_attestor_key() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let (compactc_path, _) = create_fake_compactc(workspace.path());
        let error = serve_midnight_gateway(
            0,
            1,
            1,
            5.0,
            Some(compactc_path),
            Some(workspace.path().join("missing.mldsa87")),
            true,
        )
        .expect_err("gateway startup should fail without attestor key");
        assert!(
            error.contains("gateway attestor key"),
            "unexpected startup error: {error}"
        );
    }

    #[tokio::test]
    async fn gateway_ready_reports_compactc_and_attestor_identity() {
        let server = start_gateway_server_with_capacity(2, 1);

        let response = build_client(REQUEST_TIMEOUT_SECS)
            .get(format!("{}/ready", server.base_url()))
            .send()
            .await
            .expect("gateway ready request");

        assert_eq!(response.status(), 200);
        let json: serde_json::Value = response.json().await.expect("gateway ready json");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["jobCapacity"], 2);
        assert_eq!(
            json["compactc"]["requiredVersion"],
            MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION
        );
        assert_eq!(
            json["compactc"]["detectedVersion"],
            MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION
        );
        assert_eq!(json["compactc"]["status"], "ok");
        assert_eq!(
            json["attestor"]["publicKeyBase64"],
            server.attestor_info.public_key_base64
        );
        assert_eq!(
            json["attestor"]["publicKeySha256"],
            server.attestor_info.public_key_sha256
        );

        stop_gateway_server(server).await;
    }

    #[tokio::test]
    async fn gateway_ready_reports_busy_with_identity_fields() {
        let server = start_gateway_server_with_capacity(1, 1);
        let runtime = Arc::clone(&server.runtime);

        let handle = runtime
            .submit(CompatibilityJobKind::GatewayVerify, || {
                std::thread::sleep(Duration::from_millis(250));
                Ok(br#"{"verdict":"pass"}"#.to_vec())
            })
            .expect("submit gateway job");

        tokio::time::sleep(Duration::from_millis(30)).await;

        let response = build_client(REQUEST_TIMEOUT_SECS)
            .get(format!("{}/ready", server.base_url()))
            .send()
            .await
            .expect("gateway busy ready request");

        assert_eq!(response.status(), 503);
        let json: serde_json::Value = response.json().await.expect("gateway busy ready json");
        assert_eq!(json["status"], "busy");
        assert_eq!(json["compactc"]["status"], "ok");
        assert_eq!(
            json["attestor"]["publicKeySha256"],
            server.attestor_info.public_key_sha256
        );

        let _ = handle.wait();
        stop_gateway_server(server).await;
    }

    #[tokio::test]
    async fn gateway_ready_reports_runtime_compiler_drift() {
        let server = start_gateway_server_with_capacity(2, 1);
        fs::write(&server.version_path, "0.29.0\n").expect("rewrite compactc version");

        let response = build_client(REQUEST_TIMEOUT_SECS)
            .get(format!("{}/ready", server.base_url()))
            .send()
            .await
            .expect("gateway drift ready request");

        assert_eq!(response.status(), 503);
        let json: serde_json::Value = response.json().await.expect("gateway drift ready json");
        assert_eq!(json["status"], "misconfigured");
        assert_eq!(json["compactc"]["status"], "wrong-version");
        assert_eq!(json["compactc"]["detectedVersion"], "0.29.0");
        assert_eq!(
            json["attestor"]["publicKeySha256"],
            server.attestor_info.public_key_sha256
        );

        stop_gateway_server(server).await;
    }

    #[tokio::test]
    async fn gateway_verify_rejects_missing_circuit_samples() {
        let server = start_gateway_server_with_capacity(2, 1);

        let response = build_client(REQUEST_TIMEOUT_SECS)
            .post(format!("{}/v1/verify-compact", server.base_url()))
            .json(&serde_json::json!({
                "compact_source": passing_gateway_source(),
                "contract_name": "set",
                "samples": {}
            }))
            .send()
            .await
            .expect("gateway verify request");

        assert_eq!(response.status(), 400);

        stop_gateway_server(server).await;
    }

    #[tokio::test]
    async fn gateway_verify_returns_signed_pass_report() {
        let server = start_gateway_server_with_capacity(2, 1);
        let ready: serde_json::Value = build_client(REQUEST_TIMEOUT_SECS)
            .get(format!("{}/ready", server.base_url()))
            .send()
            .await
            .expect("ready request")
            .json()
            .await
            .expect("ready json");

        let response = build_client(LONG_REQUEST_TIMEOUT_SECS)
            .post(format!("{}/v1/verify-compact", server.base_url()))
            .json(&serde_json::json!({
                "compact_source": passing_gateway_source(),
                "contract_name": "set",
                "samples": {
                    "set": [
                        { "value": 7 }
                    ]
                }
            }))
            .send()
            .await
            .expect("gateway pass verify request");

        assert_eq!(response.status(), 200);
        let json: serde_json::Value = response.json().await.expect("pass json");
        assert_eq!(json["verdict"], "pass");
        assert_eq!(json["compactc"]["detectedVersion"], "0.30.0");
        assert_eq!(
            json["attestor"]["publicKeySha256"],
            ready["attestor"]["publicKeySha256"]
        );
        assert_eq!(
            json["attestor"]["publicKeyBase64"],
            ready["attestor"]["publicKeyBase64"]
        );
        assert_eq!(json["circuits"][0]["name"], "set");
        assert_eq!(json["circuits"][0]["verdict"], "pass");
        assert!(
            json["circuits"][0]["sampleChecks"]
                .as_array()
                .is_some_and(|checks| checks.len() >= 2)
        );
        assert!(
            json["signatureBase64"]
                .as_str()
                .is_some_and(|signature| !signature.is_empty())
        );

        stop_gateway_server(server).await;
    }

    #[tokio::test]
    async fn gateway_verify_returns_signed_fail_report_for_underconstrained_contract() {
        let server = start_gateway_server_with_capacity(2, 1);

        let response = build_client(LONG_REQUEST_TIMEOUT_SECS)
            .post(format!("{}/v1/verify-compact", server.base_url()))
            .json(&serde_json::json!({
                "compact_source": failing_gateway_source(),
                "contract_name": "publish_sum",
                "samples": {
                    "publish_sum": [
                        { "a": 1, "b": 2 }
                    ]
                }
            }))
            .send()
            .await
            .expect("gateway fail verify request");

        assert_eq!(response.status(), 200);
        let json: serde_json::Value = response.json().await.expect("fail json");
        assert_eq!(json["verdict"], "fail");
        assert_eq!(json["circuits"][0]["name"], "publish_sum");
        assert_eq!(json["circuits"][0]["verdict"], "fail");
        assert_eq!(json["circuits"][0]["stage"], "audit");
        assert!(json["circuits"][0]["underconstraintAnalysis"].is_object());
        assert!(
            json["circuits"][0]["diagnostics"]
                .as_array()
                .is_some_and(|diagnostics| diagnostics.iter().any(|diag| {
                    diag["code"] == "audit_failure" || diag["stage"] == "audit"
                }))
        );
        assert!(
            json["signatureBase64"]
                .as_str()
                .is_some_and(|signature| !signature.is_empty())
        );

        stop_gateway_server(server).await;
    }

    #[test]
    fn gateway_attestation_signatures_verify_and_poseidon_commitments_are_stable() {
        let workspace = tempfile::tempdir().expect("tempdir");
        let (attestor_key_path, attestor_info) = create_gateway_attestor_fixture(workspace.path());
        let attestor = load_gateway_attestor(Some(&attestor_key_path)).expect("load attestor");
        let timestamp = DateTime::parse_from_rfc3339("2026-03-31T05:33:47Z")
            .expect("timestamp")
            .with_timezone(&Utc);
        let compactc = GatewayCompactcStatus {
            required_version: MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION,
            detected_version: MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION.to_string(),
            status: GatewayCompactcProbeStatus::Ok,
        };
        let pass = build_signed_gateway_attestation(
            "set",
            &sha256_hex(passing_gateway_source().as_bytes()),
            compactc.clone(),
            &attestor,
            timestamp,
            Vec::new(),
            Vec::new(),
        )
        .expect("build pass attestation");
        let fail = build_signed_gateway_attestation(
            "publish_sum",
            &sha256_hex(failing_gateway_source().as_bytes()),
            compactc,
            &attestor,
            timestamp,
            vec![GatewayDiagnostic {
                code: "audit_failure".to_string(),
                stage: "audit".to_string(),
                message: "underconstrained private signals".to_string(),
                circuit: Some("publish_sum".to_string()),
            }],
            Vec::new(),
        )
        .expect("build fail attestation");

        let public_key = base64::engine::general_purpose::STANDARD
            .decode(&attestor_info.public_key_base64)
            .expect("decode public key");
        let pass_signature = base64::engine::general_purpose::STANDARD
            .decode(&pass.signature_base64)
            .expect("decode pass signature");
        let fail_signature = base64::engine::general_purpose::STANDARD
            .decode(&fail.signature_base64)
            .expect("decode fail signature");
        let pass_bytes = serde_json::to_vec(&pass.attestation).expect("serialize pass payload");
        let fail_bytes = serde_json::to_vec(&fail.attestation).expect("serialize fail payload");

        assert!(zkf_core::verify_ml_dsa_signature(
            &public_key,
            &pass_bytes,
            &pass_signature,
            MIDNIGHT_GATEWAY_ATTESTATION_CONTEXT,
        ));
        assert!(zkf_core::verify_ml_dsa_signature(
            &public_key,
            &fail_bytes,
            &fail_signature,
            MIDNIGHT_GATEWAY_ATTESTATION_CONTEXT,
        ));

        let pass_again = build_signed_gateway_attestation(
            "set",
            &sha256_hex(passing_gateway_source().as_bytes()),
            GatewayCompactcStatus {
                required_version: MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION,
                detected_version: MIDNIGHT_GATEWAY_PINNED_COMPACTC_VERSION.to_string(),
                status: GatewayCompactcProbeStatus::Ok,
            },
            &attestor,
            timestamp,
            Vec::new(),
            Vec::new(),
        )
        .expect("rebuild pass attestation");
        assert_eq!(
            pass.attestation.poseidon_commitment,
            pass_again.attestation.poseidon_commitment
        );
        assert_eq!(pass.attestation.report_sha256, pass_again.attestation.report_sha256);
        assert_ne!(pass.signature_base64, pass_again.signature_base64);
    }
}
