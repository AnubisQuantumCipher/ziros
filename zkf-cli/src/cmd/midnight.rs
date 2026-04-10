use actix_cors::Cors;
use actix_web::error::{
    ErrorBadRequest, ErrorInternalServerError, ErrorServiceUnavailable, ErrorTooManyRequests,
};
use actix_web::http::StatusCode;
use actix_web::rt::System;
use actix_web::web::{self, Bytes, BytesMut, Data, Payload};
use actix_web::{App, Error, HttpResponse, HttpResponseBuilder, HttpServer, Responder};
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
use midnight_proof_server::endpoints::PUBLIC_PARAMS;
use midnight_proof_server::worker_pool::{JobStatus, WorkError, WorkerPool};
use rand::rngs::OsRng;
use serde::Serialize;
use serialize::{tagged_deserialize, tagged_serialize};
use std::collections::HashMap;
use std::sync::Arc;
use storage::db::InMemoryDB;
use transient_crypto::commitment::PedersenRandomness;
use transient_crypto::curve::Fr;
use transient_crypto::proofs::{
    KeyLocation, ProvingKeyMaterial, Resolver as ResolverT, WrappedIr, Zkir,
};
use zkf_runtime::{
    CompatibilityJobHandle, CompatibilityJobKind, CompatibilityRuntime, CompatibilityRuntimeConfig,
    CompatibilityRuntimeError,
};
use zkir as zkir_v2;

mod disclosure;
mod doctor;
mod gateway;
mod init;
mod resolve;
pub(crate) mod shared;
mod templates;

use crate::cli::{
    MidnightCommands, MidnightContractCommands, MidnightGatewayCommands,
    MidnightProofServerCommands,
};
use zkf_command_surface::midnight as surface_midnight;
use zkf_command_surface::{CommandEventKindV1, CommandEventV1, JsonlEventSink, new_operation_id};

const DEFAULT_KEY_LOCATIONS: [&str; 4] = [
    "midnight/zswap/spend",
    "midnight/zswap/output",
    "midnight/zswap/sign",
    "midnight/dust/spend",
];
pub(crate) const MIDNIGHT_PROOF_SERVER_COMPAT_VERSION: &str = "8.0.3";

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

pub(crate) fn handle_midnight(command: MidnightCommands) -> Result<(), String> {
    match command {
        MidnightCommands::Status {
            json,
            project,
            network,
            proof_server_url,
            gateway_url,
            events_jsonl,
        } => handle_midnight_status(
            json,
            project,
            network,
            proof_server_url,
            gateway_url,
            events_jsonl,
        ),
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
            MidnightGatewayCommands::Serve { port, json } => gateway::handle_serve(port, json),
        },
        MidnightCommands::Templates { json } => templates::handle_templates(json),
        MidnightCommands::Init {
            name,
            template,
            out,
            network,
        } => init::handle_init(name, template, out, network),
        MidnightCommands::Doctor {
            json,
            strict,
            project,
            network,
            proof_server_url,
            gateway_url,
            browser_check,
            no_browser_check,
            require_wallet,
        } => doctor::handle_doctor(doctor::DoctorArgs {
            json,
            strict,
            project,
            network,
            proof_server_url,
            gateway_url,
            browser_check,
            no_browser_check,
            require_wallet,
        }),
        MidnightCommands::Disclosure { program, json } => {
            disclosure::handle_disclosure(program, json)
        }
        MidnightCommands::Resolve {
            network,
            project,
            dry_run,
            skip_install,
            skip_compile,
            skip_test,
            json,
            verbose,
        } => resolve::handle_resolve(resolve::ResolveArgs {
            network,
            project,
            dry_run,
            skip_install,
            skip_compile,
            skip_test,
            json,
            verbose,
        }),
        MidnightCommands::Contract { command } => handle_midnight_contract(command),
    }
}

fn handle_midnight_status(
    json_output: bool,
    project: Option<std::path::PathBuf>,
    network: String,
    proof_server_url: Option<String>,
    gateway_url: Option<String>,
    events_jsonl: Option<std::path::PathBuf>,
) -> Result<(), String> {
    let action_id = new_operation_id("midnight-status");
    let mut sink = JsonlEventSink::open(events_jsonl)?;
    emit_surface_event(
        &mut sink,
        CommandEventKindV1::Started,
        &action_id,
        "midnight status started",
    )?;
    let network = surface_midnight::MidnightNetworkV1::parse(&network)?;
    let report = surface_midnight::status(
        network,
        project.as_deref(),
        proof_server_url.as_deref(),
        gateway_url.as_deref(),
    )?;
    print_surface_output(json_output, &report)?;
    emit_surface_event(
        &mut sink,
        CommandEventKindV1::Completed,
        &action_id,
        "midnight status completed",
    )
}

fn handle_midnight_contract(command: MidnightContractCommands) -> Result<(), String> {
    match command {
        MidnightContractCommands::Compile {
            source,
            out,
            network,
            json,
            events_jsonl,
        } => {
            let action_id = new_operation_id("midnight-contract-compile");
            let mut sink = JsonlEventSink::open(events_jsonl)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Started,
                &action_id,
                "midnight contract compile started",
            )?;
            let network = surface_midnight::MidnightNetworkV1::parse(&network)?;
            let report = surface_midnight::compile_contract(network, &source, &out)?;
            print_surface_output(json, &report)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Completed,
                &action_id,
                "midnight contract compile completed",
            )
        }
        MidnightContractCommands::DeployPrepare {
            source,
            out,
            project,
            network,
            proof_server_url,
            gateway_url,
            json,
            events_jsonl,
        } => {
            let action_id = new_operation_id("midnight-deploy-prepare");
            let mut sink = JsonlEventSink::open(events_jsonl)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Started,
                &action_id,
                "midnight deploy-prepare started",
            )?;
            let network = surface_midnight::MidnightNetworkV1::parse(&network)?;
            let report = surface_midnight::deploy_prepare(
                network,
                &source,
                &out,
                proof_server_url.as_deref(),
                gateway_url.as_deref(),
                project.as_deref(),
            )?;
            print_surface_output(json, &report)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Completed,
                &action_id,
                "midnight deploy-prepare completed",
            )
        }
        MidnightContractCommands::CallPrepare {
            source,
            call,
            inputs,
            out,
            project,
            network,
            proof_server_url,
            gateway_url,
            json,
            events_jsonl,
        } => {
            let action_id = new_operation_id("midnight-call-prepare");
            let mut sink = JsonlEventSink::open(events_jsonl)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Started,
                &action_id,
                "midnight call-prepare started",
            )?;
            let network = surface_midnight::MidnightNetworkV1::parse(&network)?;
            let report = surface_midnight::call_prepare(
                network,
                &source,
                &call,
                &inputs,
                &out,
                proof_server_url.as_deref(),
                gateway_url.as_deref(),
                project.as_deref(),
            )?;
            print_surface_output(json, &report)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Completed,
                &action_id,
                "midnight call-prepare completed",
            )
        }
        MidnightContractCommands::Test {
            project,
            network,
            proof_server_url,
            gateway_url,
            json,
            events_jsonl,
        } => {
            let action_id = new_operation_id("midnight-contract-test");
            let mut sink = JsonlEventSink::open(events_jsonl)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Started,
                &action_id,
                "midnight contract test started",
            )?;
            let report = surface_midnight::test_contract(
                &project,
                surface_midnight::MidnightNetworkV1::parse(&network)?,
                proof_server_url.as_deref(),
                gateway_url.as_deref(),
            )?;
            let ok = report.ok;
            print_surface_output(json, &report)?;
            emit_surface_event(
                &mut sink,
                if ok {
                    CommandEventKindV1::Completed
                } else {
                    CommandEventKindV1::Failed
                },
                &action_id,
                if ok {
                    "midnight contract test completed"
                } else {
                    "midnight contract test failed"
                },
            )?;
            if ok {
                Ok(())
            } else {
                Err(format!("midnight contract test failed: {}", report.stderr))
            }
        }
        MidnightContractCommands::Deploy {
            project,
            json,
            events_jsonl,
        } => {
            let action_id = new_operation_id("midnight-contract-deploy");
            let mut sink = JsonlEventSink::open(events_jsonl)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Started,
                &action_id,
                "midnight contract deploy started",
            )?;
            let report = surface_midnight::deploy_contract(&project)?;
            let ok = report.ok;
            print_surface_output(json, &report)?;
            emit_surface_event(
                &mut sink,
                if ok {
                    CommandEventKindV1::Completed
                } else {
                    CommandEventKindV1::Failed
                },
                &action_id,
                if ok {
                    "midnight contract deploy completed"
                } else {
                    "midnight contract deploy failed"
                },
            )?;
            if ok {
                Ok(())
            } else {
                Err(format!(
                    "midnight contract deploy failed: {}",
                    report.stderr
                ))
            }
        }
        MidnightContractCommands::Call {
            project,
            json,
            events_jsonl,
        } => {
            let action_id = new_operation_id("midnight-contract-call");
            let mut sink = JsonlEventSink::open(events_jsonl)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Started,
                &action_id,
                "midnight contract call started",
            )?;
            let report = surface_midnight::call_contract(&project)?;
            let ok = report.ok;
            print_surface_output(json, &report)?;
            emit_surface_event(
                &mut sink,
                if ok {
                    CommandEventKindV1::Completed
                } else {
                    CommandEventKindV1::Failed
                },
                &action_id,
                if ok {
                    "midnight contract call completed"
                } else {
                    "midnight contract call failed"
                },
            )?;
            if ok {
                Ok(())
            } else {
                Err(format!("midnight contract call failed: {}", report.stderr))
            }
        }
        MidnightContractCommands::VerifyExplorer {
            project,
            json,
            events_jsonl,
        } => {
            let action_id = new_operation_id("midnight-contract-verify-explorer");
            let mut sink = JsonlEventSink::open(events_jsonl)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Started,
                &action_id,
                "midnight contract verify-explorer started",
            )?;
            let report = surface_midnight::verify_explorer(&project)?;
            print_surface_output(json, &report)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Completed,
                &action_id,
                "midnight contract verify-explorer completed",
            )
        }
        MidnightContractCommands::Diagnose {
            project,
            network,
            proof_server_url,
            gateway_url,
            json,
            events_jsonl,
        } => {
            let action_id = new_operation_id("midnight-contract-diagnose");
            let mut sink = JsonlEventSink::open(events_jsonl)?;
            emit_surface_event(
                &mut sink,
                CommandEventKindV1::Started,
                &action_id,
                "midnight contract diagnose started",
            )?;
            let report = surface_midnight::diagnose_contract(
                &project,
                surface_midnight::MidnightNetworkV1::parse(&network)?,
                proof_server_url.as_deref(),
                gateway_url.as_deref(),
            )?;
            let ready = report.ready;
            print_surface_output(json, &report)?;
            emit_surface_event(
                &mut sink,
                if ready {
                    CommandEventKindV1::Completed
                } else {
                    CommandEventKindV1::Failed
                },
                &action_id,
                if ready {
                    "midnight contract diagnose completed"
                } else {
                    "midnight contract diagnose found blockers"
                },
            )?;
            if ready {
                Ok(())
            } else {
                Err(format!(
                    "midnight contract diagnose blocked: {}",
                    report.blockers.join("; ")
                ))
            }
        }
    }
}

fn emit_surface_event(
    sink: &mut Option<JsonlEventSink>,
    kind: CommandEventKindV1,
    action_id: &str,
    message: &str,
) -> Result<(), String> {
    if let Some(sink) = sink.as_mut() {
        sink.emit(&CommandEventV1::new(action_id, kind, message))?;
    }
    Ok(())
}

fn print_surface_output<T: serde::Serialize>(json_output: bool, value: &T) -> Result<(), String> {
    let body = serde_json::to_string_pretty(value).map_err(|error| error.to_string())?;
    if json_output {
        println!("{body}");
    } else {
        println!("{body}");
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::dev::ServerHandle;
    use coin_structure::coin;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use reqwest::Client;
    use std::sync::mpsc;
    use std::time::Duration;

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

    fn build_client(timeout_secs: u64) -> Client {
        Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("reqwest client")
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
}
