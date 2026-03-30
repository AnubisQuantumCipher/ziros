use actix_web::rt::System;
use base_crypto::data_provider::{FetchMode, MidnightDataProvider, OutputMode};
use futures::future::{join, join_all};
use ledger::dust::DustResolver;
use ledger::prove::Resolver;
use midnight_proof_server::endpoints::PUBLIC_PARAMS;
use midnight_proof_server::server;
use midnight_proof_server::worker_pool::WorkerPool;
use serde::Serialize;
use transient_crypto::proofs::{KeyLocation, Resolver as ResolverT};

use crate::cli::{MidnightCommands, MidnightProofServerCommands};

const DEFAULT_KEY_LOCATIONS: [&str; 4] = [
    "midnight/zswap/spend",
    "midnight/zswap/output",
    "midnight/zswap/sign",
    "midnight/dust/spend",
];

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
}

pub(crate) fn handle_midnight(command: MidnightCommands) -> Result<(), String> {
    match command {
        MidnightCommands::ProofServer { command } => match command {
            MidnightProofServerCommands::Serve {
                port,
                job_capacity,
                num_workers,
                job_timeout,
                no_fetch_params,
                json,
            } => serve_midnight_proof_server(
                port,
                job_capacity,
                num_workers,
                job_timeout,
                no_fetch_params,
                json,
            ),
        },
    }
}

fn serve_midnight_proof_server(
    port: u16,
    job_capacity: usize,
    num_workers: usize,
    job_timeout: f64,
    no_fetch_params: bool,
    json: bool,
) -> Result<(), String> {
    System::new().block_on(async move {
        if !no_fetch_params {
            ensure_midnight_params_ready().await?;
        }

        let pool = WorkerPool::new(num_workers, job_capacity, job_timeout);
        let (srv, bound_port) = server(port, !no_fetch_params, pool)
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
        };

        if json {
            println!(
                "{}",
                serde_json::to_string_pretty(&started).map_err(|error| error.to_string())?
            );
        } else {
            println!(
                "Midnight proof server listening on {} (/prove, /check, /health)",
                started.base_url
            );
        }

        srv.await
            .map_err(|error| format!("Midnight proof server exited with error: {error}"))
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::{dev::ServerHandle, rt};
    use coin_structure::coin;
    use ledger::structure::{ProofPreimageVersioned, ProofVersioned};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use reqwest::Client;
    use serialize::{tagged_deserialize, tagged_serialize};
    use std::sync::{LazyLock, OnceLock};
    use std::time::Duration;
    use storage::db::InMemoryDB;
    use transient_crypto::proofs::{ProvingKeyMaterial, WrappedIr};

    const DEFAULT_JOB_CAPACITY: usize = 2;
    const DEFAULT_NUM_WORKERS: usize = 2;
    const REQUEST_TIMEOUT_SECS: u64 = 5;
    const LONG_REQUEST_TIMEOUT_SECS: u64 = 30;

    static LOGGER_INIT: OnceLock<()> = OnceLock::new();
    static HTTP_CLIENT: LazyLock<Client> = LazyLock::new(|| build_client(REQUEST_TIMEOUT_SECS));

    struct TestServer {
        handle: ServerHandle,
        port: u16,
    }

    impl TestServer {
        fn base_url(&self) -> String {
            format!("http://127.0.0.1:{}", self.port)
        }
    }

    fn init_logger() {
        LOGGER_INIT.get_or_init(|| {
            let _ = ();
        });
    }

    fn build_client(timeout_secs: u64) -> Client {
        Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .expect("reqwest client")
    }

    fn start_server(warm_params: bool) -> TestServer {
        init_logger();

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            rt::System::new().block_on(async move {
                if warm_params {
                    ensure_midnight_params_ready()
                        .await
                        .expect("warm Midnight params");
                }
                let pool = WorkerPool::new(DEFAULT_NUM_WORKERS, DEFAULT_JOB_CAPACITY, 600.0);
                let (srv, port) = server(0, false, pool).expect("start proof server");
                tx.send((srv.handle(), port)).expect("send server handle");
                srv.await.expect("proof server");
            });
        });

        let (handle, port) = rx.recv().expect("receive server handle");
        TestServer { handle, port }
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
        let server = start_server(false);

        let response = HTTP_CLIENT
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
        let server = start_server(false);

        let response = HTTP_CLIENT
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
        let server = start_server(false);

        let response = HTTP_CLIENT
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
        let server = start_server(true);

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
        let server = start_server(true);

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
}
