//! ZKF API — proving-as-a-service REST server.
//!
//! Axum-based API with authentication, job queuing, and metering for hosted
//! proof generation, wrapping, and Solidity verifier deployment.
mod auth;
mod db;
mod handlers;
mod jobs;
mod metering;
mod solidity;
mod types;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::HeaderValue,
    middleware,
    routing::{get, post},
};
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

/// Maximum request body size (16 MiB). Prevents oversized payloads from
/// exhausting memory. Override with `ZKF_API_MAX_BODY_BYTES`.
const DEFAULT_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub struct AppState {
    db: Arc<db::Database>,
    job_queue: Arc<jobs::JobQueue>,
    rate_limiter: Arc<metering::RateLimiter>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let deployment_mode = db::DeploymentMode::parse(
        &std::env::var("ZKF_API_MODE").unwrap_or_else(|_| "development".to_string()),
    )
    .map_err(std::io::Error::other)?;
    let db_locator = std::env::var("ZKF_API_DATABASE_URL")
        .or_else(|_| std::env::var("ZKF_API_DB"))
        .unwrap_or_else(|_| "zkf-api.db".to_string());
    let db =
        Arc::new(db::Database::open(&db_locator, deployment_mode).map_err(std::io::Error::other)?);
    let job_queue = Arc::new(jobs::JobQueue::new(db.clone()).await);

    let state = AppState {
        db: db.clone(),
        job_queue: job_queue.clone(),
        rate_limiter: Arc::new(metering::RateLimiter::new()),
    };

    let app = Router::new()
        .route("/v1/prove", post(handlers::prove))
        .route("/v1/credentials/prove", post(handlers::credential_prove))
        .route("/v1/credentials/verify", post(handlers::credential_verify))
        .route("/v1/wrap", post(handlers::wrap))
        .route("/v1/deploy", post(handlers::deploy))
        .route("/v1/benchmark", post(handlers::benchmark))
        .route("/v1/status/{id}", get(handlers::status))
        .route("/v1/jobs/{id}", get(handlers::status))
        .route("/v1/capabilities", get(handlers::capabilities))
        .route("/v1/keys", post(handlers::create_key))
        .route("/credentials/prove", post(handlers::credential_prove))
        .route("/credentials/verify", post(handlers::credential_verify))
        .route("/health", get(handlers::health))
        .layer(TraceLayer::new_for_http())
        .layer(cors_layer())
        .layer(DefaultBodyLimit::max(
            std::env::var("ZKF_API_MAX_BODY_BYTES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_MAX_BODY_BYTES),
        ))
        .layer(middleware::from_fn(handlers::observe_api_entrypoint))
        .with_state(state);

    let bind = std::env::var("ZKF_API_BIND").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;

    tracing::info!(
        "zkf-api listening on {bind} (mode={}, database_driver={})",
        db.deployment_mode().as_str(),
        db.driver_name()
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("shutdown signal received, draining job queue");
        })
        .await?;
    job_queue.shutdown().await;
    Ok(())
}

/// Build CORS layer from environment or default to localhost-only.
///
/// Set `ZKF_API_CORS_ORIGINS` to a comma-separated list of allowed origins
/// (e.g., `http://localhost:3001,https://app.example.com`).
/// Set to "*" for permissive mode (development only — NOT recommended for production).
fn cors_layer() -> CorsLayer {
    let origins = std::env::var("ZKF_API_CORS_ORIGINS").unwrap_or_default();
    if origins == "*" {
        tracing::warn!("CORS set to permissive mode — not recommended for production");
        CorsLayer::permissive()
    } else if origins.is_empty() {
        // Default: allow only localhost origins
        CorsLayer::new().allow_origin(AllowOrigin::list([
            HeaderValue::from_static("http://localhost:3000"),
            HeaderValue::from_static("http://localhost:3001"),
            HeaderValue::from_static("http://127.0.0.1:3000"),
            HeaderValue::from_static("http://127.0.0.1:3001"),
        ]))
    } else {
        let allowed: Vec<_> = origins
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        CorsLayer::new().allow_origin(AllowOrigin::list(allowed))
    }
}
