use std::sync::Arc;

use tokio::sync::{Mutex, RwLock, mpsc};
use tokio::task::JoinHandle;

use crate::db::Database;
use crate::handlers;
use crate::metering;
use crate::types::{BenchmarkRequest, ProveRequest, WrapRequest};

const DEFAULT_QUEUE_CAPACITY: usize = 32;
const DEFAULT_WORKER_COUNT: usize = 2;

pub struct JobQueue {
    db: Arc<Database>,
    sender: RwLock<Option<mpsc::Sender<String>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl JobQueue {
    pub async fn new(db: Arc<Database>) -> Self {
        let queue_capacity = std::env::var("ZKF_API_QUEUE_CAPACITY")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_QUEUE_CAPACITY)
            .max(1);
        let worker_count = std::env::var("ZKF_API_WORKERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(DEFAULT_WORKER_COUNT)
            .max(1);

        let (sender, receiver) = mpsc::channel::<String>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));

        let mut workers = Vec::with_capacity(worker_count);
        for worker_idx in 0..worker_count {
            let db = db.clone();
            let receiver = receiver.clone();
            workers.push(tokio::spawn(async move {
                loop {
                    let next_job = {
                        let mut receiver = receiver.lock().await;
                        receiver.recv().await
                    };
                    let Some(job_id) = next_job else {
                        break;
                    };
                    if let Err(err) = process_job(db.clone(), &job_id).await {
                        tracing::error!(
                            "job worker {worker_idx} failed to process {job_id}: {err}"
                        );
                    }
                }
            }));
        }

        let queue = Self {
            db,
            sender: RwLock::new(Some(sender)),
            workers: Mutex::new(workers),
        };
        queue.bootstrap_queued_jobs().await;
        queue
    }

    pub async fn enqueue(
        &self,
        kind: &str,
        owner_key_hash: &str,
        request: &str,
    ) -> Result<String, String> {
        let id = uuid::Uuid::new_v4().to_string();
        self.db.create_job(&id, owner_key_hash, kind, request)?;
        self.dispatch(id.clone()).await?;
        Ok(id)
    }

    pub async fn shutdown(&self) {
        self.sender.write().await.take();
        let mut workers = self.workers.lock().await;
        while let Some(handle) = workers.pop() {
            let _ = handle.await;
        }
    }

    async fn bootstrap_queued_jobs(&self) {
        match self.db.queued_job_ids() {
            Ok(ids) => {
                for id in ids {
                    if let Err(err) = self.dispatch(id.clone()).await {
                        tracing::warn!("failed to requeue persisted job {id}: {err}");
                        break;
                    }
                }
            }
            Err(err) => tracing::warn!("failed to load queued jobs on startup: {err}"),
        }
    }

    async fn dispatch(&self, id: String) -> Result<(), String> {
        let sender = self
            .sender
            .read()
            .await
            .clone()
            .ok_or_else(|| "job queue is shutting down".to_string())?;
        sender
            .send(id)
            .await
            .map_err(|_| "job queue is closed".to_string())
    }
}

async fn process_job(db: Arc<Database>, id: &str) -> Result<(), String> {
    if !db.claim_job(id)? {
        return Ok(());
    }

    let execution = db.get_job_execution(id)?;
    if execution.status != "running" {
        return Ok(());
    }

    let id_string = execution.id.clone();
    let owner_key_hash = execution.owner_key_hash.clone();
    let kind = execution.kind.clone();
    let request_json = execution.request.clone();
    let owner_key_hash_for_execution = owner_key_hash.clone();
    let result = tokio::task::spawn_blocking(move || {
        execute_job_with_api_key(&kind, &request_json, &owner_key_hash_for_execution)
    })
    .await
    .map_err(|err| format!("job worker join error: {err}"))?;

    match result {
        Ok(result) => {
            let _ = metering::record_usage(&db, &owner_key_hash, execution.kind.as_str());
            let result_json = serde_json::to_string(&result)
                .map_err(|err| format!("job result serialization: {err}"))?;
            db.update_job_status(
                id_string.as_str(),
                crate::types::JobStatus::Completed,
                Some(result_json.as_str()),
                None,
            )?;
        }
        Err(error) => {
            db.update_job_status(
                id_string.as_str(),
                crate::types::JobStatus::Failed,
                None,
                Some(error.as_str()),
            )?;
        }
    }

    Ok(())
}

fn execute_job_with_api_key(
    kind: &str,
    request_json: &str,
    owner_key_hash: &str,
) -> Result<serde_json::Value, String> {
    let security_context = handlers::api_security_context(owner_key_hash);
    match kind {
        "prove" => {
            let request: ProveRequest = serde_json::from_str(request_json)
                .map_err(|err| format!("invalid persisted prove request: {err}"))?;
            handlers::run_prove(&request, Some(security_context))
        }
        "wrap" => {
            let request: WrapRequest = serde_json::from_str(request_json)
                .map_err(|err| format!("invalid persisted wrap request: {err}"))?;
            handlers::run_wrap(&request, Some(security_context))
        }
        "benchmark" => {
            let request: BenchmarkRequest = serde_json::from_str(request_json)
                .map_err(|err| format!("invalid persisted benchmark request: {err}"))?;
            handlers::run_benchmark(&request, Some(security_context))
        }
        other => Err(format!("unsupported queued job kind '{other}'")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth;
    use crate::db::{Database, DeploymentMode};
    use serde_json::json;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use zkf_core::{
        Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessPlan,
    };

    const JOB_COMPLETION_TIMEOUT: Duration = Duration::from_secs(120);

    fn temp_sqlite_path(name: &str) -> String {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("zkf-api-{name}-{unique}.sqlite"))
            .display()
            .to_string()
    }

    fn trivial_program() -> Program {
        Program {
            name: "queue_roundtrip".into(),
            field: FieldId::Goldilocks,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal("x".into())),
                    Box::new(Expr::Signal("x".into())),
                ),
                rhs: Expr::Signal("x".into()),
                label: Some("bit".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: Default::default(),
        }
    }

    async fn wait_for_completion(db: &Database, id: &str) -> crate::types::JobStatus {
        let started = tokio::time::Instant::now();
        loop {
            let row = db.get_job(id).expect("job row");
            match row.status.as_str() {
                "completed" => return crate::types::JobStatus::Completed,
                "failed" => return crate::types::JobStatus::Failed,
                _ => {}
            }
            assert!(
                started.elapsed() < JOB_COMPLETION_TIMEOUT,
                "timed out waiting for job {id}"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn queued_prove_job_completes_through_background_worker() {
        let db =
            Arc::new(Database::open(&temp_sqlite_path("prove"), DeploymentMode::Test).expect("db"));
        db.create_api_key("test-key", "developer", None)
            .expect("key");
        let owner_key_hash = auth::hash_api_key("test-key");
        let queue = JobQueue::new(db.clone()).await;

        let request = ProveRequest {
            program: serde_json::to_value(trivial_program()).expect("program"),
            ir_family: None,
            inputs: json!({"x": FieldElement::from_i64(1)}),
            backend: Some("plonky3".into()),
            mode: None,
            hybrid: None,
        };

        let id = queue
            .enqueue(
                "prove",
                &owner_key_hash,
                &serde_json::to_string(&request).expect("request"),
            )
            .await
            .expect("queue prove");

        let status = wait_for_completion(&db, &id).await;
        let row = db.get_job(&id).expect("job row");
        assert_eq!(
            status,
            crate::types::JobStatus::Completed,
            "job failed with error: {:?}",
            row.error
        );
        let payload: serde_json::Value =
            serde_json::from_str(row.result.as_deref().expect("job result")).expect("result json");
        assert!(payload.pointer("/runtime/security_verdict").is_some());
        queue.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn startup_requeues_persisted_jobs() {
        let db = Arc::new(
            Database::open(&temp_sqlite_path("bootstrap"), DeploymentMode::Test).expect("db"),
        );
        db.create_api_key("bootstrap-key", "developer", None)
            .expect("key");
        let owner_key_hash = auth::hash_api_key("bootstrap-key");

        let request = ProveRequest {
            program: serde_json::to_value(trivial_program()).expect("program"),
            ir_family: None,
            inputs: json!({"x": FieldElement::from_i64(1)}),
            backend: Some("plonky3".into()),
            mode: None,
            hybrid: None,
        };
        let request_json = serde_json::to_string(&request).expect("request");
        db.create_job("bootstrap-job", &owner_key_hash, "prove", &request_json)
            .expect("persist queued job");

        let queue = JobQueue::new(db.clone()).await;
        let status = wait_for_completion(&db, "bootstrap-job").await;
        let row = db.get_job("bootstrap-job").expect("job row");
        assert_eq!(
            status,
            crate::types::JobStatus::Completed,
            "job failed with error: {:?}",
            row.error
        );
        queue.shutdown().await;
    }
}
