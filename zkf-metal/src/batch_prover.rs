//! GPU-aware batch proof orchestration.
//!
//! This module batches independent proof jobs behind a single scheduler so the
//! caller can execute real proving work with host/device-aware concurrency
//! rather than receiving synthetic preview bytes.

use crate::device::{self, MetalContext};
use crate::tuning::throughput_for_device;
use serde::Serialize;
use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Instant;
use zkf_core::ProofArtifact;

type ProofExecutor = Box<dyn FnOnce() -> Result<ProofArtifact, String> + Send + 'static>;

/// Scheduler recommendation for GPU-aware batch workloads.
#[derive(Debug, Clone, Serialize)]
pub struct GpuSchedulerHint {
    pub metal_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub requested_jobs: usize,
    pub total_jobs: usize,
    pub recommended_jobs: usize,
    pub estimated_job_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_budget_bytes: Option<usize>,
    pub reason: String,
}

impl GpuSchedulerHint {
    pub fn cpu_fallback(
        total_jobs: usize,
        requested_jobs: usize,
        reason: impl Into<String>,
    ) -> Self {
        let cpu_cap = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1);
        let recommended_jobs = requested_jobs.min(total_jobs).min(cpu_cap).max(1);
        Self {
            metal_available: false,
            device_name: None,
            requested_jobs,
            total_jobs,
            recommended_jobs,
            estimated_job_bytes: 0,
            memory_budget_bytes: None,
            reason: reason.into(),
        }
    }
}

/// Status of a proof job in the batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

struct JobCompletion {
    id: usize,
    elapsed_ms: u128,
    result: Result<ProofArtifact, String>,
}

/// A single proof job with its executor and current result.
pub struct ProofJob {
    /// Opaque identifier for this job.
    pub id: usize,
    /// Current status.
    pub status: JobStatus,
    /// Optional human-readable label.
    pub label: Option<String>,
    /// Caller-provided size estimate used for scheduling and diagnostics.
    pub estimated_job_bytes: usize,
    /// Result artifact after successful completion.
    pub proof: Option<ProofArtifact>,
    /// Failure message when the job fails.
    pub error: Option<String>,
    executor: Option<ProofExecutor>,
}

/// Batch prover that runs real proof jobs with GPU-aware concurrency.
///
/// Each job supplies an executor closure that performs the actual proving work
/// and returns a real [`ProofArtifact`]. The batch prover adds lightweight
/// metadata such as elapsed time and device name, but it never fabricates proof
/// bytes.
pub struct BatchProver {
    ctx: &'static MetalContext,
    jobs: Vec<ProofJob>,
    max_concurrent: usize,
}

impl BatchProver {
    /// Create a new batch prover.
    ///
    /// `max_concurrent`: maximum number of proof jobs to run at once. Passing
    /// `0` uses the device tuning profile.
    pub fn new(max_concurrent: usize) -> Option<Self> {
        let ctx = device::global_context()?;
        let tuning = throughput_for_device(&ctx.device_name());
        Some(Self {
            ctx,
            jobs: Vec::new(),
            max_concurrent: if max_concurrent == 0 {
                tuning.batch_profile_cap.max(1)
            } else {
                max_concurrent.max(1)
            },
        })
    }

    /// Add a proof job that returns a real [`ProofArtifact`] or a concrete error.
    pub fn add_job<F>(&mut self, estimated_job_bytes: usize, executor: F) -> usize
    where
        F: FnOnce() -> Result<ProofArtifact, String> + Send + 'static,
    {
        self.add_named_job(None, estimated_job_bytes, executor)
    }

    /// Add a labeled proof job.
    pub fn add_named_job<F>(
        &mut self,
        label: Option<String>,
        estimated_job_bytes: usize,
        executor: F,
    ) -> usize
    where
        F: FnOnce() -> Result<ProofArtifact, String> + Send + 'static,
    {
        let id = self.jobs.len();
        self.jobs.push(ProofJob {
            id,
            status: JobStatus::Pending,
            label,
            estimated_job_bytes,
            proof: None,
            error: None,
            executor: Some(Box::new(executor)),
        });
        id
    }

    /// Get the number of jobs in the batch.
    pub fn job_count(&self) -> usize {
        self.jobs.len()
    }

    /// Get the status of a specific job.
    pub fn job_status(&self, id: usize) -> Option<JobStatus> {
        self.jobs.get(id).map(|job| job.status)
    }

    /// Get the error for a failed job, if any.
    pub fn job_error(&self, id: usize) -> Option<&str> {
        self.jobs.get(id).and_then(|job| job.error.as_deref())
    }

    /// Run all pending jobs and return the number of proofs that completed.
    pub fn prove_all(&mut self) -> usize {
        let mut queued = VecDeque::new();
        for job in &mut self.jobs {
            if job.status != JobStatus::Pending {
                continue;
            }
            let Some(executor) = job.executor.take() else {
                job.status = JobStatus::Failed;
                job.error = Some("proof job executor was missing".to_string());
                continue;
            };
            job.status = JobStatus::Running;
            queued.push_back((job.id, executor));
        }

        if queued.is_empty() {
            return 0;
        }

        let worker_count = self.max_concurrent.min(queued.len()).max(1);
        let queue = Arc::new(Mutex::new(queued));
        let (tx, rx) = mpsc::channel::<JobCompletion>();
        let device_name = self.ctx.device_name();

        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let tx = tx.clone();
            let device_name = device_name.clone();
            handles.push(std::thread::spawn(move || {
                loop {
                    let next = match queue.lock() {
                        Ok(mut guard) => guard.pop_front(),
                        Err(_) => None,
                    };
                    let Some((id, executor)) = next else {
                        break;
                    };

                    let started = Instant::now();
                    let result = match catch_unwind(AssertUnwindSafe(executor)) {
                        Ok(result) => result,
                        Err(_) => Err("proof job panicked".to_string()),
                    }
                    .map(|mut artifact| {
                        artifact
                            .metadata
                            .insert("batch_job_id".to_string(), id.to_string());
                        artifact.metadata.insert(
                            "batch_elapsed_ms".to_string(),
                            started.elapsed().as_millis().to_string(),
                        );
                        artifact
                            .metadata
                            .insert("batch_device".to_string(), device_name.clone());
                        artifact
                    });

                    let _ = tx.send(JobCompletion {
                        id,
                        elapsed_ms: started.elapsed().as_millis(),
                        result,
                    });
                }
            }));
        }
        drop(tx);

        let mut completed = 0usize;
        for completion in rx {
            if let Some(job) = self.jobs.get_mut(completion.id) {
                match completion.result {
                    Ok(mut proof) => {
                        proof.metadata.insert(
                            "batch_scheduler_elapsed_ms".to_string(),
                            completion.elapsed_ms.to_string(),
                        );
                        job.status = JobStatus::Completed;
                        job.error = None;
                        job.proof = Some(proof);
                        completed += 1;
                    }
                    Err(err) => {
                        job.status = JobStatus::Failed;
                        job.error = Some(err);
                        job.proof = None;
                    }
                }
            }
        }

        for handle in handles {
            if handle.join().is_err() {
                for job in &mut self.jobs {
                    if job.status == JobStatus::Running {
                        job.status = JobStatus::Failed;
                        job.error = Some("batch prover worker panicked".to_string());
                        job.proof = None;
                    }
                }
            }
        }

        completed
    }

    /// Get all completed proof results.
    pub fn results(&self) -> Vec<(usize, &ProofArtifact)> {
        self.jobs
            .iter()
            .filter(|job| job.status == JobStatus::Completed)
            .filter_map(|job| job.proof.as_ref().map(|proof| (job.id, proof)))
            .collect()
    }
}

/// Recommend a GPU-aware worker count for proof batches.
pub fn recommend_job_count(
    total_jobs: usize,
    requested_jobs: Option<usize>,
    estimated_job_bytes: usize,
) -> GpuSchedulerHint {
    if total_jobs == 0 {
        return GpuSchedulerHint {
            metal_available: device::global_context().is_some(),
            device_name: device::global_context().map(|ctx| ctx.device_name()),
            requested_jobs: requested_jobs.unwrap_or(0),
            total_jobs,
            recommended_jobs: 0,
            estimated_job_bytes,
            memory_budget_bytes: device::global_context()
                .and_then(|ctx| ctx.recommended_working_set_size()),
            reason: "no jobs requested".to_string(),
        };
    }

    let requested_jobs = requested_jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .max(1)
    });

    let Some(ctx) = device::global_context() else {
        return GpuSchedulerHint::cpu_fallback(
            total_jobs,
            requested_jobs,
            "Metal unavailable; using CPU worker cap",
        );
    };

    let memory_budget = ctx.recommended_working_set_size();
    let headroom_budget = ctx.working_set_headroom().or(memory_budget);
    let device_name = ctx.device_name();
    let tuning = throughput_for_device(&device_name);
    let profile_cap = tuning.batch_profile_cap.max(1);

    let memory_jobs = headroom_budget
        .map(|budget| {
            let usable_budget =
                budget.saturating_mul(tuning.working_set_headroom_target_pct as usize) / 100;
            if estimated_job_bytes == 0 {
                profile_cap
            } else {
                (usable_budget / estimated_job_bytes.max(1)).max(1)
            }
        })
        .unwrap_or(profile_cap);

    let recommended_jobs = requested_jobs
        .min(total_jobs)
        .min(memory_jobs.max(1))
        .min(profile_cap)
        .max(1);

    let reason = match headroom_budget {
        Some(budget) if estimated_job_bytes > 0 => format!(
            "Metal available on {device_name}; capped to {recommended_jobs} jobs by ~{}% of working-set headroom {} bytes",
            tuning.working_set_headroom_target_pct, budget
        ),
        Some(budget) => format!(
            "Metal available on {device_name}; no job-size estimate provided, capped to device profile using working-set headroom {} bytes",
            budget
        ),
        None => format!(
            "Metal available on {device_name}; working-set budget unavailable, using device profile cap"
        ),
    };

    GpuSchedulerHint {
        metal_available: true,
        device_name: Some(device_name),
        requested_jobs,
        total_jobs,
        recommended_jobs,
        estimated_job_bytes,
        memory_budget_bytes: headroom_budget,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{BackendKind, FieldElement};

    fn sample_artifact(id: usize) -> ProofArtifact {
        ProofArtifact {
            backend: BackendKind::Plonky3,
            program_digest: format!("program-{id}"),
            proof: vec![id as u8, 0xaa],
            verification_key: vec![0xbb],
            public_inputs: vec![FieldElement::from_i64(id as i64)],
            metadata: Default::default(),
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
        }
    }

    #[test]
    fn batch_prover_runs_real_proof_jobs() {
        let mut prover = match BatchProver::new(4) {
            Some(prover) => prover,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        for id in 0..4 {
            let artifact = sample_artifact(id);
            prover.add_named_job(Some(format!("job-{id}")), 128 << 20, move || Ok(artifact));
        }

        assert_eq!(prover.job_count(), 4);
        let completed = prover.prove_all();
        assert_eq!(completed, 4);

        let results = prover.results();
        assert_eq!(results.len(), 4);
        assert!(
            results
                .iter()
                .all(|(_, artifact)| !artifact.proof.is_empty())
        );
        assert!(
            results
                .iter()
                .all(|(_, artifact)| artifact.metadata.contains_key("batch_job_id"))
        );
    }

    #[test]
    fn batch_prover_surfaces_job_failures() {
        let mut prover = match BatchProver::new(2) {
            Some(prover) => prover,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        prover.add_named_job(Some("ok".to_string()), 0, move || Ok(sample_artifact(1)));
        prover.add_named_job(Some("boom".to_string()), 0, move || {
            Err("prove failed".to_string())
        });

        let completed = prover.prove_all();
        assert_eq!(completed, 1);
        assert_eq!(prover.job_status(0), Some(JobStatus::Completed));
        assert_eq!(prover.job_status(1), Some(JobStatus::Failed));
        assert_eq!(prover.job_error(1), Some("prove failed"));
    }

    #[test]
    fn scheduler_hint_clamps_to_total_jobs() {
        let hint = recommend_job_count(2, Some(16), 128 << 20);
        assert!(hint.recommended_jobs <= 2);
    }

    #[test]
    fn m4_max_scheduler_prefers_higher_parallelism() {
        let cfg = throughput_for_device("Apple M4 Max");
        assert_eq!(cfg.batch_profile_cap, 16);
        assert_eq!(cfg.working_set_headroom_target_pct, 85);
    }
}
