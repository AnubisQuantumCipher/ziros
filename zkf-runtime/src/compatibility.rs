// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

//! Runtime-owned compatibility jobs for external proof-server surfaces.

use serde::Serialize;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompatibilityJobKind {
    MidnightCheck,
    MidnightProve,
    MidnightProveTx,
}

impl CompatibilityJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MidnightCheck => "midnight-check",
            Self::MidnightProve => "midnight-prove",
            Self::MidnightProveTx => "midnight-prove-tx",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompatibilityRuntimeConfig {
    pub num_workers: usize,
    pub job_capacity: usize,
    pub job_timeout: Duration,
}

#[derive(Debug, Clone, Error)]
pub enum CompatibilityRuntimeError {
    #[error("Job Queue full")]
    JobQueueFull,
    #[error("compatibility runtime closed")]
    RuntimeClosed,
    #[error("bad input")]
    BadInput(String),
    #[error("internal error")]
    Internal(String),
    #[error("compatibility job timed out after {0:.3}s")]
    TimedOut(f64),
}

impl CompatibilityRuntimeError {
    pub fn bad_input(message: impl Into<String>) -> Self {
        Self::BadInput(message.into())
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }
}

struct CompatibilityRuntimeState {
    jobs_pending: usize,
    jobs_processing: usize,
    total_submitted: u64,
    total_completed: u64,
    total_failed: u64,
    total_rejected: u64,
    total_timed_out: u64,
    completed_midnight_check: u64,
    completed_midnight_prove: u64,
    completed_midnight_prove_tx: u64,
    last_completed_kind: Option<CompatibilityJobKind>,
}

impl CompatibilityRuntimeState {
    fn new() -> Self {
        Self {
            jobs_pending: 0,
            jobs_processing: 0,
            total_submitted: 0,
            total_completed: 0,
            total_failed: 0,
            total_rejected: 0,
            total_timed_out: 0,
            completed_midnight_check: 0,
            completed_midnight_prove: 0,
            completed_midnight_prove_tx: 0,
            last_completed_kind: None,
        }
    }

    fn record_completion(&mut self, kind: CompatibilityJobKind) {
        self.total_completed = self.total_completed.saturating_add(1);
        self.last_completed_kind = Some(kind);
        match kind {
            CompatibilityJobKind::MidnightCheck => {
                self.completed_midnight_check = self.completed_midnight_check.saturating_add(1);
            }
            CompatibilityJobKind::MidnightProve => {
                self.completed_midnight_prove = self.completed_midnight_prove.saturating_add(1);
            }
            CompatibilityJobKind::MidnightProveTx => {
                self.completed_midnight_prove_tx =
                    self.completed_midnight_prove_tx.saturating_add(1);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CompatibilityRuntimeSnapshot {
    pub job_capacity: usize,
    pub jobs_pending: usize,
    pub jobs_processing: usize,
    pub total_submitted: u64,
    pub total_completed: u64,
    pub total_failed: u64,
    pub total_rejected: u64,
    pub total_timed_out: u64,
    pub completed_midnight_check: u64,
    pub completed_midnight_prove: u64,
    pub completed_midnight_prove_tx: u64,
    pub last_completed_kind: Option<&'static str>,
}

pub struct CompatibilityJobHandle {
    receiver: Receiver<Result<Vec<u8>, CompatibilityRuntimeError>>,
    timeout: Duration,
    state: Arc<Mutex<CompatibilityRuntimeState>>,
}

impl CompatibilityJobHandle {
    pub fn wait(self) -> Result<Vec<u8>, CompatibilityRuntimeError> {
        match self.receiver.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                state.total_timed_out = state.total_timed_out.saturating_add(1);
                Err(CompatibilityRuntimeError::TimedOut(
                    self.timeout.as_secs_f64(),
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(CompatibilityRuntimeError::RuntimeClosed)
            }
        }
    }
}

struct WorkItem {
    kind: CompatibilityJobKind,
    work: Box<dyn FnOnce() -> Result<Vec<u8>, CompatibilityRuntimeError> + Send + 'static>,
    result_tx: SyncSender<Result<Vec<u8>, CompatibilityRuntimeError>>,
}

pub struct CompatibilityRuntime {
    job_capacity: usize,
    job_timeout: Duration,
    sender: mpsc::Sender<WorkItem>,
    _receiver: Arc<Mutex<mpsc::Receiver<WorkItem>>>,
    state: Arc<Mutex<CompatibilityRuntimeState>>,
    _workers: Vec<thread::JoinHandle<()>>,
}

impl CompatibilityRuntime {
    pub fn new(config: CompatibilityRuntimeConfig) -> Self {
        let num_workers = config.num_workers;
        let (sender, receiver) = mpsc::channel::<WorkItem>();
        let receiver = Arc::new(Mutex::new(receiver));
        let state = Arc::new(Mutex::new(CompatibilityRuntimeState::new()));
        let mut workers = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let receiver = Arc::clone(&receiver);
            let state = Arc::clone(&state);
            workers.push(thread::spawn(move || {
                loop {
                    let work = {
                        let receiver = receiver
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        receiver.recv()
                    };
                    let Ok(work) = work else {
                        break;
                    };

                    {
                        let mut state = state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        state.jobs_pending = state.jobs_pending.saturating_sub(1);
                        state.jobs_processing = state.jobs_processing.saturating_add(1);
                    }

                    let result = (work.work)();

                    {
                        let mut state = state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        state.jobs_processing = state.jobs_processing.saturating_sub(1);
                        match &result {
                            Ok(_) => state.record_completion(work.kind),
                            Err(_) => {
                                state.total_failed = state.total_failed.saturating_add(1);
                            }
                        }
                    }

                    let _ = work.result_tx.send(result);
                }
            }));
        }

        Self {
            job_capacity: config.job_capacity,
            job_timeout: config.job_timeout,
            sender,
            _receiver: receiver,
            state,
            _workers: workers,
        }
    }

    pub fn submit<F>(
        &self,
        kind: CompatibilityJobKind,
        work: F,
    ) -> Result<CompatibilityJobHandle, CompatibilityRuntimeError>
    where
        F: FnOnce() -> Result<Vec<u8>, CompatibilityRuntimeError> + Send + 'static,
    {
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if self.job_capacity != 0 && state.jobs_pending >= self.job_capacity {
                state.total_rejected = state.total_rejected.saturating_add(1);
                return Err(CompatibilityRuntimeError::JobQueueFull);
            }
            state.jobs_pending = state.jobs_pending.saturating_add(1);
            state.total_submitted = state.total_submitted.saturating_add(1);
        }

        let (result_tx, receiver) = mpsc::sync_channel(1);
        if self
            .sender
            .send(WorkItem {
                kind,
                work: Box::new(work),
                result_tx,
            })
            .is_err()
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.jobs_pending = state.jobs_pending.saturating_sub(1);
            state.total_failed = state.total_failed.saturating_add(1);
            return Err(CompatibilityRuntimeError::RuntimeClosed);
        }

        Ok(CompatibilityJobHandle {
            receiver,
            timeout: self.job_timeout,
            state: Arc::clone(&self.state),
        })
    }

    pub fn snapshot(&self) -> CompatibilityRuntimeSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        CompatibilityRuntimeSnapshot {
            job_capacity: self.job_capacity,
            jobs_pending: state.jobs_pending,
            jobs_processing: state.jobs_processing,
            total_submitted: state.total_submitted,
            total_completed: state.total_completed,
            total_failed: state.total_failed,
            total_rejected: state.total_rejected,
            total_timed_out: state.total_timed_out,
            completed_midnight_check: state.completed_midnight_check,
            completed_midnight_prove: state.completed_midnight_prove,
            completed_midnight_prove_tx: state.completed_midnight_prove_tx,
            last_completed_kind: state.last_completed_kind.map(CompatibilityJobKind::as_str),
        }
    }

    pub fn is_full(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.job_capacity != 0 && state.jobs_pending >= self.job_capacity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatibility_runtime_tracks_completion_by_kind() {
        let runtime = CompatibilityRuntime::new(CompatibilityRuntimeConfig {
            num_workers: 1,
            job_capacity: 2,
            job_timeout: Duration::from_secs(1),
        });

        let handle = runtime
            .submit(CompatibilityJobKind::MidnightProve, || Ok(vec![1, 2, 3]))
            .expect("submit prove job");
        let response = handle.wait().expect("wait for prove job");

        assert_eq!(response, vec![1, 2, 3]);
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.total_submitted, 1);
        assert_eq!(snapshot.total_completed, 1);
        assert_eq!(snapshot.completed_midnight_prove, 1);
        assert_eq!(snapshot.last_completed_kind, Some("midnight-prove"));
    }

    #[test]
    fn compatibility_runtime_rejects_when_pending_capacity_is_full() {
        let runtime = CompatibilityRuntime::new(CompatibilityRuntimeConfig {
            num_workers: 0,
            job_capacity: 1,
            job_timeout: Duration::from_secs(1),
        });

        let first = runtime
            .submit(CompatibilityJobKind::MidnightCheck, || {
                thread::sleep(Duration::from_millis(200));
                Ok(vec![9])
            })
            .expect("submit first job");
        let second = runtime.submit(CompatibilityJobKind::MidnightCheck, || Ok(vec![5]));

        assert!(matches!(
            second,
            Err(CompatibilityRuntimeError::JobQueueFull)
        ));
        drop(first);
        let snapshot = runtime.snapshot();
        assert_eq!(snapshot.total_rejected, 1);
    }
}
