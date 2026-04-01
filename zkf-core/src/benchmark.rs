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

//! Structured benchmark measurement and reporting for ZKF operations.
//!
//! Provides statistical aggregation (`StatsAggregate`), GPU stage metrics
//! (`GpuStageMetric`), per-backend measurement containers (`BenchmarkMetrics`),
//! and a multi-backend report (`BenchmarkReport`) with query helpers.

use crate::BackendKind;
use serde::{Deserialize, Serialize};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Statistical aggregate
// ---------------------------------------------------------------------------

/// Statistical aggregate for a series of measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatsAggregate {
    pub min: f64,
    pub max: f64,
    pub median: f64,
    pub mean: f64,
    pub p99: f64,
    pub samples: usize,
}

impl StatsAggregate {
    /// Compute statistics from a slice of `f64` values.
    ///
    /// Returns `None` when the input is empty.
    pub fn from_samples(values: &[f64]) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let n = sorted.len();
        let sum: f64 = sorted.iter().sum();
        let median = if n.is_multiple_of(2) {
            (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
        } else {
            sorted[n / 2]
        };
        let p99_idx = ((n as f64) * 0.99).ceil() as usize;
        let p99 = sorted[p99_idx.min(n - 1)];
        Some(Self {
            min: sorted[0],
            max: sorted[n - 1],
            median,
            mean: sum / n as f64,
            p99,
            samples: n,
        })
    }
}

// ---------------------------------------------------------------------------
// GPU stage metric
// ---------------------------------------------------------------------------

/// Metrics for a single GPU-accelerated stage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuStageMetric {
    pub name: String,
    pub cpu_time_ms: f64,
    pub gpu_time_ms: f64,
    pub speedup: f64,
}

// ---------------------------------------------------------------------------
// Per-backend benchmark metrics
// ---------------------------------------------------------------------------

/// Complete benchmark metrics for a single backend run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetrics {
    pub backend: BackendKind,
    pub compile_time: Option<StatsAggregate>,
    pub witness_time: Option<StatsAggregate>,
    pub prove_time: Option<StatsAggregate>,
    pub verify_time: Option<StatsAggregate>,
    pub proof_size_bytes: Option<usize>,
    pub peak_memory_bytes: Option<usize>,
    pub gpu_utilization: Option<f64>,
    pub gpu_stages: Vec<GpuStageMetric>,
}

// ---------------------------------------------------------------------------
// Multi-backend benchmark report
// ---------------------------------------------------------------------------

/// Multi-backend benchmark report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub timestamp: String,
    pub program_digest: Option<String>,
    pub iterations: usize,
    pub results: Vec<BenchmarkMetrics>,
}

impl BenchmarkReport {
    /// Create a new empty report stamped with the current time (Unix seconds).
    pub fn new(iterations: usize) -> Self {
        let timestamp = format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        );
        Self {
            timestamp,
            program_digest: None,
            iterations,
            results: Vec::new(),
        }
    }

    /// Append a backend result to the report.
    pub fn add_result(&mut self, metrics: BenchmarkMetrics) {
        self.results.push(metrics);
    }

    /// Get the fastest backend by median prove time.
    pub fn fastest_prover(&self) -> Option<BackendKind> {
        self.results
            .iter()
            .filter_map(|m| m.prove_time.as_ref().map(|t| (m.backend, t.median)))
            .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(b, _)| b)
    }

    /// Get the backend that produced the smallest proof.
    pub fn smallest_proof(&self) -> Option<BackendKind> {
        self.results
            .iter()
            .filter_map(|m| m.proof_size_bytes.map(|s| (m.backend, s)))
            .min_by_key(|(_, s)| *s)
            .map(|(b, _)| b)
    }
}

// ---------------------------------------------------------------------------
// Timer utility
// ---------------------------------------------------------------------------

/// Simple timer utility for benchmarking.
pub struct BenchTimer {
    start: std::time::Instant,
}

impl BenchTimer {
    /// Start a new timer.
    pub fn start() -> Self {
        Self {
            start: std::time::Instant::now(),
        }
    }

    /// Elapsed time in milliseconds as `f64`.
    pub fn elapsed_ms(&self) -> f64 {
        self.start.elapsed().as_secs_f64() * 1000.0
    }

    /// Elapsed time as a `Duration`.
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BackendKind;

    // -- StatsAggregate -----------------------------------------------------

    #[test]
    fn stats_from_empty_returns_none() {
        assert!(StatsAggregate::from_samples(&[]).is_none());
    }

    #[test]
    fn stats_single_sample() {
        let stats = StatsAggregate::from_samples(&[42.0]).unwrap();
        assert_eq!(stats.samples, 1);
        assert!((stats.min - 42.0).abs() < 1e-12);
        assert!((stats.max - 42.0).abs() < 1e-12);
        assert!((stats.median - 42.0).abs() < 1e-12);
        assert!((stats.mean - 42.0).abs() < 1e-12);
        assert!((stats.p99 - 42.0).abs() < 1e-12);
    }

    #[test]
    fn stats_known_data() {
        // Values: 1, 2, 3, 4, 5
        let stats = StatsAggregate::from_samples(&[3.0, 1.0, 5.0, 2.0, 4.0]).unwrap();
        assert_eq!(stats.samples, 5);
        assert!((stats.min - 1.0).abs() < 1e-12);
        assert!((stats.max - 5.0).abs() < 1e-12);
        assert!((stats.median - 3.0).abs() < 1e-12);
        assert!((stats.mean - 3.0).abs() < 1e-12);
        // p99 index: ceil(5 * 0.99) = 5 → clamped to index 4 → value 5.0
        assert!((stats.p99 - 5.0).abs() < 1e-12);
    }

    #[test]
    fn stats_even_count_median() {
        // Even number of samples: median is average of two middle values.
        let stats = StatsAggregate::from_samples(&[1.0, 2.0, 3.0, 4.0]).unwrap();
        assert_eq!(stats.samples, 4);
        // sorted: [1,2,3,4], median = (2+3)/2 = 2.5
        assert!((stats.median - 2.5).abs() < 1e-12);
        assert!((stats.mean - 2.5).abs() < 1e-12);
    }

    #[test]
    fn stats_two_samples() {
        let stats = StatsAggregate::from_samples(&[10.0, 20.0]).unwrap();
        assert_eq!(stats.samples, 2);
        assert!((stats.min - 10.0).abs() < 1e-12);
        assert!((stats.max - 20.0).abs() < 1e-12);
        assert!((stats.median - 15.0).abs() < 1e-12);
        assert!((stats.mean - 15.0).abs() < 1e-12);
    }

    // -- BenchmarkReport serialization roundtrip ----------------------------

    #[test]
    fn report_serialization_roundtrip() {
        let mut report = BenchmarkReport::new(5);
        report.program_digest = Some("abc123".to_string());
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::ArkworksGroth16,
            compile_time: StatsAggregate::from_samples(&[10.0, 12.0, 11.0]),
            witness_time: StatsAggregate::from_samples(&[1.0, 1.5]),
            prove_time: StatsAggregate::from_samples(&[100.0, 110.0, 105.0]),
            verify_time: StatsAggregate::from_samples(&[5.0]),
            proof_size_bytes: Some(1024),
            peak_memory_bytes: Some(1_048_576),
            gpu_utilization: None,
            gpu_stages: vec![],
        });
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::Plonky3,
            compile_time: None,
            witness_time: None,
            prove_time: StatsAggregate::from_samples(&[50.0, 55.0]),
            verify_time: None,
            proof_size_bytes: Some(512),
            peak_memory_bytes: None,
            gpu_utilization: Some(0.75),
            gpu_stages: vec![GpuStageMetric {
                name: "ntt".to_string(),
                cpu_time_ms: 20.0,
                gpu_time_ms: 5.0,
                speedup: 4.0,
            }],
        });

        let json = serde_json::to_string_pretty(&report).expect("serialize");
        let deserialized: BenchmarkReport = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.iterations, report.iterations);
        assert_eq!(deserialized.program_digest, report.program_digest);
        assert_eq!(deserialized.results.len(), 2);
        assert_eq!(
            deserialized.results[0].backend,
            BackendKind::ArkworksGroth16
        );
        assert_eq!(deserialized.results[1].backend, BackendKind::Plonky3);
        assert_eq!(deserialized.results[1].gpu_stages.len(), 1);
        assert_eq!(deserialized.results[1].gpu_stages[0].name, "ntt");
    }

    // -- fastest_prover / smallest_proof ------------------------------------

    #[test]
    fn fastest_prover_picks_lowest_median() {
        let mut report = BenchmarkReport::new(3);
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::Halo2,
            compile_time: None,
            witness_time: None,
            prove_time: StatsAggregate::from_samples(&[200.0, 210.0, 205.0]),
            verify_time: None,
            proof_size_bytes: None,
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::Plonky3,
            compile_time: None,
            witness_time: None,
            prove_time: StatsAggregate::from_samples(&[50.0, 55.0, 52.0]),
            verify_time: None,
            proof_size_bytes: None,
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::ArkworksGroth16,
            compile_time: None,
            witness_time: None,
            prove_time: StatsAggregate::from_samples(&[100.0, 110.0, 105.0]),
            verify_time: None,
            proof_size_bytes: None,
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });

        assert_eq!(report.fastest_prover(), Some(BackendKind::Plonky3));
    }

    #[test]
    fn fastest_prover_skips_entries_without_prove_time() {
        let mut report = BenchmarkReport::new(1);
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::Halo2,
            compile_time: None,
            witness_time: None,
            prove_time: None, // no prove time
            verify_time: None,
            proof_size_bytes: None,
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::Plonky3,
            compile_time: None,
            witness_time: None,
            prove_time: StatsAggregate::from_samples(&[42.0]),
            verify_time: None,
            proof_size_bytes: None,
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });

        assert_eq!(report.fastest_prover(), Some(BackendKind::Plonky3));
    }

    #[test]
    fn fastest_prover_empty_report() {
        let report = BenchmarkReport::new(1);
        assert_eq!(report.fastest_prover(), None);
    }

    #[test]
    fn smallest_proof_picks_minimum_size() {
        let mut report = BenchmarkReport::new(1);
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::ArkworksGroth16,
            compile_time: None,
            witness_time: None,
            prove_time: None,
            verify_time: None,
            proof_size_bytes: Some(128),
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::Plonky3,
            compile_time: None,
            witness_time: None,
            prove_time: None,
            verify_time: None,
            proof_size_bytes: Some(4096),
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });

        assert_eq!(report.smallest_proof(), Some(BackendKind::ArkworksGroth16));
    }

    #[test]
    fn smallest_proof_skips_entries_without_size() {
        let mut report = BenchmarkReport::new(1);
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::Halo2,
            compile_time: None,
            witness_time: None,
            prove_time: None,
            verify_time: None,
            proof_size_bytes: None,
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });
        report.add_result(BenchmarkMetrics {
            backend: BackendKind::Plonky3,
            compile_time: None,
            witness_time: None,
            prove_time: None,
            verify_time: None,
            proof_size_bytes: Some(512),
            peak_memory_bytes: None,
            gpu_utilization: None,
            gpu_stages: vec![],
        });

        assert_eq!(report.smallest_proof(), Some(BackendKind::Plonky3));
    }

    #[test]
    fn smallest_proof_empty_report() {
        let report = BenchmarkReport::new(1);
        assert_eq!(report.smallest_proof(), None);
    }

    // -- BenchTimer ---------------------------------------------------------

    #[test]
    fn bench_timer_elapsed_is_non_negative() {
        let timer = BenchTimer::start();
        assert!(timer.elapsed_ms() >= 0.0);
        assert!(timer.elapsed() >= Duration::ZERO);
    }

    // -- GpuStageMetric serialization ---------------------------------------

    #[test]
    fn gpu_stage_metric_roundtrip() {
        let metric = GpuStageMetric {
            name: "msm".to_string(),
            cpu_time_ms: 30.0,
            gpu_time_ms: 8.0,
            speedup: 3.75,
        };
        let json = serde_json::to_string(&metric).expect("serialize");
        let deserialized: GpuStageMetric = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.name, "msm");
        assert!((deserialized.speedup - 3.75).abs() < 1e-12);
    }

    // -- Report new() defaults ----------------------------------------------

    #[test]
    fn report_new_has_expected_defaults() {
        let report = BenchmarkReport::new(10);
        assert_eq!(report.iterations, 10);
        assert!(report.program_digest.is_none());
        assert!(report.results.is_empty());
        // timestamp should be a parseable integer string (Unix seconds)
        let _ts: u64 = report
            .timestamp
            .parse()
            .expect("timestamp should be numeric");
    }
}
