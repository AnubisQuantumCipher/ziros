//! Hybrid CPU-GPU MSM -- split work between CPU threads and Metal GPU.
//!
//! Strategy: for large point counts (log2(N) >= 20), delegate bucket accumulation
//! to the GPU and bucket reduction + final sum to the CPU. For smaller counts,
//! CPU-only Pippenger is faster due to GPU dispatch overhead.
//!
//! This module provides configuration, work-splitting, timing, and auto-tune
//! infrastructure. Actual GPU kernel dispatch is handled by the existing
//! `pippenger` module; this layer decides *how* to partition work.

use serde::{Deserialize, Serialize};

/// Configuration for hybrid CPU-GPU MSM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridMsmConfig {
    /// Fraction of work to send to GPU (0.0 = CPU only, 1.0 = GPU only).
    pub gpu_fraction: f64,
    /// Minimum batch size to justify GPU dispatch overhead.
    pub min_gpu_batch: usize,
    /// Number of CPU threads for the CPU portion.
    pub cpu_threads: usize,
    /// log2(N) threshold: below this, use CPU-only.
    pub gpu_threshold_log2: u32,
    /// Whether auto-tuning has been performed.
    pub auto_tuned: bool,
}

impl Default for HybridMsmConfig {
    fn default() -> Self {
        Self::resource_aware()
    }
}

impl HybridMsmConfig {
    /// Create a resource-aware configuration based on detected GPU and system resources.
    ///
    /// M4 Max philosophy: 40 GPU cores are designed for parallel workloads with
    /// massive thermal headroom. Apple Silicon GPUs are incredibly power-efficient.
    /// The unified memory architecture means zero data transfer overhead — the GPU
    /// reads directly from the same memory pool. Instead of CPU performance cores
    /// maxing out at full clock speed generating concentrated heat, work is spread
    /// across 40 GPU cores running at lower individual power, pulling data from
    /// shared memory with zero-copy buffers.
    ///
    /// Configuration priority:
    /// 1. Detect Metal GPU device → use device-specific GPU-first tuning
    /// 2. Fall back to RAM-based heuristics if no Metal available
    pub fn resource_aware() -> Self {
        let res = zkf_core::SystemResources::detect();
        let rec = res.recommend();

        // Detect Metal GPU for device-aware tuning — GPU-first on Apple Silicon
        if let Some(ctx) = crate::device::global_context() {
            let device_name = ctx.device_name();
            let thresholds = crate::tuning::thresholds_for_device(&device_name);

            // M4 Max / M4 Ultra: GPU-first. 40 cores, 546 GB/s bandwidth,
            // unified memory = zero-copy. Push nearly everything to GPU.
            // CPU threads kept minimal — just enough for the reduction phase.
            if device_name.contains("M4 Max") || device_name.contains("M4 Ultra") {
                return Self {
                    gpu_fraction: 0.95,
                    min_gpu_batch: thresholds.msm, // 64 — even tiny MSMs on GPU
                    cpu_threads: rec.proving_threads.min(4),
                    gpu_threshold_log2: 6, // 2^6 = 64 points
                    auto_tuned: false,
                };
            }

            // M4 Pro / M3 Max / M3 Ultra: strong GPU, balanced split
            if device_name.contains("M4 Pro")
                || device_name.contains("M3 Max")
                || device_name.contains("M3 Ultra")
            {
                return Self {
                    gpu_fraction: 0.85,
                    min_gpu_batch: thresholds.msm,
                    cpu_threads: rec.proving_threads.min(6),
                    gpu_threshold_log2: 13, // 2^13 = 8K points
                    auto_tuned: false,
                };
            }

            // Other Apple Silicon (M1/M2/M3 base, M4 base): moderate GPU use
            return Self {
                gpu_fraction: 0.7,
                min_gpu_batch: thresholds.msm,
                cpu_threads: rec.proving_threads,
                gpu_threshold_log2: 14, // 2^14 = 16K points
                auto_tuned: false,
            };
        }

        // No Metal GPU available — RAM-based fallback
        let total_gib = res.total_ram_gib();
        let (gpu_fraction, min_gpu_batch, gpu_threshold_log2) = if total_gib < 16.0 {
            (0.5, 1 << 18, 22u32)
        } else if total_gib < 64.0 {
            (0.7, 1 << 16, 20)
        } else {
            (0.8, 1 << 15, 18)
        };

        Self {
            gpu_fraction,
            min_gpu_batch,
            cpu_threads: rec.proving_threads,
            gpu_threshold_log2,
            auto_tuned: false,
        }
    }

    /// Create a CPU-only configuration.
    pub fn cpu_only() -> Self {
        Self {
            gpu_fraction: 0.0,
            min_gpu_batch: usize::MAX,
            cpu_threads: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4),
            gpu_threshold_log2: u32::MAX,
            auto_tuned: false,
        }
    }

    /// Create a GPU-heavy configuration.
    pub fn gpu_heavy() -> Self {
        Self {
            gpu_fraction: 0.9,
            min_gpu_batch: 1 << 14, // 16K points
            cpu_threads: 2,         // minimal CPU threads
            gpu_threshold_log2: 16,
            auto_tuned: false,
        }
    }

    /// Whether the GPU should be used for a given point count.
    pub fn should_use_gpu(&self, num_points: usize) -> bool {
        if self.gpu_fraction <= 0.0 {
            return false;
        }
        if num_points == 0 {
            return false;
        }
        let log2_n = (num_points as f64).log2() as u32;
        log2_n >= self.gpu_threshold_log2 && num_points >= self.min_gpu_batch
    }

    /// Calculate the split: how many points go to GPU vs CPU.
    pub fn split_work(&self, total_points: usize) -> WorkSplit {
        if !self.should_use_gpu(total_points) {
            return WorkSplit {
                gpu_points: 0,
                cpu_points: total_points,
                gpu_fraction_actual: 0.0,
            };
        }
        let gpu_points = (total_points as f64 * self.gpu_fraction) as usize;
        let cpu_points = total_points - gpu_points;
        WorkSplit {
            gpu_points,
            cpu_points,
            gpu_fraction_actual: if total_points > 0 {
                gpu_points as f64 / total_points as f64
            } else {
                0.0
            },
        }
    }
}

/// Result of splitting MSM work between CPU and GPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkSplit {
    /// Number of points assigned to the GPU.
    pub gpu_points: usize,
    /// Number of points assigned to CPU threads.
    pub cpu_points: usize,
    /// Actual fraction of points sent to GPU (may differ slightly from config
    /// due to integer rounding).
    pub gpu_fraction_actual: f64,
}

impl WorkSplit {
    /// True if all work goes to the CPU.
    pub fn is_cpu_only(&self) -> bool {
        self.gpu_points == 0
    }

    /// True if all work goes to the GPU.
    pub fn is_gpu_only(&self) -> bool {
        self.cpu_points == 0
    }

    /// Total number of points (GPU + CPU).
    pub fn total(&self) -> usize {
        self.gpu_points + self.cpu_points
    }
}

/// Timing results from a hybrid MSM run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridMsmTiming {
    /// Total wall-clock time in milliseconds.
    pub total_ms: f64,
    /// Time spent on GPU work in milliseconds.
    pub gpu_ms: f64,
    /// Time spent on CPU work in milliseconds.
    pub cpu_ms: f64,
    /// Overhead (synchronization, data transfer, etc.) in milliseconds.
    pub overhead_ms: f64,
    /// Number of points in this MSM.
    pub num_points: usize,
    /// Speedup of hybrid over CPU-only (cpu_only_ms / total_ms).
    pub gpu_speedup: f64,
    /// The configuration used for this run.
    pub config: HybridMsmConfig,
}

/// Auto-tune result: optimal configuration for this hardware.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTuneResult {
    /// The optimal configuration discovered by auto-tuning.
    pub optimal_config: HybridMsmConfig,
    /// CPU-only time (milliseconds) at the benchmark size.
    pub cpu_only_ms: f64,
    /// GPU-only time (milliseconds) at the benchmark size.
    pub gpu_only_ms: f64,
    /// Best hybrid time (milliseconds) at the benchmark size.
    pub hybrid_ms: f64,
    /// Optimal GPU fraction discovered.
    pub optimal_gpu_fraction: f64,
    /// log2(N) crossover point: below this, CPU-only is faster.
    pub crossover_log2: u32,
}

/// Cached auto-tune results (persisted to disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTuneCache {
    /// Name of the Metal GPU device (e.g. "Apple M4 Max").
    pub device_name: String,
    /// Number of GPU cores, if known.
    pub gpu_cores: Option<u32>,
    /// Unified memory in bytes, if known.
    pub unified_memory_bytes: Option<u64>,
    /// The auto-tune result.
    pub result: AutoTuneResult,
    /// Unix timestamp when the auto-tune was performed.
    pub timestamp_unix: u64,
}

impl AutoTuneCache {
    /// Default cache file location: `~/.zkf/msm_autotune.json`.
    pub fn cache_path() -> std::path::PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        std::path::PathBuf::from(home)
            .join(".zkf")
            .join("msm_autotune.json")
    }

    /// Load from cache file. Returns `None` if the file does not exist or
    /// cannot be parsed.
    pub fn load() -> Option<Self> {
        let path = Self::cache_path();
        let data = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Save to cache file, creating parent directories as needed.
    pub fn save(&self) -> Result<(), String> {
        let path = Self::cache_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create cache dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialization failed: {e}"))?;
        std::fs::write(&path, json).map_err(|e| format!("write failed: {e}"))?;
        Ok(())
    }

    /// Load from a specific path (useful for testing).
    pub fn load_from(path: &std::path::Path) -> Option<Self> {
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// Save to a specific path (useful for testing).
    pub fn save_to(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create cache dir: {e}"))?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("serialization failed: {e}"))?;
        std::fs::write(path, json).map_err(|e| format!("write failed: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let cfg = HybridMsmConfig::default();
        // GPU-aware: on M4 Max gpu_fraction=0.95, on other Apple Silicon ≥0.7
        assert!(cfg.gpu_fraction >= 0.7, "gpu_fraction too low: {}", cfg.gpu_fraction);
        assert!(cfg.gpu_fraction <= 1.0);
        assert!(cfg.min_gpu_batch >= 1);
        assert!(cfg.cpu_threads >= 1);
        // GPU threshold should be reasonable (6 for M4 Max, up to 22 for no-GPU fallback)
        assert!(cfg.gpu_threshold_log2 <= 22);
        assert!(!cfg.auto_tuned);
    }

    #[test]
    fn cpu_only_config() {
        let cfg = HybridMsmConfig::cpu_only();
        assert!((cfg.gpu_fraction - 0.0).abs() < f64::EPSILON);
        assert_eq!(cfg.min_gpu_batch, usize::MAX);
        assert!(cfg.cpu_threads >= 1);
        assert_eq!(cfg.gpu_threshold_log2, u32::MAX);
        assert!(!cfg.auto_tuned);
    }

    #[test]
    fn gpu_heavy_config() {
        let cfg = HybridMsmConfig::gpu_heavy();
        assert!((cfg.gpu_fraction - 0.9).abs() < f64::EPSILON);
        assert_eq!(cfg.min_gpu_batch, 1 << 14);
        assert_eq!(cfg.cpu_threads, 2);
        assert_eq!(cfg.gpu_threshold_log2, 16);
        assert!(!cfg.auto_tuned);
    }

    #[test]
    fn should_use_gpu_below_threshold() {
        // Use cpu_only config for deterministic threshold testing
        let cfg = HybridMsmConfig::cpu_only();
        assert!(!cfg.should_use_gpu(524_288));
        assert!(!cfg.should_use_gpu(100));
        assert!(!cfg.should_use_gpu(1));
        // Default config: GPU-aware, zero is always below threshold
        let default_cfg = HybridMsmConfig::default();
        assert!(!default_cfg.should_use_gpu(0));
    }

    #[test]
    fn should_use_gpu_above_threshold() {
        let cfg = HybridMsmConfig::default();
        // Large counts should always use GPU regardless of device detection
        assert!(cfg.should_use_gpu(1 << 22)); // 4M points — above any threshold
        assert!(cfg.should_use_gpu(1 << 24)); // 16M points
    }

    #[test]
    fn should_use_gpu_cpu_only_never() {
        let cfg = HybridMsmConfig::cpu_only();
        // CPU-only config should never use GPU, no matter how many points
        assert!(!cfg.should_use_gpu(1 << 30));
        assert!(!cfg.should_use_gpu(usize::MAX / 2));
    }

    #[test]
    fn should_use_gpu_gpu_heavy_lower_threshold() {
        let cfg = HybridMsmConfig::gpu_heavy();
        // GPU-heavy has threshold at log2=16 and min_gpu_batch=16K
        assert!(cfg.should_use_gpu(1 << 16));
        assert!(cfg.should_use_gpu(1 << 20));
        // Below 16K should still be false
        assert!(!cfg.should_use_gpu(1 << 13));
    }

    #[test]
    fn should_use_gpu_respects_min_batch() {
        // Custom config: low log2 threshold but high min_gpu_batch
        let cfg = HybridMsmConfig {
            gpu_fraction: 0.5,
            min_gpu_batch: 1 << 20,
            cpu_threads: 4,
            gpu_threshold_log2: 10,
            auto_tuned: false,
        };
        // log2(100_000) ~ 16.6 >= 10, but 100_000 < 2^20
        assert!(!cfg.should_use_gpu(100_000));
        // 2^20 meets both
        assert!(cfg.should_use_gpu(1 << 20));
    }

    #[test]
    fn split_work_cpu_only() {
        let cfg = HybridMsmConfig::cpu_only();
        let split = cfg.split_work(1_000_000);
        assert_eq!(split.gpu_points, 0);
        assert_eq!(split.cpu_points, 1_000_000);
        assert!((split.gpu_fraction_actual - 0.0).abs() < f64::EPSILON);
        assert!(split.is_cpu_only());
        assert!(!split.is_gpu_only());
    }

    #[test]
    fn split_work_below_threshold() {
        // Use cpu_only for deterministic test — always below threshold
        let cfg = HybridMsmConfig::cpu_only();
        let split = cfg.split_work(1000);
        assert_eq!(split.gpu_points, 0);
        assert_eq!(split.cpu_points, 1000);
        assert!(split.is_cpu_only());
    }

    #[test]
    fn split_work_above_threshold() {
        let cfg = HybridMsmConfig::default();
        let n = 1 << 22; // 4M points — above any device's threshold
        let split = cfg.split_work(n);

        // GPU-aware config: most work goes to GPU (≥0.7 fraction)
        assert!(split.gpu_points > 0, "should send some to GPU");
        assert_eq!(split.gpu_points + split.cpu_points, n);
        assert!(!split.is_cpu_only());

        let frac = split.gpu_points as f64 / n as f64;
        assert!(frac >= 0.7, "GPU fraction should be at least 0.7, got {frac}");
        assert!(frac <= 1.0);
    }

    #[test]
    fn split_work_total_invariant() {
        // For any config and any point count, gpu_points + cpu_points == total
        for n in [0, 1, 100, 1 << 16, 1 << 20, 1 << 22] {
            for cfg in [
                HybridMsmConfig::default(),
                HybridMsmConfig::cpu_only(),
                HybridMsmConfig::gpu_heavy(),
            ] {
                let split = cfg.split_work(n);
                assert_eq!(
                    split.gpu_points + split.cpu_points,
                    n,
                    "total invariant violated for n={n}, cfg={cfg:?}"
                );
                assert_eq!(split.total(), n);
            }
        }
    }

    #[test]
    fn split_work_zero_points() {
        let cfg = HybridMsmConfig::gpu_heavy();
        let split = cfg.split_work(0);
        assert_eq!(split.gpu_points, 0);
        assert_eq!(split.cpu_points, 0);
        assert!(split.is_cpu_only());
        assert!(split.is_gpu_only()); // 0 points is trivially both
    }

    #[test]
    fn work_split_helpers() {
        let gpu_only = WorkSplit {
            gpu_points: 100,
            cpu_points: 0,
            gpu_fraction_actual: 1.0,
        };
        assert!(gpu_only.is_gpu_only());
        assert!(!gpu_only.is_cpu_only());
        assert_eq!(gpu_only.total(), 100);

        let cpu_only = WorkSplit {
            gpu_points: 0,
            cpu_points: 100,
            gpu_fraction_actual: 0.0,
        };
        assert!(cpu_only.is_cpu_only());
        assert!(!cpu_only.is_gpu_only());
        assert_eq!(cpu_only.total(), 100);

        let hybrid = WorkSplit {
            gpu_points: 70,
            cpu_points: 30,
            gpu_fraction_actual: 0.7,
        };
        assert!(!hybrid.is_cpu_only());
        assert!(!hybrid.is_gpu_only());
        assert_eq!(hybrid.total(), 100);
    }

    #[test]
    fn config_serialization_roundtrip() {
        let cfg = HybridMsmConfig {
            gpu_fraction: 0.65,
            min_gpu_batch: 32768,
            cpu_threads: 8,
            gpu_threshold_log2: 18,
            auto_tuned: true,
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        let cfg2: HybridMsmConfig = serde_json::from_str(&json).expect("deserialize");
        assert!((cfg2.gpu_fraction - 0.65).abs() < f64::EPSILON);
        assert_eq!(cfg2.min_gpu_batch, 32768);
        assert_eq!(cfg2.cpu_threads, 8);
        assert_eq!(cfg2.gpu_threshold_log2, 18);
        assert!(cfg2.auto_tuned);
    }

    #[test]
    fn work_split_serialization_roundtrip() {
        let split = WorkSplit {
            gpu_points: 700_000,
            cpu_points: 300_000,
            gpu_fraction_actual: 0.7,
        };
        let json = serde_json::to_string(&split).expect("serialize");
        let split2: WorkSplit = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(split2.gpu_points, 700_000);
        assert_eq!(split2.cpu_points, 300_000);
        assert!((split2.gpu_fraction_actual - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn timing_serialization_roundtrip() {
        let timing = HybridMsmTiming {
            total_ms: 42.5,
            gpu_ms: 30.0,
            cpu_ms: 35.0,
            overhead_ms: 2.5,
            num_points: 1 << 20,
            gpu_speedup: 2.3,
            config: HybridMsmConfig::default(),
        };
        let json = serde_json::to_string(&timing).expect("serialize");
        let timing2: HybridMsmTiming = serde_json::from_str(&json).expect("deserialize");
        assert!((timing2.total_ms - 42.5).abs() < f64::EPSILON);
        assert_eq!(timing2.num_points, 1 << 20);
        assert!((timing2.gpu_speedup - 2.3).abs() < f64::EPSILON);
    }

    #[test]
    fn auto_tune_result_serialization_roundtrip() {
        let result = AutoTuneResult {
            optimal_config: HybridMsmConfig::gpu_heavy(),
            cpu_only_ms: 100.0,
            gpu_only_ms: 40.0,
            hybrid_ms: 35.0,
            optimal_gpu_fraction: 0.85,
            crossover_log2: 17,
        };
        let json = serde_json::to_string_pretty(&result).expect("serialize");
        let result2: AutoTuneResult = serde_json::from_str(&json).expect("deserialize");
        assert!((result2.cpu_only_ms - 100.0).abs() < f64::EPSILON);
        assert!((result2.gpu_only_ms - 40.0).abs() < f64::EPSILON);
        assert!((result2.hybrid_ms - 35.0).abs() < f64::EPSILON);
        assert!((result2.optimal_gpu_fraction - 0.85).abs() < f64::EPSILON);
        assert_eq!(result2.crossover_log2, 17);
    }

    #[test]
    fn auto_tune_cache_serialization_roundtrip() {
        let cache = AutoTuneCache {
            device_name: "Apple M4 Max".to_string(),
            gpu_cores: Some(40),
            unified_memory_bytes: Some(128 * 1024 * 1024 * 1024), // 128 GB
            result: AutoTuneResult {
                optimal_config: HybridMsmConfig::default(),
                cpu_only_ms: 200.0,
                gpu_only_ms: 50.0,
                hybrid_ms: 45.0,
                optimal_gpu_fraction: 0.75,
                crossover_log2: 18,
            },
            timestamp_unix: 1_700_000_000,
        };
        let json = serde_json::to_string_pretty(&cache).expect("serialize");
        let cache2: AutoTuneCache = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(cache2.device_name, "Apple M4 Max");
        assert_eq!(cache2.gpu_cores, Some(40));
        assert_eq!(cache2.unified_memory_bytes, Some(128 * 1024 * 1024 * 1024));
        assert_eq!(cache2.timestamp_unix, 1_700_000_000);
        assert!((cache2.result.hybrid_ms - 45.0).abs() < f64::EPSILON);
    }

    #[test]
    fn auto_tune_cache_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("zkf_test_hybrid_cache");
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("test_autotune.json");

        let cache = AutoTuneCache {
            device_name: "Test GPU".to_string(),
            gpu_cores: Some(10),
            unified_memory_bytes: None,
            result: AutoTuneResult {
                optimal_config: HybridMsmConfig::cpu_only(),
                cpu_only_ms: 10.0,
                gpu_only_ms: 50.0,
                hybrid_ms: 10.0,
                optimal_gpu_fraction: 0.0,
                crossover_log2: 30,
            },
            timestamp_unix: 1_234_567_890,
        };

        cache.save_to(&path).expect("save");
        let loaded = AutoTuneCache::load_from(&path).expect("load");

        assert_eq!(loaded.device_name, "Test GPU");
        assert_eq!(loaded.gpu_cores, Some(10));
        assert_eq!(loaded.unified_memory_bytes, None);
        assert_eq!(loaded.timestamp_unix, 1_234_567_890);
        assert!((loaded.result.cpu_only_ms - 10.0).abs() < f64::EPSILON);

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_tune_cache_load_nonexistent() {
        let path = std::path::PathBuf::from("/tmp/zkf_does_not_exist_12345.json");
        assert!(AutoTuneCache::load_from(&path).is_none());
    }

    #[test]
    fn auto_tune_cache_load_invalid_json() {
        let dir = std::env::temp_dir().join("zkf_test_bad_json");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(&path, "this is not json").unwrap();
        assert!(AutoTuneCache::load_from(&path).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cache_path_is_reasonable() {
        let path = AutoTuneCache::cache_path();
        let path_str = path.to_string_lossy();
        assert!(
            path_str.contains(".zkf") && path_str.contains("msm_autotune.json"),
            "unexpected cache path: {path_str}"
        );
    }

    #[test]
    fn split_work_gpu_fraction_one() {
        // gpu_fraction = 1.0 means all points go to GPU
        let cfg = HybridMsmConfig {
            gpu_fraction: 1.0,
            min_gpu_batch: 1,
            cpu_threads: 4,
            gpu_threshold_log2: 0,
            auto_tuned: false,
        };
        let n = 1000;
        let split = cfg.split_work(n);
        assert_eq!(split.gpu_points, n);
        assert_eq!(split.cpu_points, 0);
        assert!(split.is_gpu_only());
    }

    #[test]
    fn split_work_gpu_fraction_zero() {
        // gpu_fraction = 0.0 means all points go to CPU
        let cfg = HybridMsmConfig {
            gpu_fraction: 0.0,
            min_gpu_batch: 1,
            cpu_threads: 4,
            gpu_threshold_log2: 0,
            auto_tuned: false,
        };
        let split = cfg.split_work(1_000_000);
        assert_eq!(split.gpu_points, 0);
        assert_eq!(split.cpu_points, 1_000_000);
        assert!(split.is_cpu_only());
    }
}
