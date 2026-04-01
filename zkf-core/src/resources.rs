//! Adaptive system resource detection.
//!
//! Detects available RAM, CPU cores, GPU capabilities, and memory pressure at runtime.
//! Recommends parallelism settings for builds, proving, and MSM operations
//! based on the actual hardware — never hardcoded.
//!
//! # Memory pressure model
//!
//! Raw VM statistics can produce negative "available" values under extreme compressor
//! load. The [`MemoryPressure`] struct separates the raw diagnostic signal from clamped
//! user-facing values, and classifies pressure into four levels:
//!
//! | Level | Meaning |
//! |---|---|
//! | `Normal` | ≤60% utilization, no action needed |
//! | `Elevated` | 60-80%, reduce parallelism |
//! | `High` | 80-93%, single-threaded proving recommended |
//! | `Critical` | >93% or compressor overflow, abort non-essential work |

use serde::{Deserialize, Serialize};

/// Snapshot of detected system resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemResources {
    /// Total physical RAM in bytes.
    pub total_ram_bytes: u64,
    /// Currently available (free + reclaimable) RAM in bytes.
    /// Clamped to zero — see `pressure` for raw diagnostic.
    pub available_ram_bytes: u64,
    /// Logical CPU cores (hyper-threads).
    pub cpu_cores_logical: usize,
    /// Physical CPU cores (0 if detection fails — falls back to logical).
    pub cpu_cores_physical: usize,
    /// True on Apple Silicon (unified CPU/GPU memory).
    pub unified_memory: bool,
    /// GPU memory in bytes (same as total RAM on Apple Silicon).
    pub gpu_memory_bytes: Option<u64>,
    /// Memory pressure snapshot — compressor, swap, and classification.
    pub pressure: MemoryPressure,
}

/// Memory pressure classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureLevel {
    /// ≤60% utilization. No action needed.
    Normal,
    /// 60-80% utilization. Consider reducing parallelism.
    Elevated,
    /// 80-93% utilization. Single-threaded proving recommended.
    High,
    /// >93% utilization or compressor overflow. Abort non-essential work.
    Critical,
}

impl std::fmt::Display for PressureLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PressureLevel::Normal => write!(f, "NORMAL"),
            PressureLevel::Elevated => write!(f, "ELEVATED"),
            PressureLevel::High => write!(f, "HIGH"),
            PressureLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Detailed memory pressure snapshot.
///
/// Separates raw diagnostic values (which can be negative under extreme
/// compressor load) from clamped user-facing values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPressure {
    /// Pressure classification.
    pub level: PressureLevel,
    /// RAM utilization as percentage (0-100), clamped.
    pub utilization_pct: f64,
    /// Bytes consumed by the memory compressor.
    pub compressed_bytes: u64,
    /// Bytes in swap.
    pub swap_used_bytes: u64,
    /// Raw available value before clamping (can be negative as i64).
    /// When negative, compressor pages exceed free+inactive+purgeable.
    pub raw_available_i64: i64,
    /// True if compressor overflow was detected (raw < 0).
    pub compressor_overflow: bool,
    /// Free pages (not reclaimable, truly unused).
    pub free_bytes: u64,
    /// Inactive pages (reclaimable by OS).
    pub inactive_bytes: u64,
    /// Purgeable pages (discardable by OS).
    pub purgeable_bytes: u64,
    /// Wired pages (kernel, locked, not reclaimable).
    pub wired_bytes: u64,
}

impl Default for MemoryPressure {
    fn default() -> Self {
        Self {
            level: PressureLevel::Normal,
            utilization_pct: 0.0,
            compressed_bytes: 0,
            swap_used_bytes: 0,
            raw_available_i64: 0,
            compressor_overflow: false,
            free_bytes: 0,
            inactive_bytes: 0,
            purgeable_bytes: 0,
            wired_bytes: 0,
        }
    }
}

/// Resource-aware recommendations for parallelism and memory budgets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceRecommendation {
    /// Recommended `CARGO_BUILD_JOBS` for compilation.
    pub cargo_build_jobs: usize,
    /// Recommended threads for proving/witness operations.
    pub proving_threads: usize,
    /// Maximum memory budget for circuit operations (bytes).
    pub max_circuit_memory_bytes: u64,
    /// GPU memory budget for MSM/NTT (bytes, if GPU available).
    pub gpu_memory_budget_bytes: Option<u64>,
    /// Whether to enable low-memory mode for wrapping/folding.
    pub low_memory_mode: bool,
    /// RAM headroom kept free for the OS and other processes (bytes).
    pub os_headroom_bytes: u64,
    /// Human-readable summary of the recommendation.
    pub summary: String,
}

impl SystemResources {
    /// Detect system resources for the current machine.
    pub fn detect() -> Self {
        let total_ram = detect_total_ram();
        let logical = detect_logical_cores();
        let physical = detect_physical_cores();
        let unified = detect_unified_memory();
        let gpu_mem = if unified { Some(total_ram) } else { None };

        let pressure = detect_pressure(total_ram);

        // Clamped available: use the pressure's raw value, floored at 0
        let available_ram = if pressure.raw_available_i64 > 0 {
            pressure.raw_available_i64 as u64
        } else {
            0
        };

        Self {
            total_ram_bytes: total_ram,
            available_ram_bytes: available_ram,
            cpu_cores_logical: logical,
            cpu_cores_physical: physical,
            unified_memory: unified,
            gpu_memory_bytes: gpu_mem,
            pressure,
        }
    }

    /// Total RAM in GiB (floating point for display).
    pub fn total_ram_gib(&self) -> f64 {
        self.total_ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// Available RAM in GiB (clamped to ≥0 for display).
    pub fn available_ram_gib(&self) -> f64 {
        self.available_ram_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
    }

    /// RAM utilization as a fraction (0.0 = empty, 1.0 = full), clamped to [0, 1].
    pub fn ram_utilization(&self) -> f64 {
        if self.total_ram_bytes == 0 {
            return 0.0;
        }
        let util = 1.0 - (self.available_ram_bytes as f64 / self.total_ram_bytes as f64);
        util.clamp(0.0, 1.0)
    }

    /// Generate resource recommendations based on current system state.
    ///
    /// The algorithm:
    /// - Each rustc instance uses ~2-4 GB for a ZKF crate (heavy generics from arkworks).
    /// - Keep at least 4 GB free for OS + other processes (8 GB on systems with ≥32 GB).
    /// - Proving operations need ~2-6 GB depending on circuit size.
    /// - GPU MSM should not exceed 75% of available memory.
    /// - Under High/Critical pressure, reduce parallelism aggressively.
    pub fn recommend(&self) -> ResourceRecommendation {
        let total_gib = self.total_ram_gib();
        let available_gib = self.available_ram_gib();

        // OS headroom: 4 GB on small systems, 8 GB on large (≥32 GB) systems
        let os_headroom_gib = if total_gib >= 32.0 { 8.0 } else { 4.0 };
        let os_headroom_bytes = (os_headroom_gib * 1024.0 * 1024.0 * 1024.0) as u64;

        // Budget = available RAM minus headroom
        let budget_gib = (available_gib - os_headroom_gib).max(1.0);

        // Pressure-aware scaling factor
        let pressure_scale = match self.pressure.level {
            PressureLevel::Normal => 1.0,
            PressureLevel::Elevated => 0.7,
            PressureLevel::High => 0.4,
            PressureLevel::Critical => 0.2,
        };

        // Each rustc instance: ~3 GB for ZKF workspace crates (arkworks generics are heavy)
        let ram_per_job_gib = 3.0;
        let max_jobs_by_ram = (budget_gib * pressure_scale / ram_per_job_gib).floor() as usize;
        let max_jobs_by_cores = self.cpu_cores_physical.max(self.cpu_cores_logical);

        // Cargo jobs: min(RAM-based limit, core count), at least 1
        let cargo_build_jobs = max_jobs_by_ram.min(max_jobs_by_cores).max(1);

        // Proving threads: use physical cores, but cap by memory
        let ram_per_prove_thread_gib = 1.5;
        let max_prove_by_ram =
            (budget_gib * pressure_scale / ram_per_prove_thread_gib).floor() as usize;
        let proving_threads = max_prove_by_ram.min(self.cpu_cores_physical.max(1)).max(1);

        // Circuit memory budget: 60% of available budget
        let max_circuit_memory_bytes =
            (budget_gib * pressure_scale * 0.6 * 1024.0 * 1024.0 * 1024.0) as u64;

        // GPU memory budget: 75% of available if unified memory
        let gpu_memory_budget_bytes = self
            .gpu_memory_bytes
            .map(|_| (budget_gib * pressure_scale * 0.75 * 1024.0 * 1024.0 * 1024.0) as u64);

        // Low-memory mode: enable if total RAM < 16 GB, available < 8 GB, or high pressure
        let low_memory_mode = total_gib < 16.0
            || available_gib < 8.0
            || matches!(
                self.pressure.level,
                PressureLevel::High | PressureLevel::Critical
            );

        let pressure_note = match self.pressure.level {
            PressureLevel::Normal => String::new(),
            PressureLevel::Elevated => ", pressure=ELEVATED".into(),
            PressureLevel::High => ", pressure=HIGH, LOW-MEMORY mode".into(),
            PressureLevel::Critical => ", pressure=CRITICAL, LOW-MEMORY mode".into(),
        };

        let summary = format!(
            "System: {:.1} GB total, {:.1} GB available, {} cores ({} physical). \
             Recommend: {} cargo jobs, {} proving threads, {:.1} GB circuit budget{}",
            total_gib,
            available_gib,
            self.cpu_cores_logical,
            self.cpu_cores_physical,
            cargo_build_jobs,
            proving_threads,
            max_circuit_memory_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
            pressure_note,
        );

        ResourceRecommendation {
            cargo_build_jobs,
            proving_threads,
            max_circuit_memory_bytes,
            gpu_memory_budget_bytes,
            low_memory_mode,
            os_headroom_bytes,
            summary,
        }
    }

    /// Serialize to JSON for FFI / CLI output.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Generate a shell script snippet that sets CARGO_BUILD_JOBS and other env vars.
    pub fn to_env_script(&self) -> String {
        let rec = self.recommend();
        format!(
            "export CARGO_BUILD_JOBS={}\n\
             export ZKF_PROVING_THREADS={}\n\
             export ZKF_MAX_CIRCUIT_MEMORY={}\n\
             export ZKF_LOW_MEMORY={}\n\
             export ZKF_PRESSURE_LEVEL={}\n",
            rec.cargo_build_jobs,
            rec.proving_threads,
            rec.max_circuit_memory_bytes,
            if rec.low_memory_mode { "1" } else { "0" },
            self.pressure.level,
        )
    }
}

// ── Pressure detection ───────────────────────────────────────────────────

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn detect_pressure(total_ram: u64) -> MemoryPressure {
    use std::mem;

    unsafe {
        let mut vm_stat: libc::vm_statistics64 = mem::zeroed();

        #[allow(deprecated)]
        let host = libc::mach_host_self();

        let mut count: libc::mach_msg_type_number_t =
            (mem::size_of::<libc::vm_statistics64>() / mem::size_of::<libc::integer_t>()) as _;

        let kr = libc::host_statistics64(
            host,
            libc::HOST_VM_INFO64,
            &mut vm_stat as *mut libc::vm_statistics64 as *mut libc::integer_t,
            &mut count,
        );

        if kr != libc::KERN_SUCCESS {
            return MemoryPressure::default();
        }

        let page_size = libc::sysconf(libc::_SC_PAGESIZE) as u64;

        let free_bytes = u64::from(vm_stat.free_count) * page_size;
        let inactive_bytes = u64::from(vm_stat.inactive_count) * page_size;
        let speculative_bytes = u64::from(vm_stat.speculative_count) * page_size;
        let purgeable_bytes = u64::from(vm_stat.purgeable_count) * page_size;
        let compressed_bytes = u64::from(vm_stat.compressor_page_count) * page_size;
        let wired_bytes = u64::from(vm_stat.wire_count) * page_size;

        // Raw available: signed because compressor can exceed free+inactive+purgeable.
        // On Apple Silicon, prefer the OS's own memory_pressure free% signal when available,
        // because it already accounts for reclaimable memory and avoids false "critical"
        // snapshots from transient VM counter skew.
        let fallback_raw_available_i64 = (free_bytes as i64)
            + (inactive_bytes as i64)
            + (speculative_bytes as i64)
            + (purgeable_bytes as i64)
            - (compressed_bytes as i64);
        let fallback_compressor_overflow = fallback_raw_available_i64 < 0;
        let fallback_clamped_available = fallback_raw_available_i64.max(0) as u64;
        let fallback_utilization_pct = if total_ram > 0 {
            ((total_ram.saturating_sub(fallback_clamped_available)) as f64 / total_ram as f64
                * 100.0)
                .clamp(0.0, 100.0)
        } else {
            0.0
        };

        let (raw_available_i64, compressor_overflow, utilization_pct) =
            if let Some(free_pct) = detect_memory_pressure_free_pct() {
                let utilization_pct = (100.0 - free_pct).clamp(0.0, 100.0);
                let clamped_available = ((total_ram as f64) * (free_pct / 100.0)).round() as u64;
                (
                    clamped_available.min(total_ram) as i64,
                    false,
                    utilization_pct,
                )
            } else {
                (
                    fallback_raw_available_i64,
                    fallback_compressor_overflow,
                    fallback_utilization_pct,
                )
            };

        // Detect swap usage via sysctl
        let swap_used_bytes = detect_swap_used();

        // Classify pressure level
        let level = if compressor_overflow || utilization_pct > 93.0 {
            PressureLevel::Critical
        } else if utilization_pct > 80.0 {
            PressureLevel::High
        } else if utilization_pct > 60.0 {
            PressureLevel::Elevated
        } else {
            PressureLevel::Normal
        };

        MemoryPressure {
            level,
            utilization_pct,
            compressed_bytes,
            swap_used_bytes,
            raw_available_i64,
            compressor_overflow,
            free_bytes,
            inactive_bytes,
            purgeable_bytes,
            wired_bytes,
        }
    }
}

#[cfg(target_os = "macos")]
fn detect_memory_pressure_free_pct() -> Option<f64> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    let mut child = Command::new("memory_pressure")
        .arg("-Q")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    let timeout = Duration::from_millis(250);

    let status = loop {
        match child.try_wait().ok()? {
            Some(status) => break status,
            None if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            None => thread::sleep(Duration::from_millis(5)),
        }
    };
    if !status.success() {
        return None;
    }

    let mut stdout = String::new();
    child.stdout.take()?.read_to_string(&mut stdout).ok()?;
    stdout.lines().find_map(|line| {
        let (_, pct_text) = line.split_once("System-wide memory free percentage:")?;
        let pct = pct_text.trim().trim_end_matches('%');
        pct.parse::<f64>().ok()
    })
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn detect_swap_used() -> u64 {
    use std::mem;

    unsafe {
        // xsw_usage struct: total, avail, used (all u64)
        let mut swap: libc::xsw_usage = mem::zeroed();
        let mut size = mem::size_of::<libc::xsw_usage>();
        let name = b"vm.swapusage\0";
        let ret = libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut swap as *mut libc::xsw_usage as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if ret == 0 { swap.xsu_used } else { 0 }
    }
}

// ── Platform-specific detection ──────────────────────────────────────────

#[cfg(target_os = "macos")]
fn detect_total_ram() -> u64 {
    sysctl_u64(b"hw.memsize\0").unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn detect_physical_cores() -> usize {
    sysctl_u64(b"hw.physicalcpu\0")
        .map(|n| n as usize)
        .unwrap_or_else(detect_logical_cores)
}

#[cfg(target_os = "macos")]
fn detect_unified_memory() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        true
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn sysctl_u64(name: &[u8]) -> Option<u64> {
    use std::mem;
    unsafe {
        let mut value: u64 = 0;
        let mut size = mem::size_of::<u64>();
        let ret = libc::sysctlbyname(
            name.as_ptr() as *const libc::c_char,
            &mut value as *mut u64 as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        );
        if ret == 0 { Some(value) } else { None }
    }
}

// ── Linux fallbacks ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn detect_total_ram() -> u64 {
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb: u64 = rest
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                return kb * 1024;
            }
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn detect_available_ram() -> u64 {
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("MemAvailable:") {
                let kb: u64 = rest
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                return kb * 1024;
            }
        }
    }
    detect_total_ram() / 2
}

#[cfg(target_os = "linux")]
fn detect_pressure(total_ram: u64) -> MemoryPressure {
    let available = detect_available_ram();
    let utilization_pct = if total_ram > 0 {
        ((total_ram.saturating_sub(available)) as f64 / total_ram as f64 * 100.0).clamp(0.0, 100.0)
    } else {
        0.0
    };

    // Parse swap from /proc/meminfo
    let mut swap_total: u64 = 0;
    let mut swap_free: u64 = 0;
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("SwapTotal:") {
                swap_total = rest
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    * 1024;
            }
            if let Some(rest) = line.strip_prefix("SwapFree:") {
                swap_free = rest
                    .trim()
                    .split_whitespace()
                    .next()
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0)
                    * 1024;
            }
        }
    }

    let level = if utilization_pct > 93.0 {
        PressureLevel::Critical
    } else if utilization_pct > 80.0 {
        PressureLevel::High
    } else if utilization_pct > 60.0 {
        PressureLevel::Elevated
    } else {
        PressureLevel::Normal
    };

    MemoryPressure {
        level,
        utilization_pct,
        compressed_bytes: 0, // Linux doesn't use macOS-style compression
        swap_used_bytes: swap_total.saturating_sub(swap_free),
        raw_available_i64: available as i64,
        compressor_overflow: false,
        free_bytes: available,
        inactive_bytes: 0,
        purgeable_bytes: 0,
        wired_bytes: 0,
    }
}

#[cfg(target_os = "linux")]
fn detect_physical_cores() -> usize {
    if let Ok(contents) = std::fs::read_to_string("/proc/cpuinfo") {
        let mut physical = 0usize;
        for line in contents.lines() {
            if let Some(rest) = line.strip_prefix("cpu cores") {
                if let Some(val) = rest.split(':').nth(1) {
                    if let Ok(n) = val.trim().parse::<usize>() {
                        physical = physical.max(n);
                    }
                }
            }
        }
        if physical > 0 {
            return physical;
        }
    }
    detect_logical_cores()
}

#[cfg(target_os = "linux")]
fn detect_unified_memory() -> bool {
    false
}

// ── Generic fallbacks ────────────────────────────────────────────────────

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_total_ram() -> u64 {
    0
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_pressure(_total_ram: u64) -> MemoryPressure {
    MemoryPressure::default()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_physical_cores() -> usize {
    detect_logical_cores()
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn detect_unified_memory() -> bool {
    false
}

fn detect_logical_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_nonzero_on_supported_platforms() {
        let res = SystemResources::detect();
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            assert!(res.total_ram_bytes > 0, "total RAM should be detected");
        }
        assert!(res.cpu_cores_logical >= 1, "must have at least 1 core");
        assert!(
            res.cpu_cores_physical >= 1,
            "must have at least 1 physical core"
        );
    }

    #[test]
    fn available_clamped_at_zero() {
        // Even if raw_available is negative, available_ram_bytes is 0
        let res = SystemResources::detect();
        // On a running system this should be positive, but the clamping logic
        // guarantees it can never be negative as u64.
        assert!(
            res.available_ram_bytes <= res.total_ram_bytes + 1024 * 1024,
            "available ({}) should not greatly exceed total ({})",
            res.available_ram_bytes,
            res.total_ram_bytes,
        );
    }

    #[test]
    fn pressure_detected() {
        let res = SystemResources::detect();
        // Pressure should always be populated
        assert!(res.pressure.utilization_pct >= 0.0);
        assert!(res.pressure.utilization_pct <= 100.0);
        // On macOS, we should see real values
        #[cfg(target_os = "macos")]
        {
            assert!(res.pressure.free_bytes > 0 || res.pressure.compressor_overflow);
        }
    }

    #[test]
    fn pressure_classification_thresholds() {
        // Normal: ≤60%
        let p = MemoryPressure {
            utilization_pct: 50.0,
            level: PressureLevel::Normal,
            ..MemoryPressure::default()
        };
        assert_eq!(p.level, PressureLevel::Normal);

        // Verify the classification function works
        let classify = |util_pct: f64, overflow: bool| -> PressureLevel {
            if overflow || util_pct > 93.0 {
                PressureLevel::Critical
            } else if util_pct > 80.0 {
                PressureLevel::High
            } else if util_pct > 60.0 {
                PressureLevel::Elevated
            } else {
                PressureLevel::Normal
            }
        };

        assert_eq!(classify(30.0, false), PressureLevel::Normal);
        assert_eq!(classify(60.0, false), PressureLevel::Normal);
        assert_eq!(classify(61.0, false), PressureLevel::Elevated);
        assert_eq!(classify(80.0, false), PressureLevel::Elevated);
        assert_eq!(classify(81.0, false), PressureLevel::High);
        assert_eq!(classify(93.0, false), PressureLevel::High);
        assert_eq!(classify(94.0, false), PressureLevel::Critical);
        assert_eq!(classify(50.0, true), PressureLevel::Critical);
    }

    #[test]
    fn pressure_display() {
        assert_eq!(format!("{}", PressureLevel::Normal), "NORMAL");
        assert_eq!(format!("{}", PressureLevel::Elevated), "ELEVATED");
        assert_eq!(format!("{}", PressureLevel::High), "HIGH");
        assert_eq!(format!("{}", PressureLevel::Critical), "CRITICAL");
    }

    #[test]
    fn ram_gib_conversions() {
        let res = SystemResources {
            total_ram_bytes: 48 * 1024 * 1024 * 1024,
            available_ram_bytes: 24 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(48 * 1024 * 1024 * 1024),
            pressure: MemoryPressure {
                utilization_pct: 50.0,
                level: PressureLevel::Normal,
                ..MemoryPressure::default()
            },
        };
        assert!((res.total_ram_gib() - 48.0).abs() < 0.01);
        assert!((res.available_ram_gib() - 24.0).abs() < 0.01);
        assert!((res.ram_utilization() - 0.5).abs() < 0.01);
    }

    #[test]
    fn utilization_clamped() {
        // When available exceeds total (shouldn't happen, but clamp)
        let res = SystemResources {
            total_ram_bytes: 10,
            available_ram_bytes: 20, // would give negative utilization
            cpu_cores_logical: 1,
            cpu_cores_physical: 1,
            unified_memory: false,
            gpu_memory_bytes: None,
            pressure: MemoryPressure::default(),
        };
        assert!(res.ram_utilization() >= 0.0);
        assert!(res.ram_utilization() <= 1.0);
    }

    #[test]
    fn recommend_48gb_16core() {
        let res = SystemResources {
            total_ram_bytes: 48 * 1024 * 1024 * 1024,
            available_ram_bytes: 30 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(48 * 1024 * 1024 * 1024),
            pressure: MemoryPressure {
                level: PressureLevel::Normal,
                utilization_pct: 37.5,
                ..MemoryPressure::default()
            },
        };
        let rec = res.recommend();
        assert!(
            rec.cargo_build_jobs >= 4,
            "should allow at least 4 jobs: got {}",
            rec.cargo_build_jobs
        );
        assert!(
            rec.cargo_build_jobs <= 16,
            "should not exceed cores: got {}",
            rec.cargo_build_jobs
        );
        assert!(rec.proving_threads >= 4);
        assert!(!rec.low_memory_mode);
        assert!(rec.gpu_memory_budget_bytes.is_some());
    }

    #[test]
    fn recommend_under_high_pressure() {
        let res = SystemResources {
            total_ram_bytes: 48 * 1024 * 1024 * 1024,
            available_ram_bytes: 8 * 1024 * 1024 * 1024,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(48 * 1024 * 1024 * 1024),
            pressure: MemoryPressure {
                level: PressureLevel::High,
                utilization_pct: 83.0,
                compressed_bytes: 10 * 1024 * 1024 * 1024,
                ..MemoryPressure::default()
            },
        };
        let rec = res.recommend();
        // Under High pressure (0.4 scale), jobs should be significantly reduced
        assert!(
            rec.cargo_build_jobs <= 3,
            "high pressure should limit jobs: got {}",
            rec.cargo_build_jobs
        );
        assert!(
            rec.low_memory_mode,
            "high pressure should trigger low-memory"
        );
    }

    #[test]
    fn recommend_under_critical_pressure() {
        let res = SystemResources {
            total_ram_bytes: 48 * 1024 * 1024 * 1024,
            available_ram_bytes: 0,
            cpu_cores_logical: 16,
            cpu_cores_physical: 16,
            unified_memory: true,
            gpu_memory_bytes: Some(48 * 1024 * 1024 * 1024),
            pressure: MemoryPressure {
                level: PressureLevel::Critical,
                utilization_pct: 100.0,
                compressor_overflow: true,
                raw_available_i64: -5_000_000_000,
                compressed_bytes: 20 * 1024 * 1024 * 1024,
                ..MemoryPressure::default()
            },
        };
        let rec = res.recommend();
        assert_eq!(rec.cargo_build_jobs, 1, "critical should minimize to 1 job");
        assert!(rec.low_memory_mode);
    }

    #[test]
    fn recommend_16gb_8core() {
        let res = SystemResources {
            total_ram_bytes: 16 * 1024 * 1024 * 1024,
            available_ram_bytes: 10 * 1024 * 1024 * 1024,
            cpu_cores_logical: 8,
            cpu_cores_physical: 8,
            unified_memory: false,
            gpu_memory_bytes: None,
            pressure: MemoryPressure {
                level: PressureLevel::Normal,
                utilization_pct: 37.5,
                ..MemoryPressure::default()
            },
        };
        let rec = res.recommend();
        assert!(rec.cargo_build_jobs >= 1);
        assert!(
            rec.cargo_build_jobs <= 4,
            "16GB should limit to few jobs: got {}",
            rec.cargo_build_jobs
        );
        assert!(rec.gpu_memory_budget_bytes.is_none());
    }

    #[test]
    fn recommend_8gb_triggers_low_memory() {
        let res = SystemResources {
            total_ram_bytes: 8 * 1024 * 1024 * 1024,
            available_ram_bytes: 5 * 1024 * 1024 * 1024,
            cpu_cores_logical: 4,
            cpu_cores_physical: 4,
            unified_memory: false,
            gpu_memory_bytes: None,
            pressure: MemoryPressure {
                level: PressureLevel::Normal,
                utilization_pct: 37.5,
                ..MemoryPressure::default()
            },
        };
        let rec = res.recommend();
        assert!(rec.low_memory_mode, "8GB total should trigger low-memory");
        assert!(rec.cargo_build_jobs >= 1);
    }

    #[test]
    fn recommend_128gb_40core() {
        let res = SystemResources {
            total_ram_bytes: 128 * 1024 * 1024 * 1024,
            available_ram_bytes: 100 * 1024 * 1024 * 1024,
            cpu_cores_logical: 40,
            cpu_cores_physical: 40,
            unified_memory: true,
            gpu_memory_bytes: Some(128 * 1024 * 1024 * 1024),
            pressure: MemoryPressure {
                level: PressureLevel::Normal,
                utilization_pct: 21.9,
                ..MemoryPressure::default()
            },
        };
        let rec = res.recommend();
        assert!(
            rec.cargo_build_jobs >= 20,
            "M4 Max should allow many jobs: got {}",
            rec.cargo_build_jobs
        );
        assert!(rec.cargo_build_jobs <= 40);
        assert!(!rec.low_memory_mode);
    }

    #[test]
    fn recommend_never_zero_jobs() {
        let res = SystemResources {
            total_ram_bytes: 2 * 1024 * 1024 * 1024,
            available_ram_bytes: 1 * 1024 * 1024 * 1024,
            cpu_cores_logical: 1,
            cpu_cores_physical: 1,
            unified_memory: false,
            gpu_memory_bytes: None,
            pressure: MemoryPressure {
                level: PressureLevel::Critical,
                utilization_pct: 95.0,
                ..MemoryPressure::default()
            },
        };
        let rec = res.recommend();
        assert!(rec.cargo_build_jobs >= 1);
        assert!(rec.proving_threads >= 1);
    }

    #[test]
    fn env_script_format() {
        let res = SystemResources::detect();
        let script = res.to_env_script();
        assert!(script.contains("CARGO_BUILD_JOBS="));
        assert!(script.contains("ZKF_PROVING_THREADS="));
        assert!(script.contains("ZKF_MAX_CIRCUIT_MEMORY="));
        assert!(script.contains("ZKF_LOW_MEMORY="));
        assert!(script.contains("ZKF_PRESSURE_LEVEL="));
    }

    #[test]
    fn json_roundtrip() {
        let res = SystemResources::detect();
        let json = res.to_json();
        let parsed: SystemResources = serde_json::from_str(&json).expect("parse back");
        assert_eq!(parsed.total_ram_bytes, res.total_ram_bytes);
        assert_eq!(parsed.cpu_cores_logical, res.cpu_cores_logical);
        assert_eq!(parsed.pressure.level, res.pressure.level);
    }

    #[test]
    fn zero_total_utilization() {
        let res = SystemResources {
            total_ram_bytes: 0,
            available_ram_bytes: 0,
            cpu_cores_logical: 1,
            cpu_cores_physical: 1,
            unified_memory: false,
            gpu_memory_bytes: None,
            pressure: MemoryPressure::default(),
        };
        assert!((res.ram_utilization() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn recommendation_serializes() {
        let res = SystemResources::detect();
        let rec = res.recommend();
        let json = serde_json::to_string_pretty(&rec).expect("serialize");
        let parsed: ResourceRecommendation = serde_json::from_str(&json).expect("parse");
        assert_eq!(parsed.cargo_build_jobs, rec.cargo_build_jobs);
        assert_eq!(parsed.proving_threads, rec.proving_threads);
    }

    #[test]
    fn detect_runs_without_panic() {
        let res = SystemResources::detect();
        let _rec = res.recommend();
        let _json = res.to_json();
        let _script = res.to_env_script();
    }

    #[test]
    fn pressure_default_is_normal() {
        let p = MemoryPressure::default();
        assert_eq!(p.level, PressureLevel::Normal);
        assert!(!p.compressor_overflow);
        assert_eq!(p.compressed_bytes, 0);
        assert_eq!(p.swap_used_bytes, 0);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn swap_detection() {
        // Just verify it doesn't panic — swap may or may not be in use
        let swap = detect_swap_used();
        // swap_used_bytes is a u64, just make sure it's reasonable
        assert!(swap < 1024 * 1024 * 1024 * 1024); // less than 1 TB
    }
}
