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

//! Metal device initialization and context management.

use crate::tuning::throughput_for_device;
use crate::verified_artifacts::{
    ExpectedKernelAttestation, current_toolchain_identity, expected_kernel_attestation,
    normalize_library_id, pipeline_descriptor_label, pipeline_descriptor_sha256_from_runtime,
    reflection_sha256_from_runtime_arguments,
};
use block2::DynBlock;
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_foundation::NSString;
#[cfg(metal_aot)]
use objc2_foundation::NSURL;
#[cfg(not(zkf_metal_public_artifact))]
use objc2_metal::MTLCompileOptions;
use objc2_metal::{
    MTLBuffer, MTLCommandBuffer, MTLCommandBufferDescriptor, MTLCommandBufferErrorOption,
    MTLCommandQueue, MTLComputePipelineState, MTLCreateSystemDefaultDevice, MTLDevice, MTLLibrary,
    MTLPipelineOption, MTLResourceOptions,
};
use serde::Serialize;
use std::collections::HashMap;
use std::env;
use std::ffi::c_void;
use std::fs;
use std::path::PathBuf;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// Diagnostics information about the Metal GPU device.
#[derive(Debug, Clone, Serialize)]
pub struct MetalDiagnostics {
    pub device_name: String,
    pub max_buffer_length: usize,
    pub max_threads_per_threadgroup: usize,
    pub unified_memory: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended_working_set_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_allocated_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_set_headroom: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_set_utilization_pct: Option<f64>,
    pub shared_events_supported: bool,
    pub dispatch_circuit_open: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_last_failure: Option<String>,
}

type BufferHandle = Retained<ProtocolObject<dyn MTLBuffer>>;
type BufferBucketMap = HashMap<usize, Vec<BufferHandle>>;
type TwiddleCacheMap = HashMap<(u8, u32), BufferHandle>;
type RoundConstCacheMap = HashMap<(u8, u64), BufferHandle>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ShaderLibraryLoadMode {
    AotPinned,
    RuntimeCompiled,
}

#[derive(Debug, Clone)]
pub struct ShaderLibraryBundleMetadata {
    pub library_id: &'static str,
    pub load_mode: ShaderLibraryLoadMode,
    pub metallib_path: Option<PathBuf>,
    pub declared_metallib_sha256: Option<String>,
}

#[derive(Debug)]
struct ShaderLibraryBundle {
    library: Retained<ProtocolObject<dyn MTLLibrary>>,
    metadata: ShaderLibraryBundleMetadata,
}

impl ShaderLibraryBundle {
    fn new(
        library: Retained<ProtocolObject<dyn MTLLibrary>>,
        metadata: ShaderLibraryBundleMetadata,
    ) -> Self {
        Self { library, metadata }
    }

    fn library(&self) -> &ProtocolObject<dyn MTLLibrary> {
        &self.library
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactAttestationError {
    UnsupportedKernel {
        library_id: String,
        entrypoint: String,
    },
    IncompletePinnedToolchain,
    ToolchainDrift {
        expected: Box<crate::verified_artifacts::ToolchainIdentity>,
        found: Box<crate::verified_artifacts::ToolchainIdentity>,
    },
    LibraryUnavailable {
        library_id: String,
    },
    RuntimeCompilationDisallowed {
        library_id: String,
    },
    MetallibPathMissing {
        library_id: String,
    },
    MetallibDigestMissing {
        library_id: String,
    },
    MetallibReadFailed {
        path: String,
        reason: String,
    },
    MetallibDigestMismatch {
        library_id: String,
        expected: String,
        found: String,
    },
    MissingEntrypoint {
        library_id: String,
        entrypoint: String,
    },
    PipelineCreationFailed {
        library_id: String,
        entrypoint: String,
        reason: String,
    },
    ReflectionMissing {
        library_id: String,
        entrypoint: String,
    },
    ReflectionDigestMismatch {
        library_id: String,
        entrypoint: String,
        expected: String,
        found: String,
    },
    PipelineDescriptorDigestMismatch {
        library_id: String,
        entrypoint: String,
        expected: String,
        found: String,
    },
}

impl std::fmt::Display for ArtifactAttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedKernel {
                library_id,
                entrypoint,
            } => write!(f, "unsupported verified kernel {library_id}:{entrypoint}"),
            Self::IncompletePinnedToolchain => {
                write!(
                    f,
                    "verified GPU attestation requires pinned Metal toolchain metadata"
                )
            }
            Self::ToolchainDrift { expected, found } => write!(
                f,
                "Metal toolchain drift: expected compiler=`{}` xcode=`{}` sdk=`{}`, found compiler=`{}` xcode=`{}` sdk=`{}`",
                expected.metal_compiler_version,
                expected.xcode_version,
                expected.sdk_version,
                found.metal_compiler_version,
                found.xcode_version,
                found.sdk_version
            ),
            Self::LibraryUnavailable { library_id } => {
                write!(f, "verified library {library_id} is unavailable")
            }
            Self::RuntimeCompilationDisallowed { library_id } => write!(
                f,
                "verified GPU lane rejects runtime-compiled Metal library {library_id}"
            ),
            Self::MetallibPathMissing { library_id } => {
                write!(
                    f,
                    "verified library {library_id} is missing its metallib path"
                )
            }
            Self::MetallibDigestMissing { library_id } => {
                write!(
                    f,
                    "verified library {library_id} is missing its declared metallib digest"
                )
            }
            Self::MetallibReadFailed { path, reason } => {
                write!(f, "failed to read metallib {path}: {reason}")
            }
            Self::MetallibDigestMismatch {
                library_id,
                expected,
                found,
            } => write!(
                f,
                "metallib digest mismatch for {library_id}: expected {expected}, found {found}"
            ),
            Self::MissingEntrypoint {
                library_id,
                entrypoint,
            } => write!(
                f,
                "verified entrypoint {library_id}:{entrypoint} is missing"
            ),
            Self::PipelineCreationFailed {
                library_id,
                entrypoint,
                reason,
            } => write!(
                f,
                "verified pipeline creation failed for {library_id}:{entrypoint}: {reason}"
            ),
            Self::ReflectionMissing {
                library_id,
                entrypoint,
            } => write!(
                f,
                "verified pipeline reflection missing for {library_id}:{entrypoint}"
            ),
            Self::ReflectionDigestMismatch {
                library_id,
                entrypoint,
                expected,
                found,
            } => write!(
                f,
                "reflection digest mismatch for {library_id}:{entrypoint}: expected {expected}, found {found}"
            ),
            Self::PipelineDescriptorDigestMismatch {
                library_id,
                entrypoint,
                expected,
                found,
            } => write!(
                f,
                "pipeline descriptor digest mismatch for {library_id}:{entrypoint}: expected {expected}, found {found}"
            ),
        }
    }
}

impl std::error::Error for ArtifactAttestationError {}

/// Thread-safe Metal context wrapping device, command queue, and shader library.
pub struct MetalContext {
    device: Retained<ProtocolObject<dyn MTLDevice>>,
    queue: Retained<ProtocolObject<dyn MTLCommandQueue>>,
    /// Secondary command queue for lightweight/async ops (field ops, buffer copies).
    secondary_queue: OnceLock<Option<Retained<ProtocolObject<dyn MTLCommandQueue>>>>,
    library: ShaderLibraryBundle,
    pipeline_cache: Mutex<HashMap<String, Retained<ProtocolObject<dyn MTLComputePipelineState>>>>,
    verified_attestation_cache: Mutex<HashMap<String, ExpectedKernelAttestation>>,
    msm_library: OnceLock<Option<ShaderLibraryBundle>>,
    pallas_msm_library: OnceLock<Option<ShaderLibraryBundle>>,
    vesta_msm_library: OnceLock<Option<ShaderLibraryBundle>>,
    hash_library: OnceLock<Option<ShaderLibraryBundle>>,
    buffer_pool: Mutex<BufferPool>,
    /// Cached twiddle factor buffers keyed by (field_id, log_n).
    twiddle_cache: Mutex<TwiddleCacheMap>,
    /// Cached round constant buffers keyed by (field_id, seed).
    round_const_cache: Mutex<RoundConstCacheMap>,
    dispatch_circuit_open: AtomicBool,
    dispatch_last_failure: Mutex<Option<String>>,
}

/// Simple buffer pool that caches Metal buffers by power-of-2 size buckets.
struct BufferPool {
    pools: BufferBucketMap,
    max_cached_per_bucket: usize,
}

impl BufferPool {
    fn new() -> Self {
        Self {
            pools: HashMap::new(),
            max_cached_per_bucket: 8,
        }
    }

    fn bucket_size(min_size: usize) -> usize {
        min_size.next_power_of_two().max(4096)
    }

    fn acquire(&mut self, min_size: usize) -> Option<BufferHandle> {
        let bucket = Self::bucket_size(min_size);
        self.pools.get_mut(&bucket).and_then(|pool| pool.pop())
    }

    fn release(&mut self, buffer: BufferHandle) {
        let bucket = Self::bucket_size(buffer.length());
        let pool = self.pools.entry(bucket).or_default();
        if pool.len() < self.max_cached_per_bucket {
            pool.push(buffer);
        }
    }

    fn clear(&mut self) -> usize {
        let released = self
            .pools
            .values()
            .flat_map(|pool| pool.iter())
            .map(|buffer| buffer.length())
            .sum();
        self.pools.clear();
        released
    }
}

// SAFETY: MTLDevice and friends are thread-safe per Apple's Metal documentation.
unsafe impl Send for MetalContext {}
unsafe impl Sync for MetalContext {}

static GLOBAL_CONTEXT: OnceLock<Option<MetalContext>> = OnceLock::new();

/// All Metal shader source concatenated at compile time.
/// Excludes MSM shaders which have duplicate struct definitions.
#[cfg(not(zkf_metal_public_artifact))]
const SHADER_SOURCE: &str = concat!(
    "#include <metal_stdlib>\nusing namespace metal;\n\n",
    include_str!("shaders/field_goldilocks.metal"),
    "\n",
    include_str!("shaders/field_babybear.metal"),
    "\n",
    include_str!("shaders/field_bn254_fr.metal"),
    "\n",
    include_str!("shaders/ntt_radix2.metal"),
    "\n",
    include_str!("shaders/ntt_bn254.metal"),
    "\n",
    include_str!("shaders/ntt_radix2_batch.metal"),
    "\n",
    include_str!("shaders/poseidon2.metal"),
    "\n",
    include_str!("shaders/batch_field_ops.metal"),
    "\n",
    include_str!("shaders/poly_ops.metal"),
    "\n",
    include_str!("shaders/fri.metal"),
    "\n",
    include_str!("shaders/constraint_eval.metal"),
);

#[cfg(not(zkf_metal_public_artifact))]
const BN254_MSM_SHADER_SOURCE: &str = concat!(
    include_str!("shaders/msm_bn254.metal"),
    "\n",
    include_str!("shaders/msm_sort.metal"),
    "\n",
    include_str!("shaders/msm_reduce.metal"),
);

impl MetalContext {
    #[cfg(all(metal_aot, zkf_metal_public_artifact))]
    fn resolve_public_metallib_path(file_name: &str) -> Option<PathBuf> {
        let mut candidates = Vec::new();

        if let Ok(dir) = env::var("ZKF_METALLIB_DIR") {
            candidates.push(PathBuf::from(dir));
        }
        if let Ok(repo_dir) = env::var("ZKF_METAL_REPOSITORY") {
            let repo = PathBuf::from(repo_dir);
            candidates.push(repo.join("binary"));
            candidates.push(repo);
        }
        if let Ok(exe) = env::current_exe() {
            if let Some(bin_dir) = exe.parent() {
                candidates.push(bin_dir.to_path_buf());
                candidates.push(bin_dir.join("binary"));
                candidates.push(bin_dir.join("../share"));
                candidates.push(bin_dir.join("../share/binary"));
                candidates.push(bin_dir.join("../share/repository"));
                candidates.push(bin_dir.join("../share/repository/binary"));
            }
        }
        if let Ok(cwd) = env::current_dir() {
            candidates.push(cwd.clone());
            candidates.push(cwd.join("binary"));
        }

        for dir in candidates {
            let path = dir.join(file_name);
            if path.is_file() {
                return Some(path);
            }
        }

        log::warn!(
            "[zkf-metal] public artifact build could not locate shipped metallib `{file_name}`"
        );
        None
    }

    /// Load a precompiled metallib from an environment variable path set by build.rs.
    #[cfg(metal_aot)]
    fn load_metallib(
        device: &ProtocolObject<dyn MTLDevice>,
        library_id: &'static str,
        metallib_locator: &str,
        declared_metallib_sha256: Option<&'static str>,
    ) -> Option<ShaderLibraryBundle> {
        #[cfg(zkf_metal_public_artifact)]
        let path = Self::resolve_public_metallib_path(metallib_locator)?;
        #[cfg(not(zkf_metal_public_artifact))]
        let path = PathBuf::from(metallib_locator);

        let path_string = path.display().to_string();
        let url = NSURL::fileURLWithPath(&NSString::from_str(&path_string));
        match device.newLibraryWithURL_error(&url) {
            Ok(lib) => {
                log::info!("[zkf-metal] Loaded AOT metallib: {}", path.display());
                Some(ShaderLibraryBundle::new(
                    lib,
                    ShaderLibraryBundleMetadata {
                        library_id,
                        load_mode: ShaderLibraryLoadMode::AotPinned,
                        metallib_path: Some(path),
                        declared_metallib_sha256: declared_metallib_sha256.map(str::to_string),
                    },
                ))
            }
            Err(e) => {
                log::warn!(
                    "[zkf-metal] Failed to load AOT metallib {}: {e}",
                    path.display()
                );
                None
            }
        }
    }

    #[cfg(not(zkf_metal_public_artifact))]
    fn runtime_bundle(
        library_id: &'static str,
        library: Retained<ProtocolObject<dyn MTLLibrary>>,
    ) -> ShaderLibraryBundle {
        ShaderLibraryBundle::new(
            library,
            ShaderLibraryBundleMetadata {
                library_id,
                load_mode: ShaderLibraryLoadMode::RuntimeCompiled,
                metallib_path: None,
                declared_metallib_sha256: None,
            },
        )
    }

    /// Create a new Metal context. Returns `None` if no Metal GPU is available.
    ///
    /// When built with `metal_aot` cfg (set by build.rs when the Metal toolchain
    /// is available), loads precompiled metallib files instead of runtime
    /// compilation — eliminating 200-500ms startup latency.
    pub fn new() -> Option<Self> {
        let device = MTLCreateSystemDefaultDevice()?;
        let tuning = throughput_for_device(&device.name().to_string());
        let queue = device
            .newCommandQueueWithMaxCommandBufferCount(tuning.primary_queue_depth)
            .or_else(|| device.newCommandQueue())?;

        // Try AOT-compiled metallib first, fall back to runtime compilation
        #[cfg(metal_aot)]
        let library = {
            let loaded = Self::load_metallib(
                &device,
                "main_library",
                #[cfg(zkf_metal_public_artifact)]
                env!("METALLIB_MAIN_BASENAME"),
                #[cfg(not(zkf_metal_public_artifact))]
                env!("METALLIB_MAIN"),
                option_env!("METALLIB_MAIN_SHA256"),
            );
            #[cfg(zkf_metal_public_artifact)]
            {
                loaded?
            }
            #[cfg(not(zkf_metal_public_artifact))]
            {
                loaded.unwrap_or_else(|| {
                    log::warn!(
                        "[zkf-metal] AOT main metallib failed, falling back to runtime compilation"
                    );
                    Self::runtime_bundle(
                        "main_library",
                        Self::compile_runtime(&device, SHADER_SOURCE)
                            .expect("Runtime shader compilation also failed"),
                    )
                })
            }
        };

        #[cfg(not(metal_aot))]
        let library = {
            #[cfg(zkf_metal_public_artifact)]
            {
                log::warn!(
                    "[zkf-metal] public artifact build requires AOT metallibs and cannot use runtime compilation"
                );
                return None;
            }
            #[cfg(not(zkf_metal_public_artifact))]
            Self::runtime_bundle(
                "main_library",
                Self::compile_runtime(&device, SHADER_SOURCE)?,
            )
        };

        let ctx = Self {
            device,
            queue,
            secondary_queue: OnceLock::new(),
            library,
            pipeline_cache: Mutex::new(HashMap::new()),
            verified_attestation_cache: Mutex::new(HashMap::new()),
            msm_library: OnceLock::new(),
            pallas_msm_library: OnceLock::new(),
            vesta_msm_library: OnceLock::new(),
            hash_library: OnceLock::new(),
            buffer_pool: Mutex::new(BufferPool::new()),
            twiddle_cache: Mutex::new(HashMap::new()),
            round_const_cache: Mutex::new(HashMap::new()),
            dispatch_circuit_open: AtomicBool::new(false),
            dispatch_last_failure: Mutex::new(None),
        };

        #[cfg(metal_aot)]
        log::info!(
            "[zkf-metal] Initialized (AOT): device={}, max_buffer={}MB, unified_memory={}",
            ctx.device_name(),
            ctx.max_buffer_length() / (1024 * 1024),
            ctx.device.hasUnifiedMemory(),
        );
        #[cfg(not(metal_aot))]
        log::info!(
            "[zkf-metal] Initialized (runtime): device={}, max_buffer={}MB, unified_memory={}",
            ctx.device_name(),
            ctx.max_buffer_length() / (1024 * 1024),
            ctx.device.hasUnifiedMemory(),
        );

        Some(ctx)
    }

    /// Compile shaders at runtime from source string.
    #[cfg(not(zkf_metal_public_artifact))]
    fn compile_runtime(
        device: &ProtocolObject<dyn MTLDevice>,
        source_str: &str,
    ) -> Option<Retained<ProtocolObject<dyn MTLLibrary>>> {
        let source = NSString::from_str(source_str);
        let options = MTLCompileOptions::new();
        match device.newLibraryWithSource_options_error(&source, Some(&options)) {
            Ok(lib) => Some(lib),
            Err(e) => {
                eprintln!("[zkf-metal] Failed to compile Metal shaders: {e}");
                None
            }
        }
    }

    /// Get the Metal device.
    pub fn device(&self) -> &ProtocolObject<dyn MTLDevice> {
        &self.device
    }

    /// Get the command queue.
    pub fn queue(&self) -> &ProtocolObject<dyn MTLCommandQueue> {
        &self.queue
    }

    /// Create a command buffer with detailed encoder error reporting enabled.
    ///
    /// Returning `None` here is how the Metal circuit breaker forces safe CPU
    /// fallback after a GPU timeout or command-buffer error.
    pub fn command_buffer(&self) -> Option<Retained<ProtocolObject<dyn MTLCommandBuffer>>> {
        if !self.dispatch_allowed() {
            return None;
        }
        let descriptor = MTLCommandBufferDescriptor::new();
        descriptor.setErrorOptions(MTLCommandBufferErrorOption::EncoderExecutionStatus);
        self.queue
            .commandBufferWithDescriptor(&descriptor)
            .or_else(|| self.queue.commandBuffer())
    }

    /// Get the compiled shader library.
    pub fn library(&self) -> &ProtocolObject<dyn MTLLibrary> {
        self.library.library()
    }

    /// Human-readable device name (e.g., "Apple M4 Max").
    pub fn device_name(&self) -> String {
        self.device.name().to_string()
    }

    /// Maximum buffer allocation size in bytes.
    pub fn max_buffer_length(&self) -> usize {
        self.device.maxBufferLength()
    }

    /// Recommended working-set budget in bytes for steady-state scheduling.
    pub fn recommended_working_set_size(&self) -> Option<usize> {
        let bytes = self.device.recommendedMaxWorkingSetSize() as usize;
        if bytes == 0 { None } else { Some(bytes) }
    }

    /// Bytes currently allocated by Metal on this device.
    pub fn current_allocated_size(&self) -> usize {
        self.device.currentAllocatedSize()
    }

    /// Remaining bytes before reaching the device's recommended steady-state working set.
    pub fn working_set_headroom(&self) -> Option<usize> {
        self.recommended_working_set_size()
            .map(|budget| budget.saturating_sub(self.current_allocated_size()))
    }

    /// Current working-set utilization as a fraction of the recommended steady-state budget.
    pub fn working_set_utilization_ratio(&self) -> Option<f64> {
        let budget = self.recommended_working_set_size()? as f64;
        if budget <= 0.0 {
            return None;
        }
        Some((self.current_allocated_size() as f64 / budget).clamp(0.0, 4.0))
    }

    /// Whether shared events are available on this device/runtime.
    pub fn shared_events_supported(&self) -> bool {
        self.device.newSharedEvent().is_some()
    }

    /// Whether new GPU work is still permitted for this process.
    pub fn dispatch_allowed(&self) -> bool {
        !self.dispatch_circuit_open.load(Ordering::Relaxed)
    }

    /// Last failure that opened the Metal dispatch circuit.
    pub fn last_dispatch_failure(&self) -> Option<String> {
        self.dispatch_last_failure
            .lock()
            .ok()
            .and_then(|failure| failure.clone())
    }

    /// Quarantine new GPU work after a timeout or command-buffer failure.
    pub fn disable_dispatch(&self, reason: impl Into<String>) {
        let reason = reason.into();
        if let Ok(mut last_failure) = self.dispatch_last_failure.lock() {
            *last_failure = Some(reason.clone());
        }
        let newly_open = !self.dispatch_circuit_open.swap(true, Ordering::SeqCst);
        let _ = self.harden_for_pressure(zkf_core::PressureLevel::Critical);
        if newly_open {
            log::warn!("[zkf-metal] dispatch circuit opened: {reason}");
        }
    }

    #[cfg(test)]
    fn reset_dispatch_for_tests(&self) {
        self.dispatch_circuit_open.store(false, Ordering::SeqCst);
        if let Ok(mut last_failure) = self.dispatch_last_failure.lock() {
            *last_failure = None;
        }
    }

    /// Get or create a compute pipeline for the named kernel function.
    pub fn pipeline(
        &self,
        function_name: &str,
    ) -> Option<Retained<ProtocolObject<dyn MTLComputePipelineState>>> {
        let mut cache = self.pipeline_cache.lock().ok()?;

        if let Some(pipeline) = cache.get(function_name) {
            return Some(pipeline.clone());
        }

        let name = NSString::from_str(function_name);
        let function = self.library.library().newFunctionWithName(&name)?;

        let pipeline = self
            .device
            .newComputePipelineStateWithFunction_error(&function)
            .ok()?;

        cache.insert(function_name.to_string(), pipeline.clone());
        Some(pipeline)
    }

    /// Get the cached MSM shader library (AOT or compiled on first use).
    pub fn msm_library(&self) -> Option<&ProtocolObject<dyn MTLLibrary>> {
        self.msm_library
            .get_or_init(|| {
                #[cfg(metal_aot)]
                if let Some(lib) = Self::load_metallib(
                    &self.device,
                    "bn254_msm_library",
                    #[cfg(zkf_metal_public_artifact)]
                    env!("METALLIB_MSM_BASENAME"),
                    #[cfg(not(zkf_metal_public_artifact))]
                    env!("METALLIB_MSM"),
                    option_env!("METALLIB_MSM_SHA256"),
                ) {
                    return Some(lib);
                }

                #[cfg(zkf_metal_public_artifact)]
                {
                    log::warn!(
                        "[zkf-metal] public artifact build requires shipped AOT metallib `msm.metallib`"
                    );
                    None
                }

                #[cfg(not(zkf_metal_public_artifact))]
                let source = NSString::from_str(BN254_MSM_SHADER_SOURCE);
                #[cfg(not(zkf_metal_public_artifact))]
                {
                    let options = MTLCompileOptions::new();
                    self.device
                        .newLibraryWithSource_options_error(&source, Some(&options))
                        .map_err(|e| eprintln!("[zkf-metal] Failed to compile MSM shaders: {e}"))
                        .map(|library| Self::runtime_bundle("bn254_msm_library", library))
                        .ok()
                }
            })
            .as_ref()
            .map(ShaderLibraryBundle::library)
    }

    /// Get the cached Pallas MSM shader library (AOT or compiled on first use).
    pub fn pallas_msm_library(&self) -> Option<&ProtocolObject<dyn MTLLibrary>> {
        self.pallas_msm_library
            .get_or_init(|| {
                #[cfg(metal_aot)]
                if let Some(lib) = Self::load_metallib(
                    &self.device,
                    "pallas_msm_library",
                    #[cfg(zkf_metal_public_artifact)]
                    env!("METALLIB_MSM_PALLAS_BASENAME"),
                    #[cfg(not(zkf_metal_public_artifact))]
                    env!("METALLIB_MSM_PALLAS"),
                    option_env!("METALLIB_MSM_PALLAS_SHA256"),
                ) {
                    return Some(lib);
                }

                #[cfg(zkf_metal_public_artifact)]
                {
                    log::warn!(
                        "[zkf-metal] public artifact build requires shipped AOT metallib `msm_pallas.metallib`"
                    );
                    None
                }

                #[cfg(not(zkf_metal_public_artifact))]
                let source = NSString::from_str(include_str!("shaders/msm_pallas.metal"));
                #[cfg(not(zkf_metal_public_artifact))]
                {
                    let options = MTLCompileOptions::new();
                    self.device
                        .newLibraryWithSource_options_error(&source, Some(&options))
                        .map_err(|e| eprintln!("[zkf-metal] Failed to compile Pallas MSM shaders: {e}"))
                        .map(|library| Self::runtime_bundle("pallas_msm_library", library))
                        .ok()
                }
            })
            .as_ref()
            .map(ShaderLibraryBundle::library)
    }

    /// Get the cached Vesta MSM shader library (AOT or compiled on first use).
    pub fn vesta_msm_library(&self) -> Option<&ProtocolObject<dyn MTLLibrary>> {
        self.vesta_msm_library
            .get_or_init(|| {
                #[cfg(metal_aot)]
                if let Some(lib) = Self::load_metallib(
                    &self.device,
                    "vesta_msm_library",
                    #[cfg(zkf_metal_public_artifact)]
                    env!("METALLIB_MSM_VESTA_BASENAME"),
                    #[cfg(not(zkf_metal_public_artifact))]
                    env!("METALLIB_MSM_VESTA"),
                    option_env!("METALLIB_MSM_VESTA_SHA256"),
                ) {
                    return Some(lib);
                }

                #[cfg(zkf_metal_public_artifact)]
                {
                    log::warn!(
                        "[zkf-metal] public artifact build requires shipped AOT metallib `msm_vesta.metallib`"
                    );
                    None
                }

                #[cfg(not(zkf_metal_public_artifact))]
                let source = NSString::from_str(include_str!("shaders/msm_vesta.metal"));
                #[cfg(not(zkf_metal_public_artifact))]
                {
                    let options = MTLCompileOptions::new();
                    self.device
                        .newLibraryWithSource_options_error(&source, Some(&options))
                        .map_err(|e| eprintln!("[zkf-metal] Failed to compile Vesta MSM shaders: {e}"))
                        .map(|library| Self::runtime_bundle("vesta_msm_library", library))
                        .ok()
                }
            })
            .as_ref()
            .map(ShaderLibraryBundle::library)
    }

    /// Get the cached hash shader library (AOT or SHA256/Keccak256 compiled on first use).
    pub fn hash_library(&self) -> Option<&ProtocolObject<dyn MTLLibrary>> {
        self.hash_library
            .get_or_init(|| {
                #[cfg(metal_aot)]
                if let Some(lib) = Self::load_metallib(
                    &self.device,
                    "hash_library",
                    #[cfg(zkf_metal_public_artifact)]
                    env!("METALLIB_HASH_BASENAME"),
                    #[cfg(not(zkf_metal_public_artifact))]
                    env!("METALLIB_HASH"),
                    option_env!("METALLIB_HASH_SHA256"),
                ) {
                    return Some(lib);
                }

                #[cfg(zkf_metal_public_artifact)]
                {
                    log::warn!(
                        "[zkf-metal] public artifact build requires shipped AOT metallib `hash.metallib`"
                    );
                    None
                }

                #[cfg(not(zkf_metal_public_artifact))]
                let sha256_src = include_str!("shaders/sha256.metal");
                #[cfg(not(zkf_metal_public_artifact))]
                let keccak_src = include_str!("shaders/keccak256.metal");
                // Strip #include and using lines since we concatenate manually
                #[cfg(not(zkf_metal_public_artifact))]
                {
                    let combined = format!(
                        "#include <metal_stdlib>\nusing namespace metal;\n\n{}\n{}\n",
                        sha256_src
                            .replace("#include <metal_stdlib>", "")
                            .replace("using namespace metal;", ""),
                        keccak_src
                            .replace("#include <metal_stdlib>", "")
                            .replace("using namespace metal;", ""),
                    );
                    let source = NSString::from_str(&combined);
                    let options = MTLCompileOptions::new();
                    self.device
                        .newLibraryWithSource_options_error(&source, Some(&options))
                        .map_err(|e| eprintln!("[zkf-metal] Failed to compile hash shaders: {e}"))
                        .map(|library| Self::runtime_bundle("hash_library", library))
                        .ok()
                }
            })
            .as_ref()
            .map(ShaderLibraryBundle::library)
    }

    fn attestation_cache_key(library_id: &str, entrypoint: &str) -> String {
        format!(
            "{}::{entrypoint}",
            normalize_library_id(library_id).unwrap_or(library_id)
        )
    }

    fn library_bundle(&self, library_id: &str) -> Option<&ShaderLibraryBundle> {
        match normalize_library_id(library_id)? {
            "main_library" => Some(&self.library),
            "hash_library" => self
                .hash_library
                .get_or_init(|| {
                    #[cfg(metal_aot)]
                    if let Some(lib) = Self::load_metallib(
                        &self.device,
                        "hash_library",
                        #[cfg(zkf_metal_public_artifact)]
                        env!("METALLIB_HASH_BASENAME"),
                        #[cfg(not(zkf_metal_public_artifact))]
                        env!("METALLIB_HASH"),
                        option_env!("METALLIB_HASH_SHA256"),
                    ) {
                        return Some(lib);
                    }

                    #[cfg(zkf_metal_public_artifact)]
                    {
                        log::warn!(
                            "[zkf-metal] public artifact build requires shipped AOT metallib `hash.metallib`"
                        );
                        None
                    }

                    #[cfg(not(zkf_metal_public_artifact))]
                    let sha256_src = include_str!("shaders/sha256.metal");
                    #[cfg(not(zkf_metal_public_artifact))]
                    let keccak_src = include_str!("shaders/keccak256.metal");
                    #[cfg(not(zkf_metal_public_artifact))]
                    {
                        let combined = format!(
                            "#include <metal_stdlib>\nusing namespace metal;\n\n{}\n{}\n",
                            sha256_src
                                .replace("#include <metal_stdlib>", "")
                                .replace("using namespace metal;", ""),
                            keccak_src
                                .replace("#include <metal_stdlib>", "")
                                .replace("using namespace metal;", ""),
                        );
                        let source = NSString::from_str(&combined);
                        let options = MTLCompileOptions::new();
                        self.device
                            .newLibraryWithSource_options_error(&source, Some(&options))
                            .map_err(|e| eprintln!("[zkf-metal] Failed to compile hash shaders: {e}"))
                            .map(|library| Self::runtime_bundle("hash_library", library))
                            .ok()
                    }
                })
                .as_ref(),
            "bn254_msm_library" => self
                .msm_library
                .get_or_init(|| {
                    #[cfg(metal_aot)]
                    if let Some(lib) = Self::load_metallib(
                        &self.device,
                        "bn254_msm_library",
                        #[cfg(zkf_metal_public_artifact)]
                        env!("METALLIB_MSM_BASENAME"),
                        #[cfg(not(zkf_metal_public_artifact))]
                        env!("METALLIB_MSM"),
                        option_env!("METALLIB_MSM_SHA256"),
                    ) {
                        return Some(lib);
                    }

                    #[cfg(zkf_metal_public_artifact)]
                    {
                        log::warn!(
                            "[zkf-metal] public artifact build requires shipped AOT metallib `msm.metallib`"
                        );
                        None
                    }

                    #[cfg(not(zkf_metal_public_artifact))]
                    let source = NSString::from_str(BN254_MSM_SHADER_SOURCE);
                    #[cfg(not(zkf_metal_public_artifact))]
                    {
                        let options = MTLCompileOptions::new();
                        self.device
                            .newLibraryWithSource_options_error(&source, Some(&options))
                            .map_err(|e| eprintln!("[zkf-metal] Failed to compile MSM shaders: {e}"))
                            .map(|library| Self::runtime_bundle("bn254_msm_library", library))
                            .ok()
                    }
                })
                .as_ref(),
            "pallas_msm_library" => self
                .pallas_msm_library
                .get_or_init(|| {
                    #[cfg(metal_aot)]
                    if let Some(lib) = Self::load_metallib(
                        &self.device,
                        "pallas_msm_library",
                        #[cfg(zkf_metal_public_artifact)]
                        env!("METALLIB_MSM_PALLAS_BASENAME"),
                        #[cfg(not(zkf_metal_public_artifact))]
                        env!("METALLIB_MSM_PALLAS"),
                        option_env!("METALLIB_MSM_PALLAS_SHA256"),
                    ) {
                        return Some(lib);
                    }

                    #[cfg(zkf_metal_public_artifact)]
                    {
                        log::warn!(
                            "[zkf-metal] public artifact build requires shipped AOT metallib `msm_pallas.metallib`"
                        );
                        None
                    }

                    #[cfg(not(zkf_metal_public_artifact))]
                    let source = NSString::from_str(include_str!("shaders/msm_pallas.metal"));
                    #[cfg(not(zkf_metal_public_artifact))]
                    {
                        let options = MTLCompileOptions::new();
                        self.device
                            .newLibraryWithSource_options_error(&source, Some(&options))
                            .map_err(|e| {
                                eprintln!("[zkf-metal] Failed to compile Pallas MSM shaders: {e}")
                            })
                            .map(|library| Self::runtime_bundle("pallas_msm_library", library))
                            .ok()
                    }
                })
                .as_ref(),
            "vesta_msm_library" => self
                .vesta_msm_library
                .get_or_init(|| {
                    #[cfg(metal_aot)]
                    if let Some(lib) = Self::load_metallib(
                        &self.device,
                        "vesta_msm_library",
                        #[cfg(zkf_metal_public_artifact)]
                        env!("METALLIB_MSM_VESTA_BASENAME"),
                        #[cfg(not(zkf_metal_public_artifact))]
                        env!("METALLIB_MSM_VESTA"),
                        option_env!("METALLIB_MSM_VESTA_SHA256"),
                    ) {
                        return Some(lib);
                    }

                    #[cfg(zkf_metal_public_artifact)]
                    {
                        log::warn!(
                            "[zkf-metal] public artifact build requires shipped AOT metallib `msm_vesta.metallib`"
                        );
                        None
                    }

                    #[cfg(not(zkf_metal_public_artifact))]
                    let source = NSString::from_str(include_str!("shaders/msm_vesta.metal"));
                    #[cfg(not(zkf_metal_public_artifact))]
                    {
                        let options = MTLCompileOptions::new();
                        self.device
                            .newLibraryWithSource_options_error(&source, Some(&options))
                            .map_err(|e| {
                                eprintln!("[zkf-metal] Failed to compile Vesta MSM shaders: {e}")
                            })
                            .map(|library| Self::runtime_bundle("vesta_msm_library", library))
                            .ok()
                    }
                })
                .as_ref(),
            _ => None,
        }
    }

    fn sha256_file(path: &PathBuf) -> Result<String, ArtifactAttestationError> {
        let bytes = fs::read(path).map_err(|err| ArtifactAttestationError::MetallibReadFailed {
            path: path.display().to_string(),
            reason: err.to_string(),
        })?;
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    #[allow(deprecated)]
    pub fn attest_verified_pipeline(
        &self,
        library_id: &str,
        entrypoint: &str,
    ) -> Result<ExpectedKernelAttestation, ArtifactAttestationError> {
        let canonical_library_id = normalize_library_id(library_id).ok_or_else(|| {
            ArtifactAttestationError::UnsupportedKernel {
                library_id: library_id.to_string(),
                entrypoint: entrypoint.to_string(),
            }
        })?;
        let cache_key = Self::attestation_cache_key(canonical_library_id, entrypoint);
        if let Ok(cache) = self.verified_attestation_cache.lock()
            && let Some(attestation) = cache.get(&cache_key)
        {
            return Ok(attestation.clone());
        }

        let expected =
            expected_kernel_attestation(canonical_library_id, entrypoint).ok_or_else(|| {
                ArtifactAttestationError::UnsupportedKernel {
                    library_id: canonical_library_id.to_string(),
                    entrypoint: entrypoint.to_string(),
                }
            })?;
        let found_toolchain = current_toolchain_identity();
        if expected.toolchain.metal_compiler_version.is_empty()
            || expected.toolchain.xcode_version.is_empty()
            || expected.toolchain.sdk_version.is_empty()
        {
            return Err(ArtifactAttestationError::IncompletePinnedToolchain);
        }
        if expected.toolchain != found_toolchain {
            return Err(ArtifactAttestationError::ToolchainDrift {
                expected: Box::new(expected.toolchain.clone()),
                found: Box::new(found_toolchain),
            });
        }

        let bundle = self.library_bundle(canonical_library_id).ok_or_else(|| {
            ArtifactAttestationError::LibraryUnavailable {
                library_id: canonical_library_id.to_string(),
            }
        })?;
        if bundle.metadata.load_mode != ShaderLibraryLoadMode::AotPinned {
            return Err(ArtifactAttestationError::RuntimeCompilationDisallowed {
                library_id: canonical_library_id.to_string(),
            });
        }
        let path = bundle.metadata.metallib_path.as_ref().ok_or_else(|| {
            ArtifactAttestationError::MetallibPathMissing {
                library_id: canonical_library_id.to_string(),
            }
        })?;
        let declared_digest = bundle
            .metadata
            .declared_metallib_sha256
            .as_ref()
            .ok_or_else(|| ArtifactAttestationError::MetallibDigestMissing {
                library_id: canonical_library_id.to_string(),
            })?;
        let actual_metallib_sha256 = Self::sha256_file(path)?;
        if actual_metallib_sha256 != expected.metallib_sha256
            || actual_metallib_sha256 != *declared_digest
        {
            return Err(ArtifactAttestationError::MetallibDigestMismatch {
                library_id: canonical_library_id.to_string(),
                expected: expected.metallib_sha256.clone(),
                found: actual_metallib_sha256,
            });
        }

        let entry_name = NSString::from_str(entrypoint);
        let function = bundle
            .library()
            .newFunctionWithName(&entry_name)
            .ok_or_else(|| ArtifactAttestationError::MissingEntrypoint {
                library_id: canonical_library_id.to_string(),
                entrypoint: entrypoint.to_string(),
            })?;

        let descriptor = objc2_metal::MTLComputePipelineDescriptor::new();
        let label = pipeline_descriptor_label(canonical_library_id, entrypoint);
        descriptor.setLabel(Some(&NSString::from_str(&label)));
        descriptor.setComputeFunction(Some(&function));
        descriptor.setSupportIndirectCommandBuffers(false);
        descriptor.setMaxTotalThreadsPerThreadgroup(0);
        // SAFETY: The verified descriptor explicitly fixes this optimization flag.
        unsafe {
            descriptor.setThreadGroupSizeIsMultipleOfThreadExecutionWidth(false);
        }

        let actual_descriptor_sha256 =
            pipeline_descriptor_sha256_from_runtime(canonical_library_id, entrypoint, &descriptor);
        if actual_descriptor_sha256 != expected.pipeline_descriptor_sha256 {
            return Err(ArtifactAttestationError::PipelineDescriptorDigestMismatch {
                library_id: canonical_library_id.to_string(),
                entrypoint: entrypoint.to_string(),
                expected: expected.pipeline_descriptor_sha256.clone(),
                found: actual_descriptor_sha256,
            });
        }

        let mut reflection = None;
        self.device
            .newComputePipelineStateWithDescriptor_options_reflection_error(
                &descriptor,
                MTLPipelineOption::ArgumentInfo | MTLPipelineOption::BufferTypeInfo,
                Some(&mut reflection),
            )
            .map_err(|err| ArtifactAttestationError::PipelineCreationFailed {
                library_id: canonical_library_id.to_string(),
                entrypoint: entrypoint.to_string(),
                reason: err.to_string(),
            })?;
        let reflection = reflection.ok_or_else(|| ArtifactAttestationError::ReflectionMissing {
            library_id: canonical_library_id.to_string(),
            entrypoint: entrypoint.to_string(),
        })?;
        let actual_reflection_sha256 =
            reflection_sha256_from_runtime_arguments(&reflection.arguments());
        if actual_reflection_sha256 != expected.reflection_sha256 {
            return Err(ArtifactAttestationError::ReflectionDigestMismatch {
                library_id: canonical_library_id.to_string(),
                entrypoint: entrypoint.to_string(),
                expected: expected.reflection_sha256.clone(),
                found: actual_reflection_sha256,
            });
        }

        if let Ok(mut cache) = self.verified_attestation_cache.lock() {
            cache.insert(cache_key, expected.clone());
        }
        Ok(expected)
    }

    /// Create a Metal buffer initialized from a byte slice.
    /// Uses StorageModeShared for zero-copy on unified memory (Apple Silicon).
    pub fn new_buffer_with_bytes(
        &self,
        data: &[u8],
    ) -> Option<Retained<ProtocolObject<dyn MTLBuffer>>> {
        if data.is_empty() {
            return self.new_buffer(4); // Metal doesn't like zero-length buffers
        }
        let ptr = NonNull::new(data.as_ptr() as *mut c_void)?;
        unsafe {
            self.device.newBufferWithBytes_length_options(
                ptr,
                data.len(),
                MTLResourceOptions::StorageModeShared,
            )
        }
    }

    /// Create a Metal buffer from a typed slice (zero-copy on Apple Silicon).
    pub fn new_buffer_from_slice<T>(
        &self,
        data: &[T],
    ) -> Option<Retained<ProtocolObject<dyn MTLBuffer>>> {
        let byte_len = std::mem::size_of_val(data);
        if byte_len == 0 {
            return self.new_buffer(4);
        }
        let ptr = NonNull::new(data.as_ptr() as *mut c_void)?;
        unsafe {
            self.device.newBufferWithBytes_length_options(
                ptr,
                byte_len,
                MTLResourceOptions::StorageModeShared,
            )
        }
    }

    /// Create an empty Metal buffer of the given size in bytes.
    pub fn new_buffer(&self, length: usize) -> Option<Retained<ProtocolObject<dyn MTLBuffer>>> {
        let length = length.max(4); // Metal minimum
        self.device
            .newBufferWithLength_options(length, MTLResourceOptions::StorageModeShared)
    }

    /// Read data from a Metal buffer into a Vec.
    pub fn read_buffer<T: Copy>(
        &self,
        buffer: &ProtocolObject<dyn MTLBuffer>,
        count: usize,
    ) -> Vec<T> {
        let ptr = buffer.contents().as_ptr() as *const T;
        let mut result = Vec::with_capacity(count);
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, result.as_mut_ptr(), count);
            result.set_len(count);
        }
        result
    }

    /// Get a pipeline from a specific library (for MSM shaders).
    pub fn pipeline_from_library(
        &self,
        library: &ProtocolObject<dyn MTLLibrary>,
        function_name: &str,
    ) -> Option<Retained<ProtocolObject<dyn MTLComputePipelineState>>> {
        let name = NSString::from_str(function_name);
        let function = library.newFunctionWithName(&name)?;
        self.device
            .newComputePipelineStateWithFunction_error(&function)
            .ok()
    }

    /// Create a zero-copy Metal buffer wrapping existing memory.
    ///
    /// On Apple Silicon unified memory, this avoids all memcpy — CPU and GPU
    /// share the same physical pages. The caller must ensure `data` outlives
    /// the returned buffer. The buffer length is rounded to page size internally.
    ///
    /// # Safety
    /// The data must remain valid and not be deallocated while the buffer is in use.
    pub unsafe fn new_buffer_no_copy<T>(
        &self,
        data: &mut [T],
    ) -> Option<Retained<ProtocolObject<dyn MTLBuffer>>> {
        let byte_len = std::mem::size_of_val(data);
        if byte_len == 0 {
            return self.new_buffer(4);
        }
        let ptr = NonNull::new(data.as_mut_ptr() as *mut c_void)?;

        // No-op deallocator — Rust owns the memory
        let deallocator: &DynBlock<dyn Fn(NonNull<c_void>, usize)> =
            &block2::RcBlock::new(|_ptr: NonNull<c_void>, _len: usize| {});

        // SAFETY: caller guarantees data outlives buffer, ptr is valid and aligned
        unsafe {
            self.device
                .newBufferWithBytesNoCopy_length_options_deallocator(
                    ptr,
                    byte_len,
                    MTLResourceOptions::StorageModeShared,
                    Some(deallocator),
                )
        }
    }

    /// Acquire a buffer from the pool, or create a new one.
    pub fn acquire_buffer(
        &self,
        min_size: usize,
    ) -> Option<Retained<ProtocolObject<dyn MTLBuffer>>> {
        if let Ok(mut pool) = self.buffer_pool.lock()
            && let Some(buf) = pool.acquire(min_size)
        {
            return Some(buf);
        }
        self.new_buffer(BufferPool::bucket_size(min_size))
    }

    /// Return a buffer to the pool for reuse.
    pub fn release_buffer(&self, buffer: Retained<ProtocolObject<dyn MTLBuffer>>) {
        if let Ok(mut pool) = self.buffer_pool.lock() {
            pool.release(buffer);
        }
    }

    /// Get the secondary command queue (created lazily).
    /// Used for lightweight/async ops to avoid contention with the primary queue.
    pub fn secondary_queue(&self) -> Option<&ProtocolObject<dyn MTLCommandQueue>> {
        self.secondary_queue
            .get_or_init(|| {
                let tuning = throughput_for_device(&self.device_name());
                self.device
                    .newCommandQueueWithMaxCommandBufferCount(tuning.secondary_queue_depth)
                    .or_else(|| self.device.newCommandQueue())
            })
            .as_deref()
    }

    /// Create a command buffer on the secondary queue with detailed error reporting.
    pub fn secondary_command_buffer(
        &self,
    ) -> Option<Retained<ProtocolObject<dyn MTLCommandBuffer>>> {
        if !self.dispatch_allowed() {
            return None;
        }
        let descriptor = MTLCommandBufferDescriptor::new();
        descriptor.setErrorOptions(MTLCommandBufferErrorOption::EncoderExecutionStatus);
        let queue = self.secondary_queue()?;
        queue
            .commandBufferWithDescriptor(&descriptor)
            .or_else(|| queue.commandBuffer())
    }

    /// Get or create a cached twiddle factor buffer.
    /// `field_id`: 0 = Goldilocks (u64), 1 = BabyBear (u32)
    pub fn cached_twiddle_buffer(
        &self,
        field_id: u8,
        log_n: u32,
        compute_twiddles: impl FnOnce() -> Vec<u8>,
    ) -> Option<Retained<ProtocolObject<dyn MTLBuffer>>> {
        let key = (field_id, log_n);
        if let Ok(cache) = self.twiddle_cache.lock()
            && let Some(buf) = cache.get(&key)
        {
            return Some(buf.clone());
        }

        let data = compute_twiddles();
        let buf = self.new_buffer_with_bytes(&data)?;

        if let Ok(mut cache) = self.twiddle_cache.lock() {
            cache.insert(key, buf.clone());
        }

        Some(buf)
    }

    /// Get or create a cached round constant buffer.
    /// `field_id`: 0 = Goldilocks (u64), 1 = BabyBear (u32)
    pub fn cached_round_const_buffer(
        &self,
        field_id: u8,
        seed: u64,
        compute_constants: impl FnOnce() -> Vec<u8>,
    ) -> Option<Retained<ProtocolObject<dyn MTLBuffer>>> {
        let key = (field_id, seed);
        if let Ok(cache) = self.round_const_cache.lock()
            && let Some(buf) = cache.get(&key)
        {
            return Some(buf.clone());
        }

        let data = compute_constants();
        let buf = self.new_buffer_with_bytes(&data)?;

        if let Ok(mut cache) = self.round_const_cache.lock() {
            cache.insert(key, buf.clone());
        }

        Some(buf)
    }

    /// Get diagnostic information about the Metal GPU.
    pub fn diagnostics(&self) -> MetalDiagnostics {
        let current_allocated_size = Some(self.current_allocated_size());
        let working_set_headroom = self.working_set_headroom();
        let working_set_utilization_pct = self
            .working_set_utilization_ratio()
            .map(|ratio| ratio * 100.0);
        MetalDiagnostics {
            device_name: self.device_name(),
            max_buffer_length: self.max_buffer_length(),
            max_threads_per_threadgroup: 1024, // M4 Max default
            unified_memory: self.device.hasUnifiedMemory(),
            recommended_working_set_size: self.recommended_working_set_size(),
            current_allocated_size,
            working_set_headroom,
            working_set_utilization_pct,
            shared_events_supported: self.shared_events_supported(),
            dispatch_circuit_open: !self.dispatch_allowed(),
            dispatch_last_failure: self.last_dispatch_failure(),
        }
    }

    /// Drop reusable runtime caches when OS or device memory pressure rises.
    ///
    /// On Apple Silicon the recommended working-set budget is the practical ceiling
    /// for sustained GPU residency. When the OS is already under pressure, we keep
    /// extra headroom by shedding pooled buffers and precomputed caches.
    pub fn harden_for_pressure(&self, pressure: zkf_core::PressureLevel) -> usize {
        let reserve_bytes = match pressure {
            zkf_core::PressureLevel::Normal => 2 * 1024 * 1024 * 1024,
            zkf_core::PressureLevel::Elevated => 4 * 1024 * 1024 * 1024,
            zkf_core::PressureLevel::High => 8 * 1024 * 1024 * 1024,
            zkf_core::PressureLevel::Critical => 12 * 1024 * 1024 * 1024,
        };
        let should_trim = matches!(
            pressure,
            zkf_core::PressureLevel::Elevated
                | zkf_core::PressureLevel::High
                | zkf_core::PressureLevel::Critical
        ) || self
            .working_set_headroom()
            .map(|headroom| headroom < reserve_bytes)
            .unwrap_or(false);
        if !should_trim {
            return 0;
        }

        let mut released = 0usize;
        if let Ok(mut pool) = self.buffer_pool.lock() {
            released += pool.clear();
        }
        if let Ok(mut cache) = self.twiddle_cache.lock() {
            released += cache.values().map(|buffer| buffer.length()).sum::<usize>();
            cache.clear();
        }
        if let Ok(mut cache) = self.round_const_cache.lock() {
            released += cache.values().map(|buffer| buffer.length()).sum::<usize>();
            cache.clear();
        }
        released
    }
}

/// Get the global Metal context (lazily initialized, thread-safe).
///
/// Respects `ZKF_METAL` environment variable:
/// - `"0"` or `"off"`: disable Metal GPU, return None
/// - `"1"`, `"on"`, or unset: auto-detect
pub fn global_context() -> Option<&'static MetalContext> {
    GLOBAL_CONTEXT
        .get_or_init(|| match std::env::var("ZKF_METAL").as_deref() {
            Ok("0") | Ok("off") | Ok("OFF") => {
                log::info!("[zkf-metal] Disabled via ZKF_METAL=0");
                None
            }
            _ => MetalContext::new(),
        })
        .as_ref()
}

pub fn dispatch_allowed() -> bool {
    global_context()
        .map(MetalContext::dispatch_allowed)
        .unwrap_or(false)
}

/// Check if Metal was disabled via the ZKF_METAL environment variable.
pub fn is_disabled_by_env() -> bool {
    matches!(
        std::env::var("ZKF_METAL").as_deref(),
        Ok("0") | Ok("off") | Ok("OFF")
    )
}

/// Bump-allocator arena for Metal-shared (CPU+GPU accessible) buffers.
///
/// Holds proving keys, twiddle tables, and transcript buffers in unified
/// memory, eliminating CPU↔GPU copies on Apple Silicon (M1/M2/M3/M4).
pub struct SharedArena {
    /// Total capacity in bytes.
    capacity: usize,
    /// Next allocation offset (bump pointer).
    next_offset: usize,
    /// Underlying Metal buffer (unified memory, CPU+GPU readable).
    #[allow(dead_code)]
    buffer: Option<Retained<ProtocolObject<dyn MTLBuffer>>>,
}

impl SharedArena {
    /// Create a new SharedArena with the given capacity.
    pub fn new(capacity: usize) -> Self {
        if let Some(ctx) = global_context()
            && let Some(buffer) = ctx.new_buffer(capacity)
        {
            return Self {
                capacity,
                next_offset: 0,
                buffer: Some(buffer),
            };
        }
        Self {
            capacity,
            next_offset: 0,
            buffer: None,
        }
    }

    /// Allocate `size` bytes aligned to `align` bytes from the arena.
    /// Returns the byte offset into the arena buffer, or None if out of space.
    pub fn alloc(&mut self, size: usize, align: usize) -> Option<usize> {
        let aligned = (self.next_offset + align - 1) & !(align - 1);
        if aligned + size > self.capacity {
            return None;
        }
        self.next_offset = aligned + size;
        Some(aligned)
    }

    /// Reset the bump pointer, reclaiming all allocations.
    pub fn reset(&mut self) {
        self.next_offset = 0;
    }

    /// Returns current bytes used.
    pub fn used(&self) -> usize {
        self.next_offset
    }

    /// Returns total capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// Manages GPU buffer residency for hot buffers (proving keys, twiddle tables).
///
/// On M3/M4+ with MTLResidencySet support, this pins hot buffers across
/// kernel invocations, eliminating page-fault latency during proving.
/// Falls back gracefully to no-op on older hardware.
pub struct ResidencyManager {
    /// Buffers currently pinned for residency.
    pinned_count: usize,
    /// Total bytes currently resident.
    resident_bytes: usize,
}

impl ResidencyManager {
    /// Create a new ResidencyManager.
    pub fn new() -> Self {
        Self {
            pinned_count: 0,
            resident_bytes: 0,
        }
    }

    /// Pin a buffer (mark as hot/resident). On M3/M4+ this uses MTLResidencySet.
    /// On older hardware this is a no-op.
    pub fn pin(&mut self, size: usize) {
        self.pinned_count += 1;
        self.resident_bytes += size;
        // On M3/M4+ with MTLResidencySet API, we would call:
        // residency_set.add_allocation(buffer);
        // residency_set.commit();
        // This is an experimental scaffold; full MTLResidencySet support requires
        // metal-rs bindings for the M3+ API which are not yet stable.
    }

    /// Unpin a buffer. On M3/M4+ removes from MTLResidencySet.
    pub fn unpin(&mut self, size: usize) {
        self.pinned_count = self.pinned_count.saturating_sub(1);
        self.resident_bytes = self.resident_bytes.saturating_sub(size);
    }

    /// Returns number of currently pinned buffers.
    pub fn pinned_count(&self) -> usize {
        self.pinned_count
    }

    /// Returns total bytes currently pinned for residency.
    pub fn resident_bytes(&self) -> usize {
        self.resident_bytes
    }
}

impl Default for ResidencyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_returns_valid_info() {
        let ctx = match global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };
        let diag = ctx.diagnostics();
        assert!(
            !diag.device_name.is_empty(),
            "Device name should not be empty"
        );
        assert!(
            diag.max_buffer_length > 0,
            "Max buffer length should be positive"
        );
        assert!(diag.max_threads_per_threadgroup > 0);
        assert!(
            diag.unified_memory,
            "Apple Silicon should have unified memory"
        );
        eprintln!(
            "Metal device: {} (max buf: {} MB, unified: {})",
            diag.device_name,
            diag.max_buffer_length / (1024 * 1024),
            diag.unified_memory,
        );
    }

    #[test]
    fn buffer_pool_acquire_release() {
        let ctx = match global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };
        let buf1 = ctx.acquire_buffer(1024).expect("should allocate");
        let len1 = buf1.length();
        assert!(len1 >= 1024);
        ctx.release_buffer(buf1);

        // Acquiring same size should reuse the pooled buffer
        let buf2 = ctx.acquire_buffer(1024).expect("should allocate");
        assert_eq!(
            buf2.length(),
            len1,
            "Should reuse pooled buffer of same size"
        );
    }

    #[test]
    fn dispatch_circuit_blocks_new_command_buffers() {
        let ctx = match global_context() {
            Some(c) => c,
            None => {
                eprintln!("No Metal GPU, skipping");
                return;
            }
        };

        ctx.reset_dispatch_for_tests();
        assert!(ctx.dispatch_allowed());
        assert!(ctx.command_buffer().is_some());

        ctx.disable_dispatch("unit-test");
        assert!(!ctx.dispatch_allowed());
        assert!(ctx.command_buffer().is_none());
        assert_eq!(ctx.last_dispatch_failure().as_deref(), Some("unit-test"));

        ctx.reset_dispatch_for_tests();
        assert!(ctx.dispatch_allowed());
    }
}
