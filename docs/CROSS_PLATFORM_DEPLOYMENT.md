# Cross-Platform Deployment

Deploying ZKF on macOS, iOS, iPadOS, and visionOS through the FFI layer.

## Platform Support Matrix

| Platform | Proving | Metal GPU | Neural Engine | Adaptive Tuning | Watchdog |
|---|---|---|---|---|---|
| macOS (Apple Silicon) | Full | Full | Full | Full | Full |
| macOS (Intel/Rosetta) | Full | No | No (heuristic fallback) | CPU-only | Full |
| iOS / iPadOS | Full | No (Metal compute not used) | Full | Full | Full |
| visionOS | Full | No (Metal compute not used) | Full | Full | Full |

Metal GPU acceleration for compute shaders is macOS-only. On iOS/iPadOS/visionOS, the control plane and Neural Engine inference work via CoreML, but proving dispatches to CPU. The adaptive tuning system still learns CPU-only thresholds on these platforms.

## FFI Interface (ABI Version 3)

The `zkf-ffi` crate exposes C-compatible `extern "C"` functions for Swift integration. Every function returns a `*mut ZkfFfiResult` with JSON payload. The caller must free results with `zkf_free_result`.

### Platform Detection

```c
// Returns full PlatformCapability as JSON
ZkfFfiResult* zkf_platform_capability(void);
```

Returns chip family, form factor, GPU cores, Neural Engine TOPS, thermal envelope, battery state, and unified memory status.

### Neural Engine Status

```c
// Returns ANE availability, model catalog, adaptive tuning status
ZkfFfiResult* zkf_neural_engine_status(void);
```

### Control Plane Evaluation

```c
// Evaluate the control plane for a proving job
ZkfFfiResult* zkf_evaluate_control_plane(const char* request_json);
```

Request JSON fields: `job_kind`, `objective`, `constraint_count`, `signal_count`, `stage_node_counts`, `field`, `requested_backend`, `backend_candidates`, `requested_jobs`, `total_jobs`.

### Watchdog

```c
ZkfFfiResult* zkf_watchdog_create(int deterministic_mode);
ZkfFfiResult* zkf_watchdog_check_alerts(uint64_t watchdog_id);
ZkfFfiResult* zkf_watchdog_destroy(uint64_t watchdog_id);
```

Create a watchdog handle, poll for alerts (timing anomalies, thermal throttling, memory pressure, GPU circuit breaker), and destroy when done. In deterministic mode, the watchdog observes but does not recommend rerouting.

### Adaptive Tuning

```c
ZkfFfiResult* zkf_adaptive_tuning_status(void);
```

Returns learned thresholds, observation counts, base thresholds, and whether adaptive mode is active.

### Telemetry

```c
ZkfFfiResult* zkf_telemetry_stats(const char* dir);
```

Pass `NULL` for the default telemetry directory. Returns record count, corpus hash, schema version.

### Deployment / Conformance Export

```c
ZkfFfiResult* zkf_estimate_gas_for_target(
    const char* proof_path,
    const char* backend,
    const char* evm_target
);

ZkfFfiResult* zkf_deploy_for_target(
    const char* proof_path,
    const char* backend,
    const char* output_path,
    const char* contract_name,
    const char* evm_target
);

ZkfFfiResult* zkf_conformance_export(
    const char* backend,
    const char* json_path,
    const char* cbor_path
);
```

`evm_target` accepts `ethereum`, `optimism-arbitrum-l2`, and `generic-evm`. Passing `NULL`
defaults to `ethereum`.

### ABI Version Check

```c
uint32_t zkf_ffi_abi_version(void);  // Returns 3
```

Swift should call this at startup and refuse to call other functions if the version is unexpected.

## Header Generation

`cargo build -p zkf-ffi` regenerates [`zkf_ffi.h`](/Users/sicarii/Projects/ZK DEV/zkf-ffi/include/zkf_ffi.h)
through `cbindgen`. The build script preprocesses `src/lib.rs` into a temporary crate and rewrites
Rust 2024 `#[unsafe(no_mangle)]` attributes to plain `#[no_mangle]` for cbindgen compatibility
before header generation. Do not edit the checked-in header manually; update the Rust exports and
rebuild instead.

## Mobile Power Management

When `PlatformCapability` detects a mobile or headset form factor, the system automatically:

- Applies a 1.60x threshold multiplier (fewer GPU dispatches)
- Respects `low_power_mode` with an additional 1.75x multiplier
- Applies battery-on-battery 1.15x multiplier
- Uses tighter watchdog timing budgets (1.25x vs 1.50x for desktop)
- Raises thermal throttle sensitivity

These adjustments happen automatically through the adaptive tuning runtime bias system. No Swift-side configuration is needed.

## CoreML Model Portability

CoreML `.mlpackage` files are portable across all Apple Silicon devices. A single set of models works on M1 through M4, A17 Pro through A18 Pro, iPad, iPhone, and Vision Pro. CoreML compiles models per-device on first load and caches the compiled `.mlmodelc` artifacts automatically.

The five model lanes (Scheduler, Backend Recommender, Duration Estimator, Anomaly Detector, Threshold Optimizer) ship as `.mlpackage` bundles. On platforms where the Neural Engine is unavailable, CoreML routes inference to CPU automatically. The v2 feature vector (57 elements) includes platform-specific features so models can generalize across devices.

## Cross-Compilation

Build the FFI library for iOS:

```bash
cargo build -p zkf-ffi --target aarch64-apple-ios --release
```

Metal GPU features are gated behind `#[cfg(target_os = "macos")]`. The `platform.rs` detection module has conditional compilation for `target_os = "ios"`, `target_os = "visionos"`, and `target_os = "tvos"`.

## Swift Integration Example

```swift
import Foundation

guard zkf_ffi_abi_version() == 3 else {
    fatalError("FFI ABI version mismatch")
}

// Detect platform
let capResult = zkf_platform_capability()
defer { zkf_free_result(capResult) }
if capResult.pointee.status == 0,
   let data = capResult.pointee.data {
    let json = String(cString: data)
    print("Platform: \(json)")
}

// Create watchdog
let wdResult = zkf_watchdog_create(0) // non-deterministic
defer { zkf_free_result(wdResult) }

// Check for alerts after proving stages
let alertResult = zkf_watchdog_check_alerts(watchdogId)
defer { zkf_free_result(alertResult) }
```

## Privacy

Telemetry records stored locally at `~/.zkf/telemetry/` contain platform capability snapshots. The `zkf telemetry export` command and `export_anonymized_telemetry.py` script strip identifying fields (model_identifier, machine_name, raw_chip_name, timestamps) before export. No secret material (witnesses, proofs, program content) is included in telemetry.
