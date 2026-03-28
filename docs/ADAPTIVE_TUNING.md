# Adaptive Tuning

GPU dispatch thresholds that learn from real proving observations and adapt to device, workload, and environmental conditions.

## Overview

ZKF ships static GPU dispatch thresholds in three tiers (Conservative, Moderate, Aggressive) selected by chip family and GPU core count. These are engineering estimates. Adaptive tuning replaces them with thresholds learned from actual CPU-vs-GPU timing on the running device.

The adaptive tuning system:

1. Starts with the static threshold for the detected platform
2. Records whether GPU was faster than CPU for each dispatch
3. Converges on the optimal crossover point per operation via exponential moving average
4. Persists learned thresholds to `~/.zkf/tuning/<platform_key>.json`
5. Applies runtime bias for thermal pressure, battery state, low-power mode, and mobile form factor

## Architecture

```
PlatformCapability::detect()
        |
        v
  AdaptiveThresholdScope::enter()
        |
        +-- load learned state from ~/.zkf/tuning/
        +-- apply per-operation learned thresholds
        +-- apply runtime bias (thermal, battery, form factor)
        +-- push resolved thresholds into Metal tuning layer
        |
        v
  [proving job executes]
        |
        v
  AdaptiveThresholdScope::finish(report)
        |
        +-- record per-stage observations
        +-- update EMA convergence
        +-- persist updated state to disk
```

## Convergence

- **Minimum observations**: 20 per operation before overriding static thresholds
- **EMA alpha**: 0.2 (recent observations weighted more heavily)
- **Learned threshold**: midpoint of GPU-win and CPU-win batch size EMAs
- **Bounds**: clamped between 16 and 16x the static base threshold

After approximately 20 proving jobs per operation type, thresholds converge to within 10% of the optimal crossover point for the specific device and workload mix.

## Runtime Bias

Environmental conditions modify the learned thresholds in real-time:

| Condition | Multiplier | Effect |
|---|---|---|
| Low power mode | 1.75x | Raises thresholds (fewer GPU dispatches) |
| Thermal pressure >= 50% | 1.35x | Raises thresholds |
| CPU speed limit < 90% | 1.20x | Raises thresholds |
| Mobile/Headset form factor | 1.60x | Raises thresholds |
| Battery without external power | 1.15x | Raises thresholds |

Multipliers stack. A mobile device in low-power mode on battery can see thresholds 3-4x higher than the learned base, effectively routing most work to CPU.

## ThresholdOptimizer Model Lane

A fifth CoreML model lane (`threshold-optimizer`) supplements the convergence algorithm with pre-trained cross-device knowledge. It takes a 12-element feature vector:

1. chip_generation_norm
2. gpu_cores_norm (cores / 64)
3. ane_tops_norm (TOPS / 40)
4. battery_present
5. on_external_power
6. low_power_mode
7. form_factor one-hot: desktop, laptop, mobile, headset
8. total_stage_nodes_log2_norm
9. constraints_log2_norm

The model predicts a `gpu_lane_score` indicating whether GPU dispatch is beneficial for the current platform and workload. It bootstraps new devices with reasonable thresholds before the adaptive system has enough observations.

## Persistence

Learned state is stored per device at:

```
~/.zkf/tuning/<platform_key>.json
```

The platform key encodes chip family, form factor, GPU core count, and model identifier. Different devices produce different files. The schema is `zkf-adaptive-thresholds-v1`.

## Environment Overrides

| Variable | Effect |
|---|---|
| `ZKF_STATIC_THRESHOLDS=1` | Bypass all learned and runtime-biased thresholds; use static tiers only |

## Status Inspection

```bash
zkf telemetry stats
```

Shows the current corpus hash and record count. The adaptive tuning status (including learned thresholds and observation counts) is included in every telemetry record under the `adaptive_tuning` field and is available via FFI through `zkf_adaptive_tuning_status()`.

## Reset

Delete the tuning state file to reset learned thresholds:

```bash
rm ~/.zkf/tuning/*.json
```

The system falls back to static thresholds immediately.
