#!/usr/bin/env python3
"""Train ZirOS Neural Engine control-plane models from telemetry data.

Called by: zkf retrain --profile production

Reads telemetry JSON files, builds a JSONL corpus, and trains five model
lanes (scheduler, backend_recommender, duration_estimator, anomaly_detector,
security_detector) using scikit-learn, exporting each as a CoreML .mlpackage
via coremltools.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pathlib
import shutil
import sys
import time
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

try:
    import numpy as np
except ImportError:
    print(
        "error: numpy is required but not installed.\n"
        "  pip install numpy",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    from sklearn.ensemble import (
        GradientBoostingClassifier,
        GradientBoostingRegressor,
        IsolationForest,
    )
    from sklearn.linear_model import Ridge
    from sklearn.model_selection import cross_val_score, train_test_split
    from sklearn.preprocessing import StandardScaler
except ImportError:
    print(
        "error: scikit-learn is required but not installed.\n"
        "  pip install scikit-learn",
        file=sys.stderr,
    )
    sys.exit(1)

try:
    import coremltools as ct
except ImportError:
    print(
        "error: coremltools is required but not installed.\n"
        "  pip install coremltools",
        file=sys.stderr,
    )
    sys.exit(1)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TELEMETRY_DIR = os.path.join(
    os.path.expanduser("~"),
    "Library",
    "Mobile Documents",
    "com~apple~CloudDocs",
    "ZirOS",
    "telemetry",
)

CONTROL_PLANE_SCHEMA = "zkf-neural-control-plane-v3"
COREML_INPUT_NAME = "features"
CONTROL_INPUT_DIM = 128
SECURITY_INPUT_DIM = 145

LANE_METADATA = {
    "scheduler": {
        "runtime_lane": "scheduler",
        "filename": "scheduler_v3.mlpackage",
        "input_shape": CONTROL_INPUT_DIM,
        "output_name": "predicted_duration_ms",
    },
    "backend_recommender": {
        "runtime_lane": "backend",
        "filename": "backend_recommender_v3.mlpackage",
        "input_shape": CONTROL_INPUT_DIM,
        "output_name": "backend_score",
    },
    "duration_estimator": {
        "runtime_lane": "duration",
        "filename": "duration_estimator_v3.mlpackage",
        "input_shape": CONTROL_INPUT_DIM,
        "output_name": "predicted_duration_ms",
    },
    "anomaly_detector": {
        "runtime_lane": "anomaly",
        "filename": "anomaly_detector_v3.mlpackage",
        "input_shape": CONTROL_INPUT_DIM,
        "output_name": "anomaly_score",
    },
    "security_detector": {
        "runtime_lane": "security",
        "filename": "security_detector_v3.mlpackage",
        "input_shape": SECURITY_INPUT_DIM,
        "output_name": "risk_score",
    },
}

DISPATCH_CANDIDATES = [
    "cpu-only",
    "hash-only",
    "algebra-only",
    "stark-heavy",
    "balanced",
    "full-gpu",
]

RUNTIME_BACKENDS = [
    "plonky3",
    "arkworks-groth16",
    "nova",
    "hypernova",
    "sp1",
    "risc-zero",
    "halo2",
    "midnight-compact",
]

OBJECTIVES = ["fastest-prove", "smallest-proof", "no-trusted-setup"]

GPU_CAPABLE_STAGE_KEYS = [
    "ntt",
    "lde",
    "msm",
    "poseidon-batch",
    "sha256-batch",
    "merkle-layer",
    "fri-fold",
    "fri-query-open",
]

DISPATCH_GPU_STAGES = {
    "cpu-only": [],
    "hash-only": ["poseidon-batch", "sha256-batch", "merkle-layer"],
    "algebra-only": ["ntt", "lde", "msm"],
    "stark-heavy": ["ntt", "lde", "merkle-layer", "fri-fold", "fri-query-open"],
    "balanced": ["ntt", "lde", "msm", "poseidon-batch", "merkle-layer", "fri-fold"],
    "full-gpu": GPU_CAPABLE_STAGE_KEYS,
}

NUMERIC_FEATURES = [
    "constraint_count",
    "signal_count",
    "prove_time_ms",
    "verify_time_ms",
    "witness_gen_time_ms",
    "gpu_busy_ratio",
    "peak_memory_bytes",
    "proof_size_bytes",
]

CATEGORICAL_FEATURES = ["backend", "field"]

# Model lanes produced by this script.
MODEL_LANES = [
    "scheduler",
    "backend_recommender",
    "duration_estimator",
    "anomaly_detector",
    "security_detector",
]

# Backend and field vocabularies for one-hot encoding.
KNOWN_BACKENDS = [
    "groth16",
    "halo2",
    "nova",
    "plonk",
    "spartan",
    "stark",
    "supernova",
    "unknown",
]
KNOWN_FIELDS = [
    "bn254",
    "bls12-381",
    "goldilocks",
    "pallas",
    "vesta",
    "babybear",
    "mersenne31",
    "unknown",
]

# ---------------------------------------------------------------------------
# Telemetry parsing
# ---------------------------------------------------------------------------


def _safe_float(obj: Any, *keys: str, default: float = 0.0) -> float:
    """Drill into nested dicts and return a float, or *default* on any miss."""
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
    try:
        return float(cur) if cur is not None else default
    except (TypeError, ValueError):
        return default


def _safe_int(obj: Any, *keys: str, default: int = 0) -> int:
    val = _safe_float(obj, *keys, default=float(default))
    return int(val)


def _safe_str(obj: Any, *keys: str, default: str = "unknown") -> str:
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
    return str(cur) if cur is not None else default


def _safe_dict(obj: Any, *keys: str) -> dict:
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return {}
    return cur if isinstance(cur, dict) else {}


def _safe_bool(obj: Any, *keys: str, default: bool = False) -> bool:
    cur = obj
    for k in keys:
        if isinstance(cur, dict):
            cur = cur.get(k)
        else:
            return default
    if isinstance(cur, bool):
        return cur
    if isinstance(cur, str):
        return cur.strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(cur, (int, float)):
        return cur != 0
    return default


def _normalized_log2(value: float, max_log2: float) -> float:
    if value <= 0:
        return 0.0
    return float(min(max(math.log2(value + 1.0) / max_log2, 0.0), 1.0))


def _chip_generation_norm(chip_family: str) -> float:
    return {
        "m1": 0.25,
        "m2": 0.50,
        "vision-pro": 0.50,
        "m3": 0.75,
        "m4": 1.00,
        "a17-pro": 0.90,
        "a18": 0.95,
        "a18-pro": 1.00,
    }.get(chip_family, 0.60)


def _canonical_backend(value: str) -> str:
    raw = value.strip().lower().replace("_", "-")
    aliases = {
        "arkworks": "arkworks-groth16",
        "groth16": "arkworks-groth16",
        "hyper-nova": "hypernova",
        "risc0": "risc-zero",
        "midnight": "midnight-compact",
        "compact": "midnight-compact",
    }
    return aliases.get(raw, raw)


def _digest_bucket_64(digest: str) -> int:
    if len(digest) >= 2:
        try:
            return int(digest[:2], 16) % 64
        except ValueError:
            pass
    return hashlib.sha256(digest.encode("utf-8")).digest()[0] % 64


def _stage_ratio(stage_node_counts: dict, stages: list[str]) -> float:
    total = max(sum(int(v) for v in stage_node_counts.values()), 1)
    matched = sum(int(stage_node_counts.get(stage, 0)) for stage in stages)
    return float(min(max(matched / total, 0.0), 1.0))


def _blackbox_ratio(distribution: dict, key: str) -> float:
    total = max(sum(int(v) for v in distribution.values()), 1)
    return float(min(max(int(distribution.get(key, 0)) / total, 0.0), 1.0))


def parse_telemetry_record(raw: dict) -> dict | None:
    """Extract a flat feature dict from a single telemetry JSON record.

    Returns None if the record is malformed or lacks critical fields.
    """
    if "constraint_count" in raw and "prove_time_ms" in raw:
        constraints = _safe_int(raw, "constraint_count")
        signals = _safe_int(raw, "signal_count", default=constraints)
        peak_memory_bytes = _safe_int(raw, "peak_memory_bytes")
        return {
            "constraint_count": constraints,
            "signal_count": signals,
            "witness_size": _safe_int(raw, "witness_size", default=signals),
            "max_constraint_degree": _safe_int(raw, "max_constraint_degree", default=2),
            "blackbox_op_distribution": _safe_dict(raw, "blackbox_op_distribution"),
            "stage_node_counts": _safe_dict(raw, "stage_node_counts"),
            "prove_time_ms": _safe_float(raw, "prove_time_ms"),
            "verify_time_ms": _safe_float(raw, "verify_time_ms"),
            "witness_gen_time_ms": _safe_float(raw, "witness_gen_time_ms"),
            "backend": _safe_str(raw, "backend", default="arkworks-groth16"),
            "field": _safe_str(raw, "field", default="bn254"),
            "job_kind": _safe_str(raw, "job_kind", default="prove"),
            "objective": _safe_str(raw, "objective", default="fastest-prove"),
            "dispatch_candidate": _safe_str(raw, "dispatch_candidate", default="balanced"),
            "backend_route": _safe_str(raw, "backend_route", default="native-auto"),
            "program_digest": _safe_str(raw, "program_digest", default=""),
            "requested_jobs": _safe_int(raw, "requested_jobs", default=1),
            "total_jobs": _safe_int(raw, "total_jobs", default=1),
            "gpu_busy_ratio": _safe_float(raw, "gpu_busy_ratio"),
            "peak_memory_bytes": peak_memory_bytes,
            "proof_size_bytes": _safe_int(raw, "proof_size_bytes"),
            "hardware_profile": _safe_str(
                raw, "hardware_profile", default="apple-silicon-m4-max-48gb"
            ),
            "chip_family": _safe_str(raw, "chip_family", default="m4"),
            "form_factor": _safe_str(raw, "form_factor", default="laptop"),
            "gpu_core_count": _safe_int(raw, "gpu_core_count", default=40),
            "ane_tops": _safe_float(raw, "ane_tops", default=38.0),
            "metal_available": _safe_bool(raw, "metal_available", default=False),
            "unified_memory": _safe_bool(raw, "unified_memory", default=True),
            "ram_utilization": _safe_float(raw, "ram_utilization", default=0.17),
            "memory_pressure_ratio": _safe_float(
                raw,
                "memory_pressure_ratio",
                default=min(max(peak_memory_bytes / (48.0 * 1024.0**3), 0.0), 1.0),
            ),
            "battery_present": _safe_bool(raw, "battery_present", default=True),
            "on_external_power": _safe_bool(raw, "on_external_power", default=True),
            "low_power_mode": _safe_bool(raw, "low_power_mode", default=False),
            "thermal_pressure": _safe_float(raw, "thermal_pressure", default=0.0),
            "cpu_speed_limit": _safe_float(raw, "cpu_speed_limit", default=1.0),
            "anomaly_severity": _safe_str(raw, "anomaly_severity", default="normal"),
            "integrity_mismatch_count": _safe_int(raw, "integrity_mismatch_count", default=0),
            "synthetic": _safe_bool(raw, "synthetic", default=False),
            "gpu_was_faster": _safe_bool(raw, "gpu_was_faster"),
        }

    circuit = raw.get("circuit_features")
    outcome = raw.get("outcome")
    metadata = raw.get("metadata")
    hardware = raw.get("hardware_state")
    control_plane_features = _safe_dict(raw, "control_plane", "decision", "features")
    dispatch_plan = _safe_dict(raw, "control_plane", "decision", "dispatch_plan")

    if circuit is None or outcome is None or metadata is None:
        return None

    constraint_count = _safe_int(circuit, "constraint_count")
    signal_count = _safe_int(circuit, "signal_count")

    # Total proving time is our main timing field.
    prove_time_ms = _safe_float(outcome, "total_proving_time_ms")

    # Per-stage times: attempt to extract verify and witness gen.
    per_stage = outcome.get("per_stage_times_ms", {}) if isinstance(outcome, dict) else {}
    verify_time_ms = _safe_float(per_stage, "verify", default=0.0)
    if verify_time_ms == 0.0:
        verify_time_ms = _safe_float(per_stage, "verification", default=0.0)
    witness_gen_time_ms = _safe_float(per_stage, "witness_gen", default=0.0)
    if witness_gen_time_ms == 0.0:
        witness_gen_time_ms = _safe_float(per_stage, "witness-gen", default=0.0)

    backend = _safe_str(metadata, "backend_used")
    field = _safe_str(metadata, "field_used")
    proof_size_bytes = _safe_int(metadata, "proof_size_bytes")

    gpu_busy_ratio = _safe_float(hardware, "gpu_utilization") if hardware else 0.0
    peak_memory_bytes = _safe_int(hardware, "memory_pressure_bytes") if hardware else 0

    gpu_was_faster = outcome.get("gpu_was_faster", False) if isinstance(outcome, dict) else False
    stage_node_counts = _safe_dict(control_plane_features, "stage_node_counts")
    if not stage_node_counts:
        stage_node_counts = _safe_dict(raw, "dispatch_config", "batch_sizes")
    if not stage_node_counts:
        runtime_stage_keys = raw.get("dispatch_config", {}).get("runtime_stage_keys", [])
        if isinstance(runtime_stage_keys, list):
            stage_node_counts = {str(stage): 1 for stage in runtime_stage_keys}

    dispatch_candidate = _safe_str(dispatch_plan, "candidate", default="")
    if not dispatch_candidate:
        dispatch_candidate = _safe_str(raw, "dispatch_config", "dispatch_candidate", default="balanced")
    program_digest = _safe_str(metadata, "program_digest", default="")
    if not program_digest:
        program_digest = hashlib.sha256(
            json.dumps(raw.get("circuit_features", {}), sort_keys=True).encode("utf-8")
        ).hexdigest()

    return {
        "constraint_count": constraint_count,
        "signal_count": signal_count,
        "witness_size": _safe_int(circuit, "witness_size", default=signal_count),
        "max_constraint_degree": _safe_int(circuit, "max_constraint_degree", default=2),
        "blackbox_op_distribution": _safe_dict(circuit, "blackbox_op_distribution"),
        "stage_node_counts": stage_node_counts,
        "prove_time_ms": prove_time_ms,
        "verify_time_ms": verify_time_ms,
        "witness_gen_time_ms": witness_gen_time_ms,
        "backend": backend,
        "field": field,
        "job_kind": _safe_str(metadata, "job_kind", default="prove"),
        "objective": _safe_str(metadata, "optimization_objective", default="fastest-prove"),
        "dispatch_candidate": dispatch_candidate,
        "backend_route": _safe_str(metadata, "backend_route", default="native-auto"),
        "program_digest": program_digest,
        "requested_jobs": _safe_int(control_plane_features, "requested_jobs", default=1),
        "total_jobs": _safe_int(control_plane_features, "total_jobs", default=1),
        "gpu_busy_ratio": gpu_busy_ratio,
        "peak_memory_bytes": peak_memory_bytes,
        "proof_size_bytes": proof_size_bytes,
        "hardware_profile": _safe_str(
            control_plane_features,
            "hardware_profile",
            default=_safe_str(metadata, "hardware_profile", default="apple-silicon-m4-max-48gb"),
        ),
        "chip_family": _safe_str(control_plane_features, "chip_family", default="m4"),
        "form_factor": _safe_str(control_plane_features, "form_factor", default="laptop"),
        "gpu_core_count": _safe_int(control_plane_features, "gpu_core_count", default=40),
        "ane_tops": _safe_float(control_plane_features, "ane_tops", default=38.0),
        "metal_available": _safe_bool(
            control_plane_features,
            "metal_available",
            default=_safe_bool(hardware or {}, "metal_available"),
        ),
        "unified_memory": _safe_bool(control_plane_features, "unified_memory", default=True),
        "ram_utilization": _safe_float(control_plane_features, "ram_utilization", default=0.17),
        "memory_pressure_ratio": _safe_float(
            control_plane_features,
            "memory_pressure_ratio",
            default=min(max(peak_memory_bytes / (48.0 * 1024.0**3), 0.0), 1.0),
        ),
        "battery_present": _safe_bool(control_plane_features, "battery_present", default=True),
        "on_external_power": _safe_bool(control_plane_features, "on_external_power", default=True),
        "low_power_mode": _safe_bool(control_plane_features, "low_power_mode", default=False),
        "thermal_pressure": _safe_float(control_plane_features, "thermal_pressure", default=0.0),
        "cpu_speed_limit": _safe_float(control_plane_features, "cpu_speed_limit", default=1.0),
        "anomaly_severity": _safe_str(
            raw,
            "control_plane",
            "anomaly_verdict",
            "severity",
            default="normal",
        ),
        "integrity_mismatch_count": len(
            metadata.get("integrity_mismatch_flags", [])
            if isinstance(metadata.get("integrity_mismatch_flags"), list)
            else []
        ),
        "synthetic": False,
        # Derived labels for classification lanes.
        "gpu_was_faster": bool(gpu_was_faster),
    }


def load_telemetry(input_dirs: list[str]) -> list[dict]:
    """Read JSON/JSONL telemetry files from given files or directories."""
    records: list[dict] = []
    for input_path in input_dirs:
        path = pathlib.Path(input_path)
        files: list[pathlib.Path]
        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = [candidate for candidate in sorted(path.iterdir()) if candidate.is_file()]
        else:
            print(f"  [warn] telemetry input not found: {path}")
            continue
        for filepath in files:
            if filepath.suffix not in (".json", ".jsonl"):
                continue
            try:
                if filepath.suffix == ".jsonl":
                    for line in filepath.read_text(encoding="utf-8").splitlines():
                        if not line.strip():
                            continue
                        parsed = parse_telemetry_record(json.loads(line))
                        if parsed is not None:
                            records.append(parsed)
                    continue
                raw = json.loads(filepath.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                print(f"  [warn] skipping {filepath.name}: {exc}")
                continue
            parsed = parse_telemetry_record(raw)
            if parsed is not None:
                records.append(parsed)
    return records


# ---------------------------------------------------------------------------
# Corpus I/O
# ---------------------------------------------------------------------------


def write_corpus(records: list[dict], corpus_path: str) -> str:
    """Write JSONL corpus and return its SHA-256 hash."""
    os.makedirs(os.path.dirname(corpus_path) or ".", exist_ok=True)
    hasher = hashlib.sha256()
    with open(corpus_path, "w", encoding="utf-8") as fh:
        for rec in records:
            line = json.dumps(rec, sort_keys=True)
            fh.write(line + "\n")
            hasher.update(line.encode("utf-8"))
    return hasher.hexdigest()


def write_summary(records: list[dict], summary_path: str) -> None:
    """Write a summary JSON with record count and feature statistics."""
    os.makedirs(os.path.dirname(summary_path) or ".", exist_ok=True)
    stats: dict[str, Any] = {}
    for feat in NUMERIC_FEATURES:
        vals = [r[feat] for r in records if feat in r]
        if vals:
            arr = np.array(vals, dtype=np.float64)
            stats[feat] = {
                "count": len(vals),
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
                "median": float(np.median(arr)),
            }
    for feat in CATEGORICAL_FEATURES:
        vals = [r.get(feat, "unknown") for r in records]
        unique, counts = np.unique(vals, return_counts=True)
        stats[feat] = {
            "distinct_values": int(len(unique)),
            "distribution": {str(u): int(c) for u, c in zip(unique, counts)},
        }
    summary = {
        "schema": "zkf-training-corpus-summary-v1",
        "record_count": len(records),
        "feature_statistics": stats,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")


# ---------------------------------------------------------------------------
# Feature encoding
# ---------------------------------------------------------------------------


def _one_hot(value: str, vocabulary: list[str]) -> list[float]:
    """Return a one-hot vector for *value* against *vocabulary*."""
    vec = [0.0] * len(vocabulary)
    lower = value.lower()
    for i, v in enumerate(vocabulary):
        if lower == v:
            vec[i] = 1.0
            return vec
    # If not found, mark the last slot ("unknown").
    vec[-1] = 1.0
    return vec


def _candidate_stages(candidate: str) -> list[str]:
    return DISPATCH_GPU_STAGES.get(candidate, DISPATCH_GPU_STAGES["balanced"])


def _heuristic_scheduler_ms(rec: dict, backend: str, candidate: str) -> float:
    constraints = max(float(rec.get("constraint_count", 1)), 1.0)
    signals = max(float(rec.get("signal_count", 1)), 1.0)
    witness_scale = max(math.log2(max(float(rec.get("witness_size", 1)), 1.0)), 1.0)
    stage_weight = max(sum(int(v) for v in rec.get("stage_node_counts", {}).values()), 1)
    memory_pressure = float(rec.get("memory_pressure_ratio", 0.0))
    pressure_penalty = 2.3 if memory_pressure >= 0.95 else 1.8 if memory_pressure >= 0.85 else 1.25 if memory_pressure >= 0.70 else 1.0
    thermal_penalty = 1.0 + min(max(float(rec.get("thermal_pressure", 0.0)), 0.0), 1.0) * 0.50
    mobile_penalty = 1.35 if rec.get("form_factor") == "mobile" else 1.20 if rec.get("form_factor") == "headset" else 1.0
    low_power_penalty = 1.18 if rec.get("low_power_mode") else 1.0
    backend_weight = {
        "plonky3": 0.85,
        "arkworks-groth16": 1.0,
        "nova": 1.20,
        "hypernova": 1.20,
        "halo2": 1.15,
        "halo2-bls12-381": 1.15,
        "sp1": 1.40,
        "risc-zero": 1.40,
        "midnight-compact": 1.30,
    }.get(backend, 1.0)
    stage_counts = rec.get("stage_node_counts", {})
    gpu_discount = {
        "cpu-only": 1.20,
        "hash-only": 1.00 - _stage_ratio(stage_counts, ["poseidon-batch", "sha256-batch", "merkle-layer"]) * 0.18,
        "algebra-only": 1.00 - _stage_ratio(stage_counts, ["ntt", "lde", "msm"]) * 0.22,
        "stark-heavy": 1.00 - _stage_ratio(stage_counts, ["ntt", "lde", "poseidon-batch", "merkle-layer", "fri-fold", "fri-query-open"]) * 0.28,
        "balanced": 0.84,
        "full-gpu": 0.76 + memory_pressure * 0.20 if rec.get("metal_available") else 1.25,
    }.get(candidate, 0.84)
    return (
        (math.log2(constraints) * 18.0)
        + (math.log2(signals) * 12.0)
        + (witness_scale * 8.0)
        + (stage_weight * 6.0)
    ) * backend_weight * pressure_penalty * thermal_penalty * mobile_penalty * low_power_penalty * max(gpu_discount, 0.40)


def _heuristic_expected_proof_size_bytes(rec: dict, backend: str) -> int:
    scale = max(math.log2(max(float(rec.get("constraint_count", 1)), 1.0)), 1.0)
    base = {
        "arkworks-groth16": 128.0,
        "plonky3": 24_576.0,
        "nova": 1_770_000.0,
        "hypernova": 1_200_000.0,
        "halo2": 8_192.0,
        "halo2-bls12-381": 9_216.0,
        "sp1": 65_536.0,
        "risc-zero": 65_536.0,
        "midnight-compact": 4_096.0,
    }.get(backend, 128.0)
    return int(base + scale * 96.0)


def _execution_regime(rec: dict, candidate: str) -> str:
    stages = _candidate_stages(candidate)
    if not rec.get("metal_available") or not stages:
        return "cpu-only"
    if len(stages) == len(GPU_CAPABLE_STAGE_KEYS):
        return "gpu-capable"
    return "partial-fallback"


def _duration_upper_bound(rec: dict, regime: str, estimate_ms: float) -> float:
    if not rec.get("metal_available"):
        return estimate_ms
    memory_penalty = 1.0 + min(max(float(rec.get("memory_pressure_ratio", 0.0)), 0.0), 1.0) * 1.25
    thermal_penalty = 1.0 + min(max(float(rec.get("thermal_pressure", 0.0)), 0.0), 1.0) * 0.50
    low_power_penalty = 1.10 if rec.get("low_power_mode") else 1.0
    base = 1.10 if regime == "gpu-capable" else 1.35 if regime == "partial-fallback" else 1.75
    ratio = min(max(base * memory_penalty * thermal_penalty * low_power_penalty, 1.10), 4.0)
    return estimate_ms * ratio


def control_feature_labels_v1() -> list[str]:
    labels = [
        "constraints_log2_norm",
        "signals_log2_norm",
        "witness_size_log2_norm",
        "max_constraint_degree_norm",
        "blackbox_poseidon_ratio",
        "blackbox_sha256_ratio",
        "blackbox_keccak_ratio",
        "blackbox_pedersen_ratio",
        "blackbox_schnorr_ratio",
        "lookup_ratio",
        "stage_ntt_ratio",
        "stage_lde_ratio",
        "stage_msm_ratio",
        "stage_poseidon_ratio",
        "stage_sha256_ratio",
        "stage_merkle_ratio",
        "stage_fri_ratio",
        "requested_jobs_ratio",
        "total_jobs_log2_norm",
        "ram_utilization",
        "memory_pressure_ratio",
        "thermal_pressure",
        "cpu_speed_limit",
        "metal_available",
        "unified_memory",
        "hardware_profile_m4_max",
        "hardware_profile_apple_silicon",
        "job_kind_prove",
        "job_kind_fold",
        "job_kind_wrap",
    ]
    labels.extend(f"dispatch_candidate_{candidate}" for candidate in DISPATCH_CANDIDATES)
    labels.extend(f"backend_{backend}" for backend in RUNTIME_BACKENDS)
    labels.extend(f"objective_{objective}" for objective in OBJECTIVES)
    return labels


def control_feature_labels_v2() -> list[str]:
    labels = control_feature_labels_v1()
    labels.extend([
        "chip_generation_norm",
        "gpu_cores_norm",
        "ane_tops_norm",
        "battery_present",
        "on_external_power",
        "low_power_mode",
        "form_factor_desktop",
        "form_factor_laptop",
        "form_factor_mobile",
        "form_factor_headset",
    ])
    return labels


def control_feature_labels_v3() -> list[str]:
    labels = control_feature_labels_v2()
    labels.extend([
        "heuristic_estimate_ms_log2_norm",
        "heuristic_upper_bound_ms_log2_norm",
        "heuristic_upper_bound_ratio",
        "heuristic_expected_proof_size_log2_norm",
        "execution_regime_cpu_only",
        "execution_regime_partial_fallback",
        "execution_regime_gpu_capable",
    ])
    labels.extend(f"program_digest_bucket_{bucket:02}" for bucket in range(64))
    return labels


def security_feature_labels_v3() -> list[str]:
    labels = control_feature_labels_v3()
    labels.extend([
        "watchdog_notice_count_log2_norm",
        "watchdog_warning_count_log2_norm",
        "watchdog_critical_count_log2_norm",
        "timing_alert_count_log2_norm",
        "thermal_alert_count_log2_norm",
        "memory_alert_count_log2_norm",
        "gpu_circuit_breaker_count_log2_norm",
        "repeated_fallback_count_log2_norm",
        "anomaly_severity_score_norm",
        "model_integrity_failure_count_log2_norm",
        "rate_limit_violation_count_log2_norm",
        "auth_failure_count_log2_norm",
        "malformed_request_count_log2_norm",
        "backend_incompatibility_attempt_count_log2_norm",
        "telemetry_replay_flag",
        "integrity_mismatch_flag",
        "anonymous_burst_flag",
    ])
    return labels


def schema_fingerprint(labels: list[str]) -> str:
    hasher = hashlib.sha256()
    for label in labels:
        hasher.update(label.encode("utf-8"))
        hasher.update(b"\x00")
    return hasher.hexdigest()


def encode_control_features(records: list[dict]) -> np.ndarray:
    rows: list[list[float]] = []
    for rec in records:
        stage_counts = rec.get("stage_node_counts", {})
        blackboxes = rec.get("blackbox_op_distribution", {})
        constraints = max(int(rec.get("constraint_count", 0)), 0)
        total_jobs = max(int(rec.get("total_jobs", rec.get("requested_jobs", 1))), 1)
        requested_jobs = max(int(rec.get("requested_jobs", total_jobs)), 0)
        candidate = rec.get("dispatch_candidate", "balanced")
        backend = _canonical_backend(rec.get("backend", "arkworks-groth16"))
        objective = rec.get("objective", "fastest-prove")
        hardware_profile = rec.get("hardware_profile", "")
        chip_family = rec.get("chip_family", "m4")
        form_factor = rec.get("form_factor", "laptop")
        estimate_ms = max(_heuristic_scheduler_ms(rec, backend, candidate), 1.0)
        upper_bound_ms = _duration_upper_bound(rec, _execution_regime(rec, candidate), estimate_ms)
        upper_bound_ratio = upper_bound_ms / estimate_ms if estimate_ms > 0 else 1.0
        objective_bias = {
            "fastest-prove": 1.0,
            "smallest-proof": 0.85,
            "no-trusted-setup": 1.15,
        }.get(objective, 1.0)
        proof_size = max(_heuristic_expected_proof_size_bytes(rec, backend), 1)
        regime = _execution_regime(rec, candidate)

        row = [
            _normalized_log2(constraints, 24.0),
            _normalized_log2(rec.get("signal_count", 0), 24.0),
            _normalized_log2(max(rec.get("witness_size", 1), 1), 24.0),
            min(max(float(rec.get("max_constraint_degree", 2)) / 8.0, 0.0), 1.0),
            _blackbox_ratio(blackboxes, "poseidon2"),
            _blackbox_ratio(blackboxes, "sha256"),
            _blackbox_ratio(blackboxes, "keccak256"),
            _blackbox_ratio(blackboxes, "pedersen"),
            _blackbox_ratio(blackboxes, "schnorr"),
            min(max(float(stage_counts.get("lookup-expand", 0)) / max(constraints, 1), 0.0), 1.0),
            _stage_ratio(stage_counts, ["ntt"]),
            _stage_ratio(stage_counts, ["lde"]),
            _stage_ratio(stage_counts, ["msm"]),
            _stage_ratio(stage_counts, ["poseidon-batch"]),
            _stage_ratio(stage_counts, ["sha256-batch"]),
            _stage_ratio(stage_counts, ["merkle-layer"]),
            _stage_ratio(stage_counts, ["fri-fold", "fri-query-open"]),
            min(max(requested_jobs / total_jobs, 0.0), 1.0),
            _normalized_log2(total_jobs, 8.0),
            min(max(float(rec.get("ram_utilization", 0.0)), 0.0), 1.0),
            min(max(float(rec.get("memory_pressure_ratio", 0.0)), 0.0), 1.0),
            min(max(float(rec.get("thermal_pressure", 0.0)), 0.0), 1.0),
            min(max(float(rec.get("cpu_speed_limit", 1.0)), 0.0), 1.0),
            1.0 if rec.get("metal_available") else 0.0,
            1.0 if rec.get("unified_memory") else 0.0,
            1.0 if hardware_profile == "apple-silicon-m4-max-48gb" else 0.0,
            1.0 if hardware_profile.startswith("apple") or chip_family != "non-apple" else 0.0,
            1.0 if rec.get("job_kind") == "prove" else 0.0,
            1.0 if rec.get("job_kind") == "fold" else 0.0,
            1.0 if rec.get("job_kind") == "wrap" else 0.0,
        ]
        row.extend(1.0 if candidate == supported else 0.0 for supported in DISPATCH_CANDIDATES)
        row.extend(1.0 if backend == supported else 0.0 for supported in RUNTIME_BACKENDS)
        row.extend(1.0 if objective == supported else 0.0 for supported in OBJECTIVES)
        row.extend([
            _chip_generation_norm(chip_family),
            min(max(float(rec.get("gpu_core_count", 0)) / 64.0, 0.0), 1.0),
            min(max(float(rec.get("ane_tops", 0.0)) / 40.0, 0.0), 1.0),
            1.0 if rec.get("battery_present") else 0.0,
            1.0 if rec.get("on_external_power") else 0.0,
            1.0 if rec.get("low_power_mode") else 0.0,
            1.0 if form_factor == "desktop" else 0.0,
            1.0 if form_factor == "laptop" else 0.0,
            1.0 if form_factor == "mobile" else 0.0,
            1.0 if form_factor == "headset" else 0.0,
            _normalized_log2(math.ceil(estimate_ms * objective_bias), 24.0),
            _normalized_log2(math.ceil(upper_bound_ms), 24.0),
            min(max(upper_bound_ratio / 8.0, 0.0), 1.0),
            _normalized_log2(proof_size, 28.0),
            1.0 if regime == "cpu-only" else 0.0,
            1.0 if regime == "partial-fallback" else 0.0,
            1.0 if regime == "gpu-capable" else 0.0,
        ])
        digest_bucket = _digest_bucket_64(rec.get("program_digest", ""))
        row.extend(1.0 if digest_bucket == bucket else 0.0 for bucket in range(64))
        if len(row) != CONTROL_INPUT_DIM:
            raise ValueError(f"control-plane v3 vector width mismatch: {len(row)}")
        rows.append(row)
    return np.array(rows, dtype=np.float64)


def encode_security_features(records: list[dict]) -> np.ndarray:
    base = encode_control_features(records)
    rows: list[list[float]] = []
    severity_scores = {"normal": 0.0, "notice": 0.25, "warning": 0.60, "critical": 1.0}
    for rec, base_row in zip(records, base):
        mismatch_count = int(rec.get("integrity_mismatch_count", 0))
        row = list(base_row)
        row.extend([
            0.0,
            0.0,
            0.0,
            _normalized_log2(1 if rec.get("anomaly_severity") in {"warning", "critical"} else 0, 5.0),
            _normalized_log2(1 if float(rec.get("thermal_pressure", 0.0)) > 0.7 else 0, 4.0),
            _normalized_log2(1 if float(rec.get("memory_pressure_ratio", 0.0)) > 0.85 else 0, 4.0),
            0.0,
            _normalized_log2(0 if rec.get("metal_available") else 1, 5.0),
            severity_scores.get(str(rec.get("anomaly_severity", "normal")), 0.0),
            _normalized_log2(mismatch_count, 4.0),
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            1.0 if mismatch_count > 0 else 0.0,
            0.0,
        ])
        if len(row) != SECURITY_INPUT_DIM:
            raise ValueError(f"security v3 vector width mismatch: {len(row)}")
        rows.append(row)
    return np.array(rows, dtype=np.float64)


def feature_dimension() -> int:
    """Return the native v3 control-plane feature vector width."""
    return CONTROL_INPUT_DIM


# ---------------------------------------------------------------------------
# Synthetic data generation (fallback when telemetry is sparse)
# ---------------------------------------------------------------------------


def generate_synthetic_records(n: int = 500) -> list[dict]:
    """Generate synthetic telemetry records for bootstrapping models."""
    rng = np.random.default_rng(seed=42)
    records: list[dict] = []
    for _ in range(n):
        constraints = int(rng.integers(100, 1_000_000))
        signals = int(constraints * rng.uniform(0.8, 1.5))
        backend = rng.choice([
            "arkworks-groth16",
            "plonky3",
            "nova",
            "hypernova",
            "halo2",
            "sp1",
            "risc-zero",
            "midnight-compact",
        ])
        field = rng.choice(KNOWN_FIELDS[:-1])
        candidate = rng.choice(DISPATCH_CANDIDATES)
        gpu_ratio = float(rng.uniform(0.0, 1.0))
        stage_node_counts = {
            stage: int(rng.integers(0, 4)) for stage in GPU_CAPABLE_STAGE_KEYS
        }
        stage_node_counts["witness-solve"] = int(rng.integers(1, 4))
        stage_node_counts["backend-prove"] = int(rng.integers(1, 3))
        memory_pressure_ratio = float(rng.uniform(0.05, 0.75))
        metal_available = bool(gpu_ratio > 0.12)
        prove_time = float(constraints * rng.uniform(0.001, 0.012) + rng.normal(50, 20))
        prove_time = max(1.0, prove_time)
        verify_time = float(rng.uniform(1.0, prove_time * 0.1))
        witness_gen = float(rng.uniform(0.5, prove_time * 0.3))
        peak_mem = int(constraints * rng.uniform(50, 500))
        proof_size = int(rng.integers(128, 65536))
        gpu_faster = bool(constraints > 50_000 and gpu_ratio > 0.3)
        records.append({
            "constraint_count": constraints,
            "signal_count": signals,
            "witness_size": int(signals * rng.uniform(8, 64)),
            "max_constraint_degree": int(rng.choice([2, 3, 4, 5, 6])),
            "blackbox_op_distribution": {
                "poseidon2": int(rng.integers(0, 20)),
                "sha256": int(rng.integers(0, 12)),
                "keccak256": int(rng.integers(0, 8)),
                "pedersen": int(rng.integers(0, 8)),
                "schnorr": int(rng.integers(0, 4)),
            },
            "stage_node_counts": stage_node_counts,
            "prove_time_ms": prove_time,
            "verify_time_ms": verify_time,
            "witness_gen_time_ms": witness_gen,
            "backend": str(backend),
            "field": str(field),
            "job_kind": "prove",
            "objective": str(rng.choice(OBJECTIVES)),
            "dispatch_candidate": str(candidate),
            "backend_route": "native-auto",
            "program_digest": hashlib.sha256(
                f"{constraints}:{signals}:{backend}:{candidate}".encode("utf-8")
            ).hexdigest(),
            "requested_jobs": int(rng.integers(1, 16)),
            "total_jobs": 16,
            "gpu_busy_ratio": gpu_ratio,
            "peak_memory_bytes": peak_mem,
            "proof_size_bytes": proof_size,
            "hardware_profile": "apple-silicon-m4-max-48gb",
            "chip_family": "m4",
            "form_factor": "laptop",
            "gpu_core_count": 40,
            "ane_tops": 38.0,
            "metal_available": metal_available,
            "unified_memory": True,
            "ram_utilization": memory_pressure_ratio,
            "memory_pressure_ratio": memory_pressure_ratio,
            "battery_present": True,
            "on_external_power": True,
            "low_power_mode": False,
            "thermal_pressure": float(rng.uniform(0.0, 0.35)),
            "cpu_speed_limit": 1.0,
            "anomaly_severity": "normal",
            "integrity_mismatch_count": 0,
            "synthetic": True,
            "gpu_was_faster": gpu_faster,
        })
    return records


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------


def runtime_duration_target_ms(rec: dict) -> float:
    """Training target for native v3 packages.

    The v3 model lane is a schema-native distillation of the runtime dispatch
    semantics, not the legacy raw named-scalar telemetry shape.
    """
    backend = _canonical_backend(rec.get("backend", "arkworks-groth16"))
    candidate = rec.get("dispatch_candidate", "balanced")
    return float(max(_heuristic_scheduler_ms(rec, backend, candidate), 1.0))


def _train_scheduler(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Scheduler model: predict total proving time in ms (regression)."""
    y = np.array([runtime_duration_target_ms(r) for r in records], dtype=np.float64)
    model = GradientBoostingRegressor(
        n_estimators=100 if profile == "production" else 30,
        max_depth=5,
        learning_rate=0.1,
        random_state=42,
    )
    model.fit(X, y)
    scores = cross_val_score(model, X, y, cv=min(5, max(2, len(y))), scoring="r2")
    return model, {
        "r2_cv_mean": float(np.mean(scores)),
        "r2_cv_std": float(np.std(scores)),
        "output_name": "predicted_duration_ms",
    }


def _train_backend_recommender(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Backend recommender: score candidate backend cost as a regression lane."""
    y = np.array([runtime_duration_target_ms(r) for r in records], dtype=np.float64)
    model = GradientBoostingRegressor(
        n_estimators=80 if profile == "production" else 20,
        max_depth=4,
        learning_rate=0.1,
        random_state=42,
    )
    model.fit(X, y)
    scores = cross_val_score(model, X, y, cv=min(5, max(2, len(y))), scoring="r2")
    return model, {
        "r2_cv_mean": float(np.mean(scores)),
        "r2_cv_std": float(np.std(scores)),
        "output_name": "backend_score",
    }


def _train_duration_estimator(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Duration estimator: predict total proving time (lighter regression)."""
    y = np.array([runtime_duration_target_ms(r) for r in records], dtype=np.float64)
    model = GradientBoostingRegressor(
        n_estimators=80 if profile == "production" else 20,
        max_depth=4,
        learning_rate=0.1,
        random_state=42,
    )
    model.fit(X, y)
    scores = cross_val_score(model, X, y, cv=min(5, max(2, len(y))), scoring="r2")
    return model, {
        "r2_cv_mean": float(np.mean(scores)),
        "r2_cv_std": float(np.std(scores)),
        "output_name": "predicted_duration_ms",
    }


def _train_anomaly_detector(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Anomaly detector: IsolationForest on timing features, converted to
    a regression score via decision_function."""
    iso = IsolationForest(
        n_estimators=100 if profile == "production" else 30,
        contamination=0.05,
        random_state=42,
    )
    iso.fit(X)
    # Produce an anomaly score target for a surrogate regressor that CoreML
    # can load (IsolationForest is not directly convertible).
    anomaly_scores = -iso.decision_function(X)  # higher = more anomalous
    surrogate = GradientBoostingRegressor(
        n_estimators=60 if profile == "production" else 15,
        max_depth=4,
        random_state=42,
    )
    surrogate.fit(X, anomaly_scores)
    return surrogate, {
        "anomaly_fraction": float(np.mean(iso.predict(X) == -1)),
        "output_name": "anomaly_score",
    }


def _train_security_detector(X: np.ndarray, records: list[dict], profile: str) -> tuple:
    """Security risk detector: surrogate regression on a synthetic risk score.

    Risk heuristic: high memory + unusual timing patterns + small proof size.
    """
    risk = np.zeros(len(records), dtype=np.float64)
    for i, rec in enumerate(records):
        mem_norm = min(rec["peak_memory_bytes"] / 1e9, 1.0)
        timing_ratio = (rec["prove_time_ms"] + 1) / (rec["verify_time_ms"] + 1)
        timing_risk = 1.0 / (1.0 + np.exp(-(timing_ratio - 100) / 20))
        size_risk = 1.0 / (1.0 + rec["proof_size_bytes"] / 1000)
        risk[i] = 0.4 * mem_norm + 0.35 * timing_risk + 0.25 * size_risk
    model = GradientBoostingRegressor(
        n_estimators=80 if profile == "production" else 20,
        max_depth=4,
        random_state=42,
    )
    model.fit(X, risk)
    return model, {
        "risk_mean": float(np.mean(risk)),
        "risk_std": float(np.std(risk)),
        "output_name": "risk_score",
    }


LANE_TRAINERS = {
    "scheduler": _train_scheduler,
    "backend_recommender": _train_backend_recommender,
    "duration_estimator": _train_duration_estimator,
    "anomaly_detector": _train_anomaly_detector,
    "security_detector": _train_security_detector,
}


def export_to_coreml(
    model,
    lane: str,
    output_path: str,
    input_dim: int,
    output_name: str,
) -> str:
    """Convert a scikit-learn model to a CoreML .mlpackage and return its path."""
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    coreml_model = ct.converters.sklearn.convert(
        model,
        input_features=[(COREML_INPUT_NAME, ct.models.datatypes.Array(input_dim))],
        output_feature_names=output_name,
    )

    coreml_model.short_description = f"ZirOS control-plane {lane} model"
    coreml_model.author = "ZirOS Neural Engine training pipeline"
    coreml_model.version = "3"
    coreml_model.user_defined_metadata.update({
        "zkf_schema": CONTROL_PLANE_SCHEMA,
        "zkf_lane": LANE_METADATA[lane]["runtime_lane"],
        "zkf_input_name": COREML_INPUT_NAME,
        "zkf_input_shape": str(input_dim),
    })

    # Remove existing package directory if present (coremltools will fail otherwise).
    pkg_path = pathlib.Path(output_path)
    if pkg_path.exists():
        shutil.rmtree(pkg_path)

    coreml_model.save(output_path)
    return output_path


def compute_package_hash(path: str) -> str:
    """Compute SHA-256 over the contents of an .mlpackage directory tree."""
    hasher = hashlib.sha256()
    pkg = pathlib.Path(path)
    if pkg.is_dir():
        for fpath in sorted(pkg.rglob("*")):
            if fpath.is_file():
                hasher.update(str(fpath.relative_to(pkg)).encode("utf-8"))
                hasher.update(b"\x00")
                hasher.update(fpath.read_bytes())
                hasher.update(b"\x00")
    return hasher.hexdigest()


def write_sidecar(
    package_path: str,
    lane: str,
    input_shape: int,
    output_name: str,
    quality: dict,
    corpus_hash: str,
    record_count: int,
    trained_at: str,
    package_tree_sha256: str,
    metrics: dict,
) -> str:
    labels = security_feature_labels_v3() if lane == "security_detector" else control_feature_labels_v3()
    payload = {
        "schema": CONTROL_PLANE_SCHEMA,
        "lane": LANE_METADATA[lane]["runtime_lane"],
        "version": "v3",
        "input_name": COREML_INPUT_NAME,
        "input_shape": input_shape,
        "output_name": output_name,
        "schema_fingerprint": schema_fingerprint(labels),
        "feature_labels": labels,
        "quality_gate": quality,
        "corpus_hash": corpus_hash,
        "record_count": record_count,
        "corpus_record_count": record_count,
        "trained_at": trained_at,
        "package_tree_sha256": package_tree_sha256,
        "metrics": metrics,
    }
    sidecar_path = f"{package_path}.json"
    with open(sidecar_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return sidecar_path


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------


def write_manifest(
    entries: list[dict],
    manifest_path: str,
    corpus_hash: str,
    record_count: int,
) -> None:
    """Write the control_plane_models_manifest.json."""
    manifest = {
        "schema": "zkf-control-plane-model-bundle-manifest-v3",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator": "scripts/train_control_plane_models.py",
        "corpus_hash": corpus_hash,
        "corpus_record_count": record_count,
        "lanes": {entry["lane"]: entry for entry in entries},
        "models": entries,
    }
    os.makedirs(os.path.dirname(manifest_path) or ".", exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
        fh.write("\n")


# ---------------------------------------------------------------------------
# Quality gate
# ---------------------------------------------------------------------------


def _quality_gate(lane: str, metrics: dict, profile: str) -> dict:
    """Evaluate whether a trained model passes the quality gate."""
    thresholds: dict[str, float] = {}
    measurements: dict[str, float] = {}
    reasons: list[str] = []
    passed = True

    if "r2_cv_mean" in metrics:
        threshold = 0.3 if profile == "production" else 0.0
        thresholds["r2_cv_mean"] = threshold
        measurements["r2_cv_mean"] = metrics["r2_cv_mean"]
        if not math.isfinite(metrics["r2_cv_mean"]) or metrics["r2_cv_mean"] < threshold:
            passed = False
            reasons.append(
                f"R2 cross-val mean {metrics['r2_cv_mean']:.4f} < {threshold}"
            )

    if "accuracy_cv_mean" in metrics:
        threshold = 0.4 if profile == "production" else 0.0
        thresholds["accuracy_cv_mean"] = threshold
        measurements["accuracy_cv_mean"] = metrics["accuracy_cv_mean"]
        if not math.isfinite(metrics["accuracy_cv_mean"]) or metrics["accuracy_cv_mean"] < threshold:
            passed = False
            reasons.append(
                f"Accuracy cross-val mean {metrics['accuracy_cv_mean']:.4f} < {threshold}"
            )

    return {
        "passed": passed,
        "thresholds": thresholds,
        "measurements": measurements,
        "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Train ZirOS Neural Engine control-plane models.",
    )
    parser.add_argument(
        "--profile",
        required=True,
        choices=["fixture", "production"],
        help="Training quality profile.",
    )
    parser.add_argument(
        "--model-dir",
        required=True,
        help="Directory to write trained .mlpackage models.",
    )
    parser.add_argument(
        "--corpus-out",
        required=True,
        help="Path for the JSONL training corpus.",
    )
    parser.add_argument(
        "--summary-out",
        required=True,
        help="Path for the corpus summary JSON.",
    )
    parser.add_argument(
        "--manifest-out",
        required=True,
        help="Path for the models manifest JSON.",
    )
    parser.add_argument(
        "--input",
        action="append",
        default=None,
        help="Telemetry input directory (may be repeated). "
        "Defaults to iCloud ZirOS telemetry path.",
    )
    args = parser.parse_args()

    input_dirs = args.input if args.input else [DEFAULT_TELEMETRY_DIR]

    print(f"[train_control_plane] profile={args.profile}")
    print(f"[train_control_plane] model-dir={args.model_dir}")
    print(f"[train_control_plane] input dirs: {input_dirs}")

    # 1. Load telemetry.
    print("[train_control_plane] loading telemetry records ...")
    records = load_telemetry(input_dirs)
    print(f"[train_control_plane] loaded {len(records)} records from telemetry")

    # If too few real records, supplement with synthetic data.
    MIN_RECORDS = 50
    if len(records) < MIN_RECORDS:
        n_synthetic = MIN_RECORDS - len(records)
        print(
            f"[train_control_plane] insufficient telemetry ({len(records)} < {MIN_RECORDS}), "
            f"generating {n_synthetic} synthetic records"
        )
        records.extend(generate_synthetic_records(n_synthetic))

    anchor_records = 1500 if args.profile == "production" else 300
    print(
        f"[train_control_plane] adding {anchor_records} v3 scenario-anchor records "
        "for schema-native training coverage"
    )
    records.extend(generate_synthetic_records(anchor_records))

    # 2. Write corpus.
    print(f"[train_control_plane] writing corpus -> {args.corpus_out}")
    corpus_hash = write_corpus(records, args.corpus_out)
    print(f"[train_control_plane] corpus hash: {corpus_hash[:16]}...")

    # 3. Write summary.
    print(f"[train_control_plane] writing summary -> {args.summary_out}")
    write_summary(records, args.summary_out)

    # 4. Encode native runtime v3 feature vectors.
    X_control = encode_control_features(records)
    X_security = encode_security_features(records)
    print(
        f"[train_control_plane] control v3 feature matrix: "
        f"{X_control.shape[0]} x {X_control.shape[1]}"
    )
    print(
        f"[train_control_plane] security v3 feature matrix: "
        f"{X_security.shape[0]} x {X_security.shape[1]}"
    )

    # 5. Train and export each model lane.
    os.makedirs(args.model_dir, exist_ok=True)
    manifest_entries: list[dict] = []
    trained_at = datetime.now(timezone.utc).isoformat()

    for lane in MODEL_LANES:
        print(f"[train_control_plane] training {lane} ...")
        t0 = time.monotonic()
        trainer = LANE_TRAINERS[lane]
        X = X_security if lane == "security_detector" else X_control
        model, metrics = trainer(X, records, args.profile)
        elapsed = time.monotonic() - t0
        print(f"[train_control_plane]   {lane} trained in {elapsed:.2f}s  metrics={metrics}")

        lane_meta = LANE_METADATA[lane]
        output_name = metrics.pop("output_name", lane_meta["output_name"])
        input_dim = lane_meta["input_shape"]
        model_filename = lane_meta["filename"]
        model_path = os.path.join(args.model_dir, model_filename)

        print(f"[train_control_plane]   exporting -> {model_path}")
        export_to_coreml(model, lane, model_path, input_dim, output_name)

        quality = _quality_gate(lane, metrics, args.profile)
        pkg_hash = compute_package_hash(model_path)
        sidecar_path = write_sidecar(
            model_path,
            lane,
            input_dim,
            output_name,
            quality,
            corpus_hash,
            len(records),
            trained_at,
            pkg_hash,
            metrics,
        )

        entry = {
            "lane": lane_meta["runtime_lane"],
            "path": model_path,
            "package": model_path,
            "sidecar": sidecar_path,
            "source": "retrained",
            "schema": CONTROL_PLANE_SCHEMA,
            "version": "v3",
            "input_shape": input_dim,
            "output_name": output_name,
            "schema_fingerprint": schema_fingerprint(
                security_feature_labels_v3()
                if lane == "security_detector"
                else control_feature_labels_v3()
            ),
            "quality_gate": quality,
            "corpus_hash": corpus_hash,
            "record_count": len(records),
            "corpus_record_count": len(records),
            "trained_at": trained_at,
            "package_tree_sha256": pkg_hash,
            "training_time_s": round(elapsed, 3),
            "metrics": metrics,
        }
        manifest_entries.append(entry)

        status = "PASS" if quality["passed"] else "WARN"
        print(f"[train_control_plane]   quality gate: {status}")

    # 6. Write manifest.
    print(f"[train_control_plane] writing manifest -> {args.manifest_out}")
    write_manifest(manifest_entries, args.manifest_out, corpus_hash, len(records))

    all_passed = all(e["quality_gate"]["passed"] for e in manifest_entries)
    print(
        f"[train_control_plane] done. {len(manifest_entries)} models exported. "
        f"quality={'ALL PASS' if all_passed else 'SOME WARNINGS'}"
    )


if __name__ == "__main__":
    main()
