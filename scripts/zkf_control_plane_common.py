#!/usr/bin/env python3
"""Shared corpus + feature helpers for ZKF control-plane training."""

from __future__ import annotations

import hashlib
import json
import math
import platform
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

BASE_FEATURE_LABELS = [
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
CONTROL_PLANE_ONE_HOT_LABELS = [
    "dispatch_candidate_cpu-only",
    "dispatch_candidate_hash-only",
    "dispatch_candidate_algebra-only",
    "dispatch_candidate_stark-heavy",
    "dispatch_candidate_balanced",
    "dispatch_candidate_full-gpu",
    "backend_plonky3",
    "backend_arkworks-groth16",
    "backend_nova",
    "backend_hypernova",
    "backend_sp1",
    "backend_risc-zero",
    "backend_halo2",
    "backend_midnight-compact",
    "objective_fastest-prove",
    "objective_smallest-proof",
    "objective_no-trusted-setup",
]
PLATFORM_FEATURE_LABELS = [
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
]
FEATURE_LABELS_V1 = BASE_FEATURE_LABELS + CONTROL_PLANE_ONE_HOT_LABELS
FEATURE_LABELS_V2 = FEATURE_LABELS_V1 + PLATFORM_FEATURE_LABELS
FEATURE_LABELS = FEATURE_LABELS_V2
THRESHOLD_OPTIMIZER_FEATURE_LABELS = [
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
    "stage_node_count_log2_norm",
    "constraint_count_log2_norm",
]
SECURITY_FEATURE_LABELS_V1 = FEATURE_LABELS_V1 + [
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
]
SECURITY_FEATURE_LABELS_V2 = FEATURE_LABELS_V2 + [
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
]
DISPATCH_CANDIDATES = [
    "cpu-only",
    "hash-only",
    "algebra-only",
    "stark-heavy",
    "balanced",
    "full-gpu",
]
BACKEND_LABELS = [
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
TRANSPARENT_BACKENDS = {"plonky3", "nova", "hypernova", "sp1", "risc-zero"}
DEFAULT_TELEMETRY_DIR = Path.home() / ".zkf" / "telemetry"
DEFAULT_MODEL_DIR = Path.home() / ".zkf" / "models"
SCHEMA_V1 = "zkf-neural-control-plane-v1"
SCHEMA_V2 = "zkf-neural-control-plane-v2"
THRESHOLD_SCHEMA_V1 = "zkf-neural-threshold-optimizer-v1"

def schema_fingerprint(labels: Iterable[str] | None = None) -> str:
    digest = hashlib.sha256()
    for label in (labels or FEATURE_LABELS):
        digest.update(label.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def control_plane_feature_labels(feature_schema: str) -> list[str]:
    if feature_schema == "v1":
        return list(FEATURE_LABELS_V1)
    if feature_schema == "v2":
        return list(FEATURE_LABELS_V2)
    raise ValueError(f"unsupported feature schema: {feature_schema}")


def security_feature_labels(feature_schema: str) -> list[str]:
    if feature_schema == "v1":
        return list(SECURITY_FEATURE_LABELS_V1)
    if feature_schema == "v2":
        return list(SECURITY_FEATURE_LABELS_V2)
    raise ValueError(f"unsupported feature schema: {feature_schema}")


def control_plane_schema_name(feature_schema: str) -> str:
    if feature_schema == "v1":
        return SCHEMA_V1
    if feature_schema == "v2":
        return SCHEMA_V2
    raise ValueError(f"unsupported feature schema: {feature_schema}")


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _load_json_path(path: Path) -> list[dict[str, Any]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(payload, dict):
        payload["_source_path"] = str(path)
        return [payload]
    return []


def _load_jsonl_path(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return records
    for lineno, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            payload["_source_path"] = f"{path}:{lineno}"
            records.append(payload)
    return records


def resolve_telemetry_paths(paths: Iterable[str] | None = None) -> list[Path]:
    candidates = set()
    if paths:
        for raw in paths:
            path = Path(raw).expanduser()
            if path.is_dir():
                candidates.update(path.glob("*.json"))
                candidates.update(path.glob("*.jsonl"))
            elif any(ch in raw for ch in "*?[]"):
                candidates.update(Path().glob(raw))
            elif path.exists():
                candidates.add(path)
    else:
        if DEFAULT_TELEMETRY_DIR.is_dir():
            candidates.update(DEFAULT_TELEMETRY_DIR.glob("*.json"))
            candidates.update(DEFAULT_TELEMETRY_DIR.glob("*.jsonl"))
    return sorted(path for path in candidates if path.suffix in {".json", ".jsonl"})


def load_telemetry_records(paths: Iterable[str] | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in resolve_telemetry_paths(paths):
        if path.suffix == ".jsonl":
            records.extend(_load_jsonl_path(path))
        else:
            records.extend(_load_json_path(path))
    return records


def corpus_hash(paths: Iterable[str] | None = None) -> str:
    digest = hashlib.sha256()
    for path in resolve_telemetry_paths(paths):
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def tool_versions() -> dict[str, str]:
    import coremltools as ct
    import numpy as np
    import sklearn

    versions = {
        "python": platform.python_version(),
        "coremltools": getattr(ct, "__version__", "unknown"),
        "numpy": getattr(np, "__version__", "unknown"),
        "scikit-learn": getattr(sklearn, "__version__", "unknown"),
    }
    try:
        import scipy

        versions["scipy"] = getattr(scipy, "__version__", "unknown")
    except Exception:
        pass
    return versions


def normalized_log2(value: int, max_log2: float) -> float:
    if value <= 0:
        return 0.0
    return min(1.0, max(0.0, (int(value) + 1).bit_length() / max_log2))


def _nested(payload: dict[str, Any], *keys: str, default: Any = None) -> Any:
    current: Any = payload
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
    return current if current is not None else default


def _float(value: Any, default: float = 0.0) -> float:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return default


def _int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return default


def _str(value: Any, default: str = "") -> str:
    return value if isinstance(value, str) else default


def _bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return default


def _chip_family(record: dict[str, Any]) -> str:
    features = _nested(record, "control_plane", "decision", "features", default={})
    if isinstance(features, dict):
        explicit = _str(features.get("chip_family"))
        if explicit:
            return explicit
        profile = _str(features.get("hardware_profile"))
    else:
        profile = ""
    profile = profile or _str(_nested(record, "metadata", "hardware_profile"))
    normalized = profile.lower()
    for chip in ["a18-pro", "a17-pro", "vision-pro", "a18", "m4", "m3", "m2", "m1"]:
        if chip in normalized:
            return chip
    return "non-apple"


def _form_factor(record: dict[str, Any]) -> str:
    features = _nested(record, "control_plane", "decision", "features", default={})
    if isinstance(features, dict):
        explicit = _str(features.get("form_factor"))
        if explicit:
            return explicit
        profile = _str(features.get("hardware_profile"))
    else:
        profile = ""
    normalized = profile.lower()
    if "vision" in normalized:
        return "headset"
    if "iphone" in normalized or normalized.startswith("apple-a"):
        return "mobile"
    if "macbook" in normalized or normalized.startswith("apple-silicon"):
        return "laptop"
    if "mac studio" in normalized or "mac mini" in normalized or "imac" in normalized:
        return "desktop"
    return "unknown"


def _chip_generation_norm(record: dict[str, Any]) -> float:
    return {
        "m1": 0.25,
        "m2": 0.50,
        "vision-pro": 0.50,
        "m3": 0.75,
        "m4": 1.00,
        "a17-pro": 0.90,
        "a18": 0.95,
        "a18-pro": 1.00,
    }.get(_chip_family(record), 0.60)


def _gpu_cores_norm(record: dict[str, Any]) -> float:
    raw = _nested(record, "control_plane", "decision", "features", "gpu_core_count")
    return min(1.0, _int(raw, 0) / 64.0)


def _ane_tops_norm(record: dict[str, Any]) -> float:
    raw = _nested(record, "control_plane", "decision", "features", "ane_tops")
    if raw is None:
        defaults = {
            "m1": 11.0,
            "m2": 15.8,
            "vision-pro": 15.8,
            "m3": 18.0,
            "m4": 38.0,
            "a17-pro": 35.0,
            "a18": 35.0,
            "a18-pro": 35.0,
        }
        raw = defaults.get(_chip_family(record), 0.0)
    return min(1.0, _float(raw, 0.0) / 40.0)


def _platform_bools(record: dict[str, Any]) -> tuple[bool, bool, bool]:
    features = _nested(record, "control_plane", "decision", "features", default={})
    if isinstance(features, dict):
        return (
            _bool(features.get("battery_present")),
            _bool(features.get("on_external_power")),
            _bool(features.get("low_power_mode")),
        )
    return False, False, False


def _stage_counts(record: dict[str, Any]) -> dict[str, int]:
    features = _nested(record, "control_plane", "decision", "features", "stage_node_counts", default={})
    if isinstance(features, dict) and features:
        return {str(key): _int(value, 0) for key, value in features.items()}
    batch_sizes = _nested(record, "dispatch_config", "batch_sizes", default={})
    if isinstance(batch_sizes, dict):
        return {str(key): _int(value, 0) for key, value in batch_sizes.items()}
    return {}


def _count_lookup_constraints(record: dict[str, Any]) -> int:
    return _stage_counts(record).get("lookup-expand", 0)


def _stage_ratio(record: dict[str, Any], names: list[str]) -> float:
    counts = _stage_counts(record)
    total = max(1, sum(int(value) for value in counts.values()))
    matched = sum(int(counts.get(name, 0)) for name in names)
    return matched / total


def build_feature_vector(
    record: dict[str, Any],
    *,
    candidate: str | None = None,
    backend: str | None = None,
    objective: str | None = None,
    feature_schema: str = "v2",
) -> list[float]:
    circuit = record.get("circuit_features", {})
    features = _nested(record, "control_plane", "decision", "features", default={})
    blackboxes = circuit.get("blackbox_op_distribution", {})
    if not isinstance(blackboxes, dict):
        blackboxes = {}
    total_blackboxes = max(1, sum(_int(value, 0) for value in blackboxes.values()))
    constraints = _int(circuit.get("constraint_count"), 1)
    signals = _int(circuit.get("signal_count"), 1)
    requested_jobs = _int(features.get("requested_jobs"), 1)
    total_jobs = max(requested_jobs, _int(features.get("total_jobs"), requested_jobs))

    vector = [
        normalized_log2(constraints, 24.0),
        normalized_log2(signals, 24.0),
        normalized_log2(_int(circuit.get("witness_size"), 1), 24.0),
        min(1.0, _int(circuit.get("max_constraint_degree"), 1) / 8.0),
        _int(blackboxes.get("poseidon2"), 0) / total_blackboxes,
        _int(blackboxes.get("sha256"), 0) / total_blackboxes,
        _int(blackboxes.get("keccak256"), 0) / total_blackboxes,
        _int(blackboxes.get("pedersen"), 0) / total_blackboxes,
        _int(blackboxes.get("schnorr"), 0) / total_blackboxes,
        _count_lookup_constraints(record) / max(1, constraints),
        _stage_ratio(record, ["ntt"]),
        _stage_ratio(record, ["lde"]),
        _stage_ratio(record, ["msm"]),
        _stage_ratio(record, ["poseidon-batch"]),
        _stage_ratio(record, ["sha256-batch"]),
        _stage_ratio(record, ["merkle-layer"]),
        _stage_ratio(record, ["fri-fold", "fri-query-open"]),
        requested_jobs / max(1, total_jobs),
        normalized_log2(total_jobs, 8.0),
        _float(features.get("ram_utilization"), _float(_nested(record, "hardware_state", "gpu_utilization", default=0.0))),
        _float(features.get("memory_pressure_ratio"), 0.0),
        _float(features.get("thermal_pressure"), 0.0),
        _float(features.get("cpu_speed_limit"), 1.0),
        1.0 if _nested(record, "hardware_state", "metal_available", default=False) else 0.0,
        1.0 if _float(features.get("unified_memory"), 0.0) > 0 else 0.0,
        1.0 if _str(features.get("hardware_profile")) == "apple-silicon-m4-max-48gb" else 0.0,
        1.0 if _str(features.get("hardware_profile")).startswith("apple-silicon") else 0.0,
        1.0 if _str(_nested(record, "metadata", "job_kind", default="prove")) == "prove" else 0.0,
        1.0 if _str(_nested(record, "metadata", "job_kind", default="prove")) == "fold" else 0.0,
        1.0 if _str(_nested(record, "metadata", "job_kind", default="prove")) == "wrap" else 0.0,
    ]

    for item in DISPATCH_CANDIDATES:
        vector.append(1.0 if candidate == item else 0.0)
    for item in BACKEND_LABELS:
        vector.append(1.0 if backend == item else 0.0)
    for item in OBJECTIVES:
        vector.append(1.0 if objective == item else 0.0)
    if feature_schema == "v1":
        return vector
    if feature_schema != "v2":
        raise ValueError(f"unsupported feature schema: {feature_schema}")
    battery_present, on_external_power, low_power_mode = _platform_bools(record)
    form_factor = _form_factor(record)
    vector.extend(
        [
            _chip_generation_norm(record),
            _gpu_cores_norm(record),
            _ane_tops_norm(record),
            1.0 if battery_present else 0.0,
            1.0 if on_external_power else 0.0,
            1.0 if low_power_mode else 0.0,
            1.0 if form_factor == "desktop" else 0.0,
            1.0 if form_factor == "laptop" else 0.0,
            1.0 if form_factor == "mobile" else 0.0,
            1.0 if form_factor == "headset" else 0.0,
        ]
    )
    return vector


def build_threshold_optimizer_feature_vector(record: dict[str, Any]) -> list[float]:
    form_factor = _form_factor(record)
    battery_present, on_external_power, low_power_mode = _platform_bools(record)
    counts = _stage_counts(record)
    return [
        _chip_generation_norm(record),
        _gpu_cores_norm(record),
        _ane_tops_norm(record),
        1.0 if battery_present else 0.0,
        1.0 if on_external_power else 0.0,
        1.0 if low_power_mode else 0.0,
        1.0 if form_factor == "desktop" else 0.0,
        1.0 if form_factor == "laptop" else 0.0,
        1.0 if form_factor == "mobile" else 0.0,
        1.0 if form_factor == "headset" else 0.0,
        normalized_log2(max(1, sum(counts.values())), 16.0),
        normalized_log2(_int(record.get("circuit_features", {}).get("constraint_count"), 1), 24.0),
    ]


def _watchdog_counts(record: dict[str, Any]) -> dict[str, int]:
    counts = Counter()
    for alert in record.get("watchdog_alerts", []) or []:
        if not isinstance(alert, dict):
            continue
        severity = _str(alert.get("severity"))
        kind = _str(alert.get("kind"))
        if severity:
            counts[f"severity:{severity}"] += 1
        if kind:
            counts[f"kind:{kind}"] += 1
    return counts


def _model_integrity(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("model_integrity")
    if isinstance(value, dict):
        return value
    value = record.get("runtime_model_integrity")
    if isinstance(value, dict):
        return value
    value = _nested(record, "control_plane", "decision", "model_catalog", default={})
    return value if isinstance(value, dict) else {}


def _security_verdict(record: dict[str, Any]) -> dict[str, Any]:
    value = record.get("security_verdict")
    if isinstance(value, dict):
        return value
    value = record.get("runtime_security_verdict")
    if isinstance(value, dict):
        return value
    return {}


def _normalized_count(value: int, max_log2: float) -> float:
    return normalized_log2(max(0, value), max_log2)


def build_security_feature_vector(record: dict[str, Any], *, feature_schema: str = "v2") -> list[float]:
    counts = _watchdog_counts(record)
    integrity = _model_integrity(record)
    verdict = _security_verdict(record)
    metadata = record.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    anomaly = _nested(record, "control_plane", "anomaly_verdict", default={})
    if not isinstance(anomaly, dict):
        anomaly = {}
    anomaly_severity = _str(anomaly.get("severity"), _str(verdict.get("risk_level"), "low"))
    anomaly_score = {
        "low": 0.0,
        "normal": 0.0,
        "notice": 0.25,
        "moderate": 0.4,
        "warning": 0.65,
        "high": 0.8,
        "critical": 1.0,
        "model-integrity-critical": 1.0,
    }.get(anomaly_severity, 0.0)
    base = build_feature_vector(
        record,
        candidate=chosen_candidate(record),
        backend=chosen_backend(record),
        objective=record_objective(record),
        feature_schema=feature_schema,
    )
    base.extend(
        [
            _normalized_count(counts.get("severity:notice", 0), 5.0),
            _normalized_count(counts.get("severity:warning", 0), 5.0),
            _normalized_count(counts.get("severity:critical", 0), 5.0),
            _normalized_count(counts.get("kind:timing-anomaly", 0), 5.0),
            _normalized_count(counts.get("kind:thermal-throttle", 0), 4.0),
            _normalized_count(counts.get("kind:memory-pressure-spike", 0), 4.0),
            _normalized_count(counts.get("kind:gpu-circuit-breaker-tripped", 0), 4.0),
            _normalized_count(_int(record.get("report", {}).get("fallback_nodes")), 5.0)
            if isinstance(record.get("report"), dict)
            else _normalized_count(_int(record.get("fallback_nodes")), 5.0),
            float(anomaly_score),
            _normalized_count(
                len(integrity.get("integrity_failures", []) or []),
                4.0,
            ),
            _normalized_count(_int(metadata.get("rate_limit_violation_count")), 5.0),
            _normalized_count(_int(metadata.get("auth_failure_count")), 5.0),
            _normalized_count(_int(metadata.get("malformed_request_count")), 5.0),
            _normalized_count(
                _int(metadata.get("backend_incompatibility_attempt_count")),
                5.0,
            ),
            1.0 if metadata.get("telemetry_replay_detected") else 0.0,
            1.0 if (metadata.get("integrity_mismatch_flags") or []) else 0.0,
            1.0 if metadata.get("anonymous_burst") else 0.0,
        ]
    )
    return base


def security_risk_label(record: dict[str, Any]) -> float:
    verdict = _security_verdict(record)
    if isinstance(verdict.get("risk_score"), (int, float)):
        return max(0.0, min(1.0, float(verdict["risk_score"])))
    label = 0.0
    for alert in record.get("watchdog_alerts", []) or []:
        if not isinstance(alert, dict):
            continue
        severity = _str(alert.get("severity"))
        if severity == "critical":
            label = max(label, 1.0)
        elif severity == "warning":
            label = max(label, 0.75)
        elif severity == "notice":
            label = max(label, 0.4)
    integrity = _model_integrity(record)
    if integrity.get("integrity_failures"):
        label = max(label, 1.0)
    anomaly = _nested(record, "control_plane", "anomaly_verdict", default={})
    if isinstance(anomaly, dict):
        severity = _str(anomaly.get("severity"))
        if severity == "critical":
            label = max(label, 1.0)
        elif severity == "warning":
            label = max(label, 0.7)
        elif severity == "notice":
            label = max(label, 0.3)
    metadata = record.get("metadata", {})
    if isinstance(metadata, dict):
        if _int(metadata.get("rate_limit_violation_count")) > 0:
            label = max(label, 0.85)
        if _int(metadata.get("auth_failure_count")) > 0:
            label = max(label, 0.8)
        if _int(metadata.get("malformed_request_count")) > 0:
            label = max(label, 0.8)
        if metadata.get("telemetry_replay_detected"):
            label = max(label, 0.9)
        if metadata.get("integrity_mismatch_flags"):
            label = max(label, 0.9)
    return label


def chosen_candidate(record: dict[str, Any]) -> str:
    return _str(
        _nested(record, "control_plane", "decision", "dispatch_plan", "candidate"),
        _str(_nested(record, "dispatch_config", "dispatch_candidate"), "cpu-only"),
    )


def chosen_backend(record: dict[str, Any]) -> str:
    return _str(_nested(record, "metadata", "backend_used"), "arkworks-groth16")


def record_role(record: dict[str, Any]) -> str:
    return _str(_nested(record, "metadata", "fixture_training_role"), "realized")


def scenario_id(record: dict[str, Any]) -> str:
    return _str(
        _nested(record, "metadata", "fixture_scenario_id"),
        _str(record.get("_source_path"), "unknown-scenario"),
    )


def record_objective(record: dict[str, Any]) -> str:
    raw = _str(
        _nested(record, "metadata", "optimization_objective"),
        _str(_nested(record, "control_plane", "decision", "features", "objective"), "fastest-prove"),
    )
    return raw if raw in OBJECTIVES else "fastest-prove"


def transparent_backend(backend: str) -> bool:
    return backend in TRANSPARENT_BACKENDS


def job_kind(record: dict[str, Any]) -> str:
    return _str(_nested(record, "metadata", "job_kind"), "prove")


def field_used(record: dict[str, Any]) -> str:
    return _str(_nested(record, "metadata", "field_used"), "unknown")


def hardware_profile(record: dict[str, Any]) -> str:
    return _str(
        _nested(record, "control_plane", "decision", "features", "hardware_profile"),
        _str(_nested(record, "metadata", "hardware_profile"), "unknown"),
    )


def is_fixture_record(record: dict[str, Any]) -> bool:
    source = _str(record.get("_source_path"))
    if "zkf-runtime/tests/fixtures/neural_engine" in source:
        return True
    metadata = record.get("metadata", {})
    if isinstance(metadata, dict):
        return any(str(key).startswith("fixture_") for key in metadata)
    return False


def degraded_state(record: dict[str, Any]) -> str:
    explicit_variant = _str(_nested(record, "metadata", "fixture_variant"))
    if explicit_variant == "degraded":
        return "degraded"
    if explicit_variant in {"realized", "nominal"}:
        return "nominal"

    features = _nested(record, "control_plane", "decision", "features", default={})
    if not isinstance(features, dict):
        features = {}
    hardware = record.get("hardware_state", {})
    if not isinstance(hardware, dict):
        hardware = {}

    thermal_pressure = _float(features.get("thermal_pressure"), _float(hardware.get("thermal_pressure"), 0.0))
    cpu_speed_limit = _float(features.get("cpu_speed_limit"), _float(hardware.get("cpu_speed_limit"), 1.0))
    memory_pressure_ratio = _float(features.get("memory_pressure_ratio"), 0.0)
    memory_pressure_bytes = _float(hardware.get("memory_pressure_bytes"), 0.0)
    if (
        thermal_pressure >= 0.2
        or cpu_speed_limit < 0.97
        or memory_pressure_ratio >= 0.25
        or memory_pressure_bytes >= 12_000_000_000.0
    ):
        return "degraded"
    return "nominal"


def proof_size_bytes(record: dict[str, Any]) -> int:
    return _int(_nested(record, "metadata", "proof_size_bytes"), 0)


def duration_ms(record: dict[str, Any]) -> float:
    return _float(_nested(record, "outcome", "total_proving_time_ms"), 0.0)


def anomaly_budget(record: dict[str, Any]) -> float:
    baseline_duration = _float(
        _nested(record, "control_plane", "decision", "duration_estimate", "upper_bound_ms"),
        _float(
            _nested(record, "control_plane", "decision", "duration_estimate", "estimate_ms"),
            _float(
                _nested(record, "control_plane", "decision", "duration_estimate", "predicted_wall_time_ms"),
                max(duration_ms(record), 1.0),
            ),
        ),
    )
    baseline_size = max(
        1,
        _int(
            _nested(record, "control_plane", "decision", "anomaly_baseline", "expected_proof_size_bytes"),
            max(proof_size_bytes(record), 1),
        ),
    )
    duration_ratio = duration_ms(record) / max(baseline_duration, 1.0)
    proof_ratio = proof_size_bytes(record) / max(1.0, float(baseline_size))
    return max(duration_ratio, proof_ratio, 1.0)


def safe_r2(y_true: Any, y_pred: Any) -> float:
    from sklearn.metrics import r2_score

    try:
        value = float(r2_score(y_true, y_pred))
    except Exception:
        return 0.0
    if math.isnan(value) or math.isinf(value):
        return 0.0
    return value


def build_quality_gate(
    thresholds: dict[str, float],
    measurements: dict[str, Any],
) -> dict[str, Any]:
    numeric_measurements = {
        key: float(value)
        for key, value in measurements.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }
    reasons: list[str] = []
    for threshold_key, threshold_value in thresholds.items():
        if threshold_key.endswith("_min"):
            metric_key = threshold_key[: -len("_min")]
            measured = numeric_measurements.get(metric_key)
            if measured is None:
                reasons.append(f"missing measurement '{metric_key}' for threshold '{threshold_key}'")
            elif measured < float(threshold_value):
                reasons.append(
                    f"{metric_key}={measured:.6f} is below required minimum {float(threshold_value):.6f}"
                )
        elif threshold_key.endswith("_max"):
            metric_key = threshold_key[: -len("_max")]
            measured = numeric_measurements.get(metric_key)
            if measured is None:
                reasons.append(f"missing measurement '{metric_key}' for threshold '{threshold_key}'")
            elif measured > float(threshold_value):
                reasons.append(
                    f"{metric_key}={measured:.6f} exceeds allowed maximum {float(threshold_value):.6f}"
                )
        else:
            measured = numeric_measurements.get(threshold_key)
            if measured is None:
                reasons.append(
                    f"missing measurement '{threshold_key}' for threshold '{threshold_key}'"
                )
            elif measured != float(threshold_value):
                reasons.append(
                    f"{threshold_key}={measured:.6f} did not match required value {float(threshold_value):.6f}"
                )

    return {
        "passed": not reasons,
        "thresholds": {key: float(value) for key, value in thresholds.items()},
        "measurements": numeric_measurements,
        "reasons": reasons,
    }


def write_sidecar(
    model_path: Path,
    lane: str,
    metrics: dict[str, Any],
    output_name: str,
    *,
    corpus_digest: str | None = None,
    trainer_script: str | None = None,
    quality_gate: dict[str, Any] | None = None,
    extra_metadata: dict[str, Any] | None = None,
    feature_labels: list[str] | None = None,
    schema: str | None = None,
    version: str | None = None,
) -> None:
    labels = list(feature_labels or FEATURE_LABELS)
    payload = {
        "lane": lane,
        "version": version or "v1",
        "schema": schema or SCHEMA_V1,
        "schema_fingerprint": schema_fingerprint(labels),
        "feature_labels": labels,
        "input_shape": len(labels),
        "output_name": output_name,
        "metrics": metrics,
        "corpus_hash": corpus_digest,
        "trainer_script": trainer_script,
        "tool_versions": tool_versions(),
    }
    if quality_gate is not None:
        payload["quality_gate"] = quality_gate
    if extra_metadata:
        payload.update(extra_metadata)
    sidecar = Path(f"{model_path}.json")
    ensure_parent(sidecar)
    sidecar.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def convert_sklearn_regressor(
    model: Any,
    output_name: str,
    out_path: Path,
    *,
    feature_count: int | None = None,
) -> None:
    import coremltools as ct

    out_path.parent.mkdir(parents=True, exist_ok=True)
    mlmodel = ct.converters.sklearn.convert(
        model,
        input_features=[
            ("features", ct.models.datatypes.Array(feature_count or len(FEATURE_LABELS)))
        ],
        output_feature_names=output_name,
    )
    mlmodel.save(str(out_path))


def summarize_corpus(records: list[dict[str, Any]]) -> dict[str, Any]:
    job_kind_counts: Counter[str] = Counter()
    objective_counts: Counter[str] = Counter()
    backend_counts: Counter[str] = Counter()
    field_counts: Counter[str] = Counter()
    hardware_profile_counts: Counter[str] = Counter()
    state_counts: Counter[str] = Counter()
    scenario_ids: set[str] = set()
    live_records = 0
    fixture_records = 0
    telemetry_sequence_ids: Counter[str] = Counter()
    replay_guards: Counter[str] = Counter()
    integrity_mismatch_records = 0

    for record in records:
        job_kind_counts[job_kind(record)] += 1
        objective_counts[record_objective(record)] += 1
        backend_counts[chosen_backend(record)] += 1
        field_counts[field_used(record)] += 1
        hardware_profile_counts[hardware_profile(record)] += 1
        state_counts[degraded_state(record)] += 1
        scenario_ids.add(scenario_id(record))
        if is_fixture_record(record):
            fixture_records += 1
        else:
            live_records += 1
        metadata = record.get("metadata", {})
        if isinstance(metadata, dict):
            sequence_id = _str(metadata.get("telemetry_sequence_id"))
            replay_guard = _str(metadata.get("telemetry_replay_guard"))
            if sequence_id:
                telemetry_sequence_ids[sequence_id] += 1
            if replay_guard:
                replay_guards[replay_guard] += 1
            if metadata.get("integrity_mismatch_flags"):
                integrity_mismatch_records += 1

    total_records = len(records)
    fixture_share = float(fixture_records / total_records) if total_records else 0.0
    return {
        "schema": "zkf-neural-corpus-summary-v1",
        "total_records": total_records,
        "distinct_scenarios": len(scenario_ids),
        "job_kinds": dict(sorted(job_kind_counts.items())),
        "objectives": dict(sorted(objective_counts.items())),
        "backends": dict(sorted(backend_counts.items())),
        "fields": dict(sorted(field_counts.items())),
        "hardware_profiles": dict(sorted(hardware_profile_counts.items())),
        "states": dict(sorted(state_counts.items())),
        "live_records": live_records,
        "fixture_records": fixture_records,
        "fixture_share": fixture_share,
        "duplicate_sequence_ids": sum(
            count - 1 for count in telemetry_sequence_ids.values() if count > 1
        ),
        "duplicate_replay_guards": sum(
            count - 1 for count in replay_guards.values() if count > 1
        ),
        "integrity_mismatch_records": integrity_mismatch_records,
    }


def validate_corpus_summary(
    summary: dict[str, Any],
    *,
    min_records: int = 0,
    min_live_records: int = 0,
    min_scenarios: int = 0,
    min_backends: int = 0,
    min_fields: int = 0,
    required_job_kinds: Iterable[str] = (),
    required_objectives: Iterable[str] = (),
    required_backends: Iterable[str] = (),
    required_fields: Iterable[str] = (),
    require_nominal: bool = False,
    require_degraded: bool = False,
    max_fixture_share: float | None = None,
    max_duplicate_sequence_ids: int = 0,
    max_duplicate_replay_guards: int = 0,
    max_integrity_mismatch_records: int = 0,
) -> list[str]:
    reasons: list[str] = []
    total_records = _int(summary.get("total_records"))
    live_records = _int(summary.get("live_records"))
    distinct_scenarios = _int(summary.get("distinct_scenarios"))
    fixture_share = _float(summary.get("fixture_share"))
    job_kinds = summary.get("job_kinds", {})
    objectives = summary.get("objectives", {})
    backends = summary.get("backends", {})
    fields = summary.get("fields", {})
    states = summary.get("states", {})
    duplicate_sequence_ids = _int(summary.get("duplicate_sequence_ids"))
    duplicate_replay_guards = _int(summary.get("duplicate_replay_guards"))
    integrity_mismatch_records = _int(summary.get("integrity_mismatch_records"))

    if total_records < min_records:
        reasons.append(f"total_records={total_records} is below required minimum {min_records}")
    if live_records < min_live_records:
        reasons.append(f"live_records={live_records} is below required minimum {min_live_records}")
    if distinct_scenarios < min_scenarios:
        reasons.append(
            f"distinct_scenarios={distinct_scenarios} is below required minimum {min_scenarios}"
        )
    if len(backends) < min_backends:
        reasons.append(f"backend_count={len(backends)} is below required minimum {min_backends}")
    if len(fields) < min_fields:
        reasons.append(f"field_count={len(fields)} is below required minimum {min_fields}")
    if max_fixture_share is not None and fixture_share > max_fixture_share:
        reasons.append(
            f"fixture_share={fixture_share:.3f} exceeds allowed maximum {max_fixture_share:.3f}"
        )
    if duplicate_sequence_ids > max_duplicate_sequence_ids:
        reasons.append(
            f"duplicate_sequence_ids={duplicate_sequence_ids} exceeds allowed maximum {max_duplicate_sequence_ids}"
        )
    if duplicate_replay_guards > max_duplicate_replay_guards:
        reasons.append(
            f"duplicate_replay_guards={duplicate_replay_guards} exceeds allowed maximum {max_duplicate_replay_guards}"
        )
    if integrity_mismatch_records > max_integrity_mismatch_records:
        reasons.append(
            f"integrity_mismatch_records={integrity_mismatch_records} exceeds allowed maximum {max_integrity_mismatch_records}"
        )
    for value in required_job_kinds:
        if _int(job_kinds.get(value)) <= 0:
            reasons.append(f"missing required job kind '{value}'")
    for value in required_objectives:
        if _int(objectives.get(value)) <= 0:
            reasons.append(f"missing required objective '{value}'")
    for value in required_backends:
        if _int(backends.get(value)) <= 0:
            reasons.append(f"missing required backend '{value}'")
    for value in required_fields:
        if _int(fields.get(value)) <= 0:
            reasons.append(f"missing required field '{value}'")
    if require_nominal and _int(states.get("nominal")) <= 0:
        reasons.append("missing nominal telemetry records")
    if require_degraded and _int(states.get("degraded")) <= 0:
        reasons.append("missing degraded telemetry records")
    return reasons
