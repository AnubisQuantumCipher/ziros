#!/usr/bin/env python3
"""ZirOS Production Soak Monitor v2 — live visual operations dashboard.

Usage:
    python3 scripts/soak_monitor.py [--port 8777] [--dir /tmp/zkf-production-soak-current]

Opens a browser to a self-contained dashboard that auto-refreshes every 5 seconds.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

DEFAULT_DIR = "/tmp/zkf-production-soak-current"
DEFAULT_PORT = 8777


def read_json(path: Path) -> dict | list | None:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def file_sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    except Exception:
        return None


def collect_thermal() -> dict:
    """Collect macOS thermal / power pressure via pmset and sysctl.

    Apple Silicon does not expose machdep.xcpm.* keys.  We use:
      - ``pmset -g therm``  → thermal_warning (0/1/2) + performance_warning
      - ``sysctl kern.memorystatus_vm_pressure_level``
      - ``pmset -g batt``   → power source + battery %
      - soak-process CPU% via ``ps``
    """
    thermal: dict = {
        "cpu_thermal_level": 0,
        "gpu_thermal_level": 0,
        "io_thermal_level": 0,
        "cpu_speed_limit": 100,
        "thermal_pressure": "nominal",
        "thermal_warning": 0,      # 0=none, 1=moderate, 2=serious
        "performance_warning": 0,
        "memory_pressure_level": 0,
        "battery_state": None,
        "power_source": None,
        "soak_cpu_pct": None,
        "soak_rss_mb": None,
    }

    # ── pmset -g therm  (works on both Intel and Apple Silicon) ──
    try:
        out = subprocess.run(
            ["pmset", "-g", "therm"], capture_output=True, text=True, timeout=3
        ).stdout
        # Lines like "CPU_Scheduler_Limit  = 100"  or  "CPU_Speed_Limit  = 100"
        for line in out.splitlines():
            low = line.lower()
            if "cpu_speed_limit" in low:
                m = re.search(r"=\s*(\d+)", line)
                if m:
                    thermal["cpu_speed_limit"] = int(m.group(1))
            # "thermal warning level" or "No thermal warning"
            if "thermal warning level" in low:
                m = re.search(r"(\d+)", line.split("=")[-1] if "=" in line else line)
                if m:
                    thermal["thermal_warning"] = int(m.group(1))
            if "performance warning" in low:
                m = re.search(r"(\d+)", line.split("=")[-1] if "=" in line else line)
                if m:
                    thermal["performance_warning"] = int(m.group(1))
    except Exception:
        pass

    # ── Intel-specific xcpm keys (no-op on Apple Silicon) ──
    try:
        out = subprocess.run(
            ["sysctl", "machdep.xcpm.cpu_thermal_level",
             "machdep.xcpm.gpu_thermal_level",
             "machdep.xcpm.io_thermal_level",
             "machdep.xcpm.cpu_speed_limit",
             "kern.memorystatus_vm_pressure_level"],
            capture_output=True, text=True, timeout=2,
        ).stdout
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) != 2:
                continue
            key, val = parts[0].strip(), parts[1].strip()
            try:
                v = int(val)
            except ValueError:
                continue
            if key == "machdep.xcpm.cpu_thermal_level":
                thermal["cpu_thermal_level"] = v
            elif key == "machdep.xcpm.gpu_thermal_level":
                thermal["gpu_thermal_level"] = v
            elif key == "machdep.xcpm.io_thermal_level":
                thermal["io_thermal_level"] = v
            elif key == "machdep.xcpm.cpu_speed_limit":
                thermal["cpu_speed_limit"] = v
            elif key == "kern.memorystatus_vm_pressure_level":
                thermal["memory_pressure_level"] = v
    except Exception:
        pass

    # ── Derive overall thermal pressure label ──
    tw = thermal["thermal_warning"]
    pw = thermal["performance_warning"]
    speed = thermal["cpu_speed_limit"]
    if tw >= 2 or speed < 70:
        thermal["thermal_pressure"] = "critical"
    elif tw >= 1 or speed < 85:
        thermal["thermal_pressure"] = "high"
    elif pw >= 1 or speed < 95:
        thermal["thermal_pressure"] = "elevated"
    else:
        thermal["thermal_pressure"] = "nominal"

    # ── Battery / power source ──
    try:
        out = subprocess.run(
            ["pmset", "-g", "batt"], capture_output=True, text=True, timeout=3
        ).stdout
        if "AC Power" in out:
            thermal["power_source"] = "AC"
        elif "Battery" in out:
            thermal["power_source"] = "Battery"
        m = re.search(r"(\d+)%", out)
        if m:
            thermal["battery_state"] = int(m.group(1))
    except Exception:
        pass

    # ── Soak process CPU% and RSS ──
    try:
        out = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=3
        ).stdout
        for line in out.splitlines():
            if "runtime certify" in line and "--mode soak" in line:
                cols = line.split()
                if len(cols) >= 6:
                    thermal["soak_cpu_pct"] = float(cols[2])
                    thermal["soak_rss_mb"] = int(cols[5]) / 1024  # ps RSS is in KB
                break
    except Exception:
        pass

    return thermal


def _detect_memory_pressure_free_pct() -> float | None:
    """Use ``memory_pressure -Q`` (same signal the runtime uses in resources.rs)."""
    try:
        out = subprocess.run(
            ["memory_pressure", "-Q"], capture_output=True, text=True, timeout=3
        )
        if out.returncode != 0:
            return None
        for line in out.stdout.splitlines():
            if "System-wide memory free percentage:" in line:
                _, pct_text = line.split("System-wide memory free percentage:")
                return float(pct_text.strip().rstrip("%"))
    except Exception:
        pass
    return None


def collect_process_memory() -> dict:
    """Snapshot current process-level memory via memory_pressure, vm_stat, and sysctl.

    Prefers ``memory_pressure -Q`` (the same signal the runtime's resources.rs uses)
    over raw vm_stat counters, because it already accounts for reclaimable memory and
    avoids false warnings from transient VM counter skew on Apple Silicon.
    """
    mem: dict = {
        "ram_used_bytes": None, "ram_free_bytes": None, "ram_total_bytes": None,
        "swap_used_bytes": None, "vm_page_size": 16384,
        "memory_pressure_free_pct": None,  # from memory_pressure -Q
        "utilization_pct": None,           # derived
        "pressure_level": "normal",        # derived: normal / elevated / high / critical
        "pressure_source": "vm_stat",      # which signal drove the classification
    }
    try:
        out = subprocess.run(
            ["sysctl", "hw.memsize"], capture_output=True, text=True, timeout=2
        ).stdout
        for line in out.splitlines():
            if "hw.memsize" in line:
                mem["ram_total_bytes"] = int(line.split(":")[-1].strip())
    except Exception:
        pass

    # Prefer memory_pressure -Q (matches runtime resources.rs)
    free_pct = _detect_memory_pressure_free_pct()
    if free_pct is not None:
        mem["memory_pressure_free_pct"] = free_pct
        mem["utilization_pct"] = round(100.0 - free_pct, 1)
        mem["pressure_source"] = "memory_pressure"
        total = mem["ram_total_bytes"] or 0
        if total > 0:
            mem["ram_free_bytes"] = int(total * free_pct / 100.0)
            mem["ram_used_bytes"] = total - mem["ram_free_bytes"]

    # Fallback / supplement with vm_stat
    try:
        out = subprocess.run(
            ["vm_stat"], capture_output=True, text=True, timeout=2
        ).stdout
        pages: dict = {}
        for line in out.splitlines():
            m = re.match(r'(.+?):\s+(\d+)', line)
            if m:
                pages[m.group(1).strip().lower()] = int(m.group(2))
        ps = mem["vm_page_size"]
        free = pages.get("pages free", 0) * ps
        active = pages.get("pages active", 0) * ps
        inactive = pages.get("pages inactive", 0) * ps
        wired = pages.get("pages wired down", 0) * ps
        compressed = pages.get("pages occupied by compressor", 0) * ps
        purgeable = pages.get("pages purgeable", 0) * ps
        speculative = pages.get("pages speculative", 0) * ps
        mem["compressed_bytes"] = compressed
        mem["wired_bytes"] = wired
        mem["purgeable_bytes"] = purgeable
        if mem["ram_free_bytes"] is None:
            # vm_stat fallback
            mem["ram_free_bytes"] = free + inactive
            mem["ram_used_bytes"] = active + wired + compressed
        if mem["utilization_pct"] is None and mem["ram_total_bytes"]:
            raw_available = free + inactive + speculative + purgeable - compressed
            clamped = max(0, raw_available)
            mem["utilization_pct"] = round(
                (mem["ram_total_bytes"] - clamped) / mem["ram_total_bytes"] * 100, 1
            )
            mem["pressure_source"] = "vm_stat"
    except Exception:
        pass

    # Classify pressure level (same thresholds as resources.rs)
    util = mem.get("utilization_pct") or 0
    if util > 93:
        mem["pressure_level"] = "critical"
    elif util > 80:
        mem["pressure_level"] = "high"
    elif util > 60:
        mem["pressure_level"] = "elevated"
    else:
        mem["pressure_level"] = "normal"

    return mem


def extract_cycle_stats(warm_cycles: list, cold: dict) -> dict:
    """Compute min/max/avg/stddev and drift for cycle durations."""
    warm_durations = []
    warm_gpu = []
    for c in warm_cycles:
        rt = c.get("runtime_trace", {})
        d = rt.get("stage_duration_ms")
        g = rt.get("gpu_stage_busy_ratio")
        if d is not None:
            warm_durations.append(d)
        if g is not None:
            warm_gpu.append(g)

    cold_duration = None
    if cold and cold.get("runtime_trace"):
        cold_duration = cold["runtime_trace"].get("stage_duration_ms")

    stats = {
        "warm_count": len(warm_durations),
        "warm_min_ms": min(warm_durations) if warm_durations else None,
        "warm_max_ms": max(warm_durations) if warm_durations else None,
        "warm_avg_ms": None,
        "warm_stddev_ms": None,
        "warm_variance_pct": None,
        "cold_duration_ms": cold_duration,
        "warm_cold_delta_pct": None,
        "gpu_avg": None,
        "gpu_min": None,
        "gpu_max": None,
        "baseline_drift_pct": None,
    }
    if warm_durations:
        avg = sum(warm_durations) / len(warm_durations)
        stats["warm_avg_ms"] = avg
        if len(warm_durations) > 1:
            variance = sum((d - avg) ** 2 for d in warm_durations) / (len(warm_durations) - 1)
            stats["warm_stddev_ms"] = math.sqrt(variance)
            stats["warm_variance_pct"] = (stats["warm_stddev_ms"] / avg * 100) if avg > 0 else 0
        if cold_duration and cold_duration > 0:
            stats["warm_cold_delta_pct"] = ((avg - cold_duration) / cold_duration) * 100
        # Drift: compare latest warm to first warm
        if len(warm_durations) >= 2:
            baseline = warm_durations[0]
            latest = warm_durations[-1]
            if baseline > 0:
                stats["baseline_drift_pct"] = ((latest - baseline) / baseline) * 100
    if warm_gpu:
        stats["gpu_avg"] = sum(warm_gpu) / len(warm_gpu)
        stats["gpu_min"] = min(warm_gpu)
        stats["gpu_max"] = max(warm_gpu)
    return stats


def extract_trust_info(warm_cycles: list, prepare: dict) -> dict:
    """Extract trust lane / semantic identity from traces."""
    info = {
        "trust_model": None,
        "wrapper": None,
        "wrapper_strategy": None,
        "source_backend": None,
        "target_backend": None,
        "support_class": None,
        "program_digest": None,
        "trust_stable": True,
        "wrapper_stable": True,
        "backend_stable": True,
        "digest_stable": True,
    }
    # From prepare report
    wp = prepare.get("wrapper_preview", {})
    info["trust_model"] = wp.get("trust_model")
    info["wrapper"] = wp.get("wrapper")
    info["wrapper_strategy"] = wp.get("strategy")
    info["source_backend"] = wp.get("source_backend")
    info["target_backend"] = wp.get("target_backend")
    lr = prepare.get("lowering_report", {})
    info["support_class"] = lr.get("support_class")

    # Check stability across cycles
    seen_trust = set()
    seen_wrapper = set()
    seen_backend = set()
    seen_digest = set()
    for c in warm_cycles:
        rt = c.get("runtime_trace", {})
        t = rt.get("trust_model")
        w = rt.get("wrapper")
        b = rt.get("source_backend")
        d = rt.get("runtime_compiled_program_digest")
        if t: seen_trust.add(t)
        if w: seen_wrapper.add(w)
        if b: seen_backend.add(b)
        if d:
            seen_digest.add(d)
            info["program_digest"] = d

    if len(seen_trust) > 1: info["trust_stable"] = False
    if len(seen_wrapper) > 1: info["wrapper_stable"] = False
    if len(seen_backend) > 1: info["backend_stable"] = False
    if len(seen_digest) > 1: info["digest_stable"] = False
    return info


def extract_memory_trend(doctors: list, warm_cycles: list) -> list:
    """Build memory usage data points across cycles from doctor snapshots."""
    points = []
    for d in doctors:
        rt = d.get("doctor", {}).get("runtime", {})
        points.append({
            "cycle": d["cycle"],
            "working_set_utilization_pct": rt.get("working_set_utilization_pct"),
            "current_allocated_bytes": rt.get("current_allocated_size_bytes"),
            "headroom_bytes": rt.get("working_set_headroom_bytes"),
            "recommended_working_set_bytes": rt.get("recommended_working_set_size_bytes"),
        })
    # Also extract peak memory from warm cycle runtime traces
    for c in warm_cycles:
        rt = c.get("runtime_trace", {})
        mem_budget = rt.get("umpg_memory_budget_bytes")
        mem_est = rt.get("umpg_estimated_memory_bytes")
        existing = next((p for p in points if p["cycle"] == c["cycle"]), None)
        if existing:
            existing["umpg_budget_bytes"] = mem_budget
            existing["umpg_estimated_bytes"] = mem_est
        else:
            points.append({
                "cycle": c["cycle"],
                "umpg_budget_bytes": mem_budget,
                "umpg_estimated_bytes": mem_est,
            })
    points.sort(key=lambda p: p["cycle"])
    return points


def extract_reliability_counters(warm_cycles: list, parallel_cycles: list, progress: dict) -> dict:
    """Count failures, retries, panics — even when all are zero."""
    counters = {
        "proof_failures": 0,
        "verifier_failures": 0,
        "export_failures": 0,
        "retry_count": 0,
        "panic_count": 0,
        "metal_kernel_faults": 0,
        "file_write_failures": 0,
        "queue_stalls": 0,
        "timeout_count": 0,
        "doctor_flips": progress.get("doctor_flips", 0),
        "degraded_runs": progress.get("degraded_runs", 0),
        "dispatch_circuit_trips": 0,
        "fallback_events": 0,
        "total_warm_cycles": len(warm_cycles),
        "total_parallel_cycles": len(parallel_cycles),
    }
    for c in warm_cycles:
        rt = c.get("runtime_trace", {})
        if rt.get("metal_dispatch_circuit_open"):
            counters["dispatch_circuit_trips"] += 1
        if rt.get("status") not in (None, "wrapped-v2", "wrapped-v3"):
            counters["proof_failures"] += 1
        # Check for fallback in stage breakdown
        breakdown = rt.get("stage_breakdown", {})
        for _name, stage in _flatten_stages_py(breakdown):
            if isinstance(stage, dict) and stage.get("no_cpu_fallback") is False and stage.get("accelerator", "").startswith("cpu"):
                counters["fallback_events"] += 1
    return counters


def _flatten_stages_py(breakdown: dict, prefix: str = "") -> list:
    result = []
    if not isinstance(breakdown, dict):
        return result
    for key, val in breakdown.items():
        name = f"{prefix} > {key}" if prefix else key
        if isinstance(val, dict) and "duration_ms" in val:
            result.append((name, val))
        elif isinstance(val, dict):
            result.extend(_flatten_stages_py(val, name))
    return result


def extract_gpu_context(warm_cycles: list) -> dict:
    """Compute detailed GPU utilization context."""
    ctx = {
        "peak_busy": 0.0,
        "avg_busy": 0.0,
        "total_gpu_time_ms": 0.0,
        "total_cpu_time_ms": 0.0,
        "total_stage_time_ms": 0.0,
        "effective_gpu_pct": 0.0,
        "cpu_waiting_on_gpu_ms": 0.0,
    }
    gpu_ratios = []
    for c in warm_cycles:
        rt = c.get("runtime_trace", {})
        ratio = rt.get("gpu_stage_busy_ratio", 0)
        gpu_ratios.append(ratio)
        breakdown = rt.get("stage_breakdown", {})
        for _name, stage in _flatten_stages_py(breakdown):
            dur = stage.get("duration_ms", 0)
            accel = stage.get("accelerator", "")
            ctx["total_stage_time_ms"] += dur
            if "metal" in accel:
                ctx["total_gpu_time_ms"] += dur
            else:
                ctx["total_cpu_time_ms"] += dur

    if gpu_ratios:
        ctx["peak_busy"] = max(gpu_ratios)
        ctx["avg_busy"] = sum(gpu_ratios) / len(gpu_ratios)
    if ctx["total_stage_time_ms"] > 0:
        ctx["effective_gpu_pct"] = ctx["total_gpu_time_ms"] / ctx["total_stage_time_ms"] * 100
    return ctx


def extract_health_summary(
    progress: dict,
    preflight: dict,
    thermal: dict,
    system_memory: dict,
    reliability: dict,
    doctors: list,
    cycle_stats: dict,
    gpu_context: dict,
    latest_artifact: dict | None,
) -> dict:
    """Synthesize a high-level machine/runtime health summary for the dashboard."""
    latest_doc = doctors[-1]["doctor"] if doctors else (preflight or {})
    runtime = (latest_doc or {}).get("runtime", {})

    pressure = system_memory.get("pressure_level") or "normal"
    thermal_pressure = thermal.get("thermal_pressure") or "nominal"
    cpu_speed = thermal.get("cpu_speed_limit", 100)
    power_source = thermal.get("power_source")
    prod_ready = bool((preflight or {}).get("production_ready"))
    cert_present = bool((preflight or {}).get("strict_certification_present"))
    cert_match = bool((preflight or {}).get("strict_certification_match"))
    cert_report = (preflight or {}).get("strict_certification_report")
    strict_ready = bool((preflight or {}).get("strict_bn254_ready"))
    strict_auto = bool((preflight or {}).get("strict_bn254_auto_route"))
    gpu_cov = (preflight or {}).get("strict_gpu_stage_coverage")
    dispatch_open = bool(runtime.get("metal_dispatch_circuit_open"))

    issues: list[str] = []
    positives: list[str] = []

    if prod_ready:
        positives.append("Production gate currently reports ready")
    else:
        issues.append("Production-ready flag is not currently satisfied")

    if cert_present and cert_match:
        positives.append("Strict certification report matches the current runtime")
    elif progress.get("phase") == "running":
        issues.append("Strict soak certification is still in progress")
    else:
        issues.append("Strict certification report is missing or stale")

    if runtime.get("metal_available") and runtime.get("metal_compiled"):
        positives.append("Metal runtime is compiled and available")
    else:
        issues.append("Metal runtime is not fully available")

    if dispatch_open:
        issues.append("Metal dispatch circuit is open")
    else:
        positives.append("Metal dispatch circuit is closed")

    if strict_ready:
        positives.append("Strict BN254 runtime is ready")
    else:
        issues.append("Strict BN254 runtime is not ready")

    if strict_auto:
        positives.append("Strict BN254 auto-route is enabled")
    else:
        issues.append("Strict BN254 auto-route is not enabled")

    if power_source == "AC":
        positives.append("Machine is on AC power for sustained proving")
    elif power_source == "Battery":
        issues.append("Machine is on battery power")

    if cpu_speed < 100:
        issues.append(f"CPU speed limit is reduced to {cpu_speed}%")
    else:
        positives.append("CPU speed limit is at 100%")

    if thermal_pressure not in ("nominal", "low"):
        issues.append(f"Thermal pressure is {thermal_pressure}")
    else:
        positives.append("Thermal pressure is nominal")

    if pressure != "normal":
        issues.append(f"Memory pressure is {pressure}")
    else:
        positives.append("Memory pressure is normal")

    major_failures = (
        reliability.get("proof_failures", 0)
        + reliability.get("verifier_failures", 0)
        + reliability.get("export_failures", 0)
        + reliability.get("timeout_count", 0)
        + reliability.get("panic_count", 0)
        + reliability.get("metal_kernel_faults", 0)
        + reliability.get("dispatch_circuit_trips", 0)
    )
    if major_failures > 0:
        issues.append(f"Observed {major_failures} major reliability fault(s)")
    else:
        positives.append("No major reliability faults observed")

    if progress.get("doctor_flips", 0) == 0 and progress.get("degraded_runs", 0) == 0:
        positives.append("No doctor flips or degraded runs in the active soak")
    else:
        issues.append("Doctor flips or degraded runs were observed in the active soak")

    overall = "healthy"
    if major_failures > 0 or dispatch_open or thermal_pressure in ("high", "critical") or pressure in ("high", "critical"):
        overall = "critical"
    elif issues:
        overall = "watch"

    return {
        "overall_status": overall,
        "production_ready": prod_ready,
        "strict_certification_present": cert_present,
        "strict_certification_match": cert_match,
        "strict_certification_report": cert_report,
        "strict_bn254_ready": strict_ready,
        "strict_bn254_auto_route": strict_auto,
        "strict_gpu_stage_coverage": gpu_cov,
        "thermal_status": thermal_pressure,
        "memory_status": pressure,
        "cpu_speed_limit": cpu_speed,
        "power_source": power_source,
        "dispatch_circuit_open": dispatch_open,
        "metal_available": bool(runtime.get("metal_available")),
        "metal_compiled": bool(runtime.get("metal_compiled")),
        "metal_device": runtime.get("metal_device"),
        "doctor_snapshot_count": len(doctors),
        "doctor_flips": progress.get("doctor_flips", 0),
        "degraded_runs": progress.get("degraded_runs", 0),
        "proof_failures": reliability.get("proof_failures", 0),
        "verifier_failures": reliability.get("verifier_failures", 0),
        "export_failures": reliability.get("export_failures", 0),
        "timeout_count": reliability.get("timeout_count", 0),
        "panic_count": reliability.get("panic_count", 0),
        "metal_kernel_faults": reliability.get("metal_kernel_faults", 0),
        "dispatch_circuit_trips": reliability.get("dispatch_circuit_trips", 0),
        "fallback_events": reliability.get("fallback_events", 0),
        "warm_count": cycle_stats.get("warm_count", 0),
        "warm_variance_pct": cycle_stats.get("warm_variance_pct"),
        "baseline_drift_pct": cycle_stats.get("baseline_drift_pct"),
        "gpu_effective_pct": gpu_context.get("effective_gpu_pct"),
        "gpu_peak_busy": gpu_context.get("peak_busy"),
        "artifact_status": (latest_artifact or {}).get("summary", {}).get("status"),
        "issues": issues,
        "positives": positives,
    }


def extract_cycle_outcomes(warm_cycles: list, soak_dir: Path) -> list:
    """Per-cycle outcome badges with digests."""
    outcomes = []
    for c in warm_cycles:
        rt = c.get("runtime_trace", {})
        status = rt.get("status", "unknown")
        digest = rt.get("runtime_compiled_program_digest", "")[:12]
        proof_path = soak_dir / f"warm-cycle-{c['cycle']}" / f"warm-cycle-{c['cycle']}.wrapped.groth16.json"
        proof_hash = file_sha256(proof_path)
        duration_ms = rt.get("stage_duration_ms")
        gpu_busy = rt.get("gpu_stage_busy_ratio", 0)
        circuit_open = rt.get("metal_dispatch_circuit_open", False)

        if status in ("wrapped-v2", "wrapped-v3") and not circuit_open:
            verdict = "pass"
        elif circuit_open:
            verdict = "degraded"
        elif status == "unknown":
            verdict = "pending"
        else:
            verdict = "fail"

        outcomes.append({
            "cycle": c["cycle"],
            "verdict": verdict,
            "status": status,
            "program_digest": digest,
            "proof_hash": proof_hash,
            "duration_ms": duration_ms,
            "gpu_busy": gpu_busy,
        })
    return outcomes


_policy_cache: dict = {"result": None, "ts": 0}


def collect_ane_policy(soak_dir: Path) -> dict | None:
    """Run `zkf-cli runtime policy` against the latest warm cycle trace with the CoreML model.

    Cached for 30 seconds to avoid hammering the Swift subprocess.
    """
    now = time.time()
    if _policy_cache["result"] is not None and (now - _policy_cache["ts"]) < 30:
        return _policy_cache["result"]

    # Find the latest warm cycle trace
    latest_trace = None
    warm_traces = []
    for cycle, cycle_dir in _numbered_paths(soak_dir, "warm-cycle-", dirs_only=True):
        candidate = cycle_dir / f"warm-cycle-{cycle}.runtime-trace.json"
        if candidate.exists():
            warm_traces.append((cycle, candidate))
    if warm_traces:
        latest_trace = warm_traces[-1][1]
    if not latest_trace:
        return None

    # Find the model
    project_root = Path(__file__).resolve().parent.parent
    model_path = None
    for candidate in [
        project_root / "target" / "coreml" / "zkf-runtime-policy.mlpackage",
        project_root / "tmp_ane_policy.mlpackage",
    ]:
        if candidate.exists():
            model_path = candidate
            break

    # Find the CLI binary
    cli_bin = project_root / "target" / "release" / "zkf-cli"
    if not cli_bin.exists():
        cli_bin = project_root / "target" / "debug" / "zkf-cli"
    if not cli_bin.exists():
        return None

    args = [
        str(cli_bin), "runtime", "policy",
        "--trace", str(latest_trace),
        "--json",
    ]
    if model_path:
        args.extend(["--model", str(model_path), "--compute-units", "cpu-and-neural-engine"])

    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return {"error": out.stderr.strip(), "trace": str(latest_trace)}
        # The CLI may print two JSON objects (model + fallback); take the first
        raw = out.stdout.strip()
        # Find first complete JSON object
        depth = 0
        end = 0
        for i, ch in enumerate(raw):
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        result = json.loads(raw[:end])
        result["_trace_path"] = str(latest_trace)
        result["_model_path"] = str(model_path) if model_path else None
        result["_collected_at"] = now
        _policy_cache["result"] = result
        _policy_cache["ts"] = now
        return result
    except Exception as e:
        return {"error": str(e), "trace": str(latest_trace)}


def extract_umpg(warm_cycles: list) -> dict:
    """Extract full UMPG execution data from the latest and across-cycle trends."""
    latest_et = None
    for c in reversed(warm_cycles):
        et = c.get("execution_trace", {})
        if et.get("runtime_plan"):
            latest_et = et
            break

    umpg: dict = {
        "plan": None,
        "node_traces": [],
        "buffer_lineage": None,
        "runtime_stages": None,
        "engines": {},
        "summary": {},
        "node_trends": {},  # per-op timing across cycles
    }
    if not latest_et:
        return umpg

    umpg["plan"] = latest_et.get("runtime_plan")
    umpg["node_traces"] = latest_et.get("node_traces", [])
    umpg["buffer_lineage"] = latest_et.get("buffer_lineage")
    umpg["runtime_stages"] = latest_et.get("runtime_stage_breakdown")
    umpg["engines"] = {
        "msm_engine": latest_et.get("groth16_msm_engine"),
        "msm_fallback": latest_et.get("groth16_msm_fallback_state"),
        "msm_parallelism": latest_et.get("groth16_msm_parallelism"),
        "msm_reason": latest_et.get("groth16_msm_reason"),
        "qap_engine": latest_et.get("qap_witness_map_engine"),
        "qap_fallback": latest_et.get("qap_witness_map_fallback_state"),
        "qap_parallelism": latest_et.get("qap_witness_map_parallelism"),
        "qap_reason": latest_et.get("qap_witness_map_reason"),
        "proof_engine": latest_et.get("proof_engine"),
        "msm_accelerator": latest_et.get("msm_accelerator"),
        "wrapper_cache_hit": latest_et.get("wrapper_cache_hit"),
        "wrapper_cache_source": latest_et.get("wrapper_cache_source"),
        "wrapper_setup_pk_format": latest_et.get("wrapper_setup_cache_pk_format"),
    }
    umpg["summary"] = {
        "plan_kind": latest_et.get("plan_kind"),
        "plan_digest": latest_et.get("plan_digest"),
        "plan_schema": latest_et.get("runtime_plan_schema"),
        "plan_sha256": latest_et.get("runtime_plan_sha256"),
        "node_count": latest_et.get("node_count"),
        "cpu_nodes": latest_et.get("cpu_nodes"),
        "gpu_nodes": latest_et.get("gpu_nodes"),
        "delegated_nodes": latest_et.get("delegated_nodes"),
        "peak_memory_bytes": latest_et.get("peak_memory_bytes"),
        "umpg_estimated_constraints": latest_et.get("umpg_estimated_constraints"),
        "umpg_estimated_memory_bytes": latest_et.get("umpg_estimated_memory_bytes"),
        "umpg_memory_budget_bytes": latest_et.get("umpg_memory_budget_bytes"),
        "umpg_low_memory_mode": latest_et.get("umpg_low_memory_mode"),
        "umpg_plan_reason": latest_et.get("umpg_plan_reason"),
        "runtime_execution_ms": latest_et.get("runtime_execution_duration_ms"),
        "runtime_cpu_wall_ms": latest_et.get("runtime_cpu_wall_time_ms"),
        "runtime_gpu_wall_ms": latest_et.get("runtime_gpu_wall_time_ms"),
        "total_wall_time_ms": latest_et.get("total_wall_time_ms"),
        "hardware_profile": latest_et.get("runtime_hardware_profile"),
        "counter_source": latest_et.get("runtime_metal_counter_source"),
    }

    # Per-op timing trends across cycles
    op_times: dict = {}
    for c in warm_cycles:
        et = c.get("execution_trace", {})
        for nt in et.get("node_traces", []):
            op = nt.get("op", "?")
            if op not in op_times:
                op_times[op] = []
            op_times[op].append(nt.get("wall_time_ms", 0))
    umpg["node_trends"] = op_times

    return umpg


def extract_soak_integrity(warm_cycles: list, doctors: list, prepare: dict) -> dict:
    """Check if everything is stable across the entire soak."""
    integrity = {
        "result_digest_stable": True,
        "doctor_snapshot_stable": True,
        "artifact_schema_stable": True,
        "backend_config_stable": True,
        "trust_lane_stable": True,
        "checks": [],
    }
    # Result digest
    digests = set()
    for c in warm_cycles:
        d = c.get("runtime_trace", {}).get("runtime_compiled_program_digest")
        if d: digests.add(d)
    if len(digests) > 1:
        integrity["result_digest_stable"] = False
        integrity["checks"].append(f"Program digest changed: {len(digests)} unique values")
    elif len(digests) == 1:
        integrity["checks"].append(f"Program digest stable: {list(digests)[0][:16]}")

    # Doctor snapshot
    circuit_states = set()
    for d in doctors:
        rt = d.get("doctor", {}).get("runtime", {})
        circuit_states.add(rt.get("metal_dispatch_circuit_open"))
    if len(circuit_states) > 1:
        integrity["doctor_snapshot_stable"] = False
        integrity["checks"].append("Doctor: dispatch circuit state changed mid-soak")
    elif doctors:
        integrity["checks"].append("Doctor: all snapshots consistent")

    # Schema
    schemas = set()
    for c in warm_cycles:
        s = c.get("runtime_trace", {}).get("trace_schema")
        if s: schemas.add(s)
    if len(schemas) > 1:
        integrity["artifact_schema_stable"] = False
        integrity["checks"].append(f"Trace schema changed: {schemas}")
    elif schemas:
        integrity["checks"].append(f"Trace schema stable: {list(schemas)[0]}")

    # Backend
    backends = set()
    for c in warm_cycles:
        b = c.get("runtime_trace", {}).get("source_backend")
        if b: backends.add(b)
    if len(backends) > 1:
        integrity["backend_config_stable"] = False
        integrity["checks"].append(f"Backend changed: {backends}")
    elif backends:
        integrity["checks"].append(f"Backend stable: {list(backends)[0]}")

    # Trust
    trusts = set()
    for c in warm_cycles:
        t = c.get("runtime_trace", {}).get("trust_model")
        if t: trusts.add(t)
    if len(trusts) > 1:
        integrity["trust_lane_stable"] = False
        integrity["checks"].append(f"Trust model changed: {trusts}")
    elif trusts:
        integrity["checks"].append(f"Trust lane stable: {list(trusts)[0]}")

    all_stable = all([
        integrity["result_digest_stable"],
        integrity["doctor_snapshot_stable"],
        integrity["artifact_schema_stable"],
        integrity["backend_config_stable"],
        integrity["trust_lane_stable"],
    ])
    integrity["all_stable"] = all_stable
    return integrity


_doctor_cache: dict = {"result": None, "ts": 0}
_strict_doctor_cache: dict = {"result": None, "ts": 0}
_caps_cache: dict = {"result": None, "ts": 0}
_metrics_cache: dict = {"result": None, "ts": 0, "soak_dir": None}
_support_matrix_cache: dict = {"result": None, "ts": 0}
_workspace_assets_cache: dict = {"result": None, "ts": 0}


def _find_cli_bin() -> Path | None:
    project_root = Path(__file__).resolve().parent.parent
    for candidate in [
        project_root / "target" / "release" / "zkf-cli",
        project_root / "target" / "debug" / "zkf-cli",
    ]:
        if candidate.exists():
            return candidate
    return None


def _numbered_paths(base: Path, prefix: str, *, suffix: str = "", dirs_only: bool = False) -> list[tuple[int, Path]]:
    if not base.is_dir():
        return []
    pattern = re.compile(rf"^{re.escape(prefix)}(\d+){re.escape(suffix)}$")
    items: list[tuple[int, Path]] = []
    for entry in base.iterdir():
        if dirs_only and not entry.is_dir():
            continue
        if not dirs_only and not entry.exists():
            continue
        match = pattern.match(entry.name)
        if not match:
            continue
        items.append((int(match.group(1)), entry))
    items.sort(key=lambda item: item[0])
    return items


def collect_support_matrix() -> dict | None:
    now = time.time()
    if _support_matrix_cache["result"] is not None and (now - _support_matrix_cache["ts"]) < 300:
        return _support_matrix_cache["result"]
    path = Path(__file__).resolve().parent.parent / "support-matrix.json"
    if not path.exists():
        return None
    try:
        result = json.loads(path.read_text())
        _support_matrix_cache["result"] = result
        _support_matrix_cache["ts"] = now
        return result
    except Exception:
        return None


def collect_workspace_assets() -> dict:
    now = time.time()
    if _workspace_assets_cache["result"] is not None and (now - _workspace_assets_cache["ts"]) < 300:
        return _workspace_assets_cache["result"]

    root = Path(__file__).resolve().parent.parent
    patterns = {
        "audit_reports": "**/*.audit.json",
        "ceremony_ptau": "**/*.ptau",
        "verifier_exports": "**/*.sol",
    }
    result: dict = {}
    for key, pattern in patterns.items():
        count = 0
        samples = []
        try:
            for match in root.glob(pattern):
                count += 1
                if len(samples) < 8:
                    samples.append(str(match.relative_to(root)))
        except Exception:
            pass
        result[key] = {"count": count, "samples": samples}

    _workspace_assets_cache["result"] = result
    _workspace_assets_cache["ts"] = now
    return result


def collect_system_doctor() -> dict | None:
    """Run `zkf-cli doctor --json`.  Cached 60s."""
    now = time.time()
    if _doctor_cache["result"] is not None and (now - _doctor_cache["ts"]) < 60:
        return _doctor_cache["result"]
    cli = _find_cli_bin()
    if not cli:
        return None
    try:
        out = subprocess.run(
            [str(cli), "doctor", "--json"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            return None
        result = json.loads(out.stdout)
        _doctor_cache["result"] = result
        _doctor_cache["ts"] = now
        return result
    except Exception:
        return None


def collect_strict_metal_doctor() -> dict | None:
    """Run `zkf-cli metal-doctor --strict --json`. Cached 60s."""
    now = time.time()
    if _strict_doctor_cache["result"] is not None and (now - _strict_doctor_cache["ts"]) < 60:
        return _strict_doctor_cache["result"]
    cli = _find_cli_bin()
    if not cli:
        return None
    try:
        out = subprocess.run(
            [str(cli), "metal-doctor", "--strict", "--json"],
            capture_output=True, text=True, timeout=20,
        )
        if out.returncode != 0:
            return None
        result = json.loads(out.stdout)
        _strict_doctor_cache["result"] = result
        _strict_doctor_cache["ts"] = now
        return result
    except Exception:
        return None


def collect_system_capabilities() -> dict | None:
    """Run `zkf-cli capabilities --json`.  Cached 120s."""
    now = time.time()
    if _caps_cache["result"] is not None and (now - _caps_cache["ts"]) < 120:
        return _caps_cache["result"]
    cli = _find_cli_bin()
    if not cli:
        return None
    try:
        out = subprocess.run(
            [str(cli), "capabilities", "--json"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode != 0:
            return None
        result = json.loads(out.stdout)
        _caps_cache["result"] = result
        _caps_cache["ts"] = now
        return result
    except Exception:
        return None


def collect_active_processes() -> list:
    """Find all running zkf-cli / zkf-api processes."""
    procs = []
    try:
        out = subprocess.run(
            ["ps", "aux"], capture_output=True, text=True, timeout=3
        ).stdout
        for line in out.splitlines():
            if "zkf-cli" not in line and "zkf-api" not in line:
                continue
            if "grep" in line:
                continue
            cols = line.split(None, 10)
            if len(cols) < 11:
                continue
            cmd_full = cols[10]
            if (
                "zkf-cli doctor --json" in cmd_full
                or "zkf-cli capabilities --json" in cmd_full
                or "zkf-cli runtime policy " in cmd_full
            ):
                continue
            # Extract the subcommand
            parts = cmd_full.split()
            subcmd = ""
            for p in parts:
                if "zkf-cli" in p or "zkf-api" in p:
                    continue
                if p.startswith("-") or p.startswith("/"):
                    continue
                subcmd = p
                break
            procs.append({
                "pid": int(cols[1]),
                "cpu_pct": float(cols[2]),
                "mem_pct": float(cols[3]),
                "rss_kb": int(cols[5]),
                "started": cols[8],
                "command": cmd_full[:200],
                "subcmd": subcmd,
            })
    except Exception:
        pass
    return procs


def collect_system_metrics(soak_dir: Path | None = None) -> dict:
    """System-wide metrics: load, uptime, disk."""
    now = time.time()
    soak_dir_key = str(soak_dir.resolve()) if soak_dir and soak_dir.exists() else None
    if (
        _metrics_cache["result"] is not None
        and _metrics_cache["soak_dir"] == soak_dir_key
        and (now - _metrics_cache["ts"]) < 60
    ):
        return _metrics_cache["result"]

    metrics: dict = {
        "load_1m": None, "load_5m": None, "load_15m": None,
        "uptime_seconds": None,
        "target_dir_size": None,
        "build_cache_targets": [],
        "wrapper_cache_size": None,
        "wrapper_cache_path": None,
        "soak_dir_size": None,
    }
    try:
        out = subprocess.run(
            ["sysctl", "-n", "vm.loadavg"], capture_output=True, text=True, timeout=2
        ).stdout.strip()
        # Format: "{ 1.86 2.63 2.66 }"
        nums = [float(x) for x in out.strip("{ }").split()]
        if len(nums) >= 3:
            metrics["load_1m"], metrics["load_5m"], metrics["load_15m"] = nums[0], nums[1], nums[2]
    except Exception:
        pass

    try:
        out = subprocess.run(
            ["sysctl", "-n", "kern.boottime"], capture_output=True, text=True, timeout=2
        ).stdout
        m = re.search(r"sec\s*=\s*(\d+)", out)
        if m:
            boot = int(m.group(1))
            metrics["uptime_seconds"] = int(time.time()) - boot
    except Exception:
        pass

    project_root = Path(__file__).resolve().parent.parent

    # Target dir size (use du -sk for speed)
    target = project_root / "target"
    if target.is_dir():
        try:
            out = subprocess.run(
                ["du", "-sk", str(target)], capture_output=True, text=True, timeout=5
            ).stdout
            metrics["target_dir_size"] = int(out.split()[0]) * 1024
        except Exception:
            pass
        try:
            cache_targets = []
            for child in sorted(target.iterdir(), key=lambda p: p.name):
                if not child.exists():
                    continue
                size_bytes = None
                scan_status = "ok"
                try:
                    out = subprocess.run(
                        ["du", "-sk", str(child)], capture_output=True, text=True, timeout=5
                    ).stdout.strip()
                    if out:
                        try:
                            size_bytes = int(out.split()[0]) * 1024
                        except Exception:
                            size_bytes = None
                except subprocess.TimeoutExpired:
                    scan_status = "timeout"
                except Exception:
                    scan_status = "error"
                cache_targets.append({
                    "name": child.name,
                    "path": str(child),
                    "is_dir": child.is_dir(),
                    "size_bytes": size_bytes,
                    "scan_status": scan_status,
                })
            cache_targets.sort(key=lambda item: item["size_bytes"] or 0, reverse=True)
            metrics["build_cache_targets"] = cache_targets[:12]
        except Exception:
            pass

    # Wrapper cache
    for base in [Path("/private/var/folders"), Path("/private/tmp")]:
        try:
            found = list(base.glob("**/zkf-stark-to-groth16"))
            if found:
                cache_path = found[0]
                metrics["wrapper_cache_path"] = str(cache_path)
                out = subprocess.run(
                    ["du", "-sk", str(cache_path)], capture_output=True, text=True, timeout=5
                ).stdout
                metrics["wrapper_cache_size"] = int(out.split()[0]) * 1024
                break
        except Exception:
            pass

    if soak_dir and soak_dir.is_dir():
        try:
            out = subprocess.run(
                ["du", "-sk", str(soak_dir)], capture_output=True, text=True, timeout=5
            ).stdout
            metrics["soak_dir_size"] = int(out.split()[0]) * 1024
        except Exception:
            pass

    _metrics_cache["result"] = metrics
    _metrics_cache["ts"] = now
    _metrics_cache["soak_dir"] = soak_dir_key
    return metrics


def _collect_active_logs(soak_dir: Path, progress: dict) -> dict:
    """Read tail of stdout/stderr logs for the currently active wrap step."""
    result: dict = {"stdout_tail": None, "stderr_tail": None, "log_files": []}
    active = progress.get("active_label", "")
    subphase = progress.get("subphase", "")
    if not active:
        return result

    # Discover log files under the active cycle directory
    # Pattern: parallel-cycle-N/job-J/*.wrap.stdout.log / *.wrap.stderr.log
    # Or:      warm-cycle-N/*.wrap.stdout.log / *.wrap.stderr.log
    candidates = []
    for pattern in [
        f"{active}/**/*.wrap.stdout.log",
        f"{active}/**/*.wrap.stderr.log",
        f"{active}/**/*.stdout.log",
        f"{active}/**/*.stderr.log",
        f"{active}/*.wrap.stdout.log",
        f"{active}/*.wrap.stderr.log",
    ]:
        candidates.extend(soak_dir.glob(pattern))

    # Also check for warm-cycle logs
    if subphase in ("warm-wrap", "warm"):
        for pattern in [
            f"warm-cycle-*/*.wrap.stdout.log",
            f"warm-cycle-*/*.wrap.stderr.log",
        ]:
            candidates.extend(soak_dir.glob(pattern))

    # Deduplicate and sort by mtime (most recent first)
    seen = set()
    unique = []
    for p in candidates:
        if p not in seen:
            seen.add(p)
            unique.append(p)
    unique.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)

    for log_path in unique[:6]:
        stat = log_path.stat()
        result["log_files"].append({
            "path": str(log_path.relative_to(soak_dir)),
            "size": stat.st_size,
            "mtime": stat.st_mtime,
        })

    # Read tail of the most recent stdout and stderr
    for log_path in unique:
        name = log_path.name
        try:
            content = log_path.read_text(errors="replace")
            # Take last 3000 chars
            tail = content[-3000:] if len(content) > 3000 else content
            if "stdout" in name and result["stdout_tail"] is None:
                result["stdout_tail"] = tail
                result["stdout_path"] = str(log_path.relative_to(soak_dir))
                result["stdout_size"] = log_path.stat().st_size
            elif "stderr" in name and result["stderr_tail"] is None:
                result["stderr_tail"] = tail
                result["stderr_path"] = str(log_path.relative_to(soak_dir))
                result["stderr_size"] = log_path.stat().st_size
        except Exception:
            pass

    return result


def collect_latest_artifact_context(soak_dir: Path) -> dict | None:
    if not soak_dir.is_dir():
        return None

    latest_cycle = None
    latest_dir = None
    for cycle, cycle_dir in reversed(_numbered_paths(soak_dir, "warm-cycle-", dirs_only=True)):
        artifact_path = cycle_dir / f"warm-cycle-{cycle}.wrapped.groth16.json"
        if artifact_path.exists():
            latest_cycle = cycle
            latest_dir = cycle_dir
            break
    if latest_cycle is None or latest_dir is None:
        return None

    artifact_path = latest_dir / f"warm-cycle-{latest_cycle}.wrapped.groth16.json"
    runtime_trace_path = latest_dir / f"warm-cycle-{latest_cycle}.runtime-trace.json"
    execution_trace_path = latest_dir / f"warm-cycle-{latest_cycle}.execution-trace.json"

    artifact = read_json(artifact_path) or {}
    runtime_trace = read_json(runtime_trace_path) or {}
    execution_trace = read_json(execution_trace_path) or {}
    metadata = artifact.get("metadata") or {}

    lowering_report = None
    lowering_report_raw = metadata.get("runtime_lowering_report_json")
    if isinstance(lowering_report_raw, str):
        try:
            lowering_report = json.loads(lowering_report_raw)
        except Exception:
            lowering_report = {"raw": lowering_report_raw}

    summary = {
        "cycle": latest_cycle,
        "artifact_path": str(artifact_path),
        "runtime_trace_path": str(runtime_trace_path),
        "execution_trace_path": str(execution_trace_path),
        "backend": artifact.get("backend"),
        "program_digest": artifact.get("program_digest"),
        "public_inputs_count": len(artifact.get("public_inputs") or []),
        "status": metadata.get("status"),
        "trust_model": metadata.get("trust_model") or execution_trace.get("trust_model"),
        "wrapper_strategy": metadata.get("wrapper_strategy"),
        "curve": metadata.get("curve"),
        "export_scheme": metadata.get("export_scheme"),
        "proof_engine": metadata.get("proof_engine") or execution_trace.get("proof_engine"),
        "source_backend": metadata.get("runtime_compiled_backend") or execution_trace.get("source_backend"),
        "hardware_profile": metadata.get("runtime_hardware_profile") or execution_trace.get("runtime_hardware_profile"),
        "plan_digest": execution_trace.get("plan_digest") or metadata.get("plan_digest"),
        "plan_sha256": execution_trace.get("runtime_plan_sha256"),
        "program_trace_digest": execution_trace.get("runtime_compiled_program_digest") or metadata.get("runtime_compiled_program_digest"),
        "source_proof_sha256": execution_trace.get("runtime_source_proof_sha256"),
        "source_compiled_sha256": execution_trace.get("runtime_source_compiled_sha256"),
        "outer_input_sha256": metadata.get("runtime_outer_input_sha256"),
        "gpu_stage_busy_ratio": metadata.get("gpu_stage_busy_ratio"),
        "qap_engine": metadata.get("qap_witness_map_engine"),
        "qap_reason": metadata.get("qap_witness_map_reason"),
        "qap_parallelism": metadata.get("qap_witness_map_parallelism"),
        "msm_engine": metadata.get("groth16_msm_engine"),
        "msm_reason": metadata.get("groth16_msm_reason"),
        "msm_parallelism": metadata.get("groth16_msm_parallelism"),
        "wrapper_cache_hit": execution_trace.get("wrapper_cache_hit") or metadata.get("wrapper_cache_hit"),
        "wrapper_cache_source": execution_trace.get("wrapper_cache_source") or metadata.get("wrapper_cache_source"),
        "counter_source": execution_trace.get("runtime_metal_counter_source") or metadata.get("metal_counter_source"),
        "log_degree": metadata.get("log_degree"),
        "num_fri_rounds": metadata.get("num_fri_rounds"),
        "merkle_tree_height": metadata.get("merkle_tree_height"),
        "num_queries": metadata.get("num_queries"),
        "poseidon2_seed": metadata.get("poseidon2_seed"),
        "target_dispatch_circuit_open": metadata.get("target_groth16_metal_dispatch_circuit_open"),
        "target_dispatch_last_failure": metadata.get("target_groth16_metal_dispatch_last_failure"),
    }

    return {
        "summary": summary,
        "metadata": metadata,
        "trust_summary": execution_trace.get("trust_summary") or {},
        "lowering_report": lowering_report,
        "runtime_trace": runtime_trace,
        "execution_trace": execution_trace,
    }


def collect_soak_data(soak_dir: Path) -> dict:
    progress = read_json(soak_dir / "soak-progress.json") if soak_dir.is_dir() else {}
    progress = progress or {}
    prepare = read_json(soak_dir / "prepare-report.json") or read_json(soak_dir / "prepare.json") or {}
    preflight_file = read_json(soak_dir / "doctor-preflight.json") or {}
    live_strict_doctor = collect_strict_metal_doctor() or {}
    preflight = live_strict_doctor or preflight_file

    warm_cycles = []
    for i, cycle_dir in _numbered_paths(soak_dir, "warm-cycle-", dirs_only=True):
        rt = read_json(cycle_dir / f"warm-cycle-{i}.runtime-trace.json") or {}
        et = read_json(cycle_dir / f"warm-cycle-{i}.execution-trace.json") or {}
        warm_cycles.append({
            "cycle": i,
            "runtime_trace": rt,
            "execution_trace": et,
            "mtime": cycle_dir.stat().st_mtime if cycle_dir.exists() else 0,
        })

    cold_dir = soak_dir / "cold"
    cold = {}
    if cold_dir.is_dir():
        cold_rt = read_json(cold_dir / "cold.runtime-trace.json") or {}
        cold_et = read_json(cold_dir / "cold.execution-trace.json") or {}
        cold = {"runtime_trace": cold_rt, "execution_trace": cold_et}

    parallel_cycles = []
    for i, cycle_dir in _numbered_paths(soak_dir, "parallel-cycle-", dirs_only=True):
        jobs = []
        for j, job_dir in _numbered_paths(cycle_dir, "job-", dirs_only=True):
            rt = read_json(job_dir / f"parallel-cycle-{i}-job-{j}.runtime-trace.json") or {}
            jobs.append({"job": j, "runtime_trace": rt})
        parallel_cycles.append({"cycle": i, "jobs": jobs})

    doctors = []
    for i, doc_path in _numbered_paths(soak_dir, "doctor-cycle-", suffix=".json"):
        doc = read_json(doc_path)
        if doc is None:
            continue
        doctors.append({"cycle": i, "doctor": doc})

    files = []
    if soak_dir.is_dir():
        for entry in sorted(soak_dir.iterdir()):
            stat = entry.stat()
            files.append({
                "name": entry.name,
                "is_dir": entry.is_dir(),
                "size": stat.st_size,
                "mtime": stat.st_mtime,
            })

    # Collect live wrap logs for the active step
    active_logs = _collect_active_logs(soak_dir, progress) if soak_dir.is_dir() else {}

    thermal = collect_thermal()
    system_memory = collect_process_memory()
    cycle_stats = extract_cycle_stats(warm_cycles, cold)
    reliability = extract_reliability_counters(warm_cycles, parallel_cycles, progress)
    gpu_context = extract_gpu_context(warm_cycles)
    latest_artifact = collect_latest_artifact_context(soak_dir)
    health = extract_health_summary(
        progress,
        preflight,
        thermal,
        system_memory,
        reliability,
        doctors,
        cycle_stats,
        gpu_context,
        latest_artifact,
    )

    return {
        "collected_at": time.time(),
        "soak_dir": str(soak_dir),
        "progress": progress,
        "active_logs": active_logs,
        "prepare": prepare,
        "preflight": preflight,
        "cold": cold,
        "warm_cycles": warm_cycles,
        "parallel_cycles": parallel_cycles,
        "doctors": doctors,
        "files": files,
        "thermal": thermal,
        "system_memory": system_memory,
        "cycle_stats": cycle_stats,
        "trust_info": extract_trust_info(warm_cycles, prepare),
        "memory_trend": extract_memory_trend(doctors, warm_cycles),
        "reliability": reliability,
        "gpu_context": gpu_context,
        "cycle_outcomes": extract_cycle_outcomes(warm_cycles, soak_dir),
        "soak_integrity": extract_soak_integrity(warm_cycles, doctors, prepare),
        "umpg": extract_umpg(warm_cycles),
        "ane_policy": collect_ane_policy(soak_dir) if soak_dir.is_dir() else None,
        "system_doctor": collect_system_doctor(),
        "strict_doctor": live_strict_doctor,
        "system_capabilities": collect_system_capabilities(),
        "active_processes": collect_active_processes(),
        "system_metrics": collect_system_metrics(soak_dir),
        "support_matrix": collect_support_matrix(),
        "workspace_assets": collect_workspace_assets(),
        "latest_artifact": latest_artifact,
        "health": health,
    }


DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZirOS System Dashboard</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
  --border: #30363d; --text: #e6edf3; --dim: #8b949e;
  --accent: #58a6ff; --green: #3fb950; --yellow: #d29922;
  --red: #f85149; --purple: #bc8cff; --orange: #f0883e;
  --cyan: #39d2c0;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
  background: var(--bg); color: var(--text); padding: 16px; line-height: 1.5;
}
h1 { font-size: 18px; color: var(--accent); margin-bottom: 4px; }
h2 { font-size: 13px; color: var(--purple); margin: 14px 0 6px; text-transform: uppercase; letter-spacing: 1px; }
h3 { font-size: 12px; color: var(--dim); margin: 6px 0 4px; }
.grid { display: grid; gap: 10px; }
.g2 { grid-template-columns: 1fr 1fr; }
.g3 { grid-template-columns: 1fr 1fr 1fr; }
.g4 { grid-template-columns: 1fr 1fr 1fr 1fr; }
.g5 { grid-template-columns: 1fr 1fr 1fr 1fr 1fr; }
.g6 { grid-template-columns: repeat(6, 1fr); }
.g7 { grid-template-columns: repeat(7, 1fr); }
@media (max-width: 1100px) { .g2,.g3,.g4,.g5,.g6,.g7 { grid-template-columns: 1fr 1fr; } }
@media (max-width: 700px) { .g2,.g3,.g4,.g5,.g6,.g7 { grid-template-columns: 1fr; } }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 10px; overflow: hidden; }
.stat { text-align: center; padding: 6px; }
.sv { font-size: 24px; font-weight: 700; }
.sl { font-size: 10px; color: var(--dim); text-transform: uppercase; letter-spacing: 0.5px; }
.ss { font-size: 10px; color: var(--dim); margin-top: 1px; }
.green { color: var(--green); } .yellow { color: var(--yellow); }
.red { color: var(--red); } .accent { color: var(--accent); }
.purple { color: var(--purple); } .orange { color: var(--orange); }
.cyan { color: var(--cyan); }

.badge {
  display: inline-block; padding: 1px 6px; border-radius: 3px;
  font-size: 10px; font-weight: 600; text-transform: uppercase;
}
.badge-pass { background: #1a3a2a; color: var(--green); border: 1px solid #2a5a3a; }
.badge-warn { background: #3a2a1a; color: var(--yellow); border: 1px solid #5a4a2a; }
.badge-fail { background: #3a1a1a; color: var(--red); border: 1px solid #5a2a2a; }
.badge-degraded { background: #3a2a1a; color: var(--orange); border: 1px solid #5a3a2a; }
.badge-pending { background: var(--surface2); color: var(--dim); border: 1px solid var(--border); }
.badge-stable { background: #1a3a2a; color: var(--green); border: 1px solid #2a5a3a; }
.badge-drift { background: #3a1a1a; color: var(--red); border: 1px solid #5a2a2a; }

.pbar-outer { width: 100%; height: 20px; background: var(--surface2); border-radius: 10px; overflow: hidden; position: relative; border: 1px solid var(--border); }
.pbar-inner { height: 100%; border-radius: 10px; transition: width 1s ease; background: linear-gradient(90deg, var(--accent), var(--purple)); position: relative; }
.pbar-inner.time { background: linear-gradient(90deg, var(--green), var(--accent)); }
.pbar-label { position: absolute; right: 6px; top: 50%; transform: translateY(-50%); font-size: 10px; font-weight: 600; }

.bar-chart { display: flex; align-items: flex-end; gap: 2px; height: 100px; padding: 2px 0; }
.bar-col { display: flex; flex-direction: column; align-items: center; flex: 1; height: 100%; justify-content: flex-end; }
.bar { width: 100%; min-width: 8px; border-radius: 2px 2px 0 0; transition: height 0.5s ease; }
.bar-label { font-size: 8px; color: var(--dim); margin-top: 2px; white-space: nowrap; }
.bar-value { font-size: 8px; color: var(--text); margin-bottom: 1px; text-align: center; }

.mini-chart { display: flex; align-items: flex-end; gap: 1px; height: 40px; }
.mini-bar { flex: 1; min-width: 4px; border-radius: 1px 1px 0 0; transition: height 0.3s; }

.stage-row { display: flex; align-items: center; gap: 6px; padding: 2px 0; font-size: 11px; }
.stage-name { flex: 0 0 180px; color: var(--dim); text-overflow: ellipsis; overflow: hidden; white-space: nowrap; }
.stage-bar-outer { flex: 1; height: 12px; background: var(--surface2); border-radius: 2px; overflow: hidden; }
.stage-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s; }
.stage-time { flex: 0 0 70px; text-align: right; font-size: 10px; }
.stage-accel { flex: 0 0 50px; text-align: right; font-size: 9px; }

.tl { position: relative; padding-left: 18px; border-left: 2px solid var(--border); margin-left: 6px; }
.tl-ev { position: relative; padding: 4px 0 4px 14px; font-size: 11px; }
.tl-ev::before { content:''; position: absolute; left: -23px; top: 8px; width: 8px; height: 8px; border-radius: 50%; background: var(--accent); border: 2px solid var(--bg); }
.tl-ev.ok::before { background: var(--green); }
.tl-ev.warn::before { background: var(--yellow); }
.tl-ev.error::before { background: var(--red); }
.tl-ev.degraded::before { background: var(--orange); }
.tl-time { color: var(--dim); font-size: 9px; }

.hg { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 4px; }
.hi { display: flex; align-items: center; gap: 5px; padding: 3px 6px; background: var(--surface2); border-radius: 3px; font-size: 10px; }
.hd { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.hd.ok { background: var(--green); } .hd.warn { background: var(--yellow); } .hd.bad { background: var(--red); }

.counter-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 4px; }
.counter-item { background: var(--surface2); border-radius: 4px; padding: 6px 8px; text-align: center; }
.counter-val { font-size: 18px; font-weight: 700; }
.counter-label { font-size: 9px; color: var(--dim); text-transform: uppercase; }

.integrity-row { display: flex; align-items: center; gap: 8px; padding: 3px 0; font-size: 11px; }
.integrity-icon { font-size: 14px; }

.cycle-row { display: flex; align-items: center; gap: 8px; padding: 4px 6px; background: var(--surface2); border-radius: 4px; margin-bottom: 3px; font-size: 11px; }
.cycle-num { flex: 0 0 28px; font-weight: 700; color: var(--accent); }
.cycle-badge { flex: 0 0 70px; }
.cycle-dur { flex: 0 0 60px; text-align: right; }
.cycle-gpu { flex: 0 0 55px; text-align: right; }
.cycle-digest { flex: 1; color: var(--dim); font-size: 9px; text-align: right; }

.ftable { width: 100%; border-collapse: collapse; font-size: 10px; }
.ftable td, .ftable th { padding: 2px 6px; text-align: left; border-bottom: 1px solid var(--border); }
.ftable th { color: var(--dim); font-weight: 500; }

.pulse { animation: pulse 2s ease-in-out infinite; }
@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.5} }
.topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
.topbar-r { display: flex; align-items: center; gap: 10px; font-size: 10px; color: var(--dim); }
.live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--green); display: inline-block; }

.tabs { display: flex; gap: 1px; margin-bottom: 6px; flex-wrap: wrap; }
.tab { padding: 3px 10px; font-size: 10px; cursor: pointer; border-radius: 3px 3px 0 0; background: var(--surface2); color: var(--dim); border: 1px solid transparent; border-bottom: none; font-family: inherit; }
.tab.active { background: var(--surface); color: var(--text); border-color: var(--border); }
.tc { display: none; }
.tc.active { display: block; }

canvas.sparkline { width: 100%; height: 60px; }
</style>
</head>
<body>

<div class="topbar">
  <div>
    <h1>ZirOS System Dashboard</h1>
    <span style="font-size:10px;color:var(--dim)" id="soak-dir"></span>
  </div>
  <div class="topbar-r">
    <span id="last-update"></span>
    <span class="live-dot pulse" id="live-dot"></span>
    <span>LIVE</span>
  </div>
</div>

<!-- TOP STATS -->
<div class="grid g7" id="top-stats"></div>

<!-- PROGRESS BARS -->
<div class="grid g2" style="margin-top:8px">
  <div class="card"><h3>Cycles</h3><div class="pbar-outer" style="margin-top:4px"><div class="pbar-inner" id="cy-bar"><span class="pbar-label" id="cy-lbl"></span></div></div></div>
  <div class="card"><h3>Time Elapsed</h3><div class="pbar-outer" style="margin-top:4px"><div class="pbar-inner time" id="tm-bar"><span class="pbar-label" id="tm-lbl"></span></div></div></div>
</div>

<!-- SOAK INTEGRITY STRIP -->
<div class="card" style="margin-top:8px" id="integrity-strip"></div>

<!-- TABS -->
<div style="margin-top:10px">
<div class="tabs" id="tab-btns">
  <button class="tab active" data-t="system">System</button>
  <button class="tab" data-t="activity">Activity</button>
  <button class="tab" data-t="perf">Performance</button>
  <button class="tab" data-t="mem">Memory</button>
  <button class="tab" data-t="gpu">GPU Detail</button>
  <button class="tab" data-t="ane">Neural Engine</button>
  <button class="tab" data-t="umpg">UMPG</button>
  <button class="tab" data-t="crypto">Crypto / Math</button>
  <button class="tab" data-t="matrix">Backends / Gadgets</button>
  <button class="tab" data-t="stages">Stages</button>
  <button class="tab" data-t="trust">Trust / Semantics</button>
  <button class="tab" data-t="reliability">Reliability</button>
  <button class="tab" data-t="thermal">Thermal</button>
  <button class="tab" data-t="health">Health</button>
  <button class="tab" data-t="cycles">Cycle Outcomes</button>
  <button class="tab" data-t="timeline">Timeline</button>
  <button class="tab" data-t="files">Files</button>
</div>

<div class="tc active" id="tab-system"></div>
<div class="tc" id="tab-activity"></div>
<div class="tc" id="tab-perf"></div>
<div class="tc" id="tab-mem"></div>
<div class="tc" id="tab-gpu"></div>
<div class="tc" id="tab-ane"></div>
<div class="tc" id="tab-umpg"></div>
<div class="tc" id="tab-crypto"></div>
<div class="tc" id="tab-matrix"></div>
<div class="tc" id="tab-stages"></div>
<div class="tc" id="tab-trust"></div>
<div class="tc" id="tab-reliability"></div>
<div class="tc" id="tab-thermal"></div>
<div class="tc" id="tab-health"></div>
<div class="tc" id="tab-cycles"></div>
<div class="tc" id="tab-timeline"></div>
<div class="tc" id="tab-files"></div>
</div>

<script>
let D = null;
document.getElementById('tab-btns').addEventListener('click', e => {
  if (!e.target.dataset.t) return;
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tc').forEach(t=>t.classList.remove('active'));
  e.target.classList.add('active');
  document.getElementById('tab-'+e.target.dataset.t).classList.add('active');
});

const F = {
  ms(ms) { if(ms<1000) return ms.toFixed(0)+'ms'; let s=ms/1000; if(s<60) return s.toFixed(1)+'s'; let m=s/60; if(m<60) return m.toFixed(1)+'m'; return (m/60).toFixed(1)+'h'; },
  dur(ms) { let t=Math.floor(ms/1000),h=Math.floor(t/3600),m=Math.floor((t%3600)/60),s=t%60; return `${h}h ${String(m).padStart(2,'0')}m ${String(s).padStart(2,'0')}s`; },
  bytes(b) { if(b<1024) return b+' B'; if(b<1048576) return (b/1024).toFixed(1)+' KB'; if(b<1073741824) return (b/1048576).toFixed(1)+' MB'; return (b/1073741824).toFixed(2)+' GB'; },
  dt(ms) { return new Date(ms).toLocaleString(); },
  tm(ms) { return new Date(ms).toLocaleTimeString(); },
  pct(v,mx) { return mx>0?Math.min(100,(v/mx)*100):0; },
  sc(v,g,b) { return v>=g?'green':v>=b?'yellow':'red'; },
  badge(v) { return `<span class="badge badge-${v}">${v}</span>`; },
};

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function sparkline(vals, color, height=40) {
  if (!vals.length) return '<span style="color:var(--dim);font-size:10px">no data</span>';
  const mx = Math.max(...vals, 0.001);
  let h = '';
  for (const v of vals) {
    const pH = Math.max(2, (v/mx)*height);
    h += `<div class="mini-bar" style="height:${pH}px;background:${color}"></div>`;
  }
  return `<div class="mini-chart" style="height:${height}px">${h}</div>`;
}

function barChart(items, height=100) {
  const mx = Math.max(...items.map(r=>r.v), 0.001);
  let h = '';
  for (const r of items) {
    const pH = Math.max(3, (r.v/mx)*100);
    h += `<div class="bar-col"><div class="bar-value">${r.top||''}</div><div class="bar" style="height:${pH}%;background:${r.c}"></div><div class="bar-label">${r.l}</div></div>`;
  }
  return `<div class="bar-chart" style="height:${height}px">${h}</div>`;
}

function fmtUptime(sec) {
  if (!sec) return '?';
  const d = Math.floor(sec/86400), h = Math.floor((sec%86400)/3600), m = Math.floor((sec%3600)/60);
  return d > 0 ? `${d}d ${h}h ${m}m` : `${h}h ${m}m`;
}

function renderSystem(d) {
  const doc = d.system_doctor||{};
  const caps = d.system_capabilities||{};
  const sm = d.system_metrics||{};
  const mem = d.system_memory||{};
  const therm = d.thermal||{};
  const procs = d.active_processes||[];

  let h = '';

  // Top metrics row
  h += '<div class="grid g6">';
  const load1 = sm.load_1m;
  const loadC = load1===null?'dim':load1<4?'green':load1<8?'yellow':'red';
  h += `<div class="card stat"><div class="sv ${loadC}">${load1!==null?load1.toFixed(2):'?'}</div><div class="sl">Load (1m)</div><div class="ss">${sm.load_5m?.toFixed(2)||'?'} / ${sm.load_15m?.toFixed(2)||'?'}</div></div>`;
  const ramPct = mem.utilization_pct;
  const ramC = ramPct===null||ramPct===undefined?'dim':ramPct<60?'green':ramPct<80?'yellow':'red';
  h += `<div class="card stat"><div class="sv ${ramC}">${ramPct!==null&&ramPct!==undefined?ramPct.toFixed(0)+'%':'?'}</div><div class="sl">RAM Used</div><div class="ss">${mem.ram_total_bytes?F.bytes(mem.ram_total_bytes):''}</div></div>`;
  h += `<div class="card stat"><div class="sv">${fmtUptime(sm.uptime_seconds)}</div><div class="sl">Uptime</div></div>`;
  h += `<div class="card stat"><div class="sv accent">${procs.length}</div><div class="sl">ZirOS Processes</div></div>`;
  const speed = therm.cpu_speed_limit??100;
  const speedC = speed>=95?'green':speed>=80?'yellow':'red';
  h += `<div class="card stat"><div class="sv ${speedC}">${speed}%</div><div class="sl">CPU Speed</div><div class="ss">${therm.thermal_pressure||'?'}</div></div>`;
  h += `<div class="card stat"><div class="sv">${therm.power_source||'?'}</div><div class="sl">Power</div><div class="ss">${therm.battery_state!==null&&therm.battery_state!==undefined?therm.battery_state+'%':''}</div></div>`;
  h += '</div>';

  // Backends & Frontends
  const backends = doc.backends||[];
  const frontends = doc.frontends||[];
  h += '<div class="grid g2" style="margin-top:8px">';

  h += '<div class="card"><h3>Backends (' + backends.length + ')</h3><div style="margin-top:4px">';
  for (const b of backends) {
    const mode = b.mode||'?';
    const mC = mode==='native'?'green':mode==='compat'?'yellow':'accent';
    h += `<div style="font-size:11px;padding:2px 0"><strong>${b.backend}</strong> <span class="${mC}">${mode}</span>`;
    if (b.trusted_setup) h += ' <span class="badge badge-warn" style="font-size:8px">trusted setup</span>';
    if (b.recursion_ready) h += ' <span class="badge badge-stable" style="font-size:8px">recursion</span>';
    if (b.transparent_setup) h += ' <span class="badge badge-stable" style="font-size:8px">transparent</span>';
    h += '</div>';
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Frontends (' + frontends.length + ')</h3><div style="margin-top:4px">';
  for (const f of frontends) {
    const compile = f.can_compile_to_ir;
    const exec = f.can_execute;
    h += `<div style="font-size:11px;padding:2px 0"><strong>${f.frontend}</strong>`;
    h += compile ? ' <span class="green">compile</span>' : ' <span class="red">no-compile</span>';
    h += exec ? ' <span class="green">execute</span>' : ' <span class="dim">no-exec</span>';
    h += '</div>';
  }
  h += '</div></div>';
  h += '</div>';

  // Metal & Accelerators (from doctor)
  const metal = doc.metal||d.preflight?.runtime||{};
  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Metal GPU</h3><div class="hg" style="margin-top:4px">';
  const mChecks = [
    ['Available', metal.metal_available, true],
    ['Compiled', metal.metal_compiled, true],
    ['Circuit Closed', !metal.metal_dispatch_circuit_open, true],
    ['Not Disabled', !metal.metal_disabled_by_env, true],
  ];
  for (const [l,v,e] of mChecks) {
    const ok = v===e;
    h += `<div class="hi"><span class="hd ${ok?'ok':'bad'}"></span>${l}</div>`;
  }
  const mInfo = [
    ['Device', metal.metal_device],
    ['Mode', metal.metallib_mode],
    ['Thresholds', metal.threshold_profile],
    ['Pipelines', metal.prewarmed_pipelines],
  ];
  for (const [l,v] of mInfo) h += `<div class="hi"><span class="hd ok"></span>${l}: <strong>${v??'?'}</strong></div>`;
  h += '</div></div>';

  h += '<div class="card"><h3>Accelerators</h3><div class="hg" style="margin-top:4px">';
  const accels = metal.active_accelerators||{};
  for (const [slot, name] of Object.entries(accels)) {
    h += `<div class="hi"><span class="hd ok"></span><strong>${slot}</strong>: ${name}</div>`;
  }
  if (!Object.keys(accels).length) h += '<div style="color:var(--dim);font-size:10px">No accelerators detected</div>';
  h += '</div></div>';
  h += '</div>';

  // Disk & Cache
  h += '<div class="grid g2" style="margin-top:8px">';
  h += `<div class="card stat"><div class="sv">${sm.wrapper_cache_size?F.bytes(sm.wrapper_cache_size):'-'}</div><div class="sl">Wrapper Cache</div><div class="ss">pk + vk + shape</div></div>`;
  h += `<div class="card stat"><div class="sv">${sm.soak_dir_size?F.bytes(sm.soak_dir_size):'-'}</div><div class="sl">Soak Artifacts</div></div>`;
  h += '</div>';

  const buildTargets = sm.build_cache_targets||[];
  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Build Cache Targets</h3>';
  if (buildTargets.length) {
    h += '<table class="ftable" style="margin-top:6px"><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Path</th></tr></thead><tbody>';
    for (const t of buildTargets) {
      const shortPath = t.path && t.path.length > 58 ? '...' + t.path.slice(-53) : (t.path || '-');
      const sizeLabel = t.size_bytes ? F.bytes(t.size_bytes) : (t.scan_status === 'timeout' ? 'scan timeout' : '-');
      h += '<tr>';
      h += `<td><strong>${escHtml(t.name||'-')}</strong></td>`;
      h += `<td>${t.is_dir ? 'dir' : 'file'}</td>`;
      h += `<td>${sizeLabel}</td>`;
      h += `<td style="font-size:9px;color:var(--dim)" title="${escHtml(t.path||'')}">${escHtml(shortPath)}</td>`;
      h += '</tr>';
    }
    h += '</tbody></table>';
  } else {
    h += '<div style="margin-top:6px;color:var(--dim);font-size:10px">No target/ cache entries discovered yet</div>';
  }
  h += '</div>';

  h += '<div class="card"><h3>Cache Paths</h3><div style="margin-top:6px">';
  const cacheRows = [
    ['target/', sm.target_dir_size ? F.bytes(sm.target_dir_size) : '-', '/Users/sicarii/Projects/ZK DEV/target'],
    ['Wrapper Cache', sm.wrapper_cache_size ? F.bytes(sm.wrapper_cache_size) : '-', sm.wrapper_cache_path || '-'],
    ['Soak Dir', sm.soak_dir_size ? F.bytes(sm.soak_dir_size) : '-', d.soak_dir || '-'],
  ];
  for (const [label, size, path] of cacheRows) {
    const short = typeof path === 'string' && path.length > 70 ? '...' + path.slice(-65) : path;
    h += `<div style="font-size:11px;padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${size}</strong> <span style="font-size:9px;color:var(--dim)" title="${escHtml(path)}">${escHtml(short)}</span></div>`;
  }
  h += '</div></div>';
  h += '</div>';

  document.getElementById('tab-system').innerHTML = h;
}

function renderActivity(d) {
  const procs = d.active_processes||[];
  let h = '';

  if (procs.length === 0) {
    h += '<div class="card"><span style="color:var(--dim)">No active ZirOS processes</span></div>';
  } else {
    h += '<div class="card"><h3>Active ZirOS Processes (' + procs.length + ')</h3>';
    h += '<table class="ftable" style="margin-top:6px"><thead><tr><th>PID</th><th>Command</th><th>CPU%</th><th>MEM%</th><th>RSS</th><th>Started</th></tr></thead><tbody>';
    for (const p of procs) {
      const cpuC = p.cpu_pct>50?'red':p.cpu_pct>10?'yellow':'green';
      const cmd = p.command.length>100 ? '...'+p.command.slice(-95) : p.command;
      h += `<tr><td>${p.pid}</td><td style="font-size:9px;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escHtml(p.command)}">${escHtml(cmd)}</td><td class="${cpuC}">${p.cpu_pct.toFixed(1)}%</td><td>${p.mem_pct.toFixed(1)}%</td><td>${F.bytes(p.rss_kb*1024)}</td><td>${p.started}</td></tr>`;
    }
    h += '</tbody></table></div>';

    // Aggregate stats
    const totalCpu = procs.reduce((a,p)=>a+p.cpu_pct, 0);
    const totalRss = procs.reduce((a,p)=>a+p.rss_kb, 0);
    const subcmds = {};
    for (const p of procs) { subcmds[p.subcmd||'other'] = (subcmds[p.subcmd||'other']||0)+1; }

    h += '<div class="grid g4" style="margin-top:8px">';
    h += `<div class="card stat"><div class="sv accent">${procs.length}</div><div class="sl">Total Processes</div></div>`;
    h += `<div class="card stat"><div class="sv">${totalCpu.toFixed(1)}%</div><div class="sl">Combined CPU</div></div>`;
    h += `<div class="card stat"><div class="sv">${F.bytes(totalRss*1024)}</div><div class="sl">Combined RSS</div></div>`;
    h += `<div class="card stat"><div class="sv">${Object.entries(subcmds).map(([k,v])=>k+':'+v).join(', ')||'-'}</div><div class="sl">By Command</div></div>`;
    h += '</div>';
  }

  // Soak status summary (if running)
  const p = d.progress||{};
  if (p.phase) {
    h += '<div class="card" style="margin-top:8px"><h3>Soak Test</h3><div style="margin-top:4px;font-size:11px">';
    const rows = [
      ['Phase', p.phase + (p.subphase ? ' / '+p.subphase : '')],
      ['Active', p.active_label||'idle'],
      ['Cycle', `${p.current_cycle||0} / ${p.required_cycles||20}`],
      ['Resumed From', p.resumed_from_cycle],
      ['Doctor Flips', p.doctor_flips],
      ['Degraded Runs', p.degraded_runs],
    ];
    for (const [l,v] of rows) {
      if (v===undefined||v===null) continue;
      h += `<div style="padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${v}</strong></div>`;
    }
    h += '</div></div>';
  }

  document.getElementById('tab-activity').innerHTML = h;
}

function renderTop(d) {
  const p=d.progress, now=Date.now(), started=p.soak_started_at_unix_ms||now;
  const elapsed=now-started, remaining=Math.max(0,(p.min_duration_ms||0)-elapsed);
  const cy=p.current_cycle||0, cyR=p.required_cycles||20, phase=p.phase||'unknown';
  const phC = phase==='running'?'green':phase==='done'?'accent':'yellow';
  const eta = new Date(started+(p.min_duration_ms||0));
  const integ = d.soak_integrity||{};
  const integC = integ.all_stable ? 'green' : 'red';
  const integL = integ.all_stable ? 'STABLE' : 'DRIFT';
  const therm = d.thermal||{};
  const thermC = therm.thermal_pressure==='nominal'||therm.thermal_pressure==='low'?'green':therm.thermal_pressure==='elevated'?'yellow':'red';

  const subphase = p.subphase || '';
  const activeLabel = p.active_label || '';
  const resumed = p.resumed_from_cycle;

  let h = '';
  // Phase card now shows subphase
  const phaseSub = subphase ? subphase : (phase==='running'?'':'');
  h += `<div class="card stat"><div class="sv ${phC}">${phase.toUpperCase()}</div><div class="sl">Phase</div>${phaseSub?`<div class="ss">${phaseSub}</div>`:''}</div>`;
  // Active label card (what's running right now)
  const activeSub = resumed ? `resumed from #${resumed}` : '';
  h += `<div class="card stat"><div class="sv" style="font-size:${activeLabel.length>16?'14':'18'}px">${activeLabel||'idle'}</div><div class="sl">Active Step</div>${activeSub?`<div class="ss">${activeSub}</div>`:''}</div>`;
  h += `<div class="card stat"><div class="sv accent">${cy}<span style="font-size:12px;color:var(--dim)">/${cyR}</span></div><div class="sl">Cycles</div></div>`;
  h += `<div class="card stat"><div class="sv">${F.dur(elapsed)}</div><div class="sl">Elapsed</div><div class="ss">${F.dur(remaining)} left</div></div>`;
  h += `<div class="card stat"><div class="sv accent">${eta.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</div><div class="sl">ETA</div><div class="ss">${eta.toLocaleDateString()}</div></div>`;
  h += `<div class="card stat"><div class="sv ${integC}">${integL}</div><div class="sl">Integrity</div></div>`;
  const cpuSpeed = therm.cpu_speed_limit ?? 100;
  h += `<div class="card stat"><div class="sv ${thermC}">${cpuSpeed}%</div><div class="sl">CPU Speed</div><div class="ss">${therm.thermal_pressure}</div></div>`;
  document.getElementById('top-stats').innerHTML = h;
  document.getElementById('soak-dir').textContent = d.soak_dir;

  const cyPct = F.pct(cy, cyR);
  document.getElementById('cy-bar').style.width = cyPct+'%';
  document.getElementById('cy-lbl').textContent = `${cy}/${cyR}`;
  const tmPct = F.pct(elapsed, p.min_duration_ms||1);
  document.getElementById('tm-bar').style.width = Math.min(100,tmPct)+'%';
  document.getElementById('tm-lbl').textContent = Math.min(100,tmPct).toFixed(1)+'%';
}

function renderIntegrityStrip(d) {
  const ig = d.soak_integrity || {};
  const items = [
    ['Result Digest', ig.result_digest_stable],
    ['Doctor Snapshots', ig.doctor_snapshot_stable],
    ['Artifact Schema', ig.artifact_schema_stable],
    ['Backend Config', ig.backend_config_stable],
    ['Trust Lane', ig.trust_lane_stable],
  ];
  let h = '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><h3 style="margin:0">Soak Integrity:</h3>';
  for (const [label, ok] of items) {
    const b = ok !== false ? 'stable' : 'drift';
    h += `<span class="badge badge-${b}">${label}</span>`;
  }
  const checks = ig.checks || [];
  if (checks.length) {
    h += '<span style="color:var(--dim);font-size:10px;margin-left:8px">' + checks.join(' | ') + '</span>';
  }
  h += '</div>';
  document.getElementById('integrity-strip').innerHTML = h;
}

function renderPerf(d) {
  const cs = d.cycle_stats||{}, warm = d.warm_cycles||[], cold = d.cold||{};
  // Duration chart
  let runs = [];
  if (cold.runtime_trace?.stage_duration_ms)
    runs.push({l:'Cold',v:cold.runtime_trace.stage_duration_ms/1000,c:'var(--orange)',top:(cold.runtime_trace.stage_duration_ms/1000).toFixed(1)+'s'});
  for (const c of warm) {
    const dur = c.runtime_trace?.stage_duration_ms;
    if (dur) runs.push({l:`W${c.cycle}`,v:dur/1000,c:'var(--accent)',top:(dur/1000).toFixed(1)+'s'});
  }
  // GPU chart
  let gpuRuns = [];
  if (cold.runtime_trace) gpuRuns.push({l:'Cold',v:(cold.runtime_trace.gpu_stage_busy_ratio||0)*100,c:'var(--orange)',top:((cold.runtime_trace.gpu_stage_busy_ratio||0)*100).toFixed(0)+'%'});
  for (const c of warm) {
    const r = c.runtime_trace?.gpu_stage_busy_ratio||0;
    gpuRuns.push({l:`W${c.cycle}`,v:r*100,c:'var(--green)',top:(r*100).toFixed(0)+'%'});
  }

  let h = '<div class="grid g2">';
  h += `<div class="card"><h3>Cycle Duration</h3>${barChart(runs)}</div>`;
  h += `<div class="card"><h3>GPU Busy Ratio</h3>${barChart(gpuRuns)}</div>`;
  h += '</div>';

  // Variance stats
  h += '<div class="grid g5" style="margin-top:8px">';
  const avg = cs.warm_avg_ms; const sd = cs.warm_stddev_ms;
  h += `<div class="card stat"><div class="sv">${avg?F.ms(avg):'-'}</div><div class="sl">Avg Duration</div></div>`;
  h += `<div class="card stat"><div class="sv">${cs.warm_min_ms?F.ms(cs.warm_min_ms):'-'} / ${cs.warm_max_ms?F.ms(cs.warm_max_ms):'-'}</div><div class="sl">Min / Max</div></div>`;
  const varPct = cs.warm_variance_pct; const varC = varPct===null?'dim':varPct<2?'green':varPct<5?'yellow':'red';
  h += `<div class="card stat"><div class="sv ${varC}">${varPct!==null?varPct.toFixed(2)+'%':'-'}</div><div class="sl">Std Dev %</div></div>`;
  const drift = cs.baseline_drift_pct; const driftC = drift===null?'dim':Math.abs(drift)<3?'green':Math.abs(drift)<8?'yellow':'red';
  h += `<div class="card stat"><div class="sv ${driftC}">${drift!==null?(drift>=0?'+':'')+drift.toFixed(2)+'%':'-'}</div><div class="sl">Baseline Drift</div></div>`;
  const wcd = cs.warm_cold_delta_pct; const wcdC = wcd===null?'dim':wcd<0?'green':wcd<5?'yellow':'red';
  h += `<div class="card stat"><div class="sv ${wcdC}">${wcd!==null?(wcd>=0?'+':'')+wcd.toFixed(1)+'%':'-'}</div><div class="sl">Warm vs Cold</div></div>`;
  h += '</div>';

  // Existing counters
  const p = d.progress;
  h += '<div class="grid g4" style="margin-top:8px">';
  h += `<div class="card stat"><div class="sv ${F.sc(p.strict_gpu_busy_ratio_peak||0,0.2,0.1)}">${((p.strict_gpu_busy_ratio_peak||0)*100).toFixed(0)}%</div><div class="sl">GPU Busy Peak</div></div>`;
  h += `<div class="card stat"><div class="sv ${p.doctor_flips===0?'green':'red'}">${p.doctor_flips||0}</div><div class="sl">Doctor Flips</div></div>`;
  h += `<div class="card stat"><div class="sv ${p.degraded_runs===0?'green':'yellow'}">${p.degraded_runs||0}</div><div class="sl">Degraded Runs</div></div>`;
  const rel = d.reliability||{};
  h += `<div class="card stat"><div class="sv ${rel.proof_failures===0?'green':'red'}">${rel.proof_failures}</div><div class="sl">Proof Failures</div></div>`;
  h += '</div>';

  document.getElementById('tab-perf').innerHTML = h;
}

function renderMem(d) {
  const mt = d.memory_trend||[], sm = d.system_memory||{}, cs = d.cycle_stats||{};

  // Working set utilization sparkline
  const wsVals = mt.map(p=>p.working_set_utilization_pct||0);
  const allocVals = mt.map(p=>(p.current_allocated_bytes||0)/1048576);
  const headVals = mt.map(p=>(p.headroom_bytes||0)/1073741824);

  let h = '<div class="grid g3">';
  h += `<div class="card"><h3>GPU Working Set Utilization (%)</h3>${sparkline(wsVals,'var(--accent)')}<div style="font-size:10px;color:var(--dim);margin-top:4px">`;
  if (wsVals.length>=2) {
    const delta = wsVals[wsVals.length-1]-wsVals[0];
    const deltaC = Math.abs(delta)<0.01?'green':Math.abs(delta)<0.1?'yellow':'red';
    h += `Delta: <span class="${deltaC}">${delta>=0?'+':''}${delta.toFixed(4)}%</span> over ${wsVals.length} cycles`;
  }
  h += '</div></div>';

  h += `<div class="card"><h3>GPU Allocated (MB)</h3>${sparkline(allocVals,'var(--purple)')}<div style="font-size:10px;color:var(--dim);margin-top:4px">`;
  if (allocVals.length>=2) {
    const delta = allocVals[allocVals.length-1]-allocVals[0];
    const deltaC = Math.abs(delta)<1?'green':Math.abs(delta)<10?'yellow':'red';
    h += `Delta: <span class="${deltaC}">${delta>=0?'+':''}${delta.toFixed(2)} MB</span>`;
  }
  h += '</div></div>';

  h += `<div class="card"><h3>GPU Headroom (GB)</h3>${sparkline(headVals,'var(--green)')}<div style="font-size:10px;color:var(--dim);margin-top:4px">`;
  if (headVals.length) h += `Latest: ${headVals[headVals.length-1].toFixed(2)} GB`;
  h += '</div></div>';
  h += '</div>';

  // System memory
  h += '<div class="grid g4" style="margin-top:8px">';
  h += `<div class="card stat"><div class="sv">${sm.ram_total_bytes?F.bytes(sm.ram_total_bytes):'-'}</div><div class="sl">Total RAM</div></div>`;
  h += `<div class="card stat"><div class="sv">${sm.ram_used_bytes?F.bytes(sm.ram_used_bytes):'-'}</div><div class="sl">RAM Used</div></div>`;
  h += `<div class="card stat"><div class="sv">${sm.ram_free_bytes?F.bytes(sm.ram_free_bytes):'-'}</div><div class="sl">RAM Free</div></div>`;
  const ramPct = sm.utilization_pct ?? (sm.ram_total_bytes&&sm.ram_used_bytes?((sm.ram_used_bytes/sm.ram_total_bytes)*100):null);
  const ramC = ramPct===null?'dim':ramPct<60?'green':ramPct<80?'yellow':'red';
  const pSrc = sm.pressure_source||'?';
  h += `<div class="card stat"><div class="sv ${ramC}">${ramPct!==null?ramPct.toFixed(1)+'%':'-'}</div><div class="sl">Utilization</div><div class="ss">via ${pSrc}</div></div>`;
  h += '</div>';

  // Per-cycle peak memory from UMPG
  const budgetVals = mt.filter(p=>p.umpg_estimated_bytes).map(p=>p.umpg_estimated_bytes/1073741824);
  if (budgetVals.length) {
    h += '<div class="card" style="margin-top:8px"><h3>UMPG Estimated Memory per Cycle (GB)</h3>';
    h += sparkline(budgetVals, 'var(--cyan)');
    h += '</div>';
  }

  document.getElementById('tab-mem').innerHTML = h;
}

function renderGpu(d) {
  const gc = d.gpu_context||{}, cs = d.cycle_stats||{};
  let h = '<div class="grid g3">';
  h += `<div class="card stat"><div class="sv ${F.sc(gc.peak_busy,0.2,0.1)}">${(gc.peak_busy*100).toFixed(1)}%</div><div class="sl">Peak GPU Busy</div></div>`;
  h += `<div class="card stat"><div class="sv">${(gc.avg_busy*100).toFixed(1)}%</div><div class="sl">Avg GPU Busy</div></div>`;
  h += `<div class="card stat"><div class="sv cyan">${gc.effective_gpu_pct.toFixed(1)}%</div><div class="sl">Effective GPU Time</div></div>`;
  h += '</div>';

  h += '<div class="grid g3" style="margin-top:8px">';
  h += `<div class="card stat"><div class="sv">${F.ms(gc.total_gpu_time_ms)}</div><div class="sl">Total GPU Time</div></div>`;
  h += `<div class="card stat"><div class="sv">${F.ms(gc.total_cpu_time_ms)}</div><div class="sl">Total CPU Time</div></div>`;
  h += `<div class="card stat"><div class="sv">${F.ms(gc.total_stage_time_ms)}</div><div class="sl">Total Stage Time</div></div>`;
  h += '</div>';

  // GPU/CPU time ratio visual
  const gpuPct = gc.total_stage_time_ms>0?(gc.total_gpu_time_ms/gc.total_stage_time_ms*100):0;
  const cpuPct = 100-gpuPct;
  h += '<div class="card" style="margin-top:8px"><h3>GPU vs CPU Time Share</h3>';
  h += `<div style="display:flex;height:24px;border-radius:4px;overflow:hidden;margin-top:4px">`;
  h += `<div style="width:${gpuPct}%;background:var(--green);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:600">${gpuPct.toFixed(0)}% GPU</div>`;
  h += `<div style="width:${cpuPct}%;background:var(--yellow);display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:600;color:var(--bg)">${cpuPct.toFixed(0)}% CPU</div>`;
  h += '</div></div>';

  // Per-cycle GPU chart
  const warm = d.warm_cycles||[];
  const gpuVals = warm.map(c=>(c.runtime_trace?.gpu_stage_busy_ratio||0)*100);
  h += '<div class="card" style="margin-top:8px"><h3>GPU Busy Trend Across Cycles</h3>';
  h += sparkline(gpuVals, 'var(--green)', 50);
  if (cs.gpu_min!==null && cs.gpu_max!==null) {
    h += `<div style="font-size:10px;color:var(--dim);margin-top:4px">Min: ${((cs.gpu_min||0)*100).toFixed(1)}% | Max: ${((cs.gpu_max||0)*100).toFixed(1)}% | Avg: ${((cs.gpu_avg||0)*100).toFixed(1)}%</div>`;
  }
  h += '</div>';

  document.getElementById('tab-gpu').innerHTML = h;
}

function renderAne(d) {
  const p = d.ane_policy;
  if (!p || p.error) {
    const err = p ? p.error : 'No policy data available';
    document.getElementById('tab-ane').innerHTML = `<div class="card"><span style="color:var(--dim)">${err}</span></div>`;
    return;
  }

  let h = '';

  // ─── SCORE GAUGES ───
  const hScore = p.heuristic_gpu_lane_score || 0;
  const mScore = p.model_gpu_lane_score;
  const fScore = p.final_gpu_lane_score || 0;
  const metalFirst = p.recommend_metal_first;
  const jobs = p.recommended_parallel_jobs;
  const model = p.model;
  const sched = p.scheduler;
  const cert = p.certification || {};
  const mr = p.metal_runtime || {};
  const resources = p.resources || {};
  const resPressure = resources.pressure || {};
  const backendCandidates = Array.isArray(p.backends) ? p.backends : [];
  const modelOutputs = (model && model.outputs && typeof model.outputs === 'object') ? model.outputs : {};
  const activeAccels = Object.entries(mr.active_accelerators || {});
  const registeredAccels = Object.entries(mr.registered_accelerators || {});

  h += '<div class="grid g5">';
  h += `<div class="card stat"><div class="sv ${fScore>=0.45?'green':fScore>=0.3?'yellow':'red'}">${(fScore*100).toFixed(1)}%</div><div class="sl">Final Score</div><div class="ss">${metalFirst?'Metal-First':'CPU-Preferred'}</div></div>`;
  h += `<div class="card stat"><div class="sv accent">${(hScore*100).toFixed(1)}%</div><div class="sl">Heuristic</div><div class="ss">70% weight</div></div>`;
  h += `<div class="card stat"><div class="sv purple">${mScore!==null&&mScore!==undefined?(mScore*100).toFixed(1)+'%':'N/A'}</div><div class="sl">ANE Model</div><div class="ss">30% weight</div></div>`;
  h += `<div class="card stat"><div class="sv">${jobs}</div><div class="sl">Parallel Jobs</div></div>`;
  h += `<div class="card stat"><div class="sv ${metalFirst?'green':'yellow'}">${metalFirst?'YES':'NO'}</div><div class="sl">Metal-First</div></div>`;
  h += '</div>';

  // ─── SCORE COMPOSITION BAR ───
  h += '<div class="card" style="margin-top:8px"><h3>Score Composition</h3>';
  h += '<div style="display:flex;height:32px;border-radius:4px;overflow:hidden;margin-top:6px">';
  const hW = 70;
  const mW = mScore !== null && mScore !== undefined ? 30 : 0;
  const hContrib = hScore * 0.70;
  const mContrib = mScore !== null && mScore !== undefined ? mScore * 0.30 : 0;
  h += `<div style="width:${hW}%;background:linear-gradient(90deg,var(--surface2),var(--accent));display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:600;border-right:1px solid var(--bg)">Heuristic: ${(hContrib*100).toFixed(1)}%</div>`;
  if (mW > 0) {
    h += `<div style="width:${mW}%;background:linear-gradient(90deg,var(--surface2),var(--purple));display:flex;align-items:center;justify-content:center;font-size:10px;font-weight:600">ANE: ${(mContrib*100).toFixed(1)}%</div>`;
  }
  h += '</div>';
  h += `<div style="margin-top:4px;font-size:10px;color:var(--dim)">Final = (heuristic * 0.70) + (model * 0.30) = ${(hContrib*100).toFixed(1)} + ${(mContrib*100).toFixed(1)} = ${(fScore*100).toFixed(1)}%</div>`;
  h += '</div>';

  // ─── FEATURE VECTOR ───
  const feats = p.features || {};
  const labels = p.feature_labels || [];
  const vector = p.feature_vector || [];
  h += '<div class="grid g2" style="margin-top:8px">';

  h += '<div class="card"><h3>Feature Vector (10 inputs to ANE model)</h3>';
  h += '<div style="margin-top:6px">';
  const featColors = ['var(--accent)','var(--accent)','var(--green)','var(--green)','var(--purple)','var(--orange)','var(--yellow)','var(--yellow)','var(--cyan)','var(--cyan)'];
  for (let i = 0; i < labels.length; i++) {
    const val = vector[i] || 0;
    const pW = Math.max(2, val * 100);
    h += `<div style="display:flex;align-items:center;gap:6px;padding:2px 0;font-size:10px">`;
    h += `<div style="flex:0 0 150px;color:var(--dim);text-align:right">${labels[i]}</div>`;
    h += `<div style="flex:1;height:10px;background:var(--surface2);border-radius:2px;overflow:hidden"><div style="height:100%;width:${pW}%;background:${featColors[i]||'var(--accent)'};border-radius:2px"></div></div>`;
    h += `<div style="flex:0 0 45px;text-align:right">${val.toFixed(3)}</div>`;
    h += '</div>';
  }
  h += '</div></div>';

  // ─── POLICY SIGNAL DOMAINS ───
  h += '<div class="card"><h3>Policy Signal Domains</h3><div style="margin-top:6px">';
  const signalGroups = [
    ['Workload', [
      ['Constraints', feats.constraints?.toLocaleString()],
      ['Signals', feats.signals?.toLocaleString()],
      ['Requested Jobs', feats.requested_jobs],
      ['Total Jobs', feats.total_jobs],
    ]],
    ['Runtime Feedback', [
      ['GPU Stage Busy', ((feats.runtime_gpu_stage_busy_ratio||0)*100).toFixed(1)+'%'],
      ['Fallback Ratio', ((feats.runtime_fallback_ratio||0)*100).toFixed(1)+'%'],
      ['GPU Nodes', feats.runtime_gpu_nodes],
      ['CPU Nodes', feats.runtime_cpu_nodes],
    ]],
    ['Memory / Pressure', [
      ['Peak Memory', feats.peak_memory_bytes ? F.bytes(feats.peak_memory_bytes) : '0'],
      ['RAM Utilization', ((feats.ram_utilization||0)*100).toFixed(1)+'%'],
      ['Available RAM', resources.available_ram_bytes ? F.bytes(resources.available_ram_bytes) : '-'],
      ['Swap Used', resPressure.swap_used_bytes ? F.bytes(resPressure.swap_used_bytes) : '0 B'],
    ]],
    ['Readiness Gates', [
      ['Metal Available', feats.metal_available ? 'YES' : 'NO'],
      ['Strict Ready', feats.strict_runtime_ready ? 'YES' : 'NO'],
      ['Cert Match', cert.matches_current ? 'YES' : 'NO'],
      ['Dispatch Closed', mr.metal_dispatch_circuit_open ? 'NO' : 'YES'],
    ]],
  ];
  for (const [group, rows] of signalGroups) {
    h += `<div style="margin-top:6px"><div style="font-size:10px;color:var(--dim);text-transform:uppercase">${group}</div>`;
    for (const [l, v] of rows) {
      h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${v}</strong></div>`;
    }
    h += '</div>';
  }
  h += '</div></div>';
  h += '</div>';

  // ─── HEURISTIC BREAKDOWN ───
  h += '<div class="card" style="margin-top:8px"><h3>Heuristic Score Breakdown</h3>';
  h += '<div style="margin-top:6px;font-size:11px">';
  const hParts = [
    ['Base', 0.10, null],
    ['Metal Available', feats.metal_available ? 0.20 : 0, '+0.20'],
    ['Dispatch Circuit Closed', !p.metal_runtime?.metal_dispatch_circuit_open ? 0.10 : 0, '+0.10'],
    ['GPU Busy Ratio', 0.20 * (feats.runtime_gpu_stage_busy_ratio||0), `+0.20 * ${((feats.runtime_gpu_stage_busy_ratio||0)*100).toFixed(0)}%`],
    ['Low Fallback', 0.10 * (1.0 - (feats.runtime_fallback_ratio||0)), '+0.10 * (1-fallback)'],
    ['Accelerator Strength', 0.10 * Math.min(Object.keys(p.metal_runtime?.active_accelerators||{}).length, 6)/6, '+0.10 * accel'],
    ['Job Scale', 0.10 * ((p.scheduler?.recommended_jobs||0)/(p.scheduler?.total_jobs||1)), '+0.10 * jobs'],
    ['Low RAM Usage', 0.10 * (1.0 - (feats.ram_utilization||0)), '+0.10 * (1-ram)'],
    ['Strict Ready', feats.strict_runtime_ready ? 0.05 : 0, '+0.05'],
    ['Certification', p.certification?.matches_current ? 0.05 : 0, '+0.05'],
  ];
  let running = 0;
  for (const [label, val, formula] of hParts) {
    running += val;
    const vC = val > 0 ? 'green' : val < 0 ? 'red' : 'dim';
    h += `<div style="display:flex;gap:8px;padding:1px 0">`;
    h += `<div style="flex:0 0 200px;color:var(--dim)">${label}</div>`;
    h += `<div style="flex:0 0 60px;text-align:right" class="${vC}">${val>=0?'+':''}${(val*100).toFixed(1)}%</div>`;
    h += `<div style="flex:0 0 60px;text-align:right;color:var(--dim)">${(running*100).toFixed(1)}%</div>`;
    if (formula) h += `<div style="flex:1;font-size:9px;color:var(--dim)">${formula}</div>`;
    h += '</div>';
  }
  h += `<div style="margin-top:4px;font-weight:600">Final Heuristic: ${(hScore*100).toFixed(1)}%</div>`;
  h += '</div></div>';

  // ─── ANE MODEL DETAILS ───
  if (model) {
    h += '<div class="card" style="margin-top:8px"><h3>Neural Engine Model Execution</h3><div style="margin-top:6px">';
    const mRows = [
      ['Runner', model.runner],
      ['Model Path', model.model_path],
      ['Compute Units', model.compute_units],
      ['GPU Lane Score', model.gpu_lane_score !== null ? (model.gpu_lane_score * 100).toFixed(2) + '%' : 'N/A'],
    ];
    for (const [l, v] of mRows) {
      const short = typeof v === 'string' && v.length > 60 ? '...' + v.slice(-55) : v;
      h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${short}</strong></div>`;
    }
    if (model.outputs) {
      h += '<div style="margin-top:4px;font-size:10px;color:var(--dim)">Raw outputs:</div>';
      h += `<pre style="font-size:10px;background:var(--surface2);padding:6px;border-radius:4px;margin-top:2px;overflow-x:auto">${JSON.stringify(model.outputs, null, 2)}</pre>`;
    }
    h += '</div></div>';
  }

  // ─── SCHEDULER DECISION ───
  if (sched) {
    h += '<div class="card" style="margin-top:8px"><h3>GPU Scheduler Decision</h3><div style="margin-top:6px">';
    const sRows = [
      ['Requested Jobs', sched.requested_jobs],
      ['Recommended Jobs', sched.recommended_jobs],
      ['Total Jobs', sched.total_jobs],
      ['Estimated Job Size', F.bytes(sched.estimated_job_bytes || 0)],
      ['Memory Budget', sched.memory_budget_bytes ? F.bytes(sched.memory_budget_bytes) : 'N/A'],
      ['Metal Device', sched.metal_device || 'N/A'],
      ['Reason', sched.reason],
    ];
    for (const [l, v] of sRows) {
      h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${v}</strong></div>`;
    }
    h += '</div></div>';
  }

  // ─── POLICY + RUNTIME CONTEXT ───
  h += '<div class="grid g2" style="margin-top:8px">';

  h += '<div class="card"><h3>Policy Context</h3><div style="margin-top:6px">';
  const ctxRows = [
    ['Trace Path', p._trace_path || p.trace_path || '-'],
    ['Field', p.field || '-'],
    ['Policy Schema', p.policy_schema || '-'],
    ['Generated', p.generated_at_unix_ms ? F.dt(p.generated_at_unix_ms) : '-'],
    ['Runner', model?.runner || '-'],
    ['Model Path', model?._model_path || model?.model_path || p._model_path || '-'],
  ];
  for (const [l, v] of ctxRows) {
    const short = typeof v === 'string' && v.length > 68 ? '...' + v.slice(-63) : v;
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${short}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Strict Certification Context</h3><div style="margin-top:6px">';
  const certRows = [
    ['Report Present', cert.present ? 'YES' : 'NO'],
    ['Matches Current Build', cert.matches_current ? 'YES' : 'NO'],
    ['Report Path', cert.report_path || '-'],
  ];
  for (const [l, v] of certRows) {
    const color = v === 'YES' ? 'green' : v === 'NO' ? 'yellow' : 'accent';
    const short = typeof v === 'string' && v.length > 68 ? '...' + v.slice(-63) : v;
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong class="${color}">${short}</strong></div>`;
  }
  const failures = cert.failures || [];
  if (failures.length) {
    h += '<div style="margin-top:4px;font-size:10px;color:var(--yellow)">';
    for (const f of failures) h += `<div>${f}</div>`;
    h += '</div>';
  }
  h += '</div></div>';
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Metal Runtime Inputs</h3><div style="margin-top:6px">';
  const rtRows = [
    ['Metal Compiled', mr.metal_compiled ? 'YES' : 'NO'],
    ['Metal Available', mr.metal_available ? 'YES' : 'NO'],
    ['Device', mr.metal_device || '-'],
    ['Metallib Mode', mr.metallib_mode || '-'],
    ['Threshold Profile', mr.threshold_profile || '-'],
    ['Threshold Summary', mr.threshold_summary || '-'],
    ['Working Set Budget', mr.recommended_working_set_size_bytes ? F.bytes(mr.recommended_working_set_size_bytes) : '-'],
    ['Current Allocated', mr.current_allocated_size_bytes ? F.bytes(mr.current_allocated_size_bytes) : '-'],
    ['Headroom', mr.working_set_headroom_bytes ? F.bytes(mr.working_set_headroom_bytes) : '-'],
    ['Utilization', mr.working_set_utilization_pct !== null && mr.working_set_utilization_pct !== undefined ? `${mr.working_set_utilization_pct.toFixed(1)}%` : '-'],
    ['Prewarmed Pipelines', mr.prewarmed_pipelines ? 'YES' : 'NO'],
    ['Counter Source', mr.metal_counter_source || '-'],
  ];
  for (const [l, v] of rtRows) {
    const short = typeof v === 'string' && v.length > 64 ? '...' + v.slice(-59) : v;
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${short}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Accelerator Registry Context</h3><div style="margin-top:6px">';
  const regRows = [
    ['Active Families', activeAccels.length],
    ['Registered Families', registeredAccels.length],
    ['Primary Queue Depth', mr.metal_primary_queue_depth ?? '-'],
    ['Secondary Queue Depth', mr.metal_secondary_queue_depth ?? '-'],
    ['Max In Flight', mr.metal_pipeline_max_in_flight ?? '-'],
    ['Scheduler Max Jobs', mr.metal_scheduler_max_jobs ?? '-'],
    ['Headroom Target', mr.metal_working_set_headroom_target_pct !== null && mr.metal_working_set_headroom_target_pct !== undefined ? `${mr.metal_working_set_headroom_target_pct}%` : '-'],
  ];
  for (const [l, v] of regRows) {
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${v}</strong></div>`;
  }
  if (activeAccels.length) {
    h += `<div style="margin-top:6px;font-size:10px"><span style="color:var(--dim)">Active:</span> ${activeAccels.map(([k]) => k).join(', ')}</div>`;
  }
  if (registeredAccels.length) {
    h += `<div style="margin-top:4px;font-size:10px;color:var(--dim)">Registered: ${registeredAccels.map(([k]) => k).join(', ')}</div>`;
    h += '<div style="margin-top:6px;font-size:10px">';
    for (const [family, impls] of registeredAccels) {
      h += `<div style="padding:1px 0"><span style="color:var(--dim)">${family}:</span> ${Array.isArray(impls) ? impls.join(', ') : impls}</div>`;
    }
    h += '</div>';
  }
  h += '</div></div>';
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Policy Resource Envelope</h3><div style="margin-top:6px">';
  const resourceRows = [
    ['Total RAM', resources.total_ram_bytes ? F.bytes(resources.total_ram_bytes) : '-'],
    ['Available RAM', resources.available_ram_bytes ? F.bytes(resources.available_ram_bytes) : '-'],
    ['Unified Memory', resources.unified_memory ? 'YES' : 'NO'],
    ['GPU Memory View', resources.gpu_memory_bytes ? F.bytes(resources.gpu_memory_bytes) : '-'],
    ['CPU Cores', resources.cpu_cores_physical!==undefined ? `${resources.cpu_cores_physical} physical / ${resources.cpu_cores_logical ?? '?'} logical` : '-'],
    ['Pressure Level', resPressure.level || '-'],
    ['Pressure Utilization', resPressure.utilization_pct!==undefined ? `${resPressure.utilization_pct}%` : '-'],
    ['Free Bytes', resPressure.free_bytes ? F.bytes(resPressure.free_bytes) : '-'],
    ['Inactive Bytes', resPressure.inactive_bytes ? F.bytes(resPressure.inactive_bytes) : '-'],
    ['Purgeable Bytes', resPressure.purgeable_bytes ? F.bytes(resPressure.purgeable_bytes) : '-'],
    ['Compressed', resPressure.compressed_bytes ? F.bytes(resPressure.compressed_bytes) : '-'],
    ['Swap Used', resPressure.swap_used_bytes ? F.bytes(resPressure.swap_used_bytes) : '0 B'],
    ['Compressor Overflow', resPressure.compressor_overflow ? 'YES' : 'NO'],
  ];
  for (const [l, v] of resourceRows) {
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${v}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Backend / Model Decision Surface</h3><div style="margin-top:6px">';
  const decisionRows = [
    ['Recommended Lane', metalFirst ? 'Metal-First' : 'CPU-Preferred'],
    ['Recommended Jobs', jobs],
    ['Candidate Backends', backendCandidates.length],
    ['Field', p.field || '-'],
    ['Scheduler Reason', sched?.reason || '-'],
    ['Model Runner', model?.runner || '-'],
    ['Compute Units', model?.compute_units || '-'],
    ['Raw Model Score', mScore!==null&&mScore!==undefined ? `${(mScore*100).toFixed(1)}%` : 'N/A'],
  ];
  for (const [l, v] of decisionRows) {
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${l}:</span> <strong>${v}</strong></div>`;
  }
  if (backendCandidates.length) {
    h += `<div style="margin-top:6px;font-size:10px"><span style="color:var(--dim)">Candidates:</span> ${backendCandidates.map(v => escHtml(String(v))).join(', ')}</div>`;
  }
  if (Object.keys(modelOutputs).length) {
    h += '<div style="margin-top:6px;font-size:10px;color:var(--dim)">Model outputs:</div>';
    for (const [k, v] of Object.entries(modelOutputs)) {
      h += `<div style="font-size:10px;padding:1px 0"><span style="color:var(--dim)">${k}:</span> <strong>${typeof v === 'number' ? v.toFixed(6) : escHtml(String(v))}</strong></div>`;
    }
  }
  h += '</div></div>';
  h += '</div>';

  // ─── DECISION FLOW ───
  h += '<div class="card" style="margin-top:8px"><h3>Decision Flow</h3>';
  const steps = [
    {label:'Trace Input', sub: p._trace_path ? '...'+p._trace_path.slice(-30) : 'params', c:'var(--dim)'},
    {label:'12 Features', sub: `${feats.constraints?.toLocaleString()||0} constraints`, c:'var(--accent)'},
    {label:'10-d Vector', sub: 'normalized [0,1]', c:'var(--accent)'},
    {label:'Heuristic', sub: `${(hScore*100).toFixed(1)}%`, c:'var(--accent)'},
  ];
  if (model) {
    steps.push({label:'ANE Model', sub: `${model.compute_units}`, c:'var(--purple)'});
    steps.push({label:'Model Score', sub: `${model.gpu_lane_score!==null?(model.gpu_lane_score*100).toFixed(1)+'%':'N/A'}`, c:'var(--purple)'});
    steps.push({label:'Blend 70/30', sub: `${(fScore*100).toFixed(1)}%`, c:'var(--green)'});
  }
  steps.push({label:metalFirst?'Metal-First':'CPU-Preferred', sub: `${jobs} job(s)`, c: metalFirst?'var(--green)':'var(--yellow)'});
  const compactFlow = steps.length > 0 && steps.length <= 8;
  h += `<div style="display:flex;align-items:stretch;gap:${compactFlow?6:0}px;margin:10px 0;${compactFlow?'width:100%;overflow:hidden;':'overflow-x:auto;'}padding:6px 0">`;
  for (let i = 0; i < steps.length; i++) {
    const s = steps[i];
    const stepStyle = compactFlow
      ? 'background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:7px 8px;flex:1 1 0;min-width:0;text-align:center;display:flex;flex-direction:column;justify-content:center'
      : 'background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:6px 10px;text-align:center;min-width:90px';
    h += `<div style="${stepStyle}">`;
    h += `<div style="font-size:${compactFlow?'9':'11'}px;font-weight:600;color:${s.c};white-space:normal;overflow-wrap:anywhere;line-height:1.15">${escHtml(String(s.label))}</div>`;
    h += `<div style="font-size:8px;color:var(--dim);white-space:normal;overflow-wrap:anywhere;line-height:1.15;margin-top:2px">${escHtml(String(s.sub))}</div>`;
    h += '</div>';
    if (i < steps.length-1) {
      const arrowStyle = compactFlow
        ? 'flex:0 0 12px;display:flex;align-items:center;justify-content:center;font-size:13px;color:var(--dim)'
        : 'font-size:16px;color:var(--dim);padding:0 3px';
      h += `<div style="${arrowStyle}">&rarr;</div>`;
    }
  }
  h += '</div></div>';

  // ─── NOTES ───
  const notes = p.notes || [];
  if (notes.length) {
    h += '<div class="card" style="margin-top:8px"><h3>Diagnostics</h3><div style="margin-top:4px">';
    for (const n of notes) {
      const isWarn = n.includes('not') || n.includes('missing') || n.includes('open');
      h += `<div style="font-size:11px;padding:2px 0;color:${isWarn?'var(--yellow)':'var(--dim)'}">${n}</div>`;
    }
    h += '</div></div>';
  }

  // ─── METADATA ───
  h += `<div style="margin-top:8px;font-size:9px;color:var(--dim)">Policy schema: ${p.policy_schema} | Generated: ${F.dt(p.generated_at_unix_ms)} | Refreshes every 30s via live CLI invocation with CoreML model</div>`;

  document.getElementById('tab-ane').innerHTML = h;
}

function renderUmpg(d) {
  const u = d.umpg||{};
  const plan = u.plan||{};
  const planNodes = Array.isArray(plan.nodes) ? plan.nodes : [];
  const planBuffers = plan.buffers||{};
  const nodes = u.node_traces||[];
  const buf = u.buffer_lineage||{};
  const rs = u.runtime_stages||{};
  const eng = u.engines||{};
  const sum = u.summary||{};
  const trends = u.node_trends||{};
  const trust = (d.latest_artifact || {}).trust_summary || {};

  if (!nodes.length && !plan.graph) {
    document.getElementById('tab-umpg').innerHTML='<div class="card"><span style="color:var(--dim)">No UMPG execution data yet</span></div>';
    return;
  }

  let h = '';
  const placement = plan.placement||{};
  const uniqueAccelerators = [...new Set(nodes.map(n=>n.accelerator_name).filter(Boolean))];
  const fallbackCount = nodes.filter(n=>n.fell_back).length;
  const delegatedCount = nodes.filter(n=>n.delegated).length;
  const totalInputBytes = nodes.reduce((acc, n)=>acc + (n.input_bytes||0), 0);
  const totalOutputBytes = nodes.reduce((acc, n)=>acc + (n.output_bytes||0), 0);
  const totalWallMs = nodes.reduce((acc, n)=>acc + (n.wall_time_ms||0), 0);
  const classTotals = planBuffers.class_totals_bytes || {};

  h += '<div class="grid g5">';
  h += `<div class="card stat"><div class="sv accent">${sum.node_count||nodes.length||0}</div><div class="sl">UMPG Nodes</div><div class="ss">${sum.plan_kind||plan.kind||'runtime'}</div></div>`;
  h += `<div class="card stat"><div class="sv yellow">${sum.cpu_nodes||nodes.filter(n=>n.placement==='cpu').length}</div><div class="sl">CPU Nodes</div></div>`;
  h += `<div class="card stat"><div class="sv green">${sum.gpu_nodes||nodes.filter(n=>n.placement==='gpu').length}</div><div class="sl">GPU Nodes</div></div>`;
  h += `<div class="card stat"><div class="sv ${fallbackCount===0&&delegatedCount===0?'green':'yellow'}">${fallbackCount}/${delegatedCount}</div><div class="sl">Fallback / Delegated</div></div>`;
  h += `<div class="card stat"><div class="sv purple">${sum.peak_memory_bytes?F.bytes(sum.peak_memory_bytes):'-'}</div><div class="sl">Peak Memory</div></div>`;
  h += '</div>';

  h += '<div class="grid g4" style="margin-top:8px">';
  h += `<div class="card stat"><div class="sv">${classTotals.spill ? F.bytes(classTotals.spill) : '0 B'}</div><div class="sl">Spill Buffers</div></div>`;
  h += `<div class="card stat"><div class="sv">${classTotals.scratch ? F.bytes(classTotals.scratch) : '0 B'}</div><div class="sl">Scratch Buffers</div></div>`;
  h += `<div class="card stat"><div class="sv">${classTotals.hot_resident ? F.bytes(classTotals.hot_resident) : '0 B'}</div><div class="sl">Hot Resident</div></div>`;
  h += `<div class="card stat"><div class="sv ${sum.umpg_low_memory_mode===false?'green':'yellow'}">${sum.umpg_low_memory_mode===false?'OFF':'ON'}</div><div class="sl">Low Memory Mode</div></div>`;
  h += '</div>';

  // ─── DAG GRAPH VISUALIZATION ───
  const graph = plan.graph||{};
  const gNodes = graph.nodes||[];
  const gEdges = graph.edges||[];
  const compactDag = gNodes.length > 0 && gNodes.length <= 6;
  h += '<div class="card"><h3>UMPG Prover DAG</h3>';
  h += `<div style="display:flex;align-items:stretch;gap:${compactDag?6:0}px;margin:12px 0;${compactDag?'width:100%;overflow:hidden;':'overflow-x:auto;'}padding:8px 0">`;
  for (let i = 0; i < gNodes.length; i++) {
    const n = gNodes[i];
    const nt = nodes.find(t=>t.op===n.op)||{};
    const wallMs = nt.wall_time_ms;
    const placement = nt.placement||'?';
    const pColor = placement==='cpu'?'var(--yellow)':'var(--green)';
    const outBytes = nt.output_bytes;
    const nodeStyle = compactDag
      ? 'background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:10px 12px;flex:1 1 0;min-width:0;text-align:center;display:flex;flex-direction:column;justify-content:center'
      : 'background:var(--surface2);border:1px solid var(--border);border-radius:6px;padding:8px 12px;min-width:130px;text-align:center';
    h += `<div style="${nodeStyle}">`;
    h += `<div style="font-size:12px;font-weight:700;color:var(--accent)">${n.op}</div>`;
    h += `<div style="font-size:10px;color:${pColor};margin-top:2px">${placement.toUpperCase()}</div>`;
    if (wallMs!==undefined) h += `<div style="font-size:10px;margin-top:2px">${F.ms(wallMs)}</div>`;
    if (outBytes!==undefined) h += `<div style="font-size:9px;color:var(--dim)">${F.bytes(outBytes)} out</div>`;
    h += '</div>';
    if (i < gNodes.length-1) {
      const arrowStyle = compactDag
        ? 'flex:0 0 18px;display:flex;align-items:center;justify-content:center;font-size:18px;color:var(--dim)'
        : 'font-size:18px;color:var(--dim);padding:0 4px';
      h += `<div style="${arrowStyle}">&rarr;</div>`;
    }
  }
  h += '</div></div>';

  // ─── NODE TRACES TABLE ───
  h += '<div class="card" style="margin-top:8px"><h3>Node Execution Traces (Latest Cycle)</h3>';
  h += '<table class="ftable" style="margin-top:6px"><thead><tr><th>Node</th><th>Op</th><th>Placement</th><th>Wall Time</th><th>In</th><th>Out</th><th>Input Digest</th><th>Output Digest</th><th>Trust</th></tr></thead><tbody>';
  for (const nt of nodes) {
    const pC = nt.placement==='cpu'?'yellow':'green';
    h += `<tr>`;
    h += `<td>#${nt.node_id}</td>`;
    h += `<td><strong>${nt.op}</strong></td>`;
    h += `<td><span class="${pC}">${nt.placement}</span></td>`;
    h += `<td>${F.ms(nt.wall_time_ms)}</td>`;
    h += `<td>${F.bytes(nt.input_bytes)}</td>`;
    h += `<td>${F.bytes(nt.output_bytes)}</td>`;
    h += `<td style="font-size:9px;color:var(--dim)">${(nt.input_digest||'-').slice(0,12)}</td>`;
    h += `<td style="font-size:9px;color:var(--dim)">${(nt.output_digest||'-').slice(0,12)}</td>`;
    h += `<td>${nt.trust_model||'-'}</td>`;
    h += `</tr>`;
  }
  h += '</tbody></table></div>';

  // ─── EXECUTION SEMANTICS ───
  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Execution Semantics</h3><div style="margin-top:4px">';
  const semRows = [
    ['Trust Model', trust.trust_model || '-'],
    ['Support Class', trust.support_class || '-'],
    ['Contains Attestation Nodes', trust.contains_attestation_nodes ? 'YES' : 'NO'],
    ['Contains Delegated Nodes', trust.contains_delegated_nodes ? 'YES' : 'NO'],
    ['Contains Metadata-only Nodes', trust.contains_metadata_only_nodes ? 'YES' : 'NO'],
    ['GPU Candidate Nodes', placement.gpu_candidate_count ?? '-'],
    ['Either-placement Nodes', placement.either_count ?? '-'],
    ['CPU-only Nodes', placement.cpu_only_count ?? '-'],
  ];
  for (const [label, val] of semRows) {
    const color = val === 'NO' ? 'green' : val === 'YES' ? 'yellow' : 'accent';
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${label}:</span> <strong class="${color}">${val}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Execution Aggregates</h3><div style="margin-top:4px">';
  const aggRows = [
    ['Observed Wall Time', F.ms(totalWallMs)],
    ['Runtime Execution', sum.runtime_execution_ms ? F.ms(sum.runtime_execution_ms) : '-'],
    ['Total Input Bytes', F.bytes(totalInputBytes)],
    ['Total Output Bytes', F.bytes(totalOutputBytes)],
    ['Unique Accelerators', uniqueAccelerators.length],
    ['Counter Source', sum.counter_source || '-'],
    ['Plan Reason', sum.umpg_plan_reason || '-'],
  ];
  for (const [label, val] of aggRows) {
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${label}:</span> <strong>${val}</strong></div>`;
  }
  if (uniqueAccelerators.length) {
    h += `<div style="margin-top:4px;font-size:10px;color:var(--dim)">Accelerators: ${uniqueAccelerators.join(', ')}</div>`;
  }
  h += '</div></div>';
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Plan Topology / Placement</h3><div style="margin-top:4px">';
  const topoRows = [
    ['Plan Nodes', planNodes.length || sum.node_count || nodes.length || 0],
    ['Graph Nodes', (graph.nodes||[]).length],
    ['Graph Edges', (graph.edges||[]).length],
    ['Buffer Objects', planBuffers.count ?? '-'],
    ['Buffer Total', planBuffers.total_size_bytes ? F.bytes(planBuffers.total_size_bytes) : '-'],
    ['Contains Attestation Nodes', plan.contains_attestation_nodes ? 'YES' : 'NO'],
    ['Contains GPU Candidates', plan.contains_gpu_candidates ? 'YES' : 'NO'],
    ['CPU-only Count', placement.cpu_only_count ?? '-'],
    ['Either-placement Count', placement.either_count ?? '-'],
    ['GPU Candidate Count', placement.gpu_candidate_count ?? '-'],
    ['Estimated Constraints', sum.umpg_estimated_constraints?.toLocaleString() || '-'],
    ['Estimated Memory', sum.umpg_estimated_memory_bytes ? F.bytes(sum.umpg_estimated_memory_bytes) : '-'],
  ];
  for (const [label, val] of topoRows) {
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${label}:</span> <strong>${val}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Node Accelerator Detail</h3>';
  h += '<table class="ftable" style="margin-top:6px"><thead><tr><th>Node</th><th>Accelerator</th><th>Residency</th><th>Allocated</th><th>Fallback</th><th>Delegated</th></tr></thead><tbody>';
  for (const nt of nodes) {
    h += '<tr>';
    h += `<td>#${nt.node_id} ${escHtml(String(nt.op||'-'))}</td>`;
    h += `<td>${escHtml(String(nt.accelerator_name||'-'))}</td>`;
    h += `<td>${nt.buffer_residency ? escHtml(String(nt.buffer_residency)) : '-'}</td>`;
    h += `<td>${nt.allocated_bytes_after ? F.bytes(nt.allocated_bytes_after) : '-'}</td>`;
    h += `<td class="${nt.fell_back?'yellow':'green'}">${nt.fell_back ? 'YES' : 'NO'}</td>`;
    h += `<td class="${nt.delegated?'yellow':'green'}">${nt.delegated ? (nt.delegated_backend||'YES') : 'NO'}</td>`;
    h += '</tr>';
  }
  h += '</tbody></table></div>';
  h += '</div>';

  h += '<div class="card" style="margin-top:8px"><h3>Plan Node Specifications</h3>';
  h += '<table class="ftable" style="margin-top:6px"><thead><tr><th>Node</th><th>Deps</th><th>Inputs</th><th>Outputs</th><th>Placement</th><th>Trust</th></tr></thead><tbody>';
  for (const pn of planNodes) {
    const deps = Array.isArray(pn.dependencies) ? pn.dependencies.join(',') : '-';
    const inputs = Array.isArray(pn.inputs) ? `${pn.inputs.length} / ${F.bytes(pn.inputs.reduce((a,b)=>a+(b.size_bytes||0),0))}` : '-';
    const outputs = Array.isArray(pn.outputs) ? `${pn.outputs.length} / ${F.bytes(pn.outputs.reduce((a,b)=>a+(b.size_bytes||0),0))}` : '-';
    h += '<tr>';
    h += `<td>#${pn.node_id ?? pn.index ?? '-'} ${escHtml(String(pn.op||'-'))}</td>`;
    h += `<td>${deps || '-'}</td>`;
    h += `<td>${inputs}</td>`;
    h += `<td>${outputs}</td>`;
    h += `<td>${pn.placement || '-'}</td>`;
    h += `<td>${pn.trust_model || '-'}</td>`;
    h += '</tr>';
  }
  h += '</tbody></table></div>';

  // ─── BUFFER LINEAGE ───
  const bufItems = buf.items||[];
  const liveClassTotals = buf.class_totals_bytes||{};
  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Buffer Lineage</h3>';
  h += `<div style="font-size:11px;margin:4px 0">Total: <strong>${F.bytes(buf.total_size_bytes||0)}</strong> across ${buf.count||0} buffers</div>`;
  h += '<table class="ftable"><thead><tr><th>Slot</th><th>Class</th><th>Size</th><th>Producers</th><th>Consumers</th></tr></thead><tbody>';
  for (const b of bufItems) {
    const classC = b.class==='spill'?'orange':b.class==='hot_resident'?'green':'accent';
    h += `<tr><td>#${b.slot}</td><td><span class="${classC}">${b.class}</span></td><td>${F.bytes(b.size_bytes)}</td>`;
    h += `<td>${(b.producer_node_ids||[]).join(',')}</td>`;
    h += `<td>${(b.consumer_node_ids||[]).join(',')}</td></tr>`;
  }
  h += '</tbody></table>';
  h += '<div style="margin-top:6px;font-size:10px">';
  for (const [cls, bytes] of Object.entries(liveClassTotals)) {
    const classC = cls==='spill'?'orange':cls==='hot_resident'?'green':'accent';
    h += `<span class="${classC}">${cls}: ${F.bytes(bytes)}</span>&nbsp;&nbsp;`;
  }
  h += '</div></div>';

  // ─── RUNTIME STAGE BREAKDOWN ───
  h += '<div class="card"><h3>UMPG Runtime Stages</h3>';
  const rsEntries = Object.entries(rs).sort((a,b)=>(b[1].duration_ms||0)-(a[1].duration_ms||0));
  const rsMx = Math.max(...rsEntries.map(([,v])=>v.duration_ms||0), 0.001);
  h += '<div style="margin-top:6px">';
  for (const [name, stage] of rsEntries) {
    const pW = Math.max(1, (stage.duration_ms/rsMx)*100);
    const hasGpu = stage.gpu_nodes>0;
    const color = hasGpu?'var(--green)':'var(--yellow)';
    h += `<div class="stage-row">`;
    h += `<div class="stage-name" title="${name}">${name}</div>`;
    h += `<div class="stage-bar-outer"><div class="stage-bar-fill" style="width:${pW}%;background:${color}"></div></div>`;
    h += `<div class="stage-time">${F.ms(stage.duration_ms)}</div>`;
    h += `<div style="flex:0 0 70px;text-align:right;font-size:9px"><span class="accent">${F.bytes(stage.input_bytes||0)}</span>&rarr;<span class="green">${F.bytes(stage.output_bytes||0)}</span></div>`;
    h += '</div>';
  }
  h += '</div></div>';
  h += '</div>';

  // ─── STAGE ACCELERATOR ROSTER ───
  h += '<div class="card" style="margin-top:8px"><h3>Stage Accelerator Roster</h3><div style="margin-top:6px">';
  for (const [name, stage] of rsEntries) {
    const accels = stage.accelerators || [];
    h += `<div style="padding:4px 0;border-bottom:1px solid var(--border)">`;
    h += `<div style="font-size:11px"><strong>${name}</strong> <span style="color:var(--dim)">(${F.ms(stage.duration_ms||0)})</span></div>`;
    h += `<div style="font-size:10px;color:var(--dim)">CPU nodes: ${stage.cpu_nodes||0} | GPU nodes: ${stage.gpu_nodes||0} | Fallbacks: ${stage.fallback_nodes||0} | Accelerators: ${accels.length?accels.join(', '):'none'}</div>`;
    h += `</div>`;
  }
  h += '</div></div>';

  // ─── ENGINE SELECTIONS ───
  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Engine Selections</h3><div style="margin-top:4px">';
  const engRows = [
    ['MSM Engine', eng.msm_engine, eng.msm_reason],
    ['MSM Accelerator', eng.msm_accelerator, `parallelism=${eng.msm_parallelism}, fallback=${eng.msm_fallback}`],
    ['QAP Witness Map', eng.qap_engine, eng.qap_reason],
    ['QAP Parallelism', eng.qap_parallelism, `fallback=${eng.qap_fallback}`],
    ['Proof Engine', eng.proof_engine, null],
    ['Wrapper Cache', eng.wrapper_cache_hit?'HIT':'MISS', `source=${eng.wrapper_cache_source}, pk=${eng.wrapper_setup_pk_format}`],
  ];
  for (const [label, val, detail] of engRows) {
    const isGood = val && (String(val).includes('metal') || val === 'HIT' || val === true);
    const vC = isGood ? 'green' : 'accent';
    h += `<div style="font-size:11px;padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong class="${vC}">${val||'-'}</strong>`;
    if (detail) h += ` <span style="font-size:9px;color:var(--dim)">(${detail})</span>`;
    h += '</div>';
  }
  h += '</div></div>';

  // ─── PLAN SUMMARY ───
  h += '<div class="card"><h3>Runtime Provenance</h3><div style="margin-top:4px">';
  const sumRows = [
    ['Plan Kind', sum.plan_kind],
    ['Plan Schema', sum.plan_schema],
    ['Hardware Profile', sum.hardware_profile],
    ['Memory Budget', sum.umpg_memory_budget_bytes ? F.bytes(sum.umpg_memory_budget_bytes) : null],
    ['Execution Time', sum.runtime_execution_ms ? F.ms(sum.runtime_execution_ms) : null],
    ['CPU Wall Time', sum.runtime_cpu_wall_ms ? F.ms(sum.runtime_cpu_wall_ms) : null],
    ['GPU Wall Time', sum.runtime_gpu_wall_ms ? F.ms(sum.runtime_gpu_wall_ms) : null],
    ['Counter Source', sum.counter_source],
    ['Plan Reason', sum.umpg_plan_reason],
  ];
  for (const [label, val] of sumRows) {
    if (val === null || val === undefined) continue;
    h += `<div style="font-size:11px;padding:1px 0"><span style="color:var(--dim)">${label}:</span> ${val}</div>`;
  }
  h += '</div></div>';
  h += '</div>';

  // ─── PER-OP TIMING TRENDS ───
  const ops = Object.keys(trends);
  if (ops.length) {
    h += '<div class="card" style="margin-top:8px"><h3>Per-Node Timing Across Cycles</h3>';
    h += '<div class="grid g3" style="margin-top:6px">';
    for (const op of ops) {
      const vals = trends[op];
      const avg = vals.reduce((a,b)=>a+b,0)/vals.length;
      const mn = Math.min(...vals);
      const mx = Math.max(...vals);
      h += `<div class="card" style="padding:6px"><div style="font-size:11px;font-weight:600;color:var(--accent)">${op}</div>`;
      h += sparkline(vals, 'var(--purple)', 30);
      h += `<div style="font-size:9px;color:var(--dim);margin-top:2px">avg ${F.ms(avg)} | min ${F.ms(mn)} | max ${F.ms(mx)} | ${vals.length} pts</div>`;
      h += '</div>';
    }
    h += '</div></div>';
  }

  // ─── PLAN DIGESTS ───
  h += '<div class="card" style="margin-top:8px"><h3>Cryptographic Bindings</h3><div style="margin-top:4px;font-size:10px;word-break:break-all">';
  h += `<div><span style="color:var(--dim)">Plan Digest:</span> ${sum.plan_digest||'-'}</div>`;
  h += `<div><span style="color:var(--dim)">Plan SHA256:</span> ${sum.plan_sha256||'-'}</div>`;
  const latest = d.warm_cycles?.length ? d.warm_cycles[d.warm_cycles.length-1] : {};
  const et = latest.execution_trace||{};
  h += `<div><span style="color:var(--dim)">Source Proof SHA256:</span> ${et.runtime_source_proof_sha256||'-'}</div>`;
  h += `<div><span style="color:var(--dim)">Compiled SHA256:</span> ${et.runtime_source_compiled_sha256||'-'}</div>`;
  h += `<div><span style="color:var(--dim)">Program Digest:</span> ${et.runtime_compiled_program_digest||'-'}</div>`;
  h += '</div></div>';

  document.getElementById('tab-umpg').innerHTML = h;
}

function renderCrypto(d) {
  const latest = d.latest_artifact || {};
  const sum = latest.summary || {};
  const trust = latest.trust_summary || {};
  const lowering = latest.lowering_report || {};

  if (!sum.artifact_path) {
    document.getElementById('tab-crypto').innerHTML = '<div class="card"><span style="color:var(--dim)">No wrapped artifact context available yet</span></div>';
    return;
  }

  let h = '';

  h += '<div class="grid g5">';
  h += `<div class="card stat"><div class="sv accent">${sum.status || '-'}</div><div class="sl">Artifact Status</div><div class="ss">cycle ${sum.cycle || '?'}</div></div>`;
  h += `<div class="card stat"><div class="sv">${sum.trust_model || '-'}</div><div class="sl">Trust Model</div><div class="ss">${sum.wrapper_strategy || '-'}</div></div>`;
  h += `<div class="card stat"><div class="sv">${sum.curve || '-'}</div><div class="sl">Curve</div><div class="ss">${sum.export_scheme || '-'}</div></div>`;
  h += `<div class="card stat"><div class="sv">${sum.proof_engine || '-'}</div><div class="sl">Proof Engine</div><div class="ss">${sum.source_backend || '-'}</div></div>`;
  h += `<div class="card stat"><div class="sv ${F.sc(parseFloat(sum.gpu_stage_busy_ratio || 0),0.2,0.1)}">${sum.gpu_stage_busy_ratio ? (parseFloat(sum.gpu_stage_busy_ratio)*100).toFixed(1)+'%' : '-'}</div><div class="sl">GPU Busy</div><div class="ss">${sum.hardware_profile || '-'}</div></div>`;
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Protocol / Math Parameters</h3><div style="margin-top:6px">';
  const paramRows = [
    ['FRI Rounds', sum.num_fri_rounds],
    ['Merkle Height', sum.merkle_tree_height],
    ['Queries', sum.num_queries],
    ['Log Degree', sum.log_degree],
    ['Poseidon2 Seed', sum.poseidon2_seed],
    ['Public Inputs', sum.public_inputs_count],
    ['QAP Engine', sum.qap_engine],
    ['QAP Reason', sum.qap_reason],
    ['QAP Parallelism', sum.qap_parallelism],
    ['MSM Engine', sum.msm_engine],
    ['MSM Reason', sum.msm_reason],
    ['MSM Parallelism', sum.msm_parallelism],
  ];
  for (const [label, val] of paramRows) {
    if (val === null || val === undefined || val === '') continue;
    h += `<div style="font-size:11px;padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${val}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Cryptographic Bindings</h3><div style="margin-top:6px;font-size:10px;word-break:break-all">';
  const bindRows = [
    ['Artifact Path', sum.artifact_path],
    ['Runtime Trace', sum.runtime_trace_path],
    ['Execution Trace', sum.execution_trace_path],
    ['Plan Digest', sum.plan_digest],
    ['Plan SHA256', sum.plan_sha256],
    ['Program Digest', sum.program_digest],
    ['Trace Program Digest', sum.program_trace_digest],
    ['Source Proof SHA256', sum.source_proof_sha256],
    ['Source Compiled SHA256', sum.source_compiled_sha256],
    ['Outer Input SHA256', sum.outer_input_sha256],
  ];
  for (const [label, val] of bindRows) {
    if (!val) continue;
    h += `<div style="padding:2px 0"><span style="color:var(--dim)">${label}:</span> ${val}</div>`;
  }
  h += '</div></div>';
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Trust / Lowering Summary</h3><div style="margin-top:6px">';
  const trustRows = [
    ['Trust Model', trust.trust_model],
    ['Support Class', trust.support_class],
    ['Attestation Nodes', trust.contains_attestation_nodes],
    ['Delegated Nodes', trust.contains_delegated_nodes],
    ['Metadata-only Nodes', trust.contains_metadata_only_nodes],
    ['Lowering Backend', lowering.backend],
    ['Lowering Trust Model', lowering.trust_model],
    ['Lowering Support Class', lowering.support_class],
  ];
  for (const [label, val] of trustRows) {
    if (val === undefined || val === null) continue;
    const rendered = typeof val === 'boolean' ? (val ? 'true' : 'false') : val;
    h += `<div style="font-size:11px;padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${rendered}</strong></div>`;
  }
  const adapted = lowering.adapted_features || [];
  const preserved = lowering.preserved_features || [];
  const delegated = lowering.delegated_features || [];
  if (adapted.length) h += `<div style="font-size:10px;color:var(--dim);margin-top:6px">Adapted: ${adapted.map(f=>f.feature || f).join(', ')}</div>`;
  if (preserved.length) h += `<div style="font-size:10px;color:var(--dim);margin-top:2px">Preserved: ${preserved.join(', ')}</div>`;
  if (delegated.length) h += `<div style="font-size:10px;color:var(--dim);margin-top:2px">Delegated: ${delegated.join(', ')}</div>`;
  h += '</div></div>';

  h += '<div class="card"><h3>Dispatch / Cache Provenance</h3><div style="margin-top:6px">';
  const provRows = [
    ['Cache Hit', sum.wrapper_cache_hit],
    ['Cache Source', sum.wrapper_cache_source],
    ['Counter Source', sum.counter_source],
    ['Target Dispatch Open', sum.target_dispatch_circuit_open],
    ['Target Dispatch Failure', sum.target_dispatch_last_failure],
  ];
  for (const [label, val] of provRows) {
    if (val === undefined || val === null || val === '') continue;
    const rendered = typeof val === 'boolean' ? (val ? 'true' : 'false') : val;
    h += `<div style="font-size:11px;padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${rendered}</strong></div>`;
  }
  h += '</div></div>';
  h += '</div>';

  document.getElementById('tab-crypto').innerHTML = h;
}

function renderMatrix(d) {
  const doc = d.system_doctor || {};
  const backends = doc.backends || [];
  const matrix = d.support_matrix || {};
  const staticBackends = matrix.backends || [];
  const gadgets = matrix.gadgets || [];
  const roadmap = matrix.roadmap_completion || {};
  const assets = d.workspace_assets || {};

  let h = '';

  h += '<div class="card"><h3>Runtime Backend Truth Matrix</h3>';
  h += '<table class="ftable" style="margin-top:6px"><thead><tr><th>Backend</th><th>Mode</th><th>Engine</th><th>Metal</th><th>Setup</th><th>Recursion</th><th>GPU Coverage</th></tr></thead><tbody>';
  for (const b of backends) {
    const cov = b.gpu_stage_coverage || {};
    const coverage = cov.coverage_ratio !== undefined ? `${(cov.coverage_ratio*100).toFixed(0)}%` : '-';
    h += `<tr>`;
    h += `<td><strong>${b.backend}</strong></td>`;
    h += `<td>${b.mode || '-'}</td>`;
    h += `<td>${b.proof_engine || '-'}</td>`;
    h += `<td class="${b.metal_complete ? 'green' : 'yellow'}">${b.metal_complete ? 'yes' : 'no'}</td>`;
    h += `<td>${b.transparent_setup ? 'transparent' : (b.trusted_setup ? 'trusted' : '-')}</td>`;
    h += `<td>${b.recursion_ready ? 'yes' : 'no'}</td>`;
    h += `<td>${coverage}</td>`;
    h += `</tr>`;
  }
  h += '</tbody></table></div>';

  h += '<div class="grid g3" style="margin-top:8px">';
  const readyBackends = staticBackends.filter(b => b.status === 'ready').length;
  const delegatedBackends = staticBackends.filter(b => b.mode === 'delegated' || b.status === 'delegated').length;
  const brokenBackends = staticBackends.filter(b => b.status === 'broken').length;
  h += `<div class="card stat"><div class="sv green">${readyBackends}</div><div class="sl">Ready Backends</div><div class="ss">${staticBackends.length} listed</div></div>`;
  h += `<div class="card stat"><div class="sv yellow">${delegatedBackends}</div><div class="sl">Delegated</div><div class="ss">runtime or compatibility</div></div>`;
  h += `<div class="card stat"><div class="sv ${brokenBackends ? 'red' : 'green'}">${brokenBackends}</div><div class="sl">Broken / Blocked</div><div class="ss">from support matrix</div></div>`;
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Gadget Coverage</h3><div style="margin-top:6px">';
  const gadgetCounts = {};
  for (const g of gadgets) gadgetCounts[g.status || 'unknown'] = (gadgetCounts[g.status || 'unknown'] || 0) + 1;
  for (const [status, count] of Object.entries(gadgetCounts)) {
    const cls = status === 'ready' ? 'green' : status === 'limited' ? 'yellow' : 'red';
    h += `<div style="font-size:11px;padding:2px 0"><span class="${cls}"><strong>${status}</strong></span>: ${count}</div>`;
  }
  const gadgetList = gadgets.slice(0, 12).map(g => `${g.id}:${g.status}`).join(', ');
  if (gadgetList) h += `<div style="font-size:10px;color:var(--dim);margin-top:6px">${gadgetList}</div>`;
  h += '</div></div>';

  h += '<div class="card"><h3>Roadmap / Research Surface</h3><div style="margin-top:6px">';
  for (const [phase, status] of Object.entries(roadmap)) {
    const cls = status === 'ready' ? 'green' : status === 'in_progress' ? 'yellow' : 'accent';
    h += `<div style="font-size:11px;padding:2px 0"><span style="color:var(--dim)">${phase}:</span> <span class="${cls}"><strong>${status}</strong></span></div>`;
  }
  h += '</div></div>';
  h += '</div>';

  h += '<div class="grid g3" style="margin-top:8px">';
  const assetCards = [
    ['Audit Reports', assets.audit_reports],
    ['Ceremony PTAU', assets.ceremony_ptau],
    ['Verifier Exports', assets.verifier_exports],
  ];
  for (const [label, asset] of assetCards) {
    const count = asset?.count || 0;
    h += `<div class="card"><h3>${label}</h3><div class="sv ${count ? 'accent' : 'yellow'}" style="font-size:20px">${count}</div>`;
    if (asset?.samples?.length) {
      h += `<div style="margin-top:6px;font-size:10px;color:var(--dim)">` + asset.samples.map(s => escHtml(s)).join('<br>') + `</div>`;
    } else {
      h += `<div style="margin-top:6px;font-size:10px;color:var(--dim)">none found</div>`;
    }
    h += `</div>`;
  }
  h += '</div>';

  document.getElementById('tab-matrix').innerHTML = h;
}

function flatStages(bd, pfx) {
  let r = []; if (!bd) return r;
  for (const [k,v] of Object.entries(bd)) {
    const n = pfx ? pfx+' > '+k : k;
    if (v && typeof v==='object' && v.duration_ms!==undefined) r.push({name:n,...v});
    else if (v && typeof v==='object') r = r.concat(flatStages(v, n));
  }
  return r;
}

function renderStages(d) {
  const warm = d.warm_cycles||[];
  const latest = warm.length>0 ? warm[warm.length-1] : null;
  const rt = latest ? latest.runtime_trace : {};
  const stages = flatStages(rt.stage_breakdown, '');
  if (!stages.length) { document.getElementById('tab-stages').innerHTML='<div class="card"><span style="color:var(--dim)">No stage data yet</span></div>'; return; }
  stages.sort((a,b)=>(b.duration_ms||0)-(a.duration_ms||0));
  const mx = Math.max(...stages.map(s=>s.duration_ms||0),1);
  let h = `<div class="card"><h3>Cycle ${latest?latest.cycle:'?'} Stage Breakdown</h3><div style="margin-top:6px">`;
  for (const s of stages) {
    const pW = Math.max(1,(s.duration_ms/mx)*100);
    const isMetal = (s.accelerator||'').includes('metal');
    const color = isMetal ? 'var(--green)' : 'var(--yellow)';
    const aL = isMetal ? 'GPU' : 'CPU';
    const fb = s.no_cpu_fallback===false ? ' <span class="badge badge-warn" style="font-size:8px">fallback</span>' : '';
    h += `<div class="stage-row"><div class="stage-name" title="${s.name}">${s.name}${fb}</div><div class="stage-bar-outer"><div class="stage-bar-fill" style="width:${pW}%;background:${color}"></div></div><div class="stage-time">${F.ms(s.duration_ms)}</div><div class="stage-accel" style="color:${color}">${aL}</div></div>`;
  }
  h += '</div></div>';

  // Stage drift: compare first warm cycle to latest
  if (warm.length >= 2) {
    const firstStages = flatStages((warm[0].runtime_trace||{}).stage_breakdown, '');
    const lastStages = flatStages((warm[warm.length-1].runtime_trace||{}).stage_breakdown, '');
    const firstMap = Object.fromEntries(firstStages.map(s=>[s.name, s.duration_ms]));
    const drifts = [];
    for (const s of lastStages) {
      const base = firstMap[s.name];
      if (base && base > 100) {
        const pctDrift = ((s.duration_ms-base)/base)*100;
        drifts.push({name:s.name, base, current:s.duration_ms, drift:pctDrift});
      }
    }
    if (drifts.length) {
      drifts.sort((a,b)=>Math.abs(b.drift)-Math.abs(a.drift));
      h += '<div class="card" style="margin-top:8px"><h3>Stage Drift: Cycle 1 vs Latest</h3><div style="margin-top:4px">';
      for (const dr of drifts.slice(0,10)) {
        const dC = Math.abs(dr.drift)<3?'green':Math.abs(dr.drift)<10?'yellow':'red';
        h += `<div style="font-size:10px;padding:2px 0"><span style="color:var(--dim)">${dr.name}</span>: ${F.ms(dr.base)} -> ${F.ms(dr.current)} <span class="${dC}">(${dr.drift>=0?'+':''}${dr.drift.toFixed(1)}%)</span></div>`;
      }
      h += '</div></div>';
    }
  }

  document.getElementById('tab-stages').innerHTML = h;
}

function renderTrust(d) {
  const ti = d.trust_info||{};
  let h = '<div class="grid g2">';

  h += '<div class="card"><h3>Trust Lane Identity</h3><div style="margin-top:6px">';
  const rows = [
    ['Trust Model', ti.trust_model, ti.trust_stable],
    ['Wrapper', ti.wrapper, ti.wrapper_stable],
    ['Strategy', ti.wrapper_strategy, null],
    ['Source Backend', ti.source_backend, ti.backend_stable],
    ['Target Backend', ti.target_backend, null],
    ['Support Class', ti.support_class, null],
    ['Program Digest', ti.program_digest ? ti.program_digest.slice(0,24)+'...' : null, ti.digest_stable],
  ];
  for (const [label, val, stable] of rows) {
    let badge = '';
    if (stable === true) badge = ' <span class="badge badge-stable">stable</span>';
    else if (stable === false) badge = ' <span class="badge badge-drift">CHANGED</span>';
    h += `<div style="font-size:11px;padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${val||'-'}</strong>${badge}</div>`;
  }
  h += '</div></div>';

  // Semantic verification
  h += '<div class="card"><h3>Semantic Verification</h3><div style="margin-top:6px">';
  const wp = d.prepare?.wrapper_preview||{};
  const checks = [
    ['Planned Status', wp.planned_status],
    ['Trust Description', wp.trust_model_description],
    ['Estimated Constraints', wp.estimated_constraints?.toLocaleString()],
    ['Memory Budget', wp.memory_budget_bytes ? F.bytes(wp.memory_budget_bytes) : null],
    ['Low Memory Mode', wp.low_memory_mode === false ? 'OFF' : 'ON'],
  ];
  for (const [label, val] of checks) {
    h += `<div style="font-size:11px;padding:2px 0"><span style="color:var(--dim)">${label}:</span> ${val||'-'}</div>`;
  }
  h += '</div></div>';
  h += '</div>';

  document.getElementById('tab-trust').innerHTML = h;
}

function renderReliability(d) {
  const r = d.reliability||{};
  const items = [
    ['Proof Failures', r.proof_failures, 0],
    ['Verifier Failures', r.verifier_failures, 0],
    ['Export Failures', r.export_failures, 0],
    ['Retry Count', r.retry_count, 0],
    ['Panic Count', r.panic_count, 0],
    ['Metal Kernel Faults', r.metal_kernel_faults, 0],
    ['File Write Failures', r.file_write_failures, 0],
    ['Queue Stalls', r.queue_stalls, 0],
    ['Timeout Count', r.timeout_count, 0],
    ['Doctor Flips', r.doctor_flips, 0],
    ['Degraded Runs', r.degraded_runs, 0],
    ['Circuit Trips', r.dispatch_circuit_trips, 0],
    ['Fallback Events', r.fallback_events, null],
    ['Warm Cycles', r.total_warm_cycles, null],
    ['Parallel Cycles', r.total_parallel_cycles, null],
  ];
  let h = '<div class="card"><h3>Reliability Counters</h3><div class="counter-grid" style="margin-top:6px">';
  for (const [label, val, zeroIsGood] of items) {
    let c = 'accent';
    if (zeroIsGood !== null) {
      c = val === 0 ? 'green' : val <= zeroIsGood ? 'yellow' : 'red';
    }
    h += `<div class="counter-item"><div class="counter-val ${c}">${val??0}</div><div class="counter-label">${label}</div></div>`;
  }
  h += '</div></div>';
  document.getElementById('tab-reliability').innerHTML = h;
}

function renderThermal(d) {
  const t = d.thermal||{};
  const sm = d.system_memory||{};
  const p = d.progress||{};
  const cs = d.cycle_stats||{};
  const gc = d.gpu_context||{};
  const rel = d.reliability||{};
  const hs = d.health||{};
  const speed = t.cpu_speed_limit ?? 100;
  const speedC = speed>=95?'green':speed>=80?'yellow':'red';
  const pressC = t.thermal_pressure==='nominal'?'green':t.thermal_pressure==='elevated'?'yellow':t.thermal_pressure==='high'?'orange':'red';
  const tw = t.thermal_warning ?? 0;
  const pw = t.performance_warning ?? 0;
  const twC = tw===0?'green':tw===1?'yellow':'red';
  const pwC = pw===0?'green':pw===1?'yellow':'red';
  const smartP = sm.pressure_level||'normal';
  const smartPC = smartP==='normal'?'green':smartP==='elevated'?'yellow':smartP==='high'?'orange':'red';
  const smartFree = sm.memory_pressure_free_pct;
  const soakCpu = t.soak_cpu_pct;
  const soakRss = t.soak_rss_mb;
  const swapUsed = sm.swap_used_bytes;
  const elapsed = p.elapsed_ms ? fmtUptime(Math.floor(p.elapsed_ms/1000)) : '-';
  const remaining = p.remaining_duration_ms ? fmtUptime(Math.floor(p.remaining_duration_ms/1000)) : '-';

  let h = '<div class="grid g6">';
  h += `<div class="card stat"><div class="sv ${pressC}">${(t.thermal_pressure||'nominal').toUpperCase()}</div><div class="sl">Thermal Pressure</div></div>`;
  h += `<div class="card stat"><div class="sv ${speedC}">${speed}%</div><div class="sl">CPU Speed Limit</div></div>`;
  h += `<div class="card stat"><div class="sv ${twC}">${tw===0?'NONE':tw===1?'MODERATE':'SERIOUS'}</div><div class="sl">Thermal Warning</div><div class="ss">Level ${tw}</div></div>`;
  h += `<div class="card stat"><div class="sv ${pwC}">${pw===0?'NONE':pw===1?'ACTIVE':'HIGH'}</div><div class="sl">Performance Warning</div><div class="ss">Level ${pw}</div></div>`;
  h += `<div class="card stat"><div class="sv">${t.power_source||'?'}</div><div class="sl">Power Source</div><div class="ss">${t.battery_state!==null&&t.battery_state!==undefined?t.battery_state+'% battery':'n/a'}</div></div>`;
  h += `<div class="card stat"><div class="sv ${smartPC}">${smartP.toUpperCase()}</div><div class="sl">Memory Pressure</div><div class="ss">${smartFree!==null&&smartFree!==undefined?smartFree+'% free':((sm.utilization_pct||0).toFixed(0)+'% used')}</div></div>`;
  h += '</div>';

  h += '<div class="grid g5" style="margin-top:8px">';
  h += `<div class="card stat"><div class="sv">${soakCpu!==null&&soakCpu!==undefined?soakCpu.toFixed(1)+'%':'-'}</div><div class="sl">Soak CPU%</div>${soakRss?`<div class="ss">RSS: ${soakRss.toFixed(0)} MB</div>`:''}</div>`;
  h += `<div class="card stat"><div class="sv">${soakRss!==null&&soakRss!==undefined?F.bytes(soakRss*1024*1024):'-'}</div><div class="sl">Soak RSS</div></div>`;
  h += `<div class="card stat"><div class="sv">${sm.ram_free_bytes?F.bytes(sm.ram_free_bytes):'-'}</div><div class="sl">RAM Free</div><div class="ss">${sm.pressure_source||'?'}</div></div>`;
  h += `<div class="card stat"><div class="sv ${swapUsed&&swapUsed>0?'yellow':'green'}">${swapUsed?F.bytes(swapUsed):'0 B'}</div><div class="sl">Swap Used</div></div>`;
  h += `<div class="card stat"><div class="sv ${F.sc((gc.effective_gpu_pct||0)/100,0.6,0.3)}">${gc.effective_gpu_pct!==null&&gc.effective_gpu_pct!==undefined?gc.effective_gpu_pct.toFixed(1)+'%':'-'}</div><div class="sl">Effective GPU Share</div></div>`;
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Pressure Signals</h3><div style="margin-top:4px;font-size:11px">';
  const pressureRows = [
    ['CPU Thermal Level', t.cpu_thermal_level ?? 0],
    ['GPU Thermal Level', t.gpu_thermal_level ?? 0],
    ['I/O Thermal Level', t.io_thermal_level ?? 0],
    ['Kernel Memory Pressure Level', t.memory_pressure_level ?? 0],
    ['Pressure Source', sm.pressure_source || '-'],
    ['Memory Free %', smartFree!==null&&smartFree!==undefined ? `${smartFree}%` : '-'],
    ['RAM Used', sm.ram_used_bytes ? F.bytes(sm.ram_used_bytes) : '-'],
    ['Compressed', sm.compressed_bytes ? F.bytes(sm.compressed_bytes) : '-'],
    ['Wired', sm.wired_bytes ? F.bytes(sm.wired_bytes) : '-'],
    ['Purgeable', sm.purgeable_bytes ? F.bytes(sm.purgeable_bytes) : '-'],
  ];
  for (const [label, val] of pressureRows) {
    h += `<div style="padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${val}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Sustained Soak Envelope</h3><div style="margin-top:4px;font-size:11px">';
  const envRows = [
    ['Elapsed', elapsed],
    ['Remaining Minimum', remaining],
    ['Current Cycle', `${p.current_cycle||0} / ${p.required_cycles||20}`],
    ['Parallel Jobs', p.parallel_jobs ?? '-'],
    ['Warm Cycles', cs.warm_count ?? '-'],
    ['Average Duration', cs.warm_avg_ms ? F.ms(cs.warm_avg_ms) : '-'],
    ['Variance', cs.warm_variance_pct!==null&&cs.warm_variance_pct!==undefined ? `${cs.warm_variance_pct.toFixed(2)}%` : '-'],
    ['Baseline Drift', cs.baseline_drift_pct!==null&&cs.baseline_drift_pct!==undefined ? `${cs.baseline_drift_pct>=0?'+':''}${cs.baseline_drift_pct.toFixed(2)}%` : '-'],
    ['GPU Busy Peak', p.strict_gpu_busy_ratio_peak!==null&&p.strict_gpu_busy_ratio_peak!==undefined ? `${(p.strict_gpu_busy_ratio_peak*100).toFixed(1)}%` : '-'],
    ['Doctor Flips / Degraded', `${p.doctor_flips||0} / ${p.degraded_runs||0}`],
  ];
  for (const [label, val] of envRows) {
    h += `<div style="padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${val}</strong></div>`;
  }
  h += '</div></div>';
  h += '</div>';

  // Power advisory for soak
  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Soak Power Advisory</h3><div style="margin-top:4px;font-size:11px">';
  const notes = [];
  if (t.power_source === 'Battery') notes.push('<span class="yellow">Running on battery — thermal throttling more likely. Plug in for reliable soak results.</span>');
  else if (t.power_source === 'AC') notes.push('<span class="green">AC power — good for sustained soak.</span>');
  if (speed < 100) notes.push(`<span class="${speedC}">CPU speed limited to ${speed}% — thermal throttling active. Results may show elevated cycle times.</span>`);
  else notes.push('<span class="green">CPU running at full speed — no throttling detected.</span>');
  if (tw > 0) notes.push(`<span class="red">Thermal warning level ${tw} active — system may be reducing performance.</span>`);
  // Use the smarter memory pressure from system_memory (memory_pressure -Q) instead of raw kernel level
  const smartPressure = sm.pressure_level || 'normal';
  const smartUtil = sm.utilization_pct;
  const smartSource = sm.pressure_source || 'unknown';
  const smartFreePct = smartFree;
  if (smartPressure !== 'normal') {
    const spC = smartPressure==='elevated'?'yellow':smartPressure==='high'?'orange':'red';
    notes.push(`<span class="${spC}">Memory pressure: ${smartPressure.toUpperCase()} (${smartUtil}% utilized, source: ${smartSource})</span>`);
  } else if (smartFreePct !== null && smartFreePct !== undefined) {
    notes.push(`<span class="green">Memory healthy — ${smartFreePct}% free (via memory_pressure -Q, same signal as runtime)</span>`);
  }
  if ((rel.timeout_count||0) > 0 || (rel.dispatch_circuit_trips||0) > 0) {
    notes.push(`<span class="yellow">Reliability counters: ${rel.timeout_count||0} timeout(s), ${rel.dispatch_circuit_trips||0} dispatch trip(s).</span>`);
  }
  if (!notes.length) notes.push('<span class="green">All thermal conditions nominal.</span>');
  h += notes.join('<br>');
  h += '</div></div>';

  h += '<div class="card"><h3>Thermal / Resource Diagnosis</h3><div style="margin-top:4px;font-size:11px">';
  const diag = [];
  diag.push(`<span class="${pressC}">Thermal envelope: ${(t.thermal_pressure||'nominal').toUpperCase()}</span>`);
  diag.push(`<span class="${smartPC}">Memory envelope: ${smartP.toUpperCase()}</span>`);
  diag.push(`<span class="${speedC}">CPU speed limit: ${speed}%</span>`);
  diag.push(`<span class="${hs.overall_status==='healthy'?'green':hs.overall_status==='watch'?'yellow':'red'}">Overall health view: ${(hs.overall_status||'watch').toUpperCase()}</span>`);
  if (gc.effective_gpu_pct!==null&&gc.effective_gpu_pct!==undefined) {
    diag.push(`<span class="${gc.effective_gpu_pct>80?'green':'yellow'}">Observed GPU stage share: ${gc.effective_gpu_pct.toFixed(1)}%</span>`);
  }
  if (swapUsed && swapUsed > 0) {
    diag.push(`<span class="yellow">Swap is in use: ${F.bytes(swapUsed)}</span>`);
  }
  h += diag.join('<br>');
  h += '</div></div>';
  h += '</div>';

  document.getElementById('tab-thermal').innerHTML = h;
}

function renderHealth(d) {
  const doc = d.doctors?.length>0 ? d.doctors[d.doctors.length-1].doctor : d.preflight;
  const rt = doc?.runtime||{};
  const pre = d.preflight||{};
  const rel = d.reliability||{};
  const p = d.progress||{};
  const hs = d.health||{};
  const integ = d.soak_integrity||{};
  const trust = (d.latest_artifact||{}).trust_summary||{};
  const overall = hs.overall_status||'watch';
  const overallC = overall==='healthy'?'green':overall==='watch'?'yellow':'red';
  const certState = hs.strict_certification_present ? (hs.strict_certification_match ? 'MATCHED' : 'STALE') : (p.phase==='running' ? 'SOAKING' : 'MISSING');
  const certC = certState==='MATCHED'?'green':certState==='SOAKING'?'yellow':'red';
  const runtimeC = pre.production_ready ? 'green' : (hs.dispatch_circuit_open ? 'red' : 'yellow');
  const relFaults = (hs.proof_failures||0)+(hs.verifier_failures||0)+(hs.export_failures||0)+(hs.timeout_count||0)+(hs.panic_count||0)+(hs.dispatch_circuit_trips||0);
  const relC = relFaults===0 && (p.degraded_runs||0)===0 ? 'green' : relFaults<3 ? 'yellow' : 'red';
  const memC = hs.memory_status==='normal'?'green':hs.memory_status==='elevated'?'yellow':hs.memory_status==='high'?'orange':'red';
  const thermC = hs.thermal_status==='nominal'?'green':hs.thermal_status==='elevated'?'yellow':hs.thermal_status==='high'?'orange':'red';

  let h = '<div class="grid g6">';
  h += `<div class="card stat"><div class="sv ${overallC}">${overall.toUpperCase()}</div><div class="sl">Overall Health</div></div>`;
  h += `<div class="card stat"><div class="sv ${runtimeC}">${pre.production_ready?'READY':'WATCH'}</div><div class="sl">Runtime Status</div></div>`;
  h += `<div class="card stat"><div class="sv ${certC}">${certState}</div><div class="sl">Certification</div></div>`;
  h += `<div class="card stat"><div class="sv ${relC}">${relFaults}</div><div class="sl">Major Faults</div></div>`;
  h += `<div class="card stat"><div class="sv ${thermC}">${(hs.thermal_status||'nominal').toUpperCase()}</div><div class="sl">Thermal State</div></div>`;
  h += `<div class="card stat"><div class="sv ${memC}">${(hs.memory_status||'normal').toUpperCase()}</div><div class="sl">Memory State</div></div>`;
  h += '</div>';

  let metalH = '';
  const checks = [
    ['Metal Available', rt.metal_available, true],
    ['Metal Compiled', rt.metal_compiled, true],
    ['Dispatch Circuit Closed', !rt.metal_dispatch_circuit_open, true],
    ['Not Disabled by Env', !rt.metal_disabled_by_env, true],
    ['Strict BN254 Ready', !!pre.strict_bn254_ready, true],
    ['Strict Auto Route', !!pre.strict_bn254_auto_route, true],
  ];
  for (const [l,v,e] of checks) {
    const ok = v===e;
    metalH += `<div class="hi"><span class="hd ${ok?'ok':'bad'}"></span>${l}</div>`;
  }
  const infos = [
    ['Device', rt.metal_device],['Mode', rt.metallib_mode],['Thresholds', rt.threshold_profile],
    ['Pipelines', rt.prewarmed_pipelines],['Primary Q', rt.metal_primary_queue_depth],
    ['Secondary Q', rt.metal_secondary_queue_depth],['Max Inflight', rt.metal_pipeline_max_in_flight],
    ['Max Jobs', rt.metal_scheduler_max_jobs],['Headroom Target', rt.metal_working_set_headroom_target_pct!==undefined?rt.metal_working_set_headroom_target_pct+'%':'?'],
    ['Strict GPU Coverage', pre.strict_gpu_stage_coverage ?? '?'],
  ];
  for (const [l,v] of infos) metalH += `<div class="hi"><span class="hd ok"></span>${l}: <strong>${v??'?'}</strong></div>`;

  let accelH = '';
  for (const [slot, name] of Object.entries(rt.active_accelerators||{}))
    accelH += `<div class="hi"><span class="hd ok"></span><strong>${slot}</strong>: ${name}</div>`;
  if (!accelH) accelH = '<span style="color:var(--dim);font-size:10px">No active accelerators reported</span>';

  let diffH = '';
  if (!d.doctors?.length) diffH = '<span style="color:var(--dim);font-size:10px">No doctor snapshots yet</span>';
  else {
    const first = d.doctors[0].doctor.runtime||{};
    const last = d.doctors[d.doctors.length-1].doctor.runtime||{};
    diffH = `<div style="font-size:11px;margin-top:4px">${d.doctors.length} snapshot(s). `;
    if (first.metal_dispatch_circuit_open !== last.metal_dispatch_circuit_open) diffH += '<span class="red">Dispatch circuit changed!</span> ';
    else diffH += '<span class="green">Dispatch circuit stable.</span> ';
    const wF = first.working_set_utilization_pct, wL = last.working_set_utilization_pct;
    if (wF!==undefined && wL!==undefined) {
      const delta = wL-wF;
      const dC = Math.abs(delta)<0.01?'green':'yellow';
      diffH += `Working set: ${wF.toFixed(4)}% -> ${wL.toFixed(4)}% (<span class="${dC}">${delta>=0?'+':''}${delta.toFixed(4)}%</span>)`;
    }
    diffH += '</div>';
  }

  h += '<div class="grid g2" style="margin-top:8px">';
  h += `<div class="card"><h3>Strict Runtime Health</h3><div class="hg" style="margin-top:4px">${metalH}</div></div>`;
  h += `<div class="card"><h3>Accelerators</h3><div class="hg" style="margin-top:4px">${accelH}</div></div>`;
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Certification / Soak State</h3><div style="margin-top:4px;font-size:11px">';
  const certRows = [
    ['Production Ready', pre.production_ready ? 'YES' : 'NO'],
    ['Strict Cert Present', hs.strict_certification_present ? 'YES' : 'NO'],
    ['Strict Cert Match', hs.strict_certification_match ? 'YES' : 'NO'],
    ['Cert Report', hs.strict_certification_report || '-'],
    ['Current Cycle', `${p.current_cycle||0} / ${p.required_cycles||20}`],
    ['Remaining Minimum', p.remaining_duration_ms ? fmtUptime(Math.floor(p.remaining_duration_ms/1000)) : '-'],
    ['Artifact Status', hs.artifact_status || '-'],
    ['Trust Model', trust.trust_model || '-'],
    ['Support Class', trust.support_class || '-'],
  ];
  for (const [label, val] of certRows) {
    const short = typeof val === 'string' && val.length > 64 ? '...' + val.slice(-59) : val;
    h += `<div style="padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${short}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Reliability Counters</h3><div style="margin-top:4px;font-size:11px">';
  const relRows = [
    ['Proof Failures', rel.proof_failures],
    ['Verifier Failures', rel.verifier_failures],
    ['Export Failures', rel.export_failures],
    ['Timeouts', rel.timeout_count],
    ['Panics', rel.panic_count],
    ['Kernel Faults', rel.metal_kernel_faults],
    ['Dispatch Circuit Trips', rel.dispatch_circuit_trips],
    ['Doctor Flips', rel.doctor_flips],
    ['Degraded Runs', rel.degraded_runs],
    ['Fallback Events', rel.fallback_events],
    ['Warm Cycles', rel.total_warm_cycles],
    ['Parallel Cycles', rel.total_parallel_cycles],
  ];
  for (const [label, val] of relRows) {
    const cls = Number(val) === 0 ? 'green' : Number(val) > 0 ? 'yellow' : 'accent';
    h += `<div style="padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong class="${cls}">${val ?? '-'}</strong></div>`;
  }
  h += '</div></div>';
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += `<div class="card"><h3>Doctor Snapshots Across Cycles</h3>${diffH}<div style="margin-top:6px;font-size:11px">`;
  const integRows = [
    ['Result Digest Stable', integ.result_digest_stable ? 'YES' : 'NO'],
    ['Doctor Snapshot Stable', integ.doctor_snapshot_stable ? 'YES' : 'NO'],
    ['Artifact Schema Stable', integ.artifact_schema_stable ? 'YES' : 'NO'],
    ['Backend Config Stable', integ.backend_config_stable ? 'YES' : 'NO'],
    ['Trust Lane Stable', integ.trust_lane_stable ? 'YES' : 'NO'],
  ];
  for (const [label, val] of integRows) {
    const cls = val === 'YES' ? 'green' : 'yellow';
    h += `<div style="padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong class="${cls}">${val}</strong></div>`;
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Current Resource Health</h3><div style="margin-top:4px;font-size:11px">';
  const resourceRows = [
    ['Power Source', hs.power_source || '-'],
    ['CPU Speed Limit', hs.cpu_speed_limit!==undefined ? `${hs.cpu_speed_limit}%` : '-'],
    ['Thermal Status', hs.thermal_status || '-'],
    ['Memory Status', hs.memory_status || '-'],
    ['GPU Effective Share', hs.gpu_effective_pct!==null&&hs.gpu_effective_pct!==undefined ? `${hs.gpu_effective_pct.toFixed(1)}%` : '-'],
    ['GPU Peak Busy', hs.gpu_peak_busy!==null&&hs.gpu_peak_busy!==undefined ? `${(hs.gpu_peak_busy*100).toFixed(1)}%` : '-'],
    ['Warm Variance', hs.warm_variance_pct!==null&&hs.warm_variance_pct!==undefined ? `${hs.warm_variance_pct.toFixed(2)}%` : '-'],
    ['Baseline Drift', hs.baseline_drift_pct!==null&&hs.baseline_drift_pct!==undefined ? `${hs.baseline_drift_pct>=0?'+':''}${hs.baseline_drift_pct.toFixed(2)}%` : '-'],
  ];
  for (const [label, val] of resourceRows) {
    h += `<div style="padding:2px 0"><span style="color:var(--dim)">${label}:</span> <strong>${val}</strong></div>`;
  }
  h += '</div></div>';
  h += '</div>';

  h += '<div class="grid g2" style="margin-top:8px">';
  h += '<div class="card"><h3>Current Issues</h3><div style="margin-top:4px;font-size:11px">';
  if ((hs.issues||[]).length) {
    for (const issue of hs.issues) h += `<div style="padding:2px 0;color:var(--yellow)">${issue}</div>`;
  } else {
    h += '<div class="green">No active health issues detected.</div>';
  }
  h += '</div></div>';

  h += '<div class="card"><h3>Green Signals</h3><div style="margin-top:4px;font-size:11px">';
  if ((hs.positives||[]).length) {
    for (const item of hs.positives) h += `<div style="padding:2px 0;color:var(--green)">${item}</div>`;
  } else {
    h += '<div style="color:var(--dim)">No positive signals recorded yet.</div>';
  }
  h += '</div></div>';
  h += '</div>';

  document.getElementById('tab-health').innerHTML = h;
}

function renderCycles(d) {
  const outcomes = d.cycle_outcomes||[];
  if (!outcomes.length) { document.getElementById('tab-cycles').innerHTML='<div class="card"><span style="color:var(--dim)">No cycle outcomes yet</span></div>'; return; }
  let h = '<div class="card"><h3>Per-Cycle Outcomes</h3><div style="margin-top:6px">';
  h += '<div class="cycle-row" style="font-weight:600;color:var(--dim);background:transparent"><div class="cycle-num">#</div><div class="cycle-badge">Verdict</div><div style="flex:0 0 80px">Status</div><div class="cycle-dur">Duration</div><div class="cycle-gpu">GPU</div><div class="cycle-digest">Proof Hash | Program Digest</div></div>';
  for (const o of outcomes) {
    h += `<div class="cycle-row">`;
    h += `<div class="cycle-num">${o.cycle}</div>`;
    h += `<div class="cycle-badge">${F.badge(o.verdict)}</div>`;
    h += `<div style="flex:0 0 80px;font-size:10px">${o.status}</div>`;
    h += `<div class="cycle-dur">${o.duration_ms?F.ms(o.duration_ms):'-'}</div>`;
    h += `<div class="cycle-gpu">${(o.gpu_busy*100).toFixed(0)}%</div>`;
    h += `<div class="cycle-digest">${o.proof_hash||'?'} | ${o.program_digest||'?'}</div>`;
    h += '</div>';
  }
  h += '</div></div>';
  document.getElementById('tab-cycles').innerHTML = h;
}

function renderTimeline(d) {
  let events = [];
  const started = d.progress.soak_started_at_unix_ms;
  if (started) events.push({t:started, text:'Soak started', cls:'ok'});
  if (d.cold?.runtime_trace?.stage_duration_ms) {
    const dur = (d.cold.runtime_trace.stage_duration_ms/1000).toFixed(1);
    events.push({t:started+30000, text:`Cold run completed (${dur}s)`, cls:'ok'});
  }
  for (const c of d.warm_cycles||[]) {
    const dur = c.runtime_trace?.stage_duration_ms ? (c.runtime_trace.stage_duration_ms/1000).toFixed(1)+'s' : '?';
    const gpu = c.runtime_trace ? ((c.runtime_trace.gpu_stage_busy_ratio||0)*100).toFixed(0)+'%' : '';
    const circuit = c.runtime_trace?.metal_dispatch_circuit_open;
    const cls = circuit ? 'warn' : 'ok';
    events.push({t:(c.mtime||0)*1000, text:`Warm cycle ${c.cycle} (${dur}, ${gpu} GPU)`, cls});
  }
  for (const c of d.parallel_cycles||[]) events.push({t:0, text:`Parallel cycle ${c.cycle}: ${c.jobs.length} job(s)`, cls:'ok'});
  if (d.progress.doctor_flips>0) events.push({t:0, text:`${d.progress.doctor_flips} doctor flip(s)`, cls:'error'});
  if (d.progress.degraded_runs>0) events.push({t:0, text:`${d.progress.degraded_runs} degraded run(s)`, cls:'warn'});
  // Resume event
  const resumed = d.progress.resumed_from_cycle;
  if (resumed) events.push({t:d.progress.updated_at_unix_ms||0, text:`Resumed from cycle ${resumed}`, cls:'warn'});

  events.sort((a,b)=>a.t-b.t);
  let h = '<div class="card"><div class="tl">';
  for (const ev of events) {
    const time = ev.t>0?F.dt(ev.t):'';
    h += `<div class="tl-ev ${ev.cls}"><div>${ev.text}</div><div class="tl-time">${time}</div></div>`;
  }
  h += '</div></div>';

  // Live wrap logs (best signal during long child steps)
  const logs = d.active_logs||{};
  const activeLabel = d.progress.active_label||'';
  const subphase = d.progress.subphase||'';
  if (activeLabel || logs.stdout_tail || logs.stderr_tail) {
    h += '<div class="card" style="margin-top:8px"><h3>Live Wrap Output';
    if (activeLabel) h += ` &mdash; ${activeLabel}`;
    if (subphase) h += ` <span style="color:var(--dim)">(${subphase})</span>`;
    h += '</h3>';
    // Log file listing
    if (logs.log_files?.length) {
      h += '<div style="margin-top:4px;font-size:10px;color:var(--dim)">';
      for (const lf of logs.log_files) {
        h += `${lf.path} (${F.bytes(lf.size)}, ${F.tm(lf.mtime*1000)}) `;
      }
      h += '</div>';
    }
    if (logs.stdout_tail) {
      h += `<div style="margin-top:6px"><div style="font-size:10px;color:var(--green);margin-bottom:2px">stdout <span style="color:var(--dim)">${logs.stdout_path||''} (${F.bytes(logs.stdout_size||0)})</span></div>`;
      h += `<pre style="font-size:10px;background:var(--surface2);padding:6px;border-radius:4px;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-all">${escHtml(logs.stdout_tail)}</pre></div>`;
    }
    if (logs.stderr_tail) {
      h += `<div style="margin-top:6px"><div style="font-size:10px;color:var(--orange);margin-bottom:2px">stderr <span style="color:var(--dim)">${logs.stderr_path||''} (${F.bytes(logs.stderr_size||0)})</span></div>`;
      h += `<pre style="font-size:10px;background:var(--surface2);padding:6px;border-radius:4px;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:var(--orange)">${escHtml(logs.stderr_tail)}</pre></div>`;
    }
    if (!logs.stdout_tail && !logs.stderr_tail) {
      h += '<div style="font-size:11px;color:var(--dim);margin-top:4px">No wrap logs found yet for this step. They appear once the child process starts writing.</div>';
    }
    h += '</div>';
  }

  document.getElementById('tab-timeline').innerHTML = h || '<div class="card"><span style="color:var(--dim)">No events yet</span></div>';
}

function renderFiles(d) {
  let h = '<div class="card"><table class="ftable"><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th></tr></thead><tbody>';
  for (const f of d.files||[]) {
    const icon = f.is_dir ? '&#128193;' : (f.name.endsWith('.json')?'&#128196;':'&#128462;');
    h += `<tr><td>${icon} ${f.name}</td><td>${f.is_dir?'dir':'file'}</td><td>${f.is_dir?'-':F.bytes(f.size)}</td><td>${F.tm(f.mtime*1000)}</td></tr>`;
  }
  h += '</tbody></table></div>';
  document.getElementById('tab-files').innerHTML = h;
}

function safeRender(tabId, fn, d) {
  try {
    fn(d);
  } catch (e) {
    console.error(`render ${tabId}:`, e);
    const el = document.getElementById(tabId);
    if (el) {
      el.innerHTML = `<div class="card"><h3>Render Error</h3><div style="margin-top:6px;font-size:11px;color:var(--yellow)">This tab failed to render: ${escHtml(String(e && e.message ? e.message : e))}</div></div>`;
    }
  }
}

function render(d) {
  D = d;
  renderTop(d);
  renderIntegrityStrip(d);
  safeRender('tab-system', renderSystem, d);
  safeRender('tab-activity', renderActivity, d);
  safeRender('tab-perf', renderPerf, d);
  safeRender('tab-mem', renderMem, d);
  safeRender('tab-gpu', renderGpu, d);
  safeRender('tab-ane', renderAne, d);
  safeRender('tab-umpg', renderUmpg, d);
  safeRender('tab-crypto', renderCrypto, d);
  safeRender('tab-matrix', renderMatrix, d);
  safeRender('tab-stages', renderStages, d);
  safeRender('tab-trust', renderTrust, d);
  safeRender('tab-reliability', renderReliability, d);
  safeRender('tab-thermal', renderThermal, d);
  safeRender('tab-health', renderHealth, d);
  safeRender('tab-cycles', renderCycles, d);
  safeRender('tab-timeline', renderTimeline, d);
  safeRender('tab-files', renderFiles, d);
  document.getElementById('last-update').textContent = 'Updated ' + new Date().toLocaleTimeString();
}

async function poll() {
  try { const r = await fetch('/api/data'); render(await r.json()); }
  catch(e) { console.error('poll:', e); }
}
poll();
setInterval(poll, 5000);
setInterval(() => { if (D) renderTop(D); }, 1000);
</script>
</body>
</html>
"""


class SoakHandler(BaseHTTPRequestHandler):
    soak_dir: Path = Path(DEFAULT_DIR)

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/api/data":
            data = collect_soak_data(self.soak_dir)
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = DASHBOARD_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="ZirOS Production Soak Monitor v2")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--dir", type=str, default=DEFAULT_DIR)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    SoakHandler.soak_dir = Path(args.dir)
    if not SoakHandler.soak_dir.is_dir():
        print(f"note: soak directory not found ({args.dir}), running in system-only mode")

    server = HTTPServer(("127.0.0.1", args.port), SoakHandler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"ZirOS System Dashboard running at {url}")
    print(f"Soak dir: {args.dir}")
    print("Press Ctrl+C to stop.\n")

    if not args.no_browser:
        webbrowser.open(url)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
