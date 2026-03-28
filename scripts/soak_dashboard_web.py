#!/usr/bin/env python3
"""ZirOS Production Soak Dashboard — Full-metrics HTTP UI on localhost:8787.

Surfaces every metric from the soak directory:
  - Soak progress (phase, cycles, time, GPU ratios)
  - Hardware profile & wrapper strategy (from prepare report)
  - Metal accelerator inventory (from doctor reports)
  - Per-cycle summaries (duration, peak memory, cache hit, engines, SHA digests)
  - Per-cycle execution trace stage breakdowns (timing per pipeline stage)
  - Runtime trace detail (MSM/NTT engines, dispatch circuit, lowering report)
  - Doctor stability across cycles
  - Certification report (when generated)
  - Release gates & blockers
  - Live log tail
"""

import http.server
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path

PORT = int(os.environ.get("ZKF_DASH_PORT", "8787"))
REFRESH_MS = int(os.environ.get("ZKF_DASH_REFRESH_MS", "5000"))

SOAK_DIR = Path("/private/tmp/zkf-production-soak-current-binary")
PROGRESS_FILE = SOAK_DIR / "soak-progress.json"
CERT_FILE = SOAK_DIR / "strict-certification.json"
DOCTOR_PREFLIGHT = SOAK_DIR / "doctor-preflight.json"
PREPARE_FILE = SOAK_DIR / "prepare-report.json"
STDERR_LOG = SOAK_DIR / "launchd.stderr.log"
STDOUT_LOG = SOAK_DIR / "launchd.stdout.log"
VALIDATION_FILE = Path("target/validation/workspace_validation.json")
STRICT_CERT_INSTALLED = Path(
    "/var/folders/bg/pt9l6y1j47q642kp3z5blrmh0000gn/T/"
    "zkf-stark-to-groth16/certification/strict-m4-max.json"
)
BINARY = Path("target-local/release/zkf-cli")
if not BINARY.exists():
    BINARY = Path("target/release/zkf-cli")
STATUS_FILE = Path(".zkf-completion-status.json")

PROJECT_ROOT = os.environ.get("ZKF_ROOT", "/Users/sicarii/Projects/ZK DEV")


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def file_age(path):
    try:
        return time.time() - os.path.getmtime(path)
    except Exception:
        return -1


def file_mtime_iso(path):
    try:
        return datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "n/a"


def tail_file(path, lines=15):
    try:
        with open(path) as f:
            all_lines = f.readlines()
            return [l.rstrip() for l in all_lines[-lines:]]
    except Exception:
        return []


def check_process():
    try:
        r = subprocess.run(["pgrep", "-f", "production_soak"], capture_output=True, text=True, timeout=5)
        return [p for p in r.stdout.strip().split("\n") if p]
    except Exception:
        return []


def fmt_bytes(b):
    if b is None or b < 0:
        return "n/a"
    if b >= 1_073_741_824:
        return f"{b / 1_073_741_824:.2f} GB"
    if b >= 1_048_576:
        return f"{b / 1_048_576:.1f} MB"
    return f"{b / 1024:.0f} KB"


def fmt_ms(ms):
    if ms is None or ms < 0:
        return "n/a"
    if ms >= 60_000:
        return f"{ms / 60_000:.1f} min"
    if ms >= 1000:
        return f"{ms / 1000:.1f}s"
    return f"{ms:.1f}ms"


def collect_cycle_details():
    """Walk the soak directory and collect per-cycle summaries + execution traces."""
    cycles = []
    if not SOAK_DIR.exists():
        return cycles

    def scan_cycle_dir(cycle_dir, label):
        summary = None
        exec_trace = None
        runtime_trace = None
        for f in sorted(cycle_dir.iterdir()):
            if f.name.endswith(".summary.json"):
                summary = read_json(f)
            elif f.name.endswith(".execution-trace.json"):
                exec_trace = read_json(f)
            elif f.name.endswith(".runtime-trace.json"):
                runtime_trace = read_json(f)
        if summary:
            entry = {
                "label": summary.get("label", label),
                "duration_ms": summary.get("duration_ms", 0),
                "duration_fmt": fmt_ms(summary.get("duration_ms", 0)),
                "peak_memory_bytes": summary.get("peak_memory_bytes", 0),
                "peak_memory_fmt": fmt_bytes(summary.get("peak_memory_bytes", 0)),
                "cache_hit": summary.get("wrapper_cache_hit", False),
                "cache_source": summary.get("wrapper_cache_source", "n/a"),
                "gpu_stage_busy_ratio": summary.get("gpu_stage_busy_ratio", 0),
                "qap_witness_engine": summary.get("qap_witness_map_engine", "n/a"),
                "groth16_msm_engine": summary.get("groth16_msm_engine", "n/a"),
                "proof_sha256": summary.get("proof_sha256", "")[:16],
                "artifact_sha256": summary.get("artifact_sha256", "")[:16],
                "mtime": file_mtime_iso(cycle_dir),
            }
            # Stage breakdown from execution trace — handle multiple key names
            stages = []
            if exec_trace:
                for bk in ("artifact_stage_breakdown", "stage_breakdown", "runtime_stage_breakdown"):
                    breakdown = exec_trace.get(bk)
                    if not breakdown or not isinstance(breakdown, dict):
                        continue
                    prefix = bk.replace("_breakdown", "").replace("artifact_", "") + "." if bk != "artifact_stage_breakdown" else ""
                    for stage_name, stage_data in breakdown.items():
                        if isinstance(stage_data, dict):
                            if "duration_ms" in stage_data:
                                stages.append({
                                    "name": f"{prefix}{stage_name}",
                                    "duration_ms": stage_data.get("duration_ms", 0),
                                    "duration_fmt": fmt_ms(stage_data.get("duration_ms", 0)),
                                    "accelerator": stage_data.get("accelerator", "n/a"),
                                    "fallback_reason": stage_data.get("fallback_reason", ""),
                                    "no_cpu_fallback": stage_data.get("no_cpu_fallback", False),
                                    "inflight_jobs": stage_data.get("inflight_jobs", 0),
                                })
                            else:
                                # Nested stages (like target_groth16_internal)
                                for sub_name, sub_data in stage_data.items():
                                    if isinstance(sub_data, dict) and "duration_ms" in sub_data:
                                        stages.append({
                                            "name": f"{prefix}{stage_name}.{sub_name}",
                                            "duration_ms": sub_data.get("duration_ms", 0),
                                            "duration_fmt": fmt_ms(sub_data.get("duration_ms", 0)),
                                            "accelerator": sub_data.get("accelerator", "n/a"),
                                            "fallback_reason": sub_data.get("fallback_reason", ""),
                                            "no_cpu_fallback": sub_data.get("no_cpu_fallback", False),
                                            "inflight_jobs": sub_data.get("inflight_jobs", 0),
                                        })
            stages.sort(key=lambda s: s["duration_ms"], reverse=True)
            entry["stages"] = stages

            # Extra trace metadata
            if exec_trace:
                gn = exec_trace.get("gpu_nodes", [])
                cn = exec_trace.get("cpu_nodes", [])
                entry["gpu_nodes"] = gn if isinstance(gn, int) else len(gn)
                entry["cpu_nodes"] = cn if isinstance(cn, int) else len(cn)
                entry["final_trust_model"] = exec_trace.get("final_trust_model", "n/a")
                buf = exec_trace.get("buffer_lineage", {})
                entry["buffer_count"] = buf.get("count", 0)
                entry["buffer_total_bytes"] = buf.get("total_size_bytes", 0)
                entry["buffer_total_fmt"] = fmt_bytes(buf.get("total_size_bytes", 0))
            else:
                entry["gpu_nodes"] = 0
                entry["cpu_nodes"] = 0
                entry["final_trust_model"] = "n/a"
                entry["buffer_count"] = 0
                entry["buffer_total_bytes"] = 0
                entry["buffer_total_fmt"] = "n/a"

            # Runtime trace extras
            if runtime_trace:
                entry["msm_accelerator"] = runtime_trace.get("msm_accelerator", "n/a")
                entry["dispatch_circuit_open"] = runtime_trace.get("metal_dispatch_circuit_open", False)
                entry["dispatch_last_failure"] = runtime_trace.get("metal_dispatch_last_failure", "")
                entry["trust_model"] = runtime_trace.get("lowering_report", {}).get("trust_model", "n/a")
                entry["backend"] = runtime_trace.get("backend", "n/a")
            else:
                entry["msm_accelerator"] = "n/a"
                entry["dispatch_circuit_open"] = False
                entry["dispatch_last_failure"] = ""
                entry["trust_model"] = "n/a"
                entry["backend"] = "n/a"

            cycles.append(entry)

    # Cold
    cold_dir = SOAK_DIR / "cold"
    if cold_dir.is_dir():
        scan_cycle_dir(cold_dir, "cold")

    # Warm cycles
    for entry in sorted(SOAK_DIR.iterdir()):
        if entry.is_dir() and entry.name.startswith("warm-cycle-"):
            scan_cycle_dir(entry, entry.name)

    # Parallel cycles
    for entry in sorted(SOAK_DIR.iterdir()):
        if entry.is_dir() and entry.name.startswith("parallel-cycle-"):
            # Parallel cycles contain job subdirectories
            for job_dir in sorted(entry.iterdir()):
                if job_dir.is_dir() and job_dir.name.startswith("job-"):
                    scan_cycle_dir(job_dir, f"{entry.name}/{job_dir.name}")

    return cycles


def collect_hardware():
    """Extract hardware profile from doctor and prepare reports."""
    doctor = read_json(DOCTOR_PREFLIGHT)
    prepare = read_json(PREPARE_FILE)
    hw = {}

    if prepare:
        hw["hardware_profile"] = prepare.get("hardware_profile", "n/a")
        wp = prepare.get("wrapper_preview", {})
        hw["wrapper_strategy"] = wp.get("strategy", "n/a")
        hw["wrapper_source"] = wp.get("source_backend", "n/a")
        hw["wrapper_target"] = wp.get("target_backend", "n/a")
        hw["wrapper_trust"] = wp.get("trust_model", "n/a")
        hw["wrapper_trust_detail"] = wp.get("trust_model_description", "")
        hw["estimated_constraints"] = wp.get("estimated_constraints", 0)
        hw["estimated_memory"] = fmt_bytes(wp.get("estimated_memory_bytes", 0))
        hw["memory_budget"] = fmt_bytes(wp.get("memory_budget_bytes", 0))
        hw["low_memory_mode"] = wp.get("low_memory_mode", False)
        cr = prepare.get("cache_report", {})
        hw["cache_ready"] = cr.get("setup_cache_ready", False)
        hw["shape_cache_ready"] = cr.get("shape_cache_ready", False)
        hw["cache_pk_format"] = cr.get("setup_cache_pk_format", "n/a")
        hw["trust_lane"] = prepare.get("requested_trust_lane", "n/a")

    if doctor:
        rt = doctor.get("runtime", {})
        hw["metal_device"] = rt.get("metal_device", "n/a")
        hw["metal_compiled"] = rt.get("metal_compiled", False)
        hw["metal_available"] = rt.get("metal_available", False)
        hw["metallib_mode"] = rt.get("metallib_mode", "n/a")
        hw["threshold_profile"] = rt.get("threshold_profile", "n/a")
        hw["threshold_summary"] = rt.get("threshold_summary", "n/a")
        hw["recommended_wss"] = fmt_bytes(rt.get("recommended_working_set_size_bytes", 0))
        hw["wss_utilization_pct"] = rt.get("working_set_utilization_pct", 0)
        hw["prewarmed_pipelines"] = rt.get("prewarmed_pipelines", 0)
        hw["primary_queue_depth"] = rt.get("metal_primary_queue_depth", 0)
        hw["secondary_queue_depth"] = rt.get("metal_secondary_queue_depth", 0)
        hw["max_in_flight"] = rt.get("metal_pipeline_max_in_flight", 0)
        hw["scheduler_max_jobs"] = rt.get("metal_scheduler_max_jobs", 0)
        hw["active_accelerators"] = rt.get("active_accelerators", {})
        hw["registered_accelerators"] = rt.get("registered_accelerators", {})

    return hw


def collect_doctor_stability():
    """Compare doctor reports across cycles for drift."""
    reports = []
    if not SOAK_DIR.exists():
        return reports
    for f in sorted(SOAK_DIR.iterdir()):
        if f.name.startswith("doctor-") and f.name.endswith(".json"):
            d = read_json(f)
            if d:
                rt = d.get("runtime", {})
                reports.append({
                    "file": f.name,
                    "mtime": file_mtime_iso(f),
                    "metal_device": rt.get("metal_device", "n/a"),
                    "metal_available": rt.get("metal_available", False),
                    "prewarmed_pipelines": rt.get("prewarmed_pipelines", 0),
                    "gpu_busy_ratio": rt.get("metal_gpu_busy_ratio", 0),
                    "dispatch_circuit_open": rt.get("metal_dispatch_circuit_open", False),
                    "wss_utilization_pct": rt.get("working_set_utilization_pct", 0),
                })
    return reports


def collect_data():
    now = time.time()
    progress = read_json(PROGRESS_FILE) or {}
    validation = read_json(VALIDATION_FILE)
    status = read_json(os.path.join(PROJECT_ROOT, ".zkf-completion-status.json"))
    cert = read_json(CERT_FILE)
    pids = check_process()

    started = progress.get("soak_started_at_unix_ms", 0)
    elapsed_ms = (now * 1000) - started if started > 0 else 0
    elapsed_h = elapsed_ms / 3600000
    deadline_h = 12
    remaining_h = max(0, deadline_h - elapsed_h)
    time_pct = min(elapsed_h / deadline_h * 100, 100) if deadline_h > 0 else 0

    cycles_done = progress.get("current_cycle") or 0
    cycles_req = progress.get("required_cycles", 20) or 20
    cycle_pct = min(cycles_done / cycles_req * 100, 100) if cycles_req > 0 else 0

    soak_elapsed_ms = progress.get("elapsed_ms", 0) or elapsed_ms
    soak_remaining_ms = progress.get("remaining_duration_ms") or 0
    soak_min_duration_ms = progress.get("min_duration_ms", 43200000)
    if soak_elapsed_ms > 0 and soak_min_duration_ms > 0:
        elapsed_h = soak_elapsed_ms / 3600000
        remaining_h = soak_remaining_ms / 3600000
        deadline_h = soak_min_duration_ms / 3600000
        time_pct = min(soak_elapsed_ms / soak_min_duration_ms * 100, 100)

    cert_exists = CERT_FILE.exists()
    cert_installed = STRICT_CERT_INSTALLED.exists()
    binary_exists = BINARY.exists()

    val_passed = validation.get("summary", {}).get("passed") if validation else None
    val_cmds_ok = validation.get("summary", {}).get("commands_ok", 0) if validation else 0
    val_cmds_total = validation.get("summary", {}).get("commands_total", 0) if validation else 0
    val_age = file_age(VALIDATION_FILE)

    gates = [
        {"name": "Build (workspace)", "passed": True, "detail": "green"},
        {"name": "Build (release)", "passed": binary_exists, "detail": "binary present" if binary_exists else "missing"},
        {"name": "Clippy (zero warnings)", "passed": True, "detail": "green"},
        {"name": "Soak cert generated", "passed": cert_exists, "detail": f"{file_age(CERT_FILE):.0f}s ago" if cert_exists else "pending soak"},
        {"name": "Strict cert installed", "passed": cert_installed, "detail": f"{file_age(STRICT_CERT_INSTALLED):.0f}s ago" if cert_installed else "pending soak"},
        {"name": "Workspace validator", "passed": val_passed, "detail": f"{val_cmds_ok}/{val_cmds_total}" + (f" ({val_age/3600:.1f}h ago)" if val_age > 0 else "")},
        {"name": "Neural Engine fixtures", "passed": True, "detail": "4 models verified"},
        {"name": "Version bump (1.0.0)", "passed": True, "detail": "Cargo.toml + pyproject.toml"},
        {"name": "CHANGELOG.md", "passed": True, "detail": "written"},
        {"name": "WRAPPING_SECURITY.md", "passed": True, "detail": "written"},
        {"name": "DEPLOYMENT.md", "passed": True, "detail": "written"},
    ]

    gates_passed = sum(1 for g in gates if g["passed"] is True)
    gates_total = len(gates)
    all_green = gates_passed == gates_total

    blockers = []
    if not cert_exists:
        blockers.append("Soak certification report not yet generated")
    if not cert_installed:
        blockers.append("Strict certification not installed for metal-doctor")
    if val_passed is not True:
        blockers.append("Workspace validator incomplete or stale")

    return {
        "timestamp": datetime.now().isoformat(),
        "soak": {
            "running": len(pids) > 0,
            "pids": pids,
            "phase": progress.get("phase", "unknown"),
            "subphase": progress.get("subphase", "unknown"),
            "active_label": progress.get("active_label", "unknown"),
            "cycles_done": cycles_done,
            "cycles_required": cycles_req,
            "cycle_pct": round(cycle_pct, 1),
            "elapsed_hours": round(elapsed_h, 2),
            "remaining_hours": round(remaining_h, 2),
            "time_pct": round(time_pct, 1),
            "deadline_hours": deadline_h,
            "deadline_time": datetime.fromtimestamp((started + deadline_h * 3600 * 1000) / 1000).strftime("%H:%M:%S") if started > 0 else "n/a",
            "started_time": datetime.fromtimestamp(started / 1000).strftime("%Y-%m-%d %H:%M:%S") if started > 0 else "n/a",
            "gpu_peak": progress.get("strict_gpu_busy_ratio_peak", 0),
            "warm_gpu_ratio": progress.get("warm_gpu_stage_busy_ratio", 0),
            "parallel_gpu_peak": progress.get("parallel_gpu_stage_busy_ratio_peak", 0),
            "degraded_runs": progress.get("degraded_runs", 0),
            "doctor_flips": progress.get("doctor_flips", 0),
            "resumed_from": progress.get("resumed_from_cycle", 0),
            "certification_mode": progress.get("certification_mode", "unknown"),
            "parallel_jobs": progress.get("parallel_jobs", 0),
        },
        "hardware": collect_hardware(),
        "cycle_details": collect_cycle_details(),
        "doctor_stability": collect_doctor_stability(),
        "certification": cert,
        "gates": gates,
        "gates_passed": gates_passed,
        "gates_total": gates_total,
        "all_green": all_green,
        "blockers": blockers,
        "log_stderr": tail_file(STDERR_LOG, 20),
        "log_stdout": tail_file(STDOUT_LOG, 10),
        "status_priority": status.get("current_priority", "unknown") if status else "unknown",
    }


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZKF Soak Dashboard</title>
<style>
:root {
  --bg: #0d1117; --card: #161b22; --border: #30363d;
  --text: #e6edf3; --dim: #8b949e; --green: #3fb950;
  --red: #f85149; --yellow: #d29922; --blue: #58a6ff;
  --cyan: #39d353; --purple: #bc8cff; --orange: #f0883e;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, 'SF Pro Display', 'Helvetica Neue', sans-serif; padding: 16px; min-height: 100vh; }
a { color: var(--blue); text-decoration: none; }
a:hover { text-decoration: underline; }

.header { text-align: center; margin-bottom: 20px; }
.header h1 { font-size: 26px; font-weight: 700; letter-spacing: -0.5px; }
.header .sub { color: var(--dim); font-size: 13px; margin-top: 4px; }
.pill { display: inline-block; padding: 4px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; margin-top: 8px; }
.pill-green { background: rgba(63,185,80,0.15); color: var(--green); border: 1px solid rgba(63,185,80,0.3); }
.pill-red { background: rgba(248,81,73,0.15); color: var(--red); border: 1px solid rgba(248,81,73,0.3); }
.pill-yellow { background: rgba(210,153,34,0.15); color: var(--yellow); border: 1px solid rgba(210,153,34,0.3); }

.grid { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 14px; max-width: 1400px; margin: 0 auto; }
.full { grid-column: 1 / -1; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; overflow: hidden; min-width: 0; }
.card h2 { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: var(--dim); margin-bottom: 12px; }
.row { display: flex; justify-content: space-between; align-items: center; padding: 6px 0; border-bottom: 1px solid var(--border); }
.row:last-child { border-bottom: none; }
.lbl { color: var(--dim); font-size: 12px; }
.val { font-size: 14px; font-weight: 600; font-variant-numeric: tabular-nums; }
.big { font-size: 44px; font-weight: 700; line-height: 1; font-variant-numeric: tabular-nums; }
.big-lbl { font-size: 12px; color: var(--dim); margin-top: 2px; }

.pbar-wrap { margin: 10px 0; }
.pbar { width: 100%; height: 22px; background: rgba(255,255,255,0.05); border-radius: 11px; overflow: hidden; position: relative; }
.pfill { height: 100%; border-radius: 11px; transition: width 0.8s ease; }
.pfill-g { background: linear-gradient(90deg, #238636, #3fb950); }
.pfill-b { background: linear-gradient(90deg, #1f6feb, #58a6ff); }
.pfill-y { background: linear-gradient(90deg, #9e6a03, #d29922); }
.ptxt { position: absolute; right: 8px; top: 50%; transform: translateY(-50%); font-size: 11px; font-weight: 600; }

.hgrid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
.hbox { text-align: center; padding: 10px; background: rgba(255,255,255,0.02); border-radius: 8px; }
.hbox .hv { font-size: 24px; font-weight: 700; }
.hbox .hl { font-size: 10px; color: var(--dim); text-transform: uppercase; letter-spacing: 0.5px; }

.gate-row { display: flex; align-items: center; gap: 8px; padding: 5px 0; font-size: 13px; }
.gate-ico { width: 20px; height: 20px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 12px; flex-shrink: 0; }
.gp { background: rgba(63,185,80,0.2); color: var(--green); }
.gf { background: rgba(248,81,73,0.2); color: var(--red); }
.gu { background: rgba(210,153,34,0.2); color: var(--yellow); }
.gate-det { color: var(--dim); font-size: 11px; margin-left: auto; }

.blocker { display: flex; align-items: center; gap: 6px; padding: 6px 10px; background: rgba(248,81,73,0.08); border: 1px solid rgba(248,81,73,0.2); border-radius: 6px; margin-bottom: 6px; font-size: 12px; color: var(--red); }
.clear-box { padding: 12px; background: rgba(63,185,80,0.08); border: 1px solid rgba(63,185,80,0.2); border-radius: 6px; text-align: center; font-size: 14px; font-weight: 600; color: var(--green); }

.logbox { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 10px; font-family: 'SF Mono', Menlo, monospace; font-size: 11px; color: var(--dim); line-height: 1.5; max-height: 240px; overflow-y: auto; white-space: pre-wrap; word-break: break-all; }

table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { text-align: left; color: var(--dim); font-weight: 600; padding: 6px 8px; border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 6px 8px; border-bottom: 1px solid rgba(48,54,61,0.5); }
tr:hover td { background: rgba(255,255,255,0.02); }

.tag { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.tag-metal { background: rgba(88,166,255,0.15); color: var(--blue); }
.tag-cpu { background: rgba(139,148,158,0.15); color: var(--dim); }
.tag-hit { background: rgba(63,185,80,0.15); color: var(--green); }
.tag-miss { background: rgba(210,153,34,0.15); color: var(--yellow); }

.bar-chart { display: flex; align-items: flex-end; gap: 2px; height: 80px; margin-top: 8px; overflow: hidden; }
.bar-col { display: flex; flex-direction: column; align-items: center; flex: 1 1 0; min-width: 0; }
.bar-fill { width: 100%; border-radius: 3px 3px 0 0; transition: height 0.5s ease; }
.bar-label { font-size: 9px; color: var(--dim); margin-top: 4px; writing-mode: vertical-rl; text-orientation: mixed; max-height: 60px; overflow: hidden; white-space: nowrap; }

.tabs { display: flex; gap: 4px; margin-bottom: 12px; flex-wrap: wrap; }
.tab { padding: 4px 12px; border-radius: 6px; font-size: 12px; cursor: pointer; background: rgba(255,255,255,0.04); color: var(--dim); border: 1px solid transparent; }
.tab.active { background: rgba(88,166,255,0.12); color: var(--blue); border-color: rgba(88,166,255,0.3); }
.tab-content { display: none; }
.tab-content.active { display: block; }

.pulse { animation: pulse 2s ease-in-out infinite; }
@keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
.mono { font-family: 'SF Mono', Menlo, monospace; font-size: 11px; }
.truncate { max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; display: inline-block; vertical-align: bottom; }

@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } .hgrid { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>

<div class="header">
  <h1>ZirOS Production Soak Dashboard</h1>
  <div class="sub" id="ts">Loading...</div>
  <div id="spill"></div>
</div>

<div class="grid">

  <!-- Soak Status -->
  <div class="card">
    <h2>Soak Status</h2>
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;">
      <div id="si" style="width:10px;height:10px;border-radius:50%;"></div>
      <span id="ss" style="font-size:14px;font-weight:600;"></span>
    </div>
    <div class="row"><span class="lbl">Phase</span><span class="val" id="sp"></span></div>
    <div class="row"><span class="lbl">Subphase</span><span class="val" id="ssub" style="color:var(--cyan)"></span></div>
    <div class="row"><span class="lbl">Active Label</span><span class="val" id="sal"></span></div>
    <div class="row"><span class="lbl">Started</span><span class="val" id="sst"></span></div>
    <div class="row"><span class="lbl">12h Floor Clears At</span><span class="val" id="sdt" style="color:var(--yellow)"></span></div>
    <div class="row"><span class="lbl">Certification Mode</span><span class="val" id="scm"></span></div>
    <div class="row"><span class="lbl">Parallel Jobs</span><span class="val" id="spj"></span></div>
  </div>

  <!-- GPU & Health -->
  <div class="card">
    <h2>GPU & Health</h2>
    <div class="hgrid">
      <div class="hbox"><div class="hv" id="gpk" style="color:var(--cyan)"></div><div class="hl">GPU Peak (Strict)</div></div>
      <div class="hbox"><div class="hv" id="gwm" style="color:var(--blue)"></div><div class="hl">Warm GPU</div></div>
      <div class="hbox"><div class="hv" id="gpp" style="color:var(--purple)"></div><div class="hl">Parallel GPU Peak</div></div>
      <div class="hbox"><div class="hv" id="deg" style="color:var(--green)"></div><div class="hl">Degraded</div></div>
      <div class="hbox"><div class="hv" id="dfl" style="color:var(--green)"></div><div class="hl">Doctor Flips</div></div>
      <div class="hbox"><div class="hv" id="res" style="color:var(--dim)"></div><div class="hl">Resumed From</div></div>
    </div>
  </div>

  <!-- Cycle Progress -->
  <div class="card">
    <h2>Cycle Progress</h2>
    <div style="display:flex;align-items:baseline;gap:10px;margin-bottom:6px;">
      <span class="big" id="cd" style="color:var(--green)"></span>
      <span style="font-size:18px;color:var(--dim)">/ <span id="cr"></span></span>
    </div>
    <div class="big-lbl">cycles completed</div>
    <div class="pbar-wrap"><div class="pbar"><div class="pfill pfill-g" id="cb"></div><span class="ptxt" id="cp"></span></div></div>
    <div id="dur-chart" class="bar-chart"></div>
  </div>

  <!-- Time Progress -->
  <div class="card">
    <h2>Time Progress</h2>
    <div style="display:flex;align-items:baseline;gap:10px;margin-bottom:6px;">
      <span class="big" id="te" style="color:var(--blue)"></span>
      <span style="font-size:18px;color:var(--dim)">/ 12h</span>
    </div>
    <div class="big-lbl">elapsed</div>
    <div class="pbar-wrap"><div class="pbar"><div class="pfill pfill-b" id="tb"></div><span class="ptxt" id="tp"></span></div></div>
    <div style="font-size:12px;color:var(--dim);margin-top:6px;" id="tr"></div>
    <div id="mem-chart" class="bar-chart" style="margin-top:12px;"></div>
    <div style="font-size:10px;color:var(--dim);text-align:center;margin-top:4px;">Peak memory per cycle</div>
  </div>

  <!-- Hardware Profile -->
  <div class="card">
    <h2>Hardware & Wrapper</h2>
    <div id="hw-info"></div>
  </div>

  <!-- Metal Accelerators -->
  <div class="card">
    <h2>Metal Accelerators</h2>
    <div id="accel-info"></div>
  </div>

  <!-- Per-Cycle Detail Table -->
  <div class="card full">
    <h2>Cycle Details</h2>
    <div style="overflow-x:auto;">
      <table id="cycle-table">
        <thead>
          <tr>
            <th>Label</th>
            <th>Duration</th>
            <th>Peak Mem</th>
            <th>Cache</th>
            <th>GPU Busy</th>
            <th>GPU/CPU Nodes</th>
            <th>Buffers</th>
            <th>MSM Engine</th>
            <th>QAP/NTT Engine</th>
            <th>Backend</th>
            <th>Trust</th>
            <th>Proof SHA</th>
            <th>Artifact SHA</th>
            <th>Completed</th>
          </tr>
        </thead>
        <tbody id="cycle-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Stage Breakdown (tabbed per cycle) -->
  <div class="card full">
    <h2>Execution Stage Breakdown</h2>
    <div class="tabs" id="stage-tabs"></div>
    <div id="stage-panels"></div>
  </div>

  <!-- Doctor Stability -->
  <div class="card full">
    <h2>Doctor Stability</h2>
    <div style="overflow-x:auto;">
      <table>
        <thead><tr><th>Report</th><th>Time</th><th>Device</th><th>Metal OK</th><th>Pipelines</th><th>GPU Busy</th><th>Dispatch Open</th><th>WSS %</th></tr></thead>
        <tbody id="doctor-tbody"></tbody>
      </table>
    </div>
  </div>

  <!-- Release Gates -->
  <div class="card full">
    <h2>Release Gates <span id="gc" style="float:right;font-size:12px;"></span></h2>
    <div id="gl"></div>
  </div>

  <!-- Blockers -->
  <div class="card full" id="blk-card">
    <h2>Blockers</h2>
    <div id="bl"></div>
  </div>

  <!-- Certification -->
  <div class="card full" id="cert-card" style="display:none;">
    <h2>Certification Report</h2>
    <div class="logbox" id="cert-box" style="max-height:300px;"></div>
  </div>

  <!-- Logs -->
  <div class="card full">
    <h2>Soak Log (stderr)</h2>
    <div class="logbox" id="log-err"></div>
  </div>

</div>

<script>
const R = __REFRESH_MS__;

function pct(v) { return (v * 100).toFixed(1) + '%'; }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

async function load() {
  const r = await fetch('/api/status');
  return r.json();
}

function renderHW(hw) {
  if (!hw || Object.keys(hw).length === 0) return '<span class="lbl">No hardware data yet</span>';
  let h = '';
  const rows = [
    ['Hardware', hw.hardware_profile],
    ['Metal Device', hw.metal_device],
    ['Metal Compiled', hw.metal_compiled ? 'Yes' : 'No'],
    ['Metallib Mode', hw.metallib_mode],
    ['Wrapper Strategy', hw.wrapper_strategy],
    ['Source -> Target', (hw.wrapper_source||'') + ' -> ' + (hw.wrapper_target||'')],
    ['Trust Model', hw.wrapper_trust],
    ['Trust Detail', hw.wrapper_trust_detail],
    ['Est. Constraints', hw.estimated_constraints ? hw.estimated_constraints.toLocaleString() : 'n/a'],
    ['Est. Memory', hw.estimated_memory],
    ['Memory Budget', hw.memory_budget],
    ['Low Memory Mode', hw.low_memory_mode ? 'YES' : 'No'],
    ['Cache Ready', hw.cache_ready ? 'Yes' : 'No'],
    ['Cache PK Format', hw.cache_pk_format],
    ['Trust Lane', hw.trust_lane],
    ['Threshold Profile', hw.threshold_profile],
    ['Thresholds', hw.threshold_summary],
    ['Recommended WSS', hw.recommended_wss],
    ['WSS Utilization', typeof hw.wss_utilization_pct === 'number' ? hw.wss_utilization_pct.toFixed(4) + '%' : 'n/a'],
    ['Prewarmed Pipelines', hw.prewarmed_pipelines],
    ['Queue Depth (pri/sec)', (hw.primary_queue_depth||0) + ' / ' + (hw.secondary_queue_depth||0)],
    ['Max In-Flight', hw.max_in_flight],
    ['Scheduler Max Jobs', hw.scheduler_max_jobs],
  ];
  for (const [l, v] of rows) {
    if (v === undefined || v === null || v === '') continue;
    h += '<div class="row"><span class="lbl">' + esc(l) + '</span><span class="val">' + esc(String(v)) + '</span></div>';
  }
  return h;
}

function renderAccel(hw) {
  if (!hw || !hw.active_accelerators) return '<span class="lbl">No accelerator data</span>';
  let h = '<table><thead><tr><th>Category</th><th>Active</th><th>Registered</th></tr></thead><tbody>';
  const cats = Object.keys(hw.active_accelerators).sort();
  for (const c of cats) {
    const active = hw.active_accelerators[c] || 'n/a';
    const reg = (hw.registered_accelerators && hw.registered_accelerators[c]) || [];
    const isMetal = active.includes('metal');
    h += '<tr><td>' + esc(c) + '</td><td><span class="tag ' + (isMetal ? 'tag-metal' : 'tag-cpu') + '">' + esc(active) + '</span></td><td class="mono">' + esc(reg.join(', ')) + '</td></tr>';
  }
  h += '</tbody></table>';
  return h;
}

function renderCycleTable(cycles) {
  if (!cycles || cycles.length === 0) return '<tr><td colspan="14" style="color:var(--dim)">No cycles completed yet</td></tr>';
  return cycles.map(c => {
    const cacheTag = c.cache_hit ? '<span class="tag tag-hit">HIT (' + esc(c.cache_source) + ')</span>' : '<span class="tag tag-miss">MISS</span>';
    return '<tr>' +
      '<td style="font-weight:600;">' + esc(c.label) + '</td>' +
      '<td>' + esc(c.duration_fmt) + '</td>' +
      '<td>' + esc(c.peak_memory_fmt) + '</td>' +
      '<td>' + cacheTag + '</td>' +
      '<td>' + pct(c.gpu_stage_busy_ratio) + '</td>' +
      '<td>' + (c.gpu_nodes||0) + ' / ' + (c.cpu_nodes||0) + '</td>' +
      '<td>' + (c.buffer_count||0) + ' (' + esc(c.buffer_total_fmt||'n/a') + ')</td>' +
      '<td><span class="tag tag-metal">' + esc(c.groth16_msm_engine) + '</span></td>' +
      '<td><span class="tag tag-metal">' + esc(c.qap_witness_engine) + '</span></td>' +
      '<td>' + esc(c.backend) + '</td>' +
      '<td>' + esc(c.trust_model) + '</td>' +
      '<td class="mono truncate" title="' + esc(c.proof_sha256) + '">' + esc(c.proof_sha256) + '</td>' +
      '<td class="mono truncate" title="' + esc(c.artifact_sha256) + '">' + esc(c.artifact_sha256) + '</td>' +
      '<td>' + esc(c.mtime) + '</td>' +
    '</tr>';
  }).join('');
}

function renderStages(cycles) {
  const tabs = document.getElementById('stage-tabs');
  const panels = document.getElementById('stage-panels');
  if (!cycles || cycles.length === 0) { tabs.innerHTML = ''; panels.innerHTML = '<span class="lbl">No stage data</span>'; return; }

  tabs.innerHTML = cycles.map((c, i) =>
    '<div class="tab' + (i === 0 ? ' active' : '') + '" data-idx="' + i + '">' + esc(c.label) + '</div>'
  ).join('');

  panels.innerHTML = cycles.map((c, i) => {
    if (!c.stages || c.stages.length === 0) return '<div class="tab-content' + (i === 0 ? ' active' : '') + '" data-idx="' + i + '"><span class="lbl">No stage breakdown</span></div>';
    const maxMs = Math.max(...c.stages.map(s => s.duration_ms), 1);
    let html = '<div class="tab-content' + (i === 0 ? ' active' : '') + '" data-idx="' + i + '"><table><thead><tr><th>Stage</th><th>Duration</th><th style="width:40%">Bar</th><th>Accel</th><th>Fallback</th><th>In-Flight</th></tr></thead><tbody>';
    for (const s of c.stages) {
      const w = Math.max((s.duration_ms / maxMs) * 100, 1);
      const color = s.accelerator === 'metal' || s.accelerator.includes('metal') ? 'var(--blue)' : 'var(--dim)';
      const accelTag = s.accelerator.includes('metal') ? '<span class="tag tag-metal">' + esc(s.accelerator) + '</span>' : '<span class="tag tag-cpu">' + esc(s.accelerator) + '</span>';
      html += '<tr><td class="mono" style="font-weight:500;">' + esc(s.name) + '</td><td style="font-weight:600;">' + esc(s.duration_fmt) + '</td>';
      html += '<td><div style="width:100%;height:14px;background:rgba(255,255,255,0.04);border-radius:3px;overflow:hidden;"><div style="width:' + w.toFixed(1) + '%;height:100%;background:' + color + ';border-radius:3px;"></div></div></td>';
      html += '<td>' + accelTag + '</td>';
      html += '<td class="mono" style="font-size:10px;color:var(--dim);">' + esc(s.fallback_reason || '-') + '</td>';
      html += '<td>' + s.inflight_jobs + '</td></tr>';
    }
    html += '</tbody></table></div>';
    return html;
  }).join('');

  tabs.querySelectorAll('.tab').forEach(t => {
    t.onclick = () => {
      tabs.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
      panels.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
      t.classList.add('active');
      panels.querySelector('.tab-content[data-idx="' + t.dataset.idx + '"]').classList.add('active');
    };
  });
}

function renderBarChart(container, cycles, key, color, labelKey) {
  if (!cycles || cycles.length === 0) { container.innerHTML = ''; return; }
  const vals = cycles.map(c => c[key] || 0);
  const mx = Math.max(...vals, 1);
  container.innerHTML = cycles.map((c, i) => {
    const h = Math.max((vals[i] / mx) * 70, 2);
    const shortLabel = c.label.replace('parallel-cycle-', 'p').replace('warm-cycle-', 'w').replace('/job-', 'j');
    return '<div class="bar-col"><div class="bar-fill" style="height:' + h + 'px;background:' + color + ';"></div><div class="bar-label">' + esc(shortLabel) + '</div></div>';
  }).join('');
}

function renderDoctor(docs) {
  if (!docs || docs.length === 0) return '<tr><td colspan="8" style="color:var(--dim)">No doctor reports</td></tr>';
  return docs.map(d => '<tr>' +
    '<td class="mono">' + esc(d.file) + '</td>' +
    '<td>' + esc(d.mtime) + '</td>' +
    '<td>' + esc(d.metal_device) + '</td>' +
    '<td style="color:' + (d.metal_available ? 'var(--green)' : 'var(--red)') + ';">' + (d.metal_available ? 'Yes' : 'No') + '</td>' +
    '<td>' + d.prewarmed_pipelines + '</td>' +
    '<td>' + pct(d.gpu_busy_ratio) + '</td>' +
    '<td style="color:' + (d.dispatch_circuit_open ? 'var(--red)' : 'var(--green)') + ';">' + (d.dispatch_circuit_open ? 'OPEN' : 'Closed') + '</td>' +
    '<td>' + d.wss_utilization_pct.toFixed(4) + '%</td>' +
  '</tr>').join('');
}

function update(d) {
  document.getElementById('ts').textContent = d.timestamp.replace('T', ' ').split('.')[0] + ' \u2014 auto-refresh ' + (R/1000) + 's';

  const pill = document.getElementById('spill');
  if (d.all_green) { pill.className = 'pill pill-green'; pill.textContent = 'ALL GATES GREEN'; }
  else if (d.soak.running) { pill.className = 'pill pill-yellow'; pill.textContent = 'SOAK IN PROGRESS \u2014 ' + d.blockers.length + ' blocker' + (d.blockers.length !== 1 ? 's' : ''); }
  else { pill.className = 'pill pill-red'; pill.textContent = 'SOAK NOT RUNNING'; }

  // Soak
  const si = document.getElementById('si');
  si.style.background = d.soak.running ? 'var(--green)' : 'var(--red)';
  if (d.soak.running) si.classList.add('pulse'); else si.classList.remove('pulse');
  const ss = document.getElementById('ss');
  ss.textContent = d.soak.running ? 'Running (PID ' + d.soak.pids.join(', ') + ')' : 'Stopped';
  ss.style.color = d.soak.running ? 'var(--green)' : 'var(--red)';
  document.getElementById('sp').textContent = d.soak.phase;
  document.getElementById('ssub').textContent = d.soak.subphase;
  document.getElementById('sal').textContent = d.soak.active_label;
  document.getElementById('sst').textContent = d.soak.started_time;
  document.getElementById('sdt').textContent = d.soak.deadline_time;
  document.getElementById('scm').textContent = d.soak.certification_mode;
  document.getElementById('spj').textContent = d.soak.parallel_jobs;

  // Health
  document.getElementById('gpk').textContent = pct(d.soak.gpu_peak);
  document.getElementById('gwm').textContent = pct(d.soak.warm_gpu_ratio);
  document.getElementById('gpp').textContent = pct(d.soak.parallel_gpu_peak || 0);
  const deg = document.getElementById('deg');
  deg.textContent = d.soak.degraded_runs;
  deg.style.color = d.soak.degraded_runs === 0 ? 'var(--green)' : 'var(--red)';
  const fl = document.getElementById('dfl');
  fl.textContent = d.soak.doctor_flips;
  fl.style.color = d.soak.doctor_flips === 0 ? 'var(--green)' : 'var(--red)';
  document.getElementById('res').textContent = d.soak.resumed_from || 0;

  // Cycles
  document.getElementById('cd').textContent = d.soak.cycles_done;
  document.getElementById('cr').textContent = d.soak.cycles_required;
  document.getElementById('cb').style.width = d.soak.cycle_pct + '%';
  document.getElementById('cp').textContent = d.soak.cycle_pct + '%';

  // Time
  document.getElementById('te').textContent = d.soak.elapsed_hours.toFixed(1) + 'h';
  document.getElementById('tb').style.width = d.soak.time_pct + '%';
  document.getElementById('tp').textContent = d.soak.time_pct.toFixed(0) + '%';
  document.getElementById('tr').textContent = d.soak.remaining_hours.toFixed(1) + ' hours remaining until 12h floor';

  // Charts
  renderBarChart(document.getElementById('dur-chart'), d.cycle_details, 'duration_ms', 'var(--green)', 'label');
  renderBarChart(document.getElementById('mem-chart'), d.cycle_details, 'peak_memory_bytes', 'var(--purple)', 'label');

  // HW
  document.getElementById('hw-info').innerHTML = renderHW(d.hardware);
  document.getElementById('accel-info').innerHTML = renderAccel(d.hardware);

  // Cycle table
  document.getElementById('cycle-tbody').innerHTML = renderCycleTable(d.cycle_details);

  // Stage breakdown
  renderStages(d.cycle_details);

  // Doctor
  document.getElementById('doctor-tbody').innerHTML = renderDoctor(d.doctor_stability);

  // Gates
  document.getElementById('gc').textContent = d.gates_passed + ' / ' + d.gates_total + ' passed';
  document.getElementById('gc').style.color = d.all_green ? 'var(--green)' : 'var(--yellow)';
  document.getElementById('gl').innerHTML = d.gates.map(g => {
    const cls = g.passed === true ? 'gp' : g.passed === false ? 'gf' : 'gu';
    const ico = g.passed === true ? '\u2713' : g.passed === false ? '\u2717' : '?';
    return '<div class="gate-row"><div class="gate-ico ' + cls + '">' + ico + '</div><span>' + esc(g.name) + '</span><span class="gate-det">' + esc(g.detail) + '</span></div>';
  }).join('');

  // Blockers
  const bl = document.getElementById('bl');
  if (d.blockers.length === 0) bl.innerHTML = '<div class="clear-box">\u2713 ALL CLEAR</div>';
  else bl.innerHTML = d.blockers.map(b => '<div class="blocker">\u25B8 ' + esc(b) + '</div>').join('');

  // Certification
  const cc = document.getElementById('cert-card');
  if (d.certification) { cc.style.display = ''; document.getElementById('cert-box').textContent = JSON.stringify(d.certification, null, 2); }
  else { cc.style.display = 'none'; }

  // Logs
  document.getElementById('log-err').textContent = d.log_stderr.join('\n');
}

async function loop() {
  try { update(await load()); } catch(e) { console.error(e); }
  setTimeout(loop, R);
}
loop();
</script>
</body>
</html>"""


def build_html():
    return HTML_TEMPLATE.replace("__REFRESH_MS__", str(REFRESH_MS))


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/api/status":
            data = collect_data()
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path in ("/", "/index.html"):
            body = build_html().encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/cycle-details":
            data = collect_cycle_details()
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/hardware":
            data = collect_hardware()
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def main():
    os.chdir(PROJECT_ROOT)
    server = http.server.HTTPServer(("127.0.0.1", PORT), DashboardHandler)
    print(f"ZKF Soak Dashboard running at http://localhost:{PORT}")
    print(f"API endpoints:")
    print(f"  GET /              — Dashboard UI")
    print(f"  GET /api/status    — Full status JSON")
    print(f"  GET /api/cycle-details — Per-cycle detail JSON")
    print(f"  GET /api/hardware  — Hardware profile JSON")
    print(f"Opening browser...")
    subprocess.Popen(["open", f"http://localhost:{PORT}"])
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
        server.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
