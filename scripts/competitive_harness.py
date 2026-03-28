#!/usr/bin/env python3
"""Run the cross-ecosystem competition gate for ZKF and external toolchains."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import competition_bootstrap as bootstrap


SCHEMA = "zkf-competitive-harness-v2"
GATE_SCHEMA = "zkf-competition-gate-v1"
DEFAULT_OUT = ROOT / "assistant" / "competitive_harness.json"
DEFAULT_GATE_OUT = ROOT / "assistant" / "competition_gate.json"
DEFAULT_MANIFEST = ROOT / "benchmarks" / "manifest.json"
DEFAULT_TOOLCHAIN_MANIFEST = ROOT / "assistant" / "toolchain_manifest.json"
BENCHMARK_BACKENDS = {"arkworks-groth16", "halo2", "plonky3"}
WRAP_FIXTURES = {
    "proof": ROOT / "proof-plonky3.json",
    "compiled": ROOT / "compiled-plonky3.json",
}
SCENARIO_STATUSES = {"ok", "failed", "skipped", "unsupported"}


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            text=True,
            capture_output=True,
            timeout=timeout,
            env=env,
            check=False,
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(argv, 127, stdout="", stderr=str(exc))
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(
            argv,
            124,
            stdout=exc.stdout or "",
            stderr=(exc.stderr or "") + "\ncommand timed out",
        )


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def locate_binary() -> Path | None:
    candidates = [
        ROOT / "bin" / "zkf-cli",
        ROOT / "target" / "release" / "zkf-cli",
        ROOT / "target" / "debug" / "zkf-cli",
    ]
    existing = [candidate for candidate in candidates if candidate.exists()]
    if not existing:
        return None
    return max(existing, key=lambda candidate: candidate.stat().st_mtime)


def zkf_command_prefix() -> tuple[list[str], str]:
    binary = locate_binary()
    if binary:
        return [str(binary)], str(binary)
    if shutil.which("cargo"):
        return ["cargo", "run", "-q", "-p", "zkf-cli", "--"], "cargo-run"
    raise RuntimeError("neither a built zkf-cli binary nor cargo is available")


def load_config(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    payload = read_json(path)
    return payload if isinstance(payload, dict) else {}


def load_manifest(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError("competition manifest must be a JSON object")
    if payload.get("schema") != "zkf-competition-manifest-v1":
        raise RuntimeError("competition manifest schema mismatch")
    return payload


def run_capabilities(prefix: list[str]) -> list[dict[str, Any]]:
    proc = run(prefix + ["capabilities"], cwd=ROOT, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "zkf capabilities failed")
    payload = json.loads(proc.stdout)
    if not isinstance(payload, list):
        raise RuntimeError("zkf capabilities did not return a JSON list")
    return [entry for entry in payload if isinstance(entry, dict)]


def summarize_zkf_capabilities(capabilities: list[dict[str, Any]]) -> dict[str, Any]:
    ready_real = [
        entry["backend"]
        for entry in capabilities
        if entry.get("production_ready") and entry.get("implementation_type") != "delegated"
    ]
    blocked_native = [
        {
            "backend": entry.get("backend"),
            "reason": entry.get("readiness_reason"),
            "action": entry.get("operator_action"),
            "compat_alias": entry.get("explicit_compat_alias"),
        }
        for entry in capabilities
        if entry.get("implementation_type") == "native" and not entry.get("production_ready")
    ]
    return {
        "ready_real_backends": ready_real,
        "blocked_native_backends": blocked_native,
    }


def run_zkf_benchmark(
    prefix: list[str],
    capabilities: list[dict[str, Any]],
    iterations: int,
    workdir: Path,
    requested_backends: list[str] | None,
) -> dict[str, Any]:
    benchmark_capabilities = {
        entry["backend"]: entry
        for entry in capabilities
        if entry.get("backend") in BENCHMARK_BACKENDS
    }
    ready_benchmark_backends = [
        entry["backend"]
        for entry in capabilities
        if entry.get("backend") in BENCHMARK_BACKENDS and entry.get("production_ready")
    ]
    forced_requested_backends: list[str] = []
    selection_mode = "production-ready"
    if requested_backends:
        selected = [
            backend
            for backend in requested_backends
            if backend in benchmark_capabilities
        ]
        if not selected:
            return {
                "status": "skipped",
                "reason": "requested-benchmark-backends-unavailable",
                "action": "pick one or more benchmark-capable backends from the current capabilities report",
            }
        forced_requested_backends = [
            backend
            for backend in selected
            if not benchmark_capabilities[backend].get("production_ready")
        ]
        ready_benchmark_backends = selected
        selection_mode = "requested-explicit"
    if not ready_benchmark_backends:
        return {
            "status": "skipped",
            "reason": (
                "no-ready-requested-benchmark-backends"
                if requested_backends
                else "no-ready-benchmark-backends"
            ),
            "action": (
                "pick one or more production-ready benchmark backends from the current capabilities report"
                if requested_backends
                else "build or install a binary with at least one production-ready benchmark backend"
            ),
        }

    out_path = workdir / "zkf-benchmark.json"
    cmd = prefix + [
        "benchmark",
        "--out",
        str(out_path),
        "--backends",
        ",".join(sorted(ready_benchmark_backends)),
        "--iterations",
        str(iterations),
        "--skip-large",
        "--continue-on-error",
    ]
    started = time.perf_counter()
    proc = run(cmd, cwd=ROOT, timeout=1800)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if proc.returncode != 0:
        return {
            "status": "failed",
            "elapsed_ms": elapsed_ms,
            "command": cmd,
            "error": proc.stderr.strip() or proc.stdout.strip() or "zkf benchmark failed",
        }

    report = read_json(out_path)
    results = report.get("results") or []
    ok_results = [
        entry for entry in results if isinstance(entry, dict) and (entry.get("status") or {}).get("kind") == "ok"
    ]
    fastest = None
    for entry in ok_results:
        prove_ms = entry.get("prove_ms_mean")
        if isinstance(prove_ms, (int, float)):
            candidate = {
                "backend": entry.get("backend"),
                "case_name": entry.get("case_name"),
                "field": entry.get("field"),
                "prove_ms_mean": prove_ms,
            }
            if fastest is None or prove_ms < fastest["prove_ms_mean"]:
                fastest = candidate
    return {
        "status": "ok",
        "elapsed_ms": elapsed_ms,
        "command": cmd,
        "report_path": str(out_path),
        "requested_backends": requested_backends,
        "forced_requested_backends": forced_requested_backends,
        "selection_mode": selection_mode,
        "selected_backends": sorted(ready_benchmark_backends),
        "result_count": len(results),
        "ok_result_count": len(ok_results),
        "fastest_result": fastest,
    }


def run_zkf_wrap(prefix: list[str], workdir: Path) -> dict[str, Any]:
    missing = [name for name, path in WRAP_FIXTURES.items() if not path.exists()]
    if missing:
        return {
            "status": "skipped",
            "reason": "wrap-fixture-missing",
            "action": f"restore the repo wrap fixtures: {', '.join(missing)}",
        }

    out_path = workdir / "wrapped-proof.json"
    trace_path = workdir / "wrapped.trace.json"
    cmd = prefix + [
        "wrap",
        "--proof",
        str(WRAP_FIXTURES["proof"]),
        "--compiled",
        str(WRAP_FIXTURES["compiled"]),
        "--out",
        str(out_path),
        "--trace-out",
        str(trace_path),
    ]
    started = time.perf_counter()
    proc = run(cmd, cwd=ROOT, timeout=1800)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if proc.returncode != 0:
        error = proc.stderr.strip() or proc.stdout.strip() or "zkf wrap failed"
        reason = None
        action = None
        if "--features metal-gpu" in error:
            reason = "metal-gpu-build-required"
            action = "build zkf-cli with --features metal-gpu to benchmark the strict cryptographic wrap lane"
        return {
            "status": "failed",
            "elapsed_ms": elapsed_ms,
            "command": cmd,
            "reason": reason,
            "action": action,
            "error": error,
        }

    trace = read_json(trace_path)
    return {
        "status": "ok",
        "elapsed_ms": elapsed_ms,
        "command": cmd,
        "output_path": str(out_path),
        "trace_path": str(trace_path),
        "delegated_nodes": trace.get("delegated_nodes"),
        "gpu_nodes": trace.get("gpu_nodes"),
        "cpu_nodes": trace.get("cpu_nodes"),
        "node_count": len(trace.get("node_traces") or []),
    }


def host_profile() -> dict[str, Any]:
    system = platform.system()
    machine = platform.machine()
    return {
        "platform": platform.platform(),
        "system": system,
        "machine": machine,
        "python": platform.python_version(),
        "is_apple_silicon": system == "Darwin" and machine in {"arm64", "aarch64"},
    }


def detect_lane(profile: dict[str, Any], requested: str | None) -> str:
    if requested:
        return requested
    if profile.get("is_apple_silicon"):
        return "apple-silicon"
    return "linux"


def heuristic_ne_advisory(
    *,
    lane: str,
    benchmark_backends: list[str],
    reason: str,
    error: str | None = None,
    command: list[str] | None = None,
) -> dict[str, Any]:
    backend_order = benchmark_backends or ["plonky3"]
    advisory = {
        "available": lane == "apple-silicon",
        "advisory_only": True,
        "policy_source": "heuristic-only",
        "reason": reason,
        "recommended_job_order": ["zkf-self-check", "competitors"],
        "applied_order": ["zkf-self-check", "competitors"],
        "recommended_backend_order": backend_order,
        "applied_backend_order": backend_order,
        "recommended_parallelism": 1,
        "applied_parallelism": 1,
    }
    if error:
        advisory["error"] = error
    if command:
        advisory["command"] = command
    return advisory


def collect_ne_advisory(
    prefix: list[str],
    *,
    lane: str,
    benchmark_backends: list[str],
) -> dict[str, Any]:
    if lane != "apple-silicon":
        return {
            "available": False,
            "advisory_only": True,
            "reason": "lane-not-apple-silicon",
        }
    backends = benchmark_backends or ["plonky3"]
    cmd = prefix + [
        "runtime",
        "policy",
        "--json",
        "--backends",
        ",".join(backends),
        "--requested-jobs",
        "2",
        "--total-jobs",
        "2",
    ]
    proc = run(cmd, cwd=ROOT, timeout=120)
    if proc.returncode != 0:
        return heuristic_ne_advisory(
            lane=lane,
            benchmark_backends=backends,
            reason="runtime-policy-command-failed",
            error=proc.stderr.strip() or proc.stdout.strip() or "runtime policy failed",
            command=cmd,
        )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return heuristic_ne_advisory(
            lane=lane,
            benchmark_backends=backends,
            reason="runtime-policy-json-invalid",
            command=cmd,
        )

    recommend_metal_first = bool(report.get("recommend_metal_first"))
    recommended_job_order = (
        ["zkf-self-check", "competitors"]
        if recommend_metal_first
        else ["competitors", "zkf-self-check"]
    )
    return {
        "available": True,
        "advisory_only": True,
        "policy_source": (
            "runtime-policy-model"
            if report.get("model") is not None
            else "runtime-policy-heuristic"
        ),
        "command": cmd,
        "policy_report": report,
        "recommended_job_order": recommended_job_order,
        "applied_order": recommended_job_order,
        "recommended_backend_order": report.get("backends") or backends,
        "applied_backend_order": report.get("backends") or backends,
        "recommended_parallelism": report.get("recommended_parallel_jobs"),
        "applied_parallelism": 1,
    }


def toolchain_index(toolchain_manifest: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        entry["tool"]: entry
        for entry in toolchain_manifest.get("tools") or []
        if isinstance(entry, dict) and entry.get("tool")
    }


def configured_scenario(
    config: dict[str, Any],
    competitor_id: str,
    scenario_id: str,
) -> dict[str, Any] | None:
    entry = (
        ((config.get("competitors") or {}).get(competitor_id) or {})
        .get("scenarios", {})
        .get(scenario_id)
    )
    return entry if isinstance(entry, dict) else None


def normalize_scenario_payload(
    payload: dict[str, Any],
    *,
    tool: str,
    scenario: str,
) -> dict[str, Any]:
    status = payload.get("status")
    if status not in SCENARIO_STATUSES:
        status = "failed"
        payload = {
            **payload,
            "failure_reason": payload.get("failure_reason") or "invalid-runner-status",
        }
    return {
        "tool": tool,
        "id": scenario,
        "status": status,
        "elapsed_ms": payload.get("elapsed_ms"),
        "tool_version": payload.get("tool_version"),
        "proof_path": payload.get("proof_path"),
        "verify_status": payload.get("verify_status"),
        "reason": payload.get("failure_reason"),
        "action": payload.get("operator_action"),
        "command": payload.get("command"),
        "workdir": payload.get("workdir"),
        "stdout_preview": payload.get("stdout_preview"),
        "stderr_preview": payload.get("stderr_preview"),
        "lane": payload.get("lane"),
        "runner_schema": payload.get("schema"),
    }


def run_configured_scenario(
    config: dict[str, Any],
    competitor_id: str,
    scenario_id: str,
) -> dict[str, Any]:
    scenario = configured_scenario(config, competitor_id, scenario_id)
    if scenario is None:
        return {
            "tool": competitor_id,
            "id": scenario_id,
            "status": "skipped",
            "reason": "scenario-command-not-configured",
            "action": (
                f"add competitors.{competitor_id}.scenarios.{scenario_id}.cmd "
                "to the harness override config JSON"
            ),
        }

    cmd = scenario.get("cmd")
    if not isinstance(cmd, list) or not cmd or not all(isinstance(part, str) for part in cmd):
        return {
            "tool": competitor_id,
            "id": scenario_id,
            "status": "skipped",
            "reason": "invalid-scenario-command",
            "action": "set the scenario cmd to a non-empty JSON string array",
        }

    workdir_raw = scenario.get("workdir")
    workdir = ROOT
    if isinstance(workdir_raw, str) and workdir_raw.strip():
        workdir = Path(workdir_raw).expanduser()
        if not workdir.is_absolute():
            workdir = (ROOT / workdir).resolve()

    timeout = scenario.get("timeout_sec")
    timeout_value = float(timeout) if isinstance(timeout, (int, float)) else 1800.0
    started = time.perf_counter()
    proc = run(cmd, cwd=workdir, timeout=timeout_value)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if proc.returncode != 0:
        return {
            "tool": competitor_id,
            "id": scenario_id,
            "status": "failed",
            "command": cmd,
            "workdir": str(workdir),
            "elapsed_ms": elapsed_ms,
            "reason": "scenario-command-failed",
            "stderr_preview": proc.stderr.strip()[:4000] or None,
            "stdout_preview": proc.stdout.strip()[:4000] or None,
        }

    return {
        "tool": competitor_id,
        "id": scenario_id,
        "status": "ok",
        "command": cmd,
        "workdir": str(workdir),
        "elapsed_ms": elapsed_ms,
        "verify_status": "not-run",
        "stdout_preview": proc.stdout.strip()[:4000] or None,
    }


def execute_runner(
    runner: Path,
    *,
    tool: str,
    scenario: str,
    lane: str,
    workdir: Path,
    toolchain_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    result_path = workdir / tool / f"{scenario}.json"
    result_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(runner), "--out", str(result_path), "--lane", lane]
    env = os.environ.copy()
    path_hints = []
    for entry in toolchain_entries:
        for raw in entry.get("path_hints") or []:
            if isinstance(raw, str) and raw.strip():
                path_hints.append(os.path.expandvars(raw))
    if path_hints:
        env["PATH"] = os.pathsep.join(path_hints + [env.get("PATH", "")])
    proc = run(cmd, cwd=ROOT, timeout=3600, env=env)
    if proc.returncode != 0 and not result_path.exists():
        return {
            "tool": tool,
            "id": scenario,
            "status": "failed",
            "reason": "runner-command-failed",
            "action": f"fix the repo runner at {runner}",
            "command": cmd,
            "stderr_preview": proc.stderr.strip()[:4000] or None,
            "stdout_preview": proc.stdout.strip()[:4000] or None,
        }
    if not result_path.exists():
        return {
            "tool": tool,
            "id": scenario,
            "status": "failed",
            "reason": "runner-did-not-write-report",
            "action": f"fix the repo runner at {runner}",
            "command": cmd,
        }
    payload = read_json(result_path)
    if not isinstance(payload, dict):
        return {
            "tool": tool,
            "id": scenario,
            "status": "failed",
            "reason": "runner-report-invalid",
            "action": f"fix the repo runner at {runner}",
            "command": cmd,
        }
    normalized = normalize_scenario_payload(payload, tool=tool, scenario=scenario)
    normalized["runner"] = str(runner)
    normalized["report_path"] = str(result_path)
    return normalized


def competitor_report(
    manifest: dict[str, Any],
    toolchain_manifest: dict[str, Any],
    config: dict[str, Any],
    *,
    lane: str,
    workdir: Path,
) -> list[dict[str, Any]]:
    tools_by_id = toolchain_index(toolchain_manifest)
    report = []
    for spec in manifest.get("tools") or []:
        if not isinstance(spec, dict):
            continue
        toolchain_ids = [tool_id for tool_id in spec.get("toolchain_ids") or [] if isinstance(tool_id, str)]
        toolchain_entries = [tools_by_id.get(tool_id) for tool_id in toolchain_ids]
        toolchain_entries = [entry for entry in toolchain_entries if entry is not None]
        missing_toolchain = next((entry for entry in toolchain_entries if not entry.get("ready")), None)
        scenarios = []
        for scenario in spec.get("scenarios") or []:
            if not isinstance(scenario, dict) or not scenario.get("id"):
                continue
            scenario_id = scenario["id"]
            if lane not in set(scenario.get("supports_lanes") or []):
                scenarios.append(
                    {
                        "tool": spec["id"],
                        "id": scenario_id,
                        "status": "unsupported",
                        "reason": "lane-unsupported",
                        "action": f"run this scenario on one of: {', '.join(scenario.get('supports_lanes') or [])}",
                    }
                )
                continue
            if missing_toolchain is not None:
                scenarios.append(
                    {
                        "tool": spec["id"],
                        "id": scenario_id,
                        "status": "skipped",
                        "reason": missing_toolchain.get("failure_reason") or "toolchain-not-ready",
                        "action": missing_toolchain.get("operator_action"),
                    }
                )
                continue
            override = configured_scenario(config, spec["id"], scenario_id)
            if override is not None:
                scenarios.append(run_configured_scenario(config, spec["id"], scenario_id))
                continue
            runner = (ROOT / scenario["runner"]).resolve()
            scenarios.append(
                execute_runner(
                    runner,
                    tool=spec["id"],
                    scenario=scenario_id,
                    lane=lane,
                    workdir=workdir,
                    toolchain_entries=toolchain_entries,
                )
            )

        report.append(
            {
                "id": spec["id"],
                "label": spec.get("label") or spec["id"],
                "toolchain_ids": toolchain_ids,
                "toolchains": toolchain_entries,
                "required_toolchains_ready": missing_toolchain is None,
                "scenarios": scenarios,
            }
        )
    return report


def load_or_build_toolchain_manifest(
    *,
    lock_path: Path,
    manifest_path: Path | None,
    manifest_out: Path,
) -> tuple[dict[str, Any], Path]:
    if manifest_path is not None and manifest_path.exists():
        return read_json(manifest_path), manifest_path
    payload = bootstrap.build_toolchain_manifest(
        lock_path=lock_path,
        out_path=manifest_out,
        install_missing=False,
    )
    return payload, manifest_out


def next_actions(
    zkf_summary: dict[str, Any],
    toolchain_manifest: dict[str, Any],
    competitors: list[dict[str, Any]],
) -> list[str]:
    actions = []
    for entry in zkf_summary.get("blocked_native_backends") or []:
        backend = entry.get("backend")
        reason = entry.get("reason") or "blocked"
        action = entry.get("action")
        if backend and action:
            actions.append(f"{backend} is blocked ({reason}); {action}.")

    for tool in toolchain_manifest.get("tools") or []:
        if isinstance(tool, dict) and not tool.get("ready") and tool.get("operator_action"):
            actions.append(f"{tool['tool']} is not ready; {tool['operator_action']}.")

    for competitor in competitors:
        for scenario in competitor.get("scenarios") or []:
            status = scenario.get("status")
            if status in {"failed", "skipped", "unsupported"} and scenario.get("action"):
                actions.append(
                    f"{competitor['label']} {scenario['id']} is {status}; {scenario['action']}."
                )
    return actions


def summarize_report(
    zkf_section: dict[str, Any],
    competitors: list[dict[str, Any]],
    toolchain_manifest: dict[str, Any],
    required_scenarios: list[str],
) -> dict[str, Any]:
    benchmark = zkf_section.get("benchmark") or {}
    wrap = zkf_section.get("wrap") or {}
    competitor_scenarios = [
        scenario
        for competitor in competitors
        for scenario in (competitor.get("scenarios") or [])
        if isinstance(scenario, dict)
    ]
    failed_reasons = []
    for section in (benchmark, wrap):
        reason = section.get("reason") or section.get("error")
        if section.get("status") in {"failed", "skipped"} and reason:
            failed_reasons.append(str(reason))
    for tool in toolchain_manifest.get("tools") or []:
        if isinstance(tool, dict) and not tool.get("ready") and tool.get("failure_reason"):
            failed_reasons.append(str(tool["failure_reason"]))
    for scenario in competitor_scenarios:
        if scenario.get("status") in {"failed", "skipped", "unsupported"}:
            reason = scenario.get("reason") or scenario.get("error")
            if reason:
                failed_reasons.append(str(reason))
    mixed_corpus_complete = True
    for competitor in competitors:
        scenario_map = {
            scenario.get("id"): scenario
            for scenario in competitor.get("scenarios") or []
            if isinstance(scenario, dict)
        }
        for scenario_id in required_scenarios:
            result = scenario_map.get(scenario_id)
            if result is None or result.get("status") != "ok":
                mixed_corpus_complete = False
                break
        if not mixed_corpus_complete:
            break

    required_toolchains_ready = bool((toolchain_manifest.get("summary") or {}).get("required_toolchains_ready"))
    external_evidence_complete = bool(competitor_scenarios) and all(
        scenario.get("status") == "ok" for scenario in competitor_scenarios
    )
    competition_gate_passed = all(
        [
            benchmark.get("status") == "ok",
            wrap.get("status") == "ok",
            required_toolchains_ready,
            mixed_corpus_complete,
            external_evidence_complete,
        ]
    )
    return {
        "zkf_benchmark_status": benchmark.get("status"),
        "zkf_wrap_status": wrap.get("status"),
        "zkf_self_check_passed": benchmark.get("status") == "ok" and wrap.get("status") == "ok",
        "benchmark_backend_selection": benchmark.get("selection_mode"),
        "required_toolchains_ready": required_toolchains_ready,
        "competitor_toolchains_total": len(toolchain_manifest.get("tools") or []),
        "competitor_toolchains_ready": sum(
            1 for entry in toolchain_manifest.get("tools") or [] if isinstance(entry, dict) and entry.get("ready")
        ),
        "competitor_scenarios_total": len(competitor_scenarios),
        "competitor_scenarios_ok": sum(1 for scenario in competitor_scenarios if scenario.get("status") == "ok"),
        "competitor_scenarios_failed": sum(
            1 for scenario in competitor_scenarios if scenario.get("status") == "failed"
        ),
        "competitor_scenarios_skipped": sum(
            1 for scenario in competitor_scenarios if scenario.get("status") == "skipped"
        ),
        "competitor_scenarios_unsupported": sum(
            1 for scenario in competitor_scenarios if scenario.get("status") == "unsupported"
        ),
        "mixed_corpus_complete": mixed_corpus_complete,
        "external_evidence_complete": external_evidence_complete,
        "competition_gate_passed": competition_gate_passed,
        "blocking_reasons": sorted(set(failed_reasons)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the cross-ecosystem competition gate for ZKF.")
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Detailed report JSON path")
    parser.add_argument("--gate-out", default=str(DEFAULT_GATE_OUT), help="Gate summary JSON path")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Competition manifest path")
    parser.add_argument("--toolchain-lock", default=str(bootstrap.DEFAULT_LOCK), help="Toolchain lock path")
    parser.add_argument("--toolchain-manifest", help="Optional existing toolchain manifest JSON path")
    parser.add_argument(
        "--toolchain-manifest-out",
        default=str(DEFAULT_TOOLCHAIN_MANIFEST),
        help="Toolchain manifest output path when bootstrap runs",
    )
    parser.add_argument("--config", help="Optional override JSON for competitor scenario commands")
    parser.add_argument("--iterations", type=int, default=1, help="ZKF benchmark iterations")
    parser.add_argument(
        "--lane",
        choices=["linux", "apple-silicon"],
        help="Competition lane; defaults from the current host profile",
    )
    parser.add_argument(
        "--zkf-benchmark-backends",
        help="Optional comma-separated subset of ZKF benchmark backends",
    )
    parser.add_argument("--skip-zkf-benchmark", action="store_true", help="Skip the built-in ZKF benchmark")
    parser.add_argument("--skip-zkf-wrap", action="store_true", help="Skip the built-in ZKF wrap scenario")
    parser.add_argument("--require-pass", action="store_true", help="Exit nonzero unless the gate passes")
    args = parser.parse_args()

    out_path = Path(args.out).expanduser().resolve()
    gate_out_path = Path(args.gate_out).expanduser().resolve()
    manifest_path = Path(args.manifest).expanduser().resolve()
    lock_path = Path(args.toolchain_lock).expanduser().resolve()
    config = load_config(Path(args.config).expanduser().resolve() if args.config else None)
    manifest = load_manifest(manifest_path)

    profile = host_profile()
    lane = detect_lane(profile, args.lane)
    requested_benchmark_backends = None
    if args.zkf_benchmark_backends:
        requested_benchmark_backends = [
            value.strip()
            for value in args.zkf_benchmark_backends.split(",")
            if value.strip()
        ]

    toolchain_manifest_path = (
        Path(args.toolchain_manifest).expanduser().resolve()
        if args.toolchain_manifest
        else None
    )
    toolchain_manifest_out = Path(args.toolchain_manifest_out).expanduser().resolve()
    toolchain_manifest, used_toolchain_manifest_path = load_or_build_toolchain_manifest(
        lock_path=lock_path,
        manifest_path=toolchain_manifest_path,
        manifest_out=toolchain_manifest_out,
    )

    prefix, zkf_source = zkf_command_prefix()
    capabilities = run_capabilities(prefix)
    zkf_capability_summary = summarize_zkf_capabilities(capabilities)

    benchmark_candidates = requested_benchmark_backends or [
        backend for backend in zkf_capability_summary["ready_real_backends"] if backend in BENCHMARK_BACKENDS
    ]
    ne_advisory = collect_ne_advisory(prefix, lane=lane, benchmark_backends=benchmark_candidates)

    with tempfile.TemporaryDirectory(prefix="zkf-competitive-harness-") as tempdir:
        workdir = Path(tempdir)
        zkf_section = {
            "command_source": zkf_source,
            "capabilities_summary": zkf_capability_summary,
        }

        run_zkf_first = (ne_advisory.get("applied_order") or ["zkf-self-check", "competitors"])[0] == "zkf-self-check"
        competitors: list[dict[str, Any]]
        if run_zkf_first:
            if args.skip_zkf_benchmark:
                zkf_section["benchmark"] = {"status": "skipped", "reason": "disabled-by-flag"}
            else:
                zkf_section["benchmark"] = run_zkf_benchmark(
                    prefix,
                    capabilities,
                    args.iterations,
                    workdir,
                    requested_benchmark_backends,
                )
            if args.skip_zkf_wrap:
                zkf_section["wrap"] = {"status": "skipped", "reason": "disabled-by-flag"}
            else:
                zkf_section["wrap"] = run_zkf_wrap(prefix, workdir)
            competitors = competitor_report(
                manifest,
                toolchain_manifest,
                config,
                lane=lane,
                workdir=workdir,
            )
        else:
            competitors = competitor_report(
                manifest,
                toolchain_manifest,
                config,
                lane=lane,
                workdir=workdir,
            )
            if args.skip_zkf_benchmark:
                zkf_section["benchmark"] = {"status": "skipped", "reason": "disabled-by-flag"}
            else:
                zkf_section["benchmark"] = run_zkf_benchmark(
                    prefix,
                    capabilities,
                    args.iterations,
                    workdir,
                    requested_benchmark_backends,
                )
            if args.skip_zkf_wrap:
                zkf_section["wrap"] = {"status": "skipped", "reason": "disabled-by-flag"}
            else:
                zkf_section["wrap"] = run_zkf_wrap(prefix, workdir)

        summary = summarize_report(
            zkf_section,
            competitors,
            toolchain_manifest,
            manifest.get("required_scenarios") or [],
        )
        report = {
            "schema": SCHEMA,
            "generated_at": now_iso(),
            "repo_root": str(ROOT),
            "lane": lane,
            "host_profile": profile,
            "manifest_path": str(manifest_path),
            "toolchain_manifest_path": str(used_toolchain_manifest_path),
            "toolchain_manifest": toolchain_manifest,
            "zkf": zkf_section,
            "competitors": competitors,
            "summary": summary,
            "ne_advisory": ne_advisory,
            "next_actions": next_actions(zkf_capability_summary, toolchain_manifest, competitors),
            "config_path": args.config,
        }
        gate = {
            "schema": GATE_SCHEMA,
            "generated_at": report["generated_at"],
            "lane": lane,
            "toolchain_manifest_path": str(used_toolchain_manifest_path),
            "competitive_harness_report": str(out_path),
            "required_toolchains_ready": summary["required_toolchains_ready"],
            "mixed_corpus_complete": summary["mixed_corpus_complete"],
            "external_evidence_complete": summary["external_evidence_complete"],
            "competition_gate_passed": summary["competition_gate_passed"],
            "benchmark_backend_selection": summary["benchmark_backend_selection"],
            "blocking_reasons": summary["blocking_reasons"],
            "ne_advisory": {
                "available": ne_advisory.get("available"),
                "advisory_only": ne_advisory.get("advisory_only"),
                "recommended_job_order": ne_advisory.get("recommended_job_order"),
                "recommended_backend_order": ne_advisory.get("recommended_backend_order"),
                "recommended_parallelism": ne_advisory.get("recommended_parallelism"),
            },
        }

        write_json(out_path, report)
        write_json(gate_out_path, gate)

    print(
        json.dumps(
            {
                "report": str(out_path),
                "gate": str(gate_out_path),
                "toolchain_manifest": str(used_toolchain_manifest_path),
                "schema": SCHEMA,
                "gate_schema": GATE_SCHEMA,
                "competition_gate_passed": summary["competition_gate_passed"],
            },
            indent=2,
        )
    )
    return 0 if (summary["competition_gate_passed"] or not args.require_pass) else 1


if __name__ == "__main__":
    raise SystemExit(main())
