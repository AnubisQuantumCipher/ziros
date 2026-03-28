#!/usr/bin/env python3
"""Build a machine-readable assistant bundle for the local ZFK installation.

The bundle is written under:
  ~/Library/Application Support/ZFK/assistant

It is intentionally pragmatic:
- summarize the machine and workspace state
- capture the real proving/control-plane capabilities from this repo
- record current certification / soak state
- expose a compact assistant playbook the app-side assistant can load

The Neural Engine is used on the control plane via the existing Core ML policy
model when available. We do not attempt to run proving arithmetic on ANE.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ZFK_HOME = Path.home() / "Library" / "Application Support" / "ZFK"
ASSISTANT_SCHEMA = "zkf-assistant-bundle-v2"
DEFAULT_GATE_REPORT = Path("/tmp/zkf-production-gate-current/strict-certification.json")
DEFAULT_SOAK_PROGRESS = Path("/tmp/zkf-production-soak-current/soak-progress.json")
DEFAULT_SOAK_REPORT = Path("/tmp/zkf-production-soak-current/strict-certification.json")
OFFICIAL_SOURCES = [
    {
        "label": "Apple introduces M4 Pro and M4 Max",
        "url": "https://www.apple.com/newsroom/2024/10/apple-introduces-m4-pro-and-m4-max/",
        "note": "Official M4 Max hardware summary, including the 16-core Neural Engine and unified memory positioning.",
    },
    {
        "label": "MLModelConfiguration.computeUnits",
        "url": "https://developer.apple.com/documentation/coreml/mlmodelconfiguration/computeunits",
        "note": "Core ML entry point for selecting CPU / Neural Engine compute policy.",
    },
    {
        "label": "MLComputeUnits.cpuAndNeuralEngine",
        "url": "https://developer.apple.com/documentation/coreml/mlcomputeunits/cpuandneuralengine",
        "note": "Official compute-units mode used here for assistant/control-plane inference.",
    },
    {
        "label": "MTLDevice.recommendedMaxWorkingSetSize",
        "url": "https://developer.apple.com/documentation/metal/mtldevice/recommendedmaxworkingsetsize",
        "note": "Metal unified-memory budget guidance for GPU-heavy proving workloads.",
    },
]

PUBLIC_PROVING_SURFACES = {
    "prove": ROOT / "zkf-cli" / "src" / "cmd" / "prove.rs",
    "package prove": ROOT / "zkf-cli" / "src" / "cmd" / "package" / "prove.rs",
    "package compose": ROOT / "zkf-cli" / "src" / "cmd" / "package" / "compose.rs",
    "benchmark": ROOT / "zkf-cli" / "src" / "benchmark.rs",
    "demo": ROOT / "zkf-cli" / "src" / "cmd" / "demo.rs",
    "test-vectors": ROOT / "zkf-cli" / "src" / "cmd" / "test_vectors.rs",
    "equivalence": ROOT / "zkf-cli" / "src" / "cmd" / "equivalence.rs",
}

PUBLIC_WRAP_SURFACES = {
    "wrap": ROOT / "zkf-cli" / "src" / "cmd" / "prove.rs",
    "runtime execute": ROOT / "zkf-cli" / "src" / "cmd" / "runtime.rs",
}


def run(
    argv: list[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def run_ok(argv: list[str], *, cwd: Path | None = None, timeout: float | None = None) -> str | None:
    proc = run(argv, cwd=cwd, timeout=timeout)
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def read_json(path: Path) -> Any | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def sysctl(name: str) -> str | None:
    return run_ok(["sysctl", "-n", name], timeout=2)


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat()


def latest_matching_file(paths: list[Path], patterns: tuple[str, ...]) -> Path | None:
    matches: list[Path] = []
    for base in paths:
        if not base.exists():
            continue
        for pattern in patterns:
            matches.extend(base.rglob(pattern))
    matches = [p for p in matches if p.is_file()]
    if not matches:
        return None
    return max(matches, key=lambda p: p.stat().st_mtime)


def collect_host_profile() -> dict[str, Any]:
    cpu_brand = sysctl("machdep.cpu.brand_string")
    memsize = sysctl("hw.memsize")
    ncpu = sysctl("hw.ncpu")
    perf_cores = sysctl("hw.perflevel0.physicalcpu")
    model = sysctl("hw.model")
    machine = platform.machine()
    return {
        "model": model,
        "machine_arch": machine,
        "cpu_brand": cpu_brand,
        "memory_bytes": int(memsize) if memsize and memsize.isdigit() else None,
        "cpu_cores_total": int(ncpu) if ncpu and ncpu.isdigit() else None,
        "performance_cores": int(perf_cores) if perf_cores and perf_cores.isdigit() else None,
        "is_apple_silicon": machine == "arm64",
        "certified_profile": "apple-silicon-m4-max-48gb"
        if cpu_brand and "M4 Max" in cpu_brand
        else None,
    }


def collect_workspace(zfk_home: Path) -> dict[str, Any]:
    workspace = zfk_home / "workspace"
    projects_dir = workspace / "projects"
    circuits_dir = workspace / "circuits"
    proofs_dir = workspace / "proofs"
    exports_dir = workspace / "exports"
    artifacts_dir = workspace / "artifacts"
    audit_dir = workspace / "audit"

    def dir_names(path: Path) -> list[str]:
        if not path.exists():
            return []
        return sorted(p.name for p in path.iterdir() if p.is_dir())

    def file_names(path: Path) -> list[str]:
        if not path.exists():
            return []
        return sorted(p.name for p in path.iterdir() if p.is_file())

    project_names = dir_names(projects_dir)
    return {
        "workspace_path": str(workspace),
        "project_count": len(project_names),
        "projects": project_names[:64],
        "artifact_files": file_names(artifacts_dir)[:64],
        "circuit_files": file_names(circuits_dir)[:64],
        "proof_files": file_names(proofs_dir)[:64],
        "export_files": file_names(exports_dir)[:64],
        "audit_files": file_names(audit_dir)[:64],
        "session_note": (projects_dir / "session_note.txt").read_text().strip()
        if (projects_dir / "session_note.txt").exists()
        else None,
    }


def collect_backend_matrix(zfk_home: Path) -> dict[str, Any] | None:
    del zfk_home

    binary = locate_binary()
    if binary:
        command = [str(binary), "capabilities"]
        source = str(binary)
    elif shutil.which("cargo"):
        command = ["cargo", "run", "-q", "-p", "zkf-cli", "--", "capabilities"]
        source = "cargo-run"
    else:
        return {
            "available": False,
            "live_capabilities": True,
            "error": "neither a zkf-cli binary nor cargo is available",
            "backends": [],
        }

    proc = run(command, cwd=ROOT, timeout=180)
    if proc.returncode != 0:
        return {
            "available": False,
            "live_capabilities": True,
            "source": source,
            "command": command,
            "error": proc.stderr.strip() or "zkf-cli capabilities failed",
            "backends": [],
        }

    try:
        raw_reports = json.loads(proc.stdout)
    except Exception as exc:
        return {
            "available": False,
            "live_capabilities": True,
            "source": source,
            "command": command,
            "error": f"failed to parse zkf-cli capabilities JSON: {exc}",
            "stdout": proc.stdout[:4000],
            "backends": [],
        }

    if not isinstance(raw_reports, list):
        return {
            "available": False,
            "live_capabilities": True,
            "source": source,
            "command": command,
            "error": "zkf-cli capabilities did not return a JSON list",
            "backends": [],
        }

    backends = sorted(
        [
            {
                "name": report.get("backend"),
                "implementation_type": report.get("implementation_type"),
                "mode": report.get("mode"),
                "compiled_in": bool(report.get("compiled_in")),
                "toolchain_ready": bool(report.get("toolchain_ready")),
                "runtime_ready": bool(report.get("runtime_ready")),
                "production_ready": bool(report.get("production_ready")),
                "readiness": report.get("readiness"),
                "readiness_reason": report.get("readiness_reason"),
                "operator_action": report.get("operator_action"),
                "explicit_compat_alias": report.get("explicit_compat_alias"),
                "proof_engine": report.get("proof_engine"),
                "proof_semantics": report.get("proof_semantics"),
                "blackbox_semantics": report.get("blackbox_semantics"),
                "prover_acceleration_scope": report.get("prover_acceleration_scope"),
                "transparent_setup": report.get("transparent_setup"),
                "trusted_setup": report.get("trusted_setup"),
                "recursion_ready": report.get("recursion_ready"),
                "export_scheme": report.get("export_scheme"),
                "metal_complete": report.get("metal_complete"),
                "cpu_math_fallback_reason": report.get("cpu_math_fallback_reason"),
                "native_profiles": report.get("native_profiles") or [],
                "notes": report.get("notes"),
            }
            for report in raw_reports
            if isinstance(report, dict)
        ],
        key=lambda entry: entry.get("name") or "",
    )

    def select(kind: str, *, ready: bool | None = None) -> list[dict[str, Any]]:
        entries = [
            entry
            for entry in backends
            if entry.get("implementation_type") == kind
            and (ready is None or bool(entry.get("production_ready")) == ready)
        ]
        return entries

    blocked = [entry for entry in backends if not entry.get("production_ready")]

    def names(entries: list[dict[str, Any]]) -> list[str]:
        return [entry["name"] for entry in entries if entry.get("name")]

    def blocked_summary(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "name": entry.get("name"),
                "implementation_type": entry.get("implementation_type"),
                "readiness": entry.get("readiness"),
                "readiness_reason": entry.get("readiness_reason"),
                "operator_action": entry.get("operator_action"),
                "explicit_compat_alias": entry.get("explicit_compat_alias"),
            }
            for entry in entries
        ]

    ready_real = [
        entry
        for entry in backends
        if entry.get("production_ready") and entry.get("implementation_type") != "delegated"
    ]
    blocked_native = [
        entry for entry in blocked if entry.get("implementation_type") == "native"
    ]

    return {
        "available": True,
        "live_capabilities": True,
        "source": source,
        "command": command,
        "version": 2,
        "audit_date": now_iso(),
        "summary": {
            "total_backends": len(backends),
            "ready_backends": sum(1 for entry in backends if entry.get("production_ready")),
            "ready_real_backends": len(ready_real),
            "blocked_backends": len(blocked),
            "blocked_native_backends": len(blocked_native),
        },
        "native_backends": names(select("native")),
        "delegated_backends": names(select("delegated")),
        "adapted_backends": names(select("adapted")),
        "broken_backends": names(select("broken")),
        "ready_backends": names([entry for entry in backends if entry.get("production_ready")]),
        "ready_real_backends": names(ready_real),
        "ready_native_backends": names(select("native", ready=True)),
        "blocked_backends": blocked_summary(blocked),
        "blocked_native_backends": blocked_summary(blocked_native),
        "compat_aliases": {
            entry["name"]: entry["explicit_compat_alias"]
            for entry in backends
            if entry.get("name") and entry.get("explicit_compat_alias")
        },
        "fastest_native": None,
        "backends": backends,
    }


def collect_certification_state(
    *,
    gate_report_path: Path,
    soak_progress_path: Path,
    soak_report_path: Path,
) -> dict[str, Any]:
    gate = read_json(gate_report_path)
    soak_progress = read_json(soak_progress_path)
    soak_report = read_json(soak_report_path)

    soak_proc = run(
        [
            "zsh",
            "-lc",
            "ps -axo pid=,ppid=,etime=,rss=,state=,command= | rg 'zkf-cli runtime certify --mode soak|scripts/production_soak.sh|caffeinate|zkf-cli wrap' || true",
        ],
        timeout=3,
    )
    active_processes = [line for line in soak_proc.stdout.splitlines() if line.strip()]

    return {
        "gate_report": {
            "path": str(gate_report_path),
            "present": gate is not None,
            "final_pass": (
                gate.get("final_pass")
                if isinstance(gate, dict) and "final_pass" in gate
                else (gate.get("summary") or {}).get("final_pass")
                if isinstance(gate, dict)
                else None
            ),
            "summary": gate.get("summary") if isinstance(gate, dict) else None,
        },
        "soak_progress": {
            "path": str(soak_progress_path),
            "present": soak_progress is not None,
            "data": soak_progress,
        },
        "soak_report": {
            "path": str(soak_report_path),
            "present": soak_report is not None,
            "final_pass": (
                soak_report.get("final_pass")
                if isinstance(soak_report, dict) and "final_pass" in soak_report
                else (soak_report.get("summary") or {}).get("final_pass")
                if isinstance(soak_report, dict)
                else None
            ),
        },
        "soak_active_processes": active_processes,
        "soak_running": bool(active_processes),
    }


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


def locate_ane_model() -> Path | None:
    candidates = [
        ROOT / "target" / "coreml" / "zkf-runtime-policy.mlpackage",
        ROOT / "tmp_ane_policy.mlpackage",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def collect_ane_state() -> dict[str, Any]:
    model = locate_ane_model()
    binary = locate_binary()
    latest_trace = latest_matching_file(
        [
            Path("/tmp/zkf-production-soak-current"),
            Path("/tmp/zkf-production-gate-current"),
            DEFAULT_ZFK_HOME / "workspace",
        ],
        ("*.execution-trace.json", "*.trace.json"),
    )
    runtime_policy = None
    if binary and model and latest_trace:
        proc = run(
            [
                str(binary),
                "runtime",
                "policy",
                "--trace",
                str(latest_trace),
                "--model",
                str(model),
                "--compute-units",
                "cpu-and-neural-engine",
                "--json",
            ],
            cwd=ROOT,
            timeout=20,
        )
        if proc.returncode == 0:
            try:
                runtime_policy = json.loads(proc.stdout)
            except Exception:
                runtime_policy = {
                    "error": "failed to parse runtime policy output",
                    "stdout": proc.stdout,
                }
        else:
            runtime_policy = {
                "error": "runtime policy command failed",
                "stderr": proc.stderr,
                "exit_code": proc.returncode,
            }

    return {
        "available": model is not None,
        "model_path": str(model) if model else None,
        "binary_path": str(binary) if binary else None,
        "latest_trace_path": str(latest_trace) if latest_trace else None,
        "compute_units_default": "cpu-and-neural-engine",
        "recommended_use": [
            "route backends and trust lanes",
            "rank next actions from workspace/machine state",
            "rerank retrieved assistant knowledge chunks",
            "predict safe parallelism without contending with Metal proof kernels",
        ],
        "not_recommended_for": [
            "BN254 MSM proving kernels",
            "NTT proof arithmetic",
            "direct proof generation",
        ],
        "runtime_policy_snapshot": runtime_policy,
    }


def path_contains(path: Path, needle: str) -> bool:
    if not path.exists():
        return False
    try:
        return needle in path.read_text()
    except Exception:
        return False


def collect_umpg_state() -> dict[str, Any]:
    proving_routes = {}
    for label, path in PUBLIC_PROVING_SURFACES.items():
        proving_routes[label] = {
            "path": str(path),
            "via_umpg_backend_prove": path_contains(path, "RuntimeExecutor::run_backend_prove_job"),
        }
    wrap_routes = {}
    for label, path in PUBLIC_WRAP_SURFACES.items():
        wrap_routes[label] = {
            "path": str(path),
            "via_runtime_wrap": path_contains(path, "handle_wrap_via_runtime")
            or path_contains(path, "runtime execute"),
        }
    api_path = ROOT / "zkf-runtime" / "src" / "api.rs"
    cpu_driver_path = ROOT / "zkf-runtime" / "src" / "cpu_driver.rs"
    return {
        "generic_proving_surface": "WitnessSolve -> TranscriptUpdate -> BackendProve -> ProofEncode",
        "wrapper_surface": "WitnessSolve -> TranscriptUpdate -> VerifierEmbed -> OuterProve -> ProofEncode",
        "backend_prove_under_umpg": path_contains(api_path, "run_backend_prove_job")
        and path_contains(cpu_driver_path, "BackendProve"),
        "wrapper_outer_prove_native_under_runtime": path_contains(cpu_driver_path, "wrap_with_policy"),
        "public_proving_routes": proving_routes,
        "public_wrap_routes": wrap_routes,
        "notes": [
            "Public proving commands route through UMPG backend-prove execution.",
            "Wrapper execution runs under UMPG for the supported wrapper lane.",
            "BackendProve is still an explicit runtime-controlled delegated proving boundary.",
        ],
    }


def assistant_rules(host: dict[str, Any], ane: dict[str, Any], matrix: dict[str, Any] | None) -> list[str]:
    rules = [
        "Default to strict cryptographic trust on public flows.",
        "Use UMPG runtime paths for prove, wrap, trace, and plan execution.",
        "Always verify after prove and wrap; never treat an unverified artifact as done.",
        "Use the Neural Engine only for control-plane inference, routing, reranking, and scheduling guidance.",
        "Do not route proving arithmetic to ANE; keep proof kernels on Metal/CPU.",
    ]
    if host.get("certified_profile") == "apple-silicon-m4-max-48gb":
        rules.append(
            "On this host, BN254 should default to the certified arkworks-groth16 strict lane under metal-first policy."
        )
    if matrix and matrix.get("available"):
        ready_native = matrix.get("ready_native_backends") or []
        if ready_native:
            rules.append(
                f"`package prove-all` should target all ready native backends on this binary/host: {', '.join(ready_native)}."
            )
        if matrix.get("blocked_native_backends"):
            rules.append(
                "If a native backend is blocked, report the exact readiness reason and operator action instead of silently routing to compat."
            )
    if ane.get("available"):
        rules.append(
            "If a runtime trace is available, evaluate the Core ML policy snapshot with compute units cpu-and-neural-engine."
        )
    return rules


def blocked_backend_lines(entries: list[dict[str, Any]]) -> list[str]:
    lines = []
    for entry in entries:
        name = entry.get("name") or "unknown"
        reason = entry.get("readiness_reason") or entry.get("readiness") or "blocked"
        action = entry.get("operator_action")
        alias = entry.get("explicit_compat_alias")
        line = f"{name} ({reason})"
        if alias:
            line += f", compat alias `{alias}`"
        if action:
            line += f", action: {action}"
        lines.append(line)
    return lines


def recommended_next_actions(
    matrix: dict[str, Any] | None,
    certification: dict[str, Any],
) -> list[str]:
    actions = [
        "If a proof artifact exists and export is needed, use runtime wrap and verify the wrapped proof.",
        "For new Goldilocks/BabyBear proving jobs, prefer plonky3.",
        "For strict BN254 public outputs on this certified host, prefer arkworks-groth16 through UMPG.",
    ]
    if certification.get("soak_running"):
        actions.append("If soak is active, avoid heavy unrelated GPU benchmarks or rebuilds.")
    for entry in (matrix or {}).get("blocked_native_backends") or []:
        action = entry.get("operator_action")
        if action:
            reason = entry.get("readiness_reason") or entry.get("readiness") or "blocked"
            actions.append(f"{entry.get('name')} is blocked ({reason}); {action}.")
    return actions


def build_markdown(bundle: dict[str, Any]) -> str:
    host = bundle["host"]
    workspace = bundle["workspace"]
    matrix = bundle.get("backend_matrix") or {}
    ane = bundle["neural_engine"]
    cert = bundle["certification"]
    umpg = bundle["umpg"]
    lines = [
        "# ZFK Assistant Context",
        "",
        f"- Generated: `{bundle['generated_at']}`",
        f"- Machine: `{host.get('cpu_brand')}`",
        f"- Certified profile: `{host.get('certified_profile') or 'unknown'}`",
        f"- Memory bytes: `{host.get('memory_bytes')}`",
        "",
        "## Assistant Operating Rules",
        "",
    ]
    for rule in bundle["assistant_rules"]:
        lines.append(f"- {rule}")
    lines.extend(
        [
            "",
            "## Workspace Snapshot",
            "",
            f"- Projects: `{workspace['project_count']}`",
            f"- Session note: `{workspace.get('session_note')}`",
            f"- Proof files: `{', '.join(workspace['proof_files'][:8]) or 'none'}`",
            f"- Export files: `{', '.join(workspace['export_files'][:8]) or 'none'}`",
            "",
            "## UMPG Execution Surface",
            "",
            f"- Generic proving surface: `{umpg['generic_proving_surface']}`",
            f"- Wrapper surface: `{umpg['wrapper_surface']}`",
            f"- Backend prove under UMPG: `{umpg['backend_prove_under_umpg']}`",
            f"- Wrapper outer prove native under runtime: `{umpg['wrapper_outer_prove_native_under_runtime']}`",
            "",
            "## Backend Readiness",
            "",
            f"- Capability source: `{matrix.get('source') or 'unavailable'}`",
            f"- Ready real backends: `{', '.join(matrix.get('ready_real_backends') or []) or 'none'}`",
            f"- Ready native backends: `{', '.join(matrix.get('ready_native_backends') or []) or 'none'}`",
            f"- Native backends: `{', '.join(matrix.get('native_backends') or []) or 'none'}`",
            f"- Delegated backends: `{', '.join(matrix.get('delegated_backends') or []) or 'none'}`",
            f"- Broken backends: `{', '.join(matrix.get('broken_backends') or []) or 'none'}`",
        ]
    )
    if matrix.get("error"):
        lines.append(f"- Capability error: `{matrix.get('error')}`")
    blocked_native = matrix.get("blocked_native_backends") or []
    if blocked_native:
        lines.append(f"- Blocked native backends: `{'; '.join(blocked_backend_lines(blocked_native))}`")
    compat_aliases = matrix.get("compat_aliases") or {}
    if compat_aliases:
        lines.append(
            f"- Explicit compat aliases: `{', '.join(f'{name}->{alias}' for name, alias in sorted(compat_aliases.items()))}`"
        )
    lines.extend(
        [
            "",
            "## Neural Engine",
            "",
            f"- Policy model present: `{ane['available']}`",
            f"- Model path: `{ane.get('model_path')}`",
            f"- Latest trace used for policy: `{ane.get('latest_trace_path')}`",
            f"- Control-plane compute units: `{ane.get('compute_units_default')}`",
            "",
            "## Certification",
            "",
            f"- Gate report present: `{cert['gate_report']['present']}`",
            f"- Gate final pass: `{cert['gate_report']['final_pass']}`",
            f"- Soak running: `{cert['soak_running']}`",
            f"- Soak progress file: `{cert['soak_progress']['path']}`",
        ]
    )
    soak = cert["soak_progress"]["data"] or {}
    if soak:
        lines.extend(
            [
                f"- Soak phase: `{soak.get('phase')}`",
                f"- Soak subphase: `{soak.get('subphase')}`",
                f"- Current cycle: `{soak.get('current_cycle')}`",
                f"- Resumed from cycle: `{soak.get('resumed_from_cycle')}`",
            ]
        )
    lines.extend(["", "## Official Sources", ""])
    for source in bundle.get("official_sources", []):
        lines.append(f"- {source['label']}: {source['url']}")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the ZFK assistant knowledge bundle.")
    parser.add_argument(
        "--zfk-home",
        default=str(DEFAULT_ZFK_HOME),
        help="ZFK support directory (default: ~/Library/Application Support/ZFK)",
    )
    parser.add_argument(
        "--gate-report",
        default=str(DEFAULT_GATE_REPORT),
        help="Gate certification JSON path",
    )
    parser.add_argument(
        "--soak-progress",
        default=str(DEFAULT_SOAK_PROGRESS),
        help="Soak progress JSON path",
    )
    parser.add_argument(
        "--soak-report",
        default=str(DEFAULT_SOAK_REPORT),
        help="Soak certification JSON path",
    )
    args = parser.parse_args()

    zfk_home = Path(args.zfk_home).expanduser().resolve()
    gate_report_path = Path(args.gate_report).expanduser().resolve()
    soak_progress_path = Path(args.soak_progress).expanduser().resolve()
    soak_report_path = Path(args.soak_report).expanduser().resolve()
    assistant_dir = zfk_home / "assistant"

    host = collect_host_profile()
    workspace = collect_workspace(zfk_home)
    matrix = collect_backend_matrix(zfk_home)
    certification = collect_certification_state(
        gate_report_path=gate_report_path,
        soak_progress_path=soak_progress_path,
        soak_report_path=soak_report_path,
    )
    ane = collect_ane_state()
    umpg = collect_umpg_state()

    bundle = {
        "schema": ASSISTANT_SCHEMA,
        "generated_at": now_iso(),
        "repo_root": str(ROOT),
        "zfk_home": str(zfk_home),
        "host": host,
        "workspace": workspace,
        "backend_matrix": matrix,
        "certification": certification,
        "neural_engine": ane,
        "umpg": umpg,
        "assistant_rules": assistant_rules(host, ane, matrix),
        "recommended_next_actions": recommended_next_actions(matrix, certification),
        "official_research_topics": [
            "Core ML compute units and cpu-and-neural-engine execution",
            "Apple Neural Engine as on-device inference control plane",
            "Metal working-set budgeting for unified memory systems",
        ],
        "official_sources": OFFICIAL_SOURCES,
    }

    write_json(assistant_dir / "knowledge_bundle.json", bundle)
    write_text(assistant_dir / "system_context.md", build_markdown(bundle))

    print(
        json.dumps(
            {
                "bundle": str(assistant_dir / "knowledge_bundle.json"),
                "context": str(assistant_dir / "system_context.md"),
                "schema": ASSISTANT_SCHEMA,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
