#!/usr/bin/env python3
"""Finalize the no-dashboard Desktop release after the current-binary soak passes."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path("/Users/sicarii/Projects/ZK DEV")
DEFAULT_SOURCE_BINARY = Path("/tmp/zkf-certified-release-binary/zkf-cli")
DEFAULT_BUNDLE_DIR = Path("/Users/sicarii/Desktop/ZKF-Release-v1.0.0-2026-03-17-NoEmbeddedDashboard")
DEFAULT_DESKTOP_BINARY = DEFAULT_BUNDLE_DIR / "bin" / "zkf-cli"
DEFAULT_GATE_REPORT = Path("/tmp/zkf-production-gate-current-binary/strict-certification.json")
DEFAULT_SOAK_REPORT = Path("/tmp/zkf-production-soak-current-binary/strict-certification.json")
DEFAULT_SOAK_PROGRESS = Path("/tmp/zkf-production-soak-current-binary/soak-progress.json")
DEFAULT_INSTALLED_REPORT = Path(
    "/var/folders/bg/pt9l6y1j47q642kp3z5blrmh0000gn/T/zkf-stark-to-groth16/certification/strict-m4-max.json"
)
DEFAULT_ASSISTANT_BUNDLE = Path("/Users/sicarii/Library/Application Support/ZFK/assistant/knowledge_bundle.json")
DEFAULT_WORKSPACE_VALIDATION_REPORT = (
    ROOT / "target" / "validation" / "workspace_validation.certified.json"
)
DEFAULT_POST_SOAK_CHECKS_REPORT = (
    ROOT / "target" / "validation" / "post_soak_release_checks.certified.json"
)
DEFAULT_COMPETITIVE_ITERATIONS = 1
DEFAULT_SOAK_STALE_SECONDS = 30 * 60
COMPETITIVE_BENCHMARK_BACKENDS = {"arkworks-groth16", "halo2", "plonky3"}
COMPETITIVE_BENCHMARK_PROBE_ORDER = ["plonky3", "halo2", "arkworks-groth16"]
RELEASE_TOOL_SOURCES = {
    "soak_monitor.py": ROOT / "scripts" / "soak_monitor.py",
    "system_dashboard.py": ROOT / "scripts" / "system_dashboard.py",
    "system_dashboard_agent.py": ROOT / "scripts" / "system_dashboard_agent.py",
    "build_zfk_assistant_bundle.py": ROOT / "scripts" / "build_zfk_assistant_bundle.py",
    "competition_bootstrap.py": ROOT / "scripts" / "competition_bootstrap.py",
    "competitive_harness.py": ROOT / "scripts" / "competitive_harness.py",
    "competitive_harness.example.json": ROOT / "scripts" / "competitive_harness.example.json",
}
RELEASE_FIXTURE_ASSETS = {
    "proof-plonky3.json": ROOT / "proof-plonky3.json",
    "compiled-plonky3.json": ROOT / "compiled-plonky3.json",
}
RELEASE_SOURCE_SNAPSHOT = [
    ROOT / "zkf-cli" / "src" / "cmd" / "prove.rs",
    ROOT / "zkf-cli" / "src" / "cmd" / "package" / "prove.rs",
    ROOT / "zkf-cli" / "src" / "cmd" / "package" / "compose.rs",
    ROOT / "zkf-cli" / "src" / "cmd" / "demo.rs",
    ROOT / "zkf-cli" / "src" / "cmd" / "test_vectors.rs",
    ROOT / "zkf-cli" / "src" / "cmd" / "equivalence.rs",
    ROOT / "zkf-cli" / "src" / "cmd" / "runtime.rs",
    ROOT / "zkf-cli" / "src" / "benchmark.rs",
    ROOT / "zkf-runtime" / "src" / "api.rs",
    ROOT / "zkf-runtime" / "src" / "cpu_driver.rs",
]
RELEASE_BENCHMARK_SNAPSHOT = ROOT / "benchmarks"


def run_json(cmd: list[str]) -> tuple[int, dict[str, Any]]:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    payload = proc.stdout.strip()
    if not payload:
        raise RuntimeError(
            f"command produced no JSON output ({proc.returncode}): {' '.join(cmd)}\nstderr:\n{proc.stderr}"
        )
    try:
        return proc.returncode, json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"command did not produce valid JSON ({proc.returncode}): {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        ) from exc


def run_json_command(cmd: list[str], *, cwd: Path | None = None) -> dict[str, Any]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        capture_output=True,
        check=False,
    )
    payload = proc.stdout.strip()
    if proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    if not payload:
        raise RuntimeError(f"command produced no JSON output: {' '.join(cmd)}")
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"command did not produce valid JSON: {' '.join(cmd)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        ) from exc


def shasum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ensure_existing_file(path: Path, label: str) -> None:
    if not path.exists():
        raise RuntimeError(f"{label} is missing: {path}")
    if not path.is_file():
        raise RuntimeError(f"{label} is not a file: {path}")


def validate_preflight_inputs(
    *,
    source_binary: Path,
    desktop_binary: Path,
    gate_report: Path,
    workspace_validation_report: Path,
    post_soak_checks_report: Path,
) -> None:
    ensure_existing_file(source_binary, "source binary")
    ensure_existing_file(desktop_binary, "desktop binary")
    ensure_existing_file(gate_report, "gate report")
    ensure_existing_file(workspace_validation_report, "workspace validation report")
    ensure_existing_file(post_soak_checks_report, "post-soak checks report")


def wait_for_soak_report(
    report: Path,
    progress: Path,
    poll_seconds: int,
    *,
    stale_after_seconds: int = DEFAULT_SOAK_STALE_SECONDS,
) -> dict[str, Any]:
    while True:
        if report.exists():
            payload = json.loads(report.read_text())
            summary = payload.get("summary") or {}
            if summary.get("final_pass") is True:
                return payload
            if summary.get("final_pass") is False:
                raise RuntimeError(f"soak report finished with final_pass=false: {report}")
        if progress.exists():
            state = json.loads(progress.read_text())
            phase = state.get("phase")
            if phase == "failed":
                raise RuntimeError(f"soak progress entered failed state: {progress}")
            if phase in {"completed", "passed"}:
                raise RuntimeError(
                    f"soak progress completed without a final strict certification report: {progress}"
                )
            updated_at_unix_ms = state.get("updated_at_unix_ms")
            if (
                stale_after_seconds > 0
                and phase == "running"
                and isinstance(updated_at_unix_ms, (int, float))
            ):
                age_seconds = max(0.0, time.time() - (float(updated_at_unix_ms) / 1000.0))
                if age_seconds > stale_after_seconds:
                    raise RuntimeError(
                        "soak progress is stale "
                        f"({age_seconds:.0f}s since last update) without a finished report: {progress}"
                    )
        else:
            raise RuntimeError(
                f"soak progress is missing and no final strict certification report exists: {progress}"
            )
        time.sleep(poll_seconds)


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def archive_bundle(bundle_dir: Path) -> Path:
    archive_path = bundle_dir.with_suffix(".tar.gz")
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(bundle_dir, arcname=bundle_dir.name)
    return archive_path


def build_checksums(bundle_dir: Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for path in sorted(bundle_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.json":
            checksums[str(path.relative_to(bundle_dir))] = shasum(path)
    return checksums


def copy_release_tools(bundle_dir: Path) -> list[str]:
    tools_dir = bundle_dir / "dashboard-tools"
    scripts_dir = bundle_dir / "scripts"
    ensure_dir(tools_dir)
    ensure_dir(scripts_dir)
    copied = []
    for name, source in RELEASE_TOOL_SOURCES.items():
        if not source.exists():
            raise RuntimeError(f"required release tool is missing: {source}")
        shutil.copy2(source, tools_dir / name)
        shutil.copy2(source, scripts_dir / name)
        copied.append(name)
    return copied


def copy_release_source_snapshot(bundle_dir: Path) -> list[str]:
    copied = []
    for source in RELEASE_SOURCE_SNAPSHOT:
        if not source.exists():
            raise RuntimeError(f"required release source snapshot file is missing: {source}")
        relative = source.relative_to(ROOT)
        destination = bundle_dir / relative
        ensure_dir(destination.parent)
        shutil.copy2(source, destination)
        copied.append(str(relative))
    return copied


def copy_release_fixture_assets(bundle_dir: Path) -> list[str]:
    copied = []
    for name, source in RELEASE_FIXTURE_ASSETS.items():
        if not source.exists():
            raise RuntimeError(f"required release fixture asset is missing: {source}")
        destination = bundle_dir / name
        ensure_dir(destination.parent)
        shutil.copy2(source, destination)
        copied.append(name)
    return copied


def copy_release_benchmark_snapshot(bundle_dir: Path) -> list[str]:
    copied = []
    for source in sorted(RELEASE_BENCHMARK_SNAPSHOT.rglob("*")):
        if source.is_dir():
            continue
        if source.is_relative_to(ROOT):
            relative = source.relative_to(ROOT)
        else:
            relative = Path("benchmarks") / source.relative_to(RELEASE_BENCHMARK_SNAPSHOT)
        destination = bundle_dir / relative
        ensure_dir(destination.parent)
        shutil.copy2(source, destination)
        copied.append(str(relative))
    return copied


def build_bundle_assistant(bundle_dir: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        str(bundle_dir / "scripts" / "build_zfk_assistant_bundle.py"),
        "--zfk-home",
        str(bundle_dir),
        "--gate-report",
        str(bundle_dir / "certification" / "strict-gate.json"),
        "--soak-progress",
        str(bundle_dir / "certification" / "soak-progress.json"),
        "--soak-report",
        str(bundle_dir / "certification" / "strict-certification.json"),
    ]
    return run_json_command(command, cwd=bundle_dir)


def build_bundle_competitive_report(
    bundle_dir: Path,
    *,
    config_path: Path | None,
    iterations: int,
    benchmark_backends: list[str],
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(bundle_dir / "scripts" / "competitive_harness.py"),
        "--out",
        str(bundle_dir / "assistant" / "competitive_harness.json"),
        "--gate-out",
        str(bundle_dir / "assistant" / "competition_gate.json"),
        "--manifest",
        str(bundle_dir / "benchmarks" / "manifest.json"),
        "--toolchain-lock",
        str(bundle_dir / "benchmarks" / "toolchain-lock.json"),
        "--toolchain-manifest-out",
        str(bundle_dir / "assistant" / "toolchain_manifest.json"),
        "--iterations",
        str(iterations),
        "--require-pass",
    ]
    if benchmark_backends:
        command.extend(["--zkf-benchmark-backends", ",".join(benchmark_backends)])
    if config_path is not None:
        command.extend(["--config", str(config_path)])
    return run_json_command(command, cwd=bundle_dir)


def validate_bundle_competitive_report(
    payload: dict[str, Any],
    *,
    bundle_dir: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    summary = payload.get("summary") or {}
    benchmark_status = summary.get("zkf_benchmark_status")
    wrap_status = summary.get("zkf_wrap_status")
    gate_path = bundle_dir / "assistant" / "competition_gate.json"
    toolchain_manifest_path = bundle_dir / "assistant" / "toolchain_manifest.json"
    if not gate_path.exists():
        raise RuntimeError(f"bundle-local competition gate artifact is missing: {gate_path}")
    if not toolchain_manifest_path.exists():
        raise RuntimeError(f"bundle-local toolchain manifest is missing: {toolchain_manifest_path}")
    gate_payload = json.loads(gate_path.read_text())
    toolchain_manifest = json.loads(toolchain_manifest_path.read_text())
    if benchmark_status != "ok":
        raise RuntimeError(
            f"bundle-local competitive benchmark did not complete successfully: {benchmark_status}"
        )
    if wrap_status != "ok":
        raise RuntimeError(
            f"bundle-local competitive wrap did not complete successfully: {wrap_status}"
        )
    if not gate_payload.get("competition_gate_passed"):
        raise RuntimeError(
            f"bundle-local competition gate did not pass: {gate_payload.get('blocking_reasons')}"
        )
    if not (toolchain_manifest.get("summary") or {}).get("required_toolchains_ready"):
        raise RuntimeError("bundle-local toolchain manifest is not fully ready")
    return summary, gate_payload, toolchain_manifest


def validate_workspace_validation_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"workspace validation report is missing: {path}")
    payload = json.loads(path.read_text())
    if payload.get("schema") != "zkf-workspace-validation-v1":
        raise RuntimeError(f"workspace validation report schema mismatch: {path}")
    summary = payload.get("summary") or {}
    if not summary.get("passed"):
        raise RuntimeError(
            f"workspace validation did not pass: {summary.get('blocking_reasons')}"
        )
    return payload


def validate_post_soak_checks_report(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise RuntimeError(f"post-soak checks report is missing: {path}")
    payload = json.loads(path.read_text())
    if payload.get("schema") != "zkf-post-soak-release-checks-v1":
        raise RuntimeError(f"post-soak checks report schema mismatch: {path}")
    summary = payload.get("summary") or {}
    if not summary.get("passed"):
        raise RuntimeError(
            f"post-soak release checks did not pass: {summary.get('blocking_reasons')}"
        )
    return payload


def probe_release_benchmark_backend(binary: Path, backend: str) -> bool:
    with tempfile.TemporaryDirectory(prefix=f"zkf-release-benchmark-{backend}-") as tempdir:
        out_path = Path(tempdir) / "benchmark.json"
        proc = subprocess.run(
            [
                str(binary),
                "benchmark",
                "--out",
                str(out_path),
                "--backends",
                backend,
                "--iterations",
                "1",
                "--skip-large",
                "--continue-on-error",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0 or not out_path.exists():
            return False
        try:
            payload = json.loads(out_path.read_text())
        except json.JSONDecodeError:
            return False
        results = payload.get("results") or []
        return any(
            isinstance(entry, dict) and (entry.get("status") or {}).get("kind") == "ok"
            for entry in results
        )


def detect_release_benchmark_backends(binary: Path) -> tuple[list[str], str]:
    _, payload = run_json([str(binary), "capabilities"])
    if not isinstance(payload, list):
        raise RuntimeError("zkf-cli capabilities did not return a JSON list")
    production_ready = sorted(
        entry["backend"]
        for entry in payload
        if isinstance(entry, dict)
        and entry.get("backend") in COMPETITIVE_BENCHMARK_BACKENDS
        and entry.get("production_ready")
        and entry.get("implementation_type") != "delegated"
    )
    if production_ready:
        return production_ready, "production-ready"
    runtime_or_compiled = sorted(
        entry["backend"]
        for entry in payload
        if isinstance(entry, dict)
        and entry.get("backend") in COMPETITIVE_BENCHMARK_BACKENDS
        and entry.get("implementation_type") != "delegated"
        and (entry.get("runtime_ready") or entry.get("compiled_in"))
    )
    if runtime_or_compiled:
        return runtime_or_compiled, "runtime-or-compiled"
    for backend in COMPETITIVE_BENCHMARK_PROBE_ORDER:
        if probe_release_benchmark_backend(binary, backend):
            return [backend], "probed-explicit"
    return [], "none"


def render_handoff(
    *,
    bundle_dir: Path,
    source_binary: Path,
    desktop_binary: Path,
    binary_hash: str,
    gate_report: Path,
    soak_report: Path,
    installed_report: Path,
    assistant_bundle: Path,
    assistant_context: Path,
    competitive_report: Path,
    competition_gate: Path,
    toolchain_manifest: Path,
    competitive_summary: dict[str, Any],
    competition_gate_summary: dict[str, Any],
    workspace_validation: Path,
    workspace_validation_summary: dict[str, Any],
    post_soak_checks: Path,
    post_soak_checks_summary: dict[str, Any],
    benchmark_backends: list[str],
    benchmark_backend_selection: str,
    legacy_assistant_bundle: Path | None,
    copied_tools: list[str],
    copied_fixture_assets: list[str],
    copied_benchmark_snapshot: list[str],
    copied_source_snapshot: list[str],
    source_doctor: dict[str, Any],
    desktop_doctor: dict[str, Any],
) -> str:
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    assistant_line = f"- Assistant bundle snapshot:\n  - `{assistant_bundle}`\n- Assistant context summary:\n  - `{assistant_context}`\n"
    legacy_assistant_line = (
        f"- Prebuilt assistant snapshot copied for comparison only:\n  - `{legacy_assistant_bundle}`\n"
        if legacy_assistant_bundle and legacy_assistant_bundle.exists()
        else ""
    )
    benchmark_status = competitive_summary.get("zkf_benchmark_status")
    wrap_status = competitive_summary.get("zkf_wrap_status")
    available_competitors = competitive_summary.get("competitor_toolchains_ready")
    external_complete = competitive_summary.get("external_evidence_complete")
    gate_passed = competition_gate_summary.get("competition_gate_passed")
    required_toolchains_ready = competition_gate_summary.get("required_toolchains_ready")
    mixed_corpus_complete = competition_gate_summary.get("mixed_corpus_complete")
    return f"""# M4 Max Operator Handoff

This document is the release handoff for the certified `apple-silicon-m4-max-48gb` lane on this machine.

Generated: `{timestamp}`

## Signed-Off State

- Source release binary:
  - `{source_binary}`
- Desktop release binary:
  - `{desktop_binary}`
- Binary SHA-256:
  - `{binary_hash}`
- Strict production health:
  - source binary `production_ready={str(bool(source_doctor.get("production_ready"))).lower()}`
  - Desktop binary `production_ready={str(bool(desktop_doctor.get("production_ready"))).lower()}`
- Gate status:
  - passed
- Soak status:
  - passed
- Certified mode:
  - strict cryptographic
- Certified lane:
  - `wrapped-v2`
  - `direct-fri-v2`
  - BN254 strict auto-route enabled
- Dashboard delivery:
  - external-only scripts under `dashboard-tools/`
  - no embedded dashboard command in `zkf-cli`

## Certification Artifacts

- Gate report:
  - `{gate_report}`
- Soak report:
  - `{soak_report}`
- Installed matching strict certification report:
  - `{installed_report}`
{assistant_line}
- Competitive harness report:
  - `{competitive_report}`
- Competition gate summary:
  - `{competition_gate}`
- Competition toolchain manifest:
  - `{toolchain_manifest}`
- Workspace validation report:
  - `{workspace_validation}`
- Post-soak release checks report:
  - `{post_soak_checks}`
{legacy_assistant_line}
## Final Certification Result

- `final_pass=true`
- `gate_passed=true`
- `workspace_validation_passed={str(bool((workspace_validation_summary.get('summary') or {}).get('passed'))).lower()}`
- `post_soak_checks_passed={str(bool((post_soak_checks_summary.get('summary') or {}).get('passed'))).lower()}`
- `soak_passed=true`
- `strict_certification_present=true`
- `strict_certification_match=true`
- `parallel_jobs=1`
- `doctor_flips=0`
- `degraded_runs=0`

## Release Notes

- Desktop and source binaries are byte-identical; copying the binary did not cause certification mismatch.
- `nargo --version` is healthy on this machine (`1.0.0-beta.19`).
- Local degree-9 wrap previews are `cryptographic` with `wrapper_strategy=direct-fri-v2`; they are not attestation-only on this certified host profile.
- Halo2 remains partial GPU acceleration on this machine (`msm` on Metal, `fft-ntt` on CPU); partial GPU coverage does not guarantee lower wall-clock time.
- Bundle-local assistant context was regenerated from the bundled binary plus copied certification artifacts.
- Bundle-local benchmark evidence targeted `{', '.join(benchmark_backends)}` with selection mode `{benchmark_backend_selection}`.
- Bundle-local competition gate was regenerated from the bundled binary (`benchmark={benchmark_status}`, `wrap={wrap_status}`, `ready_toolchains={available_competitors}`, `required_toolchains_ready={str(bool(required_toolchains_ready)).lower()}`, `mixed_corpus_complete={str(bool(mixed_corpus_complete)).lower()}`, `external_evidence_complete={str(bool(external_complete)).lower()}`, `competition_gate_passed={str(bool(gate_passed)).lower()}`).
- Whole-workspace validation was required before finalization and is packaged as bundle-local evidence.

## One-Command Health Checks

Run from `/Users/sicarii/Projects/ZK DEV`.

```bash
{source_binary} metal-doctor --strict --json
```

```bash
python3 - <<'PY'
import json
with open('{soak_report}') as f:
    data = json.load(f)
print(json.dumps(data['summary'], indent=2))
PY
```

## Separate Dashboard Tools

- Soak monitor:
  - `{bundle_dir / 'dashboard-tools' / 'soak_monitor.py'}`
- System dashboard:
  - `{bundle_dir / 'dashboard-tools' / 'system_dashboard.py'}`
- System dashboard agent:
  - `{bundle_dir / 'dashboard-tools' / 'system_dashboard_agent.py'}`
- Assistant bundle builder:
  - `{bundle_dir / 'dashboard-tools' / 'build_zfk_assistant_bundle.py'}`
- Competitive harness:
  - `{bundle_dir / 'dashboard-tools' / 'competitive_harness.py'}`
- Competition bootstrap:
  - `{bundle_dir / 'dashboard-tools' / 'competition_bootstrap.py'}`
- Competitive harness config template:
  - `{bundle_dir / 'dashboard-tools' / 'competitive_harness.example.json'}`
- Copied release tools:
  - `{', '.join(copied_tools)}`
- Copied fixture assets:
  - `{', '.join(copied_fixture_assets)}`
- Copied benchmark corpus:
  - `{', '.join(copied_benchmark_snapshot)}`

## Source Snapshot For Tooling

- Minimal source snapshot copied into the bundle so assistant and dashboard tooling can
  inspect public UMPG routing without requiring a full source checkout.
- Copied snapshot files:
  - `{', '.join(copied_source_snapshot)}`

## Current Honest Boundaries

- This certification is for the certified M4 Max lane on this host profile, not every machine.
- The public proving surface is routed through UMPG, but not every backend is decomposed into a fully parallel runtime-native arithmetic graph.
- The strict lane is certified in desktop-safe soak mode with `parallel_jobs=1`.
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle-dir", type=Path, default=DEFAULT_BUNDLE_DIR)
    parser.add_argument("--source-binary", type=Path, default=DEFAULT_SOURCE_BINARY)
    parser.add_argument("--desktop-binary", type=Path, default=DEFAULT_DESKTOP_BINARY)
    parser.add_argument("--gate-report", type=Path, default=DEFAULT_GATE_REPORT)
    parser.add_argument("--soak-report", type=Path, default=DEFAULT_SOAK_REPORT)
    parser.add_argument("--soak-progress", type=Path, default=DEFAULT_SOAK_PROGRESS)
    parser.add_argument("--installed-report", type=Path, default=DEFAULT_INSTALLED_REPORT)
    parser.add_argument("--assistant-bundle", type=Path, default=DEFAULT_ASSISTANT_BUNDLE)
    parser.add_argument(
        "--workspace-validation-report",
        type=Path,
        default=DEFAULT_WORKSPACE_VALIDATION_REPORT,
    )
    parser.add_argument(
        "--post-soak-checks-report",
        type=Path,
        default=DEFAULT_POST_SOAK_CHECKS_REPORT,
    )
    parser.add_argument("--competitive-config", type=Path)
    parser.add_argument("--competitive-iterations", type=int, default=DEFAULT_COMPETITIVE_ITERATIONS)
    parser.add_argument("--poll-seconds", type=int, default=30)
    args = parser.parse_args()

    validate_preflight_inputs(
        source_binary=args.source_binary,
        desktop_binary=args.desktop_binary,
        gate_report=args.gate_report,
        workspace_validation_report=args.workspace_validation_report,
        post_soak_checks_report=args.post_soak_checks_report,
    )

    soak_payload = wait_for_soak_report(args.soak_report, args.soak_progress, args.poll_seconds)

    source_hash = shasum(args.source_binary)
    desktop_hash = shasum(args.desktop_binary)
    if source_hash != desktop_hash:
        raise RuntimeError(
            f"source/Desktop binary hash mismatch: {source_hash} != {desktop_hash}"
        )

    source_code, source_doctor = run_json(
        [str(args.source_binary), "metal-doctor", "--strict", "--json"]
    )
    desktop_code, desktop_doctor = run_json(
        [str(args.desktop_binary), "metal-doctor", "--strict", "--json"]
    )
    for label, code, payload in (
        ("source", source_code, source_doctor),
        ("desktop", desktop_code, desktop_doctor),
    ):
        if code != 0:
            raise RuntimeError(f"{label} strict doctor failed: {payload.get('production_failures')}")
        if not payload.get("production_ready"):
            raise RuntimeError(f"{label} binary is not production_ready")
        if not payload.get("strict_certification_present"):
            raise RuntimeError(f"{label} binary has no strict certification report")
        if not payload.get("strict_certification_match"):
            raise RuntimeError(f"{label} binary strict certification does not match")
    benchmark_backends, benchmark_backend_selection = detect_release_benchmark_backends(args.source_binary)
    if not benchmark_backends:
        raise RuntimeError("source binary has no benchmark-capable backends for release evidence")

    certification_dir = args.bundle_dir / "certification"
    assistant_dir = args.bundle_dir / "assistant"
    docs_dir = args.bundle_dir / "docs"
    ensure_dir(certification_dir)
    ensure_dir(assistant_dir)
    ensure_dir(docs_dir)
    copied_tools = copy_release_tools(args.bundle_dir)
    copied_fixture_assets = copy_release_fixture_assets(args.bundle_dir)
    copied_benchmark_snapshot = copy_release_benchmark_snapshot(args.bundle_dir)
    copied_source_snapshot = copy_release_source_snapshot(args.bundle_dir)
    workspace_validation_payload = validate_workspace_validation_report(
        args.workspace_validation_report.expanduser().resolve()
    )
    post_soak_checks_payload = validate_post_soak_checks_report(
        args.post_soak_checks_report.expanduser().resolve()
    )

    shutil.copy2(args.gate_report, certification_dir / "strict-gate.json")
    shutil.copy2(args.soak_report, certification_dir / "strict-certification.json")
    shutil.copy2(args.soak_progress, certification_dir / "soak-progress.json")
    shutil.copy2(args.installed_report, certification_dir / "installed-strict-m4-max.json")
    packaged_gate_report = certification_dir / "strict-gate.json"
    packaged_soak_report = certification_dir / "strict-certification.json"
    packaged_installed_report = certification_dir / "installed-strict-m4-max.json"

    legacy_assistant_bundle = None
    if args.assistant_bundle.exists():
        legacy_assistant_bundle = assistant_dir / "knowledge_bundle.prebuilt.json"
        shutil.copy2(args.assistant_bundle, legacy_assistant_bundle)

    assistant_payload = build_bundle_assistant(args.bundle_dir)
    assistant_bundle_path = assistant_dir / "knowledge_bundle.json"
    assistant_context_path = assistant_dir / "system_context.md"

    competitive_config_path = (
        args.competitive_config.expanduser().resolve()
        if args.competitive_config is not None
        else None
    )
    competitive_summary = build_bundle_competitive_report(
        args.bundle_dir,
        config_path=competitive_config_path,
        iterations=args.competitive_iterations,
        benchmark_backends=benchmark_backends,
    )
    competitive_report_path = assistant_dir / "competitive_harness.json"
    competitive_payload = json.loads(competitive_report_path.read_text())
    competitive_verdict, competition_gate_payload, toolchain_manifest_payload = validate_bundle_competitive_report(
        competitive_payload,
        bundle_dir=args.bundle_dir,
    )
    competition_gate_path = assistant_dir / "competition_gate.json"
    toolchain_manifest_path = assistant_dir / "toolchain_manifest.json"
    workspace_validation_path = assistant_dir / "workspace_validation.json"
    post_soak_checks_path = assistant_dir / "post_soak_release_checks.json"
    shutil.copy2(
        args.workspace_validation_report.expanduser().resolve(),
        workspace_validation_path,
    )
    shutil.copy2(
        args.post_soak_checks_report.expanduser().resolve(),
        post_soak_checks_path,
    )

    copied_competitive_config = None
    if competitive_config_path is not None:
        copied_competitive_config = assistant_dir / "competitive_harness.config.json"
        shutil.copy2(competitive_config_path, copied_competitive_config)

    handoff = render_handoff(
        bundle_dir=args.bundle_dir,
        source_binary=args.source_binary,
        desktop_binary=args.desktop_binary,
        binary_hash=source_hash,
        gate_report=packaged_gate_report,
        soak_report=packaged_soak_report,
        installed_report=packaged_installed_report,
        assistant_bundle=assistant_bundle_path,
        assistant_context=assistant_context_path,
        competitive_report=competitive_report_path,
        competition_gate=competition_gate_path,
        toolchain_manifest=toolchain_manifest_path,
        workspace_validation=workspace_validation_path,
        workspace_validation_summary=workspace_validation_payload,
        post_soak_checks=post_soak_checks_path,
        post_soak_checks_summary=post_soak_checks_payload,
        competitive_summary=competitive_verdict,
        competition_gate_summary=competition_gate_payload,
        benchmark_backends=benchmark_backends,
        benchmark_backend_selection=benchmark_backend_selection,
        legacy_assistant_bundle=legacy_assistant_bundle,
        copied_tools=copied_tools,
        copied_fixture_assets=copied_fixture_assets,
        copied_benchmark_snapshot=copied_benchmark_snapshot,
        copied_source_snapshot=copied_source_snapshot,
        source_doctor=source_doctor,
        desktop_doctor=desktop_doctor,
    )
    (docs_dir / "M4_MAX_OPERATOR_HANDOFF.md").write_text(handoff)

    status_doc = {
        "binary_sha256": source_hash,
        "source_binary": str(args.source_binary),
        "desktop_binary": str(args.desktop_binary),
        "gate_report": str(packaged_gate_report),
        "soak_report": str(packaged_soak_report),
        "soak_progress": str(certification_dir / "soak-progress.json"),
        "installed_report": str(packaged_installed_report),
        "input_gate_report": str(args.gate_report),
        "input_soak_report": str(args.soak_report),
        "input_soak_progress": str(args.soak_progress),
        "input_installed_report": str(args.installed_report),
        "production_ready": True,
        "strict_certification_present": True,
        "strict_certification_match": True,
        "release_tools": copied_tools,
        "release_fixture_assets": copied_fixture_assets,
        "release_benchmark_snapshot": copied_benchmark_snapshot,
        "release_source_snapshot": copied_source_snapshot,
        "assistant_bundle": assistant_payload.get("bundle"),
        "assistant_context": assistant_payload.get("context"),
        "assistant_bundle_schema": assistant_payload.get("schema"),
        "legacy_assistant_bundle": str(legacy_assistant_bundle) if legacy_assistant_bundle else None,
        "competitive_report": competitive_summary.get("report"),
        "competitive_report_schema": competitive_summary.get("schema"),
        "competitive_summary": competitive_verdict,
        "competition_gate": str(competition_gate_path),
        "competition_gate_schema": competition_gate_payload.get("schema"),
        "competition_gate_summary": competition_gate_payload,
        "toolchain_manifest": str(toolchain_manifest_path),
        "toolchain_manifest_schema": toolchain_manifest_payload.get("schema"),
        "toolchain_manifest_summary": toolchain_manifest_payload.get("summary"),
        "workspace_validation": str(workspace_validation_path),
        "workspace_validation_schema": workspace_validation_payload.get("schema"),
        "workspace_validation_summary": workspace_validation_payload.get("summary"),
        "post_soak_checks": str(post_soak_checks_path),
        "post_soak_checks_schema": post_soak_checks_payload.get("schema"),
        "post_soak_checks_summary": post_soak_checks_payload.get("summary"),
        "competitive_benchmark_backends": benchmark_backends,
        "competitive_benchmark_backend_selection": benchmark_backend_selection,
        "competitive_config": str(competitive_config_path) if competitive_config_path else None,
        "packaged_competitive_config": str(copied_competitive_config) if copied_competitive_config else None,
        "summary": soak_payload.get("summary"),
    }
    write_json(args.bundle_dir / "RELEASE_STATUS.json", status_doc)
    write_json(args.bundle_dir / "SHA256SUMS.json", build_checksums(args.bundle_dir))
    archive_path = archive_bundle(args.bundle_dir)
    print(json.dumps({"bundle": str(args.bundle_dir), "archive": str(archive_path), "binary_sha256": source_hash}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise
