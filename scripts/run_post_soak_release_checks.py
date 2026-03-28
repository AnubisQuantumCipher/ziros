#!/usr/bin/env python3
"""Run the post-soak release validation matrix and emit a machine-readable report."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_BINARY = Path("/tmp/zkf-certified-release-binary/zkf-cli")
DEFAULT_OUT = ROOT / "target" / "validation" / "post_soak_release_checks.certified.json"
DEFAULT_WORKSPACE_VALIDATION_REPORT = (
    ROOT / "target" / "validation" / "workspace_validation.certified.json"
)
SCHEMA = "zkf-post-soak-release-checks-v1"
LOG_DIR_SUFFIX = ".logs"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def logs_dir_for(out_path: Path) -> Path:
    return out_path.parent / f"{out_path.stem}{LOG_DIR_SUFFIX}"


def lock_path_for(out_path: Path) -> Path:
    return out_path.with_name(f".{out_path.name}.lock")


def pid_is_live(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


@contextmanager
def exclusive_output_lock(out_path: Path):
    lock_path = lock_path_for(out_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "pid": os.getpid(),
        "out_path": str(out_path),
        "created_at": now_iso(),
    }
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            stale_payload = None
            try:
                stale_payload = json.loads(lock_path.read_text())
            except (OSError, json.JSONDecodeError):
                stale_payload = None
            stale_pid = stale_payload.get("pid") if isinstance(stale_payload, dict) else None
            if isinstance(stale_pid, int) and pid_is_live(stale_pid):
                raise RuntimeError(
                    f"post-soak report output is already in use by pid {stale_pid}: {out_path}"
                )
            try:
                lock_path.unlink()
            except FileNotFoundError:
                continue
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def load_prior_results(report_path: Path | None) -> dict[str, dict[str, Any]]:
    if report_path is None or not report_path.exists():
        return {}
    payload = json.loads(report_path.read_text())
    if payload.get("schema") != SCHEMA:
        return {}
    results = {}
    for entry in payload.get("commands", []):
        label = entry.get("label")
        if isinstance(label, str):
            results[label] = entry
    return results


def run_command(
    *,
    label: str,
    cmd: list[str],
    logs_dir: Path,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    stdout_path = logs_dir / f"{label}.stdout.log"
    stderr_path = logs_dir / f"{label}.stderr.log"
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        env=env,
        check=False,
    )
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    stdout_path.write_text(proc.stdout)
    stderr_path.write_text(proc.stderr)
    return {
        "label": label,
        "command": cmd,
        "returncode": proc.returncode,
        "elapsed_ms": round(elapsed_ms, 3),
        "ok": proc.returncode == 0,
        "stdout_path": str(stdout_path),
        "stderr_path": str(stderr_path),
        "stdout_preview": proc.stdout.strip()[:4000] or None,
        "stderr_preview": proc.stderr.strip()[:4000] or None,
    }


def validate_strict_doctor_result(result: dict[str, Any]) -> dict[str, Any]:
    try:
        stdout_path = result.get("stdout_path")
        if stdout_path:
            payload = json.loads(Path(stdout_path).read_text() or "{}")
        else:
            payload = json.loads(result.get("stdout_preview") or "{}")
    except json.JSONDecodeError as exc:
        result["ok"] = False
        result["validation_error"] = f"invalid JSON output: {exc}"
        return result
    result["payload"] = payload
    for key in ("production_ready", "strict_certification_present", "strict_certification_match"):
        if not payload.get(key):
            result["ok"] = False
            result["validation_error"] = f"{key}=false"
            break
    return result


def validate_workspace_validation_report(result: dict[str, Any], report_path: Path) -> dict[str, Any]:
    if not report_path.exists():
        result["ok"] = False
        result["validation_error"] = f"workspace validation report is missing: {report_path}"
        return result
    payload = json.loads(report_path.read_text())
    result["workspace_validation_report"] = str(report_path)
    result["workspace_validation_summary"] = payload.get("summary")
    if payload.get("schema") != "zkf-workspace-validation-v1":
        result["ok"] = False
        result["validation_error"] = f"workspace validation schema mismatch: {payload.get('schema')}"
        return result
    if not (payload.get("summary") or {}).get("passed"):
        result["ok"] = False
        result["validation_error"] = "workspace validation summary did not pass"
    return result


def validate_nonzero_test_execution(
    result: dict[str, Any],
    *,
    expected_test_count: int | None = None,
) -> dict[str, Any]:
    stdout_path = result.get("stdout_path")
    if stdout_path:
        stdout = Path(stdout_path).read_text()
    else:
        stdout = result.get("stdout_preview") or ""
    if "running 0 tests" in stdout:
        result["ok"] = False
        result["validation_error"] = "command ran zero tests"
        return result
    if expected_test_count is not None and f"running {expected_test_count} test" not in stdout:
        result["ok"] = False
        result["validation_error"] = (
            f"command did not run expected test count: {expected_test_count}"
        )
    return result


def validation_commands(
    *,
    source_binary: Path,
    workspace_validation_report: Path,
) -> list[dict[str, Any]]:
    python_env = os.environ.copy()
    python_env.setdefault("PYO3_PYTHON", "python3")
    return [
        {
            "label": "strict-metal-doctor",
            "cmd": [str(source_binary), "metal-doctor", "--strict", "--json"],
            "validator": lambda result: validate_strict_doctor_result(result),
        },
        {
            "label": "cargo-build-workspace",
            "cmd": ["cargo", "build", "--workspace"],
        },
        {
            "label": "cargo-build-workspace-release",
            "cmd": ["cargo", "build", "--workspace", "--release"],
        },
        {
            "label": "cargo-test-zkf-cli-wrapper-smoke",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-cli",
                "--bin",
                "zkf-cli",
                "--features",
                "metal-gpu,neural-engine",
                "cmd::runtime::tests::runtime_execute_native_wrapper_plan_end_to_end",
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
            ],
            "validator": lambda result: validate_nonzero_test_execution(
                result,
                expected_test_count=1,
            ),
        },
        {
            "label": "cargo-test-native-zkvm-sp1",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-backends",
                "--test",
                "native_zkvm_roundtrip",
                "--features",
                "native-sp1,native-risc-zero",
                "sp1_native_roundtrip_matrix",
                "--",
                "--nocapture",
            ],
        },
        {
            "label": "cargo-test-native-zkvm-risc-zero",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-backends",
                "--test",
                "native_zkvm_roundtrip",
                "--features",
                "native-sp1,native-risc-zero",
                "risc_zero_native_roundtrip_matrix",
                "--",
                "--nocapture",
            ],
        },
        {
            "label": "cargo-test-zkf-cli-featured",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-cli",
                "--bin",
                "zkf-cli",
                "--features",
                "metal-gpu,neural-engine",
                "--",
                "--nocapture",
            ],
        },
        {
            "label": "cargo-test-hypernova-roundtrip",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-integration-tests",
                "--test",
                "hypernova_roundtrip",
                "--",
                "--nocapture",
            ],
        },
        {
            "label": "cargo-test-midnight-readiness",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-backends",
                "--test",
                "midnight_readiness",
                "--",
                "--nocapture",
            ],
        },
        {
            "label": "cargo-test-midnight-native-runtime",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-backends",
                "--test",
                "midnight_native_runtime",
                "--",
                "--nocapture",
            ],
        },
        {
            "label": "cargo-test-zkf-cli-package-bundle",
            "cmd": [
                "cargo",
                "test",
                "-p",
                "zkf-cli",
                "--bin",
                "zkf-cli",
                "package_bundle",
                "--",
                "--nocapture",
            ],
        },
        {
            "label": "cargo-test-zkf-api",
            "cmd": ["cargo", "test", "-p", "zkf-api", "--", "--nocapture"],
        },
        {
            "label": "python-import-zkf",
            "cmd": ["python3", "scripts/smoke_import_zkf_python.py", "--target-dir", "target/debug"],
            "env": python_env,
        },
        {
            "label": "cargo-test-zkf-lsp",
            "cmd": ["cargo", "test", "-p", "zkf-lsp", "--", "--nocapture"],
        },
        {
            "label": "python-validate-workspace",
            "cmd": [
                "python3",
                "scripts/validate_workspace.py",
                "--out",
                str(workspace_validation_report),
            ],
            "validator": lambda result: validate_workspace_validation_report(
                result,
                workspace_validation_report,
            ),
        },
    ]


def build_report(
    *,
    out_path: Path,
    source_binary: Path,
    workspace_validation_report: Path,
    reuse_report: Path | None = None,
) -> dict[str, Any]:
    logs_dir = logs_dir_for(out_path)
    with exclusive_output_lock(out_path):
        logs_dir.mkdir(parents=True, exist_ok=True)
        prior_results = load_prior_results(reuse_report)
        results = []
        for entry in validation_commands(
            source_binary=source_binary,
            workspace_validation_report=workspace_validation_report,
        ):
            prior_result = prior_results.get(entry["label"])
            if (
                prior_result
                and prior_result.get("ok")
                and prior_result.get("command") == entry["cmd"]
            ):
                result = dict(prior_result)
                result["reused_from_report"] = str(reuse_report)
                results.append(result)
                continue
            result = run_command(
                label=entry["label"],
                cmd=entry["cmd"],
                logs_dir=logs_dir,
                env=entry.get("env"),
            )
            validator = entry.get("validator")
            if callable(validator):
                result = validator(result)
            results.append(result)

        blocking_reasons = [result["label"] for result in results if not result.get("ok")]
        next_actions = [
            f"fix {result['label']} and inspect {result['stderr_path']} for the exact failure"
            for result in results
            if not result.get("ok")
        ]
        report = {
            "schema": SCHEMA,
            "generated_at": now_iso(),
            "root": str(ROOT),
            "source_binary": str(source_binary),
            "workspace_validation_report": str(workspace_validation_report),
            "logs_dir": str(logs_dir),
            "reuse_report": str(reuse_report) if reuse_report else None,
            "commands": results,
            "summary": {
                "passed": not blocking_reasons,
                "command_count": len(results),
                "commands_ok": sum(1 for result in results if result.get("ok")),
                "commands_reused": sum(
                    1 for result in results if result.get("reused_from_report")
                ),
                "blocking_reasons": blocking_reasons,
            },
            "next_actions": next_actions,
        }
        write_json(out_path, report)
        return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-binary", type=Path, default=DEFAULT_SOURCE_BINARY)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument(
        "--workspace-validation-report",
        type=Path,
        default=DEFAULT_WORKSPACE_VALIDATION_REPORT,
    )
    parser.add_argument(
        "--reuse-report",
        type=Path,
        default=None,
        help="reuse matching ok command results from an existing post-soak report",
    )
    args = parser.parse_args()
    try:
        report = build_report(
            out_path=args.out,
            source_binary=args.source_binary.expanduser().resolve(),
            workspace_validation_report=args.workspace_validation_report.expanduser().resolve(),
            reuse_report=args.reuse_report.expanduser().resolve() if args.reuse_report else None,
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(report["summary"], indent=2, sort_keys=True))
    return 0 if report["summary"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
