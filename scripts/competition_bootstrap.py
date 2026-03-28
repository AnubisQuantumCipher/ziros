#!/usr/bin/env python3
"""Bootstrap and validate external competition toolchains."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "benchmarks" / "toolchain-lock.json"
DEFAULT_OUT = ROOT / "assistant" / "toolchain_manifest.json"
SCHEMA = "zkf-competition-toolchain-manifest-v1"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text())


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


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


def parse_lock(path: Path) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        raise RuntimeError("toolchain lock must be a JSON object")
    if payload.get("schema") != "zkf-competition-toolchain-lock-v1":
        raise RuntimeError("toolchain lock schema mismatch")
    return payload


def first_version_line(proc: subprocess.CompletedProcess[str]) -> str | None:
    combined = "\n".join([proc.stdout, proc.stderr])
    lines = [line.strip() for line in combined.splitlines() if line.strip()]
    return lines[0] if lines else None


def json_scalar(proc: subprocess.CompletedProcess[str]) -> Any:
    combined = proc.stdout.strip() or proc.stderr.strip()
    if not combined:
        return None
    try:
        return json.loads(combined)
    except json.JSONDecodeError:
        return None


def version_matches(version: str | None, expected_hint: str | None) -> bool:
    if expected_hint is None:
        return True
    if not version:
        return False
    if expected_hint.lower() in version.lower():
        return True
    version_match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", version)
    expected_match = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", expected_hint)
    if version_match is None or expected_match is None:
        return False
    version_tuple = tuple(int(part) if part is not None else 0 for part in version_match.groups())
    expected_tuple = tuple(int(part) if part is not None else 0 for part in expected_match.groups())
    return version_tuple >= expected_tuple


def tool_env(spec: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    paths = []
    for raw in spec.get("path_hints") or []:
        if isinstance(raw, str) and raw.strip():
            paths.append(os.path.expandvars(raw))
    if paths:
        env["PATH"] = os.pathsep.join(paths + [env.get("PATH", "")])
    return env


def apply_host_requirements(spec: dict[str, Any], probe: dict[str, Any]) -> dict[str, Any]:
    host_requirements = spec.get("host_requirements")
    if not probe.get("ready") or not isinstance(host_requirements, dict):
        return probe

    requirement = host_requirements.get(platform.system()) or host_requirements.get("*")
    if not isinstance(requirement, dict):
        return probe

    probe_command = requirement.get("probe_command")
    minimum_memory_bytes = requirement.get("minimum_memory_bytes")
    if not isinstance(probe_command, list) or not isinstance(minimum_memory_bytes, int):
        return probe

    proc = run(probe_command, cwd=ROOT, timeout=30, env=tool_env(spec))
    observed_memory_bytes = json_scalar(proc)
    host_requirement = {
        "host": platform.system(),
        "probe_command": probe_command,
        "minimum_memory_bytes": minimum_memory_bytes,
        "observed_memory_bytes": observed_memory_bytes,
        "stdout_preview": proc.stdout.strip()[:4000] or None,
        "stderr_preview": proc.stderr.strip()[:4000] or None,
    }
    if proc.returncode != 0 or not isinstance(observed_memory_bytes, int):
        return {
            **probe,
            "ready": False,
            "failure_reason": requirement.get("failure_reason", "host-capacity-probe-failed"),
            "operator_action": requirement.get("operator_action") or spec.get("operator_action"),
            "host_requirement": {
                **host_requirement,
                "satisfied": False,
            },
        }
    if observed_memory_bytes < minimum_memory_bytes:
        return {
            **probe,
            "ready": False,
            "failure_reason": requirement.get("failure_reason", "host-capacity-insufficient"),
            "operator_action": requirement.get("operator_action") or spec.get("operator_action"),
            "host_requirement": {
                **host_requirement,
                "satisfied": False,
            },
        }
    return {
        **probe,
        "host_requirement": {
            **host_requirement,
            "satisfied": True,
        },
    }


def probe_tool(spec: dict[str, Any]) -> dict[str, Any]:
    expected_hint = spec.get("expected_version_hint")
    env = tool_env(spec)
    last_failure: dict[str, Any] | None = None
    for command in spec.get("probe_commands") or []:
        proc = run(command, cwd=ROOT, timeout=30, env=env)
        combined = "\n".join([proc.stdout, proc.stderr])
        version = first_version_line(proc)
        allow_nonzero_match = expected_hint is not None and version_matches(combined, expected_hint)
        if proc.returncode != 0 and not allow_nonzero_match:
            last_failure = {
                "installed": proc.returncode != 127,
                "ready": False,
                "version": version,
                "probe_command": command,
                "failure_reason": (
                    "toolchain-missing" if proc.returncode == 127 else "probe-command-failed"
                ),
                "operator_action": spec.get("operator_action"),
                "stdout_preview": proc.stdout.strip()[:4000] or None,
                "stderr_preview": proc.stderr.strip()[:4000] or None,
            }
            continue
        if version_matches(version, expected_hint):
            return apply_host_requirements(spec, {
                "installed": True,
                "ready": True,
                "version": version,
                "probe_command": command,
                "failure_reason": None,
                "operator_action": None,
                "stdout_preview": proc.stdout.strip()[:4000] or None,
                "stderr_preview": proc.stderr.strip()[:4000] or None,
            })
        return {
            "installed": True,
            "ready": False,
            "version": version,
            "probe_command": command,
            "failure_reason": "version-mismatch",
            "operator_action": (
                spec.get("operator_action")
                or f"install the pinned tool version ({expected_hint}) and rerun bootstrap"
            ),
            "stdout_preview": proc.stdout.strip()[:4000] or None,
            "stderr_preview": proc.stderr.strip()[:4000] or None,
        }
    return last_failure or {
        "installed": False,
        "ready": False,
        "version": None,
        "probe_command": None,
        "failure_reason": "toolchain-missing",
        "operator_action": spec.get("operator_action"),
        "stdout_preview": None,
        "stderr_preview": None,
    }


def install_tool(spec: dict[str, Any]) -> dict[str, Any]:
    command = spec.get("install_command")
    if not spec.get("install_supported") or not isinstance(command, list) or not command:
        return {
            "attempted": False,
            "ok": False,
            "failure_reason": "install-not-supported",
            "operator_action": spec.get("operator_action"),
        }
    proc = run(command, cwd=ROOT, timeout=1800, env=tool_env(spec))
    return {
        "attempted": True,
        "ok": proc.returncode == 0,
        "command": command,
        "failure_reason": None if proc.returncode == 0 else "install-command-failed",
        "stdout_preview": proc.stdout.strip()[:4000] or None,
        "stderr_preview": proc.stderr.strip()[:4000] or None,
        "operator_action": (
            None
            if proc.returncode == 0
            else spec.get("operator_action") or "fix the toolchain installer and rerun bootstrap"
        ),
    }


def sort_specs(payload: dict[str, Any]) -> list[dict[str, Any]]:
    pending = []
    for spec in payload.get("tools") or []:
        if isinstance(spec, dict) and spec.get("id"):
            pending.append(spec)
    sorted_specs: list[dict[str, Any]] = []
    resolved: set[str] = set()
    while pending:
        progressed = False
        for spec in list(pending):
            deps = set(spec.get("depends_on") or [])
            if deps.issubset(resolved):
                sorted_specs.append(spec)
                resolved.add(spec["id"])
                pending.remove(spec)
                progressed = True
        if not progressed:
            raise RuntimeError("toolchain lock has a circular dependency")
    return sorted_specs


def manifest_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    required = [entry for entry in entries if entry.get("required")]
    next_actions = [
        entry["operator_action"]
        for entry in required
        if not entry.get("ready") and entry.get("operator_action")
    ]
    return {
        "required_total": len(required),
        "required_ready": sum(1 for entry in required if entry.get("ready")),
        "required_toolchains_ready": all(entry.get("ready") for entry in required),
        "blocking_reasons": sorted(
            {
                entry["failure_reason"]
                for entry in required
                if entry.get("failure_reason")
            }
        ),
        "next_actions": next_actions,
    }


def build_toolchain_manifest(
    *,
    lock_path: Path,
    out_path: Path,
    install_missing: bool,
) -> dict[str, Any]:
    payload = parse_lock(lock_path)
    entries: list[dict[str, Any]] = []
    id_to_entry: dict[str, dict[str, Any]] = {}

    for spec in sort_specs(payload):
        probe = probe_tool(spec)
        install_result = None
        deps = spec.get("depends_on") or []
        dependencies_ready = all(id_to_entry.get(dep, {}).get("ready") for dep in deps)
        if not dependencies_ready and deps:
            probe = {
                "installed": False,
                "ready": False,
                "version": None,
                "probe_command": None,
                "failure_reason": "dependency-not-ready",
                "operator_action": spec.get("operator_action"),
            }
        elif install_missing and not probe["ready"] and spec.get("install_supported"):
            install_result = install_tool(spec)
            if install_result.get("ok"):
                probe = probe_tool(spec)
            elif install_result.get("failure_reason"):
                probe = {
                    **probe,
                    "failure_reason": install_result["failure_reason"],
                    "operator_action": install_result.get("operator_action") or probe.get("operator_action"),
                }

        entry = {
            "tool": spec["id"],
            "label": spec.get("label") or spec["id"],
            "required": bool(spec.get("required", True)),
            "version": probe.get("version"),
            "installed": bool(probe.get("installed")),
            "ready": bool(probe.get("ready")),
            "install_source": spec.get("install_source"),
            "expected_version_hint": spec.get("expected_version_hint"),
            "probe_command": probe.get("probe_command"),
            "install_result": install_result,
            "failure_reason": probe.get("failure_reason"),
            "operator_action": probe.get("operator_action"),
            "probe_stdout_preview": probe.get("stdout_preview"),
            "probe_stderr_preview": probe.get("stderr_preview"),
            "host_requirement": probe.get("host_requirement"),
            "depends_on": deps,
            "path_hints": spec.get("path_hints") or [],
        }
        entries.append(entry)
        id_to_entry[spec["id"]] = entry

    summary = manifest_summary(entries)
    manifest = {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "root": str(ROOT),
        "lock_path": str(lock_path),
        "install_missing": install_missing,
        "tools": entries,
        "summary": summary,
        "next_actions": summary["next_actions"],
    }
    write_json(out_path, manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--install-missing", action="store_true")
    args = parser.parse_args()

    manifest = build_toolchain_manifest(
        lock_path=args.lock.expanduser().resolve(),
        out_path=args.out.expanduser().resolve(),
        install_missing=args.install_missing,
    )
    print(
        json.dumps(
            {
                "toolchain_manifest": str(args.out.expanduser().resolve()),
                "schema": SCHEMA,
                "required_toolchains_ready": manifest["summary"]["required_toolchains_ready"],
            },
            indent=2,
        )
    )
    return 0 if manifest["summary"]["required_toolchains_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
