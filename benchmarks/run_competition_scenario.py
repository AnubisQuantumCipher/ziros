#!/usr/bin/env python3
"""Execute one repo-owned competition scenario and emit a normalized JSON result."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "zkf-competition-scenario-v1"
CONFIG_SCHEMA = "zkf-competition-scenario-config-v1"
DEFAULT_TIMEOUT = 1800.0
VERSION_COMMANDS = {
    "snarkjs": ["snarkjs", "--version"],
    "gnark": ["go", "version"],
    "nargo": ["nargo", "--version"],
    "sp1-official": ["cargo", "prove", "--version"],
    "risc-zero-official": ["cargo", "risczero", "--version"],
    "plonky3-external": ["cargo", "--version"],
}


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat()


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


def env_key(tool: str, scenario: str, suffix: str) -> str:
    normalized_tool = "".join(ch if ch.isalnum() else "_" for ch in tool.upper())
    normalized_scenario = "".join(ch if ch.isalnum() else "_" for ch in scenario.upper())
    return f"ZKF_COMPETITION_{normalized_tool}_{normalized_scenario}_{suffix}"


def scenario_config_path(tool: str, scenario: str) -> Path:
    return ROOT / "benchmarks" / "scenarios" / tool / f"{scenario}.json"


def read_scenario_config(tool: str, scenario: str) -> dict[str, Any] | None:
    path = scenario_config_path(tool, scenario)
    if not path.exists():
        return None
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise RuntimeError(f"scenario config at {path} must be a JSON object")
    if payload.get("schema") != CONFIG_SCHEMA:
        raise RuntimeError(f"scenario config at {path} has an unsupported schema")
    return payload


def tool_version(tool: str) -> str | None:
    command = VERSION_COMMANDS.get(tool)
    if command is None:
        return None
    proc = run(command, cwd=ROOT, timeout=20)
    if proc.returncode != 0:
        return None
    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return lines[0] if lines else None


def build_result(
    *,
    tool: str,
    scenario: str,
    status: str,
    lane: str,
    elapsed_ms: float,
    proof_path: str | None,
    verify_status: str,
    failure_reason: str | None,
    operator_action: str | None,
    command: list[str] | None,
    workdir: Path | None,
    stdout_preview: str | None = None,
    stderr_preview: str | None = None,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "generated_at": now_iso(),
        "tool": tool,
        "scenario": scenario,
        "lane": lane,
        "status": status,
        "elapsed_ms": round(elapsed_ms, 3),
        "tool_version": tool_version(tool),
        "proof_path": proof_path,
        "verify_status": verify_status,
        "failure_reason": failure_reason,
        "operator_action": operator_action,
        "command": command,
        "workdir": str(workdir) if workdir is not None else None,
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
    }


def resolve_workdir(tool: str, scenario: str) -> Path:
    raw = os.environ.get(env_key(tool, scenario, "WORKDIR"))
    if not raw:
        config = read_scenario_config(tool, scenario)
        raw = config.get("workdir") if isinstance(config, dict) else None
    if not raw:
        return ROOT
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (ROOT / path).resolve()
    return path


def resolve_artifact_path(path_hint: str, *, workdir: Path, from_config: bool) -> Path:
    path = Path(path_hint).expanduser()
    if path.is_absolute():
        return path
    if from_config:
        return (ROOT / path).resolve()
    return (workdir / path).resolve()


def parse_command(raw: str) -> list[str]:
    return shlex.split(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--lane", default="linux")
    args = parser.parse_args()

    config = read_scenario_config(args.tool, args.scenario)

    if config and config.get("unsupported_reason"):
        payload = build_result(
            tool=args.tool,
            scenario=args.scenario,
            status="unsupported",
            lane=args.lane,
            elapsed_ms=0.0,
            proof_path=None,
            verify_status="unsupported",
            failure_reason=str(config["unsupported_reason"]),
            operator_action=(
                str(config.get("unsupported_action"))
                if config.get("unsupported_action") is not None
                else None
            ),
            command=None,
            workdir=None,
        )
        write_json(args.out, payload)
        print(json.dumps({"report": str(args.out), "status": payload["status"]}, indent=2))
        return 0

    unsupported_reason = os.environ.get(env_key(args.tool, args.scenario, "UNSUPPORTED_REASON"))
    if unsupported_reason:
        payload = build_result(
            tool=args.tool,
            scenario=args.scenario,
            status="unsupported",
            lane=args.lane,
            elapsed_ms=0.0,
            proof_path=None,
            verify_status="unsupported",
            failure_reason=unsupported_reason,
            operator_action=os.environ.get(env_key(args.tool, args.scenario, "UNSUPPORTED_ACTION")),
            command=None,
            workdir=None,
        )
        write_json(args.out, payload)
        print(json.dumps({"report": str(args.out), "status": payload["status"]}, indent=2))
        return 0

    command_raw = os.environ.get(env_key(args.tool, args.scenario, "CMD"))
    if not command_raw and config:
        command_value = config.get("command")
        if isinstance(command_value, list):
            command_raw = " ".join(shlex.quote(str(part)) for part in command_value)
        elif isinstance(command_value, str):
            command_raw = command_value
    if not command_raw:
        payload = build_result(
            tool=args.tool,
            scenario=args.scenario,
            status="skipped",
            lane=args.lane,
            elapsed_ms=0.0,
            proof_path=None,
            verify_status="not-run",
            failure_reason="scenario-not-configured",
            operator_action=(
                f"set {env_key(args.tool, args.scenario, 'CMD')} to a real command for this scenario"
            ),
            command=None,
            workdir=None,
        )
        write_json(args.out, payload)
        print(json.dumps({"report": str(args.out), "status": payload["status"]}, indent=2))
        return 0

    command = parse_command(command_raw)
    workdir = resolve_workdir(args.tool, args.scenario)
    timeout_raw = os.environ.get(env_key(args.tool, args.scenario, "TIMEOUT_SEC"))
    if not timeout_raw and config and config.get("timeout_sec") is not None:
        timeout_raw = str(config["timeout_sec"])
    timeout_sec = float(timeout_raw) if timeout_raw else DEFAULT_TIMEOUT
    proof_hint = os.environ.get(env_key(args.tool, args.scenario, "PROOF_PATH"))
    proof_hint_from_config = False
    if not proof_hint and config and isinstance(config.get("proof_path"), str):
        proof_hint = config["proof_path"]
        proof_hint_from_config = True
    verify_command_raw = os.environ.get(env_key(args.tool, args.scenario, "VERIFY_CMD"))
    if not verify_command_raw and config:
        verify_value = config.get("verify_command")
        if isinstance(verify_value, list):
            verify_command_raw = " ".join(shlex.quote(str(part)) for part in verify_value)
        elif isinstance(verify_value, str):
            verify_command_raw = verify_value

    env = os.environ.copy()
    if config and isinstance(config.get("env"), dict):
        for key, value in config["env"].items():
            if isinstance(key, str) and isinstance(value, str):
                env[key] = os.path.expandvars(value)

    started = time.perf_counter()
    proc = run(command, cwd=workdir, timeout=timeout_sec, env=env)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    if proc.returncode != 0:
        payload = build_result(
            tool=args.tool,
            scenario=args.scenario,
            status="failed",
            lane=args.lane,
            elapsed_ms=elapsed_ms,
            proof_path=None,
            verify_status="failed",
            failure_reason="scenario-command-failed",
            operator_action="fix the scenario command or its dependencies and rerun the gate",
            command=command,
            workdir=workdir,
            stdout_preview=proc.stdout.strip()[:4000] or None,
            stderr_preview=proc.stderr.strip()[:4000] or None,
        )
        write_json(args.out, payload)
        print(json.dumps({"report": str(args.out), "status": payload["status"]}, indent=2))
        return 0

    verify_status = "not-run"
    verify_error = None
    verify_stdout = None
    if verify_command_raw:
        verify_command = parse_command(verify_command_raw)
        verify_proc = run(verify_command, cwd=workdir, timeout=timeout_sec, env=env)
        if verify_proc.returncode == 0:
            verify_status = "passed"
            verify_stdout = verify_proc.stdout.strip()[:4000] or None
        else:
            verify_status = "failed"
            verify_error = verify_proc.stderr.strip()[:4000] or verify_proc.stdout.strip()[:4000] or "verify command failed"

    payload = build_result(
        tool=args.tool,
        scenario=args.scenario,
        status="ok" if verify_status != "failed" else "failed",
        lane=args.lane,
        elapsed_ms=elapsed_ms,
        proof_path=(
            str(resolve_artifact_path(proof_hint, workdir=workdir, from_config=proof_hint_from_config))
            if proof_hint
            else None
        ),
        verify_status=verify_status,
        failure_reason=verify_error,
        operator_action=(
            "fix the verify command or produced proof artifact and rerun the gate"
            if verify_status == "failed"
            else None
        ),
        command=command,
        workdir=workdir,
        stdout_preview=verify_stdout or proc.stdout.strip()[:4000] or None,
        stderr_preview=proc.stderr.strip()[:4000] or None,
    )
    write_json(args.out, payload)
    print(json.dumps({"report": str(args.out), "status": payload["status"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
