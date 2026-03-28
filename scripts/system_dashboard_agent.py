#!/usr/bin/env python3
"""Manage the permanent ZKF system dashboard under launchd."""

from __future__ import annotations

import argparse
import os
import plistlib
import signal
import subprocess
import sys
import time
from pathlib import Path


LABEL = "com.zfk.system-dashboard"
ROOT = Path(__file__).resolve().parents[1]
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"
DEFAULT_PORT = 8777
DEFAULT_SOAK_DIR = Path("/tmp/zkf-production-soak-current")


def run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(argv, text=True, capture_output=True)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"command failed ({proc.returncode}): {' '.join(argv)}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
        )
    return proc


def gui_domain() -> str:
    uid = run(["id", "-u"]).stdout.strip()
    return f"gui/{uid}"


def listener_for_port(port: int) -> tuple[int, str] | None:
    proc = run(
        ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fpc"],
        check=False,
    )
    pid = None
    command = None
    for line in proc.stdout.splitlines():
        if line.startswith("p"):
            try:
                pid = int(line[1:])
            except ValueError:
                pid = None
        elif line.startswith("c"):
            command = line[1:]
    if pid is None:
        return None
    ps = run(["ps", "-o", "command=", "-p", str(pid)], check=False)
    full_command = ps.stdout.strip() or command or ""
    return pid, full_command


def clear_port_conflict(port: int) -> None:
    listener = listener_for_port(port)
    if not listener:
        return
    pid, command = listener
    if "system_dashboard.py" in command:
        os.kill(pid, signal.SIGTERM)
    elif "soak_monitor.py" in command:
        os.kill(pid, signal.SIGTERM)
    else:
        raise RuntimeError(
            f"port {port} is already in use by pid {pid}: {command}"
        )
    for _ in range(20):
        if listener_for_port(port) is None:
            return
        time.sleep(0.1)
    raise RuntimeError(f"port {port} did not free after terminating pid {pid}")


def build_plist(*, port: int, soak_dir: Path, auto_refresh_bundle: bool) -> dict:
    log_dir = Path.home() / "Library" / "Logs" / "ZFK"
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = log_dir / "system-dashboard.stdout.log"
    stderr_log = log_dir / "system-dashboard.stderr.log"
    program_arguments = [
        sys.executable,
        str(ROOT / "scripts" / "system_dashboard.py"),
        "--port",
        str(port),
        "--dir",
        str(soak_dir),
        "--no-browser",
    ]
    if auto_refresh_bundle:
        program_arguments.append("--auto-refresh-bundle")
    return {
        "Label": LABEL,
        "ProgramArguments": program_arguments,
        "WorkingDirectory": str(ROOT),
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(stdout_log),
        "StandardErrorPath": str(stderr_log),
        "EnvironmentVariables": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/opt/homebrew/sbin"
        },
        "ProcessType": "Background",
    }


def cmd_start(args: argparse.Namespace) -> int:
    clear_port_conflict(args.port)
    plist = build_plist(
        port=args.port,
        soak_dir=args.dir.resolve(),
        auto_refresh_bundle=args.auto_refresh_bundle,
    )
    PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PLIST_PATH.open("wb") as fh:
        plistlib.dump(plist, fh, sort_keys=True)
    domain = gui_domain()
    run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=False)
    run(["launchctl", "bootstrap", domain, str(PLIST_PATH)])
    print(f"started {LABEL}")
    print(f"url: http://127.0.0.1:{args.port}")
    print(f"plist: {PLIST_PATH}")
    return 0


def cmd_stop(_: argparse.Namespace) -> int:
    domain = gui_domain()
    run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=False)
    print(f"stopped {LABEL}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    domain = gui_domain()
    proc = run(["launchctl", "print", f"{domain}/{LABEL}"], check=False)
    if proc.returncode != 0:
        print(f"{LABEL}: not loaded")
        if PLIST_PATH.exists():
            print(f"plist: {PLIST_PATH}")
        print(f"url: http://127.0.0.1:{args.port}")
        return 1
    print(proc.stdout)
    print(f"url: http://127.0.0.1:{args.port}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the permanent ZKF system dashboard under launchd.")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="start or restart the dashboard")
    start.add_argument("--port", type=int, default=DEFAULT_PORT)
    start.add_argument("--dir", type=Path, default=DEFAULT_SOAK_DIR)
    start.add_argument("--auto-refresh-bundle", action="store_true")
    start.set_defaults(func=cmd_start)

    stop = sub.add_parser("stop", help="stop the dashboard")
    stop.set_defaults(func=cmd_stop)

    status = sub.add_parser("status", help="show dashboard launchd status")
    status.add_argument("--port", type=int, default=DEFAULT_PORT)
    status.set_defaults(func=cmd_status)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
