#!/usr/bin/env python3
"""Launch the Desktop release finalizer under macOS launchd."""

from __future__ import annotations

import argparse
import plistlib
import subprocess
import sys
from pathlib import Path


LABEL = "com.zfk.finalize-no-dashboard-release"
ROOT = Path(__file__).resolve().parents[1]
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


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


def build_plist(
    *,
    bundle_dir: Path,
    source_binary: Path,
    desktop_binary: Path,
    gate_report: Path,
    soak_report: Path,
    soak_progress: Path,
    installed_report: Path,
    assistant_bundle: Path,
) -> dict:
    log_dir = Path("/tmp/zkf-current-binary-finalize")
    log_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = log_dir / "launchd.stdout.log"
    stderr_log = log_dir / "launchd.stderr.log"
    return {
        "Label": LABEL,
        "ProgramArguments": [
            "/usr/bin/python3",
            str(ROOT / "scripts" / "finalize_no_dashboard_release.py"),
            "--bundle-dir",
            str(bundle_dir),
            "--source-binary",
            str(source_binary),
            "--desktop-binary",
            str(desktop_binary),
            "--gate-report",
            str(gate_report),
            "--soak-report",
            str(soak_report),
            "--soak-progress",
            str(soak_progress),
            "--installed-report",
            str(installed_report),
            "--assistant-bundle",
            str(assistant_bundle),
        ],
        "WorkingDirectory": str(ROOT),
        "RunAtLoad": True,
        "KeepAlive": False,
        "StandardOutPath": str(stdout_log),
        "StandardErrorPath": str(stderr_log),
        "EnvironmentVariables": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/opt/homebrew/sbin"
        },
        "ProcessType": "Background",
    }


def cmd_start(args: argparse.Namespace) -> int:
    plist = build_plist(
        bundle_dir=args.bundle_dir.resolve(),
        source_binary=args.source_binary.resolve(),
        desktop_binary=args.desktop_binary.resolve(),
        gate_report=args.gate_report.resolve(),
        soak_report=args.soak_report.resolve(),
        soak_progress=args.soak_progress.resolve(),
        installed_report=args.installed_report.resolve(),
        assistant_bundle=args.assistant_bundle.resolve(),
    )
    PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PLIST_PATH.open("wb") as fh:
        plistlib.dump(plist, fh, sort_keys=True)

    domain = gui_domain()
    run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=False)
    run(["launchctl", "bootstrap", domain, str(PLIST_PATH)])
    print(f"started {LABEL}")
    print(f"plist: {PLIST_PATH}")
    print("stdout: /tmp/zkf-current-binary-finalize/launchd.stdout.log")
    print("stderr: /tmp/zkf-current-binary-finalize/launchd.stderr.log")
    return 0


def cmd_stop(_: argparse.Namespace) -> int:
    domain = gui_domain()
    run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=False)
    print(f"stopped {LABEL}")
    return 0


def cmd_status(_: argparse.Namespace) -> int:
    domain = gui_domain()
    proc = run(["launchctl", "print", f"{domain}/{LABEL}"], check=False)
    if proc.returncode != 0:
        print(f"{LABEL}: not loaded")
        if PLIST_PATH.exists():
            print(f"plist: {PLIST_PATH}")
        return 1
    print(proc.stdout)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Manage the no-dashboard release finalizer under launchd.")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="start or restart the finalizer under launchd")
    start.add_argument("--bundle-dir", type=Path, required=True)
    start.add_argument("--source-binary", type=Path, required=True)
    start.add_argument("--desktop-binary", type=Path, required=True)
    start.add_argument("--gate-report", type=Path, required=True)
    start.add_argument("--soak-report", type=Path, required=True)
    start.add_argument("--soak-progress", type=Path, required=True)
    start.add_argument("--installed-report", type=Path, required=True)
    start.add_argument("--assistant-bundle", type=Path, required=True)
    start.set_defaults(func=cmd_start)

    stop = sub.add_parser("stop", help="stop the finalizer launch agent")
    stop.set_defaults(func=cmd_stop)

    status = sub.add_parser("status", help="show launchd status for the finalizer")
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
