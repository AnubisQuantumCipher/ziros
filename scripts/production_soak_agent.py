#!/usr/bin/env python3
"""Launch the production soak under macOS launchd.

This keeps the soak alive independently of Codex exec sessions, terminal tabs,
or other parent-shell lifetimes. It is meant for long-running certification on
the local machine.
"""

from __future__ import annotations

import argparse
import plistlib
import subprocess
import sys
from pathlib import Path


LABEL = "com.zfk.production-soak"
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
    proof: Path,
    compiled: Path,
    out_dir: Path,
    json_out: Path,
    bin_path: Path,
    parallel_jobs: str,
    hours: int,
    cycles: int,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = out_dir / "launchd.stdout.log"
    stderr_log = out_dir / "launchd.stderr.log"
    program_arguments = [
        str(ROOT / "scripts" / "production_soak.sh"),
        "--proof",
        str(proof),
        "--compiled",
        str(compiled),
        "--out-dir",
        str(out_dir),
        "--json-out",
        str(json_out),
        "--bin",
        str(bin_path),
        "--parallel-jobs",
        parallel_jobs,
        "--hours",
        str(hours),
        "--cycles",
        str(cycles),
    ]
    return {
        "Label": LABEL,
        "ProgramArguments": program_arguments,
        "WorkingDirectory": str(ROOT),
        "RunAtLoad": True,
        # Relaunch if the soak process crashes, but do not loop forever on an
        # intentional non-zero certification failure.
        "KeepAlive": {"Crashed": True},
        "StandardOutPath": str(stdout_log),
        "StandardErrorPath": str(stderr_log),
        "EnvironmentVariables": {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/opt/homebrew/sbin"
        },
        "ProcessType": "Background",
    }


def cmd_start(args: argparse.Namespace) -> int:
    plist = build_plist(
        proof=args.proof.resolve(),
        compiled=args.compiled.resolve(),
        out_dir=args.out_dir.resolve(),
        json_out=args.json_out.resolve(),
        bin_path=args.bin.resolve(),
        parallel_jobs=args.parallel_jobs,
        hours=args.hours,
        cycles=args.cycles,
    )
    PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PLIST_PATH.open("wb") as fh:
        plistlib.dump(plist, fh, sort_keys=True)

    domain = gui_domain()
    run(["launchctl", "bootout", f"{domain}/{LABEL}"], check=False)
    run(["launchctl", "bootstrap", domain, str(PLIST_PATH)])
    print(f"started {LABEL}")
    print(f"plist: {PLIST_PATH}")
    print(f"out_dir: {args.out_dir.resolve()}")
    print(f"stdout: {(args.out_dir.resolve() / 'launchd.stdout.log')}")
    print(f"stderr: {(args.out_dir.resolve() / 'launchd.stderr.log')}")
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
    parser = argparse.ArgumentParser(description="Manage the long-running ZKF production soak under launchd.")
    sub = parser.add_subparsers(dest="command", required=True)

    start = sub.add_parser("start", help="start or restart the soak under launchd")
    start.add_argument("--proof", type=Path, required=True)
    start.add_argument("--compiled", type=Path, required=True)
    start.add_argument("--out-dir", type=Path, required=True)
    start.add_argument("--json-out", type=Path, required=True)
    start.add_argument("--bin", type=Path, default=ROOT / "target" / "release" / "zkf-cli")
    start.add_argument("--parallel-jobs", default="1")
    start.add_argument("--hours", type=int, default=12)
    start.add_argument("--cycles", type=int, default=20)
    start.set_defaults(func=cmd_start)

    stop = sub.add_parser("stop", help="stop the soak launch agent")
    stop.set_defaults(func=cmd_stop)

    status = sub.add_parser("status", help="show launchd status for the soak")
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
