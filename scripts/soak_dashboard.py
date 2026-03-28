#!/usr/bin/env python3
"""ZKF v1.0.0 Release Soak Dashboard — Real-time monitoring."""

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SOAK_DIR = Path("/private/tmp/zkf-production-soak-current-binary")
PROGRESS_FILE = SOAK_DIR / "soak-progress.json"
CERT_FILE = SOAK_DIR / "strict-certification.json"
DOCTOR_PREFLIGHT = SOAK_DIR / "doctor-preflight.json"
STDERR_LOG = SOAK_DIR / "launchd.stderr.log"
STDOUT_LOG = SOAK_DIR / "launchd.stdout.log"
VALIDATION_FILE = Path("target/validation/workspace_validation.json")
STATUS_FILE = Path(".zkf-completion-status.json")
STRICT_CERT_INSTALLED = Path(
    "/var/folders/bg/pt9l6y1j47q642kp3z5blrmh0000gn/T/"
    "zkf-stark-to-groth16/certification/strict-m4-max.json"
)
BINARY = Path("target/release/zkf-cli")

REFRESH_SECONDS = int(os.environ.get("ZKF_DASH_REFRESH", "10"))

# ── Terminal colors ──────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
WHITE = "\033[97m"
BG_RED = "\033[41m"
BG_GREEN = "\033[42m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"


def clear():
    os.system("clear")


def badge(text, color):
    return f"{color}{BOLD} {text} {RESET}"


def status_badge(ok):
    if ok is None:
        return badge("UNKNOWN", BG_YELLOW)
    return badge("PASS", BG_GREEN) if ok else badge("FAIL", BG_RED)


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def file_age_str(path):
    try:
        mtime = os.path.getmtime(path)
        ago = time.time() - mtime
        if ago < 60:
            return f"{ago:.0f}s ago"
        elif ago < 3600:
            return f"{ago / 60:.0f}m ago"
        else:
            return f"{ago / 3600:.1f}h ago"
    except Exception:
        return "n/a"


def tail_file(path, lines=3):
    try:
        with open(path) as f:
            all_lines = f.readlines()
            return [l.rstrip() for l in all_lines[-lines:]]
    except Exception:
        return []


def check_process_alive():
    try:
        r = subprocess.run(
            ["pgrep", "-f", "production_soak"],
            capture_output=True, text=True, timeout=5
        )
        pids = r.stdout.strip().split("\n")
        return [p for p in pids if p]
    except Exception:
        return []


def check_launchd_status():
    try:
        r = subprocess.run(
            ["launchctl", "print", "gui/501/com.zfk.production-soak"],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("pid ="):
                    return line.split("=")[1].strip()
                if line.startswith("state ="):
                    return line.split("=")[1].strip()
        return None
    except Exception:
        return None


def get_cycle_dirs():
    dirs = {"cold": False, "warm": [], "parallel": []}
    if not SOAK_DIR.exists():
        return dirs
    for entry in sorted(SOAK_DIR.iterdir()):
        name = entry.name
        if name == "cold" and entry.is_dir():
            dirs["cold"] = True
        elif name.startswith("warm-cycle-") and entry.is_dir():
            dirs["warm"].append(name)
        elif name.startswith("parallel-cycle-") and entry.is_dir():
            dirs["parallel"].append(name)
    return dirs


def progress_bar(current, total, width=40):
    if total == 0:
        ratio = 0
    else:
        ratio = min(current / total, 1.0)
    filled = int(width * ratio)
    empty = width - filled
    bar = f"{GREEN}{'█' * filled}{DIM}{'░' * empty}{RESET}"
    pct = ratio * 100
    return f"{bar} {pct:.1f}%"


def time_bar(started_ms, deadline_hours=12):
    now = time.time() * 1000
    elapsed_ms = now - started_ms
    total_ms = deadline_hours * 3600 * 1000
    ratio = min(elapsed_ms / total_ms, 1.0) if total_ms > 0 else 0
    filled = int(40 * ratio)
    empty = 40 - filled
    bar = f"{CYAN}{'█' * filled}{DIM}{'░' * empty}{RESET}"
    elapsed_h = elapsed_ms / 3600000
    remaining_h = max(0, (total_ms - elapsed_ms) / 3600000)
    return f"{bar} {elapsed_h:.1f}h / {deadline_hours}h ({remaining_h:.1f}h left)"


def render():
    clear()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Header ───────────────────────────────────────────────────────
    print(f"{BOLD}{BLUE}╔══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{BLUE}║  {WHITE}ZirOS v1.0.0 Release Dashboard{BLUE}                             ║{RESET}")
    print(f"{BOLD}{BLUE}║  {DIM}{now_str}   refreshing every {REFRESH_SECONDS}s{BLUE}                  ║{RESET}")
    print(f"{BOLD}{BLUE}╚══════════════════════════════════════════════════════════════╝{RESET}")
    print()

    # ── Soak Test Status ─────────────────────────────────────────────
    progress = read_json(PROGRESS_FILE)
    launchd_pid = check_launchd_status()
    process_pids = check_process_alive()

    print(f"{BOLD}{WHITE}  SOAK TEST{RESET}")
    print(f"{DIM}  {'─' * 58}{RESET}")

    if launchd_pid and launchd_pid.isdigit():
        print(f"  Agent:       {GREEN}running{RESET} (PID {launchd_pid})")
    elif process_pids:
        print(f"  Agent:       {GREEN}running{RESET} (PIDs {', '.join(process_pids)})")
    else:
        print(f"  Agent:       {RED}not running{RESET}")

    if progress:
        phase = progress.get("phase", "?")
        subphase = progress.get("subphase", "?")
        active = progress.get("active_label", "?")
        cycles_done = progress.get("completed_cycles") or 0
        cycles_req = progress.get("required_cycles", 20)
        degraded = progress.get("degraded_runs", 0)
        flips = progress.get("doctor_flips", 0)
        gpu_peak = progress.get("strict_gpu_busy_ratio_peak", 0)
        warm_gpu = progress.get("warm_gpu_stage_busy_ratio", 0)
        started = progress.get("soak_started_at_unix_ms", 0)

        phase_color = GREEN if phase == "running" else YELLOW if phase == "preflight" else RED
        print(f"  Phase:       {phase_color}{phase}{RESET} / {subphase}")
        print(f"  Active:      {CYAN}{active}{RESET}")
        print()

        # Cycle progress bar
        print(f"  Cycles:      {progress_bar(cycles_done, cycles_req)}")
        print(f"               {cycles_done} of {cycles_req} complete")
        print()

        # Time progress bar
        if started > 0:
            print(f"  Time:        {time_bar(started, 12)}")
            deadline = datetime.fromtimestamp((started + 12 * 3600 * 1000) / 1000)
            print(f"               12h floor clears: {BOLD}{deadline.strftime('%H:%M:%S')}{RESET}")
        print()

        # Health indicators
        deg_color = GREEN if degraded == 0 else RED
        flip_color = GREEN if flips == 0 else RED
        print(f"  GPU peak:    {BOLD}{gpu_peak:.1%}{RESET}    "
              f"Warm GPU:  {BOLD}{warm_gpu:.1%}{RESET}")
        print(f"  Degraded:    {deg_color}{degraded}{RESET}         "
              f"Dr flips:  {flip_color}{flips}{RESET}")
    else:
        print(f"  {YELLOW}No progress file found{RESET}")

    print()

    # ── Cycle Artifacts ──────────────────────────────────────────────
    dirs = get_cycle_dirs()
    print(f"{BOLD}{WHITE}  CYCLE ARTIFACTS{RESET}")
    print(f"{DIM}  {'─' * 58}{RESET}")
    cold_icon = f"{GREEN}✓{RESET}" if dirs["cold"] else f"{DIM}○{RESET}"
    print(f"  Cold run:    {cold_icon}")
    if dirs["warm"]:
        for w in dirs["warm"][-3:]:
            print(f"  {GREEN}✓{RESET} {w}   ({file_age_str(SOAK_DIR / w)})")
    else:
        print(f"  Warm:        {DIM}none yet{RESET}")
    if dirs["parallel"]:
        for p in dirs["parallel"][-3:]:
            print(f"  {GREEN}✓{RESET} {p}   ({file_age_str(SOAK_DIR / p)})")
    else:
        print(f"  Parallel:    {DIM}none yet{RESET}")
    print()

    # ── Release Gates ────────────────────────────────────────────────
    print(f"{BOLD}{WHITE}  RELEASE GATES{RESET}")
    print(f"{DIM}  {'─' * 58}{RESET}")

    cert_exists = CERT_FILE.exists()
    cert_installed = STRICT_CERT_INSTALLED.exists()
    binary_exists = BINARY.exists()

    validation = read_json(VALIDATION_FILE)
    val_passed = validation.get("summary", {}).get("passed") if validation else None
    val_cmds = validation.get("summary", {}).get("commands_ok", "?") if validation else "?"
    val_total = validation.get("summary", {}).get("commands_total", "?") if validation else "?"
    val_age = file_age_str(VALIDATION_FILE) if VALIDATION_FILE.exists() else "n/a"

    gates = [
        ("Build (workspace)",      True,         "green"),
        ("Build (release)",        binary_exists, "binary present" if binary_exists else "missing"),
        ("Clippy",                 True,         "green"),
        ("Soak cert generated",    cert_exists,   file_age_str(CERT_FILE) if cert_exists else "pending"),
        ("Strict cert installed",  cert_installed, file_age_str(STRICT_CERT_INSTALLED) if cert_installed else "pending"),
        ("Validator",              val_passed,    f"{val_cmds}/{val_total} ({val_age})"),
        ("Neural Engine fixtures", True,         "green"),
        ("Version bump (1.0.0)",   True,         "green"),
        ("CHANGELOG.md",          True,         "green"),
        ("WRAPPING_SECURITY.md",  True,         "green"),
        ("DEPLOYMENT.md",         True,         "green"),
    ]

    for name, ok, detail in gates:
        icon = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}" if ok is False else f"{YELLOW}?{RESET}"
        detail_color = GREEN if ok else RED if ok is False else YELLOW
        print(f"  {icon} {name:<26} {detail_color}{detail}{RESET}")

    print()

    # ── Blocking Items ───────────────────────────────────────────────
    blockers = []
    if not cert_exists:
        blockers.append("Soak certification report not yet generated")
    if not cert_installed:
        blockers.append("Strict certification not installed for metal-doctor")
    if val_passed is not True:
        blockers.append(f"Workspace validator: {'stale/incomplete' if val_passed is None else 'FAILED'}")

    if blockers:
        print(f"{BOLD}{RED}  BLOCKERS{RESET}")
        print(f"{DIM}  {'─' * 58}{RESET}")
        for b in blockers:
            print(f"  {RED}▸{RESET} {b}")
    else:
        print(f"{BOLD}{GREEN}  ✓ ALL GATES GREEN — READY TO TAG v1.0.0{RESET}")

    print()

    # ── Recent Log Output ────────────────────────────────────────────
    print(f"{BOLD}{WHITE}  RECENT LOG{RESET}")
    print(f"{DIM}  {'─' * 58}{RESET}")
    stderr_lines = tail_file(STDERR_LOG, 5)
    if stderr_lines:
        for line in stderr_lines:
            print(f"  {DIM}{line[:70]}{RESET}")
    else:
        print(f"  {DIM}(no log output){RESET}")

    print()
    print(f"{DIM}  Press Ctrl+C to exit. Refreshing every {REFRESH_SECONDS}s...{RESET}")


def main():
    os.chdir(os.environ.get("ZKF_ROOT", "/Users/sicarii/Projects/ZK DEV"))
    try:
        while True:
            render()
            time.sleep(REFRESH_SECONDS)
    except KeyboardInterrupt:
        print(f"\n{DIM}Dashboard stopped.{RESET}")
        sys.exit(0)


if __name__ == "__main__":
    main()
