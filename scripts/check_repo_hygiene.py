#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path


FORBIDDEN_PATH_PATTERNS = [
    re.compile(r"(^|/)\.DS_Store$"),
    re.compile(r"(^|/)__MACOSX(/|$)"),
    re.compile(r"(^|/)__pycache__(/|$)"),
    re.compile(r"\.pyc$"),
    re.compile(r"(^|/)\.venv-coreml(/|$)"),
    re.compile(r"(^|/)target-local(/|$)"),
    re.compile(r"(^|/)target-codex-build(/|$)"),
    re.compile(r"(^|/)target-[^/]+(/|$)"),
    re.compile(r"(^|/)out(/|$)"),
    re.compile(r"(^|/)cache(/|$)"),
    re.compile(r"(^|/)wrap_test(/|$)"),
    re.compile(r"(^|/)private_identity/target(/|$)"),
]

ABSOLUTE_PATH_PATTERNS = [
    re.compile(rb"/Users/[^/\s]+"),
    re.compile(rb"/home/[^/\s]+"),
    re.compile(rb"/var/folders/[^/\s]+"),
]

SECRET_PATTERNS = [
    re.compile(rb"OPENAI_API_KEY\s*=\s*[A-Za-z0-9_\-]{20,}"),
    re.compile(rb"ghp_[A-Za-z0-9]{20,}"),
    re.compile(rb"sk-[A-Za-z0-9]{20,}"),
]

TEXT_SCAN_SUFFIXES = {
    ".md",
    ".json",
    ".toml",
    ".yml",
    ".yaml",
    ".py",
    ".sh",
    ".txt",
}

TEXT_SCAN_ROOTS = {
    ".github",
    "scripts",
}

OVERSIZE_ALLOWLIST: set[Path] = set()

ABSOLUTE_PATH_SCAN_FILES = {
    Path("README.md"),
    Path("SECURITY.md"),
    Path("CONTRIBUTING.md"),
    Path("docs/SECURITY.md"),
}

ABSOLUTE_PATH_SCAN_SCRIPT_PREFIXES = (
    "scripts/check_",
    "scripts/run_protocol_lean_proofs.sh",
    "scripts/run_verus_powered_descent_proofs.sh",
)


def git_ls_files() -> list[Path]:
    output = subprocess.check_output(["git", "ls-files", "-z"])
    return [Path(item.decode()) for item in output.split(b"\x00") if item]


def is_probably_text(path: Path) -> bool:
    try:
        data = path.read_bytes()[:4096]
    except (FileNotFoundError, OSError):
        return False
    return b"\x00" not in data


def should_scan_contents(path: Path) -> bool:
    if path.suffix.lower() not in TEXT_SCAN_SUFFIXES:
        return False
    if len(path.parts) == 1:
        return True
    return path.parts[0] in TEXT_SCAN_ROOTS


def should_scan_absolute_paths(path: Path) -> bool:
    if path in ABSOLUTE_PATH_SCAN_FILES:
        return True
    path_str = path.as_posix()
    return any(path_str.startswith(prefix) for prefix in ABSOLUTE_PATH_SCAN_SCRIPT_PREFIXES)


def main() -> int:
    parser = argparse.ArgumentParser(description="Fail on repo hygiene regressions.")
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=50 * 1024 * 1024,
        help="maximum tracked file size before the check fails",
    )
    args = parser.parse_args()

    failures: list[str] = []
    for path in git_ls_files():
        path_str = path.as_posix()
        for pattern in FORBIDDEN_PATH_PATTERNS:
            if pattern.search(path_str):
                failures.append(f"forbidden tracked path: {path_str}")
                break
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            continue
        if size > args.max_bytes and path not in OVERSIZE_ALLOWLIST:
            failures.append(f"oversized tracked file ({size} bytes): {path_str}")
        if not should_scan_contents(path) or not is_probably_text(path):
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            failures.append(f"failed to read {path_str}: {exc}")
            continue
        if should_scan_absolute_paths(path):
            for pattern in ABSOLUTE_PATH_PATTERNS:
                if pattern.search(data):
                    failures.append(f"absolute-path leak in {path_str}")
                    break
        for pattern in SECRET_PATTERNS:
            if pattern.search(data):
                failures.append(f"secret-like token in {path_str}")
                break

    if failures:
        print("repo hygiene check failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("repo hygiene check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
