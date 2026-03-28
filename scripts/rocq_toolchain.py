#!/usr/bin/env python3

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def _executable_or_none(path: Path) -> str | None:
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return None


def _home_opam_bin(name: str) -> str | None:
    for switch in ("default", "hax-5.1.1"):
        resolved = _executable_or_none(Path.home() / ".opam" / switch / "bin" / name)
        if resolved:
            return resolved
    return None


def _opam_var_bin() -> Path | None:
    opam = shutil.which("opam")
    if not opam:
        return None
    result = subprocess.run(
        [opam, "var", "bin"],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    resolved = result.stdout.strip()
    if not resolved:
        return None
    return Path(resolved)


def rocq_tool(name: str) -> str:
    on_path = shutil.which(name)
    if on_path:
        return on_path

    opam_bin = _opam_var_bin()
    if opam_bin is not None:
        resolved = _executable_or_none(opam_bin / name)
        if resolved:
            return resolved

    home_opam = _home_opam_bin(name)
    if home_opam:
        return home_opam

    raise SystemExit(
        f"{name} is required to audit Rocq proofs; expected `{name}` on PATH, "
        "`opam var bin`, or a local `~/.opam/<switch>/bin` installation"
    )
