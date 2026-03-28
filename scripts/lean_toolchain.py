#!/usr/bin/env python3

from __future__ import annotations

import os
import shutil
from pathlib import Path


LEAN_TOOLCHAIN = "leanprover/lean4:v4.28.0"


def _home_elan_binary(name: str) -> Path:
    return Path.home() / ".elan" / "bin" / name


def _executable_or_none(path: Path) -> str | None:
    if path.is_file() and os.access(path, os.X_OK):
        return str(path)
    return None


def _direct_tool(name: str) -> str | None:
    on_path = shutil.which(name)
    if on_path:
        return on_path
    return _executable_or_none(_home_elan_binary(name))


def _elan_tool() -> str | None:
    on_path = shutil.which("elan")
    if on_path:
        return on_path
    return _executable_or_none(_home_elan_binary("elan"))


def tool_cmd_prefix(name: str) -> list[str]:
    direct_tool = _direct_tool(name)
    if direct_tool:
        return [direct_tool]

    elan_tool = _elan_tool()
    if elan_tool:
        return [elan_tool, "run", LEAN_TOOLCHAIN, name]

    raise SystemExit(
        f"{name} from Lean 4.28.0 is required; expected `{name}` on PATH, "
        f"`$HOME/.elan/bin/{name}`, or an `elan` launcher"
    )


def lean_cmd_prefix() -> list[str]:
    return tool_cmd_prefix("lean")


def lake_cmd_prefix() -> list[str]:
    return tool_cmd_prefix("lake")
