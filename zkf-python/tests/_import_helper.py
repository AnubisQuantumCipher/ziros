from __future__ import annotations

import importlib
import os
import shutil
import sys
import sysconfig
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_TEMP_DIR: tempfile.TemporaryDirectory[str] | None = None


def _candidate_library_paths(target_dir: Path) -> list[Path]:
    return [
        target_dir / "libzkf.dylib",
        target_dir / "libzkf.so",
        target_dir / "zkf.dll",
        target_dir / "zkf.pyd",
    ]


def import_zkf():
    global _TEMP_DIR

    if "zkf" in sys.modules:
        return sys.modules["zkf"]

    target_dir = Path(
        os.environ.get("ZKF_PYTHON_TARGET_DIR", ROOT / "target" / "debug")
    ).expanduser()
    library = next((path for path in _candidate_library_paths(target_dir) if path.exists()), None)
    if library is None:
        raise RuntimeError(f"zkf extension library not found under {target_dir}")

    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    _TEMP_DIR = tempfile.TemporaryDirectory(prefix="zkf-python-tests-")
    temp_path = Path(_TEMP_DIR.name)
    importable_path = temp_path / f"zkf{ext_suffix}"
    shutil.copy2(library, importable_path)
    sys.path.insert(0, str(temp_path))
    return importlib.import_module("zkf")


def addition_program(field: str) -> str:
    return (
        "{"
        f"\"name\":\"python_{field}_roundtrip\","
        f"\"field\":\"{field}\","
        "\"signals\":["
        "{\"name\":\"x\",\"visibility\":\"private\"},"
        "{\"name\":\"y\",\"visibility\":\"private\"},"
        "{\"name\":\"sum\",\"visibility\":\"public\"}"
        "],"
        "\"constraints\":["
        "{"
        "\"kind\":\"equal\","
        "\"lhs\":{\"op\":\"signal\",\"args\":\"sum\"},"
        "\"rhs\":{\"op\":\"add\",\"args\":["
        "{\"op\":\"signal\",\"args\":\"x\"},"
        "{\"op\":\"signal\",\"args\":\"y\"}"
        "]}"
        "}"
        "],"
        "\"witness_plan\":{\"assignments\":[],\"hints\":[]}"
        "}"
    )
