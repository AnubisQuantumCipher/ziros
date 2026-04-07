#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = ROOT / "release" / "public_release_allowlist.json"
REPORT_PATH = ROOT / "release" / "public_release_boundary_report.json"


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def run(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        list(args),
        cwd=cwd or ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def git_dirty() -> bool:
    return bool(run("git", "status", "--short").strip())


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def normalize_path(value: str) -> str:
    return value.replace("\\", "/")


def forbidden_issues_for_path(path: str, allowlist: dict) -> list[str]:
    issues: list[str] = []
    normalized = normalize_path(path)
    for fragment in allowlist["forbidden_path_fragments"]:
        if fragment in normalized:
            issues.append(f"forbidden path fragment '{fragment}' in '{normalized}'")
    for suffix in allowlist["forbidden_suffixes"]:
        if normalized.endswith(suffix):
            issues.append(f"forbidden suffix '{suffix}' in '{normalized}'")
    return issues


def npm_pack_report(package_root: Path, allowlist: dict) -> dict:
    result = subprocess.run(
        ["npm", "pack", "--json", "--dry-run"],
        cwd=package_root,
        capture_output=True,
        text=True,
    )
    issues: list[str] = []
    packed_files: list[str] = []
    payload = None
    if result.returncode != 0:
        issues.append(result.stderr.strip() or result.stdout.strip() or "npm pack failed")
    else:
        payload = json.loads(result.stdout or "[]")
        files = payload[0].get("files", []) if payload else []
        for entry in files:
            entry_path = entry.get("path", "")
            packed_files.append(entry_path)
            issues.extend(forbidden_issues_for_path(entry_path, allowlist))
    return {
        "package_root": package_root.relative_to(ROOT).as_posix(),
        "packed_files": packed_files,
        "issues": sorted(set(issue for issue in issues if issue)),
        "raw": payload,
    }


def staging_report(staging_root: Path, allowlist: dict) -> dict:
    issues: list[str] = []
    files: list[str] = []
    if not staging_root.exists():
        return {
            "staging_root": staging_root.as_posix(),
            "files": files,
            "issues": [f"staging root '{staging_root}' does not exist"],
        }
    for path in sorted(staging_root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(staging_root).as_posix()
        files.append(rel)
        issues.extend(forbidden_issues_for_path(rel, allowlist))
        if path.suffix.lower() not in set(allowlist["allowed_public_extensions"]):
            issues.append(f"disallowed public extension '{path.suffix.lower() or '<no-ext>'}' in '{rel}'")
    return {
        "staging_root": staging_root.as_posix(),
        "files": files,
        "issues": sorted(set(issues)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--staging-root", type=Path)
    parser.add_argument("--require-clean", action="store_true")
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()

    allowlist = load_json(ALLOWLIST_PATH)
    package_reports = [
        npm_pack_report(ROOT / relative_root, allowlist)
        for relative_root in allowlist["package_roots"]
    ]
    staging = staging_report(args.staging_root, allowlist) if args.staging_root else None

    issues: list[str] = []
    if args.require_clean and git_dirty():
        issues.append("git working tree is dirty")
    for report in package_reports:
        issues.extend(report["issues"])
    if staging:
        issues.extend(staging["issues"])

    payload = {
        "schema": "ziros-public-release-boundary-report-v1",
        "generated_at": now_rfc3339(),
        "working_tree_dirty": git_dirty(),
        "require_clean": args.require_clean,
        "package_reports": package_reports,
        "staging_report": staging,
        "issues": sorted(set(issues)),
        "ok": not issues,
    }
    if args.write_report:
        write_json(REPORT_PATH, payload)
    if issues:
        for issue in payload["issues"]:
            print(issue)
        return 1
    print(REPORT_PATH.relative_to(ROOT).as_posix() if args.write_report else "public release boundary check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
