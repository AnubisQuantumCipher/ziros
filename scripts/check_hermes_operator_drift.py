#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "docs" / "agent" / "HERMES_OPERATOR_CONTRACT.json"
MANIFEST_PATH = ROOT / "setup" / "hermes" / "manifest.json"
STATUS_PATH = ROOT / "forensics" / "generated" / "hermes_operator_status.json"
DRIFT_PATH = ROOT / "forensics" / "generated" / "hermes_operator_drift.json"


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def hermes_home_root() -> Path:
    override = os.environ.get("HERMES_HOME")
    if override:
        return Path(override)
    return Path.home() / ".hermes"


def non_canonical_state() -> list[str]:
    contract = load_json(CONTRACT_PATH)
    return contract.get("non_canonical_operator_state", [])


def inspect_config(manifest: dict) -> tuple[dict, list[dict]]:
    config_path = hermes_home_root() / "config.yaml"
    if not config_path.exists():
        return (
            {
                "path": str(config_path),
                "exists": False,
                "operator_profile": None,
                "repo_root": None,
                "pack_root": None,
                "auto_load_rule_present": False,
                "missing_skills": manifest["managed_config"]["autoload_skills"],
            },
            [
                {
                    "code": "config-missing",
                    "severity": "error",
                    "message": "Hermes config.yaml is missing",
                    "path": str(config_path),
                }
            ],
        )

    text = config_path.read_text(encoding="utf-8", errors="ignore")
    missing_skills = [
        skill
        for skill in manifest["managed_config"]["autoload_skills"]
        if skill not in text
    ]
    auto_load_rule_present = manifest["managed_config"]["cwd_prefix"] in text
    status = {
        "path": str(config_path),
        "exists": True,
        "operator_profile": manifest["managed_config"]["operator_profile"]
        if f"operator_profile: {manifest['managed_config']['operator_profile']}" in text
        else None,
        "repo_root": str(ROOT) if str(ROOT) in text else None,
        "pack_root": str(hermes_home_root() / "ziros-pack")
        if str(hermes_home_root() / "ziros-pack") in text
        else None,
        "auto_load_rule_present": auto_load_rule_present,
        "missing_skills": missing_skills,
    }
    issues: list[dict] = []
    if status["operator_profile"] is None:
        issues.append(
            {
                "code": "config-profile-mismatch",
                "severity": "error",
                "message": "Hermes config does not advertise the rigorous ZirOS operator profile",
                "path": str(config_path),
            }
        )
    if status["repo_root"] is None:
        issues.append(
            {
                "code": "config-repo-root-mismatch",
                "severity": "error",
                "message": "Hermes config repo_root does not match the current ZirOS checkout",
                "path": str(config_path),
            }
        )
    if status["pack_root"] is None:
        issues.append(
            {
                "code": "config-pack-root-mismatch",
                "severity": "error",
                "message": "Hermes config pack_root does not match the managed install root",
                "path": str(config_path),
            }
        )
    if not auto_load_rule_present:
        issues.append(
            {
                "code": "config-autoload-rule-missing",
                "severity": "error",
                "message": "Hermes config is missing the ZirOS auto-load skill rule",
                "path": str(config_path),
            }
        )
    if missing_skills:
        issues.append(
            {
                "code": "config-autoload-skills-missing",
                "severity": "error",
                "message": "Hermes config is missing required ZirOS auto-load skills: "
                + ", ".join(missing_skills),
                "path": str(config_path),
            }
        )
    return status, issues


def build_status() -> dict:
    manifest = load_json(MANIFEST_PATH)
    pack_root = hermes_home_root() / "ziros-pack"
    lock_path = hermes_home_root() / "ziros-pack.lock.json"
    assets = []
    violations: list[dict] = []
    for asset in manifest["assets"]:
        source = ROOT / asset["source"]
        target = pack_root / asset["target"]
        expected_sha = sha256_file(source)
        actual_sha = sha256_file(target) if target.exists() else None
        installed = target.exists()
        sha_match = installed and actual_sha == expected_sha
        assets.append(
            {
                "id": asset["id"],
                "kind": asset["kind"],
                "source_path": str(source),
                "target_path": str(target),
                "expected_sha256": expected_sha,
                "installed": installed,
                "actual_sha256": actual_sha,
                "sha256_match": sha_match,
            }
        )
        if not installed:
            violations.append(
                {
                    "code": "missing-managed-asset",
                    "severity": "error",
                    "message": f"managed Hermes asset '{asset['id']}' is missing",
                    "path": str(target),
                }
            )
        elif not sha_match:
            violations.append(
                {
                    "code": "asset-sha-mismatch",
                    "severity": "error",
                    "message": f"managed Hermes asset '{asset['id']}' drifted from the repo copy",
                    "path": str(target),
                }
            )

    config_status, config_issues = inspect_config(manifest)
    violations.extend(config_issues)

    if not lock_path.exists():
        violations.append(
            {
                "code": "lock-missing",
                "severity": "error",
                "message": "Hermes pack lock file is missing",
                "path": str(lock_path),
            }
        )
        lock_present = False
    else:
        lock_present = True
        lock = load_json(lock_path)
        if lock.get("manifest_sha256") != sha256_file(MANIFEST_PATH):
            violations.append(
                {
                    "code": "lock-manifest-mismatch",
                    "severity": "error",
                    "message": "Hermes pack lock was generated from a different manifest",
                    "path": str(lock_path),
                }
            )

    doctor_ok = not violations
    install_complete = (
        all(asset["installed"] and asset["sha256_match"] for asset in assets)
        and config_status["exists"]
        and config_status["auto_load_rule_present"]
        and not config_status["missing_skills"]
        and lock_present
    )
    return {
        "schema": "ziros-hermes-operator-status-v1",
        "generated_at": now_rfc3339(),
        "operator_profile": "hermes-rigorous",
        "repo_root": str(ROOT),
        "hermes_home": str(hermes_home_root()),
        "pack_root": str(pack_root),
        "lock_path": str(lock_path),
        "contract_path": str(CONTRACT_PATH),
        "manifest_path": str(MANIFEST_PATH),
        "install_complete": install_complete,
        "doctor_ok": doctor_ok,
        "lock_present": lock_present,
        "config": config_status,
        "assets": assets,
        "non_canonical_state": non_canonical_state(),
        "violations": violations,
    }


def build_drift_report(status: dict) -> dict:
    return {
        "schema": "ziros-hermes-operator-drift-v1",
        "generated_at": now_rfc3339(),
        "healthy": status["doctor_ok"],
        "missing_assets": [
            asset["id"] for asset in status["assets"] if not asset["installed"]
        ],
        "changed_assets": [
            asset["id"]
            for asset in status["assets"]
            if asset["installed"] and not asset["sha256_match"]
        ],
        "config_issues": [
            issue for issue in status["violations"] if issue["code"].startswith("config-")
        ],
        "lock_issues": [
            issue for issue in status["violations"] if issue["code"].startswith("lock-")
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-report", action="store_true")
    parser.add_argument("--status-path", type=Path, default=STATUS_PATH)
    parser.add_argument("--drift-path", type=Path, default=DRIFT_PATH)
    args = parser.parse_args()

    status = build_status()
    drift = build_drift_report(status)
    if args.write_report:
        write_json(args.status_path, status)
        write_json(args.drift_path, drift)
    if status["doctor_ok"]:
        print("Hermes operator pack is in sync")
        return 0
    for issue in status["violations"]:
        print(f"{issue['code']}: {issue['message']}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
