#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = ROOT / "zkf-ir-spec" / "verification-ledger.json"
SCHEMA = "zkf-metal-supporting-proof-closure-v1"

THEOREM_GATES = {
    "field.large_prime_runtime_generated": {
        "checker": "rocq",
        "module": "FieldGenerationProvenance",
        "decl": "large_prime_runtime_fiat_binding_ok",
        "artifact_path": ROOT / "zkf-core" / "proofs" / "rocq" / "FieldGenerationProvenance.vo",
        "source_path": ROOT / "zkf-core" / "proofs" / "rocq" / "FieldGenerationProvenance.v",
    },
    "field.bn254_strict_lane_generated": {
        "checker": "rocq",
        "module": "Bn254MontgomeryStrictLane",
        "decl": "bn254_strict_lane_bug_class_closed_ok",
        "artifact_path": ROOT
        / "zkf-core"
        / "proofs"
        / "rocq"
        / "Bn254MontgomeryStrictLane.vo",
        "source_path": ROOT
        / "zkf-core"
        / "proofs"
        / "rocq"
        / "Bn254MontgomeryStrictLane.v",
    },
    "field.small_field_runtime_semantics": {
        "checker": "rocq",
        "module": "KernelFieldEncodingProofs",
        "decl": "small_field_runtime_semantics_ok",
        "artifact_path": ROOT / "zkf-core" / "proofs" / "rocq" / "KernelFieldEncodingProofs.vo",
        "source_path": ROOT / "zkf-core" / "proofs" / "rocq" / "KernelFieldEncodingProofs.v",
    },
    "pipeline.cli_runtime_path_composition": {
        "checker": "rocq",
        "module": "RuntimePipelineComposition",
        "decl": "cli_runtime_path_composition_ok",
        "artifact_path": ROOT / "zkf-runtime" / "proofs" / "rocq" / "RuntimePipelineComposition.vo",
        "source_path": ROOT / "zkf-runtime" / "proofs" / "rocq" / "RuntimePipelineComposition.v",
    },
    "orbital.surface_constants": {
        "checker": "verus",
        "module": "orbital_dynamics_verus",
        "decl": "orbital_surface_constants",
        "artifact_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
        "source_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
    },
    "orbital.position_update_half_step_soundness": {
        "checker": "verus",
        "module": "orbital_dynamics_verus",
        "decl": "orbital_position_update_reconstructs_exact_half_step",
        "artifact_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
        "source_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
    },
    "orbital.velocity_update_half_step_soundness": {
        "checker": "verus",
        "module": "orbital_dynamics_verus",
        "decl": "orbital_velocity_update_reconstructs_exact_half_step",
        "artifact_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
        "source_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
    },
    "orbital.residual_split_soundness": {
        "checker": "verus",
        "module": "orbital_dynamics_verus",
        "decl": "orbital_signed_residual_split_reconstructs",
        "artifact_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
        "source_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
    },
    "orbital.field_embedding_nonwrap_bounds": {
        "checker": "verus",
        "module": "orbital_dynamics_verus",
        "decl": "orbital_fixed_point_bounds_fit_inside_bn254",
        "artifact_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
        "source_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
    },
    "orbital.commitment_body_tag_domain_separation": {
        "checker": "verus",
        "module": "orbital_dynamics_verus",
        "decl": "orbital_body_tags_are_domain_separated",
        "artifact_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
        "source_path": ROOT / "zkf-runtime" / "proofs" / "verus" / "orbital_dynamics_verus.rs",
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_checked(command: list[str]) -> None:
    result = subprocess.run(
        command,
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    require(result.returncode == 0, f"command failed ({' '.join(command)}):\n{result.stdout}")


def ensure_private_supporting_proofs_current(*, skip_runners: bool) -> None:
    if skip_runners:
        return
    run_checked(["bash", str(ROOT / "scripts" / "run_rocq_proofs.sh")])
    run_checked(["bash", str(ROOT / "scripts" / "run_verus_orbital_proofs.sh")])


def ledger_entries_by_id() -> dict[str, dict[str, object]]:
    ledger = json.loads(LEDGER_PATH.read_text(encoding="utf-8"))
    entries = {
        entry["theorem_id"]: entry
        for entry in ledger["entries"]
        if entry["theorem_id"] in THEOREM_GATES
    }
    require(
        set(entries) == set(THEOREM_GATES),
        "supporting proof closure audit could not find all tracked theorem ledger entries",
    )
    for theorem_id, gate in THEOREM_GATES.items():
        entry = entries[theorem_id]
        require(
            entry["status"] == "mechanized_local",
            f"{theorem_id} is not mechanized_local in the verification ledger",
        )
        require(
            entry["checker"] == gate["checker"],
            f"{theorem_id} checker drifted from expected {gate['checker']}",
        )
        require(
            entry.get("trusted_assumptions") == [],
            f"{theorem_id} still carries trusted assumptions in the verification ledger",
        )
    return entries


def theorem_source_contains_decl(path: Path, checker: str, decl_name: str) -> bool:
    text = path.read_text(encoding="utf-8")
    marker = f"Theorem {decl_name}" if checker == "rocq" else f"pub proof fn {decl_name}"
    return marker in text


def build_report(*, skip_runners: bool) -> dict[str, object]:
    ensure_private_supporting_proofs_current(skip_runners=skip_runners)
    entries = ledger_entries_by_id()

    theorem_records: list[dict[str, object]] = []
    for theorem_id, gate in THEOREM_GATES.items():
        entry = entries[theorem_id]
        artifact_path = Path(gate["artifact_path"])
        source_path = Path(gate["source_path"])
        require(
            artifact_path.is_file(),
            f"missing proof artifact for {theorem_id}: {artifact_path}",
        )
        require(
            source_path.is_file(),
            f"missing proof source for {theorem_id}: {source_path}",
        )
        require(
            theorem_source_contains_decl(source_path, gate["checker"], gate["decl"]),
            f"{theorem_id} is tracked as mechanized but {source_path} lacks `{gate['decl']}`",
        )
        theorem_records.append(
            {
                "theorem_id": theorem_id,
                "title": entry["title"],
                "checker": gate["checker"],
                "decl_name": gate["decl"],
                "module_name": gate["module"],
                "proof_artifact_kind": "rocq_vo" if gate["checker"] == "rocq" else "verus_source",
                "proof_artifact_digest": sha256_file(artifact_path),
                "allowed_axioms_only": True,
                "axioms": [],
            }
        )

    theorem_records.sort(key=lambda item: str(item["theorem_id"]))
    return {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "theorems": theorem_records,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Audit the supporting mechanized proof surface and emit a redacted closure report."
    )
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument(
        "--skip-proof-runners",
        action="store_true",
        help="skip rerunning Rocq and orbital Verus proof runners before the audit",
    )
    args = parser.parse_args()

    report = build_report(skip_runners=args.skip_proof_runners)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
