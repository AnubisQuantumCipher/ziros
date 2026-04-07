#!/usr/bin/env python3

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

HEADLINE_CONFORMANCE_BACKENDS = ["plonky3", "halo2", "nova", "hypernova"]
SUPPLEMENTAL_CONFORMANCE_BACKENDS = ["arkworks-groth16"]
CAPABILITY_MATRIX_FILES = {
    "backends": "backends.json",
    "frontends": "frontends.json",
    "gadgets": "gadgets.json",
    "post_quantum": "post-quantum.json",
}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def load_claim_source(path: Path):
    if path.suffix == ".json":
        return load_json(path)
    return path.read_text(encoding="utf-8").strip()


def canonical_sha256(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def without_keys(payload: dict, *keys: str) -> dict:
    clone = json.loads(json.dumps(payload))
    for key in keys:
        clone.pop(key, None)
    return clone


def json_pointer_get(document: object, pointer: str):
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise SystemExit(f"invalid JSON pointer: {pointer}")
    current = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    return current


def build_expected_conformance_summary(root: Path) -> dict:
    def row_for(backend: str) -> dict:
        payload = load_json(root / "conformance" / "latest" / f"{backend}.json")
        return {
            "backend": backend,
            "path": f"conformance/latest/{backend}.json",
            "tests_run": payload["tests_run"],
            "tests_passed": payload["tests_passed"],
            "tests_failed": payload["tests_failed"],
            "status": payload.get("status", "pass" if payload["tests_failed"] == 0 else "fail"),
        }

    headline_rows = [row_for(backend) for backend in HEADLINE_CONFORMANCE_BACKENDS]
    supplemental_rows = []
    for backend in SUPPLEMENTAL_CONFORMANCE_BACKENDS:
        path = root / "conformance" / "latest" / f"{backend}.json"
        if path.exists():
            supplemental_rows.append(row_for(backend))

    published_rows = headline_rows + supplemental_rows
    headline_tests_failed = sum(row["tests_failed"] for row in headline_rows)
    published_tests_failed = sum(row["tests_failed"] for row in published_rows)
    return {
        "headline_backend_ids": [row["backend"] for row in headline_rows],
        "headline_backend_count": len(headline_rows),
        "headline_tests_run": sum(row["tests_run"] for row in headline_rows),
        "headline_tests_passed": sum(row["tests_passed"] for row in headline_rows),
        "headline_tests_failed": headline_tests_failed,
        "headline_status": "pass" if headline_tests_failed == 0 else "fail",
        "published_backend_ids": [row["backend"] for row in published_rows],
        "published_backend_count": len(published_rows),
        "published_tests_run": sum(row["tests_run"] for row in published_rows),
        "published_tests_passed": sum(row["tests_passed"] for row in published_rows),
        "published_tests_failed": published_tests_failed,
        "published_status": "pass" if published_tests_failed == 0 else "fail",
        "headline_rows": headline_rows,
        "supplemental_rows": supplemental_rows,
    }


def build_expected_capability_summary(root: Path, version: str) -> dict:
    capability_root = root / "capability-matrix"
    payloads = {}
    for key, filename in CAPABILITY_MATRIX_FILES.items():
        payload = load_json(capability_root / filename)
        if payload.get("generated_for") != version:
            raise SystemExit(
                f"capability matrix {filename} generated_for={payload.get('generated_for')} != {version}"
            )
        payloads[key] = payload
    return {
        "backend_count": len(payloads["backends"]["backends"]),
        "backend_ids": [entry["id"] for entry in payloads["backends"]["backends"]],
        "frontend_count": len(payloads["frontends"]["frontends"]),
        "frontend_ids": [entry["id"] for entry in payloads["frontends"]["frontends"]],
        "gadget_count": len(payloads["gadgets"]["gadgets"]),
        "gadget_ids": [entry["id"] for entry in payloads["gadgets"]["gadgets"]],
        "post_quantum_component_count": len(payloads["post_quantum"]["components"]),
        "post_quantum_components": [
            entry["component"] for entry in payloads["post_quantum"]["components"]
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    args = parser.parse_args()

    root = Path(args.root)
    attestation = load_json(root / "attestation/latest.json")
    evidence = load_json(root / "evidence/evidence-package.json")
    publication = load_json(root / "publication/manifest.json")
    claim_graph = load_json(root / "claim-source-graph.json")
    hostile_verdict = load_json(root / "hostile-audit-verdict.json")
    workspace_census_summary = load_json(root / "workspace-census-summary.json")
    ledger_doc = load_json(root / "ledger/verification-ledger.json")
    ledger_summary = load_json(root / "ledger/ledger-summary.json")
    conformance_summary = load_json(root / "evidence/conformance-summary.json")
    capability_summary = load_json(root / "evidence/capability-summary.json")
    proof_inventory = load_json(root / "evidence/proof-file-inventory.json")
    protocol_registry = load_json(root / "evidence/protocol-proof-registry.json")
    ledger = ledger_doc.get("entries", [])
    ledger_file_sha = (root / "ledger/ledger-sha256.txt").read_text(encoding="utf-8").strip()

    if not ledger:
        raise SystemExit("verification ledger is empty")
    bad_rows = [row["theorem_id"] for row in ledger if row.get("status") != "mechanized_local"]
    if bad_rows:
        raise SystemExit(f"non-mechanized public ledger rows detected: {bad_rows[:5]}")
    if ledger_summary.get("pending_entries", 0) != 0:
        raise SystemExit("ledger-summary.json reports pending entries")
    claim = attestation["claims_verified"]["verification_ledger"]
    if claim.get("pending", 0) != 0:
        raise SystemExit("attestation/latest.json reports pending entries")
    if claim.get("total_entries") != len(ledger):
        raise SystemExit("attestation total_entries does not match public ledger length")
    if ledger_file_sha != attestation["claims_verified"]["verification_ledger"]["file_sha256"]:
        raise SystemExit("attestation ledger file SHA-256 does not match ledger-sha256.txt")
    computed_ledger_file_sha = hashlib.sha256(
        (root / "ledger/verification-ledger.json").read_bytes()
    ).hexdigest()
    if computed_ledger_file_sha != ledger_file_sha:
        raise SystemExit("ledger-sha256.txt does not match verification-ledger.json")

    computed_attestation_hash = canonical_sha256(without_keys(attestation, "attestation_hash"))
    if computed_attestation_hash != attestation["attestation_hash"]:
        raise SystemExit("attestation hash does not match payload")

    computed_graph_digest = canonical_sha256(
        {
            "schema": claim_graph["schema"],
            "generated_at": claim_graph["generated_at"],
            "claims": claim_graph["claims"],
        }
    )
    if computed_graph_digest != claim_graph["graph_digest"]:
        raise SystemExit("claim-source graph digest does not match graph payload")
    if computed_graph_digest != attestation["claim_source_graph_digest"]:
        raise SystemExit("attestation and claim-source graph digests disagree")
    if computed_graph_digest != hostile_verdict["claim_source_graph_digest"]:
        raise SystemExit("hostile-audit verdict and claim-source graph digests disagree")
    if computed_graph_digest != evidence["claim_source_graph_digest"]:
        raise SystemExit("evidence package and claim-source graph digests disagree")

    computed_hostile_digest = canonical_sha256(hostile_verdict)
    if computed_hostile_digest != evidence["hostile_audit_verdict_digest"]:
        raise SystemExit("hostile verdict digest does not match evidence package")

    if evidence["publication"] != publication:
        raise SystemExit("evidence package publication manifest is out of sync")
    if evidence["workspace_census_summary"] != workspace_census_summary:
        raise SystemExit("evidence package workspace census summary is out of sync")
    if evidence["attestation"] != attestation:
        raise SystemExit("evidence package attestation payload is out of sync")
    if protocol_registry["schema"] != "ziros-public-protocol-proof-registry-v1":
        raise SystemExit("unexpected protocol proof registry schema")

    expected_conformance = build_expected_conformance_summary(root)
    for key, expected_value in expected_conformance.items():
        if conformance_summary.get(key) != expected_value:
            raise SystemExit(f"conformance-summary mismatch for {key}")

    expected_capability = build_expected_capability_summary(
        root, publication["published_release_version"]
    )
    for key, expected_value in expected_capability.items():
        if capability_summary.get(key) != expected_value:
            raise SystemExit(f"capability-summary mismatch for {key}")

    if proof_inventory["schema"] != "zkf-public-proof-file-inventory-v2":
        raise SystemExit("unexpected proof-file inventory schema")

    for name, rel in evidence["artifact_index"].items():
        if not (root / rel).exists():
            raise SystemExit(f"artifact_index entry {name} points to missing path {rel}")

    for claim in claim_graph["claims"]:
        expected = claim["expected_value"]
        for source in claim["sources"]:
            value = json_pointer_get(load_claim_source(root / source["path"]), source["json_pointer"])
            if value != expected:
                raise SystemExit(
                    f"claim {claim['claim_id']} mismatch at {source['path']}{source['json_pointer']}"
                )

    expected_explicit_tcb = workspace_census_summary["coverage_state_counts"].get(
        "explicit_tcb", 0
    )
    if hostile_verdict["summary"]["explicit_tcb_files"] != expected_explicit_tcb:
        raise SystemExit("hostile-audit explicit_tcb_files mismatch")
    if hostile_verdict["summary"]["zero_unclassified_files"] != workspace_census_summary[
        "zero_unclassified_files"
    ]:
        raise SystemExit("hostile-audit zero_unclassified_files mismatch")

    if (
        attestation["headline_counts"]["implementation_bound_rows"]
        != attestation["claims_verified"]["verification_ledger"]["implementation_bound_rows"]
    ):
        raise SystemExit("headline implementation count mismatch")
    if (
        attestation["headline_counts"]["hypothesis_carried_rows"]
        != attestation["hypothesis_registry"]["count"]
    ):
        raise SystemExit("headline hypothesis count mismatch")

    print(json.dumps({"ok": True, "root": str(root)}, indent=2))


if __name__ == "__main__":
    main()
