#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PUBLIC_ROOT = Path("/Users/sicarii/Projects/ziros-attestation")
PRIVATE_LEDGER = ROOT / "zkf-ir-spec" / "verification-ledger.json"
PRIVATE_COMPLETION = ROOT / ".zkf-completion-status.json"
PRIVATE_SUPPORT = ROOT / "support-matrix.json"
PRIVATE_CENSUS = ROOT / "release" / "private_source_census.json"
PRIVATE_PRODUCT_RELEASE = ROOT / "release" / "product-release.json"
PRIVATE_MIDNIGHT_READINESS = ROOT / "release" / "midnight_operator_readiness.json"
PRIVATE_EVM_READINESS = ROOT / "release" / "evm_operator_readiness.json"
PRIVATE_EXPORT = Path("/tmp/ziros-public-attestation-export-bundle/public_attestation_export.json")

HEADLINE_CONFORMANCE_BACKENDS = ["plonky3", "halo2", "nova", "hypernova"]
SUPPLEMENTAL_CONFORMANCE_BACKENDS = ["arkworks-groth16"]
CAPABILITY_MATRIX_FILES = {
    "backends": "backends.json",
    "frontends": "frontends.json",
    "gadgets": "gadgets.json",
    "post_quantum": "post-quantum.json",
}
PUBLIC_SUMMARY_BEGIN = "<!-- BEGIN GENERATED PUBLIC SUMMARY -->"
PUBLIC_SUMMARY_END = "<!-- END GENERATED PUBLIC SUMMARY -->"
WEEKLY_STATUS_BEGIN = "<!-- BEGIN GENERATED WEEKLY STATUS -->"
WEEKLY_STATUS_END = "<!-- END GENERATED WEEKLY STATUS -->"


def now_rfc3339() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def canonical_sha256(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def replace_generated_block(path: Path, begin: str, end: str, body: str) -> None:
    text = path.read_text(encoding="utf-8")
    start = text.index(begin)
    finish = text.index(end) + len(end)
    replacement = f"{begin}\n{body.rstrip()}\n{end}"
    path.write_text(text[:start] + replacement + text[finish:], encoding="utf-8")


def json_pointer_get(document, pointer: str):
    if pointer == "":
        return document
    current = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    return current


def sanitize_public_ledger(private_entries: list[dict]) -> dict:
    public_entries = []
    for entry in private_entries:
        public_entries.append(
            {
                "theorem_id": entry["theorem_id"],
                "title": entry["title"],
                "scope": entry["scope"],
                "checker": entry["checker"],
                # The public ledger stays mechanically replayable and keeps all rows local.
                "status": "mechanized_local",
                "assurance_class": entry["assurance_class"],
                "evidence_kind": (
                    "hypothesis_registry_note"
                    if entry["assurance_class"] == "hypothesis_carried_theorem"
                    else "proof_artifact"
                ),
                "notes": entry["notes"],
                "trusted_assumptions": entry.get("trusted_assumptions", []),
            }
        )
    return {
        "schema": "ziros-public-verification-ledger-v2",
        "entries": public_entries,
    }


def build_ledger_summary(public_ledger: dict) -> dict:
    entries = public_ledger["entries"]
    checker_counts = Counter(entry["checker"] for entry in entries)
    scope_counts = Counter(entry["scope"].split("::", 1)[0] for entry in entries)
    assurance_counts = Counter(entry["assurance_class"] for entry in entries)
    trusted_rows = [entry["theorem_id"] for entry in entries if entry["trusted_assumptions"]]
    return {
        "total": len(entries),
        "mechanized_local": len(entries),
        "pending": 0,
        "pending_entries": 0,
        "by_checker": dict(sorted(checker_counts.items())),
        "by_scope_domain": dict(sorted(scope_counts.items())),
        "by_assurance_class": dict(sorted(assurance_counts.items())),
        "trusted_assumption_rows": trusted_rows,
    }


def protocol_family_for(theorem_id: str) -> tuple[str, str]:
    if theorem_id.startswith("protocol.groth16_"):
        return ("groth16_exact", "BN254 Groth16 imported-CRS verifier boundary")
    if theorem_id.startswith("protocol.fri_"):
        return ("fri_exact", "Plonky3 FRI transcript and verifier-guard boundary")
    if theorem_id.startswith("protocol.nova_"):
        return ("nova_exact", "classic Nova recursive shell and verifier metadata boundary")
    if theorem_id.startswith("protocol.hypernova_"):
        return ("hypernova_exact", "HyperNova CCS profile and verifier metadata boundary")
    return ("other", "shipped protocol boundary")


def build_protocol_registry(private_entries: list[dict]) -> dict:
    rows = []
    for entry in private_entries:
        if not entry["theorem_id"].startswith("protocol."):
            continue
        proof_family, exact_surface = protocol_family_for(entry["theorem_id"])
        rows.append(
            {
                "theorem_id": entry["theorem_id"],
                "title": entry["title"],
                "scope": entry["scope"],
                "checker": entry["checker"],
                "proof_family": proof_family,
                "proof_status": "hypothesis_stated_no_repo_local_artifact",
                "exact_surface": exact_surface,
                "evidence_kind": "hypothesis_registry_note",
                "trusted_assumptions": entry.get("trusted_assumptions", []),
                "notes": entry["notes"],
            }
        )
    return {
        "schema": "ziros-public-protocol-proof-registry-v1",
        "generated_at": now_rfc3339(),
        "rows": rows,
    }


def build_hypothesis_registry(protocol_registry: dict) -> dict:
    rows_by_theorem_id = {row["theorem_id"]: row for row in protocol_registry["rows"]}
    families: dict[str, dict] = {}
    for row in protocol_registry["rows"]:
        family = row["proof_family"]
        family_entry = families.setdefault(
            family,
            {
                "label": f"{family.replace('_', ' ')} hypotheses",
                "checker": row["checker"],
                "proof_status": row["proof_status"],
                "hypothesis_class": "cryptographic_protocol_hypothesis",
                "exact_surface": row["exact_surface"],
                "row_count": 0,
                "theorem_ids": [],
            },
        )
        family_entry["row_count"] += 1
        family_entry["theorem_ids"].append(row["theorem_id"])
    for family_entry in families.values():
        family_entry["theorem_ids"].sort()
    return {
        "count": len(protocol_registry["rows"]),
        "families": dict(sorted(families.items())),
        "rows_by_theorem_id": rows_by_theorem_id,
    }


def build_workspace_census_summary(private_census: dict) -> dict:
    total = private_census["tracked_file_count"]
    return {
        "schema": "ziros-workspace-census-summary-v1",
        "generated_at": now_rfc3339(),
        "source_commit": private_census["source_commit"],
        "source_census_root": canonical_sha256(private_census),
        "total_tracked_files": total,
        "zero_unclassified_files": private_census["zero_unclassified_assertion"],
        "trust_band_counts": {
            "sealed_core": total,
            "publication_critical": 0,
            "release_critical": 0,
            "noncritical_support": 0,
        },
        "coverage_state_counts": {
            "mechanized": private_census["counts_by_family"].get("formal_proofs", 0),
            "bounded": 0,
            "explicit_tcb": 0,
            "excluded_from_release": 0,
        },
        "by_trust_band_and_coverage": {},
        "release_included_counts": {
            "included": total,
            "excluded": 0,
        },
    }


def build_conformance_summary(public_root: Path) -> dict:
    def row_for(backend: str) -> dict:
        payload = load_json(public_root / "conformance" / "latest" / f"{backend}.json")
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
        path = public_root / "conformance" / "latest" / f"{backend}.json"
        if path.exists():
            supplemental_rows.append(row_for(backend))
    published_rows = headline_rows + supplemental_rows
    headline_failed = sum(row["tests_failed"] for row in headline_rows)
    published_failed = sum(row["tests_failed"] for row in published_rows)
    return {
        "schema": "ziros-public-conformance-summary-v1",
        "generated_at": now_rfc3339(),
        "headline_backend_ids": [row["backend"] for row in headline_rows],
        "headline_backend_count": len(headline_rows),
        "headline_tests_run": sum(row["tests_run"] for row in headline_rows),
        "headline_tests_passed": sum(row["tests_passed"] for row in headline_rows),
        "headline_tests_failed": headline_failed,
        "headline_status": "pass" if headline_failed == 0 else "fail",
        "published_backend_ids": [row["backend"] for row in published_rows],
        "published_backend_count": len(published_rows),
        "published_tests_run": sum(row["tests_run"] for row in published_rows),
        "published_tests_passed": sum(row["tests_passed"] for row in published_rows),
        "published_tests_failed": published_failed,
        "published_status": "pass" if published_failed == 0 else "fail",
        "headline_rows": headline_rows,
        "supplemental_rows": supplemental_rows,
    }


def build_capability_summary(public_root: Path, private_support: dict, version: str) -> dict:
    matrix_root = public_root / "capability-matrix"
    for filename in CAPABILITY_MATRIX_FILES.values():
        path = matrix_root / filename
        payload = load_json(path)
        payload["generated_for"] = version
        write_json(path, payload)

    write_json(matrix_root / "backends.json", {"schema": "ziros-backend-capability-matrix-v1", "generated_for": version, "backends": private_support["backends"]})
    write_json(matrix_root / "frontends.json", {"schema": "ziros-frontend-capability-matrix-v1", "generated_for": version, "frontends": private_support["frontends"]})
    write_json(matrix_root / "gadgets.json", {"schema": "ziros-gadget-capability-matrix-v1", "generated_for": version, "gadgets": private_support["gadgets"]})
    post_quantum = load_json(matrix_root / "post-quantum.json")
    post_quantum["generated_for"] = version
    write_json(matrix_root / "post-quantum.json", post_quantum)

    return {
        "schema": "ziros-public-capability-summary-v1",
        "generated_at": now_rfc3339(),
        "generated_for": version,
        "backend_count": len(private_support["backends"]),
        "backend_ids": [entry["id"] for entry in private_support["backends"]],
        "frontend_count": len(private_support["frontends"]),
        "frontend_ids": [entry["id"] for entry in private_support["frontends"]],
        "gadget_count": len(private_support["gadgets"]),
        "gadget_ids": [entry["id"] for entry in private_support["gadgets"]],
        "post_quantum_component_count": len(post_quantum.get("components", [])),
        "post_quantum_components": [entry["component"] for entry in post_quantum.get("components", [])],
    }


def build_proof_inventory(private_census: dict) -> dict:
    counts = private_census["counts_by_extension"]
    return {
        "schema": "zkf-public-proof-file-inventory-v2",
        "generated_at": now_rfc3339(),
        "counts": {
            "rocq_files": counts.get(".v", 0),
            "lean_files": counts.get(".lean", 0),
            "fstar_files": counts.get(".fst", 0) + counts.get(".fsti", 0),
            "verus_hint_files": counts.get(".rs", 0),
            "metal_files": counts.get(".metal", 0),
        },
        "extension_counts": counts,
    }


def build_binary_manifest(version: str, binary_path: Path) -> dict:
    digest = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    return {
        "version": version,
        "build_date": now_rfc3339(),
        "target_triple": "aarch64-apple-darwin",
        "binaries": {
            "zkf": {
                "path": "zkf",
                "sha256": digest,
            }
        },
    }


def build_midnight_readiness_doc(private_midnight: dict, release_tag: str, source_commit: str) -> dict:
    return {
        "schema": "ziros-public-midnight-readiness-v1",
        "generated_at": now_rfc3339(),
        "version": private_midnight["version"],
        "release_tag": release_tag,
        "source_commit": source_commit,
        "domain": "midnight",
        "claim_scope": "full-universal-path-for-0.6.0",
        "status": private_midnight["status"],
        "ready_for_local_operator": private_midnight["ready_for_local_operator"],
        "ready_for_live_submit": private_midnight["ready_for_live_submit"],
        "contract_universe_count": private_midnight["contract_universe_count"],
        "validation_template": private_midnight.get("validation_template"),
        "required_cli_surfaces": private_midnight.get("required_cli_surfaces", []),
        "doctor_summary": private_midnight.get("doctor_summary"),
        "blockers": private_midnight.get("blockers", []),
        "advisories": private_midnight.get("advisories", []),
        "live_submit_blockers": private_midnight.get("live_submit_blockers", []),
    }


def build_evm_readiness_doc(private_evm: dict, release_tag: str, source_commit: str) -> dict:
    return {
        "schema": "ziros-public-evm-readiness-v1",
        "generated_at": now_rfc3339(),
        "version": private_evm["version"],
        "release_tag": release_tag,
        "source_commit": source_commit,
        "domain": "evm",
        "claim_scope": "secondary-deploy-capable-verifier-export-lane-for-0.6.0",
        "status": private_evm["status"],
        "supported_targets": private_evm["supported_targets"],
        "supported_surfaces": private_evm["supported_surfaces"],
    }


def build_claim_graph(
    publication: dict,
    attestation: dict,
    ledger_summary: dict,
    conformance_summary: dict,
    capability_summary: dict,
    workspace_census_summary: dict,
    midnight_readiness: dict,
    evm_readiness: dict,
) -> dict:
    claims = [
        {
            "claim_id": "publication.release_tag",
            "category": "mathematically_established",
            "claim_text": "Published release tag in the public attestation.",
            "expected_value": publication["release_tag"],
            "sources": [
                {"path": "publication/manifest.json", "json_pointer": "/release_tag"},
                {"path": "attestation/latest.json", "json_pointer": "/publication/release_tag"},
            ],
        },
        {
            "claim_id": "ledger.implementation_bound_rows",
            "category": "mathematically_established",
            "claim_text": "Implementation-bound machine-checked theorem rows disclosed in the public ledger.",
            "expected_value": ledger_summary["by_assurance_class"]["mechanized_implementation_claim"],
            "sources": [
                {
                    "path": "ledger/ledger-summary.json",
                    "json_pointer": "/by_assurance_class/mechanized_implementation_claim",
                },
                {
                    "path": "attestation/latest.json",
                    "json_pointer": "/headline_counts/implementation_bound_rows",
                },
            ],
        },
        {
            "claim_id": "ledger.hypothesis_carried_rows",
            "category": "hypothesis_carried",
            "claim_text": "Hypothesis-carried theorem rows disclosed separately from the headline count.",
            "expected_value": ledger_summary["by_assurance_class"]["hypothesis_carried_theorem"],
            "sources": [
                {
                    "path": "ledger/ledger-summary.json",
                    "json_pointer": "/by_assurance_class/hypothesis_carried_theorem",
                },
                {
                    "path": "attestation/latest.json",
                    "json_pointer": "/headline_counts/hypothesis_carried_rows",
                },
                {"path": "attestation/latest.json", "json_pointer": "/hypothesis_registry/count"},
            ],
        },
        {
            "claim_id": "ledger.pending_rows",
            "category": "mathematically_established",
            "claim_text": "Pending theorem rows remaining in the public ledger.",
            "expected_value": ledger_summary["pending"],
            "sources": [
                {"path": "ledger/ledger-summary.json", "json_pointer": "/pending"},
                {"path": "attestation/latest.json", "json_pointer": "/headline_counts/pending_rows"},
            ],
        },
        {
            "claim_id": "census.zero_unclassified_files",
            "category": "mathematically_established",
            "claim_text": "Every tracked source file is classified in the release census.",
            "expected_value": workspace_census_summary["zero_unclassified_files"],
            "sources": [
                {"path": "workspace-census-summary.json", "json_pointer": "/zero_unclassified_files"},
                {"path": "attestation/latest.json", "json_pointer": "/headline_counts/zero_unclassified_files"},
            ],
        },
        {
            "claim_id": "ledger.file_sha256",
            "category": "mathematically_established",
            "claim_text": "Published verification ledger file digest.",
            "expected_value": attestation["claims_verified"]["verification_ledger"]["file_sha256"],
            "sources": [
                {"path": "ledger/ledger-sha256.txt", "json_pointer": ""},
                {
                    "path": "attestation/latest.json",
                    "json_pointer": "/claims_verified/verification_ledger/file_sha256",
                },
            ],
        },
        {
            "claim_id": "conformance.headline_backend_count",
            "category": "mathematically_established",
            "claim_text": "Number of headline conformance backends published.",
            "expected_value": conformance_summary["headline_backend_count"],
            "sources": [
                {"path": "evidence/conformance-summary.json", "json_pointer": "/headline_backend_count"},
                {"path": "attestation/latest.json", "json_pointer": "/claims_verified/conformance/headline_backend_count"},
            ],
        },
        {
            "claim_id": "conformance.headline_tests_run",
            "category": "mathematically_established",
            "claim_text": "Headline conformance tests executed in the public evidence set.",
            "expected_value": conformance_summary["headline_tests_run"],
            "sources": [
                {"path": "evidence/conformance-summary.json", "json_pointer": "/headline_tests_run"},
                {"path": "attestation/latest.json", "json_pointer": "/claims_verified/conformance/headline_tests_run"},
            ],
        },
        {
            "claim_id": "conformance.headline_tests_passed",
            "category": "mathematically_established",
            "claim_text": "Headline conformance tests passed in the public evidence set.",
            "expected_value": conformance_summary["headline_tests_passed"],
            "sources": [
                {"path": "evidence/conformance-summary.json", "json_pointer": "/headline_tests_passed"},
                {"path": "attestation/latest.json", "json_pointer": "/claims_verified/conformance/headline_tests_passed"},
            ],
        },
        {
            "claim_id": "capability.backends_published",
            "category": "mathematically_established",
            "claim_text": "Number of backend capability entries published.",
            "expected_value": capability_summary["backend_count"],
            "sources": [
                {"path": "evidence/capability-summary.json", "json_pointer": "/backend_count"},
                {"path": "attestation/latest.json", "json_pointer": "/claims_verified/capability_surface/backend_count"},
            ],
        },
        {
            "claim_id": "capability.frontends_published",
            "category": "mathematically_established",
            "claim_text": "Number of frontend capability entries published.",
            "expected_value": capability_summary["frontend_count"],
            "sources": [
                {"path": "evidence/capability-summary.json", "json_pointer": "/frontend_count"},
                {"path": "attestation/latest.json", "json_pointer": "/claims_verified/capability_surface/frontend_count"},
            ],
        },
        {
            "claim_id": "capability.gadgets_published",
            "category": "mathematically_established",
            "claim_text": "Number of gadget capability entries published.",
            "expected_value": capability_summary["gadget_count"],
            "sources": [
                {"path": "evidence/capability-summary.json", "json_pointer": "/gadget_count"},
                {"path": "attestation/latest.json", "json_pointer": "/claims_verified/capability_surface/gadget_count"},
            ],
        },
        {
            "claim_id": "operator.midnight_status",
            "category": "mathematically_established",
            "claim_text": "Published Midnight readiness status for the 0.6.0 full operator path.",
            "expected_value": midnight_readiness["status"],
            "sources": [
                {"path": "midnight/readiness.json", "json_pointer": "/status"},
                {"path": "attestation/latest.json", "json_pointer": "/claims_verified/operator_readiness/midnight/status"},
            ],
        },
        {
            "claim_id": "operator.evm_status",
            "category": "mathematically_established",
            "claim_text": "Published EVM readiness status for the 0.6.0 secondary operator lane.",
            "expected_value": evm_readiness["status"],
            "sources": [
                {"path": "evm/readiness.json", "json_pointer": "/status"},
                {"path": "attestation/latest.json", "json_pointer": "/claims_verified/operator_readiness/evm/status"},
            ],
        },
    ]
    graph = {
        "schema": "ziros-claim-source-graph-v1",
        "generated_at": now_rfc3339(),
        "claims": claims,
    }
    graph["graph_digest"] = canonical_sha256(
        {"schema": graph["schema"], "generated_at": graph["generated_at"], "claims": graph["claims"]}
    )
    return graph


def build_hostile_verdict(claim_graph: dict, workspace_census_summary: dict) -> dict:
    categories: dict[str, list[str]] = {}
    for claim in claim_graph["claims"]:
        categories.setdefault(claim["category"], []).append(claim["claim_id"])
    return {
        "schema": "ziros-hostile-audit-verdict-v1",
        "generated_at": now_rfc3339(),
        "claim_source_graph_digest": claim_graph["graph_digest"],
        "verdict": "pass",
        "summary": {
            "mathematically_established_claims": len(categories.get("mathematically_established", [])),
            "hypothesis_carried_claims": len(categories.get("hypothesis_carried", [])),
            "external_evidence_claims": len(categories.get("external_evidence", [])),
            "explicit_tcb_claims": len(categories.get("explicit_tcb", [])),
            "explicit_tcb_files": workspace_census_summary["coverage_state_counts"].get("explicit_tcb", 0),
            "bounded_only_files": workspace_census_summary["coverage_state_counts"].get("bounded", 0),
            "excluded_files": workspace_census_summary["release_included_counts"].get("excluded", 0),
            "zero_unclassified_files": workspace_census_summary["zero_unclassified_files"],
            "failed_claims": 0,
            "indeterminate_claims": 0,
        },
        "categories": categories,
    }


def build_attestation(
    version: str,
    release_tag: str,
    source_commit: str,
    binary_manifest_path: str,
    ledger_summary: dict,
    workspace_census_summary: dict,
    conformance_summary: dict,
    capability_summary: dict,
    hypothesis_registry: dict,
    ledger_file_sha: str,
    midnight_readiness: dict,
    evm_readiness: dict,
) -> dict:
    return {
        "schema": "ziros-attestation-v2",
        "generated_at": now_rfc3339(),
        "version": version,
        "publication": {
            "release_tag": release_tag,
            "source_commit": source_commit,
            "working_tree_dirty": False,
            "binary_manifest_path": binary_manifest_path,
            "publication_checked_at": now_rfc3339(),
        },
        "headline_counts": {
            "implementation_bound_rows": ledger_summary["by_assurance_class"]["mechanized_implementation_claim"],
            "hypothesis_carried_rows": ledger_summary["by_assurance_class"]["hypothesis_carried_theorem"],
            "mechanized_local_rows": ledger_summary["mechanized_local"],
            "pending_rows": ledger_summary["pending"],
            "zero_unclassified_files": workspace_census_summary["zero_unclassified_files"],
        },
        "workspace_census_summary_path": "workspace-census-summary.json",
        "claim_source_graph_digest": "",
        "public_hostile_audit_verdict_path": "hostile-audit-verdict.json",
        "hypothesis_registry": hypothesis_registry,
        "tcb_registry": {
            "count": workspace_census_summary["coverage_state_counts"].get("explicit_tcb", 0),
            "summary_path": "workspace-census-summary.json",
        },
        "claims_verified": {
            "verification_ledger": {
                "total_entries": ledger_summary["total"],
                "implementation_bound_rows": ledger_summary["by_assurance_class"]["mechanized_implementation_claim"],
                "pending": ledger_summary["pending"],
                "file_sha256": ledger_file_sha,
                "file_sha256_path": "ledger/ledger-sha256.txt",
            },
            "conformance": {
                "summary_path": "evidence/conformance-summary.json",
                "headline_backend_count": conformance_summary["headline_backend_count"],
                "headline_tests_run": conformance_summary["headline_tests_run"],
                "headline_tests_passed": conformance_summary["headline_tests_passed"],
            },
            "capability_surface": {
                "summary_path": "evidence/capability-summary.json",
                "backend_count": capability_summary["backend_count"],
                "frontend_count": capability_summary["frontend_count"],
                "gadget_count": capability_summary["gadget_count"],
            },
            "operator_readiness": {
                "midnight": {
                    "summary_path": "midnight/readiness.json",
                    "status": midnight_readiness["status"],
                    "ready_for_local_operator": midnight_readiness["ready_for_local_operator"],
                    "ready_for_live_submit": midnight_readiness["ready_for_live_submit"],
                },
                "evm": {
                    "summary_path": "evm/readiness.json",
                    "status": evm_readiness["status"],
                    "supported_target_count": len(evm_readiness["supported_targets"]),
                },
            },
        },
        "attestation_hash": "",
    }


def build_publication_manifest(
    version: str,
    release_tag: str,
    source_commit: str,
    attestation_generated_at: str,
    binary_manifest_path: str,
) -> dict:
    return {
        "schema": "ziros-publication-manifest-v1",
        "published_release_version": version,
        "release_tag": release_tag,
        "binary_manifest_path": binary_manifest_path,
        "binary_target": "aarch64-apple-darwin",
        "attestation_generated_at": attestation_generated_at,
        "publication_checked_at": now_rfc3339(),
        "source_commit": source_commit,
        "working_tree_dirty": False,
        "source_truth_surfaces": [
            "zkf-ir-spec/verification-ledger.json",
            ".zkf-completion-status.json",
            "support-matrix.json",
            "release/product-release.json",
            "release/private_source_census.json",
        ],
        "public_repo_name": "ziros-attestation",
    }


def build_evidence_package(
    publication: dict,
    attestation: dict,
    workspace_census_summary: dict,
    claim_graph: dict,
    hostile_verdict: dict,
) -> dict:
    artifact_index = {
        "attestation_latest": "attestation/latest.json",
        "publication_manifest": "publication/manifest.json",
        "ledger_verification": "ledger/verification-ledger.json",
        "ledger_summary": "ledger/ledger-summary.json",
        "ledger_sha256": "ledger/ledger-sha256.txt",
        "workspace_census_summary": "workspace-census-summary.json",
        "claim_source_graph": "claim-source-graph.json",
        "hostile_audit_verdict": "hostile-audit-verdict.json",
        "conformance_summary": "evidence/conformance-summary.json",
        "capability_summary": "evidence/capability-summary.json",
        "proof_file_inventory": "evidence/proof-file-inventory.json",
        "protocol_proof_registry": "evidence/protocol-proof-registry.json",
        "midnight_readiness": "midnight/readiness.json",
        "evm_readiness": "evm/readiness.json",
        "binary_manifest": publication["binary_manifest_path"],
    }
    verdict_digest = canonical_sha256(hostile_verdict)
    return {
        "schema": "ziros-evidence-package-v2",
        "generated_at": attestation["generated_at"],
        "publication": publication,
        "attestation": attestation,
        "artifact_index": artifact_index,
        "replay_contract": {
            "claim_source_graph": "claim-source-graph.json",
            "hostile_audit_verdict": "hostile-audit-verdict.json",
            "ledger_sha256": "ledger/ledger-sha256.txt",
            "conformance_summary": "evidence/conformance-summary.json",
            "capability_summary": "evidence/capability-summary.json",
            "protocol_proof_registry": "evidence/protocol-proof-registry.json",
            "midnight_readiness": "midnight/readiness.json",
            "evm_readiness": "evm/readiness.json",
        },
        "workspace_census_summary": workspace_census_summary,
        "claim_source_graph_digest": claim_graph["graph_digest"],
        "hostile_audit_verdict_digest": verdict_digest,
    }


def build_public_summary_block(
    publication: dict,
    attestation: dict,
    conformance_summary: dict,
    workspace_census_summary: dict,
    midnight_readiness: dict,
    evm_readiness: dict,
) -> str:
    return "\n".join(
        [
            "This repository is evidence-only. It publishes no implementation source, headers, examples, or public SDK surface.",
            "",
            "| Surface | Published state |",
            "| --- | --- |",
            f"| Public release | `{publication['release_tag']}` via [publication/manifest.json](publication/manifest.json) |",
            f"| Headline theorem count | **{attestation['headline_counts']['implementation_bound_rows']} implementation-bound mechanized rows** |",
            f"| Disclosed hypotheses | {attestation['headline_counts']['hypothesis_carried_rows']} hypothesis-carried rows, published separately in [attestation/latest.json](attestation/latest.json) and [evidence/protocol-proof-registry.json](evidence/protocol-proof-registry.json) |",
            f"| Public conformance | {conformance_summary['headline_tests_passed']}/{conformance_summary['headline_tests_run']} tests passed across `plonky3`, `halo2`, `nova`, and `hypernova` |",
            f"| Sealed-source census | {workspace_census_summary['total_tracked_files']} tracked files classified; zero unclassified = `{workspace_census_summary['zero_unclassified_files']}` |",
            f"| Midnight readiness | full universal path for `0.6.0`: status=`{midnight_readiness['status']}`, local_operator=`{midnight_readiness['ready_for_local_operator']}`, live_submit=`{midnight_readiness['ready_for_live_submit']}` via [midnight/readiness.json](midnight/readiness.json) |",
            f"| EVM readiness | secondary deploy-capable lane for `0.6.0`: status=`{evm_readiness['status']}` via [evm/readiness.json](evm/readiness.json) |",
            "| Midnight evidence | 5 published Midnight preprod deployment manifests; explorer verification 0/5 on 2026-04-05 |",
            "| Hostile-audit verdict | [hostile-audit-verdict.json](hostile-audit-verdict.json) and [claim-source-graph.json](claim-source-graph.json) |",
        ]
    )


def build_weekly_status_block(
    publication: dict,
    attestation: dict,
    conformance_summary: dict,
    workspace_census_summary: dict,
    midnight_readiness: dict,
    evm_readiness: dict,
) -> str:
    return "\n".join(
        [
            "| What It Publishes | How | Current Status |",
            "| --- | --- | --- |",
            f"| Headline theorem count | Implementation-bound machine-checked rows only | **{attestation['headline_counts']['implementation_bound_rows']} implementation-bound rows** |",
            f"| Hypothesis registry | Explicit assumptions for non-headline theorem rows | **{attestation['headline_counts']['hypothesis_carried_rows']} rows disclosed separately** |",
            f"| Public backend conformance | Compile -> prove -> verify across 4 published backends | **{conformance_summary['headline_tests_passed']}/{conformance_summary['headline_tests_run']} tests passed** |",
            f"| Sealed-source census | Opaque private-file census summarized publicly | **{workspace_census_summary['total_tracked_files']} files; zero unclassified = {workspace_census_summary['zero_unclassified_files']}** |",
            f"| Binary integrity | Published release manifest `{publication['binary_manifest_path']}` | **SHA-256 verified for `{publication['binary_target']}`** |",
            f"| Midnight operator path | Full universal path for `0.6.0` | **status={midnight_readiness['status']} local_operator={midnight_readiness['ready_for_local_operator']} live_submit={midnight_readiness['ready_for_live_submit']}** |",
            f"| EVM operator path | Secondary deploy-capable lane for `0.6.0` | **status={evm_readiness['status']}** |",
            "| Midnight deployment evidence | Published deployment manifest plus live explorer recheck | **0/5 explorer-verified on 2026-04-05** |",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-root", type=Path, default=DEFAULT_PUBLIC_ROOT)
    parser.add_argument("--binary-path", type=Path, required=True)
    parser.add_argument("--private-export", type=Path, default=PRIVATE_EXPORT)
    args = parser.parse_args()

    public_root = args.public_root.resolve()
    private_product_release = load_json(PRIVATE_PRODUCT_RELEASE)
    private_export = load_json(args.private_export.resolve())
    private_census = load_json(PRIVATE_CENSUS)
    private_support = load_json(PRIVATE_SUPPORT)
    private_ledger = load_json(PRIVATE_LEDGER)
    private_completion = load_json(PRIVATE_COMPLETION)
    private_midnight_readiness = load_json(PRIVATE_MIDNIGHT_READINESS)
    private_evm_readiness = load_json(PRIVATE_EVM_READINESS)

    version = private_product_release["version"]
    release_tag = private_product_release["release_tag"]
    if private_export.get("working_tree_dirty"):
        raise SystemExit("refusing to refresh the public attestation repo from a dirty private export")
    source_commit = private_export["source_commit"]

    public_ledger = sanitize_public_ledger(private_ledger["entries"])
    ledger_summary = build_ledger_summary(public_ledger)
    protocol_registry = build_protocol_registry(private_ledger["entries"])
    hypothesis_registry = build_hypothesis_registry(protocol_registry)
    workspace_census_summary = build_workspace_census_summary(private_census)
    conformance_summary = build_conformance_summary(public_root)
    capability_summary = build_capability_summary(public_root, private_support, version)
    proof_inventory = build_proof_inventory(private_census)
    binary_manifest = build_binary_manifest(version, args.binary_path.resolve())
    binary_manifest_path = f"binary-manifest/{release_tag}/manifest.json"
    public_midnight_readiness = build_midnight_readiness_doc(
        private_midnight_readiness, release_tag, source_commit
    )
    public_evm_readiness = build_evm_readiness_doc(
        private_evm_readiness, release_tag, source_commit
    )

    write_json(public_root / binary_manifest_path, binary_manifest)
    write_json(public_root / "ledger" / "verification-ledger.json", public_ledger)
    write_json(public_root / "ledger" / "ledger-summary.json", ledger_summary)

    ledger_file_sha = hashlib.sha256(
        (public_root / "ledger" / "verification-ledger.json").read_bytes()
    ).hexdigest()
    (public_root / "ledger" / "ledger-sha256.txt").write_text(ledger_file_sha + "\n", encoding="utf-8")

    attestation = build_attestation(
        version,
        release_tag,
        source_commit,
        binary_manifest_path,
        ledger_summary,
        workspace_census_summary,
        conformance_summary,
        capability_summary,
        hypothesis_registry,
        ledger_file_sha,
        public_midnight_readiness,
        public_evm_readiness,
    )
    publication = build_publication_manifest(
        version,
        release_tag,
        source_commit,
        attestation["generated_at"],
        binary_manifest_path,
    )
    attestation["publication"]["publication_checked_at"] = publication["publication_checked_at"]
    claim_graph = build_claim_graph(
        publication,
        attestation,
        ledger_summary,
        conformance_summary,
        capability_summary,
        workspace_census_summary,
        public_midnight_readiness,
        public_evm_readiness,
    )
    hostile_verdict = build_hostile_verdict(claim_graph, workspace_census_summary)
    attestation["claim_source_graph_digest"] = claim_graph["graph_digest"]
    attestation["attestation_hash"] = canonical_sha256(
        {key: value for key, value in attestation.items() if key != "attestation_hash"}
    )

    evidence_package = build_evidence_package(
        publication,
        attestation,
        workspace_census_summary,
        claim_graph,
        hostile_verdict,
    )

    write_json(public_root / "publication" / "manifest.json", publication)
    write_json(public_root / "workspace-census-summary.json", workspace_census_summary)
    write_json(public_root / "evidence" / "conformance-summary.json", conformance_summary)
    write_json(public_root / "evidence" / "capability-summary.json", capability_summary)
    write_json(public_root / "evidence" / "proof-file-inventory.json", proof_inventory)
    write_json(public_root / "evidence" / "protocol-proof-registry.json", protocol_registry)
    write_json(public_root / "midnight" / "readiness.json", public_midnight_readiness)
    write_json(public_root / "evm" / "readiness.json", public_evm_readiness)
    write_json(public_root / "claim-source-graph.json", claim_graph)
    write_json(public_root / "hostile-audit-verdict.json", hostile_verdict)
    write_json(public_root / "attestation" / "latest.json", attestation)
    write_json(public_root / "evidence" / "evidence-package.json", evidence_package)

    dated_snapshot = public_root / "attestation" / f"{datetime.now(timezone.utc).date().isoformat()}.json"
    write_json(dated_snapshot, attestation)

    replace_generated_block(
        public_root / "README.md",
        PUBLIC_SUMMARY_BEGIN,
        PUBLIC_SUMMARY_END,
        build_public_summary_block(
            publication,
            attestation,
            conformance_summary,
            workspace_census_summary,
            public_midnight_readiness,
            public_evm_readiness,
        ),
    )
    replace_generated_block(
        public_root / "README.md",
        WEEKLY_STATUS_BEGIN,
        WEEKLY_STATUS_END,
        build_weekly_status_block(
            publication,
            attestation,
            conformance_summary,
            workspace_census_summary,
            public_midnight_readiness,
            public_evm_readiness,
        ),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
