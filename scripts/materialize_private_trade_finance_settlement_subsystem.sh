#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
artifact_root="${1:-$repo_root/dist/showcases/private_trade_finance_settlement}"
subsystem_root="${2:-$repo_root/dist/subsystems/private_trade_finance_settlement}"
profile="${3:-flagship}"

canonicalize_target_path() {
  local target="$1"
  mkdir -p "$(dirname "$target")"
  printf '%s/%s\n' "$(cd "$(dirname "$target")" && pwd -L)" "$(basename "$target")"
}

artifact_root="$(canonicalize_target_path "$artifact_root")"
subsystem_root="$(canonicalize_target_path "$subsystem_root")"

mkdir -p "$(dirname "$artifact_root")" "$(dirname "$subsystem_root")"

echo "[trade-finance-subsystem] exporting finished showcase bundle into $artifact_root" >&2
env ZKF_PRIVATE_TRADE_FINANCE_SETTLEMENT_PROFILE="$profile" \
  cargo run --release -p zkf-lib --features metal-gpu --example private_trade_finance_settlement_showcase -- "$artifact_root"

echo "[trade-finance-subsystem] validating Midnight contract package into $artifact_root/midnight_validation" >&2
bash "$repo_root/scripts/validate_private_trade_finance_midnight_contracts.sh" "$artifact_root" preview

echo "[trade-finance-subsystem] scaffolding subsystem shell into $subsystem_root" >&2
rm -rf "$subsystem_root"
cargo run -p zkf-cli -- subsystem scaffold \
  --name private-trade-finance-and-settlement \
  --style full \
  --out "$subsystem_root" \
  --json > /dev/null

mkdir -p \
  "$subsystem_root/03_inputs" \
  "$subsystem_root/05_scripts" \
  "$subsystem_root/06_docs" \
  "$subsystem_root/07_compiled" \
  "$subsystem_root/08_proofs" \
  "$subsystem_root/09_verification" \
  "$subsystem_root/10_audit" \
  "$subsystem_root/16_compact" \
  "$subsystem_root/17_report"

cp -R "$artifact_root/compiled/." "$subsystem_root/07_compiled/"
cp -R "$artifact_root/proofs/." "$subsystem_root/08_proofs/"
cp -R "$artifact_root/verification/." "$subsystem_root/09_verification/"
cp -R "$artifact_root/audit/." "$subsystem_root/10_audit/"
cp -R "$artifact_root/midnight_package/." "$subsystem_root/16_compact/"

cp "$artifact_root/public_inputs.json" "$subsystem_root/03_inputs/public_inputs.json"
cp "$artifact_root/public_outputs.json" "$subsystem_root/03_inputs/public_outputs.json"
cp "$artifact_root/witness_summary.json" "$subsystem_root/17_report/witness_summary.json"
cp "$artifact_root/private_trade_finance_settlement.run_report.json" "$subsystem_root/17_report/run_report.json"
cp "$artifact_root/private_trade_finance_settlement.translation_report.json" "$subsystem_root/17_report/translation_report.json"
cp "$artifact_root/private_trade_finance_settlement.compiled_digest_linkage.json" "$subsystem_root/17_report/compiled_digest_linkage.json"
cp "$artifact_root/private_trade_finance_settlement.poseidon_binding_report.json" "$subsystem_root/17_report/poseidon_binding_report.json"
cp "$artifact_root/private_trade_finance_settlement.disclosure_noninterference_report.json" "$subsystem_root/17_report/disclosure_noninterference_report.json"
cp "$artifact_root/telemetry/private_trade_finance_settlement.telemetry_report.json" "$subsystem_root/17_report/telemetry_report.json"
cp "$artifact_root/private_trade_finance_settlement.evidence_summary.json" "$subsystem_root/17_report/evidence_summary.json"
cp "$artifact_root/private_trade_finance_settlement.summary.json" "$subsystem_root/17_report/summary.json"
cp "$artifact_root/private_trade_finance_settlement.report.md" "$subsystem_root/17_report/report.md"
cp "$artifact_root/deterministic_manifest.json" "$subsystem_root/17_report/deterministic_manifest.json"
cp "$artifact_root/closure_artifacts.json" "$subsystem_root/17_report/closure_artifacts.json"
cp "$artifact_root/operator_notes.md" "$subsystem_root/17_report/operator_notes.md"
cp "$artifact_root/deployment_notes.md" "$subsystem_root/17_report/deployment_notes.md"
cp "$artifact_root/summary.md" "$subsystem_root/17_report/summary.md"
cp "$artifact_root/subsystem_prebundle.json" "$subsystem_root/17_report/subsystem_prebundle.json"
cp "$artifact_root/audit_bundle.json" "$subsystem_root/10_audit/audit_bundle.json"
cp -R "$artifact_root/selective_disclosure" "$subsystem_root/10_audit/selective_disclosure"
if [[ -d "$artifact_root/midnight_validation" ]]; then
  rm -rf "$subsystem_root/17_report/midnight_validation"
  cp -R "$artifact_root/midnight_validation" "$subsystem_root/17_report/midnight_validation"
fi

if [[ -d "$artifact_root/formal" ]]; then
  rm -rf "$subsystem_root/17_report/formal"
  cp -R "$artifact_root/formal" "$subsystem_root/17_report/formal"
fi

cp "$repo_root/scripts/run_rocq_trade_finance_proofs.sh" \
  "$subsystem_root/05_scripts/run_rocq_trade_finance_proofs.sh"
cp "$repo_root/scripts/run_lean_trade_finance_proofs.sh" \
  "$subsystem_root/05_scripts/run_lean_trade_finance_proofs.sh"
cp "$repo_root/scripts/run_verus_trade_finance_proofs.sh" \
  "$subsystem_root/05_scripts/run_verus_trade_finance_proofs.sh"
cp "$repo_root/scripts/validate_private_trade_finance_midnight_contracts.sh" \
  "$subsystem_root/05_scripts/validate_private_trade_finance_midnight_contracts.sh"
cp "$repo_root/scripts/materialize_private_trade_finance_settlement_subsystem.sh" \
  "$subsystem_root/05_scripts/materialize_private_trade_finance_settlement_subsystem.sh"

cat > "$subsystem_root/06_docs/README.md" <<EOF
# Private Trade Finance Settlement Subsystem

This subsystem packages the finished ZirOS private trade finance exporter into the standard 20-slot subsystem layout.

Export profile: $profile

Core circuit modules:

- trade_finance_decision_core.primary
- trade_finance_settlement_binding.primary
- trade_finance_disclosure_projection.primary
- trade_finance_duplicate_registry_handoff.primary

The bundle also preserves:

- the public output artifact
- the witness summary
- the strict runtime telemetry report
- the selective disclosure bundle
- the Midnight Compact package
- the formal evidence logs
- deterministic manifests and closure artifacts
EOF

cat > "$subsystem_root/06_docs/disclosure_policy.md" <<'EOF'
# Disclosure Policy

- Raw supplier, buyer, invoice, and financing-policy identifying information remains private and is not exported into the subsystem bundle.
- External OCR, logistics-event, photo-analysis, vendor, and buyer-approval inputs are digest-bound rather than publicly disclosed.
- Denials and high-risk actions preserve a public `human_review_required` flag.
- Disclosure access is bound to a role, credential commitment, request id hash, caller commitment, selected view commitment, and disclosure authorization commitment.
- Midnight package sources are emitted for preview integration, but live deployment still requires separate operator wallet and network readiness checks.
EOF

verifier_exists="false"
if [[ -f "$artifact_root/solidity/TradeFinanceVerifier.sol" ]]; then
  verifier_exists="true"
fi

python3 - "$subsystem_root/02_manifest/subsystem_manifest.json" "$artifact_root/private_trade_finance_settlement.summary.json" "$profile" "$verifier_exists" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
summary_path = Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text())
summary = json.loads(summary_path.read_text())
verifier_exists = sys.argv[4].lower() == "true"
effective_backend = summary.get("effective_core_backend") or summary.get("primary_backend") or "hypernova"
lane_classification = summary.get("lane_classification") or "planning-only"
manifest["subsystem_id"] = "private_trade_finance_settlement_subsystem"
manifest["runtime_profile"] = "flagship" if lane_classification == "primary-strict" else sys.argv[3]
manifest["production_classification"] = lane_classification
manifest["minimum_report_word_count"] = 10000
manifest["circuits"] = {
    "trade_finance_decision_core": {
        "backend": effective_backend,
        "program_path": "07_compiled/trade_finance_decision_core.primary.program.json",
        "compiled_path": "07_compiled/trade_finance_decision_core.primary.compiled.json",
        "inputs_path": "03_inputs/public_inputs.json",
        "proof_path": "08_proofs/trade_finance_decision_core.primary.proof.json",
        "verification_path": "09_verification/trade_finance_decision_core.primary.verification.json",
        "audit_path": "10_audit/trade_finance_decision_core.primary.audit.json",
        "lane_classification": lane_classification,
    },
    "trade_finance_settlement_binding": {
        "backend": effective_backend,
        "program_path": "07_compiled/trade_finance_settlement_binding.primary.program.json",
        "compiled_path": "07_compiled/trade_finance_settlement_binding.primary.compiled.json",
        "inputs_path": "03_inputs/public_outputs.json",
        "proof_path": "08_proofs/trade_finance_settlement_binding.primary.proof.json",
        "verification_path": "09_verification/trade_finance_settlement_binding.primary.verification.json",
        "audit_path": "10_audit/trade_finance_settlement_binding.primary.audit.json",
        "lane_classification": lane_classification,
    },
    "trade_finance_disclosure_projection": {
        "backend": effective_backend,
        "program_path": "07_compiled/trade_finance_disclosure_projection.primary.program.json",
        "compiled_path": "07_compiled/trade_finance_disclosure_projection.primary.compiled.json",
        "inputs_path": "03_inputs/public_outputs.json",
        "proof_path": "08_proofs/trade_finance_disclosure_projection.primary.proof.json",
        "verification_path": "09_verification/trade_finance_disclosure_projection.primary.verification.json",
        "audit_path": "10_audit/trade_finance_disclosure_projection.primary.audit.json",
        "lane_classification": lane_classification,
    },
    "trade_finance_duplicate_registry_handoff": {
        "backend": effective_backend,
        "program_path": "07_compiled/trade_finance_duplicate_registry_handoff.primary.program.json",
        "compiled_path": "07_compiled/trade_finance_duplicate_registry_handoff.primary.compiled.json",
        "inputs_path": "03_inputs/public_outputs.json",
        "proof_path": "08_proofs/trade_finance_duplicate_registry_handoff.primary.proof.json",
        "verification_path": "09_verification/trade_finance_duplicate_registry_handoff.primary.verification.json",
        "audit_path": "10_audit/trade_finance_duplicate_registry_handoff.primary.audit.json",
        "lane_classification": lane_classification,
    },
}
manifest["circuit_modules"] = [
    {
        "module_id": "trade_finance_decision_core",
        "backend": effective_backend,
        "program_path": "07_compiled/trade_finance_decision_core.primary.program.json",
        "compiled_path": "07_compiled/trade_finance_decision_core.primary.compiled.json",
        "proof_path": "08_proofs/trade_finance_decision_core.primary.proof.json",
        "audit_path": "10_audit/trade_finance_decision_core.primary.audit.json",
        "guaranteed_primitives": [
            "poseidon-commitment",
            "range",
            "comparison",
            "exact-division",
            "action-derivation",
            "settlement-binding",
        ],
    },
    {
        "module_id": "trade_finance_settlement_binding",
        "backend": effective_backend,
        "program_path": "07_compiled/trade_finance_settlement_binding.primary.program.json",
        "compiled_path": "07_compiled/trade_finance_settlement_binding.primary.compiled.json",
        "proof_path": "08_proofs/trade_finance_settlement_binding.primary.proof.json",
        "audit_path": "10_audit/trade_finance_settlement_binding.primary.audit.json",
        "guaranteed_primitives": [
            "settlement-binding",
            "hold-gating",
            "repayment-completion",
        ],
    },
    {
        "module_id": "trade_finance_disclosure_projection",
        "backend": effective_backend,
        "program_path": "07_compiled/trade_finance_disclosure_projection.primary.program.json",
        "compiled_path": "07_compiled/trade_finance_disclosure_projection.primary.compiled.json",
        "proof_path": "08_proofs/trade_finance_disclosure_projection.primary.proof.json",
        "audit_path": "10_audit/trade_finance_disclosure_projection.primary.audit.json",
        "guaranteed_primitives": [
            "role-selector",
            "selective-disclosure-binding",
            "credential-authorization-binding",
        ],
    },
    {
        "module_id": "trade_finance_duplicate_registry_handoff",
        "backend": effective_backend,
        "program_path": "07_compiled/trade_finance_duplicate_registry_handoff.primary.program.json",
        "compiled_path": "07_compiled/trade_finance_duplicate_registry_handoff.primary.compiled.json",
        "proof_path": "08_proofs/trade_finance_duplicate_registry_handoff.primary.proof.json",
        "audit_path": "10_audit/trade_finance_duplicate_registry_handoff.primary.audit.json",
        "guaranteed_primitives": [
            "exact-division",
            "deterministic-shard-assignment",
            "aggregation-binding",
        ],
    },
]
manifest["contracts"] = [
    {
        "contract_id": "financing_request_registration",
        "primary_target": "midnight",
        "compact_source": "16_compact/trade-finance-settlement/contracts/compact/financing_request_registration.compact",
        "midnight_class": "custom",
    },
    {
        "contract_id": "settlement_authorization",
        "primary_target": "midnight",
        "compact_source": "16_compact/trade-finance-settlement/contracts/compact/settlement_authorization.compact",
        "midnight_class": "cooperative-treasury",
    },
    {
        "contract_id": "dispute_hold",
        "primary_target": "midnight",
        "compact_source": "16_compact/trade-finance-settlement/contracts/compact/dispute_hold.compact",
        "midnight_class": "custom",
    },
    {
        "contract_id": "disclosure_access",
        "primary_target": "midnight",
        "compact_source": "16_compact/trade-finance-settlement/contracts/compact/disclosure_access.compact",
        "midnight_class": "custom",
    },
    {
        "contract_id": "repayment_completion",
        "primary_target": "midnight",
        "compact_source": "16_compact/trade-finance-settlement/contracts/compact/repayment_completion.compact",
        "midnight_class": "custom",
    },
    {
        "contract_id": "supplier_receipt_confirmation",
        "primary_target": "midnight",
        "compact_source": "16_compact/trade-finance-settlement/contracts/compact/supplier_receipt_confirmation.compact",
        "midnight_class": "custom",
    },
]
if verifier_exists:
    manifest["contracts"].insert(0, {
        "contract_id": "trade_finance_verifier",
        "primary_target": "evm",
        "primary_circuit": "trade_finance_decision_core",
        "solidity_output": "15_solidity/TradeFinanceVerifier.sol",
        "verifier_contract_name": "TradeFinanceVerifier",
        "evm_class": "verifier-export",
    })
manifest["disclosure_policy"] = {
    "policy_id": "trade-finance-disclosure-policy-v1",
    "summary": "Raw supplier, buyer, invoice, pricing, and financing-policy evidence remain local while decision commitments, review flags, and selective disclosure bundles are exported.",
    "witness_local_only": True,
    "public_inputs_documented": True,
    "notes": [
        "Rejections and high-risk actions preserve human review.",
        "Midnight package is emitted for preview integration and requires separate operator readiness.",
    ],
}
manifest["deployment_profile"] = {
    "primary_chain": "midnight",
    "primary_network": "preview-emitted",
    "supports_live_deploy": False,
    "explorer_expected": False,
    "secondary_targets": ["runtime-hypernova"] + (["evm-verifier-export"] if verifier_exists else []),
}
manifest["release_contract"] = {
    "public_bundle_dir": "13_public_bundle",
    "evidence_bundle_path": "13_public_bundle/subsystem_bundle.json",
    "release_pin_path": "20_release/zkf-release-pin.json",
    "disclosure_policy_path": "06_docs/disclosure_policy.md",
}
manifest["evidence_refs"] = {
    "report_path": "17_report/report.md",
    "summary_path": "17_report/summary.json",
    "telemetry_report_path": "17_report/telemetry_report.json",
    "translation_report_path": "17_report/translation_report.json",
    "witness_summary_path": "17_report/witness_summary.json",
    "public_inputs_path": "03_inputs/public_inputs.json",
    "public_outputs_path": "03_inputs/public_outputs.json",
    "evidence_summary_path": "17_report/evidence_summary.json",
    "deterministic_manifest_path": "17_report/deterministic_manifest.json",
    "closure_artifacts_path": "17_report/closure_artifacts.json",
    "midnight_package_manifest_path": "16_compact/trade-finance-settlement/package_manifest.json",
    "midnight_flow_manifest_path": "16_compact/trade-finance-settlement/flow_manifest.json",
    "midnight_validation_summary_path": "17_report/midnight_validation/summary.json",
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY

if [[ -f "$artifact_root/solidity/TradeFinanceVerifier.sol" ]]; then
  mkdir -p "$subsystem_root/15_solidity"
  cp "$artifact_root/solidity/TradeFinanceVerifier.sol" "$subsystem_root/15_solidity/TradeFinanceVerifier.sol"
fi

echo "[trade-finance-subsystem] post-processing subsystem package for reviewer-safe portability" >&2
python3 "$repo_root/scripts/postprocess_private_trade_finance_settlement_subsystem.py" \
  "$repo_root" \
  "$artifact_root" \
  "$subsystem_root" > /dev/null

echo "[trade-finance-subsystem] re-signing subsystem credential after post-processing" >&2
cargo run -q -p zkf-cli --example resign_subsystem_credential -- "$subsystem_root" > /dev/null

echo "[trade-finance-subsystem] verifying subsystem completeness" >&2
"$repo_root/target-public/debug/zkf-cli" subsystem verify-completeness \
  --root "$subsystem_root" \
  --json > "$subsystem_root/17_report/verify-completeness.json"

echo "[trade-finance-subsystem] bundling public subsystem view" >&2
"$repo_root/target-public/debug/zkf-cli" subsystem bundle-public \
  --root "$subsystem_root" \
  --json > "$subsystem_root/17_report/bundle-public.json"

echo "[trade-finance-subsystem] final portability scrub after generated reports" >&2
python3 "$repo_root/scripts/postprocess_private_trade_finance_settlement_subsystem.py" \
  "$repo_root" \
  "$artifact_root" \
  "$subsystem_root" > /dev/null

echo "[trade-finance-subsystem] re-signing subsystem credential after final scrub" >&2
cargo run -q -p zkf-cli --example resign_subsystem_credential -- "$subsystem_root" > /dev/null

echo "$subsystem_root"
