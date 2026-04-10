#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
artifact_root="${1:-$repo_root/dist/showcases/private_turbine_blade_life}"
subsystem_root="${2:-$repo_root/dist/subsystems/private_turbine_blade_life}"
profile="${3:-flagship}"

canonicalize_target_path() {
  local target="$1"
  mkdir -p "$(dirname "$target")"
  printf '%s/%s\n' "$(cd "$(dirname "$target")" && pwd -L)" "$(basename "$target")"
}

artifact_root="$(canonicalize_target_path "$artifact_root")"
subsystem_root="$(canonicalize_target_path "$subsystem_root")"

mkdir -p "$(dirname "$artifact_root")" "$(dirname "$subsystem_root")"

if [[ "$profile" != "flagship" ]]; then
  echo "[turbine-subsystem] refusing profile '$profile': subsystem packaging requires a flagship bundle" >&2
  exit 1
fi

echo "[turbine-subsystem] exporting finished showcase bundle into $artifact_root" >&2
env ZKF_PRIVATE_TURBINE_BLADE_PROFILE="$profile" \
  cargo run --release -p zkf-lib --example private_turbine_blade_life_showcase -- "$artifact_root"

python3 - "$artifact_root/private_turbine_blade.summary.json" <<'PY'
import json
import sys
from pathlib import Path

summary_path = Path(sys.argv[1])
summary = json.loads(summary_path.read_text())
if summary.get("export_profile") != "flagship":
    raise SystemExit(f"{summary_path} does not describe a flagship bundle")
PY

echo "[turbine-subsystem] scaffolding subsystem shell into $subsystem_root" >&2
rm -rf "$subsystem_root"
cargo run -p zkf-cli -- subsystem scaffold \
  --name private-turbine-blade-life \
  --style full \
  --out "$subsystem_root" \
  --json > /dev/null

mkdir -p \
  "$subsystem_root/03_inputs" \
  "$subsystem_root/05_scripts" \
  "$subsystem_root/06_docs" \
  "$subsystem_root/09_verification" \
  "$subsystem_root/10_audit" \
  "$subsystem_root/15_solidity" \
  "$subsystem_root/17_report"

cp "$artifact_root/compiled/private_turbine_blade.program.original.json" \
  "$subsystem_root/07_compiled/program.json"
cp "$artifact_root/compiled/private_turbine_blade.primary.compiled.json" \
  "$subsystem_root/07_compiled/compiled.json"
cp "$artifact_root/proofs/private_turbine_blade.primary.proof.json" \
  "$subsystem_root/08_proofs/proof.json"
cp "$artifact_root/public_inputs.json" \
  "$subsystem_root/03_inputs/public_inputs.json"
cp "$artifact_root/verification/private_turbine_blade.verification_report.json" \
  "$subsystem_root/09_verification/verification.json"

cp "$artifact_root/compiled/private_turbine_blade.program.optimized.json" \
  "$subsystem_root/07_compiled/private_turbine_blade.program.optimized.json"
cp "$artifact_root/compiled/private_turbine_blade.compat.compiled.json" \
  "$subsystem_root/07_compiled/private_turbine_blade.compat.compiled.json"
cp "$artifact_root/proofs/private_turbine_blade.compat.proof.json" \
  "$subsystem_root/08_proofs/private_turbine_blade.compat.proof.json"
cp "$artifact_root/verification/private_turbine_blade.calldata.json" \
  "$subsystem_root/09_verification/private_turbine_blade.calldata.json"
cp "$artifact_root/swarm_assignments.json" \
  "$subsystem_root/09_verification/swarm_assignments.json"
cp "$artifact_root/aggregation_report.json" \
  "$subsystem_root/09_verification/aggregation_report.json"
cp "$artifact_root/private_turbine_blade.matrix_summary.json" \
  "$subsystem_root/10_audit/matrix_summary.json"
cp "$artifact_root/telemetry/private_turbine_blade.telemetry_report.json" \
  "$subsystem_root/10_audit/telemetry_report.json"
cp "$artifact_root/private_turbine_blade.audit.json" \
  "$subsystem_root/17_report/finished_app_audit_summary.json"
cp "$artifact_root/foundry_report.txt" \
  "$subsystem_root/17_report/foundry_report.txt"
cp "$artifact_root/private_turbine_blade.progress.json" \
  "$subsystem_root/17_report/progress.json"

cp "$artifact_root/foundry/src/PrivateTurbineBladeVerifier.sol" \
  "$subsystem_root/15_solidity/PrivateTurbineBladeVerifier.sol"
cp "$artifact_root/foundry/test/PrivateTurbineBladeVerifier.t.sol" \
  "$subsystem_root/15_solidity/PrivateTurbineBladeVerifier.t.sol"

cp "$artifact_root/private_turbine_blade.summary.json" \
  "$subsystem_root/17_report/summary.json"
cp "$artifact_root/private_turbine_blade.run_report.json" \
  "$subsystem_root/17_report/run_report.json"
cp "$artifact_root/private_turbine_blade.translation_report.json" \
  "$subsystem_root/17_report/translation_report.json"
cp "$artifact_root/private_turbine_blade.evidence_manifest.json" \
  "$subsystem_root/17_report/evidence_manifest.json"
cp "$artifact_root/private_turbine_blade.report.md" \
  "$subsystem_root/17_report/report.md"
cp "$artifact_root/witness_summary.json" \
  "$subsystem_root/17_report/witness_summary.json"

if [[ -d "$artifact_root/formal" ]]; then
  rm -rf "$subsystem_root/17_report/formal"
  cp -R "$artifact_root/formal" "$subsystem_root/17_report/formal"
fi

cp "$repo_root/scripts/run_rocq_turbine_blade_life_proofs.sh" \
  "$subsystem_root/05_scripts/run_rocq_turbine_blade_life_proofs.sh"
cp "$repo_root/scripts/run_verus_turbine_blade_life_proofs.sh" \
  "$subsystem_root/05_scripts/run_verus_turbine_blade_life_proofs.sh"
cp "$repo_root/scripts/materialize_private_turbine_blade_subsystem.sh" \
  "$subsystem_root/05_scripts/materialize_private_turbine_blade_subsystem.sh"

cat > "$subsystem_root/06_docs/README.md" <<'EOF'
# Private Turbine Blade Life Subsystem

This subsystem packages the finished ZirOS private turbine blade life showcase into the standard 20-slot subsystem layout.

Key surfaces:

- `07_compiled/program.json`: source program artifact
- `07_compiled/compiled.json`: primary Arkworks Groth16 compiled artifact
- `08_proofs/proof.json`: primary Arkworks Groth16 proof artifact
- `09_verification/verification.json`: verification result for the exported run
- `10_audit/audit.json`: structured finished-app audit summary
- `15_solidity/PrivateTurbineBladeVerifier.sol`: compatibility Groth16 Solidity verifier
- `17_report/foundry_report.txt`: `forge test --gas-report` output for the exported verifier bundle
- `17_report/progress.json`: final exporter progress/checkpoint state
- `17_report/report.md`: flagship engineering report for the showcase

The subsystem keeps the finished-app bundle intact while also preserving the subsystem shell generated by `zkf subsystem scaffold`.
EOF

cat > "$subsystem_root/06_docs/disclosure_policy.md" <<'EOF'
# Disclosure Policy

- Private blade geometry, material parameters, thresholds, defect state, mission profile, and commitment blinders stay local.
- The subsystem publishes only proof artifacts, verification artifacts, finished evidence, public commitments, and the public `safe_to_deploy` decision.
- Foundry verifier tests and formal runner logs are preserved under `17_report/`.
- Midnight deployment is planning-only for this subsystem bundle.
EOF

python3 - "$subsystem_root/02_manifest/subsystem_manifest.json" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
manifest = json.loads(manifest_path.read_text())
manifest["subsystem_id"] = "private_turbine_blade_life"
manifest["circuits"] = {
    "turbine_blade_life": {
        "backend": "arkworks-groth16",
        "program_path": "07_compiled/program.json",
        "compiled_path": "07_compiled/compiled.json",
        "inputs_path": "03_inputs/public_inputs.json",
        "proof_path": "08_proofs/proof.json",
        "verification_path": "09_verification/verification.json",
        "audit_path": "10_audit/audit.json",
    }
}
manifest["circuit_modules"] = [
    {
        "module_id": "turbine_blade_life",
        "backend": "arkworks-groth16",
        "program_path": "07_compiled/program.json",
        "compiled_path": "07_compiled/compiled.json",
        "proof_path": "08_proofs/proof.json",
        "audit_path": "10_audit/audit.json",
        "guaranteed_primitives": [
            "arithmetic",
            "range",
            "comparison",
            "poseidon-commitment",
            "public-output-binding",
        ],
    }
]
manifest["contracts"] = [
    {
        "contract_id": "private_turbine_blade_verifier",
        "primary_target": "evm",
        "primary_circuit": "turbine_blade_life",
        "solidity_output": "15_solidity/PrivateTurbineBladeVerifier.sol",
        "verifier_contract_name": "PrivateTurbineBladeVerifier",
        "evm_class": "verifier-export",
    }
]
manifest["disclosure_policy"] = {
    "policy_id": "private-turbine-blade-life-policy-v1",
    "summary": "Witness and private engineering inputs remain local; only commitments, the deployment decision, and finished evidence artifacts are public.",
    "witness_local_only": True,
    "public_inputs_documented": True,
    "notes": [
        "Thermal-mechanical surrogate inputs remain private.",
        "Commitment blinders are never written into the subsystem bundle.",
    ],
}
manifest["deployment_profile"] = {
    "primary_chain": "offchain",
    "primary_network": "local-or-attested-runtime",
    "supports_live_deploy": False,
    "explorer_expected": False,
    "secondary_targets": ["evm-verifier-export", "midnight-planning-only"],
}
manifest["release_contract"] = {
    "public_bundle_dir": "13_public_bundle",
    "evidence_bundle_path": "13_public_bundle/subsystem_bundle.json",
    "release_pin_path": "20_release/zkf-release-pin.json",
    "disclosure_policy_path": "06_docs/disclosure_policy.md",
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY

echo "[turbine-subsystem] generating subsystem audit artifact" >&2
cargo run -p zkf-cli -- audit \
  --program "$subsystem_root/07_compiled/program.json" \
  --out "$subsystem_root/10_audit/audit.json" > /dev/null

echo "[turbine-subsystem] verifying subsystem completeness" >&2
cargo run -p zkf-cli -- subsystem verify-completeness \
  --root "$subsystem_root" \
  --json > "$subsystem_root/17_report/verify-completeness.json"

echo "[turbine-subsystem] bundling public subsystem view" >&2
cargo run -p zkf-cli -- subsystem bundle-public \
  --root "$subsystem_root" \
  --json > "$subsystem_root/17_report/bundle-public.json"

echo "$subsystem_root"
