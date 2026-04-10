#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -L)"
extraction_dir="$repo_root/zkf-backends/proofs/rocq/extraction"
include_namespaces="-** +zkf_protocol_exact_hax::proof_groth16_exact_spec::* +zkf_protocol_exact_hax::proof_fri_exact_spec::* +zkf_protocol_exact_hax::proof_nova_exact_spec::* +zkf_protocol_exact_hax::proof_hypernova_exact_spec::*"
hax_core_root_default="$HOME/Projects/ZK DEV/.zkf-tools/hax/src/hax/hax-lib/proof-libs/coq/coq/generated-core"
hax_core_root="${HAX_COQ_CORE_ROOT:-$hax_core_root_default}"
recordupdate_root_default="$repo_root/zkf-core/proofs/rocq/vendor/RecordUpdate"
recordupdate_root="${HAX_COQ_RECORDUPDATE_ROOT:-$recordupdate_root_default}"

(
  cd "$repo_root"
  cargo hax -C -p zkf-protocol-exact-hax ';' into \
    --output-dir "$extraction_dir" \
    -i "$include_namespaces" \
    coq
)

(
  cd "$extraction_dir"
  {
    printf '%s\n' '-R ./ TODO'
    find . -maxdepth 1 -type f -name '*.v' | sed 's#^\./##' | sort
  } > _CoqProject
)

python3 - "$extraction_dir" <<'PY'
from pathlib import Path
import sys

extraction_dir = Path(sys.argv[1])
patches = {
    "Zkf_protocol_exact_hax_Proof_fri_exact_spec.v": (
        "Definition fri_exact_verifier_guard",
        """Definition t_FriExactSurfaceModel := FriExactSurfaceModel_record.
Notation f_transcript_matches := FriExactSurfaceModel_f_transcript_matches.
Notation f_seed_replay_matches := FriExactSurfaceModel_f_seed_replay_matches.
Notation f_merkle_queries_match := FriExactSurfaceModel_f_merkle_queries_match.
Notation f_verifier_accepts := FriExactSurfaceModel_f_verifier_accepts.
Definition f_not (value : bool) : bool := negb value.
Definition FriExactSurfaceModel := Build_FriExactSurfaceModel_record.

""",
    ),
    "Zkf_protocol_exact_hax_Proof_groth16_exact_spec.v": (
        "Definition groth16_verifier_guard",
        """Definition t_Groth16ExactSurfaceModel := Groth16ExactSurfaceModel_record.
Notation f_imported_crs_valid := Groth16ExactSurfaceModel_f_imported_crs_valid.
Notation f_public_input_arity_matches := Groth16ExactSurfaceModel_f_public_input_arity_matches.
Notation f_encoding_matches := Groth16ExactSurfaceModel_f_encoding_matches.
Notation f_verifier_accepts := Groth16ExactSurfaceModel_f_verifier_accepts.
Notation f_simulator_view_matches := Groth16ExactSurfaceModel_f_simulator_view_matches.
Definition f_not (value : bool) : bool := negb value.
Definition Groth16ExactSurfaceModel := Build_Groth16ExactSurfaceModel_record.

""",
    ),
    "Zkf_protocol_exact_hax_Proof_nova_exact_spec.v": (
        "Definition complete_classic_nova_ivc_metadata",
        """Definition t_NovaExactSurfaceModel := NovaExactSurfaceModel_record.
Notation f_metadata_complete := NovaExactSurfaceModel_f_metadata_complete.
Notation f_verifier_guards_match := NovaExactSurfaceModel_f_verifier_guards_match.
Notation f_fold_profile_matches := NovaExactSurfaceModel_f_fold_profile_matches.
Notation f_verifier_accepts := NovaExactSurfaceModel_f_verifier_accepts.
Definition f_not (value : bool) : bool := negb value.
Definition NovaExactSurfaceModel := Build_NovaExactSurfaceModel_record.

""",
    ),
    "Zkf_protocol_exact_hax_Proof_hypernova_exact_spec.v": (
        "Definition hypernova_exact_verifier_guard",
        """Definition t_HyperNovaExactSurfaceModel := HyperNovaExactSurfaceModel_record.
Notation f_ccs_metadata_complete := HyperNovaExactSurfaceModel_f_ccs_metadata_complete.
Notation f_verifier_guards_match := HyperNovaExactSurfaceModel_f_verifier_guards_match.
Notation f_fold_profile_matches := HyperNovaExactSurfaceModel_f_fold_profile_matches.
Notation f_verifier_accepts := HyperNovaExactSurfaceModel_f_verifier_accepts.
Definition f_not (value : bool) : bool := negb value.
Definition HyperNovaExactSurfaceModel := Build_HyperNovaExactSurfaceModel_record.

""",
    ),
}

for filename, (needle, block) in patches.items():
    path = extraction_dir / filename
    text = path.read_text()
    if block in text:
        continue
    if needle not in text:
        raise SystemExit(f"missing needle {needle!r} in {path}")
    path.write_text(text.replace(needle, block + needle, 1))
PY

coq_args=(-q -R . ZkfBackendsExtraction)
if [[ -d "$hax_core_root/src" && -d "$hax_core_root/spec" && -d "$hax_core_root/phase_library" ]]; then
  coq_args+=(
    -R "$hax_core_root/src" Core
    -R "$hax_core_root/spec" Core
    -R "$hax_core_root/phase_library" Core
  )
fi
if [[ -d "$recordupdate_root" ]]; then
  coq_args+=(-Q "$recordupdate_root" RecordUpdate)
fi

(
  cd "$extraction_dir"
  for extracted_module in \
    Zkf_protocol_exact_hax_Proof_fri_exact_spec.v \
    Zkf_protocol_exact_hax_Proof_groth16_exact_spec.v \
    Zkf_protocol_exact_hax_Proof_nova_exact_spec.v \
    Zkf_protocol_exact_hax_Proof_hypernova_exact_spec.v
  do
    coqc "${coq_args[@]}" "$extracted_module"
  done
)

"$repo_root/scripts/run_rocq_proofs.sh" \
  zkf-backends/proofs/rocq/ProtocolExactSemantics.v \
  zkf-backends/proofs/rocq/ProtocolExactProofs.v
