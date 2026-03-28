#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <pin-file>" >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$1"
bootstrap_script="$repo_root/scripts/bootstrap_hax_toolchain.sh"
env_file="$repo_root/.zkf-tools/hax/hax.env"

if [ ! -f "$pin_file" ]; then
  echo "missing hax pin at $pin_file" >&2
  exit 1
fi

pin_value() {
  local key="$1"
  awk -F '"' -v key="$key" '$1 ~ "^" key " = " { print $2; exit }' "$pin_file"
}

inject_after_line() {
  local file="$1"
  local anchor_line="$2"
  local inserted_line="$3"

  if [ ! -f "$file" ] || [ -z "$anchor_line" ] || [ -z "$inserted_line" ]; then
    return 0
  fi

  if grep -Fq "$inserted_line" "$file"; then
    return 0
  fi

  local temp_file
  temp_file="$(mktemp)"
  awk -v anchor_line="$anchor_line" -v inserted_line="$inserted_line" '
    BEGIN { inserted = 0 }
    {
      print
      if (!inserted && $0 == anchor_line) {
        print inserted_line
        inserted = 1
      }
    }
  ' "$file" >"$temp_file"
  mv "$temp_file" "$file"
}

inject_after_core_import() {
  local file="$1"
  local import_line="$2"

  inject_after_line "$file" "From Core Require Import Core." "$import_line"
}

strip_record_update_import() {
  local file="$1"

  if [ ! -f "$file" ] || ! grep -Fq "From RecordUpdate Require Import RecordSet." "$file"; then
    return 0
  fi

  local temp_file
  temp_file="$(mktemp)"
  awk '
    $0 == "From RecordUpdate Require Import RecordSet." { next }
    $0 == "Import RecordSetNotations." { next }
    { print }
  ' "$file" >"$temp_file"
  mv "$temp_file" "$file"
}

sync_record_update_import() {
  local file="$1"

  if [ ! -f "$file" ]; then
    return 0
  fi

  if grep -Fq "settable!" "$file"; then
    inject_after_core_import "$file" "From RecordUpdate Require Import RecordSet."
    inject_after_line \
      "$file" \
      "From RecordUpdate Require Import RecordSet." \
      "Import RecordSetNotations."
  else
    strip_record_update_import "$file"
  fi
}

inject_record_type_aliases() {
  local file="$1"

  if [ ! -f "$file" ]; then
    return 0
  fi

  python3 - "$file" <<'PY'
from pathlib import Path
import re
import sys

file_path = Path(sys.argv[1])
text = file_path.read_text()
lines = text.splitlines()
updated = []
current_record = None

for line in lines:
    record_match = re.match(r"Record\s+([A-Za-z0-9_]+)_record\s+:\s+Type\s+:=", line)
    if record_match:
        current_record = record_match.group(1)
        updated.append(line)
        continue

    updated.append(line)

    if current_record is not None and line.strip() == "}.":
        alias = f"Definition t_{current_record} := {current_record}_record."
        if alias not in text:
            updated.append(alias)
        current_record = None

file_path.write_text("\n".join(updated) + ("\n" if text.endswith("\n") else ""))
PY
}

inject_record_field_aliases() {
  local file="$1"

  if [ ! -f "$file" ]; then
    return 0
  fi

  python3 - "$file" <<'PY'
from pathlib import Path
import re
import sys

file_path = Path(sys.argv[1])
text = file_path.read_text()
lines = text.splitlines()
record_fields = {}
suffix_counts = {}
current_record = None

for line in lines:
    record_match = re.match(r"Record\s+([A-Za-z0-9_]+)_record\s+:\s+Type\s+:=", line)
    if record_match:
        current_record = record_match.group(1)
        record_fields[current_record] = []
        continue
    if current_record is not None:
        if line.strip() == "}.":
            current_record = None
            continue
        field_match = re.match(r"\s+([A-Za-z0-9_]+)\s+:\s+.*;", line)
        if field_match:
            field_name = field_match.group(1)
            if "_f_" in field_name:
                record_fields[current_record].append(field_name)
                suffix = field_name.split("_f_", 1)[1]
                suffix_counts[suffix] = suffix_counts.get(suffix, 0) + 1

updated = []
for line in lines:
    updated.append(line)
    settable_match = re.search(r"settable! \(Build_([A-Za-z0-9_]+)_record\)", line)
    if not settable_match:
        continue
    record_name = settable_match.group(1)
    for field_name in record_fields.get(record_name, []):
        suffix = field_name.split("_f_", 1)[1]
        if suffix_counts.get(suffix, 0) == 1:
            notation = f"Notation f_{suffix} := {field_name}."
            if notation not in text:
                updated.append(notation)
        update_notation = f"Notation t_{record_name}f_{suffix} := {field_name}."
        if update_notation not in text:
            updated.append(update_notation)

file_path.write_text("\n".join(updated) + ("\n" if text.endswith("\n") else ""))
PY
}

inject_record_constructor_aliases() {
  local file="$1"

  if [ ! -f "$file" ]; then
    return 0
  fi

  python3 - "$file" <<'PY'
from pathlib import Path
import re
import sys

file_path = Path(sys.argv[1])
text = file_path.read_text()
lines = text.splitlines()
updated = []

for line in lines:
    updated.append(line)
    settable_match = re.search(r"settable! \(Build_([A-Za-z0-9_]+)_record\)", line)
    if not settable_match:
        continue
    record_name = settable_match.group(1)
    definition = f"Definition {record_name} := Build_{record_name}_record."
    if definition not in text:
        updated.append(definition)

file_path.write_text("\n".join(updated) + ("\n" if text.endswith("\n") else ""))
PY
}

repair_known_extraction_issues() {
  local file="$1"

  case "$file" in
    */Zkf_runtime_Proof_runtime_spec.v)
      python3 - "$file" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
old = """Fixpoint runtime_digest_bytes_match_slices (expected : t_Slice t_u8) (found : t_Slice t_u8) : bool :=
  match (impl__split_first (expected),impl__split_first (found)) with
  | (Option_None,Option_None) =>
    (true : bool)
  | (Option_Some ((expected_head,expected_tail)),Option_Some ((found_head,found_tail))) =>
    andb (f_eq (expected_head) (found_head)) (runtime_digest_bytes_match_slices (expected_tail) (found_tail))
  | _ =>
    (false : bool)
  end.

Definition runtime_digest_bytes_match (expected : t_Vec ((t_u8)) ((t_Global))) (found : t_Vec ((t_u8)) ((t_Global))) : bool :=
  runtime_digest_bytes_match_slices (f_deref (expected)) (f_deref (found))."""
new = """Fixpoint runtime_digest_bytes_match_lists (expected : list t_u8) (found : list t_u8) : bool :=
  match expected, found with
  | [], [] =>
    (true : bool)
  | expected_head :: expected_tail, found_head :: found_tail =>
    andb
      (N.eqb (U8_f_v (u8_0 expected_head)) (U8_f_v (u8_0 found_head)))
      (runtime_digest_bytes_match_lists expected_tail found_tail)
  | _, _ =>
    (false : bool)
  end.

Definition runtime_digest_bytes_match_slices (expected : t_Slice t_u8) (found : t_Slice t_u8) : bool :=
  runtime_digest_bytes_match_lists (Slice_f_v expected) (Slice_f_v found).

Definition runtime_digest_bytes_match (expected : t_Vec ((t_u8)) ((t_Global))) (found : t_Vec ((t_u8)) ((t_Global))) : bool :=
  runtime_digest_bytes_match_lists expected found."""
path.write_text(source.replace(old, new))
PY
      ;;
    */Zkf_lib_Proof_embedded_app_spec.v)
      python3 - "$file" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
old = """Fixpoint digest_bytes_match_slices (expected : t_Slice t_u8) (found : t_Slice t_u8) : bool :=
  match (impl__split_first (expected),impl__split_first (found)) with
  | (Option_None,Option_None) =>
    (true : bool)
  | (Option_Some ((expected_head,expected_tail)),Option_Some ((found_head,found_tail))) =>
    andb (f_eq (expected_head) (found_head)) (digest_bytes_match_slices (expected_tail) (found_tail))
  | _ =>
    (false : bool)
  end.

Definition digest_bytes_match (expected : t_Vec ((t_u8)) ((t_Global))) (found : t_Vec ((t_u8)) ((t_Global))) : bool :=
  digest_bytes_match_slices (f_deref (expected)) (f_deref (found))."""
new = """Fixpoint digest_bytes_match_lists (expected : list t_u8) (found : list t_u8) : bool :=
  match expected, found with
  | [], [] =>
    (true : bool)
  | expected_head :: expected_tail, found_head :: found_tail =>
    andb
      (N.eqb (U8_f_v (u8_0 expected_head)) (U8_f_v (u8_0 found_head)))
      (digest_bytes_match_lists expected_tail found_tail)
  | _, _ =>
    (false : bool)
  end.

Definition digest_bytes_match_slices (expected : t_Slice t_u8) (found : t_Slice t_u8) : bool :=
  digest_bytes_match_lists (Slice_f_v expected) (Slice_f_v found).

Definition digest_bytes_match (expected : t_Vec ((t_u8)) ((t_Global))) (found : t_Vec ((t_u8)) ((t_Global))) : bool :=
  digest_bytes_match_lists expected found."""
source = source.replace(old, new)
source = source.replace(
    """Definition private_identity_merkle_direction_is_binary (direction : t_u8) : bool :=
  match direction with
  | 0
  | 1 =>
    (true : bool)
  | _ =>
    (false : bool)
  end.""",
    """Definition private_identity_merkle_direction_is_binary (direction : t_u8) : bool :=
  orb
    (N.eqb (U8_f_v (u8_0 direction)) 0%N)
    (N.eqb (U8_f_v (u8_0 direction)) 1%N).""",
)
source = source.replace(
    """Definition program_digests_match (expected : t_String) (found : t_String) : bool :=
  digest_bytes_match (impl_String__into_bytes (expected)) (impl_String__into_bytes (found)).""",
    """Definition program_digests_match (expected : t_String) (found : t_String) : bool :=
  String.eqb expected found.""",
)
path.write_text(source)
PY
      ;;
    */Zkf_runtime_Proof_swarm_spec.v)
      python3 - "$file" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
source = path.read_text()
old = """Definition artifact_bytes_eq (left : t_Array (t_u8) ((4 : t_usize))) (right : t_Array (t_u8) ((4 : t_usize))) : bool :=
  andb (andb (andb (f_eq (f_index (left) ((0 : t_usize))) (f_index (right) ((0 : t_usize)))) (f_eq (f_index (left) ((1 : t_usize))) (f_index (right) ((1 : t_usize))))) (f_eq (f_index (left) ((2 : t_usize))) (f_index (right) ((2 : t_usize))))) (f_eq (f_index (left) ((3 : t_usize))) (f_index (right) ((3 : t_usize)))).
"""
new = """Fixpoint u8_list_eq (left : list t_u8) (right : list t_u8) : bool :=
  match left, right with
  | [], [] =>
    (true : bool)
  | left_head :: left_tail, right_head :: right_tail =>
    andb
      (N.eqb (U8_f_v (u8_0 left_head)) (U8_f_v (u8_0 right_head)))
      (u8_list_eq left_tail right_tail)
  | _, _ =>
    (false : bool)
  end.

Definition artifact_bytes_eq (left : t_Array (t_u8) ((4 : t_usize))) (right : t_Array (t_u8) ((4 : t_usize))) : bool :=
  u8_list_eq
    (Slice_f_v (Array_f_v left))
    (Slice_f_v (Array_f_v right)).
"""
if old not in source:
    raise SystemExit("failed to repair runtime swarm extraction array equality")
source = source.replace(old, new)
source = source.replace("  | Result_Err (()) =>\n", "  | Result_Err _ =>\n")
path.write_text(source)
PY
      ;;
    */Zkf_distributed_Proof_swarm_reputation_spec.v)
      python3 - "$file" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
source = path.read_text()

exact_replacements = [
    (
        """Definition array2_eq (left : t_Array (t_u8) ((2 : t_usize))) (right : t_Array (t_u8) ((2 : t_usize))) : bool :=
  andb (f_eq (f_index (left) ((0 : t_usize))) (f_index (right) ((0 : t_usize)))) (f_eq (f_index (left) ((1 : t_usize))) (f_index (right) ((1 : t_usize)))).

Definition array4_eq (left : t_Array (t_u8) ((4 : t_usize))) (right : t_Array (t_u8) ((4 : t_usize))) : bool :=
  andb (andb (andb (f_eq (f_index (left) ((0 : t_usize))) (f_index (right) ((0 : t_usize)))) (f_eq (f_index (left) ((1 : t_usize))) (f_index (right) ((1 : t_usize))))) (f_eq (f_index (left) ((2 : t_usize))) (f_index (right) ((2 : t_usize))))) (f_eq (f_index (left) ((3 : t_usize))) (f_index (right) ((3 : t_usize)))).

Definition array8_eq (left : t_Array (t_u8) ((8 : t_usize))) (right : t_Array (t_u8) ((8 : t_usize))) : bool :=
  andb (andb (andb (andb (andb (andb (andb (f_eq (f_index (left) ((0 : t_usize))) (f_index (right) ((0 : t_usize)))) (f_eq (f_index (left) ((1 : t_usize))) (f_index (right) ((1 : t_usize))))) (f_eq (f_index (left) ((2 : t_usize))) (f_index (right) ((2 : t_usize))))) (f_eq (f_index (left) ((3 : t_usize))) (f_index (right) ((3 : t_usize))))) (f_eq (f_index (left) ((4 : t_usize))) (f_index (right) ((4 : t_usize))))) (f_eq (f_index (left) ((5 : t_usize))) (f_index (right) ((5 : t_usize))))) (f_eq (f_index (left) ((6 : t_usize))) (f_index (right) ((6 : t_usize))))) (f_eq (f_index (left) ((7 : t_usize))) (f_index (right) ((7 : t_usize)))).
""",
        """Fixpoint u8_list_eq (left : list t_u8) (right : list t_u8) : bool :=
  match left, right with
  | [], [] =>
    (true : bool)
  | left_head :: left_tail, right_head :: right_tail =>
    andb
      (N.eqb (U8_f_v (u8_0 left_head)) (U8_f_v (u8_0 right_head)))
      (u8_list_eq left_tail right_tail)
  | _, _ =>
    (false : bool)
  end.

Definition array2_eq (left : t_Array (t_u8) ((2 : t_usize))) (right : t_Array (t_u8) ((2 : t_usize))) : bool :=
  u8_list_eq
    (Slice_f_v (Array_f_v left))
    (Slice_f_v (Array_f_v right)).

Definition array4_eq (left : t_Array (t_u8) ((4 : t_usize))) (right : t_Array (t_u8) ((4 : t_usize))) : bool :=
  u8_list_eq
    (Slice_f_v (Array_f_v left))
    (Slice_f_v (Array_f_v right)).

Definition array8_eq (left : t_Array (t_u8) ((8 : t_usize))) (right : t_Array (t_u8) ((8 : t_usize))) : bool :=
  u8_list_eq
    (Slice_f_v (Array_f_v left))
    (Slice_f_v (Array_f_v right)).
""",
    ),
    (
        """Definition append_only_memory_chain_after_append (prefix : t_Array (t_u8) ((4 : t_usize))) (suffix : t_Array (t_u8) ((4 : t_usize))) : t_Array (t_u8) ((8 : t_usize)) :=
  [f_index (prefix) ((0 : t_usize)); f_index (prefix) ((1 : t_usize)); f_index (prefix) ((2 : t_usize)); f_index (prefix) ((3 : t_usize)); f_index (suffix) ((0 : t_usize)); f_index (suffix) ((1 : t_usize)); f_index (suffix) ((2 : t_usize)); f_index (suffix) ((3 : t_usize))].
""",
        """Definition append_only_memory_chain_after_append (prefix : t_Array (t_u8) ((4 : t_usize))) (suffix : t_Array (t_u8) ((4 : t_usize))) : t_Array (t_u8) ((8 : t_usize)) :=
  Build_t_Array (Build_t_Slice [f_index (prefix) ((0 : t_usize)); f_index (prefix) ((1 : t_usize)); f_index (prefix) ((2 : t_usize)); f_index (prefix) ((3 : t_usize)); f_index (suffix) ((0 : t_usize)); f_index (suffix) ((1 : t_usize)); f_index (suffix) ((2 : t_usize)); f_index (suffix) ((3 : t_usize))]).
""",
    ),
    (
        """Definition chain_prefix4 (bytes : t_Array (t_u8) ((8 : t_usize))) : t_Array (t_u8) ((4 : t_usize)) :=
  [f_index (bytes) ((0 : t_usize)); f_index (bytes) ((1 : t_usize)); f_index (bytes) ((2 : t_usize)); f_index (bytes) ((3 : t_usize))].
""",
        """Definition chain_prefix4 (bytes : t_Array (t_u8) ((8 : t_usize))) : t_Array (t_u8) ((4 : t_usize)) :=
  Build_t_Array (Build_t_Slice [f_index (bytes) ((0 : t_usize)); f_index (bytes) ((1 : t_usize)); f_index (bytes) ((2 : t_usize)); f_index (bytes) ((3 : t_usize))]).
""",
    ),
    (
        """Definition canonical_intelligence_leaf_pair (first : t_u8) (second : t_u8) : t_Array (t_u8) ((2 : t_usize)) :=
  if
    f_le (first) (second)
  then
    [first; second]
  else
    [second; first].
""",
        """Definition canonical_intelligence_leaf_pair (first : t_u8) (second : t_u8) : t_Array (t_u8) ((2 : t_usize)) :=
  if
    f_le (first) (second)
  then
    Build_t_Array (Build_t_Slice [first; second])
  else
    Build_t_Array (Build_t_Slice [second; first]).
""",
    ),
]

regex_replacements = [
    (
        r"Definition clamp_reputation_unit_interval \(value : float\) : float :=\n(?:  .*\n)+?      value\.\n",
        """Definition clamp_reputation_unit_interval (value : float) : float :=\n  if\n    (value <? min_reputation_bound (tt))%float\n  then\n    min_reputation_bound (tt)\n  else\n    if\n      (max_reputation_bound (tt) <? value)%float\n    then\n      max_reputation_bound (tt)\n    else\n      value.\n""",
    ),
    (
        r"Definition bounded_reputation_after_decayed_score_spec \(decayed_score : float\) \(kind : t_ProofReputationEvidenceKind\) : float :=\n  .*\n",
        """Definition bounded_reputation_after_decayed_score_spec (decayed_score : float) (kind : t_ProofReputationEvidenceKind) : float :=\n  clamp_reputation_unit_interval ((decayed_score + reputation_delta_for (kind))%float).\n""",
    ),
    (
        r"Definition bounded_decay_score_spec \(score : float\) \(decay_factor : float\) : float :=\n(?:  .*\n)+",
        """Definition bounded_decay_score_spec (score : float) (decay_factor : float) : float :=\n  let clamped_score := clamp_reputation_unit_interval (score) in\n  let clamped_decay := clamp_reputation_unit_interval (decay_factor) in\n  clamp_reputation_unit_interval\n    ((neutral_reputation_bound (tt)\n      + ((clamped_score - neutral_reputation_bound (tt)) * clamped_decay))%float).\n""",
    ),
]

for pattern, replacement in exact_replacements:
    if pattern in source:
        source = source.replace(pattern, replacement)

for pattern, replacement in regex_replacements:
    source, count = re.subn(pattern, replacement, source, count=1, flags=re.MULTILINE)
    if count != 1:
        raise SystemExit(f"failed to repair distributed swarm reputation extraction with pattern: {pattern}")

path.write_text(source)
PY
      ;;
  esac
}

crate_rel="$(pin_value crate_root)"
crate_name="$(pin_value crate)"
backend_name="$(pin_value backend)"
include_filter="$(pin_value include)"
switch_name="$(pin_value opam_switch)"

if [ -z "$crate_rel" ] || [ -z "$crate_name" ] || [ -z "$backend_name" ] || [ -z "$include_filter" ]; then
  echo "incomplete hax pin metadata in $pin_file" >&2
  exit 1
fi

crate_root="$repo_root/$crate_rel"
coq_output="$crate_root/proofs/coq/extraction"
rocq_output="$crate_root/proofs/rocq/extraction"

if [ ! -f "$env_file" ]; then
  "$bootstrap_script"
fi

if [ -f "$env_file" ]; then
  # shellcheck disable=SC1090
  source "$env_file"
fi

if ! cargo hax --version >/dev/null 2>&1; then
  "$bootstrap_script"
  # shellcheck disable=SC1090
  source "$env_file"
fi

if ! cargo hax --version >/dev/null 2>&1; then
  echo "cargo-hax is required to extract $crate_name proof kernels into Rocq" >&2
  exit 1
fi

if [ -n "$switch_name" ] && [ "$(opam switch show 2>/dev/null || true)" != "$switch_name" ]; then
  echo "expected opam switch '$switch_name' while running hax extraction" >&2
  exit 1
fi

mkdir -p "$coq_output" "$rocq_output"
find "$coq_output" -mindepth 1 -delete
find "$rocq_output" -mindepth 1 -delete

cd "$repo_root"
cargo hax -C -p "$crate_name" ';' into -i "$include_filter" --output-dir "$coq_output" "$backend_name"
cp -R "$coq_output"/. "$rocq_output"/

while IFS= read -r generated_file; do
  inject_after_core_import \
    "$generated_file" \
    "Require Import KernelCompat."
  sync_record_update_import "$generated_file"
  inject_record_type_aliases "$generated_file"
  inject_record_field_aliases "$generated_file"
  inject_record_constructor_aliases "$generated_file"
  repair_known_extraction_issues "$generated_file"
done < <(find "$rocq_output" -type f -name '*.v' ! -name '_CoqProject' | sort)

if ! find "$rocq_output" -type f -name '*.v' | grep -q .; then
  echo "no Rocq extraction files were mirrored into $rocq_output" >&2
  exit 1
fi

printf '[hax] mirrored %s extraction into %s\n' "$crate_name" "$rocq_output"
