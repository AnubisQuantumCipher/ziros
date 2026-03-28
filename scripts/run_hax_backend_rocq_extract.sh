#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$repo_root/zkf-backends/proofs/rocq/HAX_PIN.toml"
crate_root="$repo_root/zkf-backends"
rocq_workspace="$crate_root/proofs/rocq"
coq_output="$crate_root/proofs/coq/extraction"
rocq_output="$rocq_workspace/extraction"
bootstrap_script="$repo_root/scripts/bootstrap_hax_toolchain.sh"
env_file="$repo_root/.zkf-tools/hax/hax.env"

pin_value() {
  local key="$1"
  awk -F '"' -v key="$key" '$1 ~ "^" key " = " { print $2; exit }' "$pin_file"
}

inject_after_core_import() {
  local file="$1"
  local import_line="$2"

  if [ ! -f "$file" ] || [ -z "$import_line" ]; then
    return 0
  fi

  if grep -Fq "$import_line" "$file"; then
    return 0
  fi

  local temp_file
  temp_file="$(mktemp)"
  awk -v import_line="$import_line" '
    BEGIN { inserted = 0 }
    {
      print
      if (!inserted && $0 == "From Core Require Import Core.") {
        print import_line
        inserted = 1
      }
    }
  ' "$file" >"$temp_file"
  mv "$temp_file" "$file"
}

inject_after_exact_line() {
  local file="$1"
  local anchor_line="$2"
  local insert_line="$3"

  if [ ! -f "$file" ] || [ -z "$anchor_line" ] || [ -z "$insert_line" ]; then
    return 0
  fi

  if grep -Fq "$insert_line" "$file"; then
    return 0
  fi

  local temp_file
  temp_file="$(mktemp)"
  awk -v anchor_line="$anchor_line" -v insert_line="$insert_line" '
    BEGIN { inserted = 0 }
    {
      print
      if (!inserted && $0 == anchor_line) {
        print insert_line
        inserted = 1
      }
    }
  ' "$file" >"$temp_file"
  mv "$temp_file" "$file"
}

inject_block_after_exact_line() {
  local file="$1"
  local anchor_line="$2"
  local block="$3"

  if [ ! -f "$file" ] || [ -z "$anchor_line" ] || [ -z "$block" ]; then
    return 0
  fi

  local sentinel
  sentinel="$(printf '%s' "$block" | head -n 1)"
  if grep -Fq "$sentinel" "$file"; then
    return 0
  fi

  python3 - "$file" "$anchor_line" "$block" <<'PY'
from pathlib import Path
import sys

file_path = Path(sys.argv[1])
anchor_line = sys.argv[2]
block = sys.argv[3].encode("utf-8").decode("unicode_escape")
lines = file_path.read_text().splitlines()
updated = []
inserted = False

for line in lines:
    updated.append(line)
    if not inserted and line == anchor_line:
        updated.extend(block.splitlines())
        inserted = True

file_path.write_text("\n".join(updated) + "\n")
PY
}

inject_record_constructor_aliases() {
  local file="$1"
  shift

  if [ ! -f "$file" ] || [ "$#" -eq 0 ]; then
    return 0
  fi

  python3 - "$file" "$@" <<'PY'
from pathlib import Path
import sys

file_path = Path(sys.argv[1])
aliases = sys.argv[2:]
text = file_path.read_text()
lines = text.splitlines()
updated = []
for line in lines:
    updated.append(line)
    for alias in aliases:
        anchor = f"settable! (Build_{alias}_record)"
        definition = f"Definition {alias} := Build_{alias}_record."
        if anchor in line and definition not in text:
            updated.append(definition)
file_path.write_text("\n".join(updated) + ("\n" if text.endswith("\n") else ""))
PY
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
record_order = []
suffix_counts = {}
current_record = None
for line in lines:
    record_match = re.match(r"Record\s+([A-Za-z0-9_]+)_record\s+:\s+Type\s+:=", line)
    if record_match:
        current_record = record_match.group(1)
        record_order.append(current_record)
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

normalize_tuple_fun_binders() {
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

counter = 0

def fresh(prefix: str) -> str:
    global counter
    counter += 1
    return f"{prefix}_{counter}"

def repl_both(match):
    left = match.group(1)
    right = match.group(2)
    arg1 = fresh("tuple_arg")
    arg2 = fresh("tuple_arg")
    return (
        f"fun {arg1} {arg2} => let '({left}) := {arg1} in "
        f"let '({right}) := {arg2} in"
    )

def repl_first(match):
    left = match.group(1)
    right = match.group(2)
    arg1 = fresh("tuple_arg")
    return f"fun {arg1} {right} => let '({left}) := {arg1} in"

def repl_second(match):
    left = match.group(1)
    right = match.group(2)
    arg2 = fresh("tuple_arg")
    return f"fun {left} {arg2} => let '({right}) := {arg2} in"

patterns = [
    (re.compile(r"fun \(([^()]+,[^()]+)\) \(([^()]+,[^()]+)\) =>"), repl_both),
    (re.compile(r"fun \(([^()]+,[^()]+)\) ([A-Za-z0-9_]+) =>"), repl_first),
    (re.compile(r"fun ([A-Za-z0-9_]+) \(([^()]+,[^()]+)\) =>"), repl_second),
]

changed = True
while changed:
    changed = False
    for pattern, repl in patterns:
        next_text, count = pattern.subn(repl, text)
        if count:
            text = next_text
            changed = True

file_path.write_text(text)
PY
}

normalize_tuple_let_binders() {
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
pattern = re.compile(r"let \(([^()]+,[^()]+,[^()]+)\) :=")
text = pattern.sub(r"let '(\1) :=", text)
file_path.write_text(text)
PY
}

normalize_controlflow_break_hoists() {
  local file="$1"

  if [ ! -f "$file" ]; then
    return 0
  fi

  python3 - "$file" <<'PY'
from pathlib import Path
import re
import sys

file_path = Path(sys.argv[1])
lines = file_path.read_text().splitlines()
updated = []
i = 0

pattern = re.compile(r"^(\s*)let (hoist\d+) := ControlFlow_Break \((.*)\) in$")

while i < len(lines):
    line = lines[i]
    match = pattern.match(line)
    if match and i + 1 < len(lines):
        indent, name, payload = match.groups()
        next_line = lines[i + 1]
        target = f"{indent}ControlFlow_Continue (never_to_any ({name}))"
        if next_line == target:
            updated.append(f"{indent}ControlFlow_Break ({payload})")
            i += 2
            continue
    updated.append(line)
    i += 1

file_path.write_text("\n".join(updated) + "\n")
PY
}

normalize_record_variant_patterns() {
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
text = re.sub(
    r"\| DerivedComputation_Division \(([^()]+)\) \(([^()]+)\) =>",
    r"| DerivedComputation_Division ({| DerivedComputation_Division_f_division_numerator := \1; DerivedComputation_Division_f_division_denominator := \2 |}) =>",
    text,
)
text = re.sub(
    r"\| DerivedComputation_Division =>",
    r"| DerivedComputation_Division _ =>",
    text,
)
text = re.sub(
    r"\| DerivedComputation_RangeBit \(([^()]+)\) \(([^()]+)\) =>",
    r"| DerivedComputation_RangeBit ({| DerivedComputation_RangeBit_f_range_source_index := \1; DerivedComputation_RangeBit_f_range_bit := \2 |}) =>",
    text,
)
text = re.sub(
    r"\| DerivedComputation_RangeBit \(([A-Za-z0-9_]+)\) =>",
    r"| DerivedComputation_RangeBit ({| DerivedComputation_RangeBit_f_range_source_index := \1; DerivedComputation_RangeBit_f_range_bit := _ |}) =>",
    text,
)
text = re.sub(
    r"\| SpecConstraint_Equal \(([^()]+)\) \(([^()]+)\) =>",
    r"| SpecConstraint_Equal ({| SpecConstraint_Equal_f_equal_lhs := \1; SpecConstraint_Equal_f_equal_rhs := \2 |}) =>",
    text,
)
text = re.sub(
    r"\| SpecConstraint_Boolean \(([^()]+)\) =>",
    r"| SpecConstraint_Boolean ({| SpecConstraint_Boolean_f_boolean_signal := \1 |}) =>",
    text,
)
text = re.sub(
    r"\| SpecConstraint_Range \(([^()]+)\) \(([^()]+)\) =>",
    r"| SpecConstraint_Range ({| SpecConstraint_Range_f_range_signal := \1; SpecConstraint_Range_f_range_bits := \2 |}) =>",
    text,
)
file_path.write_text(text)
PY
}

normalize_unit_patterns() {
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
text = re.sub(r"Result_Ok \(\(\)\)", "Result_Ok tt", text)
text = re.sub(r"Result_Err \(\(\)\)", "Result_Err tt", text)
file_path.write_text(text)
PY
}

patch_backend_generated_dependencies() {
  local ecdsa_file="$rocq_output/Zkf_backends_Proof_blackbox_ecdsa_spec.v"
  local hash_file="$rocq_output/Zkf_backends_Proof_blackbox_hash_spec.v"
  local plonky3_file="$rocq_output/Zkf_backends_Proof_plonky3_surface.v"

  for generated_file in "$ecdsa_file" "$hash_file" "$plonky3_file"; do
    inject_after_core_import "$generated_file" "From Core Require Import ControlFlow."
    inject_after_core_import "$generated_file" "Require Import BackendCompat."
  done

  if [ -f "$ecdsa_file" ]; then
    inject_record_constructor_aliases \
      "$ecdsa_file" \
      "CriticalEcdsaRuntimeRelation" \
      "CriticalEcdsaByteAbiSemantics"
    inject_record_type_aliases "$ecdsa_file"
    inject_record_field_aliases "$ecdsa_file"
  fi

  if [ -f "$hash_file" ]; then
    inject_record_constructor_aliases \
      "$hash_file" \
      "CriticalHashLoweringSemantics"
    inject_record_type_aliases "$hash_file"
    inject_record_field_aliases "$hash_file"
  fi

  if [ -f "$plonky3_file" ]; then
    inject_block_after_exact_line \
      "$plonky3_file" \
      "| SpecPlonky3FieldId_Mersenne31." \
      "Definition spec_plonky3_field_id_eq (lhs rhs : t_SpecPlonky3FieldId) : bool :=\n  match lhs, rhs with\n  | SpecPlonky3FieldId_Goldilocks, SpecPlonky3FieldId_Goldilocks => true\n  | SpecPlonky3FieldId_BabyBear, SpecPlonky3FieldId_BabyBear => true\n  | SpecPlonky3FieldId_Mersenne31, SpecPlonky3FieldId_Mersenne31 => true\n  | _, _ => false\n  end.\n#[global] Instance t_PartialEq_SpecPlonky3FieldId : t_PartialEq t_SpecPlonky3FieldId t_SpecPlonky3FieldId :=\n  {\n    PartialEq_f_eq := spec_plonky3_field_id_eq;\n    PartialEq_f_ne := fun lhs rhs => negb (spec_plonky3_field_id_eq lhs rhs);\n  }."
    inject_block_after_exact_line \
      "$plonky3_file" \
      "| SpecVisibility_Private." \
      "Definition spec_visibility_eq (lhs rhs : t_SpecVisibility) : bool :=\n  match lhs, rhs with\n  | SpecVisibility_Public, SpecVisibility_Public => true\n  | SpecVisibility_Private, SpecVisibility_Private => true\n  | _, _ => false\n  end.\n#[global] Instance t_PartialEq_SpecVisibility : t_PartialEq t_SpecVisibility t_SpecVisibility :=\n  {\n    PartialEq_f_eq := spec_visibility_eq;\n    PartialEq_f_ne := fun lhs rhs => negb (spec_visibility_eq lhs rhs);\n  }."
    inject_after_exact_line \
      "$plonky3_file" \
      "From Core Require Import ControlFlow." \
      "Definition t_BTreeMap (_ : Type) (B : Type) (_ : globality) := list (t_String * B)."
    inject_after_exact_line \
      "$plonky3_file" \
      "Definition t_BTreeMap (_ : Type) (B : Type) (_ : globality) := list (t_String * B)." \
      "Fixpoint impl_20__contains_key (A B : Type) (G : globality) (target : t_BTreeMap A B G) (key : t_String) : bool := match target with | [] => false | (current_key, _) :: remaining => if String.eqb current_key key then true else impl_20__contains_key A B G remaining key end."
    inject_after_exact_line \
      "$plonky3_file" \
      "Fixpoint impl_20__contains_key (A B : Type) (G : globality) (target : t_BTreeMap A B G) (key : t_String) : bool := match target with | [] => false | (current_key, _) :: remaining => if String.eqb current_key key then true else impl_20__contains_key A B G remaining key end." \
      "Fixpoint impl_20__get (A B : Type) (G : globality) (target : t_BTreeMap A B G) (key : t_String) : t_Option B := match target with | [] => Option_None | (current_key, current_value) :: remaining => if String.eqb current_key key then Option_Some current_value else impl_20__get A B G remaining key end."
    inject_after_exact_line \
      "$plonky3_file" \
      "Fixpoint impl_20__get (A B : Type) (G : globality) (target : t_BTreeMap A B G) (key : t_String) : t_Option B := match target with | [] => Option_None | (current_key, current_value) :: remaining => if String.eqb current_key key then Option_Some current_value else impl_20__get A B G remaining key end." \
      "Definition impl_20__insert (A B : Type) (G : globality) (target : t_BTreeMap A B G) (key : t_String) (value : B) : t_BTreeMap A B G * t_Option B := ((key, value) :: target, Option_None)."
    inject_record_constructor_aliases \
      "$plonky3_file" \
      "MulState" \
      "InverseState" \
      "Pow2State" \
      "DerivedColumn" \
      "LoweredProgram" \
      "LoweringContext"
    inject_record_type_aliases "$plonky3_file"
    inject_record_field_aliases "$plonky3_file"
    normalize_tuple_fun_binders "$plonky3_file"
    normalize_tuple_let_binders "$plonky3_file"
    normalize_controlflow_break_hoists "$plonky3_file"
    normalize_record_variant_patterns "$plonky3_file"
    normalize_unit_patterns "$plonky3_file"
  fi
}

crate_name="$(pin_value crate)"
backend_name="$(pin_value backend)"
include_filter="$(pin_value include)"
switch_name="$(pin_value opam_switch)"

if [ ! -f "$pin_file" ]; then
  echo "missing backend hax pin at $pin_file" >&2
  exit 1
fi

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
  echo "cargo-hax is required to extract zkf-backends proof kernels into Rocq" >&2
  exit 1
fi

if [ -n "$switch_name" ] && [ "$(opam switch show 2>/dev/null || true)" != "$switch_name" ]; then
  echo "expected opam switch '$switch_name' while running backend hax extraction" >&2
  exit 1
fi

cd "$repo_root"
rm -rf "$coq_output"
mkdir -p "$coq_output"
cargo hax -C -p "$crate_name" ';' into -i "$include_filter" --output-dir "$coq_output" "$backend_name"

if [ ! -d "$coq_output" ]; then
  echo "hax did not produce the expected Coq extraction output at $coq_output" >&2
  exit 1
fi

rm -rf "$rocq_output"
mkdir -p "$rocq_output"
cp -R "$coq_output"/. "$rocq_output"/
patch_backend_generated_dependencies

if ! find "$rocq_output" -type f -name '*.v' | grep -q .; then
  echo "no Rocq extraction files were mirrored into $rocq_output" >&2
  exit 1
fi

printf '[backend-hax] mirrored extraction into %s\n' "$rocq_output"
