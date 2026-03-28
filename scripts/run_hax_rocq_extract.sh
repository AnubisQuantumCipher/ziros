#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pin_file="$repo_root/zkf-core/proofs/rocq/HAX_PIN.toml"
crate_root="$repo_root/zkf-core"
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

patch_generated_dependencies() {
  local field_file="$rocq_output/Zkf_core_Field.v"
  local ccs_file="$rocq_output/Zkf_core_Proof_ccs_spec.v"
  local bundle_file="$rocq_output/Zkf_core_Proof_kernel_spec_Bundle.v"
  local main_file="$rocq_output/Zkf_core_Proof_kernel_spec.v"
  local spec_field_ops_file="$rocq_output/Zkf_core_Proof_kernel_spec_Spec_field_ops.v"
  local transform_file="$rocq_output/Zkf_core_Proof_transform_spec.v"
  local witness_generation_file="$rocq_output/Zkf_core_Proof_witness_generation_spec.v"

  if [ -f "$bundle_file" ] && [ -f "$field_file" ]; then
    inject_after_core_import \
      "$bundle_file" \
      "Require Import KernelCompat."
    inject_after_core_import \
      "$bundle_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Field."
  elif [ -f "$bundle_file" ]; then
    inject_after_core_import \
      "$bundle_file" \
      "Require Import KernelCompat."
  fi

  if [ -f "$bundle_file" ]; then
    inject_after_core_import \
      "$main_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Proof_kernel_spec_Bundle."

    inject_after_core_import \
      "$spec_field_ops_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Proof_kernel_spec_Bundle."
  elif [ -f "$field_file" ]; then
    inject_after_core_import \
      "$main_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Field."
  fi

  if [ -f "$witness_generation_file" ]; then
    inject_after_core_import \
      "$witness_generation_file" \
      "Require Import KernelCompat."
    inject_after_core_import \
      "$witness_generation_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Proof_kernel_spec."
    inject_after_core_import \
      "$witness_generation_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Proof_kernel_spec_Bundle."
    inject_after_core_import \
      "$witness_generation_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Field."

    inject_after_exact_line \
      "$witness_generation_file" \
      "  settable! (Build_SpecWitnessSignal_record) <SpecWitnessSignal_f_constant_value; SpecWitnessSignal_f_required>." \
      "Notation \"'t_SpecWitnessSignal'\" := (SpecWitnessSignal_record)."

    inject_after_exact_line \
      "$witness_generation_file" \
      "  settable! (Build_SpecWitnessGenerationProgram_record) <SpecWitnessGenerationProgram_f_kernel_program; SpecWitnessGenerationProgram_f_signals>." \
      "Notation \"'t_SpecWitnessGenerationProgram'\" := (SpecWitnessGenerationProgram_record)."
    inject_after_exact_line \
      "$witness_generation_file" \
      "Notation \"'t_SpecWitnessGenerationProgram'\" := (SpecWitnessGenerationProgram_record)." \
      "Notation \"'f_kernel_program'\" := (SpecWitnessGenerationProgram_f_kernel_program)."
    inject_after_exact_line \
      "$witness_generation_file" \
      "Notation \"'f_kernel_program'\" := (SpecWitnessGenerationProgram_f_kernel_program)." \
      "Notation \"'f_signals'\" := (SpecWitnessGenerationProgram_f_signals)."
  fi

  if [ -f "$ccs_file" ]; then
    inject_after_core_import \
      "$ccs_file" \
      "Require Import KernelCompat."
    inject_after_core_import \
      "$ccs_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Proof_kernel_spec_Bundle."
    inject_after_core_import \
      "$ccs_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Field."
    inject_after_exact_line \
      "$ccs_file" \
      "Require Import KernelCompat." \
      "Definition t_BigInt := Z."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition t_BigInt := Z." \
      "Definition t_BTreeMap (A B : Type) (_ : globality) := list (A * B)."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition t_BTreeMap (A B G : Type) := list (A * B)." \
      "Definition impl_18__new '(_ : unit) : t_BTreeMap t_usize t_BigInt t_Global := []."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition impl_18__new '(_ : unit) : t_BTreeMap t_usize t_BigInt t_Global := []." \
      "Fixpoint impl_20__remove (target : t_BTreeMap t_usize t_BigInt t_Global) (key : t_usize) : t_BTreeMap t_usize t_BigInt t_Global * t_Option t_BigInt := match target with | [] => ([], Option_None) | (current_key, current_value) :: remaining => if f_eq current_key key then (remaining, Option_Some current_value) else let '(updated, removed) := impl_20__remove remaining key in ((current_key, current_value) :: updated, removed) end."
    inject_after_exact_line \
      "$ccs_file" \
      "Fixpoint impl_20__remove (target : t_BTreeMap t_usize t_BigInt t_Global) (key : t_usize) : t_BTreeMap t_usize t_BigInt t_Global * t_Option t_BigInt := match target with | [] => ([], Option_None) | (current_key, current_value) :: remaining => if f_eq current_key key then (remaining, Option_Some current_value) else let '(updated, removed) := impl_20__remove remaining key in ((current_key, current_value) :: updated, removed) end." \
      "Definition impl_20__insert (target : t_BTreeMap t_usize t_BigInt t_Global) (key : t_usize) (value : t_BigInt) : t_BTreeMap t_usize t_BigInt t_Global * t_Option t_BigInt := ((key, value) :: target, Option_None)."

    inject_after_exact_line \
      "$ccs_file" \
      "  settable! (Build_SpecCcsMatrixEntry_record) <SpecCcsMatrixEntry_f_row; SpecCcsMatrixEntry_f_col; SpecCcsMatrixEntry_f_value>." \
      "Definition SpecCcsMatrixEntry := Build_SpecCcsMatrixEntry_record."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition SpecCcsMatrixEntry := Build_SpecCcsMatrixEntry_record." \
      "Notation \"'t_SpecCcsMatrixEntry'\" := (SpecCcsMatrixEntry_record)."

    inject_after_exact_line \
      "$ccs_file" \
      "  settable! (Build_SpecCcsMatrix_record) <SpecCcsMatrix_f_rows; SpecCcsMatrix_f_cols; SpecCcsMatrix_f_entries>." \
      "Definition SpecCcsMatrix := Build_SpecCcsMatrix_record."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition SpecCcsMatrix := Build_SpecCcsMatrix_record." \
      "Notation \"'t_SpecCcsMatrix'\" := (SpecCcsMatrix_record)."

    inject_after_exact_line \
      "$ccs_file" \
      "  settable! (Build_SpecCcsMultiset_record) <SpecCcsMultiset_f_matrix_indices; SpecCcsMultiset_f_coefficient>." \
      "Definition SpecCcsMultiset := Build_SpecCcsMultiset_record."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition SpecCcsMultiset := Build_SpecCcsMultiset_record." \
      "Notation \"'t_SpecCcsMultiset'\" := (SpecCcsMultiset_record)."

    inject_after_exact_line \
      "$ccs_file" \
      "  settable! (Build_SpecCcsConstraintProgram_record) <SpecCcsConstraintProgram_f_field; SpecCcsConstraintProgram_f_signals; SpecCcsConstraintProgram_f_constraints>." \
      "Notation \"'t_SpecCcsConstraintProgram'\" := (SpecCcsConstraintProgram_record)."
    inject_after_exact_line \
      "$ccs_file" \
      "Notation \"'t_SpecCcsConstraintProgram'\" := (SpecCcsConstraintProgram_record)." \
      "Notation \"'f_field'\" := (SpecCcsConstraintProgram_f_field)."
    inject_after_exact_line \
      "$ccs_file" \
      "Notation \"'f_field'\" := (SpecCcsConstraintProgram_f_field)." \
      "Notation \"'f_signals'\" := (SpecCcsConstraintProgram_f_signals)."
    inject_after_exact_line \
      "$ccs_file" \
      "Notation \"'f_signals'\" := (SpecCcsConstraintProgram_f_signals)." \
      "Notation \"'f_constraints'\" := (SpecCcsConstraintProgram_f_constraints)."

    inject_after_exact_line \
      "$ccs_file" \
      "  settable! (Build_SpecCcsProgram_record) <SpecCcsProgram_f_field; SpecCcsProgram_f_num_constraints; SpecCcsProgram_f_num_variables; SpecCcsProgram_f_num_public; SpecCcsProgram_f_matrices; SpecCcsProgram_f_multisets>." \
      "Definition SpecCcsProgram := Build_SpecCcsProgram_record."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition SpecCcsProgram := Build_SpecCcsProgram_record." \
      "Notation \"'t_SpecCcsProgram'\" := (SpecCcsProgram_record)."

    inject_after_exact_line \
      "$ccs_file" \
      "  settable! (Build_SpecCcsBuilder_record) <SpecCcsBuilder_f_field; SpecCcsBuilder_f_signal_columns; SpecCcsBuilder_f_next_col; SpecCcsBuilder_f_num_public; SpecCcsBuilder_f_row; SpecCcsBuilder_f_a_entries; SpecCcsBuilder_f_b_entries; SpecCcsBuilder_f_c_entries>." \
      "Definition SpecCcsBuilder := Build_SpecCcsBuilder_record."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition SpecCcsBuilder := Build_SpecCcsBuilder_record." \
      "Notation \"'t_SpecCcsBuilder'\" := (SpecCcsBuilder_record)."

    inject_after_exact_line \
      "$ccs_file" \
      "  settable! (Build_SpecCcsSynthesisError_record) <SpecCcsSynthesisError_f_constraint_index; SpecCcsSynthesisError_f_kind>." \
      "Definition SpecCcsSynthesisError := Build_SpecCcsSynthesisError_record."
    inject_after_exact_line \
      "$ccs_file" \
      "Definition SpecCcsSynthesisError := Build_SpecCcsSynthesisError_record." \
      "Notation \"'t_SpecCcsSynthesisError'\" := (SpecCcsSynthesisError_record)."
  fi

  if [ -f "$transform_file" ]; then
    inject_after_core_import \
      "$transform_file" \
      "Require Import KernelCompat."
    inject_after_core_import \
      "$transform_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Field."
    inject_after_core_import \
      "$transform_file" \
      "From ZkfCoreExtraction Require Import Zkf_core_Proof_kernel_spec_Bundle."
    inject_after_exact_line \
      "$transform_file" \
      "Require Import KernelCompat." \
      "Definition impl__with_capacity (A : Type) (G : globality) (_ : t_usize) : t_Vec ((A)) ((G)) := impl__new tt."
    inject_after_exact_line \
      "$transform_file" \
      "Definition impl__with_capacity (A : Type) (G : globality) (_ : t_usize) : t_Vec ((A)) ((G)) := impl__new tt." \
      "Definition f_extend (A : Type) (G : globality) (target source : t_Vec ((A)) ((G))) : t_Vec ((A)) ((G)) := target ++ source."

    inject_after_exact_line \
      "$transform_file" \
      "  settable! (Build_SpecTransformSignal_record) <SpecTransformSignal_f_signal_index; SpecTransformSignal_f_sort_key; SpecTransformSignal_f_visibility; SpecTransformSignal_f_constant_value; SpecTransformSignal_f_required>." \
      "Notation \"'t_SpecTransformSignal'\" := (SpecTransformSignal_record)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'t_SpecTransformSignal'\" := (SpecTransformSignal_record)." \
      "Notation \"'f_signal_index'\" := (SpecTransformSignal_f_signal_index)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_signal_index'\" := (SpecTransformSignal_f_signal_index)." \
      "Notation \"'f_sort_key'\" := (SpecTransformSignal_f_sort_key)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_sort_key'\" := (SpecTransformSignal_f_sort_key)." \
      "Notation \"'f_visibility'\" := (SpecTransformSignal_f_visibility)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_visibility'\" := (SpecTransformSignal_f_visibility)." \
      "Notation \"'f_constant_value'\" := (SpecTransformSignal_f_constant_value)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_constant_value'\" := (SpecTransformSignal_f_constant_value)." \
      "Notation \"'f_required'\" := (SpecTransformSignal_f_required)."
    inject_after_exact_line \
      "$transform_file" \
      "  settable! (Build_SpecTransformHint_record) <SpecTransformHint_f_target_signal_index; SpecTransformHint_f_source_signal_index>." \
      "Notation \"'t_SpecTransformHint'\" := (SpecTransformHint_record)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'t_SpecTransformHint'\" := (SpecTransformHint_record)." \
      "Notation \"'f_target_signal_index'\" := (SpecTransformHint_f_target_signal_index)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_target_signal_index'\" := (SpecTransformHint_f_target_signal_index)." \
      "Notation \"'f_source_signal_index'\" := (SpecTransformHint_f_source_signal_index)."
    inject_after_exact_line \
      "$transform_file" \
      "  settable! (Build_SpecNormalizationReport_record) <SpecNormalizationReport_f_algebraic_rewrites; SpecNormalizationReport_f_constant_folds; SpecNormalizationReport_f_dead_signals_removed>." \
      "Notation \"'t_SpecNormalizationReport'\" := (SpecNormalizationReport_record)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'t_SpecNormalizationReport'\" := (SpecNormalizationReport_record)." \
      "Notation \"'f_algebraic_rewrites'\" := (SpecNormalizationReport_f_algebraic_rewrites)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_algebraic_rewrites'\" := (SpecNormalizationReport_f_algebraic_rewrites)." \
      "Notation \"'f_constant_folds'\" := (SpecNormalizationReport_f_constant_folds)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_constant_folds'\" := (SpecNormalizationReport_f_constant_folds)." \
      "Notation \"'f_dead_signals_removed'\" := (SpecNormalizationReport_f_dead_signals_removed)."
    inject_after_exact_line \
      "$transform_file" \
      "  settable! (Build_SpecOptimizeReport_record) <SpecOptimizeReport_f_folded_expr_nodes; SpecOptimizeReport_f_deduplicated_constraints; SpecOptimizeReport_f_removed_tautology_constraints; SpecOptimizeReport_f_removed_private_signals>." \
      "Notation \"'t_SpecOptimizeReport'\" := (SpecOptimizeReport_record)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'t_SpecOptimizeReport'\" := (SpecOptimizeReport_record)." \
      "Notation \"'f_folded_expr_nodes'\" := (SpecOptimizeReport_f_folded_expr_nodes)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_folded_expr_nodes'\" := (SpecOptimizeReport_f_folded_expr_nodes)." \
      "Notation \"'f_deduplicated_constraints'\" := (SpecOptimizeReport_f_deduplicated_constraints)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_deduplicated_constraints'\" := (SpecOptimizeReport_f_deduplicated_constraints)." \
      "Notation \"'f_removed_tautology_constraints'\" := (SpecOptimizeReport_f_removed_tautology_constraints)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_removed_tautology_constraints'\" := (SpecOptimizeReport_f_removed_tautology_constraints)." \
      "Notation \"'f_removed_private_signals'\" := (SpecOptimizeReport_f_removed_private_signals)."
    inject_after_exact_line \
      "$transform_file" \
      "  settable! (Build_SpecTransformAssignment_record) <SpecTransformAssignment_f_target_signal_index; SpecTransformAssignment_f_expr>." \
      "Notation \"'t_SpecTransformAssignment'\" := (SpecTransformAssignment_record)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'t_SpecTransformAssignment'\" := (SpecTransformAssignment_record)." \
      "Notation \"'f_expr'\" := (SpecTransformAssignment_f_expr)."
    inject_after_exact_line \
      "$transform_file" \
      "  settable! (Build_SpecTransformProgram_record) <SpecTransformProgram_f_field; SpecTransformProgram_f_signals; SpecTransformProgram_f_constraints; SpecTransformProgram_f_assignments; SpecTransformProgram_f_hints>." \
      "Notation \"'t_SpecTransformProgram'\" := (SpecTransformProgram_record)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'t_SpecTransformProgram'\" := (SpecTransformProgram_record)." \
      "Notation \"'f_field'\" := (SpecTransformProgram_f_field)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_field'\" := (SpecTransformProgram_f_field)." \
      "Notation \"'f_signals'\" := (SpecTransformProgram_f_signals)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_signals'\" := (SpecTransformProgram_f_signals)." \
      "Notation \"'f_constraints'\" := (SpecTransformProgram_f_constraints)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_constraints'\" := (SpecTransformProgram_f_constraints)." \
      "Notation \"'f_assignments'\" := (SpecTransformProgram_f_assignments)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'f_assignments'\" := (SpecTransformProgram_f_assignments)." \
      "Notation \"'f_hints'\" := (SpecTransformProgram_f_hints)."
    inject_after_exact_line \
      "$transform_file" \
      "  settable! (Build_SpecNormalizationResult_record) <SpecNormalizationResult_f_program; SpecNormalizationResult_f_report>." \
      "Notation \"'t_SpecNormalizationResult'\" := (SpecNormalizationResult_record)."
    inject_after_exact_line \
      "$transform_file" \
      "Notation \"'t_SpecNormalizationResult'\" := (SpecNormalizationResult_record)." \
      "Notation \"'f_program'\" := (SpecNormalizationResult_f_program)."
    inject_after_exact_line \
      "$transform_file" \
      "  settable! (Build_SpecOptimizeResult_record) <SpecOptimizeResult_f_program; SpecOptimizeResult_f_report>." \
      "Notation \"'t_SpecOptimizeResult'\" := (SpecOptimizeResult_record)."
  fi

  inject_after_exact_line \
    "$field_file" \
    "  settable! (Build_FieldElement_record) <FieldElement_f_bytes; FieldElement_f_len; FieldElement_f_negative>." \
    "Notation \"'t_FieldElement'\" := (FieldElement_record)."

  inject_after_exact_line \
    "$bundle_file" \
    "  settable! (Build_SpecFieldValue_record) <SpecFieldValue_f_bytes; SpecFieldValue_f_len; SpecFieldValue_f_negative>." \
    "Notation \"'t_SpecFieldValue'\" := (SpecFieldValue_record)."

  inject_after_exact_line \
    "$bundle_file" \
    "  settable! (Build_SpecKernelLookupTable_record) <SpecKernelLookupTable_f_column_count; SpecKernelLookupTable_f_rows>." \
    "Notation \"'t_SpecKernelLookupTable'\" := (SpecKernelLookupTable_record)."
  inject_after_exact_line \
    "$bundle_file" \
    "Notation \"'t_SpecKernelLookupTable'\" := (SpecKernelLookupTable_record)." \
    "Notation \"'f_column_count'\" := (SpecKernelLookupTable_f_column_count)."
  inject_after_exact_line \
    "$bundle_file" \
    "Notation \"'f_column_count'\" := (SpecKernelLookupTable_f_column_count)." \
    "Notation \"'f_rows'\" := (SpecKernelLookupTable_f_rows)."

  inject_after_exact_line \
    "$bundle_file" \
    "  settable! (Build_SpecKernelWitness_record) <SpecKernelWitness_f_values>." \
    "Notation \"'t_SpecKernelWitness'\" := (SpecKernelWitness_record)."
  inject_after_exact_line \
    "$bundle_file" \
    "Notation \"'t_SpecKernelWitness'\" := (SpecKernelWitness_record)." \
    "Notation \"'f_values'\" := (SpecKernelWitness_f_values)."

  inject_after_exact_line \
    "$bundle_file" \
    "  settable! (Build_SpecKernelProgram_record) <SpecKernelProgram_f_field; SpecKernelProgram_f_constraints; SpecKernelProgram_f_lookup_tables>." \
    "Notation \"'t_SpecKernelProgram'\" := (SpecKernelProgram_record)."
  inject_after_exact_line \
    "$bundle_file" \
    "Notation \"'t_SpecKernelProgram'\" := (SpecKernelProgram_record)." \
    "Notation \"'f_field'\" := (SpecKernelProgram_f_field)."
  inject_after_exact_line \
    "$bundle_file" \
    "Notation \"'f_field'\" := (SpecKernelProgram_f_field)." \
    "Notation \"'f_constraints'\" := (SpecKernelProgram_f_constraints)."
  inject_after_exact_line \
    "$bundle_file" \
    "Notation \"'f_constraints'\" := (SpecKernelProgram_f_constraints)." \
    "Notation \"'f_lookup_tables'\" := (SpecKernelProgram_f_lookup_tables)."
}

normalize_generated_fixpoints() {
  local bundle_file="$rocq_output/Zkf_core_Proof_kernel_spec_Bundle.v"
  local transform_file="$rocq_output/Zkf_core_Proof_transform_spec.v"

  if [ ! -f "$bundle_file" ]; then
    return 0
  fi

  python3 - "$bundle_file" <<'PY'
from pathlib import Path
import sys
import textwrap

path = Path(sys.argv[1])
text = path.read_text()


def replace_between(source: str, start_marker: str, end_marker: str, replacement: str) -> str:
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[:start] + textwrap.dedent(replacement).rstrip() + "\n\n" + source[end:]


replacements = [
    (
        "Fixpoint render_lookup_outputs_from ",
        "Fixpoint row_matches_inputs_from ",
        """
        Fixpoint render_lookup_outputs_from_list (signal_indices : list t_usize) (current_column : t_usize) (lookup_table : t_SpecKernelLookupTable) (witness : t_SpecKernelWitness) (field : t_FieldId) (acc : t_Vec ((t_SpecFieldValue)) ((t_Global))) : t_Result ((t_Vec ((t_SpecFieldValue)) ((t_Global)))) ((t_SpecKernelCheckError)) :=
          match signal_indices with
          | [] =>
            Result_Ok (acc)
          | signal_index :: remaining_signal_indices =>
            if
              f_lt (current_column) (f_column_count lookup_table)
            then
              match kernel_signal_value (witness) (signal_index) (field) with
              | Result_Ok (value) =>
                let acc := impl_1__push (acc) (value) in
                render_lookup_outputs_from_list (remaining_signal_indices) (f_add (current_column) ((1 : t_usize))) (lookup_table) (witness) (field) (acc)
              | Result_Err (error) =>
                Result_Err (error)
              end
            else
              render_lookup_outputs_from_list (remaining_signal_indices) (f_add (current_column) ((1 : t_usize))) (lookup_table) (witness) (field) (acc)
          end.

        Definition render_lookup_outputs_from (signal_indices : t_Slice t_usize) (current_column : t_usize) (lookup_table : t_SpecKernelLookupTable) (witness : t_SpecKernelWitness) (field : t_FieldId) (acc : t_Vec ((t_SpecFieldValue)) ((t_Global))) : t_Result ((t_Vec ((t_SpecFieldValue)) ((t_Global)))) ((t_SpecKernelCheckError)) :=
          render_lookup_outputs_from_list (Slice_f_v signal_indices) (current_column) (lookup_table) (witness) (field) (acc).
        """,
    ),
    (
        "Fixpoint row_matches_inputs_from ",
        "Fixpoint skip_row_prefix ",
        """
        Fixpoint row_matches_inputs_from_list (row : list t_SpecFieldValue) (evaluated_inputs : list t_SpecFieldValue) (field : t_FieldId) : bool :=
          match evaluated_inputs with
          | [] =>
            (true : bool)
          | input_value :: remaining_inputs =>
            let row_result := match row with
            | [] =>
              (zero (tt), [])
            | value :: remaining_row =>
              (f_clone (value), remaining_row)
            end in
            let row_value := fst row_result in
            let remaining_row := snd row_result in
            andb (PartialEq_f_eq (row_value) (input_value) (field)) (row_matches_inputs_from_list (remaining_row) (remaining_inputs) (field))
          end.

        Definition row_matches_inputs_from (row : t_Slice t_SpecFieldValue) (evaluated_inputs : t_Slice t_SpecFieldValue) (field : t_FieldId) : bool :=
          row_matches_inputs_from_list (Slice_f_v row) (Slice_f_v evaluated_inputs) (field).
        """,
    ),
    (
        "Fixpoint skip_row_prefix ",
        "Fixpoint row_matches_outputs_from ",
        """
        Fixpoint skip_row_prefix_list (row : list t_SpecFieldValue) (remaining_to_skip : t_usize) : list t_SpecFieldValue :=
          if
            f_eq (remaining_to_skip) ((0 : t_usize))
          then
            row
          else
            match row with
            | [] =>
              row
            | _value :: remaining_row =>
              skip_row_prefix_list (remaining_row) (f_sub (remaining_to_skip) ((1 : t_usize)))
            end.

        Definition skip_row_prefix (row : t_Slice t_SpecFieldValue) (remaining_to_skip : t_usize) : t_Slice t_SpecFieldValue :=
          Build_t_Slice _ (skip_row_prefix_list (Slice_f_v row) (remaining_to_skip)).
        """,
    ),
    (
        "Fixpoint row_matches_outputs_from ",
        "Record SpecKernelConstraint_Equal_record ",
        """
        Fixpoint row_matches_outputs_from_list (row : list t_SpecFieldValue) (expected_outputs : list t_SpecFieldValue) (field : t_FieldId) : bool :=
          match expected_outputs with
          | [] =>
            (true : bool)
          | output_value :: remaining_outputs =>
            let row_result := match row with
            | [] =>
              (zero (tt), [])
            | value :: remaining_row =>
              (f_clone (value), remaining_row)
            end in
            let row_value := fst row_result in
            let remaining_row := snd row_result in
            andb (PartialEq_f_eq (row_value) (output_value) (field)) (row_matches_outputs_from_list (remaining_row) (remaining_outputs) (field))
          end.

        Definition row_matches_outputs_from (row : t_Slice t_SpecFieldValue) (expected_outputs : t_Slice t_SpecFieldValue) (field : t_FieldId) : bool :=
          row_matches_outputs_from_list (Slice_f_v row) (Slice_f_v expected_outputs) (field).
        """,
    ),
    (
        "Fixpoint lookup_has_matching_row_from ",
        "Fixpoint eval_expr ",
        """
        Fixpoint lookup_has_matching_row_from_list (rows : list (t_Vec ((t_SpecFieldValue)) ((t_Global)))) (evaluated_inputs : list t_SpecFieldValue) (expected_outputs : t_Option ((t_Vec ((t_SpecFieldValue)) ((t_Global))))) (input_len : t_usize) (field : t_FieldId) : bool :=
          match rows with
          | [] =>
            (false : bool)
          | row :: remaining_rows =>
            let row_matches := if
              row_matches_inputs_from_list (row) (evaluated_inputs) (field)
            then
              match expected_outputs with
              | Option_Some (outputs) =>
                row_matches_outputs_from_list (skip_row_prefix_list (row) (input_len)) (outputs) (field)
              | Option_None =>
                (true : bool)
              end
            else
              (false : bool) in
            orb (row_matches) (lookup_has_matching_row_from_list (remaining_rows) (evaluated_inputs) (expected_outputs) (input_len) (field))
          end.

        Definition lookup_has_matching_row_from (rows : t_Slice (t_Vec ((t_SpecFieldValue)) ((t_Global)))) (evaluated_inputs : t_Slice t_SpecFieldValue) (expected_outputs : t_Option ((t_Vec ((t_SpecFieldValue)) ((t_Global))))) (input_len : t_usize) (field : t_FieldId) : bool :=
          lookup_has_matching_row_from_list (Slice_f_v rows) (Slice_f_v evaluated_inputs) (expected_outputs) (input_len) (field).
        """,
    ),
    (
        "Fixpoint collect_evaluated_inputs_from ",
        "Definition collect_evaluated_inputs ",
        """
        Fixpoint collect_evaluated_inputs_from_list (inputs : list t_SpecKernelExpr) (witness : t_SpecKernelWitness) (field : t_FieldId) (acc : t_Vec ((t_SpecFieldValue)) ((t_Global))) : t_Result ((t_Vec ((t_SpecFieldValue)) ((t_Global)))) ((t_SpecKernelCheckError)) :=
          match inputs with
          | [] =>
            Result_Ok (acc)
          | input :: remaining_inputs =>
            match eval_expr (input) (witness) (field) with
            | Result_Ok (value) =>
              let acc := impl_1__push (acc) (value) in
              collect_evaluated_inputs_from_list (remaining_inputs) (witness) (field) (acc)
            | Result_Err (error) =>
              Result_Err (error)
            end
          end.

        Definition collect_evaluated_inputs_from (inputs : t_Slice t_SpecKernelExpr) (witness : t_SpecKernelWitness) (field : t_FieldId) (acc : t_Vec ((t_SpecFieldValue)) ((t_Global))) : t_Result ((t_Vec ((t_SpecFieldValue)) ((t_Global)))) ((t_SpecKernelCheckError)) :=
          collect_evaluated_inputs_from_list (Slice_f_v inputs) (witness) (field) (acc).
        """,
    ),
    (
        "Fixpoint check_constraints_from ",
        "Definition check_program ",
        """
        Fixpoint check_constraints_from_list (constraints : list t_SpecKernelConstraint) (program : t_SpecKernelProgram) (witness : t_SpecKernelWitness) : t_Result ((unit)) ((t_SpecKernelCheckError)) :=
          match constraints with
          | [] =>
            Result_Ok (tt)
          | constraint :: remaining_constraints =>
            match constraint with
            | SpecKernelConstraint_Equal (equal_constraint) =>
              let index := SpecKernelConstraint_Equal_f_index equal_constraint in
              let lhs := SpecKernelConstraint_Equal_f_lhs equal_constraint in
              let rhs := SpecKernelConstraint_Equal_f_rhs equal_constraint in
              match eval_expr (lhs) (witness) (f_field program) with
              | Result_Ok (lhs_value) =>
                match eval_expr (rhs) (witness) (f_field program) with
                | Result_Ok (rhs_value) =>
                  if
                    PartialEq_f_eq (lhs_value) (rhs_value) (f_field program)
                  then
                    check_constraints_from_list (remaining_constraints) (program) (witness)
                  else
                    Result_Err (SpecKernelCheckError_EqualViolation {| SpecKernelCheckError_EqualViolation_f_constraint_index := (index); SpecKernelCheckError_EqualViolation_f_lhs := (lhs_value); SpecKernelCheckError_EqualViolation_f_rhs := (rhs_value) |})
                | Result_Err (error) =>
                  Result_Err (error)
                end
              | Result_Err (error) =>
                Result_Err (error)
              end
            | SpecKernelConstraint_Boolean (boolean_constraint) =>
              let index := SpecKernelConstraint_Boolean_f_index boolean_constraint in
              let signal := SpecKernelConstraint_Boolean_f_signal boolean_constraint in
              match kernel_signal_value (witness) (signal) (f_field program) with
              | Result_Ok (value) =>
                if
                  is_boolean (value) (f_field program)
                then
                  check_constraints_from_list (remaining_constraints) (program) (witness)
                else
                  Result_Err (SpecKernelCheckError_BooleanViolation {| SpecKernelCheckError_BooleanViolation_f_constraint_index := (index); SpecKernelCheckError_BooleanViolation_f_signal_index := (signal); SpecKernelCheckError_BooleanViolation_f_value := (value) |})
              | Result_Err (error) =>
                Result_Err (error)
              end
            | SpecKernelConstraint_Range (range_constraint) =>
              let index := SpecKernelConstraint_Range_f_index range_constraint in
              let signal := SpecKernelConstraint_Range_f_signal range_constraint in
              let bits := SpecKernelConstraint_Range_f_bits range_constraint in
              match kernel_signal_value (witness) (signal) (f_field program) with
              | Result_Ok (value) =>
                if
                  fits_bits (value) (bits) (f_field program)
                then
                  check_constraints_from_list (remaining_constraints) (program) (witness)
                else
                  Result_Err (SpecKernelCheckError_RangeViolation {| SpecKernelCheckError_RangeViolation_f_constraint_index := (index); SpecKernelCheckError_RangeViolation_f_signal_index := (signal); SpecKernelCheckError_RangeViolation_f_bits := (bits); SpecKernelCheckError_RangeViolation_f_value := (value) |})
              | Result_Err (error) =>
                Result_Err (error)
              end
            | SpecKernelConstraint_Lookup (lookup_constraint) =>
              let index := SpecKernelConstraint_Lookup_f_index lookup_constraint in
              let inputs := SpecKernelConstraint_Lookup_f_inputs lookup_constraint in
              let table_index := SpecKernelConstraint_Lookup_f_table_index lookup_constraint in
              let outputs := SpecKernelConstraint_Lookup_f_outputs lookup_constraint in
              match impl__get (f_deref (f_lookup_tables program)) (table_index) with
              | Option_Some (lookup_table) =>
                if
                  f_gt (impl_1__len (inputs)) (f_column_count lookup_table)
                then
                  match collect_evaluated_inputs_from_list (inputs) (witness) (f_field program) (impl__new (tt)) with
                  | Result_Ok (rendered_inputs) =>
                    match outputs with
                    | Option_Some (signal_indices) =>
                      match render_lookup_outputs_from_list (signal_indices) (impl_1__len (inputs)) (lookup_table) (witness) (f_field program) (impl__new (tt)) with
                      | Result_Ok (values) =>
                        Result_Err (SpecKernelCheckError_LookupViolation {| SpecKernelCheckError_LookupViolation_f_constraint_index := (index); SpecKernelCheckError_LookupViolation_f_table_index := (table_index); SpecKernelCheckError_LookupViolation_f_inputs := (rendered_inputs); SpecKernelCheckError_LookupViolation_f_outputs := (Option_Some (values)); SpecKernelCheckError_LookupViolation_f_kind := (SpecLookupFailureKind_InputArityMismatch {| SpecLookupFailureKind_InputArityMismatch_f_provided := (impl_1__len (inputs)); SpecLookupFailureKind_InputArityMismatch_f_available := (f_column_count lookup_table) |}) |})
                      | Result_Err (error) =>
                        Result_Err (error)
                      end
                    | Option_None =>
                      Result_Err (SpecKernelCheckError_LookupViolation {| SpecKernelCheckError_LookupViolation_f_constraint_index := (index); SpecKernelCheckError_LookupViolation_f_table_index := (table_index); SpecKernelCheckError_LookupViolation_f_inputs := (rendered_inputs); SpecKernelCheckError_LookupViolation_f_outputs := (Option_None); SpecKernelCheckError_LookupViolation_f_kind := (SpecLookupFailureKind_InputArityMismatch {| SpecLookupFailureKind_InputArityMismatch_f_provided := (impl_1__len (inputs)); SpecLookupFailureKind_InputArityMismatch_f_available := (f_column_count lookup_table) |}) |})
                    end
                  | Result_Err (error) =>
                    Result_Err (error)
                  end
                else
                  match collect_evaluated_inputs_from_list (inputs) (witness) (f_field program) (impl__new (tt)) with
                  | Result_Ok (evaluated_inputs) =>
                    match outputs with
                    | Option_Some (signal_indices) =>
                      match render_lookup_outputs_from_list (signal_indices) (impl_1__len (inputs)) (lookup_table) (witness) (f_field program) (impl__new (tt)) with
                      | Result_Ok (values) =>
                        let expected_outputs := Option_Some (values) in
                        if
                          lookup_has_matching_row_from_list (f_rows lookup_table) (evaluated_inputs) (expected_outputs) (impl_1__len (inputs)) (f_field program)
                        then
                          check_constraints_from_list (remaining_constraints) (program) (witness)
                        else
                          Result_Err (SpecKernelCheckError_LookupViolation {| SpecKernelCheckError_LookupViolation_f_constraint_index := (index); SpecKernelCheckError_LookupViolation_f_table_index := (table_index); SpecKernelCheckError_LookupViolation_f_inputs := (evaluated_inputs); SpecKernelCheckError_LookupViolation_f_outputs := (expected_outputs); SpecKernelCheckError_LookupViolation_f_kind := (SpecLookupFailureKind_NoMatchingRow) |})
                      | Result_Err (error) =>
                        Result_Err (error)
                      end
                    | Option_None =>
                      let expected_outputs := Option_None in
                      if
                        lookup_has_matching_row_from_list (f_rows lookup_table) (evaluated_inputs) (expected_outputs) (impl_1__len (inputs)) (f_field program)
                      then
                        check_constraints_from_list (remaining_constraints) (program) (witness)
                      else
                        Result_Err (SpecKernelCheckError_LookupViolation {| SpecKernelCheckError_LookupViolation_f_constraint_index := (index); SpecKernelCheckError_LookupViolation_f_table_index := (table_index); SpecKernelCheckError_LookupViolation_f_inputs := (evaluated_inputs); SpecKernelCheckError_LookupViolation_f_outputs := (expected_outputs); SpecKernelCheckError_LookupViolation_f_kind := (SpecLookupFailureKind_NoMatchingRow) |})
                    end
                  | Result_Err (error) =>
                    Result_Err (error)
                  end
              | Option_None =>
                Result_Err (SpecKernelCheckError_UnknownLookupTable {| SpecKernelCheckError_UnknownLookupTable_f_table_index := (table_index) |})
              end
            end
          end.

        Definition check_constraints_from (constraints : t_Slice t_SpecKernelConstraint) (program : t_SpecKernelProgram) (witness : t_SpecKernelWitness) : t_Result ((unit)) ((t_SpecKernelCheckError)) :=
          check_constraints_from_list (Slice_f_v constraints) (program) (witness).
        """,
    ),
]

for start_marker, end_marker, replacement in replacements:
    text = replace_between(text, start_marker, end_marker, replacement)

helper_start = "Definition spec_field_value_raw_bigint "
helper_end = "Record SpecKernelLookupTable_record "
if helper_start in text and helper_end in text:
    start = text.index(helper_start)
    end = text.index(helper_end, start)
    text = text[:start] + text[end:]

helper_anchor = "Definition kernel_signal_value (witness : t_SpecKernelWitness) (signal_index : t_usize) (field : t_FieldId) : t_Result ((t_SpecFieldValue)) ((t_SpecKernelCheckError)) :="
helper_block = textwrap.dedent(
    """
    Definition t_BigInt := Z.

    Definition impl_FieldId__modulus (field : t_FieldId) : t_BigInt :=
      spec_field_modulus field.

    Definition normalize_mod (value modulus : t_BigInt) : t_BigInt :=
      spec_normalize_z value modulus.

    Definition mod_inverse_bigint (value modulus : t_BigInt) : t_Option ((t_BigInt)) :=
      match spec_mod_inverse value modulus with
      | Some inverse =>
        Option_Some inverse
      | None =>
        Option_None
      end.

    Definition spec_field_value_raw_bigint (value : t_SpecFieldValue) : t_BigInt :=
      spec_field_value_to_z value.

    Definition spec_field_value_from_bigint_with_field (value : t_BigInt) (field : t_FieldId) : t_SpecFieldValue :=
      spec_field_value_of_z (spec_normalize_z value (spec_field_modulus field)).

    Definition spec_field_value_zero '(_ : unit) : t_SpecFieldValue :=
      spec_field_value_of_z 0%Z.

    Definition spec_field_value_is_zero_raw (value : t_SpecFieldValue) : bool :=
      Z.eqb (spec_field_value_to_z value) 0%Z.

    Definition spec_field_value_is_one_raw (value : t_SpecFieldValue) : bool :=
      Z.eqb (spec_field_value_to_z value) 1%Z.

    Definition spec_normalize_mod_bigint (value : t_BigInt) (modulus : t_BigInt) : t_BigInt :=
      spec_normalize_z value modulus.

    Definition spec_mod_inverse_bigint (value : t_BigInt) (modulus : t_BigInt) : t_Option ((t_BigInt)) :=
      match spec_mod_inverse value modulus with
      | Some inverse =>
        Option_Some inverse
      | None =>
        Option_None
      end.
    """
).strip()

if helper_anchor in text and "Definition t_BigInt := Z." not in text:
    text = text.replace(helper_anchor, helper_block + "\n\n" + helper_anchor, 1)

path.write_text(text)
PY

  if [ -f "$transform_file" ]; then
    python3 - "$transform_file" <<'PY'
from pathlib import Path
import sys
import textwrap

path = Path(sys.argv[1])
text = path.read_text()


def replace_between(source: str, start_marker: str, end_marker: str, replacement: str) -> str:
    start = source.index(start_marker)
    end = source.index(end_marker, start)
    return source[:start] + textwrap.dedent(replacement).rstrip() + "\n\n" + source[end:]


text = replace_between(
    text,
    "Definition normalize_spec_value ",
    "Definition spec_value_is_zero_raw ",
    """
    Definition normalize_spec_value (value : t_SpecFieldValue) (field : t_FieldId) : t_SpecFieldValue :=
      Zkf_core_Proof_kernel_spec_Bundle.normalize (value) (field).

    Definition add_spec_values (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : t_SpecFieldValue :=
      Zkf_core_Proof_kernel_spec_Bundle.Add_f_add (lhs) (rhs) (field).

    Definition sub_spec_values (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : t_SpecFieldValue :=
      Zkf_core_Proof_kernel_spec_Bundle.Sub_f_sub (lhs) (rhs) (field).

    Definition mul_spec_values (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : t_SpecFieldValue :=
      Zkf_core_Proof_kernel_spec_Bundle.Mul_f_mul (lhs) (rhs) (field).

    Definition div_spec_values (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : t_Option ((t_SpecFieldValue)) :=
      Zkf_core_Proof_kernel_spec_Bundle.Div_f_div (lhs) (rhs) (field).

    Definition spec_values_equal (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : bool :=
      Zkf_core_Proof_kernel_spec_Bundle.PartialEq_f_eq (lhs) (rhs) (field).

    Definition spec_value_is_boolean (value : t_SpecFieldValue) (field : t_FieldId) : bool :=
      Zkf_core_Proof_kernel_spec_Bundle.is_boolean (value) (field).

    Definition spec_value_fits_bits (value : t_SpecFieldValue) (bits : t_u32) (field : t_FieldId) : bool :=
      Zkf_core_Proof_kernel_spec_Bundle.fits_bits (value) (bits) (field).
    """,
)

replacements = [
    ("f_sort_key signal", "SpecTransformSignal_f_sort_key signal"),
    ("f_sort_key item", "SpecTransformSignal_f_sort_key item"),
    ("f_signal_index signal", "SpecTransformSignal_f_signal_index signal"),
    ("f_visibility signal", "SpecTransformSignal_f_visibility signal"),
    ("f_field program", "SpecTransformProgram_f_field program"),
    ("f_signals program", "SpecTransformProgram_f_signals program"),
    ("f_constraints program", "SpecTransformProgram_f_constraints program"),
    ("f_assignments program", "SpecTransformProgram_f_assignments program"),
    ("f_hints program", "SpecTransformProgram_f_hints program"),
    ("f_expr assignment", "SpecTransformAssignment_f_expr assignment"),
    ("f_source_signal_index hint", "SpecTransformHint_f_source_signal_index hint"),
    ("f_folded_expr_nodes report", "SpecOptimizeReport_f_folded_expr_nodes report"),
    (
        "f_deduplicated_constraints report",
        "SpecOptimizeReport_f_deduplicated_constraints report",
    ),
    (
        "f_removed_tautology_constraints report",
        "SpecOptimizeReport_f_removed_tautology_constraints report",
    ),
    (
        "f_removed_private_signals report",
        "SpecOptimizeReport_f_removed_private_signals report",
    ),
    (
        "f_algebraic_rewrites report",
        "SpecNormalizationReport_f_algebraic_rewrites report",
    ),
    (
        "f_constant_folds report",
        "SpecNormalizationReport_f_constant_folds report",
    ),
    (
        "f_dead_signals_removed report",
        "SpecNormalizationReport_f_dead_signals_removed report",
    ),
    ("f_target_signal_index hint", "SpecTransformHint_f_target_signal_index hint"),
    ("f_target_signal_index assignment", "SpecTransformAssignment_f_target_signal_index assignment"),
    (
        "f_program normalize_supported_program (program)",
        "SpecNormalizationResult_f_program (normalize_supported_program (program))",
    ),
    (
        "f_program optimize_supported_ir_program (program)",
        "SpecOptimizeResult_f_program (optimize_supported_ir_program (program))",
    ),
    (
        "f_program optimize_supported_zir_program (program)",
        "SpecOptimizeResult_f_program (optimize_supported_zir_program (program))",
    ),
]

for old, new in replacements:
    text = text.replace(old, new)

path.write_text(text)
PY
  fi
}

replace_field_model_dropped_bodies() {
  local bundle_file="$rocq_output/Zkf_core_Proof_kernel_spec_Bundle.v"

  if [ ! -f "$bundle_file" ]; then
    return 0
  fi

  python3 - "$bundle_file" <<'PY'
from pathlib import Path
import sys
import textwrap

path = Path(sys.argv[1])
text = path.read_text()

start_marker = "Definition zero "
end_marker = "Inductive t_SpecKernelExpr : Type :="
start = text.index(start_marker)
end = text.index(end_marker, start)
replacement = """
Definition spec_field_modulus (field : t_FieldId) : Z :=
  match field with
  | FieldId_Bn254 =>
    21888242871839275222246405745257275088548364400416034343698204186575808495617%Z
  | FieldId_Bls12_381_ =>
    52435875175126190479447740508185965837690552500527637822603658699938581184513%Z
  | FieldId_PastaFp =>
    28948022309329048855892746252171976963363056481941560715954676764349967630337%Z
  | FieldId_PastaFq =>
    28948022309329048855892746252171976963363056481941647379679742748393362948097%Z
  | FieldId_Goldilocks =>
    18446744069414584321%Z
  | FieldId_BabyBear =>
    2013265921%Z
  | FieldId_Mersenne31 =>
    2147483647%Z
  end.

Definition spec_normalize_z (value modulus : Z) : Z :=
  ((value mod modulus) + modulus) mod modulus.

Definition spec_u8_of_z (value : Z) : t_u8 :=
  u8 (value mod 256).

Fixpoint spec_bytes_to_z_le (bytes : list t_u8) (weight : Z) : Z :=
  match bytes with
  | [] =>
    0%Z
  | byte :: remaining =>
    ((Z.of_N (U8_f_v (u8_0 byte))) * weight + spec_bytes_to_z_le remaining (weight * 256))%Z
  end.

Definition spec_field_value_to_z (value : t_SpecFieldValue) : Z :=
  let magnitude := spec_bytes_to_z_le (Slice_f_v (Array_f_v (SpecFieldValue_f_bytes value))) 1 in
  if SpecFieldValue_f_negative value then
    (- magnitude)%Z
  else
    magnitude.

Fixpoint spec_z_to_bytes_le (count : nat) (value : Z) : list t_u8 :=
  match count with
  | O =>
    []
  | S remaining =>
    spec_u8_of_z value :: spec_z_to_bytes_le remaining (value / 256)
  end.

Fixpoint spec_canonical_len_aux (bytes : list t_u8) (index current : Z) : Z :=
  match bytes with
  | [] =>
    current
  | byte :: remaining =>
    let next := if Z.eqb (Z.of_N (U8_f_v (u8_0 byte))) 0 then current else (index + 1)%Z in
    spec_canonical_len_aux remaining (index + 1)%Z next
  end.

Definition spec_bytes_to_array32 (bytes : list t_u8) : t_Array (t_u8) ((32 : t_usize)) :=
  Build_t_Array (Build_t_Slice _ bytes).

Definition spec_field_value_of_z (value : Z) : t_SpecFieldValue :=
  let bounded := if Z.ltb value 0 then 0%Z else value in
  let bytes := spec_z_to_bytes_le 32 bounded in
  {| SpecFieldValue_f_bytes := spec_bytes_to_array32 bytes;
     SpecFieldValue_f_len := u8 (spec_canonical_len_aux bytes 0%Z 0%Z);
     SpecFieldValue_f_negative := false |}.

Definition spec_mod_inverse (value modulus : Z) : option Z :=
  let '(g, coefficients) := Z.ggcd value modulus in
  let '(coefficient, _) := coefficients in
  if Z.eqb g 1%Z then
    Some (spec_normalize_z coefficient modulus)
  else
    None.

Definition zero '(_ : unit) : t_SpecFieldValue :=
  spec_field_value_of_z 0%Z.

Definition normalize (value : t_SpecFieldValue) (field : t_FieldId) : t_SpecFieldValue :=
  spec_field_value_of_z (spec_normalize_z (spec_field_value_to_z value) (spec_field_modulus field)).

Definition kernel_signal_value (witness : t_SpecKernelWitness) (signal_index : t_usize) (field : t_FieldId) : t_Result ((t_SpecFieldValue)) ((t_SpecKernelCheckError)) :=
  match impl__get (f_deref (f_values witness)) (signal_index) with
  | Option_Some (Option_Some (value)) =>
    Result_Ok (normalize (value) (field))
  | _ =>
    Result_Err (SpecKernelCheckError_MissingSignal {| SpecKernelCheckError_MissingSignal_f_signal_index := (signal_index) |})
  end.

Definition Add_f_add (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : t_SpecFieldValue :=
  let modulus := spec_field_modulus field in
  spec_field_value_of_z
    (spec_normalize_z
      (spec_normalize_z (spec_field_value_to_z lhs) modulus +
       spec_normalize_z (spec_field_value_to_z rhs) modulus)
      modulus).

Definition Sub_f_sub (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : t_SpecFieldValue :=
  let modulus := spec_field_modulus field in
  spec_field_value_of_z
    (spec_normalize_z
      (spec_normalize_z (spec_field_value_to_z lhs) modulus -
       spec_normalize_z (spec_field_value_to_z rhs) modulus)
      modulus).

Definition Mul_f_mul (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : t_SpecFieldValue :=
  let modulus := spec_field_modulus field in
  spec_field_value_of_z
    (spec_normalize_z
      (spec_normalize_z (spec_field_value_to_z lhs) modulus *
       spec_normalize_z (spec_field_value_to_z rhs) modulus)
      modulus).

Definition Div_f_div (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : t_Option ((t_SpecFieldValue)) :=
  let modulus := spec_field_modulus field in
  let lhs_value := spec_normalize_z (spec_field_value_to_z lhs) modulus in
  let rhs_value := spec_normalize_z (spec_field_value_to_z rhs) modulus in
  match spec_mod_inverse rhs_value modulus with
  | Some inverse =>
    Option_Some
      (spec_field_value_of_z
        (spec_normalize_z (lhs_value * inverse) modulus))
  | None =>
    Option_None
  end.

Definition PartialEq_f_eq (lhs : t_SpecFieldValue) (rhs : t_SpecFieldValue) (field : t_FieldId) : bool :=
  Z.eqb
    (spec_normalize_z (spec_field_value_to_z lhs) (spec_field_modulus field))
    (spec_normalize_z (spec_field_value_to_z rhs) (spec_field_modulus field)).

Definition is_boolean (value : t_SpecFieldValue) (field : t_FieldId) : bool :=
  let normalized := spec_normalize_z (spec_field_value_to_z value) (spec_field_modulus field) in
  orb (Z.eqb normalized 0%Z) (Z.eqb normalized 1%Z).

Definition fits_bits (value : t_SpecFieldValue) (bits : t_u32) (field : t_FieldId) : bool :=
  let normalized := spec_normalize_z (spec_field_value_to_z value) (spec_field_modulus field) in
  Z.ltb normalized (2 ^ (Z.of_N (U32_f_v (u32_0 bits)))).

Definition t_BigInt := Z.

Definition impl_FieldId__modulus (field : t_FieldId) : t_BigInt :=
  spec_field_modulus field.

Definition normalize_mod (value modulus : t_BigInt) : t_BigInt :=
  spec_normalize_z value modulus.

Definition mod_inverse_bigint (value modulus : t_BigInt) : t_Option ((t_BigInt)) :=
  match spec_mod_inverse value modulus with
  | Some inverse =>
    Option_Some inverse
  | None =>
    Option_None
  end.

Definition spec_field_value_raw_bigint (value : t_SpecFieldValue) : t_BigInt :=
  spec_field_value_to_z value.

Definition spec_field_value_from_bigint_with_field (value : t_BigInt) (field : t_FieldId) : t_SpecFieldValue :=
  spec_field_value_of_z (spec_normalize_z value (spec_field_modulus field)).

Definition spec_field_value_zero '(_ : unit) : t_SpecFieldValue :=
  spec_field_value_of_z 0%Z.

Definition spec_field_value_is_zero_raw (value : t_SpecFieldValue) : bool :=
  Z.eqb (spec_field_value_to_z value) 0%Z.

Definition spec_field_value_is_one_raw (value : t_SpecFieldValue) : bool :=
  Z.eqb (spec_field_value_to_z value) 1%Z.

Definition spec_normalize_mod_bigint (value : t_BigInt) (modulus : t_BigInt) : t_BigInt :=
  spec_normalize_z value modulus.

Definition spec_mod_inverse_bigint (value : t_BigInt) (modulus : t_BigInt) : t_Option ((t_BigInt)) :=
  match spec_mod_inverse value modulus with
  | Some inverse =>
    Option_Some inverse
  | None =>
    Option_None
  end.
"""

text = text[:start] + textwrap.dedent(replacement).rstrip() + "\n\n" + text[end:]
path.write_text(text)
PY
}

normalize_generated_transform_spec() {
  local transform_file="$rocq_output/Zkf_core_Proof_transform_spec.v"
  local runtime_template="$rocq_workspace/templates/TransformRuntime.v"

  if [ ! -f "$transform_file" ]; then
    return 0
  fi

  python3 - "$transform_file" "$runtime_template" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
runtime_template_path = Path(sys.argv[2])
text = path.read_text()
runtime_template = runtime_template_path.read_text()


def extract_section(source: str, start_marker: str, end_marker: str) -> str:
    start = source.index(start_marker) + len(start_marker)
    end = source.index(end_marker, start)
    return source[start:end].strip() + "\n"

text = re.sub(r"fun \(([^()\n]*,[^()\n]*)\)", r"fun '(\1)", text)
text = re.sub(r"let \(([^()\n]*,[^()\n]*)\) :=", r"let '(\1) :=", text)

pre_record_runtime = extract_section(
    runtime_template,
    "(* BEGIN TRANSFORM PRE-RECORD RUNTIME *)",
    "(* END TRANSFORM PRE-RECORD RUNTIME *)",
)
executable_runtime = extract_section(
    runtime_template,
    "(* BEGIN TRANSFORM EXECUTABLE RUNTIME *)",
    "(* END TRANSFORM EXECUTABLE RUNTIME *)",
)

pre_record_start = "Fixpoint insert_signal_sorted_from "
pre_record_end = "Record SpecTransformConstraint_Equal_record "
if pre_record_start not in text or pre_record_end not in text:
    raise SystemExit("failed to locate transform pre-record runtime anchors")

start = text.index(pre_record_start)
end = text.index(pre_record_end, start)
text = text[:start] + pre_record_runtime + "\n" + text[end:]

runtime_start = "Definition zero_spec_expr "
if runtime_start not in text:
    raise SystemExit("failed to locate transform executable runtime anchor")

start = text.index(runtime_start)
text = text[:start] + executable_runtime.rstrip() + "\n"

path.write_text(text)
PY
}

assert_transform_fixpoints_normalized() {
  local transform_file="$rocq_output/Zkf_core_Proof_transform_spec.v"

  if [ ! -f "$transform_file" ]; then
    return 0
  fi

  if rg -n "^Fixpoint .*t_Slice" "$transform_file" >/dev/null; then
    echo "transform extraction still contains slice-recursive fixpoints" >&2
    rg -n "^Fixpoint .*t_Slice" "$transform_file" >&2
    exit 1
  fi
}

normalize_generated_witness_spec() {
  local witness_generation_file="$rocq_output/Zkf_core_Proof_witness_generation_spec.v"
  local runtime_template="$rocq_workspace/templates/WitnessGenerationRuntime.v"

  if [ ! -f "$witness_generation_file" ]; then
    return 0
  fi

  python3 - "$witness_generation_file" "$runtime_template" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
runtime_template_path = Path(sys.argv[2])
text = path.read_text()
runtime_template = runtime_template_path.read_text().rstrip()

text = text.replace(
    "t_Slice t_Option ((t_SpecFieldValue))",
    "t_Slice (t_Option ((t_SpecFieldValue)))",
)
text = text.replace(
    "Result_Ok (()) =>",
    "Result_Ok tt =>",
)

assignment_settable = "#[export] Instance settable_SpecWitnessAssignment_record : Settable _ :=\n  settable! (Build_SpecWitnessAssignment_record) <SpecWitnessAssignment_f_target_signal_index; SpecWitnessAssignment_f_expr>."
if assignment_settable in text and "Notation \"'t_SpecWitnessAssignment'\" := (SpecWitnessAssignment_record)." not in text:
    text = text.replace(
        assignment_settable,
        assignment_settable + "\nNotation \"'t_SpecWitnessAssignment'\" := (SpecWitnessAssignment_record).",
        1,
    )

hint_settable = "#[export] Instance settable_SpecWitnessHint_record : Settable _ :=\n  settable! (Build_SpecWitnessHint_record) <SpecWitnessHint_f_target_signal_index; SpecWitnessHint_f_source_signal_index>."
if hint_settable in text and "Notation \"'t_SpecWitnessHint'\" := (SpecWitnessHint_record)." not in text:
    text = text.replace(
        hint_settable,
        hint_settable + "\nNotation \"'t_SpecWitnessHint'\" := (SpecWitnessHint_record).",
        1,
    )

program_settable = "#[export] Instance settable_SpecWitnessGenerationProgram_record : Settable _ :=\n  settable! (Build_SpecWitnessGenerationProgram_record) <SpecWitnessGenerationProgram_f_kernel_program; SpecWitnessGenerationProgram_f_signals; SpecWitnessGenerationProgram_f_assignments; SpecWitnessGenerationProgram_f_hints>."
if program_settable in text and "Notation \"'t_SpecWitnessGenerationProgram'\" := (SpecWitnessGenerationProgram_record)." not in text:
    text = text.replace(
        program_settable,
        program_settable
        + "\nNotation \"'t_SpecWitnessGenerationProgram'\" := (SpecWitnessGenerationProgram_record)."
        + "\nNotation \"'f_kernel_program'\" := (SpecWitnessGenerationProgram_f_kernel_program)."
        + "\nNotation \"'f_signals'\" := (SpecWitnessGenerationProgram_f_signals)."
        + "\nNotation \"'f_assignments'\" := (SpecWitnessGenerationProgram_f_assignments)."
        + "\nNotation \"'f_hints'\" := (SpecWitnessGenerationProgram_f_hints).",
        1,
    )

runtime_definition = runtime_template + "\n\n"

marker = "Definition generate_non_blackbox_witness_unchecked "
runtime_start = "Definition generate_non_blackbox_witness_unchecked_runtime "
runtime_end = "\nDefinition generate_non_blackbox_witness_unchecked "
if runtime_start in text and runtime_end in text:
    start = text.index(runtime_start)
    end = text.index(runtime_end, start)
    text = text[:start] + runtime_definition + text[end + 1 :]
elif marker in text:
    text = text.replace(marker, runtime_definition + marker, 1)

path.write_text(text)
PY
}

normalize_generated_ccs_spec() {
  local ccs_file="$rocq_output/Zkf_core_Proof_ccs_spec.v"

  if [ ! -f "$ccs_file" ]; then
    return 0
  fi

  python3 - "$ccs_file" <<'PY'
from pathlib import Path
import sys
import textwrap

path = Path(sys.argv[1])
text = path.read_text()

t_btree_line = "Definition t_BTreeMap (A B : Type) (_ : globality) := list (A * B)."
if t_btree_line in text and "Definition impl_18__new" not in text:
    helper_block = """
Definition impl_18__new '(_ : unit) : t_BTreeMap t_usize t_BigInt t_Global := [].

Fixpoint impl_20__remove
  (target : t_BTreeMap t_usize t_BigInt t_Global)
  (key : t_usize)
  : t_BTreeMap t_usize t_BigInt t_Global * t_Option t_BigInt :=
  match target with
  | [] =>
      ([], Option_None)
  | (current_key, current_value) :: remaining =>
      if f_eq current_key key then
        (remaining, Option_Some current_value)
      else
        let '(updated, removed) := impl_20__remove remaining key in
        ((current_key, current_value) :: updated, removed)
  end.

Definition impl_20__insert
  (target : t_BTreeMap t_usize t_BigInt t_Global)
  (key : t_usize)
  (value : t_BigInt)
  : t_BTreeMap t_usize t_BigInt t_Global * t_Option t_BigInt :=
  ((key, value) :: target, Option_None).

Definition impl_FieldId__modulus (field : t_FieldId) : t_BigInt :=
  spec_field_modulus field.

Definition normalize_mod (value modulus : t_BigInt) : t_BigInt :=
  spec_normalize_z value modulus.

Definition f_one '(_ : unit) : t_BigInt := 1%Z.
Definition f_neg (value : t_BigInt) : t_BigInt := Z.opp value.
Definition f_is_zero (value : t_BigInt) : bool := Z.eqb value 0%Z.
Definition f_shl (value : t_BigInt) (amount : t_usize) : t_BigInt :=
  Z.shiftl value (Z.of_N (U64_f_v (usize_0 amount))).
"""
    text = text.replace(
        t_btree_line,
        t_btree_line + "\n" + textwrap.dedent(helper_block).rstrip(),
        1,
    )

start_marker = "Definition synthesize_ccs_program (program : t_SpecCcsConstraintProgram) : t_Result ((t_SpecCcsProgram)) ((t_SpecCcsSynthesisError)) :="
if start_marker in text:
    start = text.index(start_marker)
    next_definition = text.find("\nDefinition ", start + len(start_marker))
    if next_definition == -1:
        end = len(text)
    else:
        end = next_definition
    replacement = """
Definition synthesize_ccs_program (program : t_SpecCcsConstraintProgram) : t_Result ((t_SpecCcsProgram)) ((t_SpecCcsSynthesisError)) :=
  let builder := builder_new program in
  match synthesize_constraints_from builder (f_deref (f_constraints program)) (0 : t_usize) with
  | Result_Ok builder =>
      Result_Ok (builder_finish builder (f_field program))
  | Result_Err error =>
      Result_Err error
  end.
"""
    text = text[:start] + textwrap.dedent(replacement).rstrip() + "\n" + text[end:]

signal_settable = "#[export] Instance settable_SpecCcsSignal_record : Settable _ :=\n  settable! (Build_SpecCcsSignal_record) <SpecCcsSignal_f_visibility>."
if signal_settable in text and "Notation \"'t_SpecCcsSignal'\" := (SpecCcsSignal_record)." not in text:
    text = text.replace(
        signal_settable,
        signal_settable + "\nNotation \"'t_SpecCcsSignal'\" := (SpecCcsSignal_record).",
        1,
    )

spec_start = "Definition spec_value_to_bigint (value : t_SpecFieldValue) (field : t_FieldId) : t_BigInt :="
builder_record = "\nRecord SpecCcsBuilder_record : Type :="
if spec_start in text and builder_record in text:
    start = text.index(spec_start)
    end = text.index(builder_record, start)
    replacement = """
Definition spec_value_to_bigint (value : t_SpecFieldValue) (field : t_FieldId) : t_BigInt :=
  spec_normalize_z (spec_field_value_to_z value) (spec_field_modulus field).

Definition bigint_to_spec_value (value : t_BigInt) (field : t_FieldId) : t_SpecFieldValue :=
  spec_field_value_of_z (spec_normalize_z value (spec_field_modulus field)).
"""
    text = text[:start] + textwrap.dedent(replacement).rstrip() + "\n" + text[end:]

helper_anchor = "Definition impl_20__insert (target : t_BTreeMap t_usize t_BigInt t_Global) (key : t_usize) (value : t_BigInt) : t_BTreeMap t_usize t_BigInt t_Global * t_Option t_BigInt := ((key, value) :: target, Option_None)."
if helper_anchor in text and "Definition impl_FieldId__modulus" not in text:
    text = text.replace(
        helper_anchor,
        helper_anchor
        + "\nDefinition impl_FieldId__modulus (field : t_FieldId) : t_BigInt := spec_field_modulus field."
        + "\nDefinition normalize_mod (value modulus : t_BigInt) : t_BigInt := spec_normalize_z value modulus."
        + "\nDefinition f_one '(_ : unit) : t_BigInt := 1%Z."
        + "\nDefinition f_neg (value : t_BigInt) : t_BigInt := Z.opp value."
        + "\nDefinition f_is_zero (value : t_BigInt) : bool := Z.eqb value 0%Z."
        + "\nDefinition f_shl (value : t_BigInt) (amount : t_usize) : t_BigInt := Z.shiftl value (Z.of_N (U64_f_v (usize_0 amount))).",
        1,
    )

finish_start = "Definition builder_finish (builder : t_SpecCcsBuilder) (field : t_FieldId) : t_SpecCcsProgram :="
finish_end = "\nDefinition builder_allocate_aux "
if finish_start in text and finish_end in text:
    start = text.index(finish_start)
    end = text.index(finish_end, start)
    replacement = """
Definition builder_finish (builder : t_SpecCcsBuilder) (field : t_FieldId) : t_SpecCcsProgram :=
  let num_constraints := SpecCcsBuilder_f_row builder in
  let rows := num_constraints in
  let cols := SpecCcsBuilder_f_next_col builder in
  SpecCcsProgram
    field
    num_constraints
    cols
    (SpecCcsBuilder_f_num_public builder)
    [ SpecCcsMatrix rows cols (SpecCcsBuilder_f_a_entries builder)
    ; SpecCcsMatrix rows cols (SpecCcsBuilder_f_b_entries builder)
    ; SpecCcsMatrix rows cols (SpecCcsBuilder_f_c_entries builder)
    ]
    [ SpecCcsMultiset [(0 : t_usize); (1 : t_usize)] (bigint_to_spec_value 1%Z field)
    ; SpecCcsMultiset [(2 : t_usize)] (bigint_to_spec_value (-1)%Z field)
    ].
"""
    text = text[:start] + textwrap.dedent(replacement).rstrip() + "\n" + text[end + 1:]

allocate_start = "Definition builder_allocate_aux (builder : t_SpecCcsBuilder) : (t_SpecCcsBuilder*t_usize) :="
allocate_end = "\nDefinition lc_add_term "
if allocate_start in text and allocate_end in text:
    start = text.index(allocate_start)
    end = text.index(allocate_end, start)
    replacement = """
Definition builder_allocate_aux (builder : t_SpecCcsBuilder) : (t_SpecCcsBuilder*t_usize) :=
  let col := SpecCcsBuilder_f_next_col builder in
  let builder :=
    SpecCcsBuilder
      (SpecCcsBuilder_f_field builder)
      (SpecCcsBuilder_f_signal_columns builder)
      (f_add (SpecCcsBuilder_f_next_col builder) ((1 : t_usize)))
      (SpecCcsBuilder_f_num_public builder)
      (SpecCcsBuilder_f_row builder)
      (SpecCcsBuilder_f_a_entries builder)
      (SpecCcsBuilder_f_b_entries builder)
      (SpecCcsBuilder_f_c_entries builder) in
  (builder, col).
"""
    text = text[:start] + textwrap.dedent(replacement).rstrip() + "\n" + text[end + 1:]

lc_start = "Definition lc_add_term (target : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global))) (col : t_usize) (coeff : t_BigInt) : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :="
expr_start = "\nInductive t_SpecCcsExpr : Type :="
if lc_start in text and expr_start in text:
    start = text.index(lc_start)
    end = text.index(expr_start, start)
    replacement = """
Definition lc_add_term (target : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global))) (col : t_usize) (coeff : t_BigInt) : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :=
  if Z.eqb coeff 0%Z then
    target
  else
    let '(target, existing) := impl_20__remove target col in
    let updated :=
      match existing with
      | Option_Some value => Z.add value coeff
      | Option_None => coeff
      end in
    if Z.eqb updated 0%Z then
      target
    else
      (col, updated) :: target.

Definition lc_const (value : t_BigInt) : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :=
  lc_add_term [] (0 : t_usize) value.

Definition lc_var (col : t_usize) : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :=
  lc_add_term [] col 1%Z.

Definition lc_one '(_ : unit) : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :=
  lc_const 1%Z.

Definition lc_one_minus_var (col : t_usize) : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :=
  lc_add_term (lc_one tt) col (-1)%Z.

Definition lc_add_assign (target : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global))) (other : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global))) : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :=
  List.fold_left (fun acc entry => lc_add_term acc (fst entry) (snd entry)) other target.

Definition lc_sub_assign (target : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global))) (other : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global))) : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :=
  List.fold_left (fun acc entry => lc_add_term acc (fst entry) (Z.opp (snd entry))) other target.

Definition push_lc_entries (field : t_FieldId) (entries : t_Vec ((t_SpecCcsMatrixEntry)) ((t_Global))) (row : t_usize) (lc : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global))) : t_Vec ((t_SpecCcsMatrixEntry)) ((t_Global)) :=
  List.fold_left
    (fun acc entry =>
      let '(col, coeff) := entry in
      let normalized := normalize_mod coeff (impl_FieldId__modulus field) in
      if Z.eqb normalized 0%Z then
        acc
      else
        acc ++ [SpecCcsMatrixEntry row col (bigint_to_spec_value normalized field)])
    lc
    entries.
"""
    text = text[:start] + textwrap.dedent(replacement).rstrip() + "\n" + text[end:]

builder_expr_start = "\nFixpoint builder_expr_to_lc (builder : t_SpecCcsBuilder) (expr : t_SpecCcsExpr) (constraint_index : t_usize) : (t_SpecCcsBuilder*t_Result ((t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))) ((t_SpecCcsSynthesisError))) :="
if builder_expr_start in text and "Definition builder_signal_lc" not in text:
    helper_block = """
Definition builder_signal_lc
  (builder : t_SpecCcsBuilder)
  (signal_index : t_usize)
  (constraint_index : t_usize)
  : t_Result ((t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))) ((t_SpecCcsSynthesisError)) :=
  match impl__get (impl_1__as_slice (SpecCcsBuilder_f_signal_columns builder)) signal_index with
  | Option_Some col =>
      Result_Ok (lc_var col)
  | Option_None =>
      Result_Err
        (SpecCcsSynthesisError
          constraint_index
          SpecCcsSynthesisErrorKind_InvalidSignalIndex)
  end.

Definition builder_add_row
  (builder : t_SpecCcsBuilder)
  (a : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))
  (b : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))
  (c : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))
  : t_SpecCcsBuilder :=
  let row := SpecCcsBuilder_f_row builder in
  let a_entries := push_lc_entries (SpecCcsBuilder_f_field builder) (SpecCcsBuilder_f_a_entries builder) row a in
  let b_entries := push_lc_entries (SpecCcsBuilder_f_field builder) (SpecCcsBuilder_f_b_entries builder) row b in
  let c_entries := push_lc_entries (SpecCcsBuilder_f_field builder) (SpecCcsBuilder_f_c_entries builder) row c in
  SpecCcsBuilder
    (SpecCcsBuilder_f_field builder)
    (SpecCcsBuilder_f_signal_columns builder)
    (SpecCcsBuilder_f_next_col builder)
    (SpecCcsBuilder_f_num_public builder)
    (f_add row ((1 : t_usize)))
    a_entries
    b_entries
    c_entries.
"""
    text = text.replace(
        builder_expr_start,
        "\n" + textwrap.dedent(helper_block).rstrip() + "\n\n" + builder_expr_start.lstrip("\n"),
        1,
    )

text = text.replace("Result_Ok (()) =>", "Result_Ok tt =>")

replacements = {
    "f_field builder": "SpecCcsBuilder_f_field builder",
    "f_signal_columns builder": "SpecCcsBuilder_f_signal_columns builder",
    "f_next_col builder": "SpecCcsBuilder_f_next_col builder",
    "f_num_public builder": "SpecCcsBuilder_f_num_public builder",
    "f_row builder": "SpecCcsBuilder_f_row builder",
    "f_a_entries builder": "SpecCcsBuilder_f_a_entries builder",
    "f_b_entries builder": "SpecCcsBuilder_f_b_entries builder",
    "f_c_entries builder": "SpecCcsBuilder_f_c_entries builder",
    "f_field program": "SpecCcsConstraintProgram_f_field program",
    "f_signals program": "SpecCcsConstraintProgram_f_signals program",
    "f_constraints program": "SpecCcsConstraintProgram_f_constraints program",
    "f_visibility signal": "SpecCcsSignal_f_visibility signal",
}
for source, target in replacements.items():
    text = text.replace(source, target)

cleanup_replacements = {
    "SpecCcsBuilder_SpecCcsBuilder_f_field": "SpecCcsBuilder_f_field",
    "SpecCcsBuilder_SpecCcsBuilder_f_signal_columns": "SpecCcsBuilder_f_signal_columns",
    "SpecCcsBuilder_SpecCcsBuilder_f_next_col": "SpecCcsBuilder_f_next_col",
    "SpecCcsBuilder_SpecCcsBuilder_f_num_public": "SpecCcsBuilder_f_num_public",
    "SpecCcsBuilder_SpecCcsBuilder_f_row": "SpecCcsBuilder_f_row",
    "SpecCcsBuilder_SpecCcsBuilder_f_a_entries": "SpecCcsBuilder_f_a_entries",
    "SpecCcsBuilder_SpecCcsBuilder_f_b_entries": "SpecCcsBuilder_f_b_entries",
    "SpecCcsBuilder_SpecCcsBuilder_f_c_entries": "SpecCcsBuilder_f_c_entries",
    "SpecCcsConstraintProgram_SpecCcsConstraintProgram_f_field": "SpecCcsConstraintProgram_f_field",
    "SpecCcsConstraintProgram_SpecCcsConstraintProgram_f_signals": "SpecCcsConstraintProgram_f_signals",
    "SpecCcsConstraintProgram_SpecCcsConstraintProgram_f_constraints": "SpecCcsConstraintProgram_f_constraints",
    "SpecCcsSignal_SpecCcsSignal_f_visibility": "SpecCcsSignal_f_visibility",
}
for source, target in cleanup_replacements.items():
    text = text.replace(source, target)

for line in [
    "Notation \"'f_field'\" := (SpecCcsConstraintProgram_f_field).\n",
    "Notation \"'f_signals'\" := (SpecCcsConstraintProgram_f_signals).\n",
    "Notation \"'f_constraints'\" := (SpecCcsConstraintProgram_f_constraints).\n",
]:
    text = text.replace(line, "")

builder_new_start = "Definition builder_new (program : t_SpecCcsConstraintProgram) : t_SpecCcsBuilder :="
if builder_new_start in text:
    start = text.index(builder_new_start)
    replacement = """
Fixpoint assign_public_signal_columns
  (signals : t_Vec ((t_SpecCcsSignal)) ((t_Global)))
  (signal_index : t_usize)
  (next_col : t_usize)
  (num_public : t_usize)
  (signal_columns : t_Vec ((t_usize)) ((t_Global)))
  : t_usize * t_usize * t_Vec ((t_usize)) ((t_Global)) :=
  match signals with
  | [] =>
      (next_col, num_public, signal_columns)
  | signal :: remaining_signals =>
      match SpecCcsSignal_f_visibility signal with
      | SpecCcsVisibility_Public =>
          let signal_columns :=
            impl__to_vec
              (update_at_usize
                (impl_1__as_slice signal_columns)
                signal_index
                next_col) in
          assign_public_signal_columns
            remaining_signals
            (f_add signal_index ((1 : t_usize)))
            (f_add next_col ((1 : t_usize)))
            (f_add num_public ((1 : t_usize)))
            signal_columns
      | SpecCcsVisibility_NonPublic =>
          assign_public_signal_columns
            remaining_signals
            (f_add signal_index ((1 : t_usize)))
            next_col
            num_public
            signal_columns
      end
  end.

Fixpoint assign_non_public_signal_columns
  (signals : t_Vec ((t_SpecCcsSignal)) ((t_Global)))
  (signal_index : t_usize)
  (next_col : t_usize)
  (signal_columns : t_Vec ((t_usize)) ((t_Global)))
  : t_usize * t_Vec ((t_usize)) ((t_Global)) :=
  match signals with
  | [] =>
      (next_col, signal_columns)
  | signal :: remaining_signals =>
      match SpecCcsSignal_f_visibility signal with
      | SpecCcsVisibility_Public =>
          assign_non_public_signal_columns
            remaining_signals
            (f_add signal_index ((1 : t_usize)))
            next_col
            signal_columns
      | SpecCcsVisibility_NonPublic =>
          let signal_columns :=
            impl__to_vec
              (update_at_usize
                (impl_1__as_slice signal_columns)
                signal_index
                next_col) in
          assign_non_public_signal_columns
            remaining_signals
            (f_add signal_index ((1 : t_usize)))
            (f_add next_col ((1 : t_usize)))
            signal_columns
      end
  end.

Definition builder_new (program : t_SpecCcsConstraintProgram) : t_SpecCcsBuilder :=
  let signal_columns :=
    from_elem
      ((0 : t_usize))
      (impl_1__len (SpecCcsConstraintProgram_f_signals program)) in
  let '(next_col, num_public, signal_columns) :=
    assign_public_signal_columns
      (SpecCcsConstraintProgram_f_signals program)
      (0 : t_usize)
      (1 : t_usize)
      (0 : t_usize)
      signal_columns in
  let '(next_col, signal_columns) :=
    assign_non_public_signal_columns
      (SpecCcsConstraintProgram_f_signals program)
      (0 : t_usize)
      next_col
      signal_columns in
  SpecCcsBuilder
    (SpecCcsConstraintProgram_f_field program)
    signal_columns
    next_col
    num_public
    (0 : t_usize)
    (impl__new tt)
    (impl__new tt)
    (impl__new tt).

Definition builder_signal_lc
  (builder : t_SpecCcsBuilder)
  (signal_index : t_usize)
  (constraint_index : t_usize)
  : t_Result ((t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))) ((t_SpecCcsSynthesisError)) :=
  match impl__get (impl_1__as_slice (SpecCcsBuilder_f_signal_columns builder)) signal_index with
  | Option_Some col =>
      Result_Ok (lc_var col)
  | Option_None =>
      Result_Err
        (SpecCcsSynthesisError
          constraint_index
          SpecCcsSynthesisErrorKind_InvalidSignalIndex)
  end.

Definition builder_add_row
  (builder : t_SpecCcsBuilder)
  (a : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))
  (b : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))
  (c : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))
  : t_SpecCcsBuilder :=
  let row := SpecCcsBuilder_f_row builder in
  let a_entries :=
    push_lc_entries
      (SpecCcsBuilder_f_field builder)
      (SpecCcsBuilder_f_a_entries builder)
      row
      a in
  let b_entries :=
    push_lc_entries
      (SpecCcsBuilder_f_field builder)
      (SpecCcsBuilder_f_b_entries builder)
      row
      b in
  let c_entries :=
    push_lc_entries
      (SpecCcsBuilder_f_field builder)
      (SpecCcsBuilder_f_c_entries builder)
      row
      c in
  SpecCcsBuilder
    (SpecCcsBuilder_f_field builder)
    (SpecCcsBuilder_f_signal_columns builder)
    (SpecCcsBuilder_f_next_col builder)
    (SpecCcsBuilder_f_num_public builder)
    (f_add row ((1 : t_usize)))
    a_entries
    b_entries
    c_entries.

Definition builder_expr_fuel_budget : nat := 4096%nat.

Definition builder_fuel_exhausted_error
  (constraint_index : t_usize) : t_SpecCcsSynthesisError :=
  SpecCcsSynthesisError constraint_index SpecCcsSynthesisErrorKind_InvalidSignalIndex.

Fixpoint builder_expr_to_lc_fueled
  (fuel : nat)
  (builder : t_SpecCcsBuilder)
  (expr : t_SpecCcsExpr)
  (constraint_index : t_usize)
  {struct fuel}
  : t_SpecCcsBuilder * t_Result ((t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))) ((t_SpecCcsSynthesisError)) :=
  match fuel with
  | O =>
      (builder, Result_Err (builder_fuel_exhausted_error constraint_index))
  | S fuel =>
      match expr with
      | SpecCcsExpr_Const value =>
          (builder, Result_Ok (lc_const (spec_value_to_bigint value (SpecCcsBuilder_f_field builder))))
      | SpecCcsExpr_Signal signal_index =>
          (builder, builder_signal_lc builder signal_index constraint_index)
      | SpecCcsExpr_Add terms =>
          builder_terms_to_lc_acc_fueled fuel builder terms constraint_index (impl_18__new tt)
      | SpecCcsExpr_Sub lhs rhs =>
          let '(builder, lhs_result) := builder_expr_to_lc_fueled fuel builder lhs constraint_index in
          match lhs_result with
          | Result_Err error =>
              (builder, Result_Err error)
          | Result_Ok lhs_lc =>
              let '(builder, rhs_result) := builder_expr_to_lc_fueled fuel builder rhs constraint_index in
              match rhs_result with
              | Result_Err error =>
                  (builder, Result_Err error)
              | Result_Ok rhs_lc =>
                  (builder, Result_Ok (lc_sub_assign lhs_lc rhs_lc))
              end
          end
      | SpecCcsExpr_Mul lhs rhs =>
          let '(builder, lhs_result) := builder_expr_to_lc_fueled fuel builder lhs constraint_index in
          match lhs_result with
          | Result_Err error =>
              (builder, Result_Err error)
          | Result_Ok lhs_lc =>
              let '(builder, rhs_result) := builder_expr_to_lc_fueled fuel builder rhs constraint_index in
              match rhs_result with
              | Result_Err error =>
                  (builder, Result_Err error)
              | Result_Ok rhs_lc =>
                  let '(builder, aux_col) := builder_allocate_aux builder in
                  (builder_add_row builder lhs_lc rhs_lc (lc_var aux_col), Result_Ok (lc_var aux_col))
              end
          end
      | SpecCcsExpr_Div lhs rhs =>
          let '(builder, numerator_result) := builder_expr_to_lc_fueled fuel builder lhs constraint_index in
          match numerator_result with
          | Result_Err error =>
              (builder, Result_Err error)
          | Result_Ok numerator =>
              let '(builder, denominator_result) := builder_expr_to_lc_fueled fuel builder rhs constraint_index in
              match denominator_result with
              | Result_Err error =>
                  (builder, Result_Err error)
              | Result_Ok denominator =>
                  let '(builder, quotient_col) := builder_allocate_aux builder in
                  let '(builder, inverse_col) := builder_allocate_aux builder in
                  let builder :=
                    builder_add_row builder denominator (lc_var inverse_col) (lc_one tt) in
                  let builder :=
                    builder_add_row builder (lc_var quotient_col) denominator numerator in
                  (builder, Result_Ok (lc_var quotient_col))
              end
          end
      end
  end
with builder_terms_to_lc_acc_fueled
  (fuel : nat)
  (builder : t_SpecCcsBuilder)
  (terms : t_Vec ((t_SpecCcsExpr)) ((t_Global)))
  (constraint_index : t_usize)
  (acc : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))
  {struct fuel}
  : t_SpecCcsBuilder * t_Result ((t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))) ((t_SpecCcsSynthesisError)) :=
  match fuel with
  | O =>
      (builder, Result_Err (builder_fuel_exhausted_error constraint_index))
  | S fuel =>
      match terms with
      | [] =>
          (builder, Result_Ok acc)
      | term :: remaining_terms =>
          let '(builder, term_result) := builder_expr_to_lc_fueled fuel builder term constraint_index in
          match term_result with
          | Result_Err error =>
              (builder, Result_Err error)
          | Result_Ok term_lc =>
              builder_terms_to_lc_acc_fueled
                fuel
                builder
                remaining_terms
                constraint_index
                (lc_add_assign acc term_lc)
          end
      end
  end.

Definition builder_expr_to_lc
  (builder : t_SpecCcsBuilder)
  (expr : t_SpecCcsExpr)
  (constraint_index : t_usize)
  : t_SpecCcsBuilder * t_Result ((t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))) ((t_SpecCcsSynthesisError)) :=
  builder_expr_to_lc_fueled builder_expr_fuel_budget builder expr constraint_index.

Fixpoint range_bits_to_lc
  (remaining : nat)
  (bit_index : nat)
  (builder : t_SpecCcsBuilder)
  (recomposed : t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)))
  : t_SpecCcsBuilder * t_BTreeMap ((t_usize)) ((t_BigInt)) ((t_Global)) :=
  match remaining with
  | O =>
      (builder, recomposed)
  | S remaining_bits =>
      let '(builder, bit_col) := builder_allocate_aux builder in
      let builder :=
        builder_add_row
          builder
          (lc_var bit_col)
          (lc_one_minus_var bit_col)
          (impl_18__new tt) in
      let recomposed :=
        lc_add_term recomposed bit_col (Z.shiftl 1%Z (Z.of_nat bit_index)) in
      range_bits_to_lc remaining_bits (S bit_index) builder recomposed
  end.

Definition encode_constraint_runtime
  (builder : t_SpecCcsBuilder)
  (constraint : t_SpecCcsConstraint)
  (constraint_index : t_usize)
  : t_SpecCcsBuilder * t_Result ((unit)) ((t_SpecCcsSynthesisError)) :=
  match constraint with
  | SpecCcsConstraint_Equal equal_constraint =>
      let lhs := SpecCcsConstraint_Equal_f_lhs equal_constraint in
      let rhs := SpecCcsConstraint_Equal_f_rhs equal_constraint in
      match lhs with
      | SpecCcsExpr_Mul lhs_term rhs_term =>
          let '(builder, a_result) := builder_expr_to_lc builder lhs_term constraint_index in
          match a_result with
          | Result_Err error =>
              (builder, Result_Err error)
          | Result_Ok a =>
              let '(builder, b_result) := builder_expr_to_lc builder rhs_term constraint_index in
              match b_result with
              | Result_Err error =>
                  (builder, Result_Err error)
              | Result_Ok b =>
                  let '(builder, c_result) := builder_expr_to_lc builder rhs constraint_index in
                  match c_result with
                  | Result_Err error =>
                      (builder, Result_Err error)
                  | Result_Ok c =>
                      (builder_add_row builder a b c, Result_Ok tt)
                  end
              end
          end
      | _ =>
          match rhs with
          | SpecCcsExpr_Mul lhs_term rhs_term =>
              let '(builder, a_result) := builder_expr_to_lc builder lhs_term constraint_index in
              match a_result with
              | Result_Err error =>
                  (builder, Result_Err error)
              | Result_Ok a =>
                  let '(builder, b_result) := builder_expr_to_lc builder rhs_term constraint_index in
                  match b_result with
                  | Result_Err error =>
                      (builder, Result_Err error)
                  | Result_Ok b =>
                      let '(builder, c_result) := builder_expr_to_lc builder lhs constraint_index in
                      match c_result with
                      | Result_Err error =>
                          (builder, Result_Err error)
                      | Result_Ok c =>
                          (builder_add_row builder a b c, Result_Ok tt)
                      end
                  end
              end
          | _ =>
              let '(builder, lhs_result) := builder_expr_to_lc builder lhs constraint_index in
              match lhs_result with
              | Result_Err error =>
                  (builder, Result_Err error)
              | Result_Ok lhs_lc =>
                  let '(builder, rhs_result) := builder_expr_to_lc builder rhs constraint_index in
                  match rhs_result with
                  | Result_Err error =>
                      (builder, Result_Err error)
                  | Result_Ok rhs_lc =>
                      let diff := lc_sub_assign lhs_lc rhs_lc in
                      (builder_add_row builder diff (lc_one tt) (impl_18__new tt), Result_Ok tt)
                  end
              end
          end
      end
  | SpecCcsConstraint_Boolean boolean_constraint =>
      let signal_index := SpecCcsConstraint_Boolean_f_signal_index boolean_constraint in
      match impl__get (impl_1__as_slice (SpecCcsBuilder_f_signal_columns builder)) signal_index with
      | Option_Some col =>
          let value := lc_var col in
          (builder_add_row builder value (lc_one_minus_var col) (impl_18__new tt), Result_Ok tt)
      | Option_None =>
          (builder, Result_Err (SpecCcsSynthesisError constraint_index SpecCcsSynthesisErrorKind_InvalidSignalIndex))
      end
  | SpecCcsConstraint_Range range_constraint =>
      let signal_index := SpecCcsConstraint_Range_f_signal_index range_constraint in
      let bits := SpecCcsConstraint_Range_f_bits range_constraint in
      match builder_signal_lc builder signal_index constraint_index with
      | Result_Err error =>
          (builder, Result_Err error)
      | Result_Ok signal_value =>
          let '(builder, recomposed) :=
            range_bits_to_lc
              (N.to_nat (u32_to_n bits))
              O
              builder
              (impl_18__new tt) in
          (builder_add_row builder signal_value (lc_one tt) recomposed, Result_Ok tt)
      end
  | SpecCcsConstraint_Lookup =>
      (builder, Result_Err (SpecCcsSynthesisError constraint_index SpecCcsSynthesisErrorKind_LookupRequiresLowering))
  | SpecCcsConstraint_BlackBox black_box_constraint =>
      match SpecCcsConstraint_BlackBox_f_kind black_box_constraint with
      | SpecCcsBlackBoxKind_RecursiveAggregationMarker =>
          (builder, Result_Ok tt)
      | SpecCcsBlackBoxKind_Other =>
          (builder, Result_Err (SpecCcsSynthesisError constraint_index SpecCcsSynthesisErrorKind_BlackBoxRequiresLowering))
      end
  end.

Fixpoint synthesize_constraints_from
  (builder : t_SpecCcsBuilder)
  (constraints : t_Vec ((t_SpecCcsConstraint)) ((t_Global)))
  (constraint_index : t_usize)
  {struct constraints}
  : t_Result ((t_SpecCcsBuilder)) ((t_SpecCcsSynthesisError)) :=
  match constraints with
  | [] =>
      Result_Ok builder
  | constraint :: remaining_constraints =>
      match encode_constraint_runtime builder constraint constraint_index with
      | (next_builder, Result_Ok tt) =>
          synthesize_constraints_from
            next_builder
            remaining_constraints
            (impl_usize__saturating_add constraint_index ((1 : t_usize)))
      | (_, Result_Err error) =>
          Result_Err error
      end
  end.

Definition synthesize_ccs_program
  (program : t_SpecCcsConstraintProgram)
  : t_Result ((t_SpecCcsProgram)) ((t_SpecCcsSynthesisError)) :=
  let builder := builder_new program in
  match synthesize_constraints_from builder (SpecCcsConstraintProgram_f_constraints program) (0 : t_usize) with
  | Result_Ok builder =>
      Result_Ok (builder_finish builder (SpecCcsConstraintProgram_f_field program))
  | Result_Err error =>
      Result_Err error
  end.
"""
    text = text[:start] + textwrap.dedent(replacement).rstrip() + "\n"

path.write_text(text)
PY
}

switch_name="$(pin_value opam_switch)"
crate_name="$(pin_value crate)"
backend_name="$(pin_value backend)"
include_filter="$(pin_value include)"

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
  echo "cargo-hax is required to extract zkf-core::proof_kernel_spec into Rocq" >&2
  exit 1
fi

if [ -n "$switch_name" ] && [ "$(opam switch show 2>/dev/null || true)" != "$switch_name" ]; then
  echo "expected opam switch '$switch_name' while running hax extraction" >&2
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
patch_generated_dependencies
normalize_generated_fixpoints
replace_field_model_dropped_bodies
normalize_generated_transform_spec
normalize_generated_witness_spec
normalize_generated_ccs_spec
assert_transform_fixpoints_normalized

if ! find "$rocq_output" -type f -name '*.v' | grep -q .; then
  echo "no Rocq extraction files were mirrored into $rocq_output" >&2
  exit 1
fi

kernel_generated="$rocq_workspace/KernelGenerated.v"
coq_project="$rocq_workspace/_CoqProject"

generated_modules=()
seen_modules=""

append_module_once() {
  local module="$1"
  case "|$seen_modules|" in
    *"|$module|"*)
      return 0
      ;;
  esac

  generated_modules+=("$module")
  seen_modules="${seen_modules}|${module}"
}

preferred_modules=(
  "Zkf_core_Field"
  "Zkf_core_Proof_kernel_spec_Bundle"
  "Zkf_core_Proof_kernel_spec"
  "Zkf_core_Proof_kernel_spec_Spec_field_ops"
)

witness_generated_module="Zkf_core_Proof_witness_generation_spec"

for module in "${preferred_modules[@]}"; do
  if [ -f "$rocq_output/${module}.v" ]; then
    append_module_once "$module"
  fi
done

while IFS= read -r file; do
  module="${file#$rocq_output/}"
  module="${module%.v}"
  module="${module//\//.}"
  if [ "$module" = "$witness_generated_module" ]; then
    continue
  fi
  append_module_once "$module"
done < <(find "$rocq_output" -type f -name '*.v' | sort)

if [ "${#generated_modules[@]}" -eq 0 ]; then
  echo "no generated Rocq modules were discovered under $rocq_output" >&2
  exit 1
fi

{
  echo "(* Auto-generated by scripts/run_hax_rocq_extract.sh. *)"
  for module in "${generated_modules[@]}"; do
    echo "From ZkfCoreExtraction Require Export ${module}."
  done
} >"$kernel_generated"

{
  echo "-Q ./extraction ZkfCoreExtraction"
  echo "./KernelCompat.v"
  for module in "${generated_modules[@]}"; do
    echo "./extraction/${module//./\/}.v"
  done
  if [ -f "$rocq_output/${witness_generated_module}.v" ]; then
    echo "./extraction/${witness_generated_module}.v"
  fi
  echo "./KernelArithmetic.v"
  echo "./KernelGenerated.v"
  echo "./KernelSemantics.v"
  echo "./KernelProofs.v"
  echo "./WitnessGenerationSemantics.v"
  echo "./WitnessGenerationProofs.v"
  echo "./CcsSemantics.v"
  echo "./CcsProofs.v"
} >"$coq_project"
