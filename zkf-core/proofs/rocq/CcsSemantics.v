Require Import List.
Require Import NArith.
Import List.ListNotations.

Require Import KernelCompat.
From ZkfCoreExtraction Require Import Zkf_core_Field.
From ZkfCoreExtraction Require Import Zkf_core_Proof_ccs_spec.

Definition ConstraintSupported
  (constraint : t_SpecCcsConstraint) : Prop :=
  match constraint with
  | SpecCcsConstraint_Lookup =>
      False
  | SpecCcsConstraint_BlackBox black_box =>
      match SpecCcsConstraint_BlackBox_f_kind black_box with
      | SpecCcsBlackBoxKind_RecursiveAggregationMarker => True
      | SpecCcsBlackBoxKind_Other => False
      end
  | _ =>
      True
  end.

Definition ProgramSupported
  (program : t_SpecCcsConstraintProgram) : Prop :=
  Forall ConstraintSupported (SpecCcsConstraintProgram_f_constraints program).

Definition canonical_multisets
  (field : t_FieldId) : t_Vec SpecCcsMultiset_record t_Global :=
  [ SpecCcsMultiset
      [n_to_usize 0%N; n_to_usize 1%N]
      (bigint_to_spec_value (f_one tt) field)
  ; SpecCcsMultiset
      [n_to_usize 2%N]
      (bigint_to_spec_value (f_neg (f_one tt)) field)
  ].

Definition MatrixDimensionsMatchProgram
  (program : t_SpecCcsProgram)
  (matrix : SpecCcsMatrix_record) : Prop :=
  SpecCcsMatrix_f_rows matrix = SpecCcsProgram_f_num_constraints program /\
  SpecCcsMatrix_f_cols matrix = SpecCcsProgram_f_num_variables program.

Definition CanonicalCcsShape
  (program : t_SpecCcsProgram) : Prop :=
  length (SpecCcsProgram_f_matrices program) = 3 /\
  Forall (MatrixDimensionsMatchProgram program) (SpecCcsProgram_f_matrices program) /\
  SpecCcsProgram_f_multisets program =
    canonical_multisets (SpecCcsProgram_f_field program).
