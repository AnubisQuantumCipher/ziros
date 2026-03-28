(* File manually aligned with the proof-facing backend lookup lowering surface. *)
From Coq Require Import ZArith NArith.
Open Scope Z_scope.
Open Scope bool_scope.
Require Import BackendCompat.

Inductive t_SpecSupportedLookupLoweringPath : Type :=
| SpecSupportedLookupLoweringPath_SelectorValueTable.

Record LookupLoweringSurface_record : Type := {
  LookupLoweringSurface_f_supported_path : t_SpecSupportedLookupLoweringPath;
  LookupLoweringSurface_f_input_count : t_usize;
  LookupLoweringSurface_f_output_count : t_usize;
  LookupLoweringSurface_f_table_rows : t_usize;
  LookupLoweringSurface_f_table_columns : t_usize;
  LookupLoweringSurface_f_selector_count : t_usize;
  LookupLoweringSurface_f_boolean_constraint_count : t_usize;
  LookupLoweringSurface_f_equality_constraint_count : t_usize;
  LookupLoweringSurface_f_output_binding_count : t_usize;
}.
Definition LookupLoweringSurface := Build_LookupLoweringSurface_record.
Definition t_LookupLoweringSurface := LookupLoweringSurface_record.

Definition lookup_lowering_surface_supported
  (input_count : t_usize)
  (table_rows : t_usize)
  (table_columns : t_usize)
  : bool :=
  andb
    (negb (f_eq table_rows ((0 : t_usize))))
    (andb
      (f_le table_rows ((256 : t_usize)))
      (f_le input_count table_columns)).

Definition lookup_lowering_output_binding_count
  (input_count : t_usize)
  (output_count : t_usize)
  (table_columns : t_usize)
  : t_usize :=
  let remaining_columns := n_to_usize (N.max 0 (usize_to_n table_columns - usize_to_n input_count)) in
  if N.leb (usize_to_n output_count) (usize_to_n remaining_columns)
  then output_count
  else remaining_columns.

Definition lookup_lowering_equality_constraint_count
  (input_count : t_usize)
  (output_count : t_usize)
  (table_columns : t_usize)
  : t_usize :=
  let output_binding_count :=
    lookup_lowering_output_binding_count input_count output_count table_columns in
  f_add ((1 : t_usize)) (f_add input_count output_binding_count).

Definition supported_lookup_lowering_surface
  (input_count : t_usize)
  (output_count : t_usize)
  (table_rows : t_usize)
  (table_columns : t_usize)
  : t_Option (t_LookupLoweringSurface) :=
  if lookup_lowering_surface_supported input_count table_rows table_columns then
    Option_Some
      (LookupLoweringSurface
         (SpecSupportedLookupLoweringPath_SelectorValueTable)
         input_count
         output_count
         table_rows
         table_columns
         table_rows
         table_rows
         (lookup_lowering_equality_constraint_count input_count output_count table_columns)
         (lookup_lowering_output_binding_count input_count output_count table_columns))
  else
    Option_None.
