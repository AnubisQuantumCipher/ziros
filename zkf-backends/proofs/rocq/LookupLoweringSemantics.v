Require Import BackendCompat.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_lookup_lowering_spec.

Definition SupportedSelectorValueTableLowering
  (surface : t_LookupLoweringSurface)
  : Prop :=
  LookupLoweringSurface_f_supported_path surface =
    SpecSupportedLookupLoweringPath_SelectorValueTable.

Definition LookupLoweringWitnessPreservation
  (input_count : t_usize)
  (output_count : t_usize)
  (table_rows : t_usize)
  (table_columns : t_usize)
  (surface : t_LookupLoweringSurface)
  : Prop :=
  SupportedSelectorValueTableLowering surface /\
  LookupLoweringSurface_f_input_count surface = input_count /\
  LookupLoweringSurface_f_output_count surface = output_count /\
  LookupLoweringSurface_f_table_rows surface = table_rows /\
  LookupLoweringSurface_f_table_columns surface = table_columns /\
  LookupLoweringSurface_f_selector_count surface = table_rows /\
  LookupLoweringSurface_f_boolean_constraint_count surface = table_rows /\
  LookupLoweringSurface_f_output_binding_count surface =
    lookup_lowering_output_binding_count input_count output_count table_columns /\
  LookupLoweringSurface_f_equality_constraint_count surface =
    lookup_lowering_equality_constraint_count input_count output_count table_columns.
