Require Import BackendCompat.
From ZkfBackendsExtraction Require Import Zkf_backends_Proof_plonky3_surface.

Definition LoweredProgramAccepted (program : t_SpecProgram) (lowered : t_LoweredProgram) : Prop :=
  lower_program program = Result_Ok lowered.

Definition LoweredProgramWellFormed (lowered : t_LoweredProgram) : Prop :=
  validate_lowered_program lowered = Result_Ok tt.

Definition PublicInputsPreserved (program : t_SpecProgram) (lowered : t_LoweredProgram) : Prop :=
  public_input_positions_preserved program lowered = Result_Ok true.

Definition TraceRowAccepted
  (lowered : t_LoweredProgram)
  (witness : t_SpecWitness)
  (field : t_SpecPlonky3FieldId)
  (row : t_Vec t_u64 t_Global)
  : Prop :=
  build_trace_row lowered witness field = Result_Ok row.
