module Zkf_core.Field
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

type t_FieldId =
  | FieldId_Bn254 : t_FieldId
  | FieldId_Bls12_381_ : t_FieldId
  | FieldId_PastaFp : t_FieldId
  | FieldId_PastaFq : t_FieldId
  | FieldId_Goldilocks : t_FieldId
  | FieldId_BabyBear : t_FieldId
  | FieldId_Mersenne31 : t_FieldId

/// A field element stored as a byte-backed integer (little-endian unsigned
/// magnitude + sign). No string parsing on arithmetic operations.
/// JSON serialization emits decimal strings for backward compatibility.
type t_FieldElement = {
  f_bytes:t_Array u8 (mk_usize 32);
  f_len:u8;
  f_negative:bool
}
