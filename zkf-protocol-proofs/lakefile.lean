import Lake
open Lake DSL

package zkf_protocol_proofs where
  moreLeanArgs := #["-T1000"]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.28.0"

require Arklib from "vendor/arklib"

lean_lib ZkfProtocolProofs
