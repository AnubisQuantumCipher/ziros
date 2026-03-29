module Zkf_core.Proof_kernel_spec.Spec_field_ops
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open FStar.Mul
open Core_models

include Zkf_core.Proof_kernel_spec.Bundle {zero as zero}

include Zkf_core.Proof_kernel_spec.Bundle {normalize as normalize}

include Zkf_core.Proof_kernel_spec.Bundle {add as add}

include Zkf_core.Proof_kernel_spec.Bundle {sub as sub}

include Zkf_core.Proof_kernel_spec.Bundle {mul as mul}

include Zkf_core.Proof_kernel_spec.Bundle {div as div}

include Zkf_core.Proof_kernel_spec.Bundle {eq as eq}

include Zkf_core.Proof_kernel_spec.Bundle {is_boolean as is_boolean}

include Zkf_core.Proof_kernel_spec.Bundle {fits_bits as fits_bits}
