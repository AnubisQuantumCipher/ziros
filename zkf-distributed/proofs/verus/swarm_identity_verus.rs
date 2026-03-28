use vstd::prelude::*;

verus! {

pub open spec fn hybrid_identity_prefers_bundle(bundle_present: bool) -> bool {
    bundle_present
}

pub open spec fn verify_admission_pow(difficulty: nat, leading_zero_bits: nat) -> bool {
    difficulty == 0 || leading_zero_bits >= difficulty
}

pub proof fn swarm_identity_bundle_pow_binding(bundle_present: bool, difficulty: nat, leading_zero_bits: nat)
    ensures
        bundle_present ==> hybrid_identity_prefers_bundle(bundle_present),
        difficulty == 0 ==> verify_admission_pow(difficulty, leading_zero_bits),
        leading_zero_bits >= difficulty ==> verify_admission_pow(difficulty, leading_zero_bits),
{
}

} // verus!
