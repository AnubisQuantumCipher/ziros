use vstd::prelude::*;

verus! {

spec fn deductible_adjusted(covered: nat, deductible: nat) -> nat {
    if covered >= deductible { covered - deductible } else { 0 }
}

spec fn capped_payout(covered: nat, deductible: nat, cap: nat) -> nat {
    let adjusted = deductible_adjusted(covered, deductible);
    if adjusted <= cap { adjusted } else { cap }
}

proof fn capped_payout_respects_cap(covered: nat, deductible: nat, cap: nat)
    ensures capped_payout(covered, deductible, cap) <= cap
{
}

proof fn deductible_adjusted_is_nonnegative(covered: nat, deductible: nat)
    ensures 0 <= deductible_adjusted(covered, deductible)
{
}

}

fn main() {}
