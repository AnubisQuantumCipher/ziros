use vstd::prelude::*;

verus! {

pub open spec fn two_thirds_accepts(accepted_count: nat, total_count: nat) -> bool {
    let total = if total_count == 0 { 1nat } else { total_count };
    accepted_count * 3 >= total * 2
}

pub proof fn swarm_consensus_two_thirds_threshold(accepted_count: nat, total_count: nat)
    ensures
        two_thirds_accepts(2, 3),
        !two_thirds_accepts(2, 4),
{
}

} // verus!
