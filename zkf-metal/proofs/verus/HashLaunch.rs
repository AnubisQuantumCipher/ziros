mod LaunchContracts;

use vstd::prelude::*;
use LaunchContracts::*;

verus! {

pub proof fn hash_launch_surface_ok(input: HashContractInputModel)
    requires
        hash_contract_accepts(input),
    ensures
        validated_hash_dispatch(input).family is Hash,
        validated_hash_dispatch(input).dispatch.threadgroups_y == 1,
        validated_hash_dispatch(input).read_regions[0].elements == input.input_bytes,
        validated_hash_dispatch(input).write_regions[0].elements == input.output_bytes,
{
    hash_accepts_implies_validated_surface(input);
}

}
