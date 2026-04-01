mod LaunchContracts;

use vstd::prelude::*;
use LaunchContracts::*;

verus! {

pub proof fn poseidon2_launch_surface_ok(input: Poseidon2ContractInputModel)
    requires
        poseidon2_contract_accepts(input),
    ensures
        validated_poseidon2_dispatch(input).family is Poseidon2,
        validated_poseidon2_dispatch(input).read_regions[0].elements == input.state_elements,
        validated_poseidon2_dispatch(input).write_regions[0].elements == input.state_elements,
        input.simd ==> validated_poseidon2_dispatch(input).scratch_bytes == poseidon2_state_width() * input.element_bytes,
{
    poseidon2_accepts_implies_validated_surface(input);
}

}
