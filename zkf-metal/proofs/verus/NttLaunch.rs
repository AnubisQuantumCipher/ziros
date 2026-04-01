mod LaunchContracts;

use vstd::prelude::*;
use LaunchContracts::*;

verus! {

pub proof fn ntt_launch_surface_ok(input: NttContractInputModel)
    requires
        ntt_contract_accepts(input),
    ensures
        validated_ntt_dispatch(input).family is Ntt,
        validated_ntt_dispatch(input).read_regions[0].elements == input.height * input.width,
        validated_ntt_dispatch(input).write_regions[0].elements == input.height * input.width,
{
    ntt_accepts_implies_validated_surface(input);
}

}
