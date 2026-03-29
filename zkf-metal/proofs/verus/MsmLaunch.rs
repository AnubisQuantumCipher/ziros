mod LaunchContracts;

use vstd::prelude::*;
use LaunchContracts::*;

verus! {

pub proof fn msm_launch_surface_ok(input: MsmContractInputModel)
    requires
        msm_contract_accepts(input),
    ensures
        validated_msm_dispatch(input).family is Msm,
        validated_msm_dispatch(input).read_regions[3].elements == input.map_entries,
        validated_msm_dispatch(input).write_regions[0].elements == input.bucket_entries,
{
    msm_accepts_implies_validated_surface(input);
}

pub proof fn certified_bn254_surface_excludes_hybrid_and_full_gpu()
    ensures
        certified_bn254_route_ok(MsmRouteModel::Classic),
        !certified_bn254_route_ok(MsmRouteModel::Hybrid),
        !certified_bn254_route_ok(MsmRouteModel::FullGpu),
        !certified_bn254_route_ok(MsmRouteModel::Tensor),
{
}

}
