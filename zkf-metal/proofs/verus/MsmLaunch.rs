// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

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
