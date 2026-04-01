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
