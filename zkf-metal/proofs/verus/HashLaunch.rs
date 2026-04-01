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
