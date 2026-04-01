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
