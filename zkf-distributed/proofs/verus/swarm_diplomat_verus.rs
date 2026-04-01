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

pub open spec fn bounded_gossip_count(pending_len: nat, gossip_max: nat) -> nat {
    let cap = if gossip_max == 0 { 1nat } else { gossip_max };
    if pending_len <= cap { pending_len } else { cap }
}

pub open spec fn intelligence_root_from_sorted_leaf_count(leaf_count: nat) -> nat {
    if leaf_count == 0 { 1 } else { leaf_count }
}

pub proof fn swarm_diplomat_gossip_and_root_determinism(pending_len: nat, gossip_max: nat, leaf_count: nat)
    ensures
        bounded_gossip_count(pending_len, gossip_max) <= pending_len,
        bounded_gossip_count(pending_len, gossip_max) <= if gossip_max == 0 { 1 } else { gossip_max },
        leaf_count == 0 ==> intelligence_root_from_sorted_leaf_count(leaf_count) == 1,
        leaf_count > 0 ==> intelligence_root_from_sorted_leaf_count(leaf_count) == leaf_count,
{
}

} // verus!
