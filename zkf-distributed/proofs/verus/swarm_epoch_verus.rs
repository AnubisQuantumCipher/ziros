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

pub open spec fn has_plaintext_threat_surface(
    digest_count: nat,
    activation_level_present: bool,
    intelligence_root_present: bool,
    local_pressure_present: bool,
    network_pressure_present: bool,
) -> bool {
    digest_count > 0
        || activation_level_present
        || intelligence_root_present
        || local_pressure_present
        || network_pressure_present
}

pub open spec fn encrypted_gossip_negotiated(
    local_support: bool,
    remote_support: bool,
    remote_epoch_keys_present: bool,
) -> bool {
    local_support && remote_support && remote_epoch_keys_present
}

pub proof fn swarm_epoch_negotiation_fail_closed(
    digest_count: nat,
    activation_level_present: bool,
    intelligence_root_present: bool,
    local_pressure_present: bool,
    network_pressure_present: bool,
)
    ensures
        encrypted_gossip_negotiated(true, true, true),
        !encrypted_gossip_negotiated(true, true, false),
        !has_plaintext_threat_surface(0, false, false, false, false),
        digest_count > 0
            || activation_level_present
            || intelligence_root_present
            || local_pressure_present
            || network_pressure_present
            ==> has_plaintext_threat_surface(
                digest_count,
                activation_level_present,
                intelligence_root_present,
                local_pressure_present,
                network_pressure_present,
            ),
{
}

} // verus!
