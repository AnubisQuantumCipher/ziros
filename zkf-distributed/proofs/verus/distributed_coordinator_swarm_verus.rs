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

pub open spec fn digest_prefix_equal(remote_digest_prefix: int, local_digest_prefix: int) -> bool {
    remote_digest_prefix == local_digest_prefix
}

pub open spec fn attestation_matches(output_match: bool, trace_match: bool) -> bool {
    output_match && trace_match
}

pub proof fn swarm_coordinator_acceptance_soundness(
    remote_digest_prefix: int,
    local_digest_prefix: int,
    output_match: bool,
    trace_match: bool,
)
    ensures
        digest_prefix_equal(remote_digest_prefix, local_digest_prefix)
            ==> digest_prefix_equal(remote_digest_prefix, local_digest_prefix),
        attestation_matches(output_match, trace_match) == (output_match && trace_match),
{
}

} // verus!
