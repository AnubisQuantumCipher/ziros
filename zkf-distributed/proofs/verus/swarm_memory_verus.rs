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

pub open spec fn attestation_signing_bytes_len(job_id_len: nat) -> nat {
    job_id_len + 4 + 32 + 32 + 1
}

pub open spec fn append_only_chain_head_stable(previous_head: int, imported_head: int) -> bool {
    previous_head == imported_head
}

pub proof fn swarm_memory_append_only_identity(job_id_len: nat, previous_head: int, imported_head: int)
    ensures
        attestation_signing_bytes_len(job_id_len) >= job_id_len,
        previous_head == imported_head ==> append_only_chain_head_stable(previous_head, imported_head),
{
}

} // verus!
