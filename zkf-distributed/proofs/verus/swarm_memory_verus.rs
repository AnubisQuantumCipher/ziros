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
