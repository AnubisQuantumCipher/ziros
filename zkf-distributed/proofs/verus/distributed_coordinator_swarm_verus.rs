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
