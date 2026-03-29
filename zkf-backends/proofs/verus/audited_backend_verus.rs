use vstd::prelude::*;
use vstd::seq::*;

verus! {

/// Shell-contract model for the audited backend retention branch.
///
/// The theorem below only characterizes the public retention boundary:
/// when the source and compiled digests differ, the audited backend keeps
/// the original program attached to the compiled artifact.
pub open spec fn audited_compile_retains_original_on_digest_mismatch(
    retained_original_program: bool,
    source_digest: Seq<u8>,
    compiled_digest: Seq<u8>,
) -> bool {
    retained_original_program == (source_digest != compiled_digest)
}

pub proof fn audited_compile_retains_original_on_digest_mismatch_ok(
    source_digest: Seq<u8>,
    compiled_digest: Seq<u8>,
)
    ensures
        audited_compile_retains_original_on_digest_mismatch(
            source_digest != compiled_digest,
            source_digest,
            compiled_digest,
        ),
{
}

} // verus!
