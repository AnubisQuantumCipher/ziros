use vstd::prelude::*;

verus! {

pub open spec fn compact_constraint_lowering_boundary(
    source_constraint_opcode_count: nat,
    public_alias_constraint_count: nat,
    structural_constraint_count: nat,
    emitted_constraint_count: nat,
    silently_dropped_constraint_opcode_count: nat,
) -> bool {
    silently_dropped_constraint_opcode_count == 0
        && emitted_constraint_count
            == source_constraint_opcode_count
                + public_alias_constraint_count
                + structural_constraint_count
}

pub open spec fn compact_signal_visibility_boundary(
    private_signal_count: nat,
    preserved_private_signal_count: nat,
    explicit_public_alias_count: nat,
    materialized_public_signal_count: nat,
) -> bool {
    private_signal_count == preserved_private_signal_count
        && explicit_public_alias_count == materialized_public_signal_count
}

pub open spec fn compact_disclose_transcript_boundary(
    transcript_entry_count: nat,
    disclosed_signal_count: nat,
    emitted_public_alias_count: nat,
) -> bool {
    transcript_entry_count == disclosed_signal_count
        && transcript_entry_count == emitted_public_alias_count
}

pub proof fn compact_import_preserves_constraint_count_ok(
    source_constraint_opcode_count: nat,
    public_alias_constraint_count: nat,
    structural_constraint_count: nat,
    emitted_constraint_count: nat,
    silently_dropped_constraint_opcode_count: nat,
)
    requires
        compact_constraint_lowering_boundary(
            source_constraint_opcode_count,
            public_alias_constraint_count,
            structural_constraint_count,
            emitted_constraint_count,
            silently_dropped_constraint_opcode_count,
        ),
    ensures
        silently_dropped_constraint_opcode_count == 0,
        emitted_constraint_count
            == source_constraint_opcode_count
                + public_alias_constraint_count
                + structural_constraint_count,
{
}

pub proof fn compact_import_preserves_signal_visibility_ok(
    private_signal_count: nat,
    preserved_private_signal_count: nat,
    explicit_public_alias_count: nat,
    materialized_public_signal_count: nat,
)
    requires
        compact_signal_visibility_boundary(
            private_signal_count,
            preserved_private_signal_count,
            explicit_public_alias_count,
            materialized_public_signal_count,
        ),
    ensures
        private_signal_count == preserved_private_signal_count,
        explicit_public_alias_count == materialized_public_signal_count,
{
}

pub proof fn compact_disclose_transcript_preserved_ok(
    transcript_entry_count: nat,
    disclosed_signal_count: nat,
    emitted_public_alias_count: nat,
)
    requires
        compact_disclose_transcript_boundary(
            transcript_entry_count,
            disclosed_signal_count,
            emitted_public_alias_count,
        ),
    ensures
        transcript_entry_count == disclosed_signal_count,
        transcript_entry_count == emitted_public_alias_count,
{
}

} // verus!
