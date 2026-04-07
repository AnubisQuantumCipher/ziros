#[path = "midnight_gateway_verus.rs"]
mod midnight_gateway_verus;
#[path = "../../../zkf-core/proofs/verus/audit_pipeline_verus.rs"]
mod audit_pipeline_verus;
#[path = "../../../zkf-frontends/proofs/verus/compact_import_verus.rs"]
mod compact_import_verus;

use vstd::prelude::*;
use vstd::seq::*;

verus! {

pub open spec fn gateway_submission_reproducible(
    program_tag: int,
    input_tag: int,
    constraint_check_ok: bool,
) -> bool {
    midnight_gateway_verus::gateway_sample_verdict_from_result_model(
        midnight_gateway_verus::gateway_generate_witness_result_model(
            program_tag,
            input_tag,
        ),
        constraint_check_ok,
    ) == midnight_gateway_verus::gateway_sample_verdict_from_result_model(
        midnight_gateway_verus::gateway_generate_witness_result_model(
            program_tag,
            input_tag,
        ),
        constraint_check_ok,
    )
}

pub proof fn gateway_end_to_end_safety_ok(
    diagnostics_len: nat,
    circuit_count: nat,
    passing_circuit_count: nat,
    any_stage_error: bool,
    transport_error: bool,
    source_tag: int,
    required_version: Seq<int>,
    detected_version: Seq<int>,
    caller_sample_count: nat,
    smoke_sample_count: nat,
    processed_caller_sample_count: nat,
    processed_smoke_sample_count: nat,
    processed_total_sample_count: nat,
    emitted_circuit_count: nat,
    verified_circuit_count: nat,
    sanitized_name_len: nat,
    hex_input_len: nat,
    valid_hex: bool,
    hex_ok: bool,
    hex_output_len: nat,
    alias_count: nat,
    covered_alias_count: nat,
    unknown_type_present: bool,
    returned_empty: bool,
    witness_generation_ok: bool,
    constraint_check_ok: bool,
    sample_verdict_pass: bool,
    program_tag: int,
    input_tag: int,
    total_constraints: nat,
    visited_constraints: nat,
    private_signal_count: nat,
    classified_private_signal_count: nat,
    has_failure: bool,
    first_failing_constraint_index: nat,
    checked_constraint_count: nat,
    checker_result_ok: bool,
    total_checks: nat,
    passed_checks: nat,
    warned_checks: nat,
    failed_checks: nat,
    skipped_checks: nat,
    source_constraint_opcode_count: nat,
    public_alias_constraint_count: nat,
    structural_constraint_count: nat,
    emitted_constraint_count: nat,
    silently_dropped_constraint_opcode_count: nat,
    preserved_private_signal_count: nat,
    explicit_public_alias_count: nat,
    materialized_public_signal_count: nat,
    transcript_entry_count: nat,
    disclosed_signal_count: nat,
    emitted_public_alias_count: nat,
)
    requires
        !any_stage_error,
        midnight_gateway_verus::gateway_attestation_passes(
            diagnostics_len,
            circuit_count,
            passing_circuit_count,
        ),
        transport_error == false,
        detected_version == required_version,
        processed_caller_sample_count == caller_sample_count,
        processed_smoke_sample_count == smoke_sample_count,
        processed_total_sample_count
            == processed_caller_sample_count + processed_smoke_sample_count,
        emitted_circuit_count == verified_circuit_count,
        sanitized_name_len > 0,
        hex_ok
            == midnight_gateway_verus::gateway_hex_to_bytes_accepts(
                hex_input_len,
                valid_hex,
            ),
        hex_ok ==> hex_output_len * 2 == hex_input_len,
        midnight_gateway_verus::gateway_smoke_sample_alias_coverage(
            alias_count,
            covered_alias_count,
            unknown_type_present,
            returned_empty,
        ),
        sample_verdict_pass
            == midnight_gateway_verus::gateway_sample_verdict_model(
                witness_generation_ok,
                constraint_check_ok,
            ),
        audit_pipeline_verus::audit_underconstrained_boundary(
            total_constraints,
            visited_constraints,
            private_signal_count,
            classified_private_signal_count,
        ),
        audit_pipeline_verus::audit_constraint_checker_boundary(
            total_constraints,
            has_failure,
            first_failing_constraint_index,
            checked_constraint_count,
            checker_result_ok,
        ),
        audit_pipeline_verus::audit_report_aggregation_boundary(
            total_checks,
            passed_checks,
            warned_checks,
            failed_checks,
            skipped_checks,
        ),
        compact_import_verus::compact_constraint_lowering_boundary(
            source_constraint_opcode_count,
            public_alias_constraint_count,
            structural_constraint_count,
            emitted_constraint_count,
            silently_dropped_constraint_opcode_count,
        ),
        compact_import_verus::compact_signal_visibility_boundary(
            private_signal_count,
            preserved_private_signal_count,
            explicit_public_alias_count,
            materialized_public_signal_count,
        ),
        compact_import_verus::compact_disclose_transcript_boundary(
            transcript_entry_count,
            disclosed_signal_count,
            emitted_public_alias_count,
        ),
    ensures
        detected_version == required_version,
        !transport_error,
        visited_constraints == total_constraints,
        classified_private_signal_count == private_signal_count,
        processed_total_sample_count
            == caller_sample_count + smoke_sample_count,
        emitted_circuit_count == verified_circuit_count,
        midnight_gateway_verus::gateway_source_digest_model(source_tag) == source_tag,
        gateway_submission_reproducible(
            program_tag,
            input_tag,
            constraint_check_ok,
        ),
        sample_verdict_pass <==> (
            witness_generation_ok && constraint_check_ok
        ),
        passed_checks + warned_checks + failed_checks + skipped_checks == total_checks,
        silently_dropped_constraint_opcode_count == 0,
        transcript_entry_count == disclosed_signal_count,
{
    midnight_gateway_verus::gateway_verdict_is_logical_and_ok(
        diagnostics_len,
        circuit_count,
        passing_circuit_count,
        midnight_gateway_verus::gateway_attestation_passes(
            diagnostics_len,
            circuit_count,
            passing_circuit_count,
        ),
    );
    midnight_gateway_verus::gateway_fail_closed_on_any_error_ok(
        any_stage_error,
        transport_error,
        midnight_gateway_verus::gateway_attestation_passes(
            diagnostics_len,
            circuit_count,
            passing_circuit_count,
        ),
    );
    midnight_gateway_verus::gateway_source_digest_faithful_ok(source_tag);
    midnight_gateway_verus::gateway_commitment_deterministic_ok(source_tag);
    midnight_gateway_verus::gateway_compactc_version_pinned_ok(
        required_version,
        detected_version,
    );
    midnight_gateway_verus::gateway_all_samples_checked_ok(
        caller_sample_count,
        smoke_sample_count,
        processed_caller_sample_count,
        processed_smoke_sample_count,
        processed_total_sample_count,
    );
    midnight_gateway_verus::gateway_all_circuits_checked_ok(
        emitted_circuit_count,
        verified_circuit_count,
    );
    midnight_gateway_verus::gateway_sanitize_contract_name_nonempty_ok(
        sanitized_name_len,
    );
    midnight_gateway_verus::gateway_hex_to_bytes_roundtrip_ok(
        hex_input_len,
        valid_hex,
        hex_ok,
        hex_output_len,
    );
    midnight_gateway_verus::gateway_smoke_samples_cover_all_aliases_ok(
        alias_count,
        covered_alias_count,
        unknown_type_present,
        returned_empty,
    );
    midnight_gateway_verus::gateway_sample_verdict_faithful_ok(
        witness_generation_ok,
        constraint_check_ok,
        sample_verdict_pass,
    );
    midnight_gateway_verus::gateway_witness_generation_deterministic_ok(
        program_tag,
        input_tag,
        constraint_check_ok,
    );
    audit_pipeline_verus::audit_underconstrained_detection_complete_ok(
        total_constraints,
        visited_constraints,
        private_signal_count,
        classified_private_signal_count,
    );
    audit_pipeline_verus::audit_constraint_checker_evaluates_all_ok(
        total_constraints,
        has_failure,
        first_failing_constraint_index,
        checked_constraint_count,
        checker_result_ok,
    );
    audit_pipeline_verus::audit_report_aggregation_correct_ok(
        total_checks,
        passed_checks,
        warned_checks,
        failed_checks,
        skipped_checks,
    );
    compact_import_verus::compact_import_preserves_constraint_count_ok(
        source_constraint_opcode_count,
        public_alias_constraint_count,
        structural_constraint_count,
        emitted_constraint_count,
        silently_dropped_constraint_opcode_count,
    );
    compact_import_verus::compact_import_preserves_signal_visibility_ok(
        private_signal_count,
        preserved_private_signal_count,
        explicit_public_alias_count,
        materialized_public_signal_count,
    );
    compact_import_verus::compact_disclose_transcript_preserved_ok(
        transcript_entry_count,
        disclosed_signal_count,
        emitted_public_alias_count,
    );
}

} // verus!
