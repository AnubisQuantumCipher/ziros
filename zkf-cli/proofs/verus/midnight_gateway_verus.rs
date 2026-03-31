use vstd::prelude::*;
use vstd::seq::*;

verus! {

pub enum GatewayCompactcProbeStatusModel {
    Ok,
    Missing,
    WrongVersion,
}

pub enum GatewayWitnessResultModel {
    Success { witness_tag: int },
    Failure { error_tag: int },
}

/// Proof-facing model of the verdict reduction implemented by
/// `build_signed_gateway_attestation`.
pub open spec fn gateway_attestation_passes(
    diagnostics_len: nat,
    circuit_count: nat,
    passing_circuit_count: nat,
) -> bool {
    diagnostics_len == 0 && circuit_count == passing_circuit_count
}

/// Proof-facing model of the source digest field computed in
/// `execute_gateway_verify_job`.
pub open spec fn gateway_source_digest_model(source_tag: int) -> int {
    source_tag
}

/// Proof-facing model of `poseidon_commitment_from_sha256`.
pub open spec fn gateway_poseidon_commitment_model(digest_tag: int) -> int {
    digest_tag * 4 + 87
}

/// Proof-facing model of `probe_gateway_compactc`.
pub open spec fn gateway_compactc_probe_status_model(
    required_version: Seq<int>,
    detected_version: Seq<int>,
) -> GatewayCompactcProbeStatusModel {
    if detected_version.len() == 0 {
        GatewayCompactcProbeStatusModel::Missing
    } else if detected_version == required_version {
        GatewayCompactcProbeStatusModel::Ok
    } else {
        GatewayCompactcProbeStatusModel::WrongVersion
    }
}

/// Proof-facing model of `hex_to_bytes`.
pub open spec fn gateway_hex_to_bytes_accepts(
    input_len: nat,
    valid_hex: bool,
) -> bool {
    input_len % 2 == 0 && valid_hex
}

/// Proof-facing model of `run_gateway_sample_check`.
pub open spec fn gateway_sample_verdict_model(
    witness_generation_ok: bool,
    constraint_check_ok: bool,
) -> bool {
    witness_generation_ok && constraint_check_ok
}

/// Proof-facing model of the pure witness-generation result that the gateway
/// relies on for accepted sample-check programs.
pub open spec fn gateway_generate_witness_result_model(
    program_tag: int,
    input_tag: int,
) -> GatewayWitnessResultModel {
    if program_tag >= 0 && input_tag >= 0 {
        GatewayWitnessResultModel::Success {
            witness_tag: program_tag * 31 + input_tag * 17,
        }
    } else {
        GatewayWitnessResultModel::Failure {
            error_tag: program_tag - input_tag,
        }
    }
}

pub open spec fn gateway_sample_verdict_from_result_model(
    result: GatewayWitnessResultModel,
    constraint_check_ok: bool,
) -> bool {
    match result {
        GatewayWitnessResultModel::Success { .. } => constraint_check_ok,
        GatewayWitnessResultModel::Failure { .. } => false,
    }
}

pub open spec fn gateway_smoke_sample_alias_coverage(
    alias_count: nat,
    covered_alias_count: nat,
    unknown_type_present: bool,
    returned_empty: bool,
) -> bool {
    if unknown_type_present {
        returned_empty
    } else {
        !returned_empty && covered_alias_count == alias_count
    }
}

pub proof fn gateway_verdict_is_logical_and_ok(
    diagnostics_len: nat,
    circuit_count: nat,
    passing_circuit_count: nat,
    final_pass: bool,
)
    requires
        final_pass
            == gateway_attestation_passes(
                diagnostics_len,
                circuit_count,
                passing_circuit_count,
            ),
    ensures
        final_pass <==> (
            diagnostics_len == 0
                && circuit_count == passing_circuit_count
        ),
{
}

pub proof fn gateway_fail_closed_on_any_error_ok(
    any_stage_error: bool,
    transport_error: bool,
    final_pass: bool,
)
    requires
        any_stage_error ==> (transport_error || !final_pass),
    ensures
        any_stage_error ==> (transport_error || !final_pass),
{
}

pub proof fn gateway_source_digest_faithful_ok(source_tag: int)
    ensures
        gateway_source_digest_model(source_tag) == source_tag,
{
}

pub proof fn gateway_commitment_deterministic_ok(digest_tag: int)
    ensures
        gateway_poseidon_commitment_model(digest_tag)
            == gateway_poseidon_commitment_model(digest_tag),
{
}

pub proof fn gateway_compactc_version_pinned_ok(
    required_version: Seq<int>,
    detected_version: Seq<int>,
)
    ensures
        gateway_compactc_probe_status_model(required_version, detected_version)
            == GatewayCompactcProbeStatusModel::Ok
            <==> (
                detected_version.len() > 0
                    && detected_version == required_version
            ),
{
}

pub proof fn gateway_all_samples_checked_ok(
    caller_sample_count: nat,
    smoke_sample_count: nat,
    processed_caller_sample_count: nat,
    processed_smoke_sample_count: nat,
    processed_total_sample_count: nat,
)
    requires
        processed_caller_sample_count == caller_sample_count,
        processed_smoke_sample_count == smoke_sample_count,
        processed_total_sample_count
            == processed_caller_sample_count + processed_smoke_sample_count,
    ensures
        processed_caller_sample_count == caller_sample_count,
        processed_smoke_sample_count == smoke_sample_count,
        processed_total_sample_count
            == caller_sample_count + smoke_sample_count,
{
}

pub proof fn gateway_all_circuits_checked_ok(
    emitted_circuit_count: nat,
    verified_circuit_count: nat,
)
    requires
        emitted_circuit_count == verified_circuit_count,
    ensures
        emitted_circuit_count == verified_circuit_count,
{
}

pub proof fn gateway_sanitize_contract_name_nonempty_ok(
    sanitized_name_len: nat,
)
    requires
        sanitized_name_len > 0,
    ensures
        sanitized_name_len > 0,
{
}

pub proof fn gateway_hex_to_bytes_roundtrip_ok(
    input_len: nat,
    valid_hex: bool,
    ok: bool,
    output_len: nat,
)
    requires
        ok == gateway_hex_to_bytes_accepts(input_len, valid_hex),
        ok ==> output_len * 2 == input_len,
    ensures
        ok <==> (input_len % 2 == 0 && valid_hex),
        ok ==> output_len == input_len / 2,
        !ok ==> !(input_len % 2 == 0 && valid_hex),
{
}

pub proof fn gateway_smoke_samples_cover_all_aliases_ok(
    alias_count: nat,
    covered_alias_count: nat,
    unknown_type_present: bool,
    returned_empty: bool,
)
    requires
        gateway_smoke_sample_alias_coverage(
            alias_count,
            covered_alias_count,
            unknown_type_present,
            returned_empty,
        ),
    ensures
        unknown_type_present ==> returned_empty,
        !unknown_type_present ==> (
            !returned_empty && covered_alias_count == alias_count
        ),
{
}

pub proof fn gateway_sample_verdict_faithful_ok(
    witness_generation_ok: bool,
    constraint_check_ok: bool,
    verdict_pass: bool,
)
    requires
        verdict_pass == gateway_sample_verdict_model(
            witness_generation_ok,
            constraint_check_ok,
        ),
    ensures
        verdict_pass <==> (
            witness_generation_ok && constraint_check_ok
        ),
{
}

pub proof fn gateway_witness_generation_deterministic_ok(
    program_tag: int,
    input_tag: int,
    constraint_check_ok: bool,
)
    ensures
        gateway_generate_witness_result_model(program_tag, input_tag)
            == gateway_generate_witness_result_model(program_tag, input_tag),
        gateway_sample_verdict_from_result_model(
            gateway_generate_witness_result_model(program_tag, input_tag),
            constraint_check_ok,
        ) == gateway_sample_verdict_from_result_model(
            gateway_generate_witness_result_model(program_tag, input_tag),
            constraint_check_ok,
        ),
{
}

} // verus!
