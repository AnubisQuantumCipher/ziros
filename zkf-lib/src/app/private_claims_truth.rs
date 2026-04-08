#![cfg_attr(not(test), allow(dead_code))]

use num_bigint::BigInt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zkf_backends::blackbox_gadgets::poseidon2_permutation_native;
#[cfg(test)]
use zkf_backends::prepare_witness_for_proving;
#[cfg(test)]
use zkf_core::check_constraints;
use zkf_core::{
    BigIntFieldValue, Expr, FieldElement, FieldId, FieldValue, Program, Witness, WitnessInputs, ZkfError,
    ZkfResult,
    generate_witness,
};

use super::builder::ProgramBuilder;
use super::templates::TemplateProgram;

pub const PRIVATE_CLAIMS_MAX_LINE_ITEMS: usize = 4;
pub const PRIVATE_CLAIMS_MAX_DIGESTS: usize = 4;
pub const PRIVATE_CLAIMS_MAX_PERILS: usize = 4;
pub const PRIVATE_CLAIMS_PUBLIC_OUTPUTS: usize = 10;
pub const CLAIMS_FIXED_POINT_SCALE: u64 = 10_000;

const CLAIMS_FIELD: FieldId = FieldId::PastaFq;
const CLAIMS_ACTION_APPROVE_AND_SETTLE: u64 = 0;
const CLAIMS_ACTION_APPROVE_WITH_MANUAL_REVIEW: u64 = 1;
const CLAIMS_ACTION_ESCALATE_FOR_INVESTIGATION: u64 = 2;
const CLAIMS_ACTION_DENY_FOR_POLICY_RULE: u64 = 3;
const CLAIMS_ACTION_DENY_FOR_INCONSISTENCY: u64 = 4;
const CLAIMS_DOMAIN_COVERAGE: i64 = 1101;
const CLAIMS_DOMAIN_CONSISTENCY: i64 = 1102;
const CLAIMS_DOMAIN_FRAUD: i64 = 1103;
const CLAIMS_DOMAIN_PAYOUT: i64 = 1104;
const CLAIMS_DOMAIN_RESERVE: i64 = 1105;
const CLAIMS_DOMAIN_SETTLEMENT: i64 = 1106;
const CLAIMS_DOMAIN_DISCLOSURE: i64 = 1107;
const CLAIMS_DOMAIN_SHARD_BATCH: i64 = 1108;
const CLAIMS_SCORE_CAP: u64 = 10_000;
const CLAIMS_COMPONENT_SCORE_CAP: u64 = 4_000;
const CLAIMS_UINT_BOUND: u64 = 4_000_000_000;
const CLAIMS_TIMESTAMP_BOUND: u64 = 4_000_000_000;
const CLAIMS_HASH_BOUND: u64 = 18_000_000_000_000_000_000;
const CLAIMS_SIGNED_MARGIN_OFFSET: u64 = 100_000_000;
const CLAIMS_SIGNED_MARGIN_BOUND: u64 = 200_000_000;
const CLAIMS_VALUE_BOUND: u64 = 100_000_000;
const CLAIMS_RATIO_BOUND: u64 = 10_000_000;
const CLAIMS_SHARD_COUNT_MAX: u64 = 4;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthPolicyDataV1 {
    pub policy_id_hash: u64,
    pub policy_effective_timestamp: u64,
    pub policy_expiration_timestamp: u64,
    pub covered_peril_flags: [u64; PRIVATE_CLAIMS_MAX_PERILS],
    pub exclusion_flags: [u64; PRIVATE_CLAIMS_MAX_PERILS],
    pub deductible_schedule: [u64; 2],
    pub payout_cap_schedule: [u64; 2],
    pub depreciation_rules: [u64; 2],
    pub reserve_policy_parameters: [u64; 2],
    pub reinsurer_sharing_parameters: [u64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthClaimEventDataV1 {
    pub claim_id_hash: u64,
    pub claimant_id_hash: u64,
    pub incident_timestamp: u64,
    pub reported_timestamp: u64,
    pub event_region_bucket: u64,
    pub peril_classification_flags: [u64; PRIVATE_CLAIMS_MAX_PERILS],
    pub damaged_asset_class: u64,
    pub claimed_loss_categories: [u64; PRIVATE_CLAIMS_MAX_PERILS],
    pub prior_claim_linkage_hashes: [u64; PRIVATE_CLAIMS_MAX_DIGESTS],
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthEstimateLineItemV1 {
    pub quantity: u64,
    pub unit_amount: u64,
    pub replacement_cost: u64,
    pub depreciation_basis: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthInvoiceLineItemV1 {
    pub quantity: u64,
    pub invoice_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthEvidenceDataV1 {
    pub repair_estimate_line_items:
        [ClaimsTruthEstimateLineItemV1; PRIVATE_CLAIMS_MAX_LINE_ITEMS],
    pub invoice_line_items: [ClaimsTruthInvoiceLineItemV1; PRIVATE_CLAIMS_MAX_LINE_ITEMS],
    pub replacement_cost_schedules: [u64; PRIVATE_CLAIMS_MAX_LINE_ITEMS],
    pub depreciation_basis_values: [u64; PRIVATE_CLAIMS_MAX_LINE_ITEMS],
    pub telematics_structured_event_summary_values: [u64; PRIVATE_CLAIMS_MAX_DIGESTS],
    pub vendor_attestation_digests: [u64; PRIVATE_CLAIMS_MAX_DIGESTS],
    pub photo_analysis_result_digest: u64,
    pub document_extraction_result_digest: u64,
    pub authority_report_reference_digest: u64,
    pub evidence_manifest_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthConsistencyFraudInputsV1 {
    pub duplicate_claim_candidate_hashes: [u64; PRIVATE_CLAIMS_MAX_DIGESTS],
    pub price_deviation_baselines: [u64; PRIVATE_CLAIMS_MAX_DIGESTS],
    pub vendor_anomaly_baselines: [u64; PRIVATE_CLAIMS_MAX_DIGESTS],
    pub chronology_consistency_threshold: u64,
    pub geographic_reasonableness_threshold: u64,
    pub quantity_tolerance_threshold: u64,
    pub valuation_tolerance_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthSettlementGovernanceInputsV1 {
    pub claimant_payout_destination_commitment: u64,
    pub insurer_reserve_account_commitment: u64,
    pub reinsurer_participation_commitment: u64,
    pub dispute_escalation_threshold: u64,
    pub fraud_review_threshold: u64,
    pub manual_review_threshold: u64,
    pub settlement_blinding_values: [u64; 2],
    pub public_disclosure_blinding_values: [u64; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthPrivateInputsV1 {
    pub policy: ClaimsTruthPolicyDataV1,
    pub claim_event: ClaimsTruthClaimEventDataV1,
    pub evidence: ClaimsTruthEvidenceDataV1,
    pub analysis_inputs: ClaimsTruthConsistencyFraudInputsV1,
    pub settlement_governance: ClaimsTruthSettlementGovernanceInputsV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimsActionClassV1 {
    ApproveAndSettle,
    ApproveWithManualReview,
    EscalateForInvestigation,
    DenyForPolicyRule,
    DenyForInconsistency,
}

impl ClaimsActionClassV1 {
    pub fn code(self) -> u64 {
        match self {
            Self::ApproveAndSettle => CLAIMS_ACTION_APPROVE_AND_SETTLE,
            Self::ApproveWithManualReview => CLAIMS_ACTION_APPROVE_WITH_MANUAL_REVIEW,
            Self::EscalateForInvestigation => CLAIMS_ACTION_ESCALATE_FOR_INVESTIGATION,
            Self::DenyForPolicyRule => CLAIMS_ACTION_DENY_FOR_POLICY_RULE,
            Self::DenyForInconsistency => CLAIMS_ACTION_DENY_FOR_INCONSISTENCY,
        }
    }

    pub fn from_code(code: u64) -> ZkfResult<Self> {
        match code {
            CLAIMS_ACTION_APPROVE_AND_SETTLE => Ok(Self::ApproveAndSettle),
            CLAIMS_ACTION_APPROVE_WITH_MANUAL_REVIEW => Ok(Self::ApproveWithManualReview),
            CLAIMS_ACTION_ESCALATE_FOR_INVESTIGATION => Ok(Self::EscalateForInvestigation),
            CLAIMS_ACTION_DENY_FOR_POLICY_RULE => Ok(Self::DenyForPolicyRule),
            CLAIMS_ACTION_DENY_FOR_INCONSISTENCY => Ok(Self::DenyForInconsistency),
            other => Err(ZkfError::InvalidArtifact(format!(
                "unsupported claims action code {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClaimsTruthPublicOutputsV1 {
    pub claim_packet_commitment: String,
    pub coverage_decision_commitment: String,
    pub consistency_score_commitment: String,
    pub fraud_evidence_score_commitment: String,
    pub payout_amount_commitment: String,
    pub reserve_amount_commitment: String,
    pub settlement_instruction_commitment: String,
    pub action_class: ClaimsActionClassV1,
    pub human_review_required: bool,
    pub eligible_for_midnight_settlement: bool,
    pub proof_verification_result: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaimsCoreComputation {
    claim_packet_commitment: BigInt,
    evidence_manifest_digest: BigInt,
    coverage_decision_commitment: BigInt,
    consistency_score_commitment: BigInt,
    fraud_evidence_score_commitment: BigInt,
    payout_amount_commitment: BigInt,
    reserve_amount_commitment: BigInt,
    settlement_instruction_commitment: BigInt,
    policy_eligible: bool,
    within_period: bool,
    covered_peril_supported: bool,
    peril_excluded: bool,
    chronology_score: u64,
    valuation_score: u64,
    duplication_score: u64,
    vendor_score: u64,
    policy_mismatch_score: u64,
    evidence_completeness_score: u64,
    structured_inconsistency_score: u64,
    consistency_score: u64,
    fraud_evidence_score: u64,
    payout_amount: u64,
    reserve_amount: u64,
    reinsurer_share_amount: u64,
    report_delay: u64,
    total_estimate_amount: u64,
    total_invoice_amount: u64,
    total_replacement_amount: u64,
    total_valuation_gap: u64,
    total_quantity_gap: u64,
    duplicate_match_count: u64,
    action_class: ClaimsActionClassV1,
    human_review_required: bool,
    eligible_for_midnight_settlement: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaimsSettlementComputation {
    settlement_instruction_commitment: BigInt,
    dispute_hold_commitment: BigInt,
    reinsurer_release_commitment: BigInt,
    settlement_finality_flag: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaimsDisclosureComputation {
    role_code: u64,
    disclosure_view_commitment: BigInt,
    disclosed_value_a: BigInt,
    disclosed_value_b: BigInt,
}

#[derive(Debug, Clone)]
pub(crate) struct ClaimsShardComputation {
    batch_root_commitment: BigInt,
    assignment_commitment: BigInt,
}

fn zero() -> BigInt {
    BigInt::from(0u8)
}

fn one() -> BigInt {
    BigInt::from(1u8)
}

fn field(value: impl Into<BigInt>) -> FieldElement {
    FieldElement::from_bigint(value.into())
}

fn const_expr(value: impl Into<BigInt>) -> Expr {
    Expr::Const(field(value))
}

fn signal_expr(name: &str) -> Expr {
    Expr::signal(name)
}

fn add_expr(values: Vec<Expr>) -> Expr {
    if values.len() == 1 {
        values.into_iter().next().unwrap_or_else(|| const_expr(0))
    } else {
        Expr::Add(values)
    }
}

fn sub_expr(left: Expr, right: Expr) -> Expr {
    Expr::Sub(Box::new(left), Box::new(right))
}

fn mul_expr(left: Expr, right: Expr) -> Expr {
    Expr::Mul(Box::new(left), Box::new(right))
}

fn select_expr(selector: Expr, when_true: Expr, when_false: Expr) -> Expr {
    add_expr(vec![
        mul_expr(selector.clone(), when_true),
        mul_expr(sub_expr(const_expr(1), selector), when_false),
    ])
}

fn bits_for_bound(bound: u64) -> u32 {
    BigInt::from(bound).to_str_radix(2).len() as u32
}

fn hash_state_names(prefix: &str) -> [String; 4] {
    [
        format!("{prefix}_poseidon_state_0"),
        format!("{prefix}_poseidon_state_1"),
        format!("{prefix}_poseidon_state_2"),
        format!("{prefix}_poseidon_state_3"),
    ]
}

fn poseidon_permutation4(inputs: [&BigInt; 4]) -> ZkfResult<[FieldElement; 4]> {
    let params = BTreeMap::from([("width".to_string(), "4".to_string())]);
    let lanes = poseidon2_permutation_native(
        &inputs.into_iter().cloned().collect::<Vec<_>>(),
        &params,
        CLAIMS_FIELD,
    )
    .map_err(ZkfError::Backend)?;
    if lanes.len() != 4 {
        return Err(ZkfError::Backend(format!(
            "claims poseidon permutation returned {} lanes instead of 4",
            lanes.len()
        )));
    }
    Ok([
        field(lanes[0].clone()),
        field(lanes[1].clone()),
        field(lanes[2].clone()),
        field(lanes[3].clone()),
    ])
}

fn write_hash_lanes(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    lanes: [FieldElement; 4],
) -> BigInt {
    let names = hash_state_names(prefix);
    for (name, lane) in names.iter().zip(lanes) {
        values.insert(name.clone(), lane);
    }
    values
        .get(&names[0])
        .cloned()
        .unwrap_or(FieldElement::ZERO)
        .as_bigint()
}

fn write_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: impl Into<BigInt>,
) {
    values.insert(name.into(), field(value));
}

fn write_bool_value(values: &mut BTreeMap<String, FieldElement>, name: impl Into<String>, value: bool) {
    values.insert(
        name.into(),
        if value {
            FieldElement::ONE
        } else {
            FieldElement::ZERO
        },
    );
}

fn positive_comparison_offset(bound: u64) -> BigInt {
    BigInt::from(bound) + one()
}

fn comparator_slack(lhs: &BigInt, rhs: &BigInt, offset: &BigInt) -> BigInt {
    if lhs >= rhs {
        lhs - rhs
    } else {
        lhs - rhs + offset
    }
}

fn write_nonnegative_support(
    values: &mut BTreeMap<String, FieldElement>,
    signal_name: impl Into<String>,
    value: &BigInt,
    bound: u64,
    prefix: &str,
) -> ZkfResult<()> {
    let bound_bigint = BigInt::from(bound);
    if value < &zero() || value > &bound_bigint {
        return Err(ZkfError::InvalidArtifact(format!(
            "{prefix} expected a nonnegative value <= {bound}, got {}",
            value.to_str_radix(10),
        )));
    }
    values.insert(signal_name.into(), field(value.clone()));
    values.insert(
        format!("{prefix}_comparator_slack_nonnegative_bound_slack"),
        field(bound_bigint.clone() - value),
    );
    values.insert(
        format!("{prefix}_comparator_slack_nonnegative_bound_anchor"),
        field((bound_bigint.clone() - value) * (bound_bigint - value)),
    );
    Ok(())
}

fn write_geq_support(
    values: &mut BTreeMap<String, FieldElement>,
    bit_signal: &str,
    slack_signal: &str,
    lhs: &BigInt,
    rhs: &BigInt,
    bound: u64,
    prefix: &str,
) -> ZkfResult<bool> {
    let offset = positive_comparison_offset(bound);
    let bit = lhs >= rhs;
    let slack = comparator_slack(lhs, rhs, &offset);
    write_bool_value(values, bit_signal, bit);
    write_nonnegative_support(values, slack_signal, &slack, bound, prefix)?;
    Ok(bit)
}

fn write_equality_with_inverse_support(
    values: &mut BTreeMap<String, FieldElement>,
    lhs: &BigInt,
    rhs: &BigInt,
    prefix: &str,
) {
    let diff = lhs - rhs;
    let equal = lhs == rhs;
    write_bool_value(values, format!("{prefix}_eq"), equal);
    write_value(values, format!("{prefix}_diff"), diff.clone());
    let inv = if equal {
        FieldElement::ZERO
    } else {
        BigIntFieldValue::new(CLAIMS_FIELD, diff)
            .inv()
            .map(|value| value.to_field_element())
            .unwrap_or(FieldElement::ZERO)
    };
    values.insert(format!("{prefix}_inv"), inv);
}

fn write_poseidon_hash_support(
    values: &mut BTreeMap<String, FieldElement>,
    prefix: &str,
    inputs: [&BigInt; 4],
) -> ZkfResult<BigInt> {
    let digest = poseidon_permutation4(inputs)?;
    Ok(write_hash_lanes(values, prefix, digest))
}

fn append_geq_comparator_bit(
    builder: &mut ProgramBuilder,
    lhs: Expr,
    rhs: Expr,
    bit_signal: &str,
    slack_signal: &str,
    bound: u64,
    prefix: &str,
) -> ZkfResult<()> {
    let offset = positive_comparison_offset(bound);
    builder.private_signal(bit_signal)?;
    builder.constrain_boolean(bit_signal)?;
    builder.private_signal(slack_signal)?;
    builder.constrain_equal(
        add_expr(vec![lhs, const_expr(offset.clone())]),
        add_expr(vec![
            rhs,
            signal_expr(slack_signal),
            mul_expr(signal_expr(bit_signal), const_expr(offset)),
        ]),
    )?;
    builder.constrain_range(slack_signal, bits_for_bound(bound))?;
    builder.private_signal(&format!(
        "{prefix}_comparator_slack_nonnegative_bound_slack"
    ))?;
    builder.private_signal(&format!(
        "{prefix}_comparator_slack_nonnegative_bound_anchor"
    ))?;
    builder.constrain_equal(
        signal_expr(&format!(
            "{prefix}_comparator_slack_nonnegative_bound_anchor"
        )),
        mul_expr(
            signal_expr(&format!(
                "{prefix}_comparator_slack_nonnegative_bound_slack"
            )),
            signal_expr(&format!(
                "{prefix}_comparator_slack_nonnegative_bound_slack"
            )),
        ),
    )?;
    builder.constrain_equal(
        add_expr(vec![
            signal_expr(slack_signal),
            signal_expr(&format!(
                "{prefix}_comparator_slack_nonnegative_bound_slack"
            )),
        ]),
        const_expr(BigInt::from(bound)),
    )?;
    builder.constrain_range(
        &format!("{prefix}_comparator_slack_nonnegative_bound_slack"),
        bits_for_bound(bound),
    )?;
    Ok(())
}

fn append_pairwise_min_signal(
    builder: &mut ProgramBuilder,
    target: &str,
    left_signal: &str,
    right_signal: &str,
    bound: u64,
    prefix: &str,
) -> ZkfResult<()> {
    let bit_signal = format!("{prefix}_geq_bit");
    let slack_signal = format!("{prefix}_geq_slack");
    append_geq_comparator_bit(
        builder,
        signal_expr(left_signal),
        signal_expr(right_signal),
        &bit_signal,
        &slack_signal,
        bound,
        prefix,
    )?;
    builder.private_signal(target)?;
    builder.bind(
        target,
        select_expr(
            signal_expr(&bit_signal),
            signal_expr(right_signal),
            signal_expr(left_signal),
        ),
    )?;
    builder.constrain_range(target, bits_for_bound(bound))?;
    Ok(())
}

fn append_pairwise_max_signal(
    builder: &mut ProgramBuilder,
    target: &str,
    left_signal: &str,
    right_signal: &str,
    bound: u64,
    prefix: &str,
) -> ZkfResult<()> {
    let bit_signal = format!("{prefix}_geq_bit");
    let slack_signal = format!("{prefix}_geq_slack");
    append_geq_comparator_bit(
        builder,
        signal_expr(left_signal),
        signal_expr(right_signal),
        &bit_signal,
        &slack_signal,
        bound,
        prefix,
    )?;
    builder.private_signal(target)?;
    builder.bind(
        target,
        select_expr(
            signal_expr(&bit_signal),
            signal_expr(left_signal),
            signal_expr(right_signal),
        ),
    )?;
    builder.constrain_range(target, bits_for_bound(bound))?;
    Ok(())
}

fn append_boolean_and(
    builder: &mut ProgramBuilder,
    target: &str,
    left: Expr,
    right: Expr,
) -> ZkfResult<()> {
    builder.private_signal(target)?;
    builder.bind(target, mul_expr(left, right))?;
    builder.constrain_boolean(target)?;
    Ok(())
}

fn append_boolean_or(
    builder: &mut ProgramBuilder,
    target: &str,
    left: Expr,
    right: Expr,
) -> ZkfResult<()> {
    builder.private_signal(target)?;
    builder.bind(
        target,
        sub_expr(add_expr(vec![left.clone(), right.clone()]), mul_expr(left, right)),
    )?;
    builder.constrain_boolean(target)?;
    Ok(())
}

fn append_equality_with_inverse(
    builder: &mut ProgramBuilder,
    lhs: Expr,
    rhs: Expr,
    prefix: &str,
) -> ZkfResult<String> {
    let diff = format!("{prefix}_diff");
    let eq = format!("{prefix}_eq");
    let inv = format!("{prefix}_inv");
    builder.private_signal(&diff)?;
    builder.bind(&diff, sub_expr(lhs, rhs))?;
    builder.private_signal(&eq)?;
    builder.constrain_boolean(&eq)?;
    builder.private_signal(&inv)?;
    builder.constrain_equal(
        mul_expr(signal_expr(&diff), signal_expr(&eq)),
        const_expr(0),
    )?;
    builder.constrain_equal(
        sub_expr(const_expr(1), signal_expr(&eq)),
        mul_expr(signal_expr(&diff), signal_expr(&inv)),
    )?;
    Ok(eq)
}

fn append_nonzero_indicator(
    builder: &mut ProgramBuilder,
    target: &str,
    value: Expr,
    prefix: &str,
) -> ZkfResult<()> {
    let zero_eq = append_equality_with_inverse(builder, value, const_expr(0), &format!("{prefix}_zero"))?;
    builder.private_signal(target)?;
    builder.bind(target, sub_expr(const_expr(1), signal_expr(&zero_eq)))?;
    builder.constrain_boolean(target)?;
    Ok(())
}

fn append_square_nonlinear_anchor(builder: &mut ProgramBuilder, signal: &str) -> ZkfResult<()> {
    let anchor = format!("{signal}_square_anchor");
    builder.private_signal(&anchor)?;
    builder.bind(&anchor, mul_expr(signal_expr(signal), signal_expr(signal)))?;
    Ok(())
}

fn write_exact_division_support(
    values: &mut BTreeMap<String, FieldElement>,
    numerator: u64,
    denominator: u64,
    quotient: &str,
    remainder: &str,
    slack: &str,
    prefix: &str,
) -> ZkfResult<()> {
    if denominator == 0 {
        return Err(ZkfError::InvalidArtifact(format!(
            "{prefix} denominator must be non-zero"
        )));
    }
    let quotient_value = numerator / denominator;
    let remainder_value = numerator % denominator;
    let slack_value = denominator
        .checked_sub(remainder_value + 1)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(format!(
                "{prefix} denominator={denominator} is inconsistent with remainder={remainder_value}"
            ))
        })?;
    write_value(values, quotient, quotient_value);
    write_value(values, remainder, remainder_value);
    write_value(values, slack, slack_value);
    write_value(
        values,
        format!("{prefix}_exact_division_slack_anchor"),
        slack_value * slack_value,
    );
    Ok(())
}

fn write_exact_division_support_bigint(
    values: &mut BTreeMap<String, FieldElement>,
    numerator: &BigInt,
    denominator: u64,
    quotient: &str,
    remainder: &str,
    slack: &str,
    prefix: &str,
) -> ZkfResult<()> {
    if denominator == 0 {
        return Err(ZkfError::InvalidArtifact(format!(
            "{prefix} denominator must be non-zero"
        )));
    }
    let denominator_bigint = BigInt::from(denominator);
    let quotient_value = numerator / &denominator_bigint;
    let remainder_value = numerator % &denominator_bigint;
    let remainder_u64: u64 = remainder_value
        .clone()
        .try_into()
        .map_err(|_| ZkfError::InvalidArtifact(format!("{prefix} remainder did not fit in u64")))?;
    let slack_value = denominator
        .checked_sub(remainder_u64 + 1)
        .ok_or_else(|| {
            ZkfError::InvalidArtifact(format!(
                "{prefix} denominator={denominator} is inconsistent with remainder={remainder_u64}"
            ))
        })?;
    write_value(values, quotient, quotient_value);
    write_value(values, remainder, remainder_value);
    write_value(values, slack, slack_value);
    write_value(
        values,
        format!("{prefix}_exact_division_slack_anchor"),
        slack_value * slack_value,
    );
    Ok(())
}

fn append_private_input_anchor_chain(
    builder: &mut ProgramBuilder,
    inputs: &[String],
    prefix: &str,
) -> ZkfResult<String> {
    let mut previous = const_expr(0);
    let mut final_digest = String::new();
    for (index, chunk) in inputs.chunks(3).enumerate() {
        let digest = builder.append_poseidon_hash(
            &format!("{prefix}_{index}"),
            [
                previous.clone(),
                signal_expr(&chunk[0]),
                chunk
                    .get(1)
                    .map(|value| signal_expr(value))
                    .unwrap_or_else(|| const_expr(0)),
                chunk
                    .get(2)
                    .map(|value| signal_expr(value))
                    .unwrap_or_else(|| const_expr(0)),
            ],
        )?;
        previous = signal_expr(&digest);
        final_digest = digest;
    }
    Ok(final_digest)
}

fn write_private_input_anchor_chain(
    values: &mut BTreeMap<String, FieldElement>,
    input_names: &[String],
    prefix: &str,
) -> ZkfResult<BigInt> {
    let mut previous = zero();
    for (index, chunk) in input_names.chunks(3).enumerate() {
        let lane_1 = values
            .get(&chunk[0])
            .cloned()
            .unwrap_or(FieldElement::ZERO)
            .as_bigint();
        let lane_2 = chunk
            .get(1)
            .and_then(|name| values.get(name))
            .cloned()
            .unwrap_or(FieldElement::ZERO)
            .as_bigint();
        let lane_3 = chunk
            .get(2)
            .and_then(|name| values.get(name))
            .cloned()
            .unwrap_or(FieldElement::ZERO)
            .as_bigint();
        let digest = poseidon_permutation4([&previous, &lane_1, &lane_2, &lane_3])?;
        previous = write_hash_lanes(values, &format!("{prefix}_{index}"), digest);
    }
    Ok(previous)
}

fn evidence_manifest_digest_bigint(value: &str) -> ZkfResult<BigInt> {
    BigInt::parse_bytes(value.as_bytes(), 10).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "claims evidence manifest digest must be a base-10 integer string, got {value:?}"
        ))
    })
}

fn policy_input_name(name: &str) -> String {
    format!("claims_policy_{name}")
}

fn policy_array_name(name: &str, index: usize) -> String {
    format!("claims_policy_{name}_{index}")
}

fn claim_input_name(name: &str) -> String {
    format!("claims_claim_{name}")
}

fn claim_array_name(name: &str, index: usize) -> String {
    format!("claims_claim_{name}_{index}")
}

fn evidence_line_name(kind: &str, field: &str, index: usize) -> String {
    format!("claims_evidence_{kind}_{field}_{index}")
}

fn evidence_name(name: &str) -> String {
    format!("claims_evidence_{name}")
}

fn evidence_array_name(name: &str, index: usize) -> String {
    format!("claims_evidence_{name}_{index}")
}

fn analysis_name(name: &str) -> String {
    format!("claims_analysis_{name}")
}

fn analysis_array_name(name: &str, index: usize) -> String {
    format!("claims_analysis_{name}_{index}")
}

fn governance_name(name: &str) -> String {
    format!("claims_governance_{name}")
}

fn governance_array_name(name: &str, index: usize) -> String {
    format!("claims_governance_{name}_{index}")
}

fn settlement_input_names() -> Vec<String> {
    vec![
        "claims_settlement_claim_packet_commitment".to_string(),
        "claims_settlement_coverage_decision_commitment".to_string(),
        "claims_settlement_fraud_evidence_score".to_string(),
        "claims_settlement_payout_amount".to_string(),
        "claims_settlement_reserve_amount".to_string(),
        "claims_settlement_reinsurer_share_amount".to_string(),
        "claims_settlement_action_class_code".to_string(),
        "claims_settlement_claimant_destination_commitment".to_string(),
        "claims_settlement_insurer_reserve_account_commitment".to_string(),
        "claims_settlement_reinsurer_participation_commitment".to_string(),
        "claims_settlement_dispute_threshold".to_string(),
        "claims_settlement_blinding_0".to_string(),
        "claims_settlement_blinding_1".to_string(),
        "claims_settlement_public_blinding_0".to_string(),
        "claims_settlement_public_blinding_1".to_string(),
    ]
}

fn disclosure_input_names() -> Vec<String> {
    vec![
        "claims_disclosure_role_auditor".to_string(),
        "claims_disclosure_role_regulator".to_string(),
        "claims_disclosure_role_reinsurer".to_string(),
        "claims_disclosure_role_claimant".to_string(),
        "claims_disclosure_role_investigator".to_string(),
        "claims_disclosure_claim_packet_commitment".to_string(),
        "claims_disclosure_coverage_decision_commitment".to_string(),
        "claims_disclosure_consistency_score_commitment".to_string(),
        "claims_disclosure_fraud_score_commitment".to_string(),
        "claims_disclosure_payout_commitment".to_string(),
        "claims_disclosure_reserve_commitment".to_string(),
        "claims_disclosure_settlement_commitment".to_string(),
        "claims_disclosure_reinsurer_share_amount".to_string(),
        "claims_disclosure_public_blinding_0".to_string(),
        "claims_disclosure_public_blinding_1".to_string(),
    ]
}

fn shard_input_names() -> Vec<String> {
    let mut names = vec![
        "claims_shard_shard_count".to_string(),
        "claims_shard_blinding_0".to_string(),
        "claims_shard_blinding_1".to_string(),
    ];
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        names.push(format!("claims_shard_claim_commitment_{index}"));
    }
    names
}

pub fn claims_truth_private_input_names_v1() -> Vec<String> {
    let mut names = vec![
        policy_input_name("policy_id_hash"),
        policy_input_name("effective_timestamp"),
        policy_input_name("expiration_timestamp"),
    ];
    for index in 0..PRIVATE_CLAIMS_MAX_PERILS {
        names.push(policy_array_name("covered_peril_flag", index));
        names.push(policy_array_name("exclusion_flag", index));
    }
    for index in 0..2 {
        names.push(policy_array_name("deductible_schedule", index));
        names.push(policy_array_name("payout_cap_schedule", index));
        names.push(policy_array_name("depreciation_rule", index));
        names.push(policy_array_name("reserve_policy_parameter", index));
    }
    for index in 0..3 {
        names.push(policy_array_name("reinsurer_sharing_parameter", index));
    }
    names.extend([
        claim_input_name("claim_id_hash"),
        claim_input_name("claimant_id_hash"),
        claim_input_name("incident_timestamp"),
        claim_input_name("reported_timestamp"),
        claim_input_name("event_region_bucket"),
        claim_input_name("damaged_asset_class"),
    ]);
    for index in 0..PRIVATE_CLAIMS_MAX_PERILS {
        names.push(claim_array_name("peril_classification_flag", index));
        names.push(claim_array_name("claimed_loss_category", index));
    }
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        names.push(claim_array_name("prior_claim_linkage_hash", index));
    }
    for index in 0..PRIVATE_CLAIMS_MAX_LINE_ITEMS {
        names.push(evidence_line_name("estimate", "quantity", index));
        names.push(evidence_line_name("estimate", "unit_amount", index));
        names.push(evidence_line_name("estimate", "replacement_cost", index));
        names.push(evidence_line_name("estimate", "depreciation_basis", index));
        names.push(evidence_line_name("invoice", "quantity", index));
        names.push(evidence_line_name("invoice", "amount", index));
        names.push(evidence_array_name("replacement_cost_schedule", index));
        names.push(evidence_array_name("depreciation_basis_value", index));
    }
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        names.push(evidence_array_name("telematics_summary", index));
        names.push(evidence_array_name("vendor_attestation_digest", index));
        names.push(analysis_array_name("duplicate_candidate_hash", index));
        names.push(analysis_array_name("price_deviation_baseline", index));
        names.push(analysis_array_name("vendor_anomaly_baseline", index));
    }
    names.extend([
        evidence_name("photo_analysis_result_digest"),
        evidence_name("document_extraction_result_digest"),
        evidence_name("authority_report_reference_digest"),
        evidence_name("evidence_manifest_digest"),
        analysis_name("chronology_threshold"),
        analysis_name("geographic_reasonableness_threshold"),
        analysis_name("quantity_tolerance_threshold"),
        analysis_name("valuation_tolerance_threshold"),
        governance_name("claimant_payout_destination_commitment"),
        governance_name("insurer_reserve_account_commitment"),
        governance_name("reinsurer_participation_commitment"),
        governance_name("dispute_escalation_threshold"),
        governance_name("fraud_review_threshold"),
        governance_name("manual_review_threshold"),
        governance_array_name("settlement_blinding", 0),
        governance_array_name("settlement_blinding", 1),
        governance_array_name("public_disclosure_blinding", 0),
        governance_array_name("public_disclosure_blinding", 1),
    ]);
    names
}

fn expected_public_output_names() -> Vec<String> {
    vec![
        "claim_packet_commitment".to_string(),
        "coverage_decision_commitment".to_string(),
        "consistency_score_commitment".to_string(),
        "fraud_evidence_score_commitment".to_string(),
        "payout_amount_commitment".to_string(),
        "reserve_amount_commitment".to_string(),
        "settlement_instruction_commitment".to_string(),
        "action_class_code".to_string(),
        "human_review_required".to_string(),
        "eligible_for_midnight_settlement".to_string(),
    ]
}

fn validate_private_inputs(request: &ClaimsTruthPrivateInputsV1) -> ZkfResult<()> {
    if request.policy.policy_effective_timestamp > request.policy.policy_expiration_timestamp {
        return Err(ZkfError::InvalidArtifact(
            "policy effective timestamp must be <= expiration timestamp".to_string(),
        ));
    }
    if request.claim_event.incident_timestamp > request.claim_event.reported_timestamp {
        return Err(ZkfError::InvalidArtifact(
            "incident timestamp must be <= reported timestamp for this flagship lane".to_string(),
        ));
    }
    for flag in request
        .policy
        .covered_peril_flags
        .into_iter()
        .chain(request.policy.exclusion_flags)
        .chain(request.claim_event.peril_classification_flags)
        .chain(request.claim_event.claimed_loss_categories)
    {
        if flag > 1 {
            return Err(ZkfError::InvalidArtifact(
                "boolean policy/claim flags must be 0 or 1".to_string(),
            ));
        }
    }
    for value in [
        request.analysis_inputs.chronology_consistency_threshold,
        request.analysis_inputs.quantity_tolerance_threshold,
        request.analysis_inputs.valuation_tolerance_threshold,
        request.settlement_governance.dispute_escalation_threshold,
        request.settlement_governance.fraud_review_threshold,
        request.settlement_governance.manual_review_threshold,
    ] {
        if value == 0 {
            return Err(ZkfError::InvalidArtifact(
                "threshold inputs must be non-zero".to_string(),
            ));
        }
    }
    let _ = evidence_manifest_digest_bigint(&request.evidence.evidence_manifest_digest)?;
    Ok(())
}

fn flatten_private_inputs(request: &ClaimsTruthPrivateInputsV1) -> ZkfResult<WitnessInputs> {
    validate_private_inputs(request)?;
    let mut values = BTreeMap::new();
    write_value(
        &mut values,
        policy_input_name("policy_id_hash"),
        request.policy.policy_id_hash,
    );
    write_value(
        &mut values,
        policy_input_name("effective_timestamp"),
        request.policy.policy_effective_timestamp,
    );
    write_value(
        &mut values,
        policy_input_name("expiration_timestamp"),
        request.policy.policy_expiration_timestamp,
    );
    for index in 0..PRIVATE_CLAIMS_MAX_PERILS {
        write_value(
            &mut values,
            policy_array_name("covered_peril_flag", index),
            request.policy.covered_peril_flags[index],
        );
        write_value(
            &mut values,
            policy_array_name("exclusion_flag", index),
            request.policy.exclusion_flags[index],
        );
        write_value(
            &mut values,
            claim_array_name("peril_classification_flag", index),
            request.claim_event.peril_classification_flags[index],
        );
        write_value(
            &mut values,
            claim_array_name("claimed_loss_category", index),
            request.claim_event.claimed_loss_categories[index],
        );
    }
    for index in 0..2 {
        write_value(
            &mut values,
            policy_array_name("deductible_schedule", index),
            request.policy.deductible_schedule[index],
        );
        write_value(
            &mut values,
            policy_array_name("payout_cap_schedule", index),
            request.policy.payout_cap_schedule[index],
        );
        write_value(
            &mut values,
            policy_array_name("depreciation_rule", index),
            request.policy.depreciation_rules[index],
        );
        write_value(
            &mut values,
            policy_array_name("reserve_policy_parameter", index),
            request.policy.reserve_policy_parameters[index],
        );
    }
    for index in 0..3 {
        write_value(
            &mut values,
            policy_array_name("reinsurer_sharing_parameter", index),
            request.policy.reinsurer_sharing_parameters[index],
        );
    }
    write_value(
        &mut values,
        claim_input_name("claim_id_hash"),
        request.claim_event.claim_id_hash,
    );
    write_value(
        &mut values,
        claim_input_name("claimant_id_hash"),
        request.claim_event.claimant_id_hash,
    );
    write_value(
        &mut values,
        claim_input_name("incident_timestamp"),
        request.claim_event.incident_timestamp,
    );
    write_value(
        &mut values,
        claim_input_name("reported_timestamp"),
        request.claim_event.reported_timestamp,
    );
    write_value(
        &mut values,
        claim_input_name("event_region_bucket"),
        request.claim_event.event_region_bucket,
    );
    write_value(
        &mut values,
        claim_input_name("damaged_asset_class"),
        request.claim_event.damaged_asset_class,
    );
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        write_value(
            &mut values,
            claim_array_name("prior_claim_linkage_hash", index),
            request.claim_event.prior_claim_linkage_hashes[index],
        );
        write_value(
            &mut values,
            evidence_array_name("telematics_summary", index),
            request.evidence.telematics_structured_event_summary_values[index],
        );
        write_value(
            &mut values,
            evidence_array_name("vendor_attestation_digest", index),
            request.evidence.vendor_attestation_digests[index],
        );
        write_value(
            &mut values,
            analysis_array_name("duplicate_candidate_hash", index),
            request.analysis_inputs.duplicate_claim_candidate_hashes[index],
        );
        write_value(
            &mut values,
            analysis_array_name("price_deviation_baseline", index),
            request.analysis_inputs.price_deviation_baselines[index],
        );
        write_value(
            &mut values,
            analysis_array_name("vendor_anomaly_baseline", index),
            request.analysis_inputs.vendor_anomaly_baselines[index],
        );
    }
    for index in 0..PRIVATE_CLAIMS_MAX_LINE_ITEMS {
        let estimate = &request.evidence.repair_estimate_line_items[index];
        let invoice = &request.evidence.invoice_line_items[index];
        write_value(
            &mut values,
            evidence_line_name("estimate", "quantity", index),
            estimate.quantity,
        );
        write_value(
            &mut values,
            evidence_line_name("estimate", "unit_amount", index),
            estimate.unit_amount,
        );
        write_value(
            &mut values,
            evidence_line_name("estimate", "replacement_cost", index),
            estimate.replacement_cost,
        );
        write_value(
            &mut values,
            evidence_line_name("estimate", "depreciation_basis", index),
            estimate.depreciation_basis,
        );
        write_value(
            &mut values,
            evidence_line_name("invoice", "quantity", index),
            invoice.quantity,
        );
        write_value(
            &mut values,
            evidence_line_name("invoice", "amount", index),
            invoice.invoice_amount,
        );
        write_value(
            &mut values,
            evidence_array_name("replacement_cost_schedule", index),
            request.evidence.replacement_cost_schedules[index],
        );
        write_value(
            &mut values,
            evidence_array_name("depreciation_basis_value", index),
            request.evidence.depreciation_basis_values[index],
        );
    }
    write_value(
        &mut values,
        evidence_name("photo_analysis_result_digest"),
        request.evidence.photo_analysis_result_digest,
    );
    write_value(
        &mut values,
        evidence_name("document_extraction_result_digest"),
        request.evidence.document_extraction_result_digest,
    );
    write_value(
        &mut values,
        evidence_name("authority_report_reference_digest"),
        request.evidence.authority_report_reference_digest,
    );
    write_value(
        &mut values,
        evidence_name("evidence_manifest_digest"),
        evidence_manifest_digest_bigint(&request.evidence.evidence_manifest_digest)?,
    );
    write_value(
        &mut values,
        analysis_name("chronology_threshold"),
        request.analysis_inputs.chronology_consistency_threshold,
    );
    write_value(
        &mut values,
        analysis_name("geographic_reasonableness_threshold"),
        request.analysis_inputs.geographic_reasonableness_threshold,
    );
    write_value(
        &mut values,
        analysis_name("quantity_tolerance_threshold"),
        request.analysis_inputs.quantity_tolerance_threshold,
    );
    write_value(
        &mut values,
        analysis_name("valuation_tolerance_threshold"),
        request.analysis_inputs.valuation_tolerance_threshold,
    );
    write_value(
        &mut values,
        governance_name("claimant_payout_destination_commitment"),
        request
            .settlement_governance
            .claimant_payout_destination_commitment,
    );
    write_value(
        &mut values,
        governance_name("insurer_reserve_account_commitment"),
        request
            .settlement_governance
            .insurer_reserve_account_commitment,
    );
    write_value(
        &mut values,
        governance_name("reinsurer_participation_commitment"),
        request
            .settlement_governance
            .reinsurer_participation_commitment,
    );
    write_value(
        &mut values,
        governance_name("dispute_escalation_threshold"),
        request.settlement_governance.dispute_escalation_threshold,
    );
    write_value(
        &mut values,
        governance_name("fraud_review_threshold"),
        request.settlement_governance.fraud_review_threshold,
    );
    write_value(
        &mut values,
        governance_name("manual_review_threshold"),
        request.settlement_governance.manual_review_threshold,
    );
    for index in 0..2 {
        write_value(
            &mut values,
            governance_array_name("settlement_blinding", index),
            request.settlement_governance.settlement_blinding_values[index],
        );
        write_value(
            &mut values,
            governance_array_name("public_disclosure_blinding", index),
            request
                .settlement_governance
                .public_disclosure_blinding_values[index],
        );
    }
    Ok(values)
}

fn declare_private_inputs(builder: &mut ProgramBuilder) -> ZkfResult<()> {
    for name in claims_truth_private_input_names_v1() {
        builder.private_input(&name)?;
    }
    for index in 0..PRIVATE_CLAIMS_MAX_PERILS {
        builder.constrain_boolean(policy_array_name("covered_peril_flag", index))?;
        builder.constrain_boolean(policy_array_name("exclusion_flag", index))?;
        builder.constrain_boolean(claim_array_name("peril_classification_flag", index))?;
        builder.constrain_boolean(claim_array_name("claimed_loss_category", index))?;
    }
    for name in [
        policy_input_name("policy_id_hash"),
        policy_input_name("effective_timestamp"),
        policy_input_name("expiration_timestamp"),
        claim_input_name("claim_id_hash"),
        claim_input_name("claimant_id_hash"),
        claim_input_name("incident_timestamp"),
        claim_input_name("reported_timestamp"),
        claim_input_name("event_region_bucket"),
        claim_input_name("damaged_asset_class"),
        evidence_name("photo_analysis_result_digest"),
        evidence_name("document_extraction_result_digest"),
        evidence_name("authority_report_reference_digest"),
        analysis_name("chronology_threshold"),
        analysis_name("geographic_reasonableness_threshold"),
        analysis_name("quantity_tolerance_threshold"),
        analysis_name("valuation_tolerance_threshold"),
        governance_name("claimant_payout_destination_commitment"),
        governance_name("insurer_reserve_account_commitment"),
        governance_name("reinsurer_participation_commitment"),
        governance_name("dispute_escalation_threshold"),
        governance_name("fraud_review_threshold"),
        governance_name("manual_review_threshold"),
    ] {
        let bound = if name.contains("timestamp") {
            CLAIMS_TIMESTAMP_BOUND
        } else if name.contains("digest") || name.contains("commitment") || name.contains("hash") {
            CLAIMS_HASH_BOUND
        } else {
            CLAIMS_UINT_BOUND
        };
        builder.constrain_range(&name, bits_for_bound(bound))?;
    }
    builder.constrain_range(evidence_name("evidence_manifest_digest"), 254)?;
    for index in 0..2 {
        for name in [
            policy_array_name("deductible_schedule", index),
            policy_array_name("payout_cap_schedule", index),
            policy_array_name("depreciation_rule", index),
            policy_array_name("reserve_policy_parameter", index),
            governance_array_name("settlement_blinding", index),
            governance_array_name("public_disclosure_blinding", index),
        ] {
            builder.constrain_range(&name, bits_for_bound(CLAIMS_UINT_BOUND))?;
        }
    }
    for index in 0..3 {
        builder.constrain_range(
            policy_array_name("reinsurer_sharing_parameter", index),
            bits_for_bound(CLAIMS_UINT_BOUND),
        )?;
    }
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        for name in [
            claim_array_name("prior_claim_linkage_hash", index),
            evidence_array_name("telematics_summary", index),
            evidence_array_name("vendor_attestation_digest", index),
            analysis_array_name("duplicate_candidate_hash", index),
            analysis_array_name("price_deviation_baseline", index),
            analysis_array_name("vendor_anomaly_baseline", index),
        ] {
            builder.constrain_range(&name, bits_for_bound(CLAIMS_HASH_BOUND))?;
        }
    }
    for index in 0..PRIVATE_CLAIMS_MAX_LINE_ITEMS {
        for name in [
            evidence_line_name("estimate", "quantity", index),
            evidence_line_name("estimate", "unit_amount", index),
            evidence_line_name("estimate", "replacement_cost", index),
            evidence_line_name("estimate", "depreciation_basis", index),
            evidence_line_name("invoice", "quantity", index),
            evidence_line_name("invoice", "amount", index),
            evidence_array_name("replacement_cost_schedule", index),
            evidence_array_name("depreciation_basis_value", index),
        ] {
            builder.constrain_range(&name, bits_for_bound(CLAIMS_VALUE_BOUND))?;
        }
    }
    Ok(())
}

pub fn build_claim_decision_core_program() -> ZkfResult<Program> {
    let mut builder =
        ProgramBuilder::new("claims_truth_claim_decision_core_v1", CLAIMS_FIELD);
    declare_private_inputs(&mut builder)?;
    for output in expected_public_output_names() {
        builder.public_output(output)?;
    }
    builder.metadata_entry("nova_ivc_in", "claim_packet_commitment")?;
    builder.metadata_entry("nova_ivc_out", "settlement_instruction_commitment")?;
    builder.constant_signal("__claims_score_cap", field(CLAIMS_SCORE_CAP))?;
    builder.constant_signal("__claims_component_score_cap", field(CLAIMS_COMPONENT_SCORE_CAP))?;
    builder.constant_signal("__claims_scale", field(CLAIMS_FIXED_POINT_SCALE))?;
    builder.constant_signal("__claims_one", FieldElement::ONE)?;
    builder.constant_signal("__claims_zero", FieldElement::ZERO)?;

    let all_inputs = claims_truth_private_input_names_v1();
    let claim_packet_digest =
        append_private_input_anchor_chain(&mut builder, &all_inputs, "claims_packet_anchor")?;
    builder.constrain_equal(
        signal_expr("claim_packet_commitment"),
        signal_expr(&claim_packet_digest),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&claim_input_name("incident_timestamp")),
        signal_expr(&policy_input_name("effective_timestamp")),
        "claims_within_period_incident_after_effective_bit",
        "claims_within_period_incident_after_effective_slack",
        CLAIMS_TIMESTAMP_BOUND,
        "claims_within_period_incident_after_effective",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&policy_input_name("expiration_timestamp")),
        signal_expr(&claim_input_name("incident_timestamp")),
        "claims_within_period_expiration_after_incident_bit",
        "claims_within_period_expiration_after_incident_slack",
        CLAIMS_TIMESTAMP_BOUND,
        "claims_within_period_expiration_after_incident",
    )?;
    append_boolean_and(
        &mut builder,
        "claims_within_period_bit",
        signal_expr("claims_within_period_incident_after_effective_bit"),
        signal_expr("claims_within_period_expiration_after_incident_bit"),
    )?;

    builder.private_signal("claims_covered_peril_count")?;
    builder.bind(
        "claims_covered_peril_count",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_PERILS)
                .map(|index| {
                    mul_expr(
                        signal_expr(&policy_array_name("covered_peril_flag", index)),
                        signal_expr(&claim_array_name("peril_classification_flag", index)),
                    )
                })
                .collect(),
        ),
    )?;
    builder.constrain_range("claims_covered_peril_count", 4)?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_covered_peril_count"),
        const_expr(1),
        "claims_covered_peril_supported_bit",
        "claims_covered_peril_supported_slack",
        PRIVATE_CLAIMS_MAX_PERILS as u64 + 1,
        "claims_covered_peril_supported",
    )?;

    builder.private_signal("claims_excluded_peril_count")?;
    builder.bind(
        "claims_excluded_peril_count",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_PERILS)
                .map(|index| {
                    mul_expr(
                        signal_expr(&policy_array_name("exclusion_flag", index)),
                        signal_expr(&claim_array_name("peril_classification_flag", index)),
                    )
                })
                .collect(),
        ),
    )?;
    builder.constrain_range("claims_excluded_peril_count", 4)?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_excluded_peril_count"),
        const_expr(1),
        "claims_peril_excluded_bit",
        "claims_peril_excluded_slack",
        PRIVATE_CLAIMS_MAX_PERILS as u64 + 1,
        "claims_peril_excluded",
    )?;

    builder.private_signal("claims_claimed_category_count")?;
    builder.bind(
        "claims_claimed_category_count",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_PERILS)
                .map(|index| signal_expr(&claim_array_name("claimed_loss_category", index)))
                .collect(),
        ),
    )?;
    builder.constrain_range("claims_claimed_category_count", 4)?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_claimed_category_count"),
        const_expr(1),
        "claims_claim_category_present_bit",
        "claims_claim_category_present_slack",
        PRIVATE_CLAIMS_MAX_PERILS as u64 + 1,
        "claims_claim_category_present",
    )?;

    builder.private_signal("claims_not_peril_excluded_bit")?;
    builder.bind(
        "claims_not_peril_excluded_bit",
        sub_expr(const_expr(1), signal_expr("claims_peril_excluded_bit")),
    )?;
    builder.constrain_boolean("claims_not_peril_excluded_bit")?;

    append_boolean_and(
        &mut builder,
        "claims_policy_eligible_pre_category_bit",
        signal_expr("claims_within_period_bit"),
        signal_expr("claims_covered_peril_supported_bit"),
    )?;
    append_boolean_and(
        &mut builder,
        "claims_policy_eligible_pre_exclusion_bit",
        signal_expr("claims_policy_eligible_pre_category_bit"),
        signal_expr("claims_not_peril_excluded_bit"),
    )?;
    append_boolean_and(
        &mut builder,
        "claims_policy_eligible_bit",
        signal_expr("claims_policy_eligible_pre_exclusion_bit"),
        signal_expr("claims_claim_category_present_bit"),
    )?;

    let coverage_commitment = builder.append_poseidon_hash(
        "claims_coverage_commitment",
        [
            const_expr(CLAIMS_DOMAIN_COVERAGE),
            signal_expr("claims_policy_eligible_bit"),
            signal_expr("claims_within_period_bit"),
            signal_expr("claims_excluded_peril_count"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("coverage_decision_commitment"),
        signal_expr(&coverage_commitment),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&claim_input_name("reported_timestamp")),
        signal_expr(&claim_input_name("incident_timestamp")),
        "claims_reported_after_incident_bit",
        "claims_reported_after_incident_slack",
        CLAIMS_TIMESTAMP_BOUND,
        "claims_reported_after_incident",
    )?;
    builder.private_signal("claims_report_delay")?;
    builder.bind(
        "claims_report_delay",
        sub_expr(
            signal_expr(&claim_input_name("reported_timestamp")),
            signal_expr(&claim_input_name("incident_timestamp")),
        ),
    )?;
    builder.constrain_range("claims_report_delay", bits_for_bound(CLAIMS_TIMESTAMP_BOUND))?;
    builder.private_signal("claims_report_delay_margin_shifted")?;
    builder.constrain_equal(
        signal_expr("claims_report_delay_margin_shifted"),
        add_expr(vec![
            signal_expr("claims_report_delay"),
            const_expr(CLAIMS_SIGNED_MARGIN_OFFSET),
            sub_expr(
                const_expr(0),
                signal_expr(&analysis_name("chronology_threshold")),
            ),
        ]),
    )?;
    builder.constrain_range(
        "claims_report_delay_margin_shifted",
        bits_for_bound(CLAIMS_SIGNED_MARGIN_BOUND),
    )?;

    let digest_inputs = vec![
        evidence_name("photo_analysis_result_digest"),
        evidence_name("document_extraction_result_digest"),
        evidence_name("authority_report_reference_digest"),
        evidence_array_name("telematics_summary", 0),
    ];
    let digest_anchor =
        append_private_input_anchor_chain(&mut builder, &digest_inputs, "claims_evidence_anchor")?;
    builder.constrain_equal(
        signal_expr(&digest_anchor),
        signal_expr(&evidence_name("evidence_manifest_digest")),
    )?;

    for index in 0..PRIVATE_CLAIMS_MAX_LINE_ITEMS {
        builder.private_signal(&format!("claims_estimate_total_{index}"))?;
        builder.bind(
            format!("claims_estimate_total_{index}"),
            mul_expr(
                signal_expr(&evidence_line_name("estimate", "quantity", index)),
                signal_expr(&evidence_line_name("estimate", "unit_amount", index)),
            ),
        )?;
        builder.constrain_range(
            &format!("claims_estimate_total_{index}"),
            bits_for_bound(CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND),
        )?;
        append_pairwise_min_signal(
            &mut builder,
            &format!("claims_replacement_min_{index}"),
            &format!("claims_estimate_total_{index}"),
            &evidence_line_name("estimate", "replacement_cost", index),
            CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
            &format!("claims_replacement_min_{index}"),
        )?;
        append_pairwise_max_signal(
            &mut builder,
            &format!("claims_replacement_max_{index}"),
            &format!("claims_estimate_total_{index}"),
            &evidence_line_name("estimate", "replacement_cost", index),
            CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
            &format!("claims_replacement_max_{index}"),
        )?;
        builder.private_signal(&format!("claims_replacement_gap_{index}"))?;
        builder.bind(
            format!("claims_replacement_gap_{index}"),
            sub_expr(
                signal_expr(&format!("claims_replacement_max_{index}")),
                signal_expr(&format!("claims_replacement_min_{index}")),
            ),
        )?;
        append_pairwise_min_signal(
            &mut builder,
            &format!("claims_invoice_amount_min_{index}"),
            &format!("claims_estimate_total_{index}"),
            &evidence_line_name("invoice", "amount", index),
            CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
            &format!("claims_invoice_amount_min_{index}"),
        )?;
        append_pairwise_max_signal(
            &mut builder,
            &format!("claims_invoice_amount_max_{index}"),
            &format!("claims_estimate_total_{index}"),
            &evidence_line_name("invoice", "amount", index),
            CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
            &format!("claims_invoice_amount_max_{index}"),
        )?;
        builder.private_signal(&format!("claims_invoice_gap_{index}"))?;
        builder.bind(
            format!("claims_invoice_gap_{index}"),
            sub_expr(
                signal_expr(&format!("claims_invoice_amount_max_{index}")),
                signal_expr(&format!("claims_invoice_amount_min_{index}")),
            ),
        )?;
        append_pairwise_min_signal(
            &mut builder,
            &format!("claims_invoice_quantity_min_{index}"),
            &evidence_line_name("estimate", "quantity", index),
            &evidence_line_name("invoice", "quantity", index),
            CLAIMS_VALUE_BOUND,
            &format!("claims_invoice_quantity_min_{index}"),
        )?;
        append_pairwise_max_signal(
            &mut builder,
            &format!("claims_invoice_quantity_max_{index}"),
            &evidence_line_name("estimate", "quantity", index),
            &evidence_line_name("invoice", "quantity", index),
            CLAIMS_VALUE_BOUND,
            &format!("claims_invoice_quantity_max_{index}"),
        )?;
        builder.private_signal(&format!("claims_quantity_gap_{index}"))?;
        builder.bind(
            format!("claims_quantity_gap_{index}"),
            sub_expr(
                signal_expr(&format!("claims_invoice_quantity_max_{index}")),
                signal_expr(&format!("claims_invoice_quantity_min_{index}")),
            ),
        )?;
    }

    for aggregate in [
        "claims_total_estimate_amount",
        "claims_total_invoice_amount",
        "claims_total_replacement_amount",
        "claims_total_valuation_gap",
        "claims_total_quantity_gap",
        "claims_total_price_baseline",
        "claims_total_vendor_baseline",
        "claims_total_vendor_digest",
        "claims_complete_digest_count",
        "claims_duplicate_match_count",
    ] {
        builder.private_signal(aggregate)?;
    }
    builder.bind(
        "claims_total_estimate_amount",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_LINE_ITEMS)
                .map(|index| signal_expr(&format!("claims_estimate_total_{index}")))
                .collect(),
        ),
    )?;
    builder.bind(
        "claims_total_invoice_amount",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_LINE_ITEMS)
                .map(|index| signal_expr(&evidence_line_name("invoice", "amount", index)))
                .collect(),
        ),
    )?;
    builder.bind(
        "claims_total_replacement_amount",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_LINE_ITEMS)
                .map(|index| signal_expr(&evidence_line_name("estimate", "replacement_cost", index)))
                .collect(),
        ),
    )?;
    builder.bind(
        "claims_total_valuation_gap",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_LINE_ITEMS)
                .flat_map(|index| {
                    [
                        signal_expr(&format!("claims_replacement_gap_{index}")),
                        signal_expr(&format!("claims_invoice_gap_{index}")),
                    ]
                })
                .collect(),
        ),
    )?;
    builder.bind(
        "claims_total_quantity_gap",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_LINE_ITEMS)
                .map(|index| signal_expr(&format!("claims_quantity_gap_{index}")))
                .collect(),
        ),
    )?;
    builder.bind(
        "claims_total_price_baseline",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_DIGESTS)
                .map(|index| signal_expr(&analysis_array_name("price_deviation_baseline", index)))
                .collect(),
        ),
    )?;
    builder.bind(
        "claims_total_vendor_baseline",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_DIGESTS)
                .map(|index| signal_expr(&analysis_array_name("vendor_anomaly_baseline", index)))
                .collect(),
        ),
    )?;
    builder.bind(
        "claims_total_vendor_digest",
        add_expr(
            (0..PRIVATE_CLAIMS_MAX_DIGESTS)
                .map(|index| signal_expr(&evidence_array_name("vendor_attestation_digest", index)))
                .collect(),
        ),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&analysis_name("geographic_reasonableness_threshold")),
        signal_expr(&claim_input_name("event_region_bucket")),
        "claims_geographic_reasonable_bit",
        "claims_geographic_reasonable_slack",
        CLAIMS_UINT_BOUND,
        "claims_geographic_reasonable",
    )?;

    let mut duplicate_eq_bits = Vec::new();
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        duplicate_eq_bits.push(append_equality_with_inverse(
            &mut builder,
            signal_expr(&claim_array_name("prior_claim_linkage_hash", index)),
            signal_expr(&analysis_array_name("duplicate_candidate_hash", index)),
            &format!("claims_duplicate_match_{index}"),
        )?);
    }
    builder.bind(
        "claims_duplicate_match_count",
        add_expr(duplicate_eq_bits.iter().map(|name| signal_expr(name)).collect()),
    )?;

    let nonzero_digest_sources = vec![
        evidence_name("photo_analysis_result_digest"),
        evidence_name("document_extraction_result_digest"),
        evidence_name("authority_report_reference_digest"),
        evidence_name("evidence_manifest_digest"),
    ];
    let mut complete_digest_bits = Vec::new();
    for (index, source) in nonzero_digest_sources.iter().enumerate() {
        let present = format!("claims_digest_present_{index}");
        append_nonzero_indicator(&mut builder, &present, signal_expr(source), &present)?;
        complete_digest_bits.push(present);
    }
    builder.bind(
        "claims_complete_digest_count",
        add_expr(complete_digest_bits.iter().map(|name| signal_expr(name)).collect()),
    )?;

    builder.append_exact_division_constraints(
        signal_expr("claims_report_delay"),
        signal_expr(&analysis_name("chronology_threshold")),
        "claims_chronology_ratio",
        "claims_chronology_ratio_remainder",
        "claims_chronology_ratio_slack",
        &BigInt::from(CLAIMS_TIMESTAMP_BOUND),
        "claims_chronology_ratio",
    )?;
    builder.private_signal("claims_chronology_score_raw")?;
    builder.bind(
        "claims_chronology_score_raw",
        add_expr(vec![
            mul_expr(signal_expr("claims_chronology_ratio"), const_expr(1_000)),
            mul_expr(
                sub_expr(const_expr(1), signal_expr("claims_reported_after_incident_bit")),
                const_expr(2_000),
            ),
        ]),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "claims_chronology_score",
        "claims_chronology_score_raw",
        "__claims_component_score_cap",
        CLAIMS_RATIO_BOUND,
        "claims_chronology_score",
    )?;

    builder.append_exact_division_constraints(
        signal_expr("claims_total_valuation_gap"),
        signal_expr(&analysis_name("valuation_tolerance_threshold")),
        "claims_valuation_ratio",
        "claims_valuation_ratio_remainder",
        "claims_valuation_ratio_slack",
        &BigInt::from(CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND),
        "claims_valuation_ratio",
    )?;
    builder.private_signal("claims_valuation_score_raw")?;
    builder.bind(
        "claims_valuation_score_raw",
        mul_expr(signal_expr("claims_valuation_ratio"), const_expr(1_000)),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "claims_valuation_score",
        "claims_valuation_score_raw",
        "__claims_component_score_cap",
        CLAIMS_RATIO_BOUND,
        "claims_valuation_score",
    )?;

    builder.append_exact_division_constraints(
        signal_expr("claims_total_quantity_gap"),
        signal_expr(&analysis_name("quantity_tolerance_threshold")),
        "claims_quantity_ratio",
        "claims_quantity_ratio_remainder",
        "claims_quantity_ratio_slack",
        &BigInt::from(CLAIMS_VALUE_BOUND),
        "claims_quantity_ratio",
    )?;
    builder.private_signal("claims_quantity_score_raw")?;
    builder.bind(
        "claims_quantity_score_raw",
        mul_expr(signal_expr("claims_quantity_ratio"), const_expr(1_000)),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "claims_quantity_score",
        "claims_quantity_score_raw",
        "__claims_component_score_cap",
        CLAIMS_RATIO_BOUND,
        "claims_quantity_score",
    )?;

    append_pairwise_min_signal(
        &mut builder,
        "claims_vendor_gap_min",
        "claims_total_vendor_digest",
        "claims_total_vendor_baseline",
        CLAIMS_HASH_BOUND,
        "claims_vendor_gap_min",
    )?;
    append_pairwise_max_signal(
        &mut builder,
        "claims_vendor_gap_max",
        "claims_total_vendor_digest",
        "claims_total_vendor_baseline",
        CLAIMS_HASH_BOUND,
        "claims_vendor_gap_max",
    )?;
    builder.private_signal("claims_vendor_gap")?;
    builder.bind(
        "claims_vendor_gap",
        sub_expr(
            signal_expr("claims_vendor_gap_max"),
            signal_expr("claims_vendor_gap_min"),
        ),
    )?;
    builder.private_signal("claims_total_vendor_baseline_plus_one")?;
    builder.bind(
        "claims_total_vendor_baseline_plus_one",
        add_expr(vec![signal_expr("claims_total_vendor_baseline"), const_expr(1)]),
    )?;
    builder.append_exact_division_constraints(
        signal_expr("claims_vendor_gap"),
        signal_expr("claims_total_vendor_baseline_plus_one"),
        "claims_vendor_ratio",
        "claims_vendor_ratio_remainder",
        "claims_vendor_ratio_slack",
        &BigInt::from(CLAIMS_HASH_BOUND),
        "claims_vendor_ratio",
    )?;
    builder.private_signal("claims_vendor_score_raw")?;
    builder.bind(
        "claims_vendor_score_raw",
        mul_expr(signal_expr("claims_vendor_ratio"), const_expr(750)),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "claims_vendor_score",
        "claims_vendor_score_raw",
        "__claims_component_score_cap",
        CLAIMS_RATIO_BOUND,
        "claims_vendor_score",
    )?;

    builder.private_signal("claims_policy_mismatch_score")?;
    builder.bind(
        "claims_policy_mismatch_score",
        add_expr(vec![
            mul_expr(
                sub_expr(const_expr(1), signal_expr("claims_policy_eligible_bit")),
                const_expr(5_000),
            ),
            mul_expr(signal_expr("claims_peril_excluded_bit"), const_expr(2_000)),
        ]),
    )?;
    builder.constrain_range(
        "claims_policy_mismatch_score",
        bits_for_bound(CLAIMS_SCORE_CAP),
    )?;

    builder.private_signal("claims_expected_digest_count")?;
    builder.bind("claims_expected_digest_count", const_expr(nonzero_digest_sources.len() as u64))?;
    builder.private_signal("claims_missing_digest_count")?;
    builder.bind(
        "claims_missing_digest_count",
        sub_expr(
            signal_expr("claims_expected_digest_count"),
            signal_expr("claims_complete_digest_count"),
        ),
    )?;
    builder.private_signal("claims_evidence_completeness_score")?;
    builder.bind(
        "claims_evidence_completeness_score",
        mul_expr(signal_expr("claims_missing_digest_count"), const_expr(1_000)),
    )?;
    builder.constrain_range(
        "claims_evidence_completeness_score",
        bits_for_bound(CLAIMS_SCORE_CAP),
    )?;

    builder.private_signal("claims_structured_inconsistency_score_raw")?;
    builder.bind(
        "claims_structured_inconsistency_score_raw",
        add_expr(vec![
            signal_expr("claims_valuation_score"),
            signal_expr("claims_quantity_score"),
            mul_expr(
                sub_expr(const_expr(1), signal_expr("claims_geographic_reasonable_bit")),
                const_expr(800),
            ),
            mul_expr(
                sub_expr(const_expr(1), signal_expr("claims_reported_after_incident_bit")),
                const_expr(2_000),
            ),
            signal_expr("claims_evidence_completeness_score"),
        ]),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "claims_structured_inconsistency_score",
        "claims_structured_inconsistency_score_raw",
        "__claims_score_cap",
        CLAIMS_SCORE_CAP * 2,
        "claims_structured_inconsistency_score",
    )?;
    builder.private_signal("claims_consistency_score")?;
    builder.bind(
        "claims_consistency_score",
        sub_expr(
            signal_expr("__claims_score_cap"),
            signal_expr("claims_structured_inconsistency_score"),
        ),
    )?;
    builder.constrain_range("claims_consistency_score", bits_for_bound(CLAIMS_SCORE_CAP))?;

    builder.private_signal("claims_duplication_score")?;
    builder.bind(
        "claims_duplication_score",
        mul_expr(signal_expr("claims_duplicate_match_count"), const_expr(3_000)),
    )?;
    builder.private_signal("claims_fraud_evidence_score_raw")?;
    builder.bind(
        "claims_fraud_evidence_score_raw",
        add_expr(vec![
            signal_expr("claims_duplication_score"),
            signal_expr("claims_vendor_score"),
            signal_expr("claims_chronology_score"),
            signal_expr("claims_policy_mismatch_score"),
        ]),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "claims_fraud_evidence_score",
        "claims_fraud_evidence_score_raw",
        "__claims_score_cap",
        CLAIMS_SCORE_CAP * 2,
        "claims_fraud_evidence_score",
    )?;

    let consistency_commitment = builder.append_poseidon_hash(
        "claims_consistency_commitment",
        [
            const_expr(CLAIMS_DOMAIN_CONSISTENCY),
            signal_expr("claims_consistency_score"),
            signal_expr(&governance_array_name("public_disclosure_blinding", 0)),
            signal_expr(&governance_array_name("public_disclosure_blinding", 1)),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("consistency_score_commitment"),
        signal_expr(&consistency_commitment),
    )?;
    let fraud_commitment = builder.append_poseidon_hash(
        "claims_fraud_commitment",
        [
            const_expr(CLAIMS_DOMAIN_FRAUD),
            signal_expr("claims_fraud_evidence_score"),
            signal_expr(&governance_array_name("public_disclosure_blinding", 0)),
            signal_expr(&governance_array_name("public_disclosure_blinding", 1)),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("fraud_evidence_score_commitment"),
        signal_expr(&fraud_commitment),
    )?;

    append_pairwise_min_signal(
        &mut builder,
        "claims_covered_amount_before_deductible",
        "claims_total_estimate_amount",
        "claims_total_replacement_amount",
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_covered_amount_before_deductible",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_covered_amount_before_deductible"),
        signal_expr(&policy_array_name("deductible_schedule", 0)),
        "claims_deductible_applies_bit",
        "claims_deductible_applies_slack",
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_deductible_applies",
    )?;
    builder.private_signal("claims_deductible_adjusted_amount")?;
    builder.bind(
        "claims_deductible_adjusted_amount",
        select_expr(
            signal_expr("claims_deductible_applies_bit"),
            sub_expr(
                signal_expr("claims_covered_amount_before_deductible"),
                signal_expr(&policy_array_name("deductible_schedule", 0)),
            ),
            const_expr(0),
        ),
    )?;
    builder.constrain_range(
        "claims_deductible_adjusted_amount",
        bits_for_bound(CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND),
    )?;
    builder.private_signal("claims_depreciation_raw")?;
    builder.bind(
        "claims_depreciation_raw",
        mul_expr(
            signal_expr("claims_deductible_adjusted_amount"),
            signal_expr(&policy_array_name("depreciation_rule", 0)),
        ),
    )?;
    builder.append_exact_division_constraints(
        signal_expr("claims_depreciation_raw"),
        signal_expr("__claims_scale"),
        "claims_depreciation_amount",
        "claims_depreciation_remainder",
        "claims_depreciation_slack",
        &BigInt::from(CLAIMS_FIXED_POINT_SCALE),
        "claims_depreciation",
    )?;
    builder.private_signal("claims_depreciation_adjusted_amount")?;
    builder.bind(
        "claims_depreciation_adjusted_amount",
        sub_expr(
            signal_expr("claims_deductible_adjusted_amount"),
            signal_expr("claims_depreciation_amount"),
        ),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "claims_capped_payout_amount",
        "claims_depreciation_adjusted_amount",
        &policy_array_name("payout_cap_schedule", 0),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_capped_payout_amount",
    )?;
    builder.private_signal("claims_reserve_margin_raw")?;
    builder.bind(
        "claims_reserve_margin_raw",
        mul_expr(
            signal_expr("claims_capped_payout_amount"),
            signal_expr(&policy_array_name("reserve_policy_parameter", 0)),
        ),
    )?;
    builder.append_exact_division_constraints(
        signal_expr("claims_reserve_margin_raw"),
        signal_expr("__claims_scale"),
        "claims_reserve_margin_amount",
        "claims_reserve_margin_remainder",
        "claims_reserve_margin_slack",
        &BigInt::from(CLAIMS_FIXED_POINT_SCALE),
        "claims_reserve_margin",
    )?;
    builder.private_signal("claims_reserve_amount_pre_floor")?;
    builder.bind(
        "claims_reserve_amount_pre_floor",
        add_expr(vec![
            signal_expr("claims_capped_payout_amount"),
            signal_expr("claims_reserve_margin_amount"),
        ]),
    )?;
    append_pairwise_max_signal(
        &mut builder,
        "claims_reserve_amount",
        "claims_reserve_amount_pre_floor",
        &policy_array_name("reserve_policy_parameter", 1),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_reserve_amount",
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_capped_payout_amount"),
        signal_expr(&policy_array_name("reinsurer_sharing_parameter", 1)),
        "claims_reinsurer_attached_bit",
        "claims_reinsurer_attached_slack",
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_reinsurer_attached",
    )?;
    builder.private_signal("claims_reinsurer_attachment_excess")?;
    builder.bind(
        "claims_reinsurer_attachment_excess",
        select_expr(
            signal_expr("claims_reinsurer_attached_bit"),
            sub_expr(
                signal_expr("claims_capped_payout_amount"),
                signal_expr(&policy_array_name("reinsurer_sharing_parameter", 1)),
            ),
            const_expr(0),
        ),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "claims_reinsurer_share_base",
        "claims_reinsurer_attachment_excess",
        &policy_array_name("reinsurer_sharing_parameter", 2),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_reinsurer_share_base",
    )?;
    builder.private_signal("claims_reinsurer_share_raw")?;
    builder.bind(
        "claims_reinsurer_share_raw",
        mul_expr(
            signal_expr("claims_reinsurer_share_base"),
            signal_expr(&policy_array_name("reinsurer_sharing_parameter", 0)),
        ),
    )?;
    builder.append_exact_division_constraints(
        signal_expr("claims_reinsurer_share_raw"),
        signal_expr("__claims_scale"),
        "claims_reinsurer_share_amount",
        "claims_reinsurer_share_remainder",
        "claims_reinsurer_share_slack",
        &BigInt::from(CLAIMS_FIXED_POINT_SCALE),
        "claims_reinsurer_share",
    )?;

    let payout_commitment_inner = builder.append_poseidon_hash(
        "claims_payout_commitment_inner",
        [
            const_expr(CLAIMS_DOMAIN_PAYOUT),
            signal_expr("claims_capped_payout_amount"),
            signal_expr(&governance_array_name("settlement_blinding", 0)),
            signal_expr(&governance_array_name("settlement_blinding", 1)),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("payout_amount_commitment"),
        signal_expr(&payout_commitment_inner),
    )?;
    let reserve_commitment_inner = builder.append_poseidon_hash(
        "claims_reserve_commitment_inner",
        [
            const_expr(CLAIMS_DOMAIN_RESERVE),
            signal_expr("claims_reserve_amount"),
            signal_expr(&governance_array_name("settlement_blinding", 0)),
            signal_expr(&governance_array_name("settlement_blinding", 1)),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("reserve_amount_commitment"),
        signal_expr(&reserve_commitment_inner),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_structured_inconsistency_score"),
        signal_expr(&governance_name("dispute_escalation_threshold")),
        "claims_inconsistency_threshold_hit_bit",
        "claims_inconsistency_threshold_hit_slack",
        CLAIMS_SCORE_CAP,
        "claims_inconsistency_threshold_hit",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_fraud_evidence_score"),
        signal_expr(&governance_name("fraud_review_threshold")),
        "claims_fraud_threshold_hit_bit",
        "claims_fraud_threshold_hit_slack",
        CLAIMS_SCORE_CAP,
        "claims_fraud_threshold_hit",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_capped_payout_amount"),
        signal_expr(&governance_name("manual_review_threshold")),
        "claims_manual_review_payout_hit_bit",
        "claims_manual_review_payout_hit_slack",
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_manual_review_payout_hit",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_reserve_amount"),
        signal_expr(&governance_name("manual_review_threshold")),
        "claims_manual_review_reserve_hit_bit",
        "claims_manual_review_reserve_hit_slack",
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_manual_review_reserve_hit",
    )?;
    append_boolean_or(
        &mut builder,
        "claims_manual_review_hit_bit",
        signal_expr("claims_manual_review_payout_hit_bit"),
        signal_expr("claims_manual_review_reserve_hit_bit"),
    )?;
    builder.private_signal("claims_policy_ineligible_bit")?;
    builder.bind(
        "claims_policy_ineligible_bit",
        sub_expr(const_expr(1), signal_expr("claims_policy_eligible_bit")),
    )?;
    builder.constrain_boolean("claims_policy_ineligible_bit")?;
    builder.private_signal("claims_not_inconsistency_bit")?;
    builder.bind(
        "claims_not_inconsistency_bit",
        sub_expr(const_expr(1), signal_expr("claims_inconsistency_threshold_hit_bit")),
    )?;
    builder.constrain_boolean("claims_not_inconsistency_bit")?;
    builder.private_signal("claims_not_fraud_review_bit")?;
    builder.bind(
        "claims_not_fraud_review_bit",
        sub_expr(const_expr(1), signal_expr("claims_fraud_threshold_hit_bit")),
    )?;
    builder.constrain_boolean("claims_not_fraud_review_bit")?;

    builder.private_signal("claims_action_deny_policy_bit")?;
    builder.bind("claims_action_deny_policy_bit", signal_expr("claims_policy_ineligible_bit"))?;
    builder.constrain_boolean("claims_action_deny_policy_bit")?;
    append_boolean_and(
        &mut builder,
        "claims_action_deny_inconsistency_bit",
        signal_expr("claims_policy_eligible_bit"),
        signal_expr("claims_inconsistency_threshold_hit_bit"),
    )?;
    builder.private_signal("claims_action_can_review_bit")?;
    builder.bind(
        "claims_action_can_review_bit",
        mul_expr(
            signal_expr("claims_policy_eligible_bit"),
            signal_expr("claims_not_inconsistency_bit"),
        ),
    )?;
    builder.constrain_boolean("claims_action_can_review_bit")?;
    append_boolean_and(
        &mut builder,
        "claims_action_escalate_bit",
        signal_expr("claims_action_can_review_bit"),
        signal_expr("claims_fraud_threshold_hit_bit"),
    )?;
    builder.private_signal("claims_action_manual_pre_bit")?;
    builder.bind(
        "claims_action_manual_pre_bit",
        mul_expr(
            signal_expr("claims_action_can_review_bit"),
            signal_expr("claims_not_fraud_review_bit"),
        ),
    )?;
    builder.constrain_boolean("claims_action_manual_pre_bit")?;
    append_boolean_and(
        &mut builder,
        "claims_action_manual_review_bit",
        signal_expr("claims_action_manual_pre_bit"),
        signal_expr("claims_manual_review_hit_bit"),
    )?;
    builder.private_signal("claims_action_non_auto_sum")?;
    builder.bind(
        "claims_action_non_auto_sum",
        add_expr(vec![
            signal_expr("claims_action_deny_policy_bit"),
            signal_expr("claims_action_deny_inconsistency_bit"),
            signal_expr("claims_action_escalate_bit"),
            signal_expr("claims_action_manual_review_bit"),
        ]),
    )?;
    builder.constrain_range("claims_action_non_auto_sum", 3)?;
    builder.private_signal("claims_action_approve_and_settle_bit")?;
    builder.bind(
        "claims_action_approve_and_settle_bit",
        sub_expr(const_expr(1), signal_expr("claims_action_non_auto_sum")),
    )?;
    builder.constrain_boolean("claims_action_approve_and_settle_bit")?;

    builder.constrain_equal(
        signal_expr("action_class_code"),
        add_expr(vec![
            mul_expr(
                signal_expr("claims_action_manual_review_bit"),
                const_expr(CLAIMS_ACTION_APPROVE_WITH_MANUAL_REVIEW),
            ),
            mul_expr(
                signal_expr("claims_action_escalate_bit"),
                const_expr(CLAIMS_ACTION_ESCALATE_FOR_INVESTIGATION),
            ),
            mul_expr(
                signal_expr("claims_action_deny_policy_bit"),
                const_expr(CLAIMS_ACTION_DENY_FOR_POLICY_RULE),
            ),
            mul_expr(
                signal_expr("claims_action_deny_inconsistency_bit"),
                const_expr(CLAIMS_ACTION_DENY_FOR_INCONSISTENCY),
            ),
        ]),
    )?;
    builder.constrain_range("action_class_code", 3)?;
    builder.constrain_equal(
        signal_expr("human_review_required"),
        sub_expr(
            const_expr(1),
            signal_expr("claims_action_approve_and_settle_bit"),
        ),
    )?;
    builder.constrain_boolean("human_review_required")?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_capped_payout_amount"),
        const_expr(1),
        "claims_payout_nonzero_bit",
        "claims_payout_nonzero_slack",
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_payout_nonzero",
    )?;
    builder.constrain_equal(
        signal_expr("eligible_for_midnight_settlement"),
        mul_expr(
            signal_expr("claims_action_approve_and_settle_bit"),
            signal_expr("claims_payout_nonzero_bit"),
        ),
    )?;
    builder.constrain_boolean("eligible_for_midnight_settlement")?;

    let settlement_instruction_inner = builder.append_poseidon_hash(
        "claims_settlement_instruction_inner",
        [
            signal_expr("claims_capped_payout_amount"),
            signal_expr("claims_reserve_amount"),
            signal_expr("action_class_code"),
            signal_expr(&governance_name("claimant_payout_destination_commitment")),
        ],
    )?;
    let settlement_instruction_outer = builder.append_poseidon_hash(
        "claims_settlement_instruction_outer",
        [
            signal_expr(&settlement_instruction_inner),
            signal_expr(&governance_name("insurer_reserve_account_commitment")),
            signal_expr(&governance_array_name("settlement_blinding", 0)),
            signal_expr(&governance_array_name("settlement_blinding", 1)),
        ],
    )?;
    let settlement_instruction_binding = builder.append_poseidon_hash(
        "claims_settlement_instruction_binding",
        [
            signal_expr(&settlement_instruction_outer),
            signal_expr("claim_packet_commitment"),
            signal_expr("coverage_decision_commitment"),
            signal_expr(&governance_array_name("public_disclosure_blinding", 1)),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("settlement_instruction_commitment"),
        signal_expr(&settlement_instruction_binding),
    )?;
    append_square_nonlinear_anchor(&mut builder, "claims_report_delay_margin_shifted")?;
    for index in 0..PRIVATE_CLAIMS_MAX_LINE_ITEMS {
        append_square_nonlinear_anchor(&mut builder, &format!("claims_replacement_gap_{index}"))?;
        append_square_nonlinear_anchor(&mut builder, &format!("claims_invoice_gap_{index}"))?;
        append_square_nonlinear_anchor(&mut builder, &format!("claims_quantity_gap_{index}"))?;
    }
    for signal in [
        "claims_total_invoice_amount",
        "claims_total_price_baseline",
        "claims_policy_mismatch_score",
        "claims_evidence_completeness_score",
        "claims_duplication_score",
    ] {
        append_square_nonlinear_anchor(&mut builder, signal)?;
    }
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        append_square_nonlinear_anchor(&mut builder, &format!("claims_digest_present_{index}"))?;
    }

    builder.build()
}

pub fn build_settlement_binding_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("claims_truth_settlement_binding_v1", CLAIMS_FIELD);
    for name in settlement_input_names() {
        builder.private_input(&name)?;
    }
    for name in [
        "claims_settlement_settlement_instruction_commitment",
        "claims_settlement_dispute_hold_commitment",
        "claims_settlement_reinsurer_release_commitment",
        "claims_settlement_finality_flag",
    ] {
        builder.public_output(name)?;
    }
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_settlement_fraud_evidence_score"),
        signal_expr("claims_settlement_dispute_threshold"),
        "claims_settlement_hold_by_fraud_bit",
        "claims_settlement_hold_by_fraud_slack",
        CLAIMS_SCORE_CAP,
        "claims_settlement_hold_by_fraud",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_settlement_action_class_code"),
        const_expr(1),
        "claims_settlement_non_auto_action_bit",
        "claims_settlement_non_auto_action_slack",
        8,
        "claims_settlement_non_auto_action",
    )?;
    append_boolean_or(
        &mut builder,
        "claims_settlement_hold_required_bit",
        signal_expr("claims_settlement_hold_by_fraud_bit"),
        signal_expr("claims_settlement_non_auto_action_bit"),
    )?;
    builder.constrain_equal(
        signal_expr("claims_settlement_finality_flag"),
        sub_expr(const_expr(1), signal_expr("claims_settlement_hold_required_bit")),
    )?;
    let settlement_commitment = builder.append_poseidon_hash(
        "claims_settlement_instruction_commitment_inner",
        [
            signal_expr("claims_settlement_payout_amount"),
            signal_expr("claims_settlement_reserve_amount"),
            signal_expr("claims_settlement_action_class_code"),
            signal_expr("claims_settlement_claimant_destination_commitment"),
        ],
    )?;
    let settlement_commitment_outer = builder.append_poseidon_hash(
        "claims_settlement_instruction_commitment_outer",
        [
            signal_expr(&settlement_commitment),
            signal_expr("claims_settlement_insurer_reserve_account_commitment"),
            signal_expr("claims_settlement_blinding_0"),
            signal_expr("claims_settlement_blinding_1"),
        ],
    )?;
    let settlement_commitment_binding = builder.append_poseidon_hash(
        "claims_settlement_instruction_commitment_binding",
        [
            signal_expr(&settlement_commitment_outer),
            signal_expr("claims_settlement_claim_packet_commitment"),
            signal_expr("claims_settlement_coverage_decision_commitment"),
            signal_expr("claims_settlement_public_blinding_1"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("claims_settlement_settlement_instruction_commitment"),
        signal_expr(&settlement_commitment_binding),
    )?;
    let dispute_hold_commitment = builder.append_poseidon_hash(
        "claims_settlement_dispute_hold_commitment_inner",
        [
            const_expr(CLAIMS_DOMAIN_SETTLEMENT),
            signal_expr("claims_settlement_action_class_code"),
            signal_expr("claims_settlement_fraud_evidence_score"),
            signal_expr("claims_settlement_dispute_threshold"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("claims_settlement_dispute_hold_commitment"),
        signal_expr(&dispute_hold_commitment),
    )?;
    let reinsurer_release_commitment = builder.append_poseidon_hash(
        "claims_settlement_reinsurer_release_commitment_inner",
        [
            signal_expr("claims_settlement_reinsurer_share_amount"),
            signal_expr("claims_settlement_payout_amount"),
            signal_expr("claims_settlement_reinsurer_participation_commitment"),
            signal_expr("claims_settlement_public_blinding_0"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("claims_settlement_reinsurer_release_commitment"),
        signal_expr(&reinsurer_release_commitment),
    )?;
    builder.build()
}

pub fn build_disclosure_projection_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("claims_truth_disclosure_projection_v1", CLAIMS_FIELD);
    for name in disclosure_input_names() {
        builder.private_input(&name)?;
    }
    for name in [
        "claims_disclosure_role_code",
        "claims_disclosure_view_commitment",
        "claims_disclosure_value_a",
        "claims_disclosure_value_b",
    ] {
        builder.public_output(name)?;
    }
    for role in [
        "claims_disclosure_role_auditor",
        "claims_disclosure_role_regulator",
        "claims_disclosure_role_reinsurer",
        "claims_disclosure_role_claimant",
        "claims_disclosure_role_investigator",
    ] {
        builder.constrain_boolean(role)?;
    }
    builder.private_signal("claims_disclosure_role_sum")?;
    builder.bind(
        "claims_disclosure_role_sum",
        add_expr(vec![
            signal_expr("claims_disclosure_role_auditor"),
            signal_expr("claims_disclosure_role_regulator"),
            signal_expr("claims_disclosure_role_reinsurer"),
            signal_expr("claims_disclosure_role_claimant"),
            signal_expr("claims_disclosure_role_investigator"),
        ]),
    )?;
    builder.constrain_equal(signal_expr("claims_disclosure_role_sum"), const_expr(1))?;
    builder.constrain_equal(
        signal_expr("claims_disclosure_role_code"),
        add_expr(vec![
            mul_expr(signal_expr("claims_disclosure_role_regulator"), const_expr(1)),
            mul_expr(signal_expr("claims_disclosure_role_reinsurer"), const_expr(2)),
            mul_expr(signal_expr("claims_disclosure_role_claimant"), const_expr(3)),
            mul_expr(signal_expr("claims_disclosure_role_investigator"), const_expr(4)),
        ]),
    )?;
    builder.constrain_range("claims_disclosure_role_code", 3)?;
    builder.private_signal("claims_disclosure_value_a_private")?;
    builder.bind(
        "claims_disclosure_value_a_private",
        add_expr(vec![
            mul_expr(
                signal_expr("claims_disclosure_role_auditor"),
                signal_expr("claims_disclosure_payout_commitment"),
            ),
            mul_expr(
                signal_expr("claims_disclosure_role_regulator"),
                signal_expr("claims_disclosure_reserve_commitment"),
            ),
            mul_expr(
                signal_expr("claims_disclosure_role_reinsurer"),
                signal_expr("claims_disclosure_claim_packet_commitment"),
            ),
            mul_expr(
                signal_expr("claims_disclosure_role_claimant"),
                signal_expr("claims_disclosure_settlement_commitment"),
            ),
            mul_expr(
                signal_expr("claims_disclosure_role_investigator"),
                signal_expr("claims_disclosure_fraud_score_commitment"),
            ),
        ]),
    )?;
    builder.private_signal("claims_disclosure_value_b_private")?;
    builder.bind(
        "claims_disclosure_value_b_private",
        add_expr(vec![
            mul_expr(
                signal_expr("claims_disclosure_role_auditor"),
                signal_expr("claims_disclosure_consistency_score_commitment"),
            ),
            mul_expr(
                signal_expr("claims_disclosure_role_regulator"),
                signal_expr("claims_disclosure_fraud_score_commitment"),
            ),
            mul_expr(
                signal_expr("claims_disclosure_role_reinsurer"),
                signal_expr("claims_disclosure_reserve_commitment"),
            ),
            mul_expr(
                signal_expr("claims_disclosure_role_claimant"),
                signal_expr("claims_disclosure_payout_commitment"),
            ),
            mul_expr(
                signal_expr("claims_disclosure_role_investigator"),
                signal_expr("claims_disclosure_coverage_decision_commitment"),
            ),
        ]),
    )?;
    builder.constrain_equal(
        signal_expr("claims_disclosure_value_a"),
        signal_expr("claims_disclosure_value_a_private"),
    )?;
    builder.constrain_equal(
        signal_expr("claims_disclosure_value_b"),
        signal_expr("claims_disclosure_value_b_private"),
    )?;
    let view_commitment = builder.append_poseidon_hash(
        "claims_disclosure_view_commitment_inner",
        [
            const_expr(CLAIMS_DOMAIN_DISCLOSURE),
            signal_expr("claims_disclosure_role_code"),
            signal_expr("claims_disclosure_value_a_private"),
            signal_expr("claims_disclosure_value_b_private"),
        ],
    )?;
    let view_commitment_outer = builder.append_poseidon_hash(
        "claims_disclosure_view_commitment_outer",
        [
            signal_expr(&view_commitment),
            signal_expr("claims_disclosure_reinsurer_share_amount"),
            signal_expr("claims_disclosure_public_blinding_0"),
            signal_expr("claims_disclosure_public_blinding_1"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("claims_disclosure_view_commitment"),
        signal_expr(&view_commitment_outer),
    )?;
    append_square_nonlinear_anchor(&mut builder, "claims_disclosure_role_sum")?;
    builder.build()
}

pub fn build_batch_shard_handoff_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("claims_truth_batch_shard_handoff_v1", CLAIMS_FIELD);
    for name in shard_input_names() {
        builder.private_input(&name)?;
    }
    for name in [
        "claims_shard_batch_root_commitment",
        "claims_shard_assignment_commitment",
    ] {
        builder.public_output(name)?;
    }
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("claims_shard_shard_count"),
        const_expr(2),
        "claims_shard_count_valid_bit",
        "claims_shard_count_valid_slack",
        CLAIMS_SHARD_COUNT_MAX,
        "claims_shard_count_valid",
    )?;
    builder.constrain_equal(signal_expr("claims_shard_count_valid_bit"), const_expr(1))?;
    let mut assignment_names = Vec::new();
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        builder.append_exact_division_constraints(
            signal_expr(&format!("claims_shard_claim_commitment_{index}")),
            signal_expr("claims_shard_shard_count"),
            &format!("claims_shard_assignment_quotient_{index}"),
            &format!("claims_shard_assignment_{index}"),
            &format!("claims_shard_assignment_slack_{index}"),
            &BigInt::from(CLAIMS_SHARD_COUNT_MAX),
            &format!("claims_shard_assignment_{index}"),
        )?;
        assignment_names.push(format!("claims_shard_assignment_{index}"));
    }
    let batch_commitment = builder.append_poseidon_hash(
        "claims_shard_batch_root_commitment_inner",
        [
            const_expr(CLAIMS_DOMAIN_SHARD_BATCH),
            signal_expr("claims_shard_claim_commitment_0"),
            signal_expr("claims_shard_claim_commitment_1"),
            signal_expr("claims_shard_claim_commitment_2"),
        ],
    )?;
    let batch_commitment_outer = builder.append_poseidon_hash(
        "claims_shard_batch_root_commitment_outer",
        [
            signal_expr(&batch_commitment),
            signal_expr("claims_shard_claim_commitment_3"),
            signal_expr("claims_shard_blinding_0"),
            signal_expr("claims_shard_blinding_1"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("claims_shard_batch_root_commitment"),
        signal_expr(&batch_commitment_outer),
    )?;
    let assignment_commitment = builder.append_poseidon_hash(
        "claims_shard_assignment_commitment_inner",
        [
            signal_expr(&assignment_names[0]),
            signal_expr(&assignment_names[1]),
            signal_expr(&assignment_names[2]),
            signal_expr(&assignment_names[3]),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("claims_shard_assignment_commitment"),
        signal_expr(&assignment_commitment),
    )?;
    builder.build()
}

fn bigint_from_map(values: &BTreeMap<String, FieldElement>, name: &str) -> BigInt {
    values
        .get(name)
        .cloned()
        .unwrap_or(FieldElement::ZERO)
        .as_bigint()
}

fn write_square_nonlinear_anchor(values: &mut BTreeMap<String, FieldElement>, signal: &str) {
    let value = bigint_from_map(values, signal);
    write_value(values, format!("{signal}_square_anchor"), value.clone() * value);
}

fn u64_from_map(values: &BTreeMap<String, FieldElement>, name: &str) -> u64 {
    bigint_from_map(values, name).try_into().unwrap_or_default()
}

fn compute_core_support_values(
    request: &ClaimsTruthPrivateInputsV1,
) -> ZkfResult<(BTreeMap<String, FieldElement>, ClaimsCoreComputation)> {
    let mut values = flatten_private_inputs(request)?;
    let input_names = claims_truth_private_input_names_v1();
    let claim_packet_commitment =
        write_private_input_anchor_chain(&mut values, &input_names, "claims_packet_anchor")?;

    let coverage_count = request
        .policy
        .covered_peril_flags
        .iter()
        .zip(request.claim_event.peril_classification_flags.iter())
        .map(|(policy_flag, claim_flag)| policy_flag * claim_flag)
        .sum::<u64>();
    let exclusion_count = request
        .policy
        .exclusion_flags
        .iter()
        .zip(request.claim_event.peril_classification_flags.iter())
        .map(|(policy_flag, claim_flag)| policy_flag * claim_flag)
        .sum::<u64>();
    let claim_category_count = request
        .claim_event
        .claimed_loss_categories
        .iter()
        .sum::<u64>();
    let incident_after_effective = write_geq_support(
        &mut values,
        "claims_within_period_incident_after_effective_bit",
        "claims_within_period_incident_after_effective_slack",
        &BigInt::from(request.claim_event.incident_timestamp),
        &BigInt::from(request.policy.policy_effective_timestamp),
        CLAIMS_TIMESTAMP_BOUND,
        "claims_within_period_incident_after_effective",
    )?;
    let expiration_after_incident = write_geq_support(
        &mut values,
        "claims_within_period_expiration_after_incident_bit",
        "claims_within_period_expiration_after_incident_slack",
        &BigInt::from(request.policy.policy_expiration_timestamp),
        &BigInt::from(request.claim_event.incident_timestamp),
        CLAIMS_TIMESTAMP_BOUND,
        "claims_within_period_expiration_after_incident",
    )?;
    let covered_peril_supported = write_geq_support(
        &mut values,
        "claims_covered_peril_supported_bit",
        "claims_covered_peril_supported_slack",
        &BigInt::from(coverage_count),
        &BigInt::from(1u8),
        PRIVATE_CLAIMS_MAX_PERILS as u64 + 1,
        "claims_covered_peril_supported",
    )?;
    let peril_excluded = write_geq_support(
        &mut values,
        "claims_peril_excluded_bit",
        "claims_peril_excluded_slack",
        &BigInt::from(exclusion_count),
        &BigInt::from(1u8),
        PRIVATE_CLAIMS_MAX_PERILS as u64 + 1,
        "claims_peril_excluded",
    )?;
    let claim_category_present = write_geq_support(
        &mut values,
        "claims_claim_category_present_bit",
        "claims_claim_category_present_slack",
        &BigInt::from(claim_category_count),
        &BigInt::from(1u8),
        PRIVATE_CLAIMS_MAX_PERILS as u64 + 1,
        "claims_claim_category_present",
    )?;
    let within_period = incident_after_effective && expiration_after_incident;
    let policy_eligible = within_period && covered_peril_supported && !peril_excluded && claim_category_present;
    write_value(&mut values, "claims_covered_peril_count", coverage_count);
    write_value(&mut values, "claims_excluded_peril_count", exclusion_count);
    write_value(&mut values, "claims_claimed_category_count", claim_category_count);
    write_bool_value(&mut values, "claims_within_period_bit", within_period);
    write_bool_value(
        &mut values,
        "claims_not_peril_excluded_bit",
        !peril_excluded,
    );
    write_bool_value(
        &mut values,
        "claims_policy_eligible_pre_category_bit",
        within_period && covered_peril_supported,
    );
    write_bool_value(
        &mut values,
        "claims_policy_eligible_pre_exclusion_bit",
        within_period && covered_peril_supported && !peril_excluded,
    );
    write_bool_value(&mut values, "claims_policy_eligible_bit", policy_eligible);
    let coverage_decision_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_coverage_commitment",
        [
            &BigInt::from(CLAIMS_DOMAIN_COVERAGE),
            &BigInt::from(policy_eligible as u8),
            &BigInt::from(within_period as u8),
            &BigInt::from(exclusion_count),
        ],
    )?;

    let reported_after_incident = write_geq_support(
        &mut values,
        "claims_reported_after_incident_bit",
        "claims_reported_after_incident_slack",
        &BigInt::from(request.claim_event.reported_timestamp),
        &BigInt::from(request.claim_event.incident_timestamp),
        CLAIMS_TIMESTAMP_BOUND,
        "claims_reported_after_incident",
    )?;
    let report_delay = request
        .claim_event
        .reported_timestamp
        .saturating_sub(request.claim_event.incident_timestamp);
    write_value(&mut values, "claims_report_delay", report_delay);
    write_value(
        &mut values,
        "claims_report_delay_margin_shifted",
        report_delay + CLAIMS_SIGNED_MARGIN_OFFSET
            - request.analysis_inputs.chronology_consistency_threshold,
    );

    let digest_manifest = write_private_input_anchor_chain(
        &mut values,
        &[
            evidence_name("photo_analysis_result_digest"),
            evidence_name("document_extraction_result_digest"),
            evidence_name("authority_report_reference_digest"),
            evidence_array_name("telematics_summary", 0),
        ],
        "claims_evidence_anchor",
    )?;

    let mut total_estimate_amount = 0u64;
    let mut total_invoice_amount = 0u64;
    let mut total_replacement_amount = 0u64;
    let mut total_valuation_gap = 0u64;
    let mut total_quantity_gap = 0u64;
    for index in 0..PRIVATE_CLAIMS_MAX_LINE_ITEMS {
        let estimate = &request.evidence.repair_estimate_line_items[index];
        let invoice = &request.evidence.invoice_line_items[index];
        let estimate_total = estimate.quantity.saturating_mul(estimate.unit_amount);
        let replacement_min = estimate_total.min(estimate.replacement_cost);
        let replacement_max = estimate_total.max(estimate.replacement_cost);
        let invoice_min = estimate_total.min(invoice.invoice_amount);
        let invoice_max = estimate_total.max(invoice.invoice_amount);
        let quantity_min = estimate.quantity.min(invoice.quantity);
        let quantity_max = estimate.quantity.max(invoice.quantity);
        let replacement_gap = replacement_max - replacement_min;
        let invoice_gap = invoice_max - invoice_min;
        let quantity_gap = quantity_max - quantity_min;
        total_estimate_amount = total_estimate_amount.saturating_add(estimate_total);
        total_invoice_amount = total_invoice_amount.saturating_add(invoice.invoice_amount);
        total_replacement_amount = total_replacement_amount.saturating_add(estimate.replacement_cost);
        total_valuation_gap = total_valuation_gap
            .saturating_add(replacement_gap)
            .saturating_add(invoice_gap);
        total_quantity_gap = total_quantity_gap.saturating_add(quantity_gap);
        write_value(&mut values, format!("claims_estimate_total_{index}"), estimate_total);
        let prefix = format!("claims_replacement_min_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate_total),
            &BigInt::from(estimate.replacement_cost),
            CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("claims_replacement_max_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate_total),
            &BigInt::from(estimate.replacement_cost),
            CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("claims_invoice_amount_min_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate_total),
            &BigInt::from(invoice.invoice_amount),
            CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("claims_invoice_amount_max_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate_total),
            &BigInt::from(invoice.invoice_amount),
            CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("claims_invoice_quantity_min_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate.quantity),
            &BigInt::from(invoice.quantity),
            CLAIMS_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("claims_invoice_quantity_max_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate.quantity),
            &BigInt::from(invoice.quantity),
            CLAIMS_VALUE_BOUND,
            &prefix,
        )?;
        write_value(&mut values, format!("claims_replacement_gap_{index}"), replacement_gap);
        write_value(&mut values, format!("claims_invoice_gap_{index}"), invoice_gap);
        write_value(&mut values, format!("claims_quantity_gap_{index}"), quantity_gap);
        write_value(&mut values, format!("claims_replacement_min_{index}"), replacement_min);
        write_value(&mut values, format!("claims_replacement_max_{index}"), replacement_max);
        write_value(&mut values, format!("claims_invoice_amount_min_{index}"), invoice_min);
        write_value(&mut values, format!("claims_invoice_amount_max_{index}"), invoice_max);
        write_value(&mut values, format!("claims_invoice_quantity_min_{index}"), quantity_min);
        write_value(&mut values, format!("claims_invoice_quantity_max_{index}"), quantity_max);
    }
    write_value(&mut values, "claims_total_estimate_amount", total_estimate_amount);
    write_value(&mut values, "claims_total_invoice_amount", total_invoice_amount);
    write_value(
        &mut values,
        "claims_total_replacement_amount",
        total_replacement_amount,
    );
    write_value(&mut values, "claims_total_valuation_gap", total_valuation_gap);
    write_value(&mut values, "claims_total_quantity_gap", total_quantity_gap);

    let total_price_baseline = request
        .analysis_inputs
        .price_deviation_baselines
        .iter()
        .copied()
        .sum::<u64>();
    let total_vendor_baseline = request
        .analysis_inputs
        .vendor_anomaly_baselines
        .iter()
        .copied()
        .sum::<u64>();
    let total_vendor_digest = request
        .evidence
        .vendor_attestation_digests
        .iter()
        .copied()
        .sum::<u64>();
    write_value(&mut values, "claims_total_price_baseline", total_price_baseline);
    write_value(&mut values, "claims_total_vendor_baseline", total_vendor_baseline);
    write_value(&mut values, "claims_total_vendor_digest", total_vendor_digest);
    let geographic_reasonable = write_geq_support(
        &mut values,
        "claims_geographic_reasonable_bit",
        "claims_geographic_reasonable_slack",
        &BigInt::from(request.analysis_inputs.geographic_reasonableness_threshold),
        &BigInt::from(request.claim_event.event_region_bucket),
        CLAIMS_UINT_BOUND,
        "claims_geographic_reasonable",
    )?;

    let mut duplicate_match_count = 0u64;
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        let lhs = request.claim_event.prior_claim_linkage_hashes[index];
        let rhs = request.analysis_inputs.duplicate_claim_candidate_hashes[index];
        let equal = request.claim_event.prior_claim_linkage_hashes[index]
            == request.analysis_inputs.duplicate_claim_candidate_hashes[index];
        if equal {
            duplicate_match_count += 1;
        }
        write_bool_value(
            &mut values,
            format!("claims_duplicate_match_{index}_eq"),
            equal,
        );
        write_value(
            &mut values,
            format!("claims_duplicate_match_{index}_diff"),
            BigInt::from(lhs) - BigInt::from(rhs),
        );
        let inv = if equal {
            FieldElement::ZERO
        } else {
            BigIntFieldValue::new(CLAIMS_FIELD, BigInt::from(lhs) - BigInt::from(rhs))
                .inv()
                .map(|value| value.to_field_element())
                .unwrap_or(FieldElement::ZERO)
        };
        values.insert(format!("claims_duplicate_match_{index}_inv"), inv);
    }
    write_value(&mut values, "claims_duplicate_match_count", duplicate_match_count);

    let digest_presence_values = [
        BigInt::from(request.evidence.photo_analysis_result_digest),
        BigInt::from(request.evidence.document_extraction_result_digest),
        BigInt::from(request.evidence.authority_report_reference_digest),
        evidence_manifest_digest_bigint(&request.evidence.evidence_manifest_digest)?,
    ];
    let expected_digest_count = digest_presence_values.len() as u64;
    let mut complete_digest_count = 0u64;
    for (index, source) in digest_presence_values.iter().enumerate() {
        let prefix = format!("claims_digest_present_{index}_zero");
        let is_zero = source == &zero();
        write_equality_with_inverse_support(&mut values, source, &zero(), &prefix);
        let present = !is_zero;
        write_bool_value(&mut values, format!("claims_digest_present_{index}"), present);
        if present {
            complete_digest_count += 1;
        }
    }
    write_value(&mut values, "claims_complete_digest_count", complete_digest_count);

    let chronology_ratio = report_delay / request.analysis_inputs.chronology_consistency_threshold;
    let _chronology_remainder =
        report_delay % request.analysis_inputs.chronology_consistency_threshold;
    write_exact_division_support(
        &mut values,
        report_delay,
        request.analysis_inputs.chronology_consistency_threshold,
        "claims_chronology_ratio",
        "claims_chronology_ratio_remainder",
        "claims_chronology_ratio_slack",
        "claims_chronology_ratio",
    )?;
    let chronology_score = (chronology_ratio.saturating_mul(1_000)
        + u64::from(!reported_after_incident) * 2_000)
        .min(CLAIMS_COMPONENT_SCORE_CAP);
    write_value(&mut values, "claims_chronology_score_raw", chronology_ratio * 1_000);
    write_geq_support(
        &mut values,
        "claims_chronology_score_geq_bit",
        "claims_chronology_score_geq_slack",
        &BigInt::from(chronology_ratio.saturating_mul(1_000)),
        &BigInt::from(CLAIMS_COMPONENT_SCORE_CAP),
        CLAIMS_RATIO_BOUND,
        "claims_chronology_score",
    )?;
    write_value(&mut values, "claims_chronology_score", chronology_score);

    write_exact_division_support(
        &mut values,
        total_valuation_gap,
        request.analysis_inputs.valuation_tolerance_threshold,
        "claims_valuation_ratio",
        "claims_valuation_ratio_remainder",
        "claims_valuation_ratio_slack",
        "claims_valuation_ratio",
    )?;
    let valuation_ratio = total_valuation_gap / request.analysis_inputs.valuation_tolerance_threshold;
    let valuation_score = valuation_ratio.saturating_mul(1_000).min(CLAIMS_COMPONENT_SCORE_CAP);
    write_value(&mut values, "claims_valuation_score_raw", valuation_ratio * 1_000);
    write_geq_support(
        &mut values,
        "claims_valuation_score_geq_bit",
        "claims_valuation_score_geq_slack",
        &BigInt::from(valuation_ratio.saturating_mul(1_000)),
        &BigInt::from(CLAIMS_COMPONENT_SCORE_CAP),
        CLAIMS_RATIO_BOUND,
        "claims_valuation_score",
    )?;
    write_value(&mut values, "claims_valuation_score", valuation_score);

    write_exact_division_support(
        &mut values,
        total_quantity_gap,
        request.analysis_inputs.quantity_tolerance_threshold,
        "claims_quantity_ratio",
        "claims_quantity_ratio_remainder",
        "claims_quantity_ratio_slack",
        "claims_quantity_ratio",
    )?;
    let quantity_ratio = total_quantity_gap / request.analysis_inputs.quantity_tolerance_threshold;
    let quantity_score = quantity_ratio.saturating_mul(1_000).min(CLAIMS_COMPONENT_SCORE_CAP);
    write_value(&mut values, "claims_quantity_score_raw", quantity_ratio * 1_000);
    write_geq_support(
        &mut values,
        "claims_quantity_score_geq_bit",
        "claims_quantity_score_geq_slack",
        &BigInt::from(quantity_ratio.saturating_mul(1_000)),
        &BigInt::from(CLAIMS_COMPONENT_SCORE_CAP),
        CLAIMS_RATIO_BOUND,
        "claims_quantity_score",
    )?;
    write_value(&mut values, "claims_quantity_score", quantity_score);

    let vendor_gap = total_vendor_digest.abs_diff(total_vendor_baseline);
    write_geq_support(
        &mut values,
        "claims_vendor_gap_min_geq_bit",
        "claims_vendor_gap_min_geq_slack",
        &BigInt::from(total_vendor_digest),
        &BigInt::from(total_vendor_baseline),
        CLAIMS_HASH_BOUND,
        "claims_vendor_gap_min",
    )?;
    write_geq_support(
        &mut values,
        "claims_vendor_gap_max_geq_bit",
        "claims_vendor_gap_max_geq_slack",
        &BigInt::from(total_vendor_digest),
        &BigInt::from(total_vendor_baseline),
        CLAIMS_HASH_BOUND,
        "claims_vendor_gap_max",
    )?;
    write_value(
        &mut values,
        "claims_vendor_gap_min",
        total_vendor_digest.min(total_vendor_baseline),
    );
    write_value(
        &mut values,
        "claims_vendor_gap_max",
        total_vendor_digest.max(total_vendor_baseline),
    );
    write_value(&mut values, "claims_vendor_gap", vendor_gap);
    write_value(
        &mut values,
        "claims_total_vendor_baseline_plus_one",
        total_vendor_baseline + 1,
    );
    write_exact_division_support(
        &mut values,
        vendor_gap,
        total_vendor_baseline + 1,
        "claims_vendor_ratio",
        "claims_vendor_ratio_remainder",
        "claims_vendor_ratio_slack",
        "claims_vendor_ratio",
    )?;
    let vendor_ratio = vendor_gap / (total_vendor_baseline + 1);
    let vendor_score = vendor_ratio.saturating_mul(750).min(CLAIMS_COMPONENT_SCORE_CAP);
    write_value(&mut values, "claims_vendor_score_raw", vendor_ratio * 750);
    write_geq_support(
        &mut values,
        "claims_vendor_score_geq_bit",
        "claims_vendor_score_geq_slack",
        &BigInt::from(vendor_ratio.saturating_mul(750)),
        &BigInt::from(CLAIMS_COMPONENT_SCORE_CAP),
        CLAIMS_RATIO_BOUND,
        "claims_vendor_score",
    )?;
    write_value(&mut values, "claims_vendor_score", vendor_score);

    let policy_mismatch_score = (u64::from(!policy_eligible) * 5_000)
        .saturating_add(u64::from(peril_excluded) * 2_000);
    write_value(
        &mut values,
        "claims_policy_mismatch_score",
        policy_mismatch_score,
    );
    write_value(
        &mut values,
        "claims_expected_digest_count",
        expected_digest_count,
    );
    let missing_digest_count = expected_digest_count - complete_digest_count;
    write_value(&mut values, "claims_missing_digest_count", missing_digest_count);
    let evidence_completeness_score = missing_digest_count * 1_000;
    write_value(
        &mut values,
        "claims_evidence_completeness_score",
        evidence_completeness_score,
    );

    let structured_inconsistency_score = valuation_score
        .saturating_add(quantity_score)
        .saturating_add(u64::from(!geographic_reasonable) * 800)
        .saturating_add(u64::from(!reported_after_incident) * 2_000)
        .saturating_add(evidence_completeness_score)
        .min(CLAIMS_SCORE_CAP);
    write_value(
        &mut values,
        "claims_structured_inconsistency_score_raw",
        valuation_score
            .saturating_add(quantity_score)
            .saturating_add(u64::from(!geographic_reasonable) * 800)
            .saturating_add(u64::from(!reported_after_incident) * 2_000)
            .saturating_add(evidence_completeness_score),
    );
    write_geq_support(
        &mut values,
        "claims_structured_inconsistency_score_geq_bit",
        "claims_structured_inconsistency_score_geq_slack",
        &BigInt::from(
            valuation_score
                .saturating_add(quantity_score)
                .saturating_add(u64::from(!geographic_reasonable) * 800)
                .saturating_add(u64::from(!reported_after_incident) * 2_000)
                .saturating_add(evidence_completeness_score),
        ),
        &BigInt::from(CLAIMS_SCORE_CAP),
        CLAIMS_SCORE_CAP * 2,
        "claims_structured_inconsistency_score",
    )?;
    write_value(
        &mut values,
        "claims_structured_inconsistency_score",
        structured_inconsistency_score,
    );
    let consistency_score = CLAIMS_SCORE_CAP - structured_inconsistency_score;
    write_value(&mut values, "claims_consistency_score", consistency_score);

    let duplication_score = duplicate_match_count.saturating_mul(3_000);
    write_value(&mut values, "claims_duplication_score", duplication_score);
    let fraud_evidence_score = duplication_score
        .saturating_add(vendor_score)
        .saturating_add(chronology_score)
        .saturating_add(policy_mismatch_score)
        .min(CLAIMS_SCORE_CAP);
    write_value(
        &mut values,
        "claims_fraud_evidence_score_raw",
        duplication_score
            .saturating_add(vendor_score)
            .saturating_add(chronology_score)
            .saturating_add(policy_mismatch_score),
    );
    write_geq_support(
        &mut values,
        "claims_fraud_evidence_score_geq_bit",
        "claims_fraud_evidence_score_geq_slack",
        &BigInt::from(
            duplication_score
                .saturating_add(vendor_score)
                .saturating_add(chronology_score)
                .saturating_add(policy_mismatch_score),
        ),
        &BigInt::from(CLAIMS_SCORE_CAP),
        CLAIMS_SCORE_CAP * 2,
        "claims_fraud_evidence_score",
    )?;
    write_value(
        &mut values,
        "claims_fraud_evidence_score",
        fraud_evidence_score,
    );

    let consistency_score_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_consistency_commitment",
        [
            &BigInt::from(CLAIMS_DOMAIN_CONSISTENCY),
            &BigInt::from(consistency_score),
            &BigInt::from(request.settlement_governance.public_disclosure_blinding_values[0]),
            &BigInt::from(request.settlement_governance.public_disclosure_blinding_values[1]),
        ],
    )?;
    let fraud_evidence_score_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_fraud_commitment",
        [
            &BigInt::from(CLAIMS_DOMAIN_FRAUD),
            &BigInt::from(fraud_evidence_score),
            &BigInt::from(request.settlement_governance.public_disclosure_blinding_values[0]),
            &BigInt::from(request.settlement_governance.public_disclosure_blinding_values[1]),
        ],
    )?;

    let covered_amount_before_deductible = total_estimate_amount.min(total_replacement_amount);
    write_geq_support(
        &mut values,
        "claims_covered_amount_before_deductible_geq_bit",
        "claims_covered_amount_before_deductible_geq_slack",
        &BigInt::from(total_estimate_amount),
        &BigInt::from(total_replacement_amount),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_covered_amount_before_deductible",
    )?;
    write_value(
        &mut values,
        "claims_covered_amount_before_deductible",
        covered_amount_before_deductible,
    );
    let deductible_applies = write_geq_support(
        &mut values,
        "claims_deductible_applies_bit",
        "claims_deductible_applies_slack",
        &BigInt::from(covered_amount_before_deductible),
        &BigInt::from(request.policy.deductible_schedule[0]),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_deductible_applies",
    )?;
    let deductible_adjusted_amount = if deductible_applies {
        covered_amount_before_deductible - request.policy.deductible_schedule[0]
    } else {
        0
    };
    write_value(
        &mut values,
        "claims_deductible_adjusted_amount",
        deductible_adjusted_amount,
    );
    let depreciation_raw =
        deductible_adjusted_amount.saturating_mul(request.policy.depreciation_rules[0]);
    write_value(&mut values, "claims_depreciation_raw", depreciation_raw);
    write_exact_division_support(
        &mut values,
        depreciation_raw,
        CLAIMS_FIXED_POINT_SCALE,
        "claims_depreciation_amount",
        "claims_depreciation_remainder",
        "claims_depreciation_slack",
        "claims_depreciation",
    )?;
    let depreciation_amount = depreciation_raw / CLAIMS_FIXED_POINT_SCALE;
    let depreciation_adjusted_amount = deductible_adjusted_amount.saturating_sub(depreciation_amount);
    write_value(
        &mut values,
        "claims_depreciation_adjusted_amount",
        depreciation_adjusted_amount,
    );
    write_geq_support(
        &mut values,
        "claims_capped_payout_amount_geq_bit",
        "claims_capped_payout_amount_geq_slack",
        &BigInt::from(depreciation_adjusted_amount),
        &BigInt::from(request.policy.payout_cap_schedule[0]),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_capped_payout_amount",
    )?;
    let payout_amount = depreciation_adjusted_amount.min(request.policy.payout_cap_schedule[0]);
    write_value(&mut values, "claims_capped_payout_amount", payout_amount);
    let reserve_margin_raw =
        payout_amount.saturating_mul(request.policy.reserve_policy_parameters[0]);
    write_value(&mut values, "claims_reserve_margin_raw", reserve_margin_raw);
    write_exact_division_support(
        &mut values,
        reserve_margin_raw,
        CLAIMS_FIXED_POINT_SCALE,
        "claims_reserve_margin_amount",
        "claims_reserve_margin_remainder",
        "claims_reserve_margin_slack",
        "claims_reserve_margin",
    )?;
    let reserve_margin_amount = reserve_margin_raw / CLAIMS_FIXED_POINT_SCALE;
    let reserve_amount_pre_floor = payout_amount.saturating_add(reserve_margin_amount);
    write_value(
        &mut values,
        "claims_reserve_amount_pre_floor",
        reserve_amount_pre_floor,
    );
    write_geq_support(
        &mut values,
        "claims_reserve_amount_geq_bit",
        "claims_reserve_amount_geq_slack",
        &BigInt::from(reserve_amount_pre_floor),
        &BigInt::from(request.policy.reserve_policy_parameters[1]),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_reserve_amount",
    )?;
    let reserve_amount = reserve_amount_pre_floor.max(request.policy.reserve_policy_parameters[1]);
    write_value(&mut values, "claims_reserve_amount", reserve_amount);

    let reinsurer_attached = write_geq_support(
        &mut values,
        "claims_reinsurer_attached_bit",
        "claims_reinsurer_attached_slack",
        &BigInt::from(payout_amount),
        &BigInt::from(request.policy.reinsurer_sharing_parameters[1]),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_reinsurer_attached",
    )?;
    let reinsurer_attachment_excess = if reinsurer_attached {
        payout_amount - request.policy.reinsurer_sharing_parameters[1]
    } else {
        0
    };
    write_value(
        &mut values,
        "claims_reinsurer_attachment_excess",
        reinsurer_attachment_excess,
    );
    write_geq_support(
        &mut values,
        "claims_reinsurer_share_base_geq_bit",
        "claims_reinsurer_share_base_geq_slack",
        &BigInt::from(reinsurer_attachment_excess),
        &BigInt::from(request.policy.reinsurer_sharing_parameters[2]),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_reinsurer_share_base",
    )?;
    let reinsurer_share_base =
        reinsurer_attachment_excess.min(request.policy.reinsurer_sharing_parameters[2]);
    write_value(
        &mut values,
        "claims_reinsurer_share_base",
        reinsurer_share_base,
    );
    let reinsurer_share_raw =
        reinsurer_share_base.saturating_mul(request.policy.reinsurer_sharing_parameters[0]);
    write_value(&mut values, "claims_reinsurer_share_raw", reinsurer_share_raw);
    write_exact_division_support(
        &mut values,
        reinsurer_share_raw,
        CLAIMS_FIXED_POINT_SCALE,
        "claims_reinsurer_share_amount",
        "claims_reinsurer_share_remainder",
        "claims_reinsurer_share_slack",
        "claims_reinsurer_share",
    )?;
    let reinsurer_share_amount = reinsurer_share_raw / CLAIMS_FIXED_POINT_SCALE;

    let payout_amount_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_payout_commitment_inner",
        [
            &BigInt::from(CLAIMS_DOMAIN_PAYOUT),
            &BigInt::from(payout_amount),
            &BigInt::from(request.settlement_governance.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_governance.settlement_blinding_values[1]),
        ],
    )?;
    let reserve_amount_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_reserve_commitment_inner",
        [
            &BigInt::from(CLAIMS_DOMAIN_RESERVE),
            &BigInt::from(reserve_amount),
            &BigInt::from(request.settlement_governance.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_governance.settlement_blinding_values[1]),
        ],
    )?;

    let inconsistency_hit = write_geq_support(
        &mut values,
        "claims_inconsistency_threshold_hit_bit",
        "claims_inconsistency_threshold_hit_slack",
        &BigInt::from(structured_inconsistency_score),
        &BigInt::from(request.settlement_governance.dispute_escalation_threshold),
        CLAIMS_SCORE_CAP,
        "claims_inconsistency_threshold_hit",
    )?;
    let fraud_hit = write_geq_support(
        &mut values,
        "claims_fraud_threshold_hit_bit",
        "claims_fraud_threshold_hit_slack",
        &BigInt::from(fraud_evidence_score),
        &BigInt::from(request.settlement_governance.fraud_review_threshold),
        CLAIMS_SCORE_CAP,
        "claims_fraud_threshold_hit",
    )?;
    let manual_payout_hit = write_geq_support(
        &mut values,
        "claims_manual_review_payout_hit_bit",
        "claims_manual_review_payout_hit_slack",
        &BigInt::from(payout_amount),
        &BigInt::from(request.settlement_governance.manual_review_threshold),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_manual_review_payout_hit",
    )?;
    let manual_reserve_hit = write_geq_support(
        &mut values,
        "claims_manual_review_reserve_hit_bit",
        "claims_manual_review_reserve_hit_slack",
        &BigInt::from(reserve_amount),
        &BigInt::from(request.settlement_governance.manual_review_threshold),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_manual_review_reserve_hit",
    )?;
    let manual_hit = manual_payout_hit || manual_reserve_hit;
    write_bool_value(&mut values, "claims_manual_review_hit_bit", manual_hit);
    write_bool_value(&mut values, "claims_policy_ineligible_bit", !policy_eligible);
    write_bool_value(
        &mut values,
        "claims_not_inconsistency_bit",
        !inconsistency_hit,
    );
    write_bool_value(&mut values, "claims_not_fraud_review_bit", !fraud_hit);
    let deny_policy_bit = !policy_eligible;
    let deny_inconsistency_bit = policy_eligible && inconsistency_hit;
    let escalate_bit = policy_eligible && !inconsistency_hit && fraud_hit;
    let manual_review_bit = policy_eligible && !inconsistency_hit && !fraud_hit && manual_hit;
    let approve_and_settle_bit =
        !deny_policy_bit && !deny_inconsistency_bit && !escalate_bit && !manual_review_bit;
    let action_class = if deny_policy_bit {
        ClaimsActionClassV1::DenyForPolicyRule
    } else if deny_inconsistency_bit {
        ClaimsActionClassV1::DenyForInconsistency
    } else if escalate_bit {
        ClaimsActionClassV1::EscalateForInvestigation
    } else if manual_review_bit {
        ClaimsActionClassV1::ApproveWithManualReview
    } else {
        ClaimsActionClassV1::ApproveAndSettle
    };
    let action_class_code = action_class.code();
    let action_non_auto_sum =
        u64::from(deny_policy_bit) + u64::from(deny_inconsistency_bit) + u64::from(escalate_bit)
            + u64::from(manual_review_bit);
    write_bool_value(&mut values, "claims_action_deny_policy_bit", deny_policy_bit);
    write_bool_value(
        &mut values,
        "claims_action_deny_inconsistency_bit",
        deny_inconsistency_bit,
    );
    write_bool_value(&mut values, "claims_action_can_review_bit", policy_eligible && !inconsistency_hit);
    write_bool_value(&mut values, "claims_action_escalate_bit", escalate_bit);
    write_bool_value(
        &mut values,
        "claims_action_manual_pre_bit",
        policy_eligible && !inconsistency_hit && !fraud_hit,
    );
    write_bool_value(
        &mut values,
        "claims_action_manual_review_bit",
        manual_review_bit,
    );
    write_value(&mut values, "claims_action_non_auto_sum", action_non_auto_sum);
    write_bool_value(
        &mut values,
        "claims_action_approve_and_settle_bit",
        approve_and_settle_bit,
    );
    write_value(&mut values, "action_class_code", action_class_code);
    let human_review_required = !approve_and_settle_bit;
    write_bool_value(&mut values, "human_review_required", human_review_required);
    let payout_nonzero = write_geq_support(
        &mut values,
        "claims_payout_nonzero_bit",
        "claims_payout_nonzero_slack",
        &BigInt::from(payout_amount),
        &BigInt::from(1u8),
        CLAIMS_VALUE_BOUND * CLAIMS_VALUE_BOUND,
        "claims_payout_nonzero",
    )?;
    let eligible_for_midnight_settlement = approve_and_settle_bit && payout_nonzero;
    write_bool_value(
        &mut values,
        "eligible_for_midnight_settlement",
        eligible_for_midnight_settlement,
    );

    let settlement_instruction_inner = write_poseidon_hash_support(
        &mut values,
        "claims_settlement_instruction_inner",
        [
            &BigInt::from(payout_amount),
            &BigInt::from(reserve_amount),
            &BigInt::from(action_class_code),
            &BigInt::from(
                request
                    .settlement_governance
                    .claimant_payout_destination_commitment,
            ),
        ],
    )?;
    let settlement_instruction_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_settlement_instruction_outer",
        [
            &settlement_instruction_inner,
            &BigInt::from(
                request
                    .settlement_governance
                    .insurer_reserve_account_commitment,
            ),
            &BigInt::from(request.settlement_governance.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_governance.settlement_blinding_values[1]),
        ],
    )?;
    let settlement_instruction_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_settlement_instruction_binding",
        [
            &settlement_instruction_commitment,
            &claim_packet_commitment,
            &coverage_decision_commitment,
            &BigInt::from(request.settlement_governance.public_disclosure_blinding_values[1]),
        ],
    )?;
    write_square_nonlinear_anchor(&mut values, "claims_report_delay_margin_shifted");
    for index in 0..PRIVATE_CLAIMS_MAX_LINE_ITEMS {
        write_square_nonlinear_anchor(&mut values, &format!("claims_replacement_gap_{index}"));
        write_square_nonlinear_anchor(&mut values, &format!("claims_invoice_gap_{index}"));
        write_square_nonlinear_anchor(&mut values, &format!("claims_quantity_gap_{index}"));
    }
    for signal in [
        "claims_total_invoice_amount",
        "claims_total_price_baseline",
        "claims_policy_mismatch_score",
        "claims_evidence_completeness_score",
        "claims_duplication_score",
    ] {
        write_square_nonlinear_anchor(&mut values, signal);
    }
    for index in 0..PRIVATE_CLAIMS_MAX_DIGESTS {
        write_square_nonlinear_anchor(&mut values, &format!("claims_digest_present_{index}"));
    }

    Ok((
        values,
        ClaimsCoreComputation {
            claim_packet_commitment,
            evidence_manifest_digest: digest_manifest,
            coverage_decision_commitment,
            consistency_score_commitment,
            fraud_evidence_score_commitment,
            payout_amount_commitment,
            reserve_amount_commitment,
            settlement_instruction_commitment,
            policy_eligible,
            within_period,
            covered_peril_supported,
            peril_excluded,
            chronology_score,
            valuation_score,
            duplication_score,
            vendor_score,
            policy_mismatch_score,
            evidence_completeness_score,
            structured_inconsistency_score,
            consistency_score,
            fraud_evidence_score,
            payout_amount,
            reserve_amount,
            reinsurer_share_amount,
            report_delay,
            total_estimate_amount,
            total_invoice_amount,
            total_replacement_amount,
            total_valuation_gap,
            total_quantity_gap,
            duplicate_match_count,
            action_class,
            human_review_required,
            eligible_for_midnight_settlement,
        },
    ))
}

pub(crate) fn claims_truth_claim_decision_witness_from_inputs(
    request: &ClaimsTruthPrivateInputsV1,
) -> ZkfResult<(Witness, ClaimsCoreComputation)> {
    let program = build_claim_decision_core_program()?;
    let (support_values, computation) = compute_core_support_values(request)?;
    let witness = generate_witness(&program, &support_values)?;
    Ok((witness, computation))
}

fn compute_settlement_binding_values(
    request: &ClaimsTruthPrivateInputsV1,
    core: &ClaimsCoreComputation,
) -> ZkfResult<(WitnessInputs, ClaimsSettlementComputation)> {
    let mut values = WitnessInputs::new();
    write_value(
        &mut values,
        "claims_settlement_claim_packet_commitment",
        core.claim_packet_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_settlement_coverage_decision_commitment",
        core.coverage_decision_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_settlement_fraud_evidence_score",
        core.fraud_evidence_score,
    );
    write_value(
        &mut values,
        "claims_settlement_payout_amount",
        core.payout_amount,
    );
    write_value(
        &mut values,
        "claims_settlement_reserve_amount",
        core.reserve_amount,
    );
    write_value(
        &mut values,
        "claims_settlement_reinsurer_share_amount",
        core.reinsurer_share_amount,
    );
    write_value(
        &mut values,
        "claims_settlement_action_class_code",
        core.action_class.code(),
    );
    write_value(
        &mut values,
        "claims_settlement_claimant_destination_commitment",
        request
            .settlement_governance
            .claimant_payout_destination_commitment,
    );
    write_value(
        &mut values,
        "claims_settlement_insurer_reserve_account_commitment",
        request
            .settlement_governance
            .insurer_reserve_account_commitment,
    );
    write_value(
        &mut values,
        "claims_settlement_reinsurer_participation_commitment",
        request
            .settlement_governance
            .reinsurer_participation_commitment,
    );
    write_value(
        &mut values,
        "claims_settlement_dispute_threshold",
        request.settlement_governance.dispute_escalation_threshold,
    );
    write_value(
        &mut values,
        "claims_settlement_blinding_0",
        request.settlement_governance.settlement_blinding_values[0],
    );
    write_value(
        &mut values,
        "claims_settlement_blinding_1",
        request.settlement_governance.settlement_blinding_values[1],
    );
    write_value(
        &mut values,
        "claims_settlement_public_blinding_0",
        request.settlement_governance.public_disclosure_blinding_values[0],
    );
    write_value(
        &mut values,
        "claims_settlement_public_blinding_1",
        request.settlement_governance.public_disclosure_blinding_values[1],
    );
    let hold_by_fraud = write_geq_support(
        &mut values,
        "claims_settlement_hold_by_fraud_bit",
        "claims_settlement_hold_by_fraud_slack",
        &BigInt::from(core.fraud_evidence_score),
        &BigInt::from(request.settlement_governance.dispute_escalation_threshold),
        CLAIMS_SCORE_CAP,
        "claims_settlement_hold_by_fraud",
    )?;
    let non_auto_action = write_geq_support(
        &mut values,
        "claims_settlement_non_auto_action_bit",
        "claims_settlement_non_auto_action_slack",
        &BigInt::from(core.action_class.code()),
        &BigInt::from(1u8),
        8,
        "claims_settlement_non_auto_action",
    )?;
    let hold_required = hold_by_fraud || non_auto_action;
    write_bool_value(
        &mut values,
        "claims_settlement_hold_required_bit",
        hold_required,
    );
    write_bool_value(
        &mut values,
        "claims_settlement_finality_flag",
        !hold_required,
    );
    let settlement_instruction_inner = write_poseidon_hash_support(
        &mut values,
        "claims_settlement_instruction_commitment_inner",
        [
            &BigInt::from(core.payout_amount),
            &BigInt::from(core.reserve_amount),
            &BigInt::from(core.action_class.code()),
            &BigInt::from(
                request
                    .settlement_governance
                    .claimant_payout_destination_commitment,
            ),
        ],
    )?;
    let settlement_instruction_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_settlement_instruction_commitment_outer",
        [
            &settlement_instruction_inner,
            &BigInt::from(
                request
                    .settlement_governance
                    .insurer_reserve_account_commitment,
            ),
            &BigInt::from(request.settlement_governance.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_governance.settlement_blinding_values[1]),
        ],
    )?;
    let settlement_instruction_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_settlement_instruction_commitment_binding",
        [
            &settlement_instruction_commitment,
            &core.claim_packet_commitment,
            &core.coverage_decision_commitment,
            &BigInt::from(request.settlement_governance.public_disclosure_blinding_values[1]),
        ],
    )?;
    let dispute_hold_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_settlement_dispute_hold_commitment_inner",
        [
            &BigInt::from(CLAIMS_DOMAIN_SETTLEMENT),
            &BigInt::from(core.action_class.code()),
            &BigInt::from(core.fraud_evidence_score),
            &BigInt::from(request.settlement_governance.dispute_escalation_threshold),
        ],
    )?;
    let reinsurer_release_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_settlement_reinsurer_release_commitment_inner",
        [
            &BigInt::from(core.reinsurer_share_amount),
            &BigInt::from(core.payout_amount),
            &BigInt::from(
                request
                    .settlement_governance
                    .reinsurer_participation_commitment,
            ),
            &BigInt::from(
                request
                    .settlement_governance
                    .public_disclosure_blinding_values[0],
            ),
        ],
    )?;
    write_value(
        &mut values,
        "claims_settlement_settlement_instruction_commitment",
        settlement_instruction_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_settlement_dispute_hold_commitment",
        dispute_hold_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_settlement_reinsurer_release_commitment",
        reinsurer_release_commitment.clone(),
    );
    Ok((
        values,
        ClaimsSettlementComputation {
            settlement_instruction_commitment,
            dispute_hold_commitment,
            reinsurer_release_commitment,
            settlement_finality_flag: !hold_required,
        },
    ))
}

pub(crate) fn claims_truth_settlement_binding_witness_from_inputs(
    request: &ClaimsTruthPrivateInputsV1,
    core: &ClaimsCoreComputation,
) -> ZkfResult<(Witness, ClaimsSettlementComputation)> {
    let program = build_settlement_binding_program()?;
    let (values, computation) = compute_settlement_binding_values(request, core)?;
    let witness = generate_witness(&program, &values)?;
    Ok((witness, computation))
}

fn compute_disclosure_projection_values(
    request: &ClaimsTruthPrivateInputsV1,
    core: &ClaimsCoreComputation,
    role_code: u64,
) -> ZkfResult<(WitnessInputs, ClaimsDisclosureComputation)> {
    let mut values = WitnessInputs::new();
    let role_bits = [
        role_code == 0,
        role_code == 1,
        role_code == 2,
        role_code == 3,
        role_code == 4,
    ];
    write_bool_value(&mut values, "claims_disclosure_role_auditor", role_bits[0]);
    write_bool_value(&mut values, "claims_disclosure_role_regulator", role_bits[1]);
    write_bool_value(&mut values, "claims_disclosure_role_reinsurer", role_bits[2]);
    write_bool_value(&mut values, "claims_disclosure_role_claimant", role_bits[3]);
    write_bool_value(&mut values, "claims_disclosure_role_investigator", role_bits[4]);
    write_value(
        &mut values,
        "claims_disclosure_claim_packet_commitment",
        core.claim_packet_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_coverage_decision_commitment",
        core.coverage_decision_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_consistency_score_commitment",
        core.consistency_score_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_fraud_score_commitment",
        core.fraud_evidence_score_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_payout_commitment",
        core.payout_amount_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_reserve_commitment",
        core.reserve_amount_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_settlement_commitment",
        core.settlement_instruction_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_reinsurer_share_amount",
        core.reinsurer_share_amount,
    );
    write_value(
        &mut values,
        "claims_disclosure_public_blinding_0",
        request
            .settlement_governance
            .public_disclosure_blinding_values[0],
    );
    write_value(
        &mut values,
        "claims_disclosure_public_blinding_1",
        request
            .settlement_governance
            .public_disclosure_blinding_values[1],
    );
    write_value(&mut values, "claims_disclosure_role_sum", 1u64);
    write_value(&mut values, "claims_disclosure_role_code", role_code);
    let disclosed_value_a = match role_code {
        0 => core.payout_amount_commitment.clone(),
        1 => core.reserve_amount_commitment.clone(),
        2 => core.claim_packet_commitment.clone(),
        3 => core.settlement_instruction_commitment.clone(),
        _ => core.fraud_evidence_score_commitment.clone(),
    };
    let disclosed_value_b = match role_code {
        0 => core.consistency_score_commitment.clone(),
        1 => core.fraud_evidence_score_commitment.clone(),
        2 => core.reserve_amount_commitment.clone(),
        3 => core.payout_amount_commitment.clone(),
        _ => core.coverage_decision_commitment.clone(),
    };
    write_value(
        &mut values,
        "claims_disclosure_value_a_private",
        disclosed_value_a.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_value_b_private",
        disclosed_value_b.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_value_a",
        disclosed_value_a.clone(),
    );
    write_value(
        &mut values,
        "claims_disclosure_value_b",
        disclosed_value_b.clone(),
    );
    let disclosure_view_inner = write_poseidon_hash_support(
        &mut values,
        "claims_disclosure_view_commitment_inner",
        [
            &BigInt::from(CLAIMS_DOMAIN_DISCLOSURE),
            &BigInt::from(role_code),
            &disclosed_value_a,
            &disclosed_value_b,
        ],
    )?;
    let disclosure_view_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_disclosure_view_commitment_outer",
        [
            &disclosure_view_inner,
            &BigInt::from(core.reinsurer_share_amount),
            &BigInt::from(
                request
                    .settlement_governance
                    .public_disclosure_blinding_values[0],
            ),
            &BigInt::from(
                request
                    .settlement_governance
                    .public_disclosure_blinding_values[1],
            ),
        ],
    )?;
    write_value(
        &mut values,
        "claims_disclosure_view_commitment",
        disclosure_view_commitment.clone(),
    );
    write_square_nonlinear_anchor(&mut values, "claims_disclosure_role_sum");
    Ok((
        values,
        ClaimsDisclosureComputation {
            role_code,
            disclosure_view_commitment,
            disclosed_value_a,
            disclosed_value_b,
        },
    ))
}

pub(crate) fn claims_truth_disclosure_projection_witness_from_inputs(
    request: &ClaimsTruthPrivateInputsV1,
    core: &ClaimsCoreComputation,
    role_code: u64,
) -> ZkfResult<(Witness, ClaimsDisclosureComputation)> {
    let program = build_disclosure_projection_program()?;
    let (values, computation) = compute_disclosure_projection_values(request, core, role_code)?;
    let witness = generate_witness(&program, &values)?;
    Ok((witness, computation))
}

fn compute_batch_shard_values(
    commitments: &[BigInt; PRIVATE_CLAIMS_MAX_DIGESTS],
) -> ZkfResult<(WitnessInputs, ClaimsShardComputation)> {
    let mut values = WitnessInputs::new();
    write_value(&mut values, "claims_shard_shard_count", 2u64);
    write_value(&mut values, "claims_shard_blinding_0", 17u64);
    write_value(&mut values, "claims_shard_blinding_1", 29u64);
    for (index, commitment) in commitments.iter().enumerate() {
        write_value(
            &mut values,
            format!("claims_shard_claim_commitment_{index}"),
            commitment.clone(),
        );
        write_exact_division_support_bigint(
            &mut values,
            commitment,
            2,
            &format!("claims_shard_assignment_quotient_{index}"),
            &format!("claims_shard_assignment_{index}"),
            &format!("claims_shard_assignment_slack_{index}"),
            &format!("claims_shard_assignment_{index}"),
        )?;
    }
    write_geq_support(
        &mut values,
        "claims_shard_count_valid_bit",
        "claims_shard_count_valid_slack",
        &BigInt::from(2u8),
        &BigInt::from(2u8),
        CLAIMS_SHARD_COUNT_MAX,
        "claims_shard_count_valid",
    )?;
    let batch_root_inner = write_poseidon_hash_support(
        &mut values,
        "claims_shard_batch_root_commitment_inner",
        [
            &BigInt::from(CLAIMS_DOMAIN_SHARD_BATCH),
            &commitments[0],
            &commitments[1],
            &commitments[2],
        ],
    )?;
    let batch_root_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_shard_batch_root_commitment_outer",
        [
            &batch_root_inner,
            &commitments[3],
            &BigInt::from(17u8),
            &BigInt::from(29u8),
        ],
    )?;
    let assignment_0 = bigint_from_map(&values, "claims_shard_assignment_0");
    let assignment_1 = bigint_from_map(&values, "claims_shard_assignment_1");
    let assignment_2 = bigint_from_map(&values, "claims_shard_assignment_2");
    let assignment_3 = bigint_from_map(&values, "claims_shard_assignment_3");
    let assignment_commitment = write_poseidon_hash_support(
        &mut values,
        "claims_shard_assignment_commitment_inner",
        [
            &assignment_0,
            &assignment_1,
            &assignment_2,
            &assignment_3,
        ],
    )?;
    write_value(
        &mut values,
        "claims_shard_batch_root_commitment",
        batch_root_commitment.clone(),
    );
    write_value(
        &mut values,
        "claims_shard_assignment_commitment",
        assignment_commitment.clone(),
    );
    Ok((
        values,
        ClaimsShardComputation {
            batch_root_commitment,
            assignment_commitment,
        },
    ))
}

pub(crate) fn claims_truth_batch_shard_handoff_witness_from_commitments(
    commitments: &[BigInt; PRIVATE_CLAIMS_MAX_DIGESTS],
) -> ZkfResult<(Witness, ClaimsShardComputation)> {
    let program = build_batch_shard_handoff_program()?;
    let (values, computation) = compute_batch_shard_values(commitments)?;
    let witness = generate_witness(&program, &values)?;
    Ok((witness, computation))
}

pub fn private_claims_truth_sample_inputs() -> ClaimsTruthPrivateInputsV1 {
    let mut sample = ClaimsTruthPrivateInputsV1 {
        policy: ClaimsTruthPolicyDataV1 {
            policy_id_hash: 1001,
            policy_effective_timestamp: 1_700_000_000,
            policy_expiration_timestamp: 1_900_000_000,
            covered_peril_flags: [1, 0, 1, 0],
            exclusion_flags: [0, 0, 0, 1],
            deductible_schedule: [5_000, 0],
            payout_cap_schedule: [80_000, 0],
            depreciation_rules: [1_500, 0],
            reserve_policy_parameters: [2_000, 12_000],
            reinsurer_sharing_parameters: [4_000, 20_000, 50_000],
        },
        claim_event: ClaimsTruthClaimEventDataV1 {
            claim_id_hash: 2002,
            claimant_id_hash: 3003,
            incident_timestamp: 1_750_000_000,
            reported_timestamp: 1_750_086_400,
            event_region_bucket: 8,
            peril_classification_flags: [1, 0, 0, 0],
            damaged_asset_class: 2,
            claimed_loss_categories: [1, 1, 0, 0],
            prior_claim_linkage_hashes: [9101, 9102, 9103, 9104],
        },
        evidence: ClaimsTruthEvidenceDataV1 {
            repair_estimate_line_items: [
                ClaimsTruthEstimateLineItemV1 {
                    quantity: 1,
                    unit_amount: 18_000,
                    replacement_cost: 18_500,
                    depreciation_basis: 16_000,
                },
                ClaimsTruthEstimateLineItemV1 {
                    quantity: 2,
                    unit_amount: 7_500,
                    replacement_cost: 15_500,
                    depreciation_basis: 14_000,
                },
                ClaimsTruthEstimateLineItemV1 {
                    quantity: 1,
                    unit_amount: 4_500,
                    replacement_cost: 4_700,
                    depreciation_basis: 4_000,
                },
                ClaimsTruthEstimateLineItemV1 {
                    quantity: 1,
                    unit_amount: 3_000,
                    replacement_cost: 3_200,
                    depreciation_basis: 2_600,
                },
            ],
            invoice_line_items: [
                ClaimsTruthInvoiceLineItemV1 {
                    quantity: 1,
                    invoice_amount: 18_100,
                },
                ClaimsTruthInvoiceLineItemV1 {
                    quantity: 2,
                    invoice_amount: 15_300,
                },
                ClaimsTruthInvoiceLineItemV1 {
                    quantity: 1,
                    invoice_amount: 4_450,
                },
                ClaimsTruthInvoiceLineItemV1 {
                    quantity: 1,
                    invoice_amount: 3_050,
                },
            ],
            replacement_cost_schedules: [18_500, 15_500, 4_700, 3_200],
            depreciation_basis_values: [16_000, 14_000, 4_000, 2_600],
            telematics_structured_event_summary_values: [101, 102, 103, 104],
            vendor_attestation_digests: [4_001, 4_002, 4_003, 4_004],
            photo_analysis_result_digest: 8_001,
            document_extraction_result_digest: 8_002,
            authority_report_reference_digest: 8_003,
            evidence_manifest_digest: "0".to_string(),
        },
        analysis_inputs: ClaimsTruthConsistencyFraudInputsV1 {
            duplicate_claim_candidate_hashes: [10001, 10002, 9103, 10004],
            price_deviation_baselines: [500, 500, 300, 200],
            vendor_anomaly_baselines: [1_000, 1_000, 1_000, 1_000],
            chronology_consistency_threshold: 172_800,
            geographic_reasonableness_threshold: 12,
            quantity_tolerance_threshold: 2,
            valuation_tolerance_threshold: 8_000,
        },
        settlement_governance: ClaimsTruthSettlementGovernanceInputsV1 {
            claimant_payout_destination_commitment: 70_001,
            insurer_reserve_account_commitment: 70_002,
            reinsurer_participation_commitment: 70_003,
            dispute_escalation_threshold: 8_000,
            fraud_review_threshold: 6_000,
            manual_review_threshold: 60_000,
            settlement_blinding_values: [111, 222],
            public_disclosure_blinding_values: [333, 444],
        },
    };
    let digest = {
        let mut values = flatten_private_inputs(&sample).expect("flatten claims sample");
        write_private_input_anchor_chain(
            &mut values,
            &[
                evidence_name("photo_analysis_result_digest"),
                evidence_name("document_extraction_result_digest"),
                evidence_name("authority_report_reference_digest"),
                evidence_array_name("telematics_summary", 0),
            ],
            "claims_evidence_anchor_sample",
        )
        .expect("sample digest")
    };
    sample.evidence.evidence_manifest_digest = digest.to_str_radix(10);
    sample
}

pub fn private_claims_truth_manual_review_inputs() -> ClaimsTruthPrivateInputsV1 {
    let mut sample = private_claims_truth_sample_inputs();
    sample.evidence.repair_estimate_line_items[0].unit_amount = 30_000;
    sample.evidence.invoice_line_items[0].invoice_amount = 30_200;
    sample.settlement_governance.manual_review_threshold = 35_000;
    sample
}

pub fn private_claims_truth_investigation_inputs() -> ClaimsTruthPrivateInputsV1 {
    let mut sample = private_claims_truth_sample_inputs();
    sample.analysis_inputs.duplicate_claim_candidate_hashes[0] =
        sample.claim_event.prior_claim_linkage_hashes[0];
    sample.analysis_inputs.duplicate_claim_candidate_hashes[1] =
        sample.claim_event.prior_claim_linkage_hashes[1];
    sample
}

pub fn private_claims_truth_policy_denial_inputs() -> ClaimsTruthPrivateInputsV1 {
    let mut sample = private_claims_truth_sample_inputs();
    sample.claim_event.incident_timestamp = 1_950_000_000;
    sample.claim_event.reported_timestamp = 1_950_086_400;
    sample
}

pub fn private_claims_truth_inconsistency_denial_inputs() -> ClaimsTruthPrivateInputsV1 {
    let mut sample = private_claims_truth_sample_inputs();
    sample.evidence.invoice_line_items[1].quantity = 8;
    sample.evidence.invoice_line_items[1].invoice_amount = 90_000;
    sample.analysis_inputs.valuation_tolerance_threshold = 1_000;
    sample.analysis_inputs.quantity_tolerance_threshold = 1;
    sample
}

pub fn private_claims_truth_violation_inputs() -> ClaimsTruthPrivateInputsV1 {
    let mut sample = private_claims_truth_sample_inputs();
    sample.evidence.evidence_manifest_digest = "12345".to_string();
    sample
}

pub fn private_claims_truth_showcase() -> ZkfResult<TemplateProgram> {
    Ok(TemplateProgram {
        program: build_claim_decision_core_program()?,
        expected_inputs: claims_truth_private_input_names_v1(),
        public_outputs: expected_public_output_names(),
        sample_inputs: flatten_private_inputs(&private_claims_truth_sample_inputs())?,
        violation_inputs: flatten_private_inputs(&private_claims_truth_violation_inputs())?,
        description: "Private claims truth and settlement showcase for property and casualty insurance claim consistency, scoring, payout, reserve, and settlement binding.",
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[path = "private_claims_truth_export.rs"]
mod export;

#[cfg(not(target_arch = "wasm32"))]
pub use export::{
    APP_ID as PRIVATE_CLAIMS_TRUTH_APP_ID, PrivateClaimsTruthExportConfig,
    PrivateClaimsTruthExportProfile, PrivateClaimsTruthHypernovaDiagnosticReport,
    run_private_claims_truth_export, run_private_claims_truth_hypernova_diagnostics,
};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string_pretty};

    fn assert_action(request: &ClaimsTruthPrivateInputsV1, expected: ClaimsActionClassV1) {
        let program = build_claim_decision_core_program().expect("program");
        let (witness, computation) =
            claims_truth_claim_decision_witness_from_inputs(request).expect("witness");
        check_constraints(&program, &witness).expect("constraints");
        assert_eq!(computation.action_class, expected);
    }

    #[test]
    fn claims_truth_approve_and_settle_fixture_is_valid() {
        assert_action(
            &private_claims_truth_sample_inputs(),
            ClaimsActionClassV1::ApproveAndSettle,
        );
    }

    #[test]
    fn claims_truth_manual_review_fixture_is_valid() {
        assert_action(
            &private_claims_truth_manual_review_inputs(),
            ClaimsActionClassV1::ApproveWithManualReview,
        );
    }

    #[test]
    fn claims_truth_investigation_fixture_is_valid() {
        assert_action(
            &private_claims_truth_investigation_inputs(),
            ClaimsActionClassV1::EscalateForInvestigation,
        );
    }

    #[test]
    fn claims_truth_policy_denial_fixture_is_valid() {
        assert_action(
            &private_claims_truth_policy_denial_inputs(),
            ClaimsActionClassV1::DenyForPolicyRule,
        );
    }

    #[test]
    fn claims_truth_inconsistency_denial_fixture_is_valid() {
        assert_action(
            &private_claims_truth_inconsistency_denial_inputs(),
            ClaimsActionClassV1::DenyForInconsistency,
        );
    }

    #[test]
    fn claims_truth_serialization_round_trip() {
        let sample = private_claims_truth_sample_inputs();
        let json = to_string_pretty(&sample).expect("serialize");
        let round_trip: ClaimsTruthPrivateInputsV1 = from_str(&json).expect("deserialize");
        assert_eq!(round_trip, sample);
    }

    #[test]
    fn claims_truth_violation_fixture_breaks_constraints() {
        let program = build_claim_decision_core_program().expect("program");
        let (mut values, _) =
            compute_core_support_values(&private_claims_truth_sample_inputs()).expect("values");
        write_value(&mut values, evidence_name("evidence_manifest_digest"), 12345u64);
        match generate_witness(&program, &values) {
            Ok(witness) => {
                let err = check_constraints(&program, &witness).expect_err("must fail");
                let text = err.to_string();
                assert!(text.contains("Constraint") || text.contains("constraint"));
            }
            Err(err) => {
                let text = err.to_string();
                assert!(text.contains("Constraint") || text.contains("constraint"));
            }
        }
    }

    #[test]
    fn claims_truth_settlement_binding_matches_core_commitment() {
        let request = private_claims_truth_sample_inputs();
        let (core_witness, core) =
            claims_truth_claim_decision_witness_from_inputs(&request).expect("core");
        check_constraints(&build_claim_decision_core_program().expect("program"), &core_witness)
            .expect("core constraints");
        let (settlement_witness, settlement) =
            claims_truth_settlement_binding_witness_from_inputs(&request, &core)
                .expect("settlement");
        check_constraints(
            &build_settlement_binding_program().expect("program"),
            &settlement_witness,
        )
        .expect("settlement constraints");
        assert_eq!(
            settlement.settlement_instruction_commitment,
            core.settlement_instruction_commitment
        );
    }

    #[test]
    fn claims_truth_disclosure_projection_is_deterministic() {
        let request = private_claims_truth_sample_inputs();
        let (_, core_a) = claims_truth_claim_decision_witness_from_inputs(&request).expect("core");
        let (_, disclosure_a) =
            claims_truth_disclosure_projection_witness_from_inputs(&request, &core_a, 2)
                .expect("disclosure");
        let (_, disclosure_b) =
            claims_truth_disclosure_projection_witness_from_inputs(&request, &core_a, 2)
                .expect("disclosure");
        assert_eq!(
            disclosure_a.disclosure_view_commitment,
            disclosure_b.disclosure_view_commitment
        );
    }

    #[test]
    fn claims_truth_batch_shard_handoff_is_valid() {
        let request = private_claims_truth_sample_inputs();
        let (_, core_a) = claims_truth_claim_decision_witness_from_inputs(&request).expect("core");
        let commitments = [
            core_a.claim_packet_commitment.clone(),
            core_a.coverage_decision_commitment.clone(),
            core_a.consistency_score_commitment.clone(),
            core_a.settlement_instruction_commitment.clone(),
        ];
        let (witness, _) =
            claims_truth_batch_shard_handoff_witness_from_commitments(&commitments)
                .expect("shard witness");
        check_constraints(
            &build_batch_shard_handoff_program().expect("program"),
            &witness,
        )
        .expect("shard constraints");
    }

    #[test]
    #[ignore = "debug-only HyperNova witness diagnostic"]
    fn claims_truth_sample_hypernova_prepared_witness_reports_pasta_overflow_values() {
        let (witness, _) =
            claims_truth_claim_decision_witness_from_inputs(&private_claims_truth_sample_inputs())
                .expect("witness");
        let program = build_claim_decision_core_program().expect("program");
        let compiled = crate::app::api::compile(&program, "hypernova", None).expect("compile");
        let prepared = prepare_witness_for_proving(&compiled, &witness).expect("prepared");
        let pasta_modulus = FieldId::PastaFq.modulus().clone();
        let mut offenders = prepared
            .values
            .iter()
            .filter_map(|(name, value)| {
                let bigint = value.to_bigint().ok()?;
                if bigint >= pasta_modulus {
                    Some((name.clone(), bigint.to_str_radix(10)))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        offenders.sort_by(|left, right| left.0.cmp(&right.0));
        eprintln!("prepared-overflow-count={}", offenders.len());
        for (name, value) in offenders.iter().take(12) {
            eprintln!("{name}={value}");
        }
    }
}
