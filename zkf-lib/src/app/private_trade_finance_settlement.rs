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
    BigIntFieldValue, Expr, FieldElement, FieldId, FieldValue, Program, Witness, WitnessInputs,
    ZkfError, ZkfResult, generate_witness,
};

use super::builder::ProgramBuilder;
use super::templates::TemplateProgram;

pub const PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS: usize = 4;
pub const PRIVATE_TRADE_FINANCE_MAX_DIGESTS: usize = 4;
pub const PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES: usize = 4;
pub const PRIVATE_TRADE_FINANCE_PUBLIC_OUTPUTS: usize = 10;
pub const TRADE_FINANCE_FIXED_POINT_SCALE: u64 = 10_000;

const TRADE_FINANCE_FIELD: FieldId = FieldId::PastaFq;
const TRADE_FINANCE_ACTION_APPROVE_AND_SETTLE: u64 = 0;
const TRADE_FINANCE_ACTION_APPROVE_WITH_MANUAL_REVIEW: u64 = 1;
const TRADE_FINANCE_ACTION_ESCALATE_FOR_INVESTIGATION: u64 = 2;
const TRADE_FINANCE_ACTION_DENY_FOR_POLICY_RULE: u64 = 3;
const TRADE_FINANCE_ACTION_DENY_FOR_INCONSISTENCY: u64 = 4;
const TRADE_FINANCE_DISCLOSURE_ROLE_SUPPLIER: u64 = 0;
const TRADE_FINANCE_DISCLOSURE_ROLE_FINANCIER: u64 = 1;
const TRADE_FINANCE_DISCLOSURE_ROLE_BUYER: u64 = 2;
const TRADE_FINANCE_DISCLOSURE_ROLE_AUDITOR: u64 = 3;
const TRADE_FINANCE_DISCLOSURE_ROLE_REGULATOR: u64 = 4;
const TRADE_FINANCE_DOMAIN_COVERAGE: i64 = 1101;
const TRADE_FINANCE_DOMAIN_CONSISTENCY: i64 = 1102;
const TRADE_FINANCE_DOMAIN_DUPLICATE_RISK: i64 = 1103;
const TRADE_FINANCE_DOMAIN_APPROVED_ADVANCE: i64 = 1104;
const TRADE_FINANCE_DOMAIN_RESERVE: i64 = 1105;
const TRADE_FINANCE_DOMAIN_SETTLEMENT: i64 = 1106;
const TRADE_FINANCE_DOMAIN_DISCLOSURE: i64 = 1107;
const TRADE_FINANCE_DOMAIN_SHARD_BATCH: i64 = 1108;
const TRADE_FINANCE_DOMAIN_FEE: i64 = 1109;
const TRADE_FINANCE_DOMAIN_MATURITY: i64 = 1110;
const TRADE_FINANCE_DOMAIN_DISCLOSURE_AUTHORIZATION: i64 = 1111;
const TRADE_FINANCE_SCORE_CAP: u64 = 10_000;
const TRADE_FINANCE_COMPONENT_SCORE_CAP: u64 = 4_000;
const TRADE_FINANCE_UINT_BOUND: u64 = 4_000_000_000;
const TRADE_FINANCE_TIMESTAMP_BOUND: u64 = 4_000_000_000;
const TRADE_FINANCE_HASH_BOUND: u64 = 18_000_000_000_000_000_000;
const TRADE_FINANCE_SIGNED_MARGIN_OFFSET: u64 = 100_000_000;
const TRADE_FINANCE_SIGNED_MARGIN_BOUND: u64 = 200_000_000;
const TRADE_FINANCE_VALUE_BOUND: u64 = 100_000_000;
const TRADE_FINANCE_RATIO_BOUND: u64 = 10_000_000;
const TRADE_FINANCE_SHARD_COUNT_MAX: u64 = 4;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinancePolicyDataV1 {
    pub financing_policy_id_hash: u64,
    pub financing_window_open_timestamp: u64,
    pub financing_window_close_timestamp: u64,
    pub eligibility_predicate_flags: [u64; PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES],
    pub lender_exclusion_predicate_flags: [u64; PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES],
    pub supplier_retention_schedule: [u64; 2],
    pub advance_cap_schedule: [u64; 2],
    pub discount_rate_rules: [u64; 2],
    pub reserve_holdback_parameters: [u64; 2],
    pub financier_participation_parameters: [u64; 3],
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinanceReceivableContextDataV1 {
    pub receivable_id_hash: u64,
    pub supplier_id_hash: u64,
    pub invoice_presented_timestamp: u64,
    pub financing_request_timestamp: u64,
    pub jurisdiction_corridor_bucket: u64,
    pub observed_eligibility_predicate_flags: [u64; PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES],
    pub goods_or_service_class: u64,
    pub buyer_acceptance_term_flags: [u64; PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES],
    pub prior_financing_linkage_hashes: [u64; PRIVATE_TRADE_FINANCE_MAX_DIGESTS],
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinanceEstimateLineItemV1 {
    pub quantity: u64,
    pub unit_amount: u64,
    pub reference_amount: u64,
    pub discount_basis: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinanceInvoiceLineItemV1 {
    pub quantity: u64,
    pub invoice_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinanceEvidenceDataV1 {
    pub supporting_schedule_line_items:
        [TradeFinanceEstimateLineItemV1; PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS],
    pub invoice_line_items: [TradeFinanceInvoiceLineItemV1; PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS],
    pub reference_amount_schedules: [u64; PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS],
    pub discount_basis_values: [u64; PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS],
    pub logistics_event_summary_values: [u64; PRIVATE_TRADE_FINANCE_MAX_DIGESTS],
    pub vendor_attestation_digests: [u64; PRIVATE_TRADE_FINANCE_MAX_DIGESTS],
    pub photo_analysis_result_digest: u64,
    pub document_extraction_result_digest: u64,
    pub buyer_approval_reference_digest: u64,
    pub evidence_manifest_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinanceConsistencyFraudInputsV1 {
    pub duplicate_receivable_candidate_hashes: [u64; PRIVATE_TRADE_FINANCE_MAX_DIGESTS],
    pub price_deviation_baselines: [u64; PRIVATE_TRADE_FINANCE_MAX_DIGESTS],
    pub vendor_anomaly_baselines: [u64; PRIVATE_TRADE_FINANCE_MAX_DIGESTS],
    pub chronology_consistency_threshold: u64,
    pub geographic_reasonableness_threshold: u64,
    pub quantity_tolerance_threshold: u64,
    pub valuation_tolerance_threshold: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinanceSettlementGovernanceInputsV1 {
    pub supplier_advance_destination_commitment: u64,
    pub financier_reserve_account_commitment: u64,
    pub financier_participation_commitment: u64,
    pub disclosure_credential_commitment: u64,
    pub disclosure_request_id_hash: u64,
    pub disclosure_caller_commitment: u64,
    pub dispute_escalation_threshold: u64,
    pub risk_review_threshold: u64,
    pub manual_review_threshold: u64,
    pub settlement_blinding_values: [u64; 2],
    pub public_disclosure_blinding_values: [u64; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinancePrivateInputsV1 {
    pub financing_policy: TradeFinancePolicyDataV1,
    pub receivable_context: TradeFinanceReceivableContextDataV1,
    pub supporting_documents: TradeFinanceEvidenceDataV1,
    pub duplicate_risk_inputs: TradeFinanceConsistencyFraudInputsV1,
    pub settlement_terms: TradeFinanceSettlementGovernanceInputsV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TradeFinanceActionClassV1 {
    Approve,
    ApproveWithManualReview,
    EscalateForRiskReview,
    RejectForRuleFailure,
    RejectForInconsistency,
}

impl TradeFinanceActionClassV1 {
    pub fn code(self) -> u64 {
        match self {
            Self::Approve => TRADE_FINANCE_ACTION_APPROVE_AND_SETTLE,
            Self::ApproveWithManualReview => TRADE_FINANCE_ACTION_APPROVE_WITH_MANUAL_REVIEW,
            Self::EscalateForRiskReview => TRADE_FINANCE_ACTION_ESCALATE_FOR_INVESTIGATION,
            Self::RejectForRuleFailure => TRADE_FINANCE_ACTION_DENY_FOR_POLICY_RULE,
            Self::RejectForInconsistency => TRADE_FINANCE_ACTION_DENY_FOR_INCONSISTENCY,
        }
    }

    pub fn from_code(code: u64) -> ZkfResult<Self> {
        match code {
            TRADE_FINANCE_ACTION_APPROVE_AND_SETTLE => Ok(Self::Approve),
            TRADE_FINANCE_ACTION_APPROVE_WITH_MANUAL_REVIEW => Ok(Self::ApproveWithManualReview),
            TRADE_FINANCE_ACTION_ESCALATE_FOR_INVESTIGATION => Ok(Self::EscalateForRiskReview),
            TRADE_FINANCE_ACTION_DENY_FOR_POLICY_RULE => Ok(Self::RejectForRuleFailure),
            TRADE_FINANCE_ACTION_DENY_FOR_INCONSISTENCY => Ok(Self::RejectForInconsistency),
            other => Err(ZkfError::InvalidArtifact(format!(
                "unsupported trade-finance action code {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TradeFinancePublicOutputsV1 {
    pub invoice_packet_commitment: String,
    pub eligibility_commitment: String,
    pub consistency_score_commitment: String,
    pub duplicate_financing_risk_commitment: String,
    pub approved_advance_commitment: String,
    pub fee_amount_commitment: String,
    pub reserve_amount_commitment: String,
    pub maturity_schedule_commitment: String,
    pub action_class: TradeFinanceActionClassV1,
    pub human_review_required: bool,
    pub eligible_for_midnight_settlement: bool,
    pub proof_verification_result: bool,
}

#[derive(Debug, Clone)]
pub struct TradeFinanceCoreComputationInternal {
    invoice_packet_commitment: BigInt,
    evidence_manifest_digest: BigInt,
    eligibility_commitment: BigInt,
    consistency_score_commitment: BigInt,
    duplicate_financing_risk_commitment: BigInt,
    approved_advance_commitment: BigInt,
    reserve_amount_commitment: BigInt,
    settlement_instruction_commitment: BigInt,
    eligibility_passed: bool,
    within_term_window: bool,
    eligibility_predicate_supported: bool,
    lender_exclusion_triggered: bool,
    chronology_score: u64,
    valuation_score: u64,
    duplication_score: u64,
    vendor_score: u64,
    eligibility_mismatch_score: u64,
    evidence_completeness_score: u64,
    structured_inconsistency_score: u64,
    consistency_score: u64,
    duplicate_financing_risk_score: u64,
    approved_advance_amount: u64,
    reserve_amount: u64,
    fee_amount: u64,
    report_delay: u64,
    total_estimate_amount: u64,
    total_invoice_amount: u64,
    total_reference_amount: u64,
    total_valuation_gap: u64,
    total_quantity_gap: u64,
    duplicate_match_count: u64,
    action_class: TradeFinanceActionClassV1,
    human_review_required: bool,
    eligible_for_midnight_settlement: bool,
}

#[derive(Debug, Clone)]
pub struct TradeFinanceSettlementComputationInternal {
    settlement_instruction_commitment: BigInt,
    dispute_hold_commitment: BigInt,
    repayment_completion_commitment: BigInt,
    fee_amount_commitment: BigInt,
    maturity_schedule_commitment: BigInt,
    settlement_finality_flag: bool,
}

#[derive(Debug, Clone)]
pub struct TradeFinanceDisclosureComputationInternal {
    role_code: u64,
    disclosure_view_commitment: BigInt,
    disclosure_authorization_commitment: BigInt,
    disclosed_value_a: BigInt,
    disclosed_value_b: BigInt,
}

#[derive(Debug, Clone)]
pub struct TradeFinanceDuplicateRegistryComputationInternal {
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
        TRADE_FINANCE_FIELD,
    )
    .map_err(ZkfError::Backend)?;
    if lanes.len() != 4 {
        return Err(ZkfError::Backend(format!(
            "trade-finance poseidon permutation returned {} lanes instead of 4",
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

fn write_bool_value(
    values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: bool,
) {
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
        BigIntFieldValue::new(TRADE_FINANCE_FIELD, diff)
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
        sub_expr(
            add_expr(vec![left.clone(), right.clone()]),
            mul_expr(left, right),
        ),
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
    let zero_eq =
        append_equality_with_inverse(builder, value, const_expr(0), &format!("{prefix}_zero"))?;
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
    let slack_value = denominator.checked_sub(remainder_u64 + 1).ok_or_else(|| {
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
            "trade-finance evidence manifest digest must be a base-10 integer string, got {value:?}"
        ))
    })
}

fn financing_policy_input_name(name: &str) -> String {
    format!("trade_finance_financing_policy_{name}")
}

fn financing_policy_array_name(name: &str, index: usize) -> String {
    format!("trade_finance_financing_policy_{name}_{index}")
}

fn receivable_input_name(name: &str) -> String {
    format!("trade_finance_receivable_{name}")
}

fn receivable_array_name(name: &str, index: usize) -> String {
    format!("trade_finance_receivable_{name}_{index}")
}

fn evidence_line_name(kind: &str, field: &str, index: usize) -> String {
    format!("trade_finance_evidence_{kind}_{field}_{index}")
}

fn evidence_name(name: &str) -> String {
    format!("trade_finance_evidence_{name}")
}

fn evidence_array_name(name: &str, index: usize) -> String {
    format!("trade_finance_evidence_{name}_{index}")
}

fn duplicate_risk_name(name: &str) -> String {
    format!("trade_finance_duplicate_risk_{name}")
}

fn duplicate_risk_array_name(name: &str, index: usize) -> String {
    format!("trade_finance_duplicate_risk_{name}_{index}")
}

fn settlement_terms_name(name: &str) -> String {
    format!("trade_finance_settlement_terms_{name}")
}

fn settlement_terms_array_name(name: &str, index: usize) -> String {
    format!("trade_finance_settlement_terms_{name}_{index}")
}

fn settlement_input_names() -> Vec<String> {
    vec![
        "trade_finance_settlement_invoice_packet_commitment".to_string(),
        "trade_finance_settlement_eligibility_commitment".to_string(),
        "trade_finance_settlement_duplicate_financing_risk_score".to_string(),
        "trade_finance_settlement_approved_advance_amount".to_string(),
        "trade_finance_settlement_reserve_amount".to_string(),
        "trade_finance_settlement_fee_amount".to_string(),
        "trade_finance_settlement_action_class_code".to_string(),
        "trade_finance_settlement_supplier_advance_destination_commitment".to_string(),
        "trade_finance_settlement_financier_reserve_account_commitment".to_string(),
        "trade_finance_settlement_financier_participation_commitment".to_string(),
        "trade_finance_settlement_dispute_threshold".to_string(),
        "trade_finance_settlement_blinding_0".to_string(),
        "trade_finance_settlement_blinding_1".to_string(),
        "trade_finance_settlement_public_blinding_0".to_string(),
        "trade_finance_settlement_public_blinding_1".to_string(),
        "trade_finance_settlement_financing_window_open_timestamp".to_string(),
        "trade_finance_settlement_financing_window_close_timestamp".to_string(),
        "trade_finance_settlement_invoice_presented_timestamp".to_string(),
        "trade_finance_settlement_financing_request_timestamp".to_string(),
    ]
}

fn disclosure_input_names() -> Vec<String> {
    vec![
        "trade_finance_disclosure_role_supplier".to_string(),
        "trade_finance_disclosure_role_financier".to_string(),
        "trade_finance_disclosure_role_buyer".to_string(),
        "trade_finance_disclosure_role_auditor".to_string(),
        "trade_finance_disclosure_role_regulator".to_string(),
        "trade_finance_disclosure_invoice_packet_commitment".to_string(),
        "trade_finance_disclosure_eligibility_commitment".to_string(),
        "trade_finance_disclosure_consistency_score_commitment".to_string(),
        "trade_finance_disclosure_duplicate_financing_risk_commitment".to_string(),
        "trade_finance_disclosure_approved_advance_commitment".to_string(),
        "trade_finance_disclosure_reserve_commitment".to_string(),
        "trade_finance_disclosure_settlement_commitment".to_string(),
        "trade_finance_disclosure_fee_amount".to_string(),
        "trade_finance_disclosure_credential_commitment".to_string(),
        "trade_finance_disclosure_request_id_hash".to_string(),
        "trade_finance_disclosure_caller_commitment".to_string(),
        "trade_finance_disclosure_public_blinding_0".to_string(),
        "trade_finance_disclosure_public_blinding_1".to_string(),
    ]
}

fn shard_input_names() -> Vec<String> {
    let mut names = vec![
        "trade_finance_shard_shard_count".to_string(),
        "trade_finance_shard_blinding_0".to_string(),
        "trade_finance_shard_blinding_1".to_string(),
    ];
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        names.push(format!("trade_finance_shard_receivable_commitment_{index}"));
    }
    names
}

pub fn trade_finance_private_input_names_v1() -> Vec<String> {
    let mut names = vec![
        financing_policy_input_name("financing_policy_id_hash"),
        financing_policy_input_name("financing_window_open_timestamp"),
        financing_policy_input_name("financing_window_close_timestamp"),
    ];
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES {
        names.push(financing_policy_array_name(
            "eligibility_predicate_flag",
            index,
        ));
        names.push(financing_policy_array_name(
            "lender_exclusion_predicate_flag",
            index,
        ));
    }
    for index in 0..2 {
        names.push(financing_policy_array_name(
            "supplier_retention_schedule",
            index,
        ));
        names.push(financing_policy_array_name("advance_cap_schedule", index));
        names.push(financing_policy_array_name("discount_rate_rule", index));
        names.push(financing_policy_array_name(
            "reserve_holdback_parameter",
            index,
        ));
    }
    for index in 0..3 {
        names.push(financing_policy_array_name(
            "financier_participation_parameter",
            index,
        ));
    }
    names.extend([
        receivable_input_name("receivable_id_hash"),
        receivable_input_name("supplier_id_hash"),
        receivable_input_name("invoice_presented_timestamp"),
        receivable_input_name("financing_request_timestamp"),
        receivable_input_name("jurisdiction_corridor_bucket"),
        receivable_input_name("goods_or_service_class"),
    ]);
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES {
        names.push(receivable_array_name(
            "observed_eligibility_predicate_flag",
            index,
        ));
        names.push(receivable_array_name("buyer_acceptance_term_flag", index));
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        names.push(receivable_array_name("prior_financing_linkage_hash", index));
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS {
        names.push(evidence_line_name("estimate", "quantity", index));
        names.push(evidence_line_name("estimate", "unit_amount", index));
        names.push(evidence_line_name("estimate", "reference_amount", index));
        names.push(evidence_line_name("estimate", "discount_basis", index));
        names.push(evidence_line_name("invoice", "quantity", index));
        names.push(evidence_line_name("invoice", "amount", index));
        names.push(evidence_array_name("reference_amount_schedule", index));
        names.push(evidence_array_name("discount_basis_value", index));
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        names.push(evidence_array_name("logistics_event_summary", index));
        names.push(evidence_array_name("vendor_attestation_digest", index));
        names.push(duplicate_risk_array_name("duplicate_candidate_hash", index));
        names.push(duplicate_risk_array_name("price_deviation_baseline", index));
        names.push(duplicate_risk_array_name("vendor_anomaly_baseline", index));
    }
    names.extend([
        evidence_name("photo_analysis_result_digest"),
        evidence_name("document_extraction_result_digest"),
        evidence_name("buyer_approval_reference_digest"),
        evidence_name("evidence_manifest_digest"),
        duplicate_risk_name("chronology_threshold"),
        duplicate_risk_name("geographic_reasonableness_threshold"),
        duplicate_risk_name("quantity_tolerance_threshold"),
        duplicate_risk_name("valuation_tolerance_threshold"),
        settlement_terms_name("supplier_advance_destination_commitment"),
        settlement_terms_name("financier_reserve_account_commitment"),
        settlement_terms_name("financier_participation_commitment"),
        settlement_terms_name("dispute_escalation_threshold"),
        settlement_terms_name("risk_review_threshold"),
        settlement_terms_name("manual_review_threshold"),
        settlement_terms_array_name("settlement_blinding", 0),
        settlement_terms_array_name("settlement_blinding", 1),
        settlement_terms_array_name("public_disclosure_blinding", 0),
        settlement_terms_array_name("public_disclosure_blinding", 1),
    ]);
    names
}

fn expected_public_output_names() -> Vec<String> {
    vec![
        "invoice_packet_commitment".to_string(),
        "eligibility_commitment".to_string(),
        "consistency_score_commitment".to_string(),
        "duplicate_financing_risk_commitment".to_string(),
        "approved_advance_commitment".to_string(),
        "reserve_amount_commitment".to_string(),
        "settlement_instruction_commitment".to_string(),
        "action_class_code".to_string(),
        "human_review_required".to_string(),
        "eligible_for_midnight_settlement".to_string(),
    ]
}

fn validate_private_inputs(request: &TradeFinancePrivateInputsV1) -> ZkfResult<()> {
    if request.financing_policy.financing_window_open_timestamp
        > request.financing_policy.financing_window_close_timestamp
    {
        return Err(ZkfError::InvalidArtifact(
            "financing window open timestamp must be <= financing window close timestamp"
                .to_string(),
        ));
    }
    if request.receivable_context.invoice_presented_timestamp
        > request.receivable_context.financing_request_timestamp
    {
        return Err(ZkfError::InvalidArtifact(
            "invoice presented timestamp must be <= financing request timestamp for this flagship lane".to_string(),
        ));
    }
    for flag in request
        .financing_policy
        .eligibility_predicate_flags
        .into_iter()
        .chain(request.financing_policy.lender_exclusion_predicate_flags)
        .chain(
            request
                .receivable_context
                .observed_eligibility_predicate_flags,
        )
        .chain(request.receivable_context.buyer_acceptance_term_flags)
    {
        if flag > 1 {
            return Err(ZkfError::InvalidArtifact(
                "boolean financing-policy/receivable flags must be 0 or 1".to_string(),
            ));
        }
    }
    for value in [
        request
            .duplicate_risk_inputs
            .chronology_consistency_threshold,
        request.duplicate_risk_inputs.quantity_tolerance_threshold,
        request.duplicate_risk_inputs.valuation_tolerance_threshold,
        request.settlement_terms.dispute_escalation_threshold,
        request.settlement_terms.risk_review_threshold,
        request.settlement_terms.manual_review_threshold,
    ] {
        if value == 0 {
            return Err(ZkfError::InvalidArtifact(
                "threshold inputs must be non-zero".to_string(),
            ));
        }
    }
    for value in [
        request.settlement_terms.disclosure_credential_commitment,
        request.settlement_terms.disclosure_request_id_hash,
        request.settlement_terms.disclosure_caller_commitment,
    ] {
        if value == 0 {
            return Err(ZkfError::InvalidArtifact(
                "disclosure authorization commitments must be non-zero".to_string(),
            ));
        }
    }
    let _ =
        evidence_manifest_digest_bigint(&request.supporting_documents.evidence_manifest_digest)?;
    Ok(())
}

fn flatten_private_inputs(request: &TradeFinancePrivateInputsV1) -> ZkfResult<WitnessInputs> {
    validate_private_inputs(request)?;
    let mut values = BTreeMap::new();
    write_value(
        &mut values,
        financing_policy_input_name("financing_policy_id_hash"),
        request.financing_policy.financing_policy_id_hash,
    );
    write_value(
        &mut values,
        financing_policy_input_name("financing_window_open_timestamp"),
        request.financing_policy.financing_window_open_timestamp,
    );
    write_value(
        &mut values,
        financing_policy_input_name("financing_window_close_timestamp"),
        request.financing_policy.financing_window_close_timestamp,
    );
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES {
        write_value(
            &mut values,
            financing_policy_array_name("eligibility_predicate_flag", index),
            request.financing_policy.eligibility_predicate_flags[index],
        );
        write_value(
            &mut values,
            financing_policy_array_name("lender_exclusion_predicate_flag", index),
            request.financing_policy.lender_exclusion_predicate_flags[index],
        );
        write_value(
            &mut values,
            receivable_array_name("observed_eligibility_predicate_flag", index),
            request
                .receivable_context
                .observed_eligibility_predicate_flags[index],
        );
        write_value(
            &mut values,
            receivable_array_name("buyer_acceptance_term_flag", index),
            request.receivable_context.buyer_acceptance_term_flags[index],
        );
    }
    for index in 0..2 {
        write_value(
            &mut values,
            financing_policy_array_name("supplier_retention_schedule", index),
            request.financing_policy.supplier_retention_schedule[index],
        );
        write_value(
            &mut values,
            financing_policy_array_name("advance_cap_schedule", index),
            request.financing_policy.advance_cap_schedule[index],
        );
        write_value(
            &mut values,
            financing_policy_array_name("discount_rate_rule", index),
            request.financing_policy.discount_rate_rules[index],
        );
        write_value(
            &mut values,
            financing_policy_array_name("reserve_holdback_parameter", index),
            request.financing_policy.reserve_holdback_parameters[index],
        );
    }
    for index in 0..3 {
        write_value(
            &mut values,
            financing_policy_array_name("financier_participation_parameter", index),
            request.financing_policy.financier_participation_parameters[index],
        );
    }
    write_value(
        &mut values,
        receivable_input_name("receivable_id_hash"),
        request.receivable_context.receivable_id_hash,
    );
    write_value(
        &mut values,
        receivable_input_name("supplier_id_hash"),
        request.receivable_context.supplier_id_hash,
    );
    write_value(
        &mut values,
        receivable_input_name("invoice_presented_timestamp"),
        request.receivable_context.invoice_presented_timestamp,
    );
    write_value(
        &mut values,
        receivable_input_name("financing_request_timestamp"),
        request.receivable_context.financing_request_timestamp,
    );
    write_value(
        &mut values,
        receivable_input_name("jurisdiction_corridor_bucket"),
        request.receivable_context.jurisdiction_corridor_bucket,
    );
    write_value(
        &mut values,
        receivable_input_name("goods_or_service_class"),
        request.receivable_context.goods_or_service_class,
    );
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        write_value(
            &mut values,
            receivable_array_name("prior_financing_linkage_hash", index),
            request.receivable_context.prior_financing_linkage_hashes[index],
        );
        write_value(
            &mut values,
            evidence_array_name("logistics_event_summary", index),
            request.supporting_documents.logistics_event_summary_values[index],
        );
        write_value(
            &mut values,
            evidence_array_name("vendor_attestation_digest", index),
            request.supporting_documents.vendor_attestation_digests[index],
        );
        write_value(
            &mut values,
            duplicate_risk_array_name("duplicate_candidate_hash", index),
            request
                .duplicate_risk_inputs
                .duplicate_receivable_candidate_hashes[index],
        );
        write_value(
            &mut values,
            duplicate_risk_array_name("price_deviation_baseline", index),
            request.duplicate_risk_inputs.price_deviation_baselines[index],
        );
        write_value(
            &mut values,
            duplicate_risk_array_name("vendor_anomaly_baseline", index),
            request.duplicate_risk_inputs.vendor_anomaly_baselines[index],
        );
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS {
        let estimate = &request.supporting_documents.supporting_schedule_line_items[index];
        let invoice = &request.supporting_documents.invoice_line_items[index];
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
            evidence_line_name("estimate", "reference_amount", index),
            estimate.reference_amount,
        );
        write_value(
            &mut values,
            evidence_line_name("estimate", "discount_basis", index),
            estimate.discount_basis,
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
            evidence_array_name("reference_amount_schedule", index),
            request.supporting_documents.reference_amount_schedules[index],
        );
        write_value(
            &mut values,
            evidence_array_name("discount_basis_value", index),
            request.supporting_documents.discount_basis_values[index],
        );
    }
    write_value(
        &mut values,
        evidence_name("photo_analysis_result_digest"),
        request.supporting_documents.photo_analysis_result_digest,
    );
    write_value(
        &mut values,
        evidence_name("document_extraction_result_digest"),
        request
            .supporting_documents
            .document_extraction_result_digest,
    );
    write_value(
        &mut values,
        evidence_name("buyer_approval_reference_digest"),
        request.supporting_documents.buyer_approval_reference_digest,
    );
    write_value(
        &mut values,
        evidence_name("evidence_manifest_digest"),
        evidence_manifest_digest_bigint(&request.supporting_documents.evidence_manifest_digest)?,
    );
    write_value(
        &mut values,
        duplicate_risk_name("chronology_threshold"),
        request
            .duplicate_risk_inputs
            .chronology_consistency_threshold,
    );
    write_value(
        &mut values,
        duplicate_risk_name("geographic_reasonableness_threshold"),
        request
            .duplicate_risk_inputs
            .geographic_reasonableness_threshold,
    );
    write_value(
        &mut values,
        duplicate_risk_name("quantity_tolerance_threshold"),
        request.duplicate_risk_inputs.quantity_tolerance_threshold,
    );
    write_value(
        &mut values,
        duplicate_risk_name("valuation_tolerance_threshold"),
        request.duplicate_risk_inputs.valuation_tolerance_threshold,
    );
    write_value(
        &mut values,
        settlement_terms_name("supplier_advance_destination_commitment"),
        request
            .settlement_terms
            .supplier_advance_destination_commitment,
    );
    write_value(
        &mut values,
        settlement_terms_name("financier_reserve_account_commitment"),
        request
            .settlement_terms
            .financier_reserve_account_commitment,
    );
    write_value(
        &mut values,
        settlement_terms_name("financier_participation_commitment"),
        request.settlement_terms.financier_participation_commitment,
    );
    write_value(
        &mut values,
        settlement_terms_name("dispute_escalation_threshold"),
        request.settlement_terms.dispute_escalation_threshold,
    );
    write_value(
        &mut values,
        settlement_terms_name("risk_review_threshold"),
        request.settlement_terms.risk_review_threshold,
    );
    write_value(
        &mut values,
        settlement_terms_name("manual_review_threshold"),
        request.settlement_terms.manual_review_threshold,
    );
    for index in 0..2 {
        write_value(
            &mut values,
            settlement_terms_array_name("settlement_blinding", index),
            request.settlement_terms.settlement_blinding_values[index],
        );
        write_value(
            &mut values,
            settlement_terms_array_name("public_disclosure_blinding", index),
            request.settlement_terms.public_disclosure_blinding_values[index],
        );
    }
    Ok(values)
}

fn declare_private_inputs(builder: &mut ProgramBuilder) -> ZkfResult<()> {
    for name in trade_finance_private_input_names_v1() {
        builder.private_input(&name)?;
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES {
        builder.constrain_boolean(financing_policy_array_name(
            "eligibility_predicate_flag",
            index,
        ))?;
        builder.constrain_boolean(financing_policy_array_name(
            "lender_exclusion_predicate_flag",
            index,
        ))?;
        builder.constrain_boolean(receivable_array_name(
            "observed_eligibility_predicate_flag",
            index,
        ))?;
        builder.constrain_boolean(receivable_array_name("buyer_acceptance_term_flag", index))?;
    }
    for name in [
        financing_policy_input_name("financing_policy_id_hash"),
        financing_policy_input_name("financing_window_open_timestamp"),
        financing_policy_input_name("financing_window_close_timestamp"),
        receivable_input_name("receivable_id_hash"),
        receivable_input_name("supplier_id_hash"),
        receivable_input_name("invoice_presented_timestamp"),
        receivable_input_name("financing_request_timestamp"),
        receivable_input_name("jurisdiction_corridor_bucket"),
        receivable_input_name("goods_or_service_class"),
        evidence_name("photo_analysis_result_digest"),
        evidence_name("document_extraction_result_digest"),
        evidence_name("buyer_approval_reference_digest"),
        duplicate_risk_name("chronology_threshold"),
        duplicate_risk_name("geographic_reasonableness_threshold"),
        duplicate_risk_name("quantity_tolerance_threshold"),
        duplicate_risk_name("valuation_tolerance_threshold"),
        settlement_terms_name("supplier_advance_destination_commitment"),
        settlement_terms_name("financier_reserve_account_commitment"),
        settlement_terms_name("financier_participation_commitment"),
        settlement_terms_name("dispute_escalation_threshold"),
        settlement_terms_name("risk_review_threshold"),
        settlement_terms_name("manual_review_threshold"),
    ] {
        let bound = if name.contains("timestamp") {
            TRADE_FINANCE_TIMESTAMP_BOUND
        } else if name.contains("digest") || name.contains("commitment") || name.contains("hash") {
            TRADE_FINANCE_HASH_BOUND
        } else {
            TRADE_FINANCE_UINT_BOUND
        };
        builder.constrain_range(&name, bits_for_bound(bound))?;
    }
    builder.constrain_range(evidence_name("evidence_manifest_digest"), 254)?;
    for index in 0..2 {
        for name in [
            financing_policy_array_name("supplier_retention_schedule", index),
            financing_policy_array_name("advance_cap_schedule", index),
            financing_policy_array_name("discount_rate_rule", index),
            financing_policy_array_name("reserve_holdback_parameter", index),
            settlement_terms_array_name("settlement_blinding", index),
            settlement_terms_array_name("public_disclosure_blinding", index),
        ] {
            builder.constrain_range(&name, bits_for_bound(TRADE_FINANCE_UINT_BOUND))?;
        }
    }
    for index in 0..3 {
        builder.constrain_range(
            financing_policy_array_name("financier_participation_parameter", index),
            bits_for_bound(TRADE_FINANCE_UINT_BOUND),
        )?;
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        for name in [
            receivable_array_name("prior_financing_linkage_hash", index),
            evidence_array_name("logistics_event_summary", index),
            evidence_array_name("vendor_attestation_digest", index),
            duplicate_risk_array_name("duplicate_candidate_hash", index),
            duplicate_risk_array_name("price_deviation_baseline", index),
            duplicate_risk_array_name("vendor_anomaly_baseline", index),
        ] {
            builder.constrain_range(&name, bits_for_bound(TRADE_FINANCE_HASH_BOUND))?;
        }
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS {
        for name in [
            evidence_line_name("estimate", "quantity", index),
            evidence_line_name("estimate", "unit_amount", index),
            evidence_line_name("estimate", "reference_amount", index),
            evidence_line_name("estimate", "discount_basis", index),
            evidence_line_name("invoice", "quantity", index),
            evidence_line_name("invoice", "amount", index),
            evidence_array_name("reference_amount_schedule", index),
            evidence_array_name("discount_basis_value", index),
        ] {
            builder.constrain_range(&name, bits_for_bound(TRADE_FINANCE_VALUE_BOUND))?;
        }
    }
    Ok(())
}

pub fn build_trade_finance_decision_core_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new("trade_finance_decision_core_v1", TRADE_FINANCE_FIELD);
    declare_private_inputs(&mut builder)?;
    for output in expected_public_output_names() {
        builder.public_output(output)?;
    }
    builder.metadata_entry("nova_ivc_in", "invoice_packet_commitment")?;
    builder.metadata_entry("nova_ivc_out", "settlement_instruction_commitment")?;
    builder.constant_signal("__trade_finance_score_cap", field(TRADE_FINANCE_SCORE_CAP))?;
    builder.constant_signal(
        "__trade_finance_component_score_cap",
        field(TRADE_FINANCE_COMPONENT_SCORE_CAP),
    )?;
    builder.constant_signal(
        "__trade_finance_scale",
        field(TRADE_FINANCE_FIXED_POINT_SCALE),
    )?;
    builder.constant_signal("__trade_finance_one", FieldElement::ONE)?;
    builder.constant_signal("__trade_finance_zero", FieldElement::ZERO)?;

    let all_inputs = trade_finance_private_input_names_v1();
    let invoice_packet_digest = append_private_input_anchor_chain(
        &mut builder,
        &all_inputs,
        "trade_finance_packet_anchor",
    )?;
    builder.constrain_equal(
        signal_expr("invoice_packet_commitment"),
        signal_expr(&invoice_packet_digest),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&receivable_input_name("invoice_presented_timestamp")),
        signal_expr(&financing_policy_input_name(
            "financing_window_open_timestamp",
        )),
        "trade_finance_within_term_window_incident_after_effective_bit",
        "trade_finance_within_term_window_incident_after_effective_slack",
        TRADE_FINANCE_TIMESTAMP_BOUND,
        "trade_finance_within_term_window_incident_after_effective",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&financing_policy_input_name(
            "financing_window_close_timestamp",
        )),
        signal_expr(&receivable_input_name("invoice_presented_timestamp")),
        "trade_finance_within_term_window_expiration_after_incident_bit",
        "trade_finance_within_term_window_expiration_after_incident_slack",
        TRADE_FINANCE_TIMESTAMP_BOUND,
        "trade_finance_within_term_window_expiration_after_incident",
    )?;
    append_boolean_and(
        &mut builder,
        "trade_finance_within_term_window_bit",
        signal_expr("trade_finance_within_term_window_incident_after_effective_bit"),
        signal_expr("trade_finance_within_term_window_expiration_after_incident_bit"),
    )?;

    builder.private_signal("trade_finance_matched_eligibility_predicate_count")?;
    builder.bind(
        "trade_finance_matched_eligibility_predicate_count",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES)
                .map(|index| {
                    mul_expr(
                        signal_expr(&financing_policy_array_name(
                            "eligibility_predicate_flag",
                            index,
                        )),
                        signal_expr(&receivable_array_name(
                            "observed_eligibility_predicate_flag",
                            index,
                        )),
                    )
                })
                .collect(),
        ),
    )?;
    builder.constrain_range("trade_finance_matched_eligibility_predicate_count", 4)?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_matched_eligibility_predicate_count"),
        const_expr(1),
        "trade_finance_eligibility_predicate_supported_bit",
        "trade_finance_eligibility_predicate_supported_slack",
        PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES as u64 + 1,
        "trade_finance_eligibility_predicate_supported",
    )?;

    builder.private_signal("trade_finance_lender_exclusion_match_count")?;
    builder.bind(
        "trade_finance_lender_exclusion_match_count",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES)
                .map(|index| {
                    mul_expr(
                        signal_expr(&financing_policy_array_name(
                            "lender_exclusion_predicate_flag",
                            index,
                        )),
                        signal_expr(&receivable_array_name(
                            "observed_eligibility_predicate_flag",
                            index,
                        )),
                    )
                })
                .collect(),
        ),
    )?;
    builder.constrain_range("trade_finance_lender_exclusion_match_count", 4)?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_lender_exclusion_match_count"),
        const_expr(1),
        "trade_finance_lender_exclusion_triggered_bit",
        "trade_finance_lender_exclusion_triggered_slack",
        PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES as u64 + 1,
        "trade_finance_lender_exclusion_triggered",
    )?;

    builder.private_signal("trade_finance_buyer_acceptance_term_count")?;
    builder.bind(
        "trade_finance_buyer_acceptance_term_count",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES)
                .map(|index| {
                    signal_expr(&receivable_array_name("buyer_acceptance_term_flag", index))
                })
                .collect(),
        ),
    )?;
    builder.constrain_range("trade_finance_buyer_acceptance_term_count", 4)?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_buyer_acceptance_term_count"),
        const_expr(1),
        "trade_finance_receivable_category_present_bit",
        "trade_finance_receivable_category_present_slack",
        PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES as u64 + 1,
        "trade_finance_receivable_category_present",
    )?;

    builder.private_signal("trade_finance_not_lender_exclusion_triggered_bit")?;
    builder.bind(
        "trade_finance_not_lender_exclusion_triggered_bit",
        sub_expr(
            const_expr(1),
            signal_expr("trade_finance_lender_exclusion_triggered_bit"),
        ),
    )?;
    builder.constrain_boolean("trade_finance_not_lender_exclusion_triggered_bit")?;

    append_boolean_and(
        &mut builder,
        "trade_finance_eligibility_passed_pre_category_bit",
        signal_expr("trade_finance_within_term_window_bit"),
        signal_expr("trade_finance_eligibility_predicate_supported_bit"),
    )?;
    append_boolean_and(
        &mut builder,
        "trade_finance_eligibility_passed_pre_exclusion_bit",
        signal_expr("trade_finance_eligibility_passed_pre_category_bit"),
        signal_expr("trade_finance_not_lender_exclusion_triggered_bit"),
    )?;
    append_boolean_and(
        &mut builder,
        "trade_finance_eligibility_passed_bit",
        signal_expr("trade_finance_eligibility_passed_pre_exclusion_bit"),
        signal_expr("trade_finance_receivable_category_present_bit"),
    )?;

    let coverage_commitment = builder.append_poseidon_hash(
        "trade_finance_coverage_commitment",
        [
            const_expr(TRADE_FINANCE_DOMAIN_COVERAGE),
            signal_expr("trade_finance_eligibility_passed_bit"),
            signal_expr("trade_finance_within_term_window_bit"),
            signal_expr("trade_finance_lender_exclusion_match_count"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("eligibility_commitment"),
        signal_expr(&coverage_commitment),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&receivable_input_name("financing_request_timestamp")),
        signal_expr(&receivable_input_name("invoice_presented_timestamp")),
        "trade_finance_reported_after_incident_bit",
        "trade_finance_reported_after_incident_slack",
        TRADE_FINANCE_TIMESTAMP_BOUND,
        "trade_finance_reported_after_incident",
    )?;
    builder.private_signal("trade_finance_report_delay")?;
    builder.bind(
        "trade_finance_report_delay",
        sub_expr(
            signal_expr(&receivable_input_name("financing_request_timestamp")),
            signal_expr(&receivable_input_name("invoice_presented_timestamp")),
        ),
    )?;
    builder.constrain_range(
        "trade_finance_report_delay",
        bits_for_bound(TRADE_FINANCE_TIMESTAMP_BOUND),
    )?;
    builder.private_signal("trade_finance_report_delay_margin_shifted")?;
    builder.constrain_equal(
        signal_expr("trade_finance_report_delay_margin_shifted"),
        add_expr(vec![
            signal_expr("trade_finance_report_delay"),
            const_expr(TRADE_FINANCE_SIGNED_MARGIN_OFFSET),
            sub_expr(
                const_expr(0),
                signal_expr(&duplicate_risk_name("chronology_threshold")),
            ),
        ]),
    )?;
    builder.constrain_range(
        "trade_finance_report_delay_margin_shifted",
        bits_for_bound(TRADE_FINANCE_SIGNED_MARGIN_BOUND),
    )?;

    let digest_inputs = vec![
        evidence_name("photo_analysis_result_digest"),
        evidence_name("document_extraction_result_digest"),
        evidence_name("buyer_approval_reference_digest"),
        evidence_array_name("logistics_event_summary", 0),
    ];
    let digest_anchor = append_private_input_anchor_chain(
        &mut builder,
        &digest_inputs,
        "trade_finance_evidence_anchor",
    )?;
    builder.constrain_equal(
        signal_expr(&digest_anchor),
        signal_expr(&evidence_name("evidence_manifest_digest")),
    )?;

    for index in 0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS {
        builder.private_signal(&format!("trade_finance_estimate_total_{index}"))?;
        builder.bind(
            format!("trade_finance_estimate_total_{index}"),
            mul_expr(
                signal_expr(&evidence_line_name("estimate", "quantity", index)),
                signal_expr(&evidence_line_name("estimate", "unit_amount", index)),
            ),
        )?;
        builder.constrain_range(
            &format!("trade_finance_estimate_total_{index}"),
            bits_for_bound(TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND),
        )?;
        append_pairwise_min_signal(
            &mut builder,
            &format!("trade_finance_replacement_min_{index}"),
            &format!("trade_finance_estimate_total_{index}"),
            &evidence_line_name("estimate", "reference_amount", index),
            TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
            &format!("trade_finance_replacement_min_{index}"),
        )?;
        append_pairwise_max_signal(
            &mut builder,
            &format!("trade_finance_replacement_max_{index}"),
            &format!("trade_finance_estimate_total_{index}"),
            &evidence_line_name("estimate", "reference_amount", index),
            TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
            &format!("trade_finance_replacement_max_{index}"),
        )?;
        builder.private_signal(&format!("trade_finance_replacement_gap_{index}"))?;
        builder.bind(
            format!("trade_finance_replacement_gap_{index}"),
            sub_expr(
                signal_expr(&format!("trade_finance_replacement_max_{index}")),
                signal_expr(&format!("trade_finance_replacement_min_{index}")),
            ),
        )?;
        append_pairwise_min_signal(
            &mut builder,
            &format!("trade_finance_invoice_amount_min_{index}"),
            &format!("trade_finance_estimate_total_{index}"),
            &evidence_line_name("invoice", "amount", index),
            TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
            &format!("trade_finance_invoice_amount_min_{index}"),
        )?;
        append_pairwise_max_signal(
            &mut builder,
            &format!("trade_finance_invoice_amount_max_{index}"),
            &format!("trade_finance_estimate_total_{index}"),
            &evidence_line_name("invoice", "amount", index),
            TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
            &format!("trade_finance_invoice_amount_max_{index}"),
        )?;
        builder.private_signal(&format!("trade_finance_invoice_gap_{index}"))?;
        builder.bind(
            format!("trade_finance_invoice_gap_{index}"),
            sub_expr(
                signal_expr(&format!("trade_finance_invoice_amount_max_{index}")),
                signal_expr(&format!("trade_finance_invoice_amount_min_{index}")),
            ),
        )?;
        append_pairwise_min_signal(
            &mut builder,
            &format!("trade_finance_invoice_quantity_min_{index}"),
            &evidence_line_name("estimate", "quantity", index),
            &evidence_line_name("invoice", "quantity", index),
            TRADE_FINANCE_VALUE_BOUND,
            &format!("trade_finance_invoice_quantity_min_{index}"),
        )?;
        append_pairwise_max_signal(
            &mut builder,
            &format!("trade_finance_invoice_quantity_max_{index}"),
            &evidence_line_name("estimate", "quantity", index),
            &evidence_line_name("invoice", "quantity", index),
            TRADE_FINANCE_VALUE_BOUND,
            &format!("trade_finance_invoice_quantity_max_{index}"),
        )?;
        builder.private_signal(&format!("trade_finance_quantity_gap_{index}"))?;
        builder.bind(
            format!("trade_finance_quantity_gap_{index}"),
            sub_expr(
                signal_expr(&format!("trade_finance_invoice_quantity_max_{index}")),
                signal_expr(&format!("trade_finance_invoice_quantity_min_{index}")),
            ),
        )?;
    }

    for aggregate in [
        "trade_finance_total_estimate_amount",
        "trade_finance_total_invoice_amount",
        "trade_finance_total_reference_amount",
        "trade_finance_total_valuation_gap",
        "trade_finance_total_quantity_gap",
        "trade_finance_total_price_baseline",
        "trade_finance_total_vendor_baseline",
        "trade_finance_total_vendor_digest",
        "trade_finance_complete_digest_count",
        "trade_finance_duplicate_match_count",
    ] {
        builder.private_signal(aggregate)?;
    }
    builder.bind(
        "trade_finance_total_estimate_amount",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS)
                .map(|index| signal_expr(&format!("trade_finance_estimate_total_{index}")))
                .collect(),
        ),
    )?;
    builder.bind(
        "trade_finance_total_invoice_amount",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS)
                .map(|index| signal_expr(&evidence_line_name("invoice", "amount", index)))
                .collect(),
        ),
    )?;
    builder.bind(
        "trade_finance_total_reference_amount",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS)
                .map(|index| {
                    signal_expr(&evidence_line_name("estimate", "reference_amount", index))
                })
                .collect(),
        ),
    )?;
    builder.bind(
        "trade_finance_total_valuation_gap",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS)
                .flat_map(|index| {
                    [
                        signal_expr(&format!("trade_finance_replacement_gap_{index}")),
                        signal_expr(&format!("trade_finance_invoice_gap_{index}")),
                    ]
                })
                .collect(),
        ),
    )?;
    builder.bind(
        "trade_finance_total_quantity_gap",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS)
                .map(|index| signal_expr(&format!("trade_finance_quantity_gap_{index}")))
                .collect(),
        ),
    )?;
    builder.bind(
        "trade_finance_total_price_baseline",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS)
                .map(|index| {
                    signal_expr(&duplicate_risk_array_name(
                        "price_deviation_baseline",
                        index,
                    ))
                })
                .collect(),
        ),
    )?;
    builder.bind(
        "trade_finance_total_vendor_baseline",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS)
                .map(|index| {
                    signal_expr(&duplicate_risk_array_name("vendor_anomaly_baseline", index))
                })
                .collect(),
        ),
    )?;
    builder.bind(
        "trade_finance_total_vendor_digest",
        add_expr(
            (0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS)
                .map(|index| signal_expr(&evidence_array_name("vendor_attestation_digest", index)))
                .collect(),
        ),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr(&duplicate_risk_name("geographic_reasonableness_threshold")),
        signal_expr(&receivable_input_name("jurisdiction_corridor_bucket")),
        "trade_finance_geographic_reasonable_bit",
        "trade_finance_geographic_reasonable_slack",
        TRADE_FINANCE_UINT_BOUND,
        "trade_finance_geographic_reasonable",
    )?;

    let mut duplicate_eq_bits = Vec::new();
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        duplicate_eq_bits.push(append_equality_with_inverse(
            &mut builder,
            signal_expr(&receivable_array_name(
                "prior_financing_linkage_hash",
                index,
            )),
            signal_expr(&duplicate_risk_array_name(
                "duplicate_candidate_hash",
                index,
            )),
            &format!("trade_finance_duplicate_match_{index}"),
        )?);
    }
    builder.bind(
        "trade_finance_duplicate_match_count",
        add_expr(
            duplicate_eq_bits
                .iter()
                .map(|name| signal_expr(name))
                .collect(),
        ),
    )?;

    let nonzero_digest_sources = vec![
        evidence_name("photo_analysis_result_digest"),
        evidence_name("document_extraction_result_digest"),
        evidence_name("buyer_approval_reference_digest"),
        evidence_name("evidence_manifest_digest"),
    ];
    let mut complete_digest_bits = Vec::new();
    for (index, source) in nonzero_digest_sources.iter().enumerate() {
        let present = format!("trade_finance_digest_present_{index}");
        append_nonzero_indicator(&mut builder, &present, signal_expr(source), &present)?;
        complete_digest_bits.push(present);
    }
    builder.bind(
        "trade_finance_complete_digest_count",
        add_expr(
            complete_digest_bits
                .iter()
                .map(|name| signal_expr(name))
                .collect(),
        ),
    )?;

    builder.append_exact_division_constraints(
        signal_expr("trade_finance_report_delay"),
        signal_expr(&duplicate_risk_name("chronology_threshold")),
        "trade_finance_chronology_ratio",
        "trade_finance_chronology_ratio_remainder",
        "trade_finance_chronology_ratio_slack",
        &BigInt::from(TRADE_FINANCE_TIMESTAMP_BOUND),
        "trade_finance_chronology_ratio",
    )?;
    builder.private_signal("trade_finance_chronology_score_raw")?;
    builder.bind(
        "trade_finance_chronology_score_raw",
        add_expr(vec![
            mul_expr(
                signal_expr("trade_finance_chronology_ratio"),
                const_expr(1_000),
            ),
            mul_expr(
                sub_expr(
                    const_expr(1),
                    signal_expr("trade_finance_reported_after_incident_bit"),
                ),
                const_expr(2_000),
            ),
        ]),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_chronology_score",
        "trade_finance_chronology_score_raw",
        "__trade_finance_component_score_cap",
        TRADE_FINANCE_RATIO_BOUND,
        "trade_finance_chronology_score",
    )?;

    builder.append_exact_division_constraints(
        signal_expr("trade_finance_total_valuation_gap"),
        signal_expr(&duplicate_risk_name("valuation_tolerance_threshold")),
        "trade_finance_valuation_ratio",
        "trade_finance_valuation_ratio_remainder",
        "trade_finance_valuation_ratio_slack",
        &BigInt::from(TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND),
        "trade_finance_valuation_ratio",
    )?;
    builder.private_signal("trade_finance_valuation_score_raw")?;
    builder.bind(
        "trade_finance_valuation_score_raw",
        mul_expr(
            signal_expr("trade_finance_valuation_ratio"),
            const_expr(1_000),
        ),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_valuation_score",
        "trade_finance_valuation_score_raw",
        "__trade_finance_component_score_cap",
        TRADE_FINANCE_RATIO_BOUND,
        "trade_finance_valuation_score",
    )?;

    builder.append_exact_division_constraints(
        signal_expr("trade_finance_total_quantity_gap"),
        signal_expr(&duplicate_risk_name("quantity_tolerance_threshold")),
        "trade_finance_quantity_ratio",
        "trade_finance_quantity_ratio_remainder",
        "trade_finance_quantity_ratio_slack",
        &BigInt::from(TRADE_FINANCE_VALUE_BOUND),
        "trade_finance_quantity_ratio",
    )?;
    builder.private_signal("trade_finance_quantity_score_raw")?;
    builder.bind(
        "trade_finance_quantity_score_raw",
        mul_expr(
            signal_expr("trade_finance_quantity_ratio"),
            const_expr(1_000),
        ),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_quantity_score",
        "trade_finance_quantity_score_raw",
        "__trade_finance_component_score_cap",
        TRADE_FINANCE_RATIO_BOUND,
        "trade_finance_quantity_score",
    )?;

    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_vendor_gap_min",
        "trade_finance_total_vendor_digest",
        "trade_finance_total_vendor_baseline",
        TRADE_FINANCE_HASH_BOUND,
        "trade_finance_vendor_gap_min",
    )?;
    append_pairwise_max_signal(
        &mut builder,
        "trade_finance_vendor_gap_max",
        "trade_finance_total_vendor_digest",
        "trade_finance_total_vendor_baseline",
        TRADE_FINANCE_HASH_BOUND,
        "trade_finance_vendor_gap_max",
    )?;
    builder.private_signal("trade_finance_vendor_gap")?;
    builder.bind(
        "trade_finance_vendor_gap",
        sub_expr(
            signal_expr("trade_finance_vendor_gap_max"),
            signal_expr("trade_finance_vendor_gap_min"),
        ),
    )?;
    builder.private_signal("trade_finance_total_vendor_baseline_plus_one")?;
    builder.bind(
        "trade_finance_total_vendor_baseline_plus_one",
        add_expr(vec![
            signal_expr("trade_finance_total_vendor_baseline"),
            const_expr(1),
        ]),
    )?;
    builder.append_exact_division_constraints(
        signal_expr("trade_finance_vendor_gap"),
        signal_expr("trade_finance_total_vendor_baseline_plus_one"),
        "trade_finance_vendor_ratio",
        "trade_finance_vendor_ratio_remainder",
        "trade_finance_vendor_ratio_slack",
        &BigInt::from(TRADE_FINANCE_HASH_BOUND),
        "trade_finance_vendor_ratio",
    )?;
    builder.private_signal("trade_finance_vendor_score_raw")?;
    builder.bind(
        "trade_finance_vendor_score_raw",
        mul_expr(signal_expr("trade_finance_vendor_ratio"), const_expr(750)),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_vendor_score",
        "trade_finance_vendor_score_raw",
        "__trade_finance_component_score_cap",
        TRADE_FINANCE_RATIO_BOUND,
        "trade_finance_vendor_score",
    )?;

    builder.private_signal("trade_finance_eligibility_mismatch_score")?;
    builder.bind(
        "trade_finance_eligibility_mismatch_score",
        add_expr(vec![
            mul_expr(
                sub_expr(
                    const_expr(1),
                    signal_expr("trade_finance_eligibility_passed_bit"),
                ),
                const_expr(5_000),
            ),
            mul_expr(
                signal_expr("trade_finance_lender_exclusion_triggered_bit"),
                const_expr(2_000),
            ),
        ]),
    )?;
    builder.constrain_range(
        "trade_finance_eligibility_mismatch_score",
        bits_for_bound(TRADE_FINANCE_SCORE_CAP),
    )?;

    builder.private_signal("trade_finance_expected_digest_count")?;
    builder.bind(
        "trade_finance_expected_digest_count",
        const_expr(nonzero_digest_sources.len() as u64),
    )?;
    builder.private_signal("trade_finance_missing_digest_count")?;
    builder.bind(
        "trade_finance_missing_digest_count",
        sub_expr(
            signal_expr("trade_finance_expected_digest_count"),
            signal_expr("trade_finance_complete_digest_count"),
        ),
    )?;
    builder.private_signal("trade_finance_evidence_completeness_score")?;
    builder.bind(
        "trade_finance_evidence_completeness_score",
        mul_expr(
            signal_expr("trade_finance_missing_digest_count"),
            const_expr(1_000),
        ),
    )?;
    builder.constrain_range(
        "trade_finance_evidence_completeness_score",
        bits_for_bound(TRADE_FINANCE_SCORE_CAP),
    )?;

    builder.private_signal("trade_finance_structured_inconsistency_score_raw")?;
    builder.bind(
        "trade_finance_structured_inconsistency_score_raw",
        add_expr(vec![
            signal_expr("trade_finance_valuation_score"),
            signal_expr("trade_finance_quantity_score"),
            mul_expr(
                sub_expr(
                    const_expr(1),
                    signal_expr("trade_finance_geographic_reasonable_bit"),
                ),
                const_expr(800),
            ),
            mul_expr(
                sub_expr(
                    const_expr(1),
                    signal_expr("trade_finance_reported_after_incident_bit"),
                ),
                const_expr(2_000),
            ),
            signal_expr("trade_finance_evidence_completeness_score"),
        ]),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_structured_inconsistency_score",
        "trade_finance_structured_inconsistency_score_raw",
        "__trade_finance_score_cap",
        TRADE_FINANCE_SCORE_CAP * 2,
        "trade_finance_structured_inconsistency_score",
    )?;
    builder.private_signal("trade_finance_consistency_score")?;
    builder.bind(
        "trade_finance_consistency_score",
        sub_expr(
            signal_expr("__trade_finance_score_cap"),
            signal_expr("trade_finance_structured_inconsistency_score"),
        ),
    )?;
    builder.constrain_range(
        "trade_finance_consistency_score",
        bits_for_bound(TRADE_FINANCE_SCORE_CAP),
    )?;

    builder.private_signal("trade_finance_duplication_score")?;
    builder.bind(
        "trade_finance_duplication_score",
        mul_expr(
            signal_expr("trade_finance_duplicate_match_count"),
            const_expr(3_000),
        ),
    )?;
    builder.private_signal("trade_finance_duplicate_financing_risk_score_raw")?;
    builder.bind(
        "trade_finance_duplicate_financing_risk_score_raw",
        add_expr(vec![
            signal_expr("trade_finance_duplication_score"),
            signal_expr("trade_finance_vendor_score"),
            signal_expr("trade_finance_chronology_score"),
            signal_expr("trade_finance_eligibility_mismatch_score"),
        ]),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_duplicate_financing_risk_score",
        "trade_finance_duplicate_financing_risk_score_raw",
        "__trade_finance_score_cap",
        TRADE_FINANCE_SCORE_CAP * 2,
        "trade_finance_duplicate_financing_risk_score",
    )?;

    let consistency_commitment = builder.append_poseidon_hash(
        "trade_finance_consistency_commitment",
        [
            const_expr(TRADE_FINANCE_DOMAIN_CONSISTENCY),
            signal_expr("trade_finance_consistency_score"),
            signal_expr(&settlement_terms_array_name(
                "public_disclosure_blinding",
                0,
            )),
            signal_expr(&settlement_terms_array_name(
                "public_disclosure_blinding",
                1,
            )),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("consistency_score_commitment"),
        signal_expr(&consistency_commitment),
    )?;
    let duplicate_risk_commitment = builder.append_poseidon_hash(
        "trade_finance_duplicate_financing_risk_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_DUPLICATE_RISK),
            signal_expr("trade_finance_duplicate_financing_risk_score"),
            signal_expr(&settlement_terms_array_name(
                "public_disclosure_blinding",
                0,
            )),
            signal_expr(&settlement_terms_array_name(
                "public_disclosure_blinding",
                1,
            )),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("duplicate_financing_risk_commitment"),
        signal_expr(&duplicate_risk_commitment),
    )?;

    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_financing_base_amount_before_retention",
        "trade_finance_total_estimate_amount",
        "trade_finance_total_reference_amount",
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_financing_base_amount_before_retention",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_financing_base_amount_before_retention"),
        signal_expr(&financing_policy_array_name(
            "supplier_retention_schedule",
            0,
        )),
        "trade_finance_supplier_retention_applies_bit",
        "trade_finance_supplier_retention_applies_slack",
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_supplier_retention_applies",
    )?;
    builder.private_signal("trade_finance_supplier_retention_adjusted_amount")?;
    builder.bind(
        "trade_finance_supplier_retention_adjusted_amount",
        select_expr(
            signal_expr("trade_finance_supplier_retention_applies_bit"),
            sub_expr(
                signal_expr("trade_finance_financing_base_amount_before_retention"),
                signal_expr(&financing_policy_array_name(
                    "supplier_retention_schedule",
                    0,
                )),
            ),
            const_expr(0),
        ),
    )?;
    builder.constrain_range(
        "trade_finance_supplier_retention_adjusted_amount",
        bits_for_bound(TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND),
    )?;
    builder.private_signal("trade_finance_discount_raw")?;
    builder.bind(
        "trade_finance_discount_raw",
        mul_expr(
            signal_expr("trade_finance_supplier_retention_adjusted_amount"),
            signal_expr(&financing_policy_array_name("discount_rate_rule", 0)),
        ),
    )?;
    builder.append_exact_division_constraints(
        signal_expr("trade_finance_discount_raw"),
        signal_expr("__trade_finance_scale"),
        "trade_finance_discount_amount",
        "trade_finance_discount_remainder",
        "trade_finance_discount_slack",
        &BigInt::from(TRADE_FINANCE_FIXED_POINT_SCALE),
        "trade_finance_discount",
    )?;
    builder.private_signal("trade_finance_discount_adjusted_amount")?;
    builder.bind(
        "trade_finance_discount_adjusted_amount",
        sub_expr(
            signal_expr("trade_finance_supplier_retention_adjusted_amount"),
            signal_expr("trade_finance_discount_amount"),
        ),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_capped_approved_advance_amount",
        "trade_finance_discount_adjusted_amount",
        &financing_policy_array_name("advance_cap_schedule", 0),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_capped_approved_advance_amount",
    )?;
    builder.private_signal("trade_finance_reserve_margin_raw")?;
    builder.bind(
        "trade_finance_reserve_margin_raw",
        mul_expr(
            signal_expr("trade_finance_capped_approved_advance_amount"),
            signal_expr(&financing_policy_array_name(
                "reserve_holdback_parameter",
                0,
            )),
        ),
    )?;
    builder.append_exact_division_constraints(
        signal_expr("trade_finance_reserve_margin_raw"),
        signal_expr("__trade_finance_scale"),
        "trade_finance_reserve_margin_amount",
        "trade_finance_reserve_margin_remainder",
        "trade_finance_reserve_margin_slack",
        &BigInt::from(TRADE_FINANCE_FIXED_POINT_SCALE),
        "trade_finance_reserve_margin",
    )?;
    builder.private_signal("trade_finance_reserve_amount_pre_floor")?;
    builder.bind(
        "trade_finance_reserve_amount_pre_floor",
        add_expr(vec![
            signal_expr("trade_finance_capped_approved_advance_amount"),
            signal_expr("trade_finance_reserve_margin_amount"),
        ]),
    )?;
    append_pairwise_max_signal(
        &mut builder,
        "trade_finance_reserve_amount",
        "trade_finance_reserve_amount_pre_floor",
        &financing_policy_array_name("reserve_holdback_parameter", 1),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_reserve_amount",
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_capped_approved_advance_amount"),
        signal_expr(&financing_policy_array_name(
            "financier_participation_parameter",
            1,
        )),
        "trade_finance_financier_participation_attached_bit",
        "trade_finance_financier_participation_attached_slack",
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_financier_participation_attached",
    )?;
    builder.private_signal("trade_finance_financier_participation_attachment_excess")?;
    builder.bind(
        "trade_finance_financier_participation_attachment_excess",
        select_expr(
            signal_expr("trade_finance_financier_participation_attached_bit"),
            sub_expr(
                signal_expr("trade_finance_capped_approved_advance_amount"),
                signal_expr(&financing_policy_array_name(
                    "financier_participation_parameter",
                    1,
                )),
            ),
            const_expr(0),
        ),
    )?;
    append_pairwise_min_signal(
        &mut builder,
        "trade_finance_financier_participation_share_base",
        "trade_finance_financier_participation_attachment_excess",
        &financing_policy_array_name("financier_participation_parameter", 2),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_financier_participation_share_base",
    )?;
    builder.private_signal("trade_finance_financier_participation_share_raw")?;
    builder.bind(
        "trade_finance_financier_participation_share_raw",
        mul_expr(
            signal_expr("trade_finance_financier_participation_share_base"),
            signal_expr(&financing_policy_array_name(
                "financier_participation_parameter",
                0,
            )),
        ),
    )?;
    builder.append_exact_division_constraints(
        signal_expr("trade_finance_financier_participation_share_raw"),
        signal_expr("__trade_finance_scale"),
        "trade_finance_fee_amount",
        "trade_finance_financier_participation_share_remainder",
        "trade_finance_financier_participation_share_slack",
        &BigInt::from(TRADE_FINANCE_FIXED_POINT_SCALE),
        "trade_finance_financier_participation_share",
    )?;

    let approved_advance_commitment_inner = builder.append_poseidon_hash(
        "trade_finance_approved_advance_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_APPROVED_ADVANCE),
            signal_expr("trade_finance_capped_approved_advance_amount"),
            signal_expr(&settlement_terms_array_name("settlement_blinding", 0)),
            signal_expr(&settlement_terms_array_name("settlement_blinding", 1)),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("approved_advance_commitment"),
        signal_expr(&approved_advance_commitment_inner),
    )?;
    let reserve_commitment_inner = builder.append_poseidon_hash(
        "trade_finance_reserve_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_RESERVE),
            signal_expr("trade_finance_reserve_amount"),
            signal_expr(&settlement_terms_array_name("settlement_blinding", 0)),
            signal_expr(&settlement_terms_array_name("settlement_blinding", 1)),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("reserve_amount_commitment"),
        signal_expr(&reserve_commitment_inner),
    )?;

    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_structured_inconsistency_score"),
        signal_expr(&settlement_terms_name("dispute_escalation_threshold")),
        "trade_finance_inconsistency_threshold_hit_bit",
        "trade_finance_inconsistency_threshold_hit_slack",
        TRADE_FINANCE_SCORE_CAP,
        "trade_finance_inconsistency_threshold_hit",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_duplicate_financing_risk_score"),
        signal_expr(&settlement_terms_name("risk_review_threshold")),
        "trade_finance_duplicate_risk_threshold_hit_bit",
        "trade_finance_duplicate_risk_threshold_hit_slack",
        TRADE_FINANCE_SCORE_CAP,
        "trade_finance_duplicate_risk_threshold_hit",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_capped_approved_advance_amount"),
        signal_expr(&settlement_terms_name("manual_review_threshold")),
        "trade_finance_manual_review_approved_advance_hit_bit",
        "trade_finance_manual_review_approved_advance_hit_slack",
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_manual_review_approved_advance_hit",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_reserve_amount"),
        signal_expr(&settlement_terms_name("manual_review_threshold")),
        "trade_finance_manual_review_reserve_hit_bit",
        "trade_finance_manual_review_reserve_hit_slack",
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_manual_review_reserve_hit",
    )?;
    append_boolean_or(
        &mut builder,
        "trade_finance_manual_review_hit_bit",
        signal_expr("trade_finance_manual_review_approved_advance_hit_bit"),
        signal_expr("trade_finance_manual_review_reserve_hit_bit"),
    )?;
    builder.private_signal("trade_finance_financing_policy_ineligible_bit")?;
    builder.bind(
        "trade_finance_financing_policy_ineligible_bit",
        sub_expr(
            const_expr(1),
            signal_expr("trade_finance_eligibility_passed_bit"),
        ),
    )?;
    builder.constrain_boolean("trade_finance_financing_policy_ineligible_bit")?;
    builder.private_signal("trade_finance_not_inconsistency_bit")?;
    builder.bind(
        "trade_finance_not_inconsistency_bit",
        sub_expr(
            const_expr(1),
            signal_expr("trade_finance_inconsistency_threshold_hit_bit"),
        ),
    )?;
    builder.constrain_boolean("trade_finance_not_inconsistency_bit")?;
    builder.private_signal("trade_finance_not_duplicate_risk_review_bit")?;
    builder.bind(
        "trade_finance_not_duplicate_risk_review_bit",
        sub_expr(
            const_expr(1),
            signal_expr("trade_finance_duplicate_risk_threshold_hit_bit"),
        ),
    )?;
    builder.constrain_boolean("trade_finance_not_duplicate_risk_review_bit")?;

    builder.private_signal("trade_finance_action_deny_policy_bit")?;
    builder.bind(
        "trade_finance_action_deny_policy_bit",
        signal_expr("trade_finance_financing_policy_ineligible_bit"),
    )?;
    builder.constrain_boolean("trade_finance_action_deny_policy_bit")?;
    append_boolean_and(
        &mut builder,
        "trade_finance_action_deny_inconsistency_bit",
        signal_expr("trade_finance_eligibility_passed_bit"),
        signal_expr("trade_finance_inconsistency_threshold_hit_bit"),
    )?;
    builder.private_signal("trade_finance_action_can_review_bit")?;
    builder.bind(
        "trade_finance_action_can_review_bit",
        mul_expr(
            signal_expr("trade_finance_eligibility_passed_bit"),
            signal_expr("trade_finance_not_inconsistency_bit"),
        ),
    )?;
    builder.constrain_boolean("trade_finance_action_can_review_bit")?;
    append_boolean_and(
        &mut builder,
        "trade_finance_action_escalate_bit",
        signal_expr("trade_finance_action_can_review_bit"),
        signal_expr("trade_finance_duplicate_risk_threshold_hit_bit"),
    )?;
    builder.private_signal("trade_finance_action_manual_pre_bit")?;
    builder.bind(
        "trade_finance_action_manual_pre_bit",
        mul_expr(
            signal_expr("trade_finance_action_can_review_bit"),
            signal_expr("trade_finance_not_duplicate_risk_review_bit"),
        ),
    )?;
    builder.constrain_boolean("trade_finance_action_manual_pre_bit")?;
    append_boolean_and(
        &mut builder,
        "trade_finance_action_manual_review_bit",
        signal_expr("trade_finance_action_manual_pre_bit"),
        signal_expr("trade_finance_manual_review_hit_bit"),
    )?;
    builder.private_signal("trade_finance_action_non_auto_sum")?;
    builder.bind(
        "trade_finance_action_non_auto_sum",
        add_expr(vec![
            signal_expr("trade_finance_action_deny_policy_bit"),
            signal_expr("trade_finance_action_deny_inconsistency_bit"),
            signal_expr("trade_finance_action_escalate_bit"),
            signal_expr("trade_finance_action_manual_review_bit"),
        ]),
    )?;
    builder.constrain_range("trade_finance_action_non_auto_sum", 3)?;
    builder.private_signal("trade_finance_action_approve_bit")?;
    builder.bind(
        "trade_finance_action_approve_bit",
        sub_expr(
            const_expr(1),
            signal_expr("trade_finance_action_non_auto_sum"),
        ),
    )?;
    builder.constrain_boolean("trade_finance_action_approve_bit")?;

    builder.constrain_equal(
        signal_expr("action_class_code"),
        add_expr(vec![
            mul_expr(
                signal_expr("trade_finance_action_manual_review_bit"),
                const_expr(TRADE_FINANCE_ACTION_APPROVE_WITH_MANUAL_REVIEW),
            ),
            mul_expr(
                signal_expr("trade_finance_action_escalate_bit"),
                const_expr(TRADE_FINANCE_ACTION_ESCALATE_FOR_INVESTIGATION),
            ),
            mul_expr(
                signal_expr("trade_finance_action_deny_policy_bit"),
                const_expr(TRADE_FINANCE_ACTION_DENY_FOR_POLICY_RULE),
            ),
            mul_expr(
                signal_expr("trade_finance_action_deny_inconsistency_bit"),
                const_expr(TRADE_FINANCE_ACTION_DENY_FOR_INCONSISTENCY),
            ),
        ]),
    )?;
    builder.constrain_range("action_class_code", 3)?;
    builder.constrain_equal(
        signal_expr("human_review_required"),
        sub_expr(
            const_expr(1),
            signal_expr("trade_finance_action_approve_bit"),
        ),
    )?;
    builder.constrain_boolean("human_review_required")?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_capped_approved_advance_amount"),
        const_expr(1),
        "trade_finance_approved_advance_nonzero_bit",
        "trade_finance_approved_advance_nonzero_slack",
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_approved_advance_nonzero",
    )?;
    builder.constrain_equal(
        signal_expr("eligible_for_midnight_settlement"),
        mul_expr(
            signal_expr("trade_finance_action_approve_bit"),
            signal_expr("trade_finance_approved_advance_nonzero_bit"),
        ),
    )?;
    builder.constrain_boolean("eligible_for_midnight_settlement")?;

    let settlement_instruction_inner = builder.append_poseidon_hash(
        "trade_finance_settlement_instruction_inner",
        [
            signal_expr("trade_finance_capped_approved_advance_amount"),
            signal_expr("trade_finance_reserve_amount"),
            signal_expr("action_class_code"),
            signal_expr(&settlement_terms_name(
                "supplier_advance_destination_commitment",
            )),
        ],
    )?;
    let settlement_instruction_outer = builder.append_poseidon_hash(
        "trade_finance_settlement_instruction_outer",
        [
            signal_expr(&settlement_instruction_inner),
            signal_expr(&settlement_terms_name(
                "financier_reserve_account_commitment",
            )),
            signal_expr(&settlement_terms_array_name("settlement_blinding", 0)),
            signal_expr(&settlement_terms_array_name("settlement_blinding", 1)),
        ],
    )?;
    let settlement_instruction_binding = builder.append_poseidon_hash(
        "trade_finance_settlement_instruction_binding",
        [
            signal_expr(&settlement_instruction_outer),
            signal_expr("invoice_packet_commitment"),
            signal_expr("eligibility_commitment"),
            signal_expr(&settlement_terms_array_name(
                "public_disclosure_blinding",
                1,
            )),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("settlement_instruction_commitment"),
        signal_expr(&settlement_instruction_binding),
    )?;
    append_square_nonlinear_anchor(&mut builder, "trade_finance_report_delay_margin_shifted")?;
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS {
        append_square_nonlinear_anchor(
            &mut builder,
            &format!("trade_finance_replacement_gap_{index}"),
        )?;
        append_square_nonlinear_anchor(
            &mut builder,
            &format!("trade_finance_invoice_gap_{index}"),
        )?;
        append_square_nonlinear_anchor(
            &mut builder,
            &format!("trade_finance_quantity_gap_{index}"),
        )?;
    }
    for signal in [
        "trade_finance_total_invoice_amount",
        "trade_finance_total_price_baseline",
        "trade_finance_eligibility_mismatch_score",
        "trade_finance_evidence_completeness_score",
        "trade_finance_duplication_score",
    ] {
        append_square_nonlinear_anchor(&mut builder, signal)?;
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        append_square_nonlinear_anchor(
            &mut builder,
            &format!("trade_finance_digest_present_{index}"),
        )?;
    }

    builder.build()
}

pub fn build_trade_finance_settlement_binding_program() -> ZkfResult<Program> {
    let mut builder =
        ProgramBuilder::new("trade_finance_settlement_binding_v1", TRADE_FINANCE_FIELD);
    for name in settlement_input_names() {
        builder.private_input(&name)?;
    }
    for name in [
        "trade_finance_settlement_settlement_instruction_commitment",
        "trade_finance_settlement_dispute_hold_commitment",
        "trade_finance_settlement_repayment_completion_commitment",
        "trade_finance_settlement_fee_amount_commitment",
        "trade_finance_settlement_maturity_schedule_commitment",
        "trade_finance_settlement_finality_flag",
    ] {
        builder.public_output(name)?;
    }
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_settlement_duplicate_financing_risk_score"),
        signal_expr("trade_finance_settlement_dispute_threshold"),
        "trade_finance_settlement_hold_by_duplicate_risk_bit",
        "trade_finance_settlement_hold_by_duplicate_risk_slack",
        TRADE_FINANCE_SCORE_CAP,
        "trade_finance_settlement_hold_by_duplicate_risk",
    )?;
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_settlement_action_class_code"),
        const_expr(1),
        "trade_finance_settlement_non_auto_action_bit",
        "trade_finance_settlement_non_auto_action_slack",
        8,
        "trade_finance_settlement_non_auto_action",
    )?;
    append_boolean_or(
        &mut builder,
        "trade_finance_settlement_hold_required_bit",
        signal_expr("trade_finance_settlement_hold_by_duplicate_risk_bit"),
        signal_expr("trade_finance_settlement_non_auto_action_bit"),
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_settlement_finality_flag"),
        sub_expr(
            const_expr(1),
            signal_expr("trade_finance_settlement_hold_required_bit"),
        ),
    )?;
    let settlement_commitment = builder.append_poseidon_hash(
        "trade_finance_settlement_instruction_commitment_inner",
        [
            signal_expr("trade_finance_settlement_approved_advance_amount"),
            signal_expr("trade_finance_settlement_reserve_amount"),
            signal_expr("trade_finance_settlement_action_class_code"),
            signal_expr("trade_finance_settlement_supplier_advance_destination_commitment"),
        ],
    )?;
    let settlement_commitment_outer = builder.append_poseidon_hash(
        "trade_finance_settlement_instruction_commitment_outer",
        [
            signal_expr(&settlement_commitment),
            signal_expr("trade_finance_settlement_financier_reserve_account_commitment"),
            signal_expr("trade_finance_settlement_blinding_0"),
            signal_expr("trade_finance_settlement_blinding_1"),
        ],
    )?;
    let settlement_commitment_binding = builder.append_poseidon_hash(
        "trade_finance_settlement_instruction_commitment_binding",
        [
            signal_expr(&settlement_commitment_outer),
            signal_expr("trade_finance_settlement_invoice_packet_commitment"),
            signal_expr("trade_finance_settlement_eligibility_commitment"),
            signal_expr("trade_finance_settlement_public_blinding_1"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_settlement_settlement_instruction_commitment"),
        signal_expr(&settlement_commitment_binding),
    )?;
    let dispute_hold_commitment = builder.append_poseidon_hash(
        "trade_finance_settlement_dispute_hold_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_SETTLEMENT),
            signal_expr("trade_finance_settlement_action_class_code"),
            signal_expr("trade_finance_settlement_duplicate_financing_risk_score"),
            signal_expr("trade_finance_settlement_dispute_threshold"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_settlement_dispute_hold_commitment"),
        signal_expr(&dispute_hold_commitment),
    )?;
    let repayment_completion_commitment = builder.append_poseidon_hash(
        "trade_finance_settlement_repayment_completion_commitment_inner",
        [
            signal_expr("trade_finance_settlement_fee_amount"),
            signal_expr("trade_finance_settlement_approved_advance_amount"),
            signal_expr("trade_finance_settlement_financier_participation_commitment"),
            signal_expr("trade_finance_settlement_public_blinding_0"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_settlement_repayment_completion_commitment"),
        signal_expr(&repayment_completion_commitment),
    )?;
    let fee_amount_commitment = builder.append_poseidon_hash(
        "trade_finance_settlement_fee_amount_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_FEE),
            signal_expr("trade_finance_settlement_fee_amount"),
            signal_expr("trade_finance_settlement_blinding_0"),
            signal_expr("trade_finance_settlement_blinding_1"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_settlement_fee_amount_commitment"),
        signal_expr(&fee_amount_commitment),
    )?;
    let maturity_schedule_inner = builder.append_poseidon_hash(
        "trade_finance_settlement_maturity_schedule_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_MATURITY),
            signal_expr("trade_finance_settlement_financing_window_open_timestamp"),
            signal_expr("trade_finance_settlement_invoice_presented_timestamp"),
            signal_expr("trade_finance_settlement_financing_request_timestamp"),
        ],
    )?;
    let maturity_schedule_outer = builder.append_poseidon_hash(
        "trade_finance_settlement_maturity_schedule_commitment_outer",
        [
            signal_expr(&maturity_schedule_inner),
            signal_expr("trade_finance_settlement_financing_window_close_timestamp"),
            signal_expr("trade_finance_settlement_blinding_0"),
            signal_expr("trade_finance_settlement_blinding_1"),
        ],
    )?;
    let maturity_schedule_binding = builder.append_poseidon_hash(
        "trade_finance_settlement_maturity_schedule_commitment_binding",
        [
            signal_expr(&maturity_schedule_outer),
            signal_expr("trade_finance_settlement_invoice_packet_commitment"),
            signal_expr("trade_finance_settlement_eligibility_commitment"),
            signal_expr("trade_finance_settlement_public_blinding_1"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_settlement_maturity_schedule_commitment"),
        signal_expr(&maturity_schedule_binding),
    )?;
    builder.build()
}

pub fn build_trade_finance_disclosure_projection_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new(
        "trade_finance_disclosure_projection_v1",
        TRADE_FINANCE_FIELD,
    );
    for name in disclosure_input_names() {
        builder.private_input(&name)?;
    }
    for name in [
        "trade_finance_disclosure_role_code",
        "trade_finance_disclosure_view_commitment",
        "trade_finance_disclosure_authorization_commitment",
        "trade_finance_disclosure_value_a",
        "trade_finance_disclosure_value_b",
    ] {
        builder.public_output(name)?;
    }
    for role in [
        "trade_finance_disclosure_role_supplier",
        "trade_finance_disclosure_role_financier",
        "trade_finance_disclosure_role_buyer",
        "trade_finance_disclosure_role_auditor",
        "trade_finance_disclosure_role_regulator",
    ] {
        builder.constrain_boolean(role)?;
    }
    builder.private_signal("trade_finance_disclosure_role_sum")?;
    builder.bind(
        "trade_finance_disclosure_role_sum",
        add_expr(vec![
            signal_expr("trade_finance_disclosure_role_supplier"),
            signal_expr("trade_finance_disclosure_role_financier"),
            signal_expr("trade_finance_disclosure_role_buyer"),
            signal_expr("trade_finance_disclosure_role_auditor"),
            signal_expr("trade_finance_disclosure_role_regulator"),
        ]),
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_disclosure_role_sum"),
        const_expr(1),
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_disclosure_role_code"),
        add_expr(vec![
            mul_expr(
                signal_expr("trade_finance_disclosure_role_financier"),
                const_expr(1),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_buyer"),
                const_expr(2),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_auditor"),
                const_expr(3),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_regulator"),
                const_expr(4),
            ),
        ]),
    )?;
    builder.constrain_range("trade_finance_disclosure_role_code", 3)?;
    builder.private_signal("trade_finance_disclosure_value_a_private")?;
    builder.bind(
        "trade_finance_disclosure_value_a_private",
        add_expr(vec![
            mul_expr(
                signal_expr("trade_finance_disclosure_role_supplier"),
                signal_expr("trade_finance_disclosure_settlement_commitment"),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_financier"),
                signal_expr("trade_finance_disclosure_approved_advance_commitment"),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_buyer"),
                signal_expr("trade_finance_disclosure_invoice_packet_commitment"),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_auditor"),
                signal_expr("trade_finance_disclosure_approved_advance_commitment"),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_regulator"),
                signal_expr("trade_finance_disclosure_reserve_commitment"),
            ),
        ]),
    )?;
    builder.private_signal("trade_finance_disclosure_value_b_private")?;
    builder.bind(
        "trade_finance_disclosure_value_b_private",
        add_expr(vec![
            mul_expr(
                signal_expr("trade_finance_disclosure_role_supplier"),
                signal_expr("trade_finance_disclosure_approved_advance_commitment"),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_financier"),
                signal_expr("trade_finance_disclosure_reserve_commitment"),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_buyer"),
                signal_expr("trade_finance_disclosure_eligibility_commitment"),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_auditor"),
                signal_expr("trade_finance_disclosure_consistency_score_commitment"),
            ),
            mul_expr(
                signal_expr("trade_finance_disclosure_role_regulator"),
                signal_expr("trade_finance_disclosure_duplicate_financing_risk_commitment"),
            ),
        ]),
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_disclosure_value_a"),
        signal_expr("trade_finance_disclosure_value_a_private"),
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_disclosure_value_b"),
        signal_expr("trade_finance_disclosure_value_b_private"),
    )?;
    let view_commitment = builder.append_poseidon_hash(
        "trade_finance_disclosure_view_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_DISCLOSURE),
            signal_expr("trade_finance_disclosure_role_code"),
            signal_expr("trade_finance_disclosure_value_a_private"),
            signal_expr("trade_finance_disclosure_value_b_private"),
        ],
    )?;
    let view_commitment_outer = builder.append_poseidon_hash(
        "trade_finance_disclosure_view_commitment_outer",
        [
            signal_expr(&view_commitment),
            signal_expr("trade_finance_disclosure_fee_amount"),
            signal_expr("trade_finance_disclosure_public_blinding_0"),
            signal_expr("trade_finance_disclosure_public_blinding_1"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_disclosure_view_commitment"),
        signal_expr(&view_commitment_outer),
    )?;
    let authorization_commitment = builder.append_poseidon_hash(
        "trade_finance_disclosure_authorization_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_DISCLOSURE_AUTHORIZATION),
            signal_expr("trade_finance_disclosure_role_code"),
            signal_expr("trade_finance_disclosure_credential_commitment"),
            signal_expr("trade_finance_disclosure_request_id_hash"),
        ],
    )?;
    let authorization_commitment_outer = builder.append_poseidon_hash(
        "trade_finance_disclosure_authorization_commitment_outer",
        [
            signal_expr(&authorization_commitment),
            signal_expr("trade_finance_disclosure_caller_commitment"),
            signal_expr(&view_commitment_outer),
            signal_expr("trade_finance_disclosure_public_blinding_0"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_disclosure_authorization_commitment"),
        signal_expr(&authorization_commitment_outer),
    )?;
    append_square_nonlinear_anchor(&mut builder, "trade_finance_disclosure_role_sum")?;
    builder.build()
}

pub fn build_trade_finance_duplicate_registry_handoff_program() -> ZkfResult<Program> {
    let mut builder = ProgramBuilder::new(
        "trade_finance_duplicate_registry_handoff_v1",
        TRADE_FINANCE_FIELD,
    );
    for name in shard_input_names() {
        builder.private_input(&name)?;
    }
    for name in [
        "trade_finance_shard_batch_root_commitment",
        "trade_finance_shard_assignment_commitment",
    ] {
        builder.public_output(name)?;
    }
    append_geq_comparator_bit(
        &mut builder,
        signal_expr("trade_finance_shard_shard_count"),
        const_expr(2),
        "trade_finance_shard_count_valid_bit",
        "trade_finance_shard_count_valid_slack",
        TRADE_FINANCE_SHARD_COUNT_MAX,
        "trade_finance_shard_count_valid",
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_shard_count_valid_bit"),
        const_expr(1),
    )?;
    let mut assignment_names = Vec::new();
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        builder.append_exact_division_constraints(
            signal_expr(&format!(
                "trade_finance_shard_receivable_commitment_{index}"
            )),
            signal_expr("trade_finance_shard_shard_count"),
            &format!("trade_finance_shard_assignment_quotient_{index}"),
            &format!("trade_finance_shard_assignment_{index}"),
            &format!("trade_finance_shard_assignment_slack_{index}"),
            &BigInt::from(TRADE_FINANCE_SHARD_COUNT_MAX),
            &format!("trade_finance_shard_assignment_{index}"),
        )?;
        assignment_names.push(format!("trade_finance_shard_assignment_{index}"));
    }
    let batch_commitment = builder.append_poseidon_hash(
        "trade_finance_shard_batch_root_commitment_inner",
        [
            const_expr(TRADE_FINANCE_DOMAIN_SHARD_BATCH),
            signal_expr("trade_finance_shard_receivable_commitment_0"),
            signal_expr("trade_finance_shard_receivable_commitment_1"),
            signal_expr("trade_finance_shard_receivable_commitment_2"),
        ],
    )?;
    let batch_commitment_outer = builder.append_poseidon_hash(
        "trade_finance_shard_batch_root_commitment_outer",
        [
            signal_expr(&batch_commitment),
            signal_expr("trade_finance_shard_receivable_commitment_3"),
            signal_expr("trade_finance_shard_blinding_0"),
            signal_expr("trade_finance_shard_blinding_1"),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_shard_batch_root_commitment"),
        signal_expr(&batch_commitment_outer),
    )?;
    let assignment_commitment = builder.append_poseidon_hash(
        "trade_finance_shard_assignment_commitment_inner",
        [
            signal_expr(&assignment_names[0]),
            signal_expr(&assignment_names[1]),
            signal_expr(&assignment_names[2]),
            signal_expr(&assignment_names[3]),
        ],
    )?;
    builder.constrain_equal(
        signal_expr("trade_finance_shard_assignment_commitment"),
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
    write_value(
        values,
        format!("{signal}_square_anchor"),
        value.clone() * value,
    );
}

fn u64_from_map(values: &BTreeMap<String, FieldElement>, name: &str) -> u64 {
    bigint_from_map(values, name).try_into().unwrap_or_default()
}

fn compute_core_support_values(
    request: &TradeFinancePrivateInputsV1,
) -> ZkfResult<(
    BTreeMap<String, FieldElement>,
    TradeFinanceCoreComputationInternal,
)> {
    let mut values = flatten_private_inputs(request)?;
    let input_names = trade_finance_private_input_names_v1();
    let invoice_packet_commitment =
        write_private_input_anchor_chain(&mut values, &input_names, "trade_finance_packet_anchor")?;

    let coverage_count = request
        .financing_policy
        .eligibility_predicate_flags
        .iter()
        .zip(
            request
                .receivable_context
                .observed_eligibility_predicate_flags
                .iter(),
        )
        .map(|(policy_flag, receivable_flag)| policy_flag * receivable_flag)
        .sum::<u64>();
    let exclusion_count = request
        .financing_policy
        .lender_exclusion_predicate_flags
        .iter()
        .zip(
            request
                .receivable_context
                .observed_eligibility_predicate_flags
                .iter(),
        )
        .map(|(policy_flag, receivable_flag)| policy_flag * receivable_flag)
        .sum::<u64>();
    let buyer_acceptance_term_count = request
        .receivable_context
        .buyer_acceptance_term_flags
        .iter()
        .sum::<u64>();
    let incident_after_effective = write_geq_support(
        &mut values,
        "trade_finance_within_term_window_incident_after_effective_bit",
        "trade_finance_within_term_window_incident_after_effective_slack",
        &BigInt::from(request.receivable_context.invoice_presented_timestamp),
        &BigInt::from(request.financing_policy.financing_window_open_timestamp),
        TRADE_FINANCE_TIMESTAMP_BOUND,
        "trade_finance_within_term_window_incident_after_effective",
    )?;
    let expiration_after_incident = write_geq_support(
        &mut values,
        "trade_finance_within_term_window_expiration_after_incident_bit",
        "trade_finance_within_term_window_expiration_after_incident_slack",
        &BigInt::from(request.financing_policy.financing_window_close_timestamp),
        &BigInt::from(request.receivable_context.invoice_presented_timestamp),
        TRADE_FINANCE_TIMESTAMP_BOUND,
        "trade_finance_within_term_window_expiration_after_incident",
    )?;
    let eligibility_predicate_supported = write_geq_support(
        &mut values,
        "trade_finance_eligibility_predicate_supported_bit",
        "trade_finance_eligibility_predicate_supported_slack",
        &BigInt::from(coverage_count),
        &BigInt::from(1u8),
        PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES as u64 + 1,
        "trade_finance_eligibility_predicate_supported",
    )?;
    let lender_exclusion_triggered = write_geq_support(
        &mut values,
        "trade_finance_lender_exclusion_triggered_bit",
        "trade_finance_lender_exclusion_triggered_slack",
        &BigInt::from(exclusion_count),
        &BigInt::from(1u8),
        PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES as u64 + 1,
        "trade_finance_lender_exclusion_triggered",
    )?;
    let buyer_acceptance_term_present = write_geq_support(
        &mut values,
        "trade_finance_receivable_category_present_bit",
        "trade_finance_receivable_category_present_slack",
        &BigInt::from(buyer_acceptance_term_count),
        &BigInt::from(1u8),
        PRIVATE_TRADE_FINANCE_MAX_POLICY_PREDICATES as u64 + 1,
        "trade_finance_receivable_category_present",
    )?;
    let within_term_window = incident_after_effective && expiration_after_incident;
    let eligibility_passed = within_term_window
        && eligibility_predicate_supported
        && !lender_exclusion_triggered
        && buyer_acceptance_term_present;
    write_value(
        &mut values,
        "trade_finance_matched_eligibility_predicate_count",
        coverage_count,
    );
    write_value(
        &mut values,
        "trade_finance_lender_exclusion_match_count",
        exclusion_count,
    );
    write_value(
        &mut values,
        "trade_finance_buyer_acceptance_term_count",
        buyer_acceptance_term_count,
    );
    write_bool_value(
        &mut values,
        "trade_finance_within_term_window_bit",
        within_term_window,
    );
    write_bool_value(
        &mut values,
        "trade_finance_not_lender_exclusion_triggered_bit",
        !lender_exclusion_triggered,
    );
    write_bool_value(
        &mut values,
        "trade_finance_eligibility_passed_pre_category_bit",
        within_term_window && eligibility_predicate_supported,
    );
    write_bool_value(
        &mut values,
        "trade_finance_eligibility_passed_pre_exclusion_bit",
        within_term_window && eligibility_predicate_supported && !lender_exclusion_triggered,
    );
    write_bool_value(
        &mut values,
        "trade_finance_eligibility_passed_bit",
        eligibility_passed,
    );
    let eligibility_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_coverage_commitment",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_COVERAGE),
            &BigInt::from(eligibility_passed as u8),
            &BigInt::from(within_term_window as u8),
            &BigInt::from(exclusion_count),
        ],
    )?;

    let reported_after_incident = write_geq_support(
        &mut values,
        "trade_finance_reported_after_incident_bit",
        "trade_finance_reported_after_incident_slack",
        &BigInt::from(request.receivable_context.financing_request_timestamp),
        &BigInt::from(request.receivable_context.invoice_presented_timestamp),
        TRADE_FINANCE_TIMESTAMP_BOUND,
        "trade_finance_reported_after_incident",
    )?;
    let report_delay = request
        .receivable_context
        .financing_request_timestamp
        .saturating_sub(request.receivable_context.invoice_presented_timestamp);
    write_value(&mut values, "trade_finance_report_delay", report_delay);
    write_value(
        &mut values,
        "trade_finance_report_delay_margin_shifted",
        report_delay + TRADE_FINANCE_SIGNED_MARGIN_OFFSET
            - request
                .duplicate_risk_inputs
                .chronology_consistency_threshold,
    );

    let digest_manifest = write_private_input_anchor_chain(
        &mut values,
        &[
            evidence_name("photo_analysis_result_digest"),
            evidence_name("document_extraction_result_digest"),
            evidence_name("buyer_approval_reference_digest"),
            evidence_array_name("logistics_event_summary", 0),
        ],
        "trade_finance_evidence_anchor",
    )?;

    let mut total_estimate_amount = 0u64;
    let mut total_invoice_amount = 0u64;
    let mut total_reference_amount = 0u64;
    let mut total_valuation_gap = 0u64;
    let mut total_quantity_gap = 0u64;
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS {
        let estimate = &request.supporting_documents.supporting_schedule_line_items[index];
        let invoice = &request.supporting_documents.invoice_line_items[index];
        let estimate_total = estimate.quantity.saturating_mul(estimate.unit_amount);
        let replacement_min = estimate_total.min(estimate.reference_amount);
        let replacement_max = estimate_total.max(estimate.reference_amount);
        let invoice_min = estimate_total.min(invoice.invoice_amount);
        let invoice_max = estimate_total.max(invoice.invoice_amount);
        let quantity_min = estimate.quantity.min(invoice.quantity);
        let quantity_max = estimate.quantity.max(invoice.quantity);
        let replacement_gap = replacement_max - replacement_min;
        let invoice_gap = invoice_max - invoice_min;
        let quantity_gap = quantity_max - quantity_min;
        total_estimate_amount = total_estimate_amount.saturating_add(estimate_total);
        total_invoice_amount = total_invoice_amount.saturating_add(invoice.invoice_amount);
        total_reference_amount = total_reference_amount.saturating_add(estimate.reference_amount);
        total_valuation_gap = total_valuation_gap
            .saturating_add(replacement_gap)
            .saturating_add(invoice_gap);
        total_quantity_gap = total_quantity_gap.saturating_add(quantity_gap);
        write_value(
            &mut values,
            format!("trade_finance_estimate_total_{index}"),
            estimate_total,
        );
        let prefix = format!("trade_finance_replacement_min_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate_total),
            &BigInt::from(estimate.reference_amount),
            TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("trade_finance_replacement_max_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate_total),
            &BigInt::from(estimate.reference_amount),
            TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("trade_finance_invoice_amount_min_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate_total),
            &BigInt::from(invoice.invoice_amount),
            TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("trade_finance_invoice_amount_max_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate_total),
            &BigInt::from(invoice.invoice_amount),
            TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("trade_finance_invoice_quantity_min_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate.quantity),
            &BigInt::from(invoice.quantity),
            TRADE_FINANCE_VALUE_BOUND,
            &prefix,
        )?;
        let prefix = format!("trade_finance_invoice_quantity_max_{index}");
        write_geq_support(
            &mut values,
            &format!("{prefix}_geq_bit"),
            &format!("{prefix}_geq_slack"),
            &BigInt::from(estimate.quantity),
            &BigInt::from(invoice.quantity),
            TRADE_FINANCE_VALUE_BOUND,
            &prefix,
        )?;
        write_value(
            &mut values,
            format!("trade_finance_replacement_gap_{index}"),
            replacement_gap,
        );
        write_value(
            &mut values,
            format!("trade_finance_invoice_gap_{index}"),
            invoice_gap,
        );
        write_value(
            &mut values,
            format!("trade_finance_quantity_gap_{index}"),
            quantity_gap,
        );
        write_value(
            &mut values,
            format!("trade_finance_replacement_min_{index}"),
            replacement_min,
        );
        write_value(
            &mut values,
            format!("trade_finance_replacement_max_{index}"),
            replacement_max,
        );
        write_value(
            &mut values,
            format!("trade_finance_invoice_amount_min_{index}"),
            invoice_min,
        );
        write_value(
            &mut values,
            format!("trade_finance_invoice_amount_max_{index}"),
            invoice_max,
        );
        write_value(
            &mut values,
            format!("trade_finance_invoice_quantity_min_{index}"),
            quantity_min,
        );
        write_value(
            &mut values,
            format!("trade_finance_invoice_quantity_max_{index}"),
            quantity_max,
        );
    }
    write_value(
        &mut values,
        "trade_finance_total_estimate_amount",
        total_estimate_amount,
    );
    write_value(
        &mut values,
        "trade_finance_total_invoice_amount",
        total_invoice_amount,
    );
    write_value(
        &mut values,
        "trade_finance_total_reference_amount",
        total_reference_amount,
    );
    write_value(
        &mut values,
        "trade_finance_total_valuation_gap",
        total_valuation_gap,
    );
    write_value(
        &mut values,
        "trade_finance_total_quantity_gap",
        total_quantity_gap,
    );

    let total_price_baseline = request
        .duplicate_risk_inputs
        .price_deviation_baselines
        .iter()
        .copied()
        .sum::<u64>();
    let total_vendor_baseline = request
        .duplicate_risk_inputs
        .vendor_anomaly_baselines
        .iter()
        .copied()
        .sum::<u64>();
    let total_vendor_digest = request
        .supporting_documents
        .vendor_attestation_digests
        .iter()
        .copied()
        .sum::<u64>();
    write_value(
        &mut values,
        "trade_finance_total_price_baseline",
        total_price_baseline,
    );
    write_value(
        &mut values,
        "trade_finance_total_vendor_baseline",
        total_vendor_baseline,
    );
    write_value(
        &mut values,
        "trade_finance_total_vendor_digest",
        total_vendor_digest,
    );
    let geographic_reasonable = write_geq_support(
        &mut values,
        "trade_finance_geographic_reasonable_bit",
        "trade_finance_geographic_reasonable_slack",
        &BigInt::from(
            request
                .duplicate_risk_inputs
                .geographic_reasonableness_threshold,
        ),
        &BigInt::from(request.receivable_context.jurisdiction_corridor_bucket),
        TRADE_FINANCE_UINT_BOUND,
        "trade_finance_geographic_reasonable",
    )?;

    let mut duplicate_match_count = 0u64;
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        let lhs = request.receivable_context.prior_financing_linkage_hashes[index];
        let rhs = request
            .duplicate_risk_inputs
            .duplicate_receivable_candidate_hashes[index];
        let equal = request.receivable_context.prior_financing_linkage_hashes[index]
            == request
                .duplicate_risk_inputs
                .duplicate_receivable_candidate_hashes[index];
        if equal {
            duplicate_match_count += 1;
        }
        write_bool_value(
            &mut values,
            format!("trade_finance_duplicate_match_{index}_eq"),
            equal,
        );
        write_value(
            &mut values,
            format!("trade_finance_duplicate_match_{index}_diff"),
            BigInt::from(lhs) - BigInt::from(rhs),
        );
        let inv = if equal {
            FieldElement::ZERO
        } else {
            BigIntFieldValue::new(TRADE_FINANCE_FIELD, BigInt::from(lhs) - BigInt::from(rhs))
                .inv()
                .map(|value| value.to_field_element())
                .unwrap_or(FieldElement::ZERO)
        };
        values.insert(format!("trade_finance_duplicate_match_{index}_inv"), inv);
    }
    write_value(
        &mut values,
        "trade_finance_duplicate_match_count",
        duplicate_match_count,
    );

    let digest_presence_values = [
        BigInt::from(request.supporting_documents.photo_analysis_result_digest),
        BigInt::from(
            request
                .supporting_documents
                .document_extraction_result_digest,
        ),
        BigInt::from(request.supporting_documents.buyer_approval_reference_digest),
        evidence_manifest_digest_bigint(&request.supporting_documents.evidence_manifest_digest)?,
    ];
    let expected_digest_count = digest_presence_values.len() as u64;
    let mut complete_digest_count = 0u64;
    for (index, source) in digest_presence_values.iter().enumerate() {
        let prefix = format!("trade_finance_digest_present_{index}_zero");
        let is_zero = source == &zero();
        write_equality_with_inverse_support(&mut values, source, &zero(), &prefix);
        let present = !is_zero;
        write_bool_value(
            &mut values,
            format!("trade_finance_digest_present_{index}"),
            present,
        );
        if present {
            complete_digest_count += 1;
        }
    }
    write_value(
        &mut values,
        "trade_finance_complete_digest_count",
        complete_digest_count,
    );

    let chronology_ratio = report_delay
        / request
            .duplicate_risk_inputs
            .chronology_consistency_threshold;
    let _chronology_remainder = report_delay
        % request
            .duplicate_risk_inputs
            .chronology_consistency_threshold;
    write_exact_division_support(
        &mut values,
        report_delay,
        request
            .duplicate_risk_inputs
            .chronology_consistency_threshold,
        "trade_finance_chronology_ratio",
        "trade_finance_chronology_ratio_remainder",
        "trade_finance_chronology_ratio_slack",
        "trade_finance_chronology_ratio",
    )?;
    let chronology_score = (chronology_ratio.saturating_mul(1_000)
        + u64::from(!reported_after_incident) * 2_000)
        .min(TRADE_FINANCE_COMPONENT_SCORE_CAP);
    write_value(
        &mut values,
        "trade_finance_chronology_score_raw",
        chronology_ratio * 1_000,
    );
    write_geq_support(
        &mut values,
        "trade_finance_chronology_score_geq_bit",
        "trade_finance_chronology_score_geq_slack",
        &BigInt::from(chronology_ratio.saturating_mul(1_000)),
        &BigInt::from(TRADE_FINANCE_COMPONENT_SCORE_CAP),
        TRADE_FINANCE_RATIO_BOUND,
        "trade_finance_chronology_score",
    )?;
    write_value(
        &mut values,
        "trade_finance_chronology_score",
        chronology_score,
    );

    write_exact_division_support(
        &mut values,
        total_valuation_gap,
        request.duplicate_risk_inputs.valuation_tolerance_threshold,
        "trade_finance_valuation_ratio",
        "trade_finance_valuation_ratio_remainder",
        "trade_finance_valuation_ratio_slack",
        "trade_finance_valuation_ratio",
    )?;
    let valuation_ratio =
        total_valuation_gap / request.duplicate_risk_inputs.valuation_tolerance_threshold;
    let valuation_score = valuation_ratio
        .saturating_mul(1_000)
        .min(TRADE_FINANCE_COMPONENT_SCORE_CAP);
    write_value(
        &mut values,
        "trade_finance_valuation_score_raw",
        valuation_ratio * 1_000,
    );
    write_geq_support(
        &mut values,
        "trade_finance_valuation_score_geq_bit",
        "trade_finance_valuation_score_geq_slack",
        &BigInt::from(valuation_ratio.saturating_mul(1_000)),
        &BigInt::from(TRADE_FINANCE_COMPONENT_SCORE_CAP),
        TRADE_FINANCE_RATIO_BOUND,
        "trade_finance_valuation_score",
    )?;
    write_value(
        &mut values,
        "trade_finance_valuation_score",
        valuation_score,
    );

    write_exact_division_support(
        &mut values,
        total_quantity_gap,
        request.duplicate_risk_inputs.quantity_tolerance_threshold,
        "trade_finance_quantity_ratio",
        "trade_finance_quantity_ratio_remainder",
        "trade_finance_quantity_ratio_slack",
        "trade_finance_quantity_ratio",
    )?;
    let quantity_ratio =
        total_quantity_gap / request.duplicate_risk_inputs.quantity_tolerance_threshold;
    let quantity_score = quantity_ratio
        .saturating_mul(1_000)
        .min(TRADE_FINANCE_COMPONENT_SCORE_CAP);
    write_value(
        &mut values,
        "trade_finance_quantity_score_raw",
        quantity_ratio * 1_000,
    );
    write_geq_support(
        &mut values,
        "trade_finance_quantity_score_geq_bit",
        "trade_finance_quantity_score_geq_slack",
        &BigInt::from(quantity_ratio.saturating_mul(1_000)),
        &BigInt::from(TRADE_FINANCE_COMPONENT_SCORE_CAP),
        TRADE_FINANCE_RATIO_BOUND,
        "trade_finance_quantity_score",
    )?;
    write_value(&mut values, "trade_finance_quantity_score", quantity_score);

    let vendor_gap = total_vendor_digest.abs_diff(total_vendor_baseline);
    write_geq_support(
        &mut values,
        "trade_finance_vendor_gap_min_geq_bit",
        "trade_finance_vendor_gap_min_geq_slack",
        &BigInt::from(total_vendor_digest),
        &BigInt::from(total_vendor_baseline),
        TRADE_FINANCE_HASH_BOUND,
        "trade_finance_vendor_gap_min",
    )?;
    write_geq_support(
        &mut values,
        "trade_finance_vendor_gap_max_geq_bit",
        "trade_finance_vendor_gap_max_geq_slack",
        &BigInt::from(total_vendor_digest),
        &BigInt::from(total_vendor_baseline),
        TRADE_FINANCE_HASH_BOUND,
        "trade_finance_vendor_gap_max",
    )?;
    write_value(
        &mut values,
        "trade_finance_vendor_gap_min",
        total_vendor_digest.min(total_vendor_baseline),
    );
    write_value(
        &mut values,
        "trade_finance_vendor_gap_max",
        total_vendor_digest.max(total_vendor_baseline),
    );
    write_value(&mut values, "trade_finance_vendor_gap", vendor_gap);
    write_value(
        &mut values,
        "trade_finance_total_vendor_baseline_plus_one",
        total_vendor_baseline + 1,
    );
    write_exact_division_support(
        &mut values,
        vendor_gap,
        total_vendor_baseline + 1,
        "trade_finance_vendor_ratio",
        "trade_finance_vendor_ratio_remainder",
        "trade_finance_vendor_ratio_slack",
        "trade_finance_vendor_ratio",
    )?;
    let vendor_ratio = vendor_gap / (total_vendor_baseline + 1);
    let vendor_score = vendor_ratio
        .saturating_mul(750)
        .min(TRADE_FINANCE_COMPONENT_SCORE_CAP);
    write_value(
        &mut values,
        "trade_finance_vendor_score_raw",
        vendor_ratio * 750,
    );
    write_geq_support(
        &mut values,
        "trade_finance_vendor_score_geq_bit",
        "trade_finance_vendor_score_geq_slack",
        &BigInt::from(vendor_ratio.saturating_mul(750)),
        &BigInt::from(TRADE_FINANCE_COMPONENT_SCORE_CAP),
        TRADE_FINANCE_RATIO_BOUND,
        "trade_finance_vendor_score",
    )?;
    write_value(&mut values, "trade_finance_vendor_score", vendor_score);

    let eligibility_mismatch_score = (u64::from(!eligibility_passed) * 5_000)
        .saturating_add(u64::from(lender_exclusion_triggered) * 2_000);
    write_value(
        &mut values,
        "trade_finance_eligibility_mismatch_score",
        eligibility_mismatch_score,
    );
    write_value(
        &mut values,
        "trade_finance_expected_digest_count",
        expected_digest_count,
    );
    let missing_digest_count = expected_digest_count - complete_digest_count;
    write_value(
        &mut values,
        "trade_finance_missing_digest_count",
        missing_digest_count,
    );
    let evidence_completeness_score = missing_digest_count * 1_000;
    write_value(
        &mut values,
        "trade_finance_evidence_completeness_score",
        evidence_completeness_score,
    );

    let structured_inconsistency_score = valuation_score
        .saturating_add(quantity_score)
        .saturating_add(u64::from(!geographic_reasonable) * 800)
        .saturating_add(u64::from(!reported_after_incident) * 2_000)
        .saturating_add(evidence_completeness_score)
        .min(TRADE_FINANCE_SCORE_CAP);
    write_value(
        &mut values,
        "trade_finance_structured_inconsistency_score_raw",
        valuation_score
            .saturating_add(quantity_score)
            .saturating_add(u64::from(!geographic_reasonable) * 800)
            .saturating_add(u64::from(!reported_after_incident) * 2_000)
            .saturating_add(evidence_completeness_score),
    );
    write_geq_support(
        &mut values,
        "trade_finance_structured_inconsistency_score_geq_bit",
        "trade_finance_structured_inconsistency_score_geq_slack",
        &BigInt::from(
            valuation_score
                .saturating_add(quantity_score)
                .saturating_add(u64::from(!geographic_reasonable) * 800)
                .saturating_add(u64::from(!reported_after_incident) * 2_000)
                .saturating_add(evidence_completeness_score),
        ),
        &BigInt::from(TRADE_FINANCE_SCORE_CAP),
        TRADE_FINANCE_SCORE_CAP * 2,
        "trade_finance_structured_inconsistency_score",
    )?;
    write_value(
        &mut values,
        "trade_finance_structured_inconsistency_score",
        structured_inconsistency_score,
    );
    let consistency_score = TRADE_FINANCE_SCORE_CAP - structured_inconsistency_score;
    write_value(
        &mut values,
        "trade_finance_consistency_score",
        consistency_score,
    );

    let duplication_score = duplicate_match_count.saturating_mul(3_000);
    write_value(
        &mut values,
        "trade_finance_duplication_score",
        duplication_score,
    );
    let duplicate_financing_risk_score = duplication_score
        .saturating_add(vendor_score)
        .saturating_add(chronology_score)
        .saturating_add(eligibility_mismatch_score)
        .min(TRADE_FINANCE_SCORE_CAP);
    write_value(
        &mut values,
        "trade_finance_duplicate_financing_risk_score_raw",
        duplication_score
            .saturating_add(vendor_score)
            .saturating_add(chronology_score)
            .saturating_add(eligibility_mismatch_score),
    );
    write_geq_support(
        &mut values,
        "trade_finance_duplicate_financing_risk_score_geq_bit",
        "trade_finance_duplicate_financing_risk_score_geq_slack",
        &BigInt::from(
            duplication_score
                .saturating_add(vendor_score)
                .saturating_add(chronology_score)
                .saturating_add(eligibility_mismatch_score),
        ),
        &BigInt::from(TRADE_FINANCE_SCORE_CAP),
        TRADE_FINANCE_SCORE_CAP * 2,
        "trade_finance_duplicate_financing_risk_score",
    )?;
    write_value(
        &mut values,
        "trade_finance_duplicate_financing_risk_score",
        duplicate_financing_risk_score,
    );

    let consistency_score_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_consistency_commitment",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_CONSISTENCY),
            &BigInt::from(consistency_score),
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[0]),
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[1]),
        ],
    )?;
    let duplicate_financing_risk_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_duplicate_financing_risk_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_DUPLICATE_RISK),
            &BigInt::from(duplicate_financing_risk_score),
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[0]),
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[1]),
        ],
    )?;

    let financing_base_amount_before_retention = total_estimate_amount.min(total_reference_amount);
    write_geq_support(
        &mut values,
        "trade_finance_financing_base_amount_before_retention_geq_bit",
        "trade_finance_financing_base_amount_before_retention_geq_slack",
        &BigInt::from(total_estimate_amount),
        &BigInt::from(total_reference_amount),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_financing_base_amount_before_retention",
    )?;
    write_value(
        &mut values,
        "trade_finance_financing_base_amount_before_retention",
        financing_base_amount_before_retention,
    );
    let supplier_retention_applies = write_geq_support(
        &mut values,
        "trade_finance_supplier_retention_applies_bit",
        "trade_finance_supplier_retention_applies_slack",
        &BigInt::from(financing_base_amount_before_retention),
        &BigInt::from(request.financing_policy.supplier_retention_schedule[0]),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_supplier_retention_applies",
    )?;
    let supplier_retention_adjusted_amount = if supplier_retention_applies {
        financing_base_amount_before_retention
            - request.financing_policy.supplier_retention_schedule[0]
    } else {
        0
    };
    write_value(
        &mut values,
        "trade_finance_supplier_retention_adjusted_amount",
        supplier_retention_adjusted_amount,
    );
    let discount_raw = supplier_retention_adjusted_amount
        .saturating_mul(request.financing_policy.discount_rate_rules[0]);
    write_value(&mut values, "trade_finance_discount_raw", discount_raw);
    write_exact_division_support(
        &mut values,
        discount_raw,
        TRADE_FINANCE_FIXED_POINT_SCALE,
        "trade_finance_discount_amount",
        "trade_finance_discount_remainder",
        "trade_finance_discount_slack",
        "trade_finance_discount",
    )?;
    let discount_amount = discount_raw / TRADE_FINANCE_FIXED_POINT_SCALE;
    let discount_adjusted_amount =
        supplier_retention_adjusted_amount.saturating_sub(discount_amount);
    write_value(
        &mut values,
        "trade_finance_discount_adjusted_amount",
        discount_adjusted_amount,
    );
    write_geq_support(
        &mut values,
        "trade_finance_capped_approved_advance_amount_geq_bit",
        "trade_finance_capped_approved_advance_amount_geq_slack",
        &BigInt::from(discount_adjusted_amount),
        &BigInt::from(request.financing_policy.advance_cap_schedule[0]),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_capped_approved_advance_amount",
    )?;
    let approved_advance_amount =
        discount_adjusted_amount.min(request.financing_policy.advance_cap_schedule[0]);
    write_value(
        &mut values,
        "trade_finance_capped_approved_advance_amount",
        approved_advance_amount,
    );
    let reserve_margin_raw = approved_advance_amount
        .saturating_mul(request.financing_policy.reserve_holdback_parameters[0]);
    write_value(
        &mut values,
        "trade_finance_reserve_margin_raw",
        reserve_margin_raw,
    );
    write_exact_division_support(
        &mut values,
        reserve_margin_raw,
        TRADE_FINANCE_FIXED_POINT_SCALE,
        "trade_finance_reserve_margin_amount",
        "trade_finance_reserve_margin_remainder",
        "trade_finance_reserve_margin_slack",
        "trade_finance_reserve_margin",
    )?;
    let reserve_margin_amount = reserve_margin_raw / TRADE_FINANCE_FIXED_POINT_SCALE;
    let reserve_amount_pre_floor = approved_advance_amount.saturating_add(reserve_margin_amount);
    write_value(
        &mut values,
        "trade_finance_reserve_amount_pre_floor",
        reserve_amount_pre_floor,
    );
    write_geq_support(
        &mut values,
        "trade_finance_reserve_amount_geq_bit",
        "trade_finance_reserve_amount_geq_slack",
        &BigInt::from(reserve_amount_pre_floor),
        &BigInt::from(request.financing_policy.reserve_holdback_parameters[1]),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_reserve_amount",
    )?;
    let reserve_amount =
        reserve_amount_pre_floor.max(request.financing_policy.reserve_holdback_parameters[1]);
    write_value(&mut values, "trade_finance_reserve_amount", reserve_amount);

    let financier_participation_attached = write_geq_support(
        &mut values,
        "trade_finance_financier_participation_attached_bit",
        "trade_finance_financier_participation_attached_slack",
        &BigInt::from(approved_advance_amount),
        &BigInt::from(request.financing_policy.financier_participation_parameters[1]),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_financier_participation_attached",
    )?;
    let financier_participation_attachment_excess = if financier_participation_attached {
        approved_advance_amount - request.financing_policy.financier_participation_parameters[1]
    } else {
        0
    };
    write_value(
        &mut values,
        "trade_finance_financier_participation_attachment_excess",
        financier_participation_attachment_excess,
    );
    write_geq_support(
        &mut values,
        "trade_finance_financier_participation_share_base_geq_bit",
        "trade_finance_financier_participation_share_base_geq_slack",
        &BigInt::from(financier_participation_attachment_excess),
        &BigInt::from(request.financing_policy.financier_participation_parameters[2]),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_financier_participation_share_base",
    )?;
    let financier_participation_share_base = financier_participation_attachment_excess
        .min(request.financing_policy.financier_participation_parameters[2]);
    write_value(
        &mut values,
        "trade_finance_financier_participation_share_base",
        financier_participation_share_base,
    );
    let financier_participation_share_raw = financier_participation_share_base
        .saturating_mul(request.financing_policy.financier_participation_parameters[0]);
    write_value(
        &mut values,
        "trade_finance_financier_participation_share_raw",
        financier_participation_share_raw,
    );
    write_exact_division_support(
        &mut values,
        financier_participation_share_raw,
        TRADE_FINANCE_FIXED_POINT_SCALE,
        "trade_finance_fee_amount",
        "trade_finance_financier_participation_share_remainder",
        "trade_finance_financier_participation_share_slack",
        "trade_finance_financier_participation_share",
    )?;
    let fee_amount = financier_participation_share_raw / TRADE_FINANCE_FIXED_POINT_SCALE;

    let approved_advance_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_approved_advance_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_APPROVED_ADVANCE),
            &BigInt::from(approved_advance_amount),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[1]),
        ],
    )?;
    let reserve_amount_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_reserve_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_RESERVE),
            &BigInt::from(reserve_amount),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[1]),
        ],
    )?;

    let inconsistency_hit = write_geq_support(
        &mut values,
        "trade_finance_inconsistency_threshold_hit_bit",
        "trade_finance_inconsistency_threshold_hit_slack",
        &BigInt::from(structured_inconsistency_score),
        &BigInt::from(request.settlement_terms.dispute_escalation_threshold),
        TRADE_FINANCE_SCORE_CAP,
        "trade_finance_inconsistency_threshold_hit",
    )?;
    let fraud_hit = write_geq_support(
        &mut values,
        "trade_finance_duplicate_risk_threshold_hit_bit",
        "trade_finance_duplicate_risk_threshold_hit_slack",
        &BigInt::from(duplicate_financing_risk_score),
        &BigInt::from(request.settlement_terms.risk_review_threshold),
        TRADE_FINANCE_SCORE_CAP,
        "trade_finance_duplicate_risk_threshold_hit",
    )?;
    let manual_payout_hit = write_geq_support(
        &mut values,
        "trade_finance_manual_review_approved_advance_hit_bit",
        "trade_finance_manual_review_approved_advance_hit_slack",
        &BigInt::from(approved_advance_amount),
        &BigInt::from(request.settlement_terms.manual_review_threshold),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_manual_review_approved_advance_hit",
    )?;
    let manual_reserve_hit = write_geq_support(
        &mut values,
        "trade_finance_manual_review_reserve_hit_bit",
        "trade_finance_manual_review_reserve_hit_slack",
        &BigInt::from(reserve_amount),
        &BigInt::from(request.settlement_terms.manual_review_threshold),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_manual_review_reserve_hit",
    )?;
    let manual_hit = manual_payout_hit || manual_reserve_hit;
    write_bool_value(
        &mut values,
        "trade_finance_manual_review_hit_bit",
        manual_hit,
    );
    write_bool_value(
        &mut values,
        "trade_finance_financing_policy_ineligible_bit",
        !eligibility_passed,
    );
    write_bool_value(
        &mut values,
        "trade_finance_not_inconsistency_bit",
        !inconsistency_hit,
    );
    write_bool_value(
        &mut values,
        "trade_finance_not_duplicate_risk_review_bit",
        !fraud_hit,
    );
    let deny_policy_bit = !eligibility_passed;
    let deny_inconsistency_bit = eligibility_passed && inconsistency_hit;
    let escalate_bit = eligibility_passed && !inconsistency_hit && fraud_hit;
    let manual_review_bit = eligibility_passed && !inconsistency_hit && !fraud_hit && manual_hit;
    let approve_bit =
        !deny_policy_bit && !deny_inconsistency_bit && !escalate_bit && !manual_review_bit;
    let action_class = if deny_policy_bit {
        TradeFinanceActionClassV1::RejectForRuleFailure
    } else if deny_inconsistency_bit {
        TradeFinanceActionClassV1::RejectForInconsistency
    } else if escalate_bit {
        TradeFinanceActionClassV1::EscalateForRiskReview
    } else if manual_review_bit {
        TradeFinanceActionClassV1::ApproveWithManualReview
    } else {
        TradeFinanceActionClassV1::Approve
    };
    let action_class_code = action_class.code();
    let action_non_auto_sum = u64::from(deny_policy_bit)
        + u64::from(deny_inconsistency_bit)
        + u64::from(escalate_bit)
        + u64::from(manual_review_bit);
    write_bool_value(
        &mut values,
        "trade_finance_action_deny_policy_bit",
        deny_policy_bit,
    );
    write_bool_value(
        &mut values,
        "trade_finance_action_deny_inconsistency_bit",
        deny_inconsistency_bit,
    );
    write_bool_value(
        &mut values,
        "trade_finance_action_can_review_bit",
        eligibility_passed && !inconsistency_hit,
    );
    write_bool_value(
        &mut values,
        "trade_finance_action_escalate_bit",
        escalate_bit,
    );
    write_bool_value(
        &mut values,
        "trade_finance_action_manual_pre_bit",
        eligibility_passed && !inconsistency_hit && !fraud_hit,
    );
    write_bool_value(
        &mut values,
        "trade_finance_action_manual_review_bit",
        manual_review_bit,
    );
    write_value(
        &mut values,
        "trade_finance_action_non_auto_sum",
        action_non_auto_sum,
    );
    write_bool_value(&mut values, "trade_finance_action_approve_bit", approve_bit);
    write_value(&mut values, "action_class_code", action_class_code);
    let human_review_required = !approve_bit;
    write_bool_value(&mut values, "human_review_required", human_review_required);
    let payout_nonzero = write_geq_support(
        &mut values,
        "trade_finance_approved_advance_nonzero_bit",
        "trade_finance_approved_advance_nonzero_slack",
        &BigInt::from(approved_advance_amount),
        &BigInt::from(1u8),
        TRADE_FINANCE_VALUE_BOUND * TRADE_FINANCE_VALUE_BOUND,
        "trade_finance_approved_advance_nonzero",
    )?;
    let eligible_for_midnight_settlement = approve_bit && payout_nonzero;
    write_bool_value(
        &mut values,
        "eligible_for_midnight_settlement",
        eligible_for_midnight_settlement,
    );

    let settlement_instruction_inner = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_instruction_inner",
        [
            &BigInt::from(approved_advance_amount),
            &BigInt::from(reserve_amount),
            &BigInt::from(action_class_code),
            &BigInt::from(
                request
                    .settlement_terms
                    .supplier_advance_destination_commitment,
            ),
        ],
    )?;
    let settlement_instruction_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_instruction_outer",
        [
            &settlement_instruction_inner,
            &BigInt::from(
                request
                    .settlement_terms
                    .financier_reserve_account_commitment,
            ),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[1]),
        ],
    )?;
    let settlement_instruction_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_instruction_binding",
        [
            &settlement_instruction_commitment,
            &invoice_packet_commitment,
            &eligibility_commitment,
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[1]),
        ],
    )?;
    write_square_nonlinear_anchor(&mut values, "trade_finance_report_delay_margin_shifted");
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_LINE_ITEMS {
        write_square_nonlinear_anchor(
            &mut values,
            &format!("trade_finance_replacement_gap_{index}"),
        );
        write_square_nonlinear_anchor(&mut values, &format!("trade_finance_invoice_gap_{index}"));
        write_square_nonlinear_anchor(&mut values, &format!("trade_finance_quantity_gap_{index}"));
    }
    for signal in [
        "trade_finance_total_invoice_amount",
        "trade_finance_total_price_baseline",
        "trade_finance_eligibility_mismatch_score",
        "trade_finance_evidence_completeness_score",
        "trade_finance_duplication_score",
    ] {
        write_square_nonlinear_anchor(&mut values, signal);
    }
    for index in 0..PRIVATE_TRADE_FINANCE_MAX_DIGESTS {
        write_square_nonlinear_anchor(
            &mut values,
            &format!("trade_finance_digest_present_{index}"),
        );
    }

    Ok((
        values,
        TradeFinanceCoreComputationInternal {
            invoice_packet_commitment,
            evidence_manifest_digest: digest_manifest,
            eligibility_commitment,
            consistency_score_commitment,
            duplicate_financing_risk_commitment,
            approved_advance_commitment,
            reserve_amount_commitment,
            settlement_instruction_commitment,
            eligibility_passed,
            within_term_window,
            eligibility_predicate_supported,
            lender_exclusion_triggered,
            chronology_score,
            valuation_score,
            duplication_score,
            vendor_score,
            eligibility_mismatch_score,
            evidence_completeness_score,
            structured_inconsistency_score,
            consistency_score,
            duplicate_financing_risk_score,
            approved_advance_amount,
            reserve_amount,
            fee_amount,
            report_delay,
            total_estimate_amount,
            total_invoice_amount,
            total_reference_amount,
            total_valuation_gap,
            total_quantity_gap,
            duplicate_match_count,
            action_class,
            human_review_required,
            eligible_for_midnight_settlement,
        },
    ))
}

pub(crate) fn trade_finance_receivable_decision_witness_from_inputs(
    request: &TradeFinancePrivateInputsV1,
) -> ZkfResult<(Witness, TradeFinanceCoreComputationInternal)> {
    let program = build_trade_finance_decision_core_program()?;
    let (support_values, computation) = compute_core_support_values(request)?;
    let witness = generate_witness(&program, &support_values)?;
    Ok((witness, computation))
}

fn compute_trade_finance_settlement_binding_values(
    request: &TradeFinancePrivateInputsV1,
    core: &TradeFinanceCoreComputationInternal,
) -> ZkfResult<(WitnessInputs, TradeFinanceSettlementComputationInternal)> {
    let mut values = WitnessInputs::new();
    write_value(
        &mut values,
        "trade_finance_settlement_invoice_packet_commitment",
        core.invoice_packet_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_settlement_eligibility_commitment",
        core.eligibility_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_settlement_duplicate_financing_risk_score",
        core.duplicate_financing_risk_score,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_approved_advance_amount",
        core.approved_advance_amount,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_reserve_amount",
        core.reserve_amount,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_fee_amount",
        core.fee_amount,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_action_class_code",
        core.action_class.code(),
    );
    write_value(
        &mut values,
        "trade_finance_settlement_supplier_advance_destination_commitment",
        request
            .settlement_terms
            .supplier_advance_destination_commitment,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_financier_reserve_account_commitment",
        request
            .settlement_terms
            .financier_reserve_account_commitment,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_financier_participation_commitment",
        request.settlement_terms.financier_participation_commitment,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_dispute_threshold",
        request.settlement_terms.dispute_escalation_threshold,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_blinding_0",
        request.settlement_terms.settlement_blinding_values[0],
    );
    write_value(
        &mut values,
        "trade_finance_settlement_blinding_1",
        request.settlement_terms.settlement_blinding_values[1],
    );
    write_value(
        &mut values,
        "trade_finance_settlement_public_blinding_0",
        request.settlement_terms.public_disclosure_blinding_values[0],
    );
    write_value(
        &mut values,
        "trade_finance_settlement_public_blinding_1",
        request.settlement_terms.public_disclosure_blinding_values[1],
    );
    write_value(
        &mut values,
        "trade_finance_settlement_financing_window_open_timestamp",
        request.financing_policy.financing_window_open_timestamp,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_financing_window_close_timestamp",
        request.financing_policy.financing_window_close_timestamp,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_invoice_presented_timestamp",
        request.receivable_context.invoice_presented_timestamp,
    );
    write_value(
        &mut values,
        "trade_finance_settlement_financing_request_timestamp",
        request.receivable_context.financing_request_timestamp,
    );
    let hold_by_fraud = write_geq_support(
        &mut values,
        "trade_finance_settlement_hold_by_duplicate_risk_bit",
        "trade_finance_settlement_hold_by_duplicate_risk_slack",
        &BigInt::from(core.duplicate_financing_risk_score),
        &BigInt::from(request.settlement_terms.dispute_escalation_threshold),
        TRADE_FINANCE_SCORE_CAP,
        "trade_finance_settlement_hold_by_duplicate_risk",
    )?;
    let non_auto_action = write_geq_support(
        &mut values,
        "trade_finance_settlement_non_auto_action_bit",
        "trade_finance_settlement_non_auto_action_slack",
        &BigInt::from(core.action_class.code()),
        &BigInt::from(1u8),
        8,
        "trade_finance_settlement_non_auto_action",
    )?;
    let hold_required = hold_by_fraud || non_auto_action;
    write_bool_value(
        &mut values,
        "trade_finance_settlement_hold_required_bit",
        hold_required,
    );
    write_bool_value(
        &mut values,
        "trade_finance_settlement_finality_flag",
        !hold_required,
    );
    let settlement_instruction_inner = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_instruction_commitment_inner",
        [
            &BigInt::from(core.approved_advance_amount),
            &BigInt::from(core.reserve_amount),
            &BigInt::from(core.action_class.code()),
            &BigInt::from(
                request
                    .settlement_terms
                    .supplier_advance_destination_commitment,
            ),
        ],
    )?;
    let settlement_instruction_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_instruction_commitment_outer",
        [
            &settlement_instruction_inner,
            &BigInt::from(
                request
                    .settlement_terms
                    .financier_reserve_account_commitment,
            ),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[1]),
        ],
    )?;
    let settlement_instruction_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_instruction_commitment_binding",
        [
            &settlement_instruction_commitment,
            &core.invoice_packet_commitment,
            &core.eligibility_commitment,
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[1]),
        ],
    )?;
    let dispute_hold_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_dispute_hold_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_SETTLEMENT),
            &BigInt::from(core.action_class.code()),
            &BigInt::from(core.duplicate_financing_risk_score),
            &BigInt::from(request.settlement_terms.dispute_escalation_threshold),
        ],
    )?;
    let repayment_completion_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_repayment_completion_commitment_inner",
        [
            &BigInt::from(core.fee_amount),
            &BigInt::from(core.approved_advance_amount),
            &BigInt::from(request.settlement_terms.financier_participation_commitment),
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[0]),
        ],
    )?;
    let fee_amount_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_fee_amount_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_FEE),
            &BigInt::from(core.fee_amount),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[1]),
        ],
    )?;
    let maturity_schedule_inner = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_maturity_schedule_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_MATURITY),
            &BigInt::from(request.financing_policy.financing_window_open_timestamp),
            &BigInt::from(request.receivable_context.invoice_presented_timestamp),
            &BigInt::from(request.receivable_context.financing_request_timestamp),
        ],
    )?;
    let maturity_schedule_outer = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_maturity_schedule_commitment_outer",
        [
            &maturity_schedule_inner,
            &BigInt::from(request.financing_policy.financing_window_close_timestamp),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[0]),
            &BigInt::from(request.settlement_terms.settlement_blinding_values[1]),
        ],
    )?;
    let maturity_schedule_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_settlement_maturity_schedule_commitment_binding",
        [
            &maturity_schedule_outer,
            &core.invoice_packet_commitment,
            &core.eligibility_commitment,
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[1]),
        ],
    )?;
    write_value(
        &mut values,
        "trade_finance_settlement_settlement_instruction_commitment",
        settlement_instruction_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_settlement_dispute_hold_commitment",
        dispute_hold_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_settlement_repayment_completion_commitment",
        repayment_completion_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_settlement_fee_amount_commitment",
        fee_amount_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_settlement_maturity_schedule_commitment",
        maturity_schedule_commitment.clone(),
    );
    Ok((
        values,
        TradeFinanceSettlementComputationInternal {
            settlement_instruction_commitment,
            dispute_hold_commitment,
            repayment_completion_commitment,
            fee_amount_commitment,
            maturity_schedule_commitment,
            settlement_finality_flag: !hold_required,
        },
    ))
}

pub(crate) fn trade_finance_settlement_binding_internal_witness_from_inputs(
    request: &TradeFinancePrivateInputsV1,
    core: &TradeFinanceCoreComputationInternal,
) -> ZkfResult<(Witness, TradeFinanceSettlementComputationInternal)> {
    let program = build_trade_finance_settlement_binding_program()?;
    let (values, computation) = compute_trade_finance_settlement_binding_values(request, core)?;
    let witness = generate_witness(&program, &values)?;
    Ok((witness, computation))
}

fn compute_trade_finance_disclosure_projection_values(
    request: &TradeFinancePrivateInputsV1,
    core: &TradeFinanceCoreComputationInternal,
    role_code: u64,
) -> ZkfResult<(WitnessInputs, TradeFinanceDisclosureComputationInternal)> {
    let mut values = WitnessInputs::new();
    let role_bits = [
        role_code == TRADE_FINANCE_DISCLOSURE_ROLE_SUPPLIER,
        role_code == TRADE_FINANCE_DISCLOSURE_ROLE_FINANCIER,
        role_code == TRADE_FINANCE_DISCLOSURE_ROLE_BUYER,
        role_code == TRADE_FINANCE_DISCLOSURE_ROLE_AUDITOR,
        role_code == TRADE_FINANCE_DISCLOSURE_ROLE_REGULATOR,
    ];
    write_bool_value(
        &mut values,
        "trade_finance_disclosure_role_supplier",
        role_bits[0],
    );
    write_bool_value(
        &mut values,
        "trade_finance_disclosure_role_financier",
        role_bits[1],
    );
    write_bool_value(
        &mut values,
        "trade_finance_disclosure_role_buyer",
        role_bits[2],
    );
    write_bool_value(
        &mut values,
        "trade_finance_disclosure_role_auditor",
        role_bits[3],
    );
    write_bool_value(
        &mut values,
        "trade_finance_disclosure_role_regulator",
        role_bits[4],
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_invoice_packet_commitment",
        core.invoice_packet_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_eligibility_commitment",
        core.eligibility_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_consistency_score_commitment",
        core.consistency_score_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_duplicate_financing_risk_commitment",
        core.duplicate_financing_risk_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_approved_advance_commitment",
        core.approved_advance_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_reserve_commitment",
        core.reserve_amount_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_settlement_commitment",
        core.settlement_instruction_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_fee_amount",
        core.fee_amount,
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_credential_commitment",
        request.settlement_terms.disclosure_credential_commitment,
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_request_id_hash",
        request.settlement_terms.disclosure_request_id_hash,
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_caller_commitment",
        request.settlement_terms.disclosure_caller_commitment,
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_public_blinding_0",
        request.settlement_terms.public_disclosure_blinding_values[0],
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_public_blinding_1",
        request.settlement_terms.public_disclosure_blinding_values[1],
    );
    write_value(&mut values, "trade_finance_disclosure_role_sum", 1u64);
    write_value(&mut values, "trade_finance_disclosure_role_code", role_code);
    let disclosed_value_a = match role_code {
        TRADE_FINANCE_DISCLOSURE_ROLE_SUPPLIER => core.settlement_instruction_commitment.clone(),
        TRADE_FINANCE_DISCLOSURE_ROLE_FINANCIER => core.approved_advance_commitment.clone(),
        TRADE_FINANCE_DISCLOSURE_ROLE_BUYER => core.invoice_packet_commitment.clone(),
        TRADE_FINANCE_DISCLOSURE_ROLE_AUDITOR => core.approved_advance_commitment.clone(),
        TRADE_FINANCE_DISCLOSURE_ROLE_REGULATOR => core.reserve_amount_commitment.clone(),
        _ => {
            return Err(ZkfError::InvalidArtifact(format!(
                "unsupported trade-finance disclosure role code {role_code}"
            )));
        }
    };
    let disclosed_value_b = match role_code {
        TRADE_FINANCE_DISCLOSURE_ROLE_SUPPLIER => core.approved_advance_commitment.clone(),
        TRADE_FINANCE_DISCLOSURE_ROLE_FINANCIER => core.reserve_amount_commitment.clone(),
        TRADE_FINANCE_DISCLOSURE_ROLE_BUYER => core.eligibility_commitment.clone(),
        TRADE_FINANCE_DISCLOSURE_ROLE_AUDITOR => core.consistency_score_commitment.clone(),
        TRADE_FINANCE_DISCLOSURE_ROLE_REGULATOR => core.duplicate_financing_risk_commitment.clone(),
        _ => {
            return Err(ZkfError::InvalidArtifact(format!(
                "unsupported trade-finance disclosure role code {role_code}"
            )));
        }
    };
    write_value(
        &mut values,
        "trade_finance_disclosure_value_a_private",
        disclosed_value_a.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_value_b_private",
        disclosed_value_b.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_value_a",
        disclosed_value_a.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_disclosure_value_b",
        disclosed_value_b.clone(),
    );
    let disclosure_view_inner = write_poseidon_hash_support(
        &mut values,
        "trade_finance_disclosure_view_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_DISCLOSURE),
            &BigInt::from(role_code),
            &disclosed_value_a,
            &disclosed_value_b,
        ],
    )?;
    let disclosure_view_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_disclosure_view_commitment_outer",
        [
            &disclosure_view_inner,
            &BigInt::from(core.fee_amount),
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[0]),
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[1]),
        ],
    )?;
    write_value(
        &mut values,
        "trade_finance_disclosure_view_commitment",
        disclosure_view_commitment.clone(),
    );
    let disclosure_authorization_inner = write_poseidon_hash_support(
        &mut values,
        "trade_finance_disclosure_authorization_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_DISCLOSURE_AUTHORIZATION),
            &BigInt::from(role_code),
            &BigInt::from(request.settlement_terms.disclosure_credential_commitment),
            &BigInt::from(request.settlement_terms.disclosure_request_id_hash),
        ],
    )?;
    let disclosure_authorization_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_disclosure_authorization_commitment_outer",
        [
            &disclosure_authorization_inner,
            &BigInt::from(request.settlement_terms.disclosure_caller_commitment),
            &disclosure_view_commitment,
            &BigInt::from(request.settlement_terms.public_disclosure_blinding_values[0]),
        ],
    )?;
    write_value(
        &mut values,
        "trade_finance_disclosure_authorization_commitment",
        disclosure_authorization_commitment.clone(),
    );
    write_square_nonlinear_anchor(&mut values, "trade_finance_disclosure_role_sum");
    Ok((
        values,
        TradeFinanceDisclosureComputationInternal {
            role_code,
            disclosure_view_commitment,
            disclosure_authorization_commitment,
            disclosed_value_a,
            disclosed_value_b,
        },
    ))
}

pub(crate) fn trade_finance_disclosure_projection_internal_witness_from_inputs(
    request: &TradeFinancePrivateInputsV1,
    core: &TradeFinanceCoreComputationInternal,
    role_code: u64,
) -> ZkfResult<(Witness, TradeFinanceDisclosureComputationInternal)> {
    let program = build_trade_finance_disclosure_projection_program()?;
    let (values, computation) =
        compute_trade_finance_disclosure_projection_values(request, core, role_code)?;
    let witness = generate_witness(&program, &values)?;
    Ok((witness, computation))
}

fn compute_batch_shard_values(
    commitments: &[BigInt; PRIVATE_TRADE_FINANCE_MAX_DIGESTS],
) -> ZkfResult<(
    WitnessInputs,
    TradeFinanceDuplicateRegistryComputationInternal,
)> {
    let mut values = WitnessInputs::new();
    write_value(&mut values, "trade_finance_shard_shard_count", 2u64);
    write_value(&mut values, "trade_finance_shard_blinding_0", 17u64);
    write_value(&mut values, "trade_finance_shard_blinding_1", 29u64);
    for (index, commitment) in commitments.iter().enumerate() {
        write_value(
            &mut values,
            format!("trade_finance_shard_receivable_commitment_{index}"),
            commitment.clone(),
        );
        write_exact_division_support_bigint(
            &mut values,
            commitment,
            2,
            &format!("trade_finance_shard_assignment_quotient_{index}"),
            &format!("trade_finance_shard_assignment_{index}"),
            &format!("trade_finance_shard_assignment_slack_{index}"),
            &format!("trade_finance_shard_assignment_{index}"),
        )?;
    }
    write_geq_support(
        &mut values,
        "trade_finance_shard_count_valid_bit",
        "trade_finance_shard_count_valid_slack",
        &BigInt::from(2u8),
        &BigInt::from(2u8),
        TRADE_FINANCE_SHARD_COUNT_MAX,
        "trade_finance_shard_count_valid",
    )?;
    let batch_root_inner = write_poseidon_hash_support(
        &mut values,
        "trade_finance_shard_batch_root_commitment_inner",
        [
            &BigInt::from(TRADE_FINANCE_DOMAIN_SHARD_BATCH),
            &commitments[0],
            &commitments[1],
            &commitments[2],
        ],
    )?;
    let batch_root_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_shard_batch_root_commitment_outer",
        [
            &batch_root_inner,
            &commitments[3],
            &BigInt::from(17u8),
            &BigInt::from(29u8),
        ],
    )?;
    let assignment_0 = bigint_from_map(&values, "trade_finance_shard_assignment_0");
    let assignment_1 = bigint_from_map(&values, "trade_finance_shard_assignment_1");
    let assignment_2 = bigint_from_map(&values, "trade_finance_shard_assignment_2");
    let assignment_3 = bigint_from_map(&values, "trade_finance_shard_assignment_3");
    let assignment_commitment = write_poseidon_hash_support(
        &mut values,
        "trade_finance_shard_assignment_commitment_inner",
        [&assignment_0, &assignment_1, &assignment_2, &assignment_3],
    )?;
    write_value(
        &mut values,
        "trade_finance_shard_batch_root_commitment",
        batch_root_commitment.clone(),
    );
    write_value(
        &mut values,
        "trade_finance_shard_assignment_commitment",
        assignment_commitment.clone(),
    );
    Ok((
        values,
        TradeFinanceDuplicateRegistryComputationInternal {
            batch_root_commitment,
            assignment_commitment,
        },
    ))
}

pub(crate) fn trade_finance_duplicate_registry_handoff_internal_witness_from_commitments(
    commitments: &[BigInt; PRIVATE_TRADE_FINANCE_MAX_DIGESTS],
) -> ZkfResult<(Witness, TradeFinanceDuplicateRegistryComputationInternal)> {
    let program = build_trade_finance_duplicate_registry_handoff_program()?;
    let (values, computation) = compute_batch_shard_values(commitments)?;
    let witness = generate_witness(&program, &values)?;
    Ok((witness, computation))
}

pub fn private_trade_finance_settlement_sample_inputs() -> TradeFinancePrivateInputsV1 {
    let mut sample = TradeFinancePrivateInputsV1 {
        financing_policy: TradeFinancePolicyDataV1 {
            financing_policy_id_hash: 1001,
            financing_window_open_timestamp: 1_700_000_000,
            financing_window_close_timestamp: 1_900_000_000,
            eligibility_predicate_flags: [1, 0, 1, 0],
            lender_exclusion_predicate_flags: [0, 0, 0, 1],
            supplier_retention_schedule: [5_000, 0],
            advance_cap_schedule: [80_000, 0],
            discount_rate_rules: [1_500, 0],
            reserve_holdback_parameters: [2_000, 12_000],
            financier_participation_parameters: [4_000, 20_000, 50_000],
        },
        receivable_context: TradeFinanceReceivableContextDataV1 {
            receivable_id_hash: 2002,
            supplier_id_hash: 3003,
            invoice_presented_timestamp: 1_750_000_000,
            financing_request_timestamp: 1_750_086_400,
            jurisdiction_corridor_bucket: 8,
            observed_eligibility_predicate_flags: [1, 0, 0, 0],
            goods_or_service_class: 2,
            buyer_acceptance_term_flags: [1, 1, 0, 0],
            prior_financing_linkage_hashes: [9101, 9102, 9103, 9104],
        },
        supporting_documents: TradeFinanceEvidenceDataV1 {
            supporting_schedule_line_items: [
                TradeFinanceEstimateLineItemV1 {
                    quantity: 1,
                    unit_amount: 18_000,
                    reference_amount: 18_500,
                    discount_basis: 16_000,
                },
                TradeFinanceEstimateLineItemV1 {
                    quantity: 2,
                    unit_amount: 7_500,
                    reference_amount: 15_500,
                    discount_basis: 14_000,
                },
                TradeFinanceEstimateLineItemV1 {
                    quantity: 1,
                    unit_amount: 4_500,
                    reference_amount: 4_700,
                    discount_basis: 4_000,
                },
                TradeFinanceEstimateLineItemV1 {
                    quantity: 1,
                    unit_amount: 3_000,
                    reference_amount: 3_200,
                    discount_basis: 2_600,
                },
            ],
            invoice_line_items: [
                TradeFinanceInvoiceLineItemV1 {
                    quantity: 1,
                    invoice_amount: 18_100,
                },
                TradeFinanceInvoiceLineItemV1 {
                    quantity: 2,
                    invoice_amount: 15_300,
                },
                TradeFinanceInvoiceLineItemV1 {
                    quantity: 1,
                    invoice_amount: 4_450,
                },
                TradeFinanceInvoiceLineItemV1 {
                    quantity: 1,
                    invoice_amount: 3_050,
                },
            ],
            reference_amount_schedules: [18_500, 15_500, 4_700, 3_200],
            discount_basis_values: [16_000, 14_000, 4_000, 2_600],
            logistics_event_summary_values: [101, 102, 103, 104],
            vendor_attestation_digests: [4_001, 4_002, 4_003, 4_004],
            photo_analysis_result_digest: 8_001,
            document_extraction_result_digest: 8_002,
            buyer_approval_reference_digest: 8_003,
            evidence_manifest_digest: "0".to_string(),
        },
        duplicate_risk_inputs: TradeFinanceConsistencyFraudInputsV1 {
            duplicate_receivable_candidate_hashes: [10001, 10002, 9103, 10004],
            price_deviation_baselines: [500, 500, 300, 200],
            vendor_anomaly_baselines: [1_000, 1_000, 1_000, 1_000],
            chronology_consistency_threshold: 172_800,
            geographic_reasonableness_threshold: 12,
            quantity_tolerance_threshold: 2,
            valuation_tolerance_threshold: 8_000,
        },
        settlement_terms: TradeFinanceSettlementGovernanceInputsV1 {
            supplier_advance_destination_commitment: 70_001,
            financier_reserve_account_commitment: 70_002,
            financier_participation_commitment: 70_003,
            disclosure_credential_commitment: 70_004,
            disclosure_request_id_hash: 70_005,
            disclosure_caller_commitment: 70_006,
            dispute_escalation_threshold: 8_000,
            risk_review_threshold: 6_000,
            manual_review_threshold: 60_000,
            settlement_blinding_values: [111, 222],
            public_disclosure_blinding_values: [333, 444],
        },
    };
    let digest = {
        let mut values = flatten_private_inputs(&sample).expect("flatten trade-finance sample");
        write_private_input_anchor_chain(
            &mut values,
            &[
                evidence_name("photo_analysis_result_digest"),
                evidence_name("document_extraction_result_digest"),
                evidence_name("buyer_approval_reference_digest"),
                evidence_array_name("logistics_event_summary", 0),
            ],
            "trade_finance_evidence_anchor_sample",
        )
        .expect("sample digest")
    };
    sample.supporting_documents.evidence_manifest_digest = digest.to_str_radix(10);
    sample
}

pub fn private_trade_finance_settlement_manual_review_inputs() -> TradeFinancePrivateInputsV1 {
    let mut sample = private_trade_finance_settlement_sample_inputs();
    sample.supporting_documents.supporting_schedule_line_items[0].unit_amount = 30_000;
    sample.supporting_documents.invoice_line_items[0].invoice_amount = 30_200;
    sample.settlement_terms.manual_review_threshold = 35_000;
    sample
}

pub fn private_trade_finance_settlement_investigation_inputs() -> TradeFinancePrivateInputsV1 {
    let mut sample = private_trade_finance_settlement_sample_inputs();
    sample
        .duplicate_risk_inputs
        .duplicate_receivable_candidate_hashes[0] =
        sample.receivable_context.prior_financing_linkage_hashes[0];
    sample
        .duplicate_risk_inputs
        .duplicate_receivable_candidate_hashes[1] =
        sample.receivable_context.prior_financing_linkage_hashes[1];
    sample
}

pub fn private_trade_finance_settlement_rule_failure_rejection_inputs()
-> TradeFinancePrivateInputsV1 {
    let mut sample = private_trade_finance_settlement_sample_inputs();
    sample.receivable_context.invoice_presented_timestamp = 1_950_000_000;
    sample.receivable_context.financing_request_timestamp = 1_950_086_400;
    sample
}

pub fn private_trade_finance_settlement_inconsistency_denial_inputs() -> TradeFinancePrivateInputsV1
{
    let mut sample = private_trade_finance_settlement_sample_inputs();
    sample.supporting_documents.invoice_line_items[1].quantity = 8;
    sample.supporting_documents.invoice_line_items[1].invoice_amount = 90_000;
    sample.duplicate_risk_inputs.valuation_tolerance_threshold = 1_000;
    sample.duplicate_risk_inputs.quantity_tolerance_threshold = 1;
    sample
}

pub fn private_trade_finance_settlement_violation_inputs() -> TradeFinancePrivateInputsV1 {
    let mut sample = private_trade_finance_settlement_sample_inputs();
    sample.supporting_documents.evidence_manifest_digest = "12345".to_string();
    sample
}

pub fn private_trade_finance_settlement_showcase() -> ZkfResult<TemplateProgram> {
    Ok(TemplateProgram {
        program: build_trade_finance_decision_core_program()?,
        expected_inputs: trade_finance_private_input_names_v1(),
        public_outputs: expected_public_output_names(),
        sample_inputs: flatten_private_inputs(&private_trade_finance_settlement_sample_inputs())?,
        violation_inputs: flatten_private_inputs(
            &private_trade_finance_settlement_violation_inputs(),
        )?,
        description: "Private trade finance and settlement showcase for private trade-finance eligibility, duplicate-financing control, approved-advance, reserve/holdback, and settlement binding.",
    })
}

#[cfg(not(target_arch = "wasm32"))]
#[path = "private_trade_finance_settlement_export.rs"]
mod export;

#[cfg(not(target_arch = "wasm32"))]
pub use export::{
    APP_ID as PRIVATE_TRADE_FINANCE_SETTLEMENT_APP_ID, PrivateTradeFinanceSettlementExportConfig,
    PrivateTradeFinanceSettlementExportProfile,
    PrivateTradeFinanceSettlementHypernovaDiagnosticReport,
    run_private_trade_finance_settlement_export,
    run_private_trade_finance_settlement_hypernova_diagnostics,
};

pub type TradeFinanceFinancingPolicyInputsV1 = TradeFinancePolicyDataV1;
pub type TradeFinanceReceivableContextInputsV1 = TradeFinanceReceivableContextDataV1;
pub type TradeFinanceSupportingScheduleLineItemV1 = TradeFinanceEstimateLineItemV1;
pub type TradeFinanceSupportingDocumentsInputsV1 = TradeFinanceEvidenceDataV1;
pub type TradeFinanceDuplicateRiskInputsV1 = TradeFinanceConsistencyFraudInputsV1;
pub type TradeFinanceSettlementTermsInputsV1 = TradeFinanceSettlementGovernanceInputsV1;

#[derive(Debug, Clone, Serialize)]
pub struct TradeFinanceCoreDecisionComputation {
    pub invoice_packet_commitment: BigInt,
    pub evidence_manifest_digest: BigInt,
    pub eligibility_commitment: BigInt,
    pub consistency_score_commitment: BigInt,
    pub duplicate_financing_risk_commitment: BigInt,
    pub approved_advance_commitment: BigInt,
    pub reserve_amount_commitment: BigInt,
    pub settlement_instruction_commitment: BigInt,
    pub eligibility_passed: bool,
    pub within_term_window: bool,
    pub eligibility_predicate_supported: bool,
    pub lender_exclusion_triggered: bool,
    pub chronology_score: u64,
    pub valuation_score: u64,
    pub duplication_score: u64,
    pub vendor_score: u64,
    pub eligibility_mismatch_score: u64,
    pub evidence_completeness_score: u64,
    pub structured_inconsistency_score: u64,
    pub consistency_score: u64,
    pub duplicate_financing_risk_score: u64,
    pub approved_advance_amount: u64,
    pub reserve_amount: u64,
    pub fee_amount: u64,
    pub report_delay: u64,
    pub total_estimate_amount: u64,
    pub total_invoice_amount: u64,
    pub total_reference_amount: u64,
    pub total_valuation_gap: u64,
    pub total_quantity_gap: u64,
    pub duplicate_match_count: u64,
    pub action_class: TradeFinanceActionClassV1,
    pub human_review_required: bool,
    pub eligible_for_midnight_settlement: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TradeFinanceSettlementComputation {
    pub settlement_instruction_commitment: BigInt,
    pub dispute_hold_commitment: BigInt,
    pub repayment_completion_commitment: BigInt,
    pub fee_amount_commitment: BigInt,
    pub maturity_schedule_commitment: BigInt,
    pub settlement_finality_flag: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TradeFinanceDisclosureComputation {
    pub role_code: u64,
    pub disclosure_view_commitment: BigInt,
    pub disclosure_authorization_commitment: BigInt,
    pub disclosed_value_a: BigInt,
    pub disclosed_value_b: BigInt,
}

#[derive(Debug, Clone, Serialize)]
pub struct TradeFinanceDuplicateRegistryComputation {
    pub batch_root_commitment: BigInt,
    pub assignment_commitment: BigInt,
}

impl TradeFinanceCoreDecisionComputation {
    pub fn eligible_for_midnight_settlement(&self) -> bool {
        self.eligible_for_midnight_settlement
    }
}

impl From<TradeFinanceCoreComputationInternal> for TradeFinanceCoreDecisionComputation {
    fn from(value: TradeFinanceCoreComputationInternal) -> Self {
        Self {
            invoice_packet_commitment: value.invoice_packet_commitment,
            evidence_manifest_digest: value.evidence_manifest_digest,
            eligibility_commitment: value.eligibility_commitment,
            consistency_score_commitment: value.consistency_score_commitment,
            duplicate_financing_risk_commitment: value.duplicate_financing_risk_commitment,
            approved_advance_commitment: value.approved_advance_commitment,
            reserve_amount_commitment: value.reserve_amount_commitment,
            settlement_instruction_commitment: value.settlement_instruction_commitment,
            eligibility_passed: value.eligibility_passed,
            within_term_window: value.within_term_window,
            eligibility_predicate_supported: value.eligibility_predicate_supported,
            lender_exclusion_triggered: value.lender_exclusion_triggered,
            chronology_score: value.chronology_score,
            valuation_score: value.valuation_score,
            duplication_score: value.duplication_score,
            vendor_score: value.vendor_score,
            eligibility_mismatch_score: value.eligibility_mismatch_score,
            evidence_completeness_score: value.evidence_completeness_score,
            structured_inconsistency_score: value.structured_inconsistency_score,
            consistency_score: value.consistency_score,
            duplicate_financing_risk_score: value.duplicate_financing_risk_score,
            approved_advance_amount: value.approved_advance_amount,
            reserve_amount: value.reserve_amount,
            fee_amount: value.fee_amount,
            report_delay: value.report_delay,
            total_estimate_amount: value.total_estimate_amount,
            total_invoice_amount: value.total_invoice_amount,
            total_reference_amount: value.total_reference_amount,
            total_valuation_gap: value.total_valuation_gap,
            total_quantity_gap: value.total_quantity_gap,
            duplicate_match_count: value.duplicate_match_count,
            action_class: value.action_class,
            human_review_required: value.human_review_required,
            eligible_for_midnight_settlement: value.eligible_for_midnight_settlement,
        }
    }
}

impl From<TradeFinanceSettlementComputationInternal> for TradeFinanceSettlementComputation {
    fn from(value: TradeFinanceSettlementComputationInternal) -> Self {
        Self {
            settlement_instruction_commitment: value.settlement_instruction_commitment,
            dispute_hold_commitment: value.dispute_hold_commitment,
            repayment_completion_commitment: value.repayment_completion_commitment,
            fee_amount_commitment: value.fee_amount_commitment,
            maturity_schedule_commitment: value.maturity_schedule_commitment,
            settlement_finality_flag: value.settlement_finality_flag,
        }
    }
}

impl From<TradeFinanceDisclosureComputationInternal> for TradeFinanceDisclosureComputation {
    fn from(value: TradeFinanceDisclosureComputationInternal) -> Self {
        Self {
            role_code: value.role_code,
            disclosure_view_commitment: value.disclosure_view_commitment,
            disclosure_authorization_commitment: value.disclosure_authorization_commitment,
            disclosed_value_a: value.disclosed_value_a,
            disclosed_value_b: value.disclosed_value_b,
        }
    }
}

impl From<TradeFinanceDuplicateRegistryComputationInternal>
    for TradeFinanceDuplicateRegistryComputation
{
    fn from(value: TradeFinanceDuplicateRegistryComputationInternal) -> Self {
        Self {
            batch_root_commitment: value.batch_root_commitment,
            assignment_commitment: value.assignment_commitment,
        }
    }
}

impl TradeFinanceCoreComputationInternal {
    pub fn eligible_for_midnight_settlement(&self) -> bool {
        self.eligible_for_midnight_settlement
    }
}

fn trade_finance_core_from_public_wrapper(
    core: &TradeFinanceCoreDecisionComputation,
) -> TradeFinanceCoreComputationInternal {
    TradeFinanceCoreComputationInternal {
        invoice_packet_commitment: core.invoice_packet_commitment.clone(),
        evidence_manifest_digest: core.evidence_manifest_digest.clone(),
        eligibility_commitment: core.eligibility_commitment.clone(),
        consistency_score_commitment: core.consistency_score_commitment.clone(),
        duplicate_financing_risk_commitment: core.duplicate_financing_risk_commitment.clone(),
        approved_advance_commitment: core.approved_advance_commitment.clone(),
        reserve_amount_commitment: core.reserve_amount_commitment.clone(),
        settlement_instruction_commitment: core.settlement_instruction_commitment.clone(),
        eligibility_passed: core.eligibility_passed,
        within_term_window: core.within_term_window,
        eligibility_predicate_supported: core.eligibility_predicate_supported,
        lender_exclusion_triggered: core.lender_exclusion_triggered,
        chronology_score: core.chronology_score,
        valuation_score: core.valuation_score,
        duplication_score: core.duplication_score,
        vendor_score: core.vendor_score,
        eligibility_mismatch_score: core.eligibility_mismatch_score,
        evidence_completeness_score: core.evidence_completeness_score,
        structured_inconsistency_score: core.structured_inconsistency_score,
        consistency_score: core.consistency_score,
        duplicate_financing_risk_score: core.duplicate_financing_risk_score,
        approved_advance_amount: core.approved_advance_amount,
        reserve_amount: core.reserve_amount,
        fee_amount: core.fee_amount,
        report_delay: core.report_delay,
        total_estimate_amount: core.total_estimate_amount,
        total_invoice_amount: core.total_invoice_amount,
        total_reference_amount: core.total_reference_amount,
        total_valuation_gap: core.total_valuation_gap,
        total_quantity_gap: core.total_quantity_gap,
        duplicate_match_count: core.duplicate_match_count,
        action_class: core.action_class,
        human_review_required: core.human_review_required,
        eligible_for_midnight_settlement: core.eligible_for_midnight_settlement,
    }
}

pub fn private_trade_finance_approve_inputs() -> TradeFinancePrivateInputsV1 {
    private_trade_finance_settlement_sample_inputs()
}

pub fn private_trade_finance_settlement_approve_inputs() -> TradeFinancePrivateInputsV1 {
    private_trade_finance_settlement_sample_inputs()
}

pub fn private_trade_finance_settlement_approve_with_manual_review_inputs()
-> TradeFinancePrivateInputsV1 {
    private_trade_finance_settlement_manual_review_inputs()
}

pub fn private_trade_finance_settlement_risk_review_inputs() -> TradeFinancePrivateInputsV1 {
    private_trade_finance_settlement_investigation_inputs()
}

pub fn private_trade_finance_settlement_reject_for_rule_failure_inputs()
-> TradeFinancePrivateInputsV1 {
    private_trade_finance_settlement_rule_failure_rejection_inputs()
}

pub fn private_trade_finance_settlement_inconsistency_rejection_inputs()
-> TradeFinancePrivateInputsV1 {
    private_trade_finance_settlement_inconsistency_denial_inputs()
}

pub fn trade_finance_decision_witness_from_inputs(
    request: &TradeFinancePrivateInputsV1,
) -> ZkfResult<(Witness, TradeFinanceCoreDecisionComputation)> {
    trade_finance_receivable_decision_witness_from_inputs(request)
        .map(|(witness, computation)| (witness, computation.into()))
}

pub(crate) fn trade_finance_settlement_binding_witness_from_inputs(
    request: &TradeFinancePrivateInputsV1,
    core: &TradeFinanceCoreDecisionComputation,
) -> ZkfResult<(Witness, TradeFinanceSettlementComputation)> {
    let internal_core = trade_finance_core_from_public_wrapper(core);
    trade_finance_settlement_binding_internal_witness_from_inputs(request, &internal_core)
        .map(|(witness, computation)| (witness, computation.into()))
}

pub(crate) fn trade_finance_disclosure_projection_witness_from_inputs(
    request: &TradeFinancePrivateInputsV1,
    core: &TradeFinanceCoreDecisionComputation,
    role_code: u64,
) -> ZkfResult<(Witness, TradeFinanceDisclosureComputation)> {
    let internal_core = trade_finance_core_from_public_wrapper(core);
    trade_finance_disclosure_projection_internal_witness_from_inputs(
        request,
        &internal_core,
        role_code,
    )
    .map(|(witness, computation)| (witness, computation.into()))
}

pub(crate) fn trade_finance_duplicate_registry_handoff_witness_from_commitments(
    commitments: &[BigInt; 4],
) -> ZkfResult<(Witness, TradeFinanceDuplicateRegistryComputation)> {
    trade_finance_duplicate_registry_handoff_internal_witness_from_commitments(commitments)
        .map(|(witness, computation)| (witness, computation.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_string_pretty};

    fn assert_action(request: &TradeFinancePrivateInputsV1, expected: TradeFinanceActionClassV1) {
        let program = build_trade_finance_decision_core_program().expect("program");
        let (witness, computation) =
            trade_finance_receivable_decision_witness_from_inputs(request).expect("witness");
        check_constraints(&program, &witness).expect("constraints");
        assert_eq!(computation.action_class, expected);
    }

    #[test]
    fn trade_finance_approve_fixture_is_valid() {
        assert_action(
            &private_trade_finance_settlement_sample_inputs(),
            TradeFinanceActionClassV1::Approve,
        );
    }

    #[test]
    fn trade_finance_manual_review_fixture_is_valid() {
        assert_action(
            &private_trade_finance_settlement_manual_review_inputs(),
            TradeFinanceActionClassV1::ApproveWithManualReview,
        );
    }

    #[test]
    fn trade_finance_investigation_fixture_is_valid() {
        assert_action(
            &private_trade_finance_settlement_investigation_inputs(),
            TradeFinanceActionClassV1::EscalateForRiskReview,
        );
    }

    #[test]
    fn trade_finance_rule_failure_rejection_fixture_is_valid() {
        assert_action(
            &private_trade_finance_settlement_rule_failure_rejection_inputs(),
            TradeFinanceActionClassV1::RejectForRuleFailure,
        );
    }

    #[test]
    fn trade_finance_inconsistency_denial_fixture_is_valid() {
        assert_action(
            &private_trade_finance_settlement_inconsistency_denial_inputs(),
            TradeFinanceActionClassV1::RejectForInconsistency,
        );
    }

    #[test]
    fn trade_finance_serialization_round_trip() {
        let sample = private_trade_finance_settlement_sample_inputs();
        let json = to_string_pretty(&sample).expect("serialize");
        let round_trip: TradeFinancePrivateInputsV1 = from_str(&json).expect("deserialize");
        assert_eq!(round_trip, sample);
    }

    #[test]
    fn trade_finance_violation_fixture_breaks_constraints() {
        let program = build_trade_finance_decision_core_program().expect("program");
        let (mut values, _) =
            compute_core_support_values(&private_trade_finance_settlement_sample_inputs())
                .expect("values");
        write_value(
            &mut values,
            evidence_name("evidence_manifest_digest"),
            12345u64,
        );
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
    fn trade_finance_settlement_binding_matches_core_commitment() {
        let request = private_trade_finance_settlement_sample_inputs();
        let (core_witness, core) =
            trade_finance_receivable_decision_witness_from_inputs(&request).expect("core");
        check_constraints(
            &build_trade_finance_decision_core_program().expect("program"),
            &core_witness,
        )
        .expect("core constraints");
        let (settlement_witness, settlement) =
            trade_finance_settlement_binding_internal_witness_from_inputs(&request, &core)
                .expect("settlement");
        check_constraints(
            &build_trade_finance_settlement_binding_program().expect("program"),
            &settlement_witness,
        )
        .expect("settlement constraints");
        assert_eq!(
            settlement.settlement_instruction_commitment,
            core.settlement_instruction_commitment
        );
    }

    #[test]
    fn trade_finance_settlement_binding_emits_dedicated_fee_and_maturity_commitments() {
        const EXPECTED_FEE_DOMAIN: i64 = 1109;
        const EXPECTED_MATURITY_DOMAIN: i64 = 1110;

        fn poseidon_digest(inputs: [&BigInt; 4]) -> BigInt {
            poseidon_permutation4(inputs)
                .expect("poseidon")
                .first()
                .cloned()
                .expect("lane")
                .as_bigint()
        }

        let request = private_trade_finance_settlement_sample_inputs();
        let (_, core) =
            trade_finance_receivable_decision_witness_from_inputs(&request).expect("core");
        let program = build_trade_finance_settlement_binding_program().expect("program");
        let public_names = program
            .signals
            .iter()
            .filter(|signal| matches!(signal.visibility, zkf_core::Visibility::Public))
            .map(|signal| signal.name.as_str())
            .collect::<Vec<_>>();
        assert!(
            public_names.contains(&"trade_finance_settlement_fee_amount_commitment"),
            "settlement binding should expose a dedicated fee commitment output"
        );
        assert!(
            public_names.contains(&"trade_finance_settlement_maturity_schedule_commitment"),
            "settlement binding should expose a dedicated maturity schedule output"
        );

        let (witness, _) =
            trade_finance_settlement_binding_internal_witness_from_inputs(&request, &core)
                .expect("settlement");
        check_constraints(&program, &witness).expect("settlement constraints");

        let fee_amount = BigInt::from(core.fee_amount);
        let settlement_blinding_0 =
            BigInt::from(request.settlement_terms.settlement_blinding_values[0]);
        let settlement_blinding_1 =
            BigInt::from(request.settlement_terms.settlement_blinding_values[1]);
        let public_blinding_1 =
            BigInt::from(request.settlement_terms.public_disclosure_blinding_values[1]);
        let fee_expected = poseidon_digest([
            &BigInt::from(EXPECTED_FEE_DOMAIN),
            &fee_amount,
            &settlement_blinding_0,
            &settlement_blinding_1,
        ]);
        let maturity_inner = poseidon_digest([
            &BigInt::from(EXPECTED_MATURITY_DOMAIN),
            &BigInt::from(request.financing_policy.financing_window_open_timestamp),
            &BigInt::from(request.receivable_context.invoice_presented_timestamp),
            &BigInt::from(request.receivable_context.financing_request_timestamp),
        ]);
        let maturity_outer = poseidon_digest([
            &maturity_inner,
            &BigInt::from(request.financing_policy.financing_window_close_timestamp),
            &settlement_blinding_0,
            &settlement_blinding_1,
        ]);
        let maturity_expected = poseidon_digest([
            &maturity_outer,
            &core.invoice_packet_commitment,
            &core.eligibility_commitment,
            &public_blinding_1,
        ]);

        let fee_actual = witness
            .values
            .get("trade_finance_settlement_fee_amount_commitment")
            .cloned()
            .expect("fee commitment output")
            .as_bigint();
        let maturity_actual = witness
            .values
            .get("trade_finance_settlement_maturity_schedule_commitment")
            .cloned()
            .expect("maturity schedule output")
            .as_bigint();

        assert_eq!(fee_actual, fee_expected);
        assert_eq!(maturity_actual, maturity_expected);
    }

    #[test]
    fn trade_finance_disclosure_projection_is_deterministic() {
        let request = private_trade_finance_settlement_sample_inputs();
        let (_, core_a) =
            trade_finance_receivable_decision_witness_from_inputs(&request).expect("core");
        let (_, disclosure_a) =
            trade_finance_disclosure_projection_internal_witness_from_inputs(&request, &core_a, 2)
                .expect("disclosure");
        let (_, disclosure_b) =
            trade_finance_disclosure_projection_internal_witness_from_inputs(&request, &core_a, 2)
                .expect("disclosure");
        assert_eq!(
            disclosure_a.disclosure_view_commitment,
            disclosure_b.disclosure_view_commitment
        );
    }

    #[test]
    fn trade_finance_disclosure_roles_match_exported_policy_model() {
        let request = private_trade_finance_settlement_sample_inputs();
        let (_, core) =
            trade_finance_receivable_decision_witness_from_inputs(&request).expect("core");
        let program = build_trade_finance_disclosure_projection_program().expect("program");

        for (role_code, expected_a, expected_b) in [
            (
                TRADE_FINANCE_DISCLOSURE_ROLE_SUPPLIER,
                &core.settlement_instruction_commitment,
                &core.approved_advance_commitment,
            ),
            (
                TRADE_FINANCE_DISCLOSURE_ROLE_FINANCIER,
                &core.approved_advance_commitment,
                &core.reserve_amount_commitment,
            ),
            (
                TRADE_FINANCE_DISCLOSURE_ROLE_BUYER,
                &core.invoice_packet_commitment,
                &core.eligibility_commitment,
            ),
            (
                TRADE_FINANCE_DISCLOSURE_ROLE_AUDITOR,
                &core.approved_advance_commitment,
                &core.consistency_score_commitment,
            ),
            (
                TRADE_FINANCE_DISCLOSURE_ROLE_REGULATOR,
                &core.reserve_amount_commitment,
                &core.duplicate_financing_risk_commitment,
            ),
        ] {
            let (witness, disclosure) =
                trade_finance_disclosure_projection_internal_witness_from_inputs(
                    &request, &core, role_code,
                )
                .expect("disclosure");
            check_constraints(&program, &witness).expect("disclosure constraints");
            assert_eq!(disclosure.disclosed_value_a, *expected_a);
            assert_eq!(disclosure.disclosed_value_b, *expected_b);
            assert_eq!(
                witness
                    .values
                    .get("trade_finance_disclosure_authorization_commitment")
                    .expect("authorization output")
                    .as_bigint(),
                disclosure.disclosure_authorization_commitment
            );
        }
    }

    #[test]
    fn trade_finance_duplicate_registry_handoff_is_valid() {
        let request = private_trade_finance_settlement_sample_inputs();
        let (_, core_a) =
            trade_finance_receivable_decision_witness_from_inputs(&request).expect("core");
        let commitments = [
            core_a.invoice_packet_commitment.clone(),
            core_a.eligibility_commitment.clone(),
            core_a.consistency_score_commitment.clone(),
            core_a.settlement_instruction_commitment.clone(),
        ];
        let (witness, _) =
            trade_finance_duplicate_registry_handoff_witness_from_commitments(&commitments)
                .expect("shard witness");
        check_constraints(
            &build_trade_finance_duplicate_registry_handoff_program().expect("program"),
            &witness,
        )
        .expect("shard constraints");
    }

    #[test]
    #[ignore = "debug-only HyperNova witness diagnostic"]
    fn trade_finance_sample_hypernova_prepared_witness_reports_pasta_overflow_values() {
        let (witness, _) = trade_finance_receivable_decision_witness_from_inputs(
            &private_trade_finance_settlement_sample_inputs(),
        )
        .expect("witness");
        let program = build_trade_finance_decision_core_program().expect("program");
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
