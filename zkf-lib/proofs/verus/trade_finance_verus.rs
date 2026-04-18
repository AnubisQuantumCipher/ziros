use vstd::prelude::*;

verus! {

pub closed spec fn trade_finance_fixed_point_scale() -> int {
    10_000
}

pub closed spec fn trade_finance_score_cap() -> int {
    10_000
}

pub closed spec fn trade_finance_component_score_cap() -> int {
    4_000
}

pub closed spec fn trade_finance_role_count() -> int {
    5
}

pub closed spec fn trade_finance_packet_hash_bias() -> int {
    109
}

pub closed spec fn trade_finance_batch_domain() -> int {
    1108
}

pub closed spec fn trade_finance_disclosure_authorization_domain() -> int {
    1111
}

pub open spec fn bool_bit(value: bool) -> int {
    if value { 1 } else { 0 }
}

pub open spec fn min_int(left: int, right: int) -> int {
    if left <= right { left } else { right }
}

pub open spec fn max_int(left: int, right: int) -> int {
    if left >= right { left } else { right }
}

pub open spec fn sat_sub(left: int, right: int) -> int {
    if left >= right { left - right } else { 0 }
}

pub open spec fn cap_component(raw: int) -> int {
    if raw <= trade_finance_component_score_cap() {
        raw
    } else {
        trade_finance_component_score_cap()
    }
}

pub open spec fn cap_score(raw: int) -> int {
    if raw <= trade_finance_score_cap() {
        raw
    } else {
        trade_finance_score_cap()
    }
}

pub open spec fn symbolic_hash4(a: int, b: int, c: int, d: int) -> int {
    trade_finance_packet_hash_bias() + a + 101 * b + 103 * c + 107 * d
}

pub open spec fn packet_binding_step(previous: int, lane0: int, lane1: int, lane2: int) -> int {
    symbolic_hash4(previous, lane0, lane1, lane2)
}

pub open spec fn packet_binding_two_chunk(seed: int, lane0: int, lane1: int, lane2: int, lane3: int) -> int {
    packet_binding_step(packet_binding_step(seed, lane0, lane1, lane2), lane3, 0, 0)
}

pub open spec fn within_term_window(window_open: int, window_close: int, presented: int) -> bool {
    window_open <= presented && presented <= window_close
}

pub open spec fn eligibility_passed(
    window_ok: bool,
    supported_eligibility_predicate_count: int,
    lender_exclusion_match_count: int,
    buyer_acceptance_term_count: int,
) -> bool {
    window_ok && supported_eligibility_predicate_count >= 1 && lender_exclusion_match_count == 0 && buyer_acceptance_term_count >= 1
}

pub open spec fn approved_advance_amount(
    eligible_invoice: int,
    retention_amount: int,
    discount_amount: int,
    advance_cap: int,
) -> int {
    min_int(sat_sub(sat_sub(eligible_invoice, retention_amount), discount_amount), advance_cap)
}

pub open spec fn reserve_amount(approved_advance: int, reserve_margin: int, reserve_floor: int) -> int {
    max_int(approved_advance + reserve_margin, reserve_floor)
}

pub open spec fn fee_base(approved_advance: int, attachment_point: int, participation_cap: int) -> int {
    min_int(sat_sub(approved_advance, attachment_point), participation_cap)
}

pub open spec fn fee_amount(
    approved_advance: int,
    attachment_point: int,
    participation_cap: int,
    participation_rate: int,
    scale: int,
) -> int {
    (fee_base(approved_advance, attachment_point, participation_cap) * participation_rate) / scale
}

pub open spec fn structured_inconsistency_score_raw(
    valuation_score: int,
    quantity_score: int,
    geographic_reasonable: bool,
    request_after_presentment: bool,
    evidence_completeness_score: int,
) -> int {
    valuation_score
        + quantity_score
        + bool_bit(!geographic_reasonable) * 800
        + bool_bit(!request_after_presentment) * 2_000
        + evidence_completeness_score
}

pub open spec fn structured_inconsistency_score(
    valuation_score: int,
    quantity_score: int,
    geographic_reasonable: bool,
    request_after_presentment: bool,
    evidence_completeness_score: int,
) -> int {
    cap_score(structured_inconsistency_score_raw(
        valuation_score,
        quantity_score,
        geographic_reasonable,
        request_after_presentment,
        evidence_completeness_score,
    ))
}

pub open spec fn consistency_score(
    valuation_score: int,
    quantity_score: int,
    geographic_reasonable: bool,
    request_after_presentment: bool,
    evidence_completeness_score: int,
) -> int {
    trade_finance_score_cap()
        - structured_inconsistency_score(
            valuation_score,
            quantity_score,
            geographic_reasonable,
            request_after_presentment,
            evidence_completeness_score,
        )
}

pub open spec fn duplicate_financing_risk_score_raw(
    duplication_score: int,
    vendor_score: int,
    chronology_score: int,
    eligibility_mismatch_score: int,
) -> int {
    duplication_score + vendor_score + chronology_score + eligibility_mismatch_score
}

pub open spec fn duplicate_financing_risk_score(
    duplication_score: int,
    vendor_score: int,
    chronology_score: int,
    eligibility_mismatch_score: int,
) -> int {
    cap_score(duplicate_financing_risk_score_raw(
        duplication_score,
        vendor_score,
        chronology_score,
        eligibility_mismatch_score,
    ))
}

pub open spec fn action_class_code(
    eligible: bool,
    inconsistency_hit: bool,
    risk_review_hit: bool,
    manual_review_hit: bool,
) -> int {
    if !eligible {
        3
    } else if inconsistency_hit {
        4
    } else if risk_review_hit {
        2
    } else if manual_review_hit {
        1
    } else {
        0
    }
}

pub open spec fn human_review_required(
    eligible: bool,
    inconsistency_hit: bool,
    risk_review_hit: bool,
    manual_review_hit: bool,
) -> bool {
    action_class_code(eligible, inconsistency_hit, risk_review_hit, manual_review_hit) != 0
}

pub open spec fn eligible_for_midnight_settlement(
    eligible: bool,
    inconsistency_hit: bool,
    risk_review_hit: bool,
    manual_review_hit: bool,
    approved_advance: int,
) -> bool {
    action_class_code(eligible, inconsistency_hit, risk_review_hit, manual_review_hit) == 0
        && approved_advance > 0
}

pub open spec fn settlement_binding_inner(
    approved_advance: int,
    reserve: int,
    action_class: int,
    destination_commitment: int,
) -> int {
    symbolic_hash4(approved_advance, reserve, action_class, destination_commitment)
}

pub open spec fn settlement_binding_outer(
    inner: int,
    reserve_account_commitment: int,
    settlement_blinding0: int,
    settlement_blinding1: int,
) -> int {
    symbolic_hash4(inner, reserve_account_commitment, settlement_blinding0, settlement_blinding1)
}

pub open spec fn settlement_binding_digest(
    approved_advance: int,
    reserve: int,
    action_class: int,
    destination_commitment: int,
    reserve_account_commitment: int,
    settlement_blinding0: int,
    settlement_blinding1: int,
    invoice_packet_commitment: int,
    eligibility_commitment: int,
    public_blinding1: int,
) -> int {
    symbolic_hash4(
        settlement_binding_outer(
            settlement_binding_inner(
                approved_advance,
                reserve,
                action_class,
                destination_commitment,
            ),
            reserve_account_commitment,
            settlement_blinding0,
            settlement_blinding1,
        ),
        invoice_packet_commitment,
        eligibility_commitment,
        public_blinding1,
    )
}

pub open spec fn disclosure_value_a(
    role: int,
    settlement_commitment: int,
    advance_commitment: int,
    invoice_commitment: int,
    reserve_commitment: int,
) -> int {
    if role == 0 {
        settlement_commitment
    } else if role == 1 {
        advance_commitment
    } else if role == 2 {
        invoice_commitment
    } else if role == 3 {
        advance_commitment
    } else {
        reserve_commitment
    }
}

pub open spec fn disclosure_value_b(
    role: int,
    advance_commitment: int,
    eligibility_commitment: int,
    consistency_commitment: int,
    reserve_commitment: int,
    duplicate_risk_commitment: int,
) -> int {
    if role == 0 {
        advance_commitment
    } else if role == 1 {
        reserve_commitment
    } else if role == 2 {
        eligibility_commitment
    } else if role == 3 {
        consistency_commitment
    } else {
        duplicate_risk_commitment
    }
}

pub open spec fn disclosure_authorization_inner(
    role: int,
    credential_commitment: int,
    request_id_hash: int,
) -> int {
    symbolic_hash4(
        trade_finance_disclosure_authorization_domain(),
        role,
        credential_commitment,
        request_id_hash,
    )
}

pub open spec fn disclosure_authorization_commitment(
    role: int,
    credential_commitment: int,
    request_id_hash: int,
    caller_commitment: int,
    view_commitment: int,
    public_blinding: int,
) -> int {
    symbolic_hash4(
        disclosure_authorization_inner(role, credential_commitment, request_id_hash),
        caller_commitment,
        view_commitment,
        public_blinding,
    )
}

pub open spec fn duplicate_registry_batch_root(
    commitment0: int,
    commitment1: int,
    commitment2: int,
    commitment3: int,
    blinding0: int,
    blinding1: int,
) -> int {
    symbolic_hash4(
        symbolic_hash4(trade_finance_batch_domain(), commitment0, commitment1, commitment2),
        commitment3,
        blinding0,
        blinding1,
    )
}

pub open spec fn generated_circuit_certificate_accepts(
    field_is_pastafq: bool,
    poseidon_nodes_width4: bool,
    program_digest_linkage: bool,
    disclosure_authorization_bound: bool,
    emitted_noninterference_bound: bool,
) -> bool {
    field_is_pastafq
        && poseidon_nodes_width4
        && program_digest_linkage
        && disclosure_authorization_bound
        && emitted_noninterference_bound
}

pub open spec fn shard_assignment(commitment: int, shard_count: int) -> int
    recommends shard_count > 0
{
    commitment % shard_count
}

pub proof fn packet_binding_soundness(seed: int, lane0: int, lane1: int, lane2: int, lane3: int)
    ensures
        packet_binding_two_chunk(seed, lane0, lane1, lane2, lane3)
            == symbolic_hash4(symbolic_hash4(seed, lane0, lane1, lane2), lane3, 0, 0),
{
}

pub proof fn eligibility_soundness(
    window_open: int,
    window_close: int,
    presented: int,
    supported_eligibility_predicate_count: int,
    lender_exclusion_match_count: int,
    buyer_acceptance_term_count: int,
)
    requires
        window_open <= window_close,
        supported_eligibility_predicate_count >= 0,
        lender_exclusion_match_count >= 0,
        buyer_acceptance_term_count >= 0,
        eligibility_passed(
            within_term_window(window_open, window_close, presented),
            supported_eligibility_predicate_count,
            lender_exclusion_match_count,
            buyer_acceptance_term_count,
        ),
    ensures
        within_term_window(window_open, window_close, presented),
        window_open <= presented,
        presented <= window_close,
        supported_eligibility_predicate_count >= 1,
        lender_exclusion_match_count == 0,
        buyer_acceptance_term_count >= 1,
{
}

pub proof fn consistency_score_soundness(
    valuation_score: int,
    quantity_score: int,
    geographic_reasonable: bool,
    request_after_presentment: bool,
    evidence_completeness_score: int,
)
    requires
        valuation_score >= 0,
        quantity_score >= 0,
        evidence_completeness_score >= 0,
    ensures
        0 <= structured_inconsistency_score(
            valuation_score,
            quantity_score,
            geographic_reasonable,
            request_after_presentment,
            evidence_completeness_score,
        ) <= trade_finance_score_cap(),
        consistency_score(
            valuation_score,
            quantity_score,
            geographic_reasonable,
            request_after_presentment,
            evidence_completeness_score,
        )
            + structured_inconsistency_score(
                valuation_score,
                quantity_score,
                geographic_reasonable,
                request_after_presentment,
                evidence_completeness_score,
            ) == trade_finance_score_cap(),
{
}

pub proof fn duplicate_financing_risk_soundness(
    duplication_score: int,
    vendor_score: int,
    chronology_score: int,
    eligibility_mismatch_score: int,
)
    requires
        duplication_score >= 0,
        vendor_score >= 0,
        chronology_score >= 0,
        eligibility_mismatch_score >= 0,
    ensures
        duplicate_financing_risk_score(
            duplication_score,
            vendor_score,
            chronology_score,
            eligibility_mismatch_score,
        )
            == cap_score(
                duplication_score + vendor_score + chronology_score + eligibility_mismatch_score,
            ),
        0 <= duplicate_financing_risk_score(
            duplication_score,
            vendor_score,
            chronology_score,
            eligibility_mismatch_score,
        ) <= trade_finance_score_cap(),
{
}

pub proof fn approved_advance_fee_reserve_soundness(
    eligible_invoice: int,
    retention_amount: int,
    discount_amount: int,
    advance_cap: int,
    reserve_margin: int,
    reserve_floor: int,
    attachment_point: int,
    participation_cap: int,
    participation_rate: int,
    scale: int,
)
    requires
        eligible_invoice >= 0,
        retention_amount >= 0,
        discount_amount >= 0,
        advance_cap >= 0,
        reserve_margin >= 0,
        reserve_floor >= 0,
        attachment_point >= 0,
        participation_cap >= 0,
        participation_rate >= 0,
        scale > 0,
    ensures
        0 <= approved_advance_amount(
            eligible_invoice,
            retention_amount,
            discount_amount,
            advance_cap,
        ) <= advance_cap,
        reserve_amount(
            approved_advance_amount(
                eligible_invoice,
                retention_amount,
                discount_amount,
                advance_cap,
            ),
            reserve_margin,
            reserve_floor,
        ) >= reserve_floor,
        reserve_amount(
            approved_advance_amount(
                eligible_invoice,
                retention_amount,
                discount_amount,
                advance_cap,
            ),
            reserve_margin,
            reserve_floor,
        )
            >= approved_advance_amount(
                eligible_invoice,
                retention_amount,
                discount_amount,
                advance_cap,
            ),
        approved_advance_amount(
            eligible_invoice,
            retention_amount,
            discount_amount,
            advance_cap,
        ) <= attachment_point
            ==> fee_amount(
                approved_advance_amount(
                    eligible_invoice,
                    retention_amount,
                    discount_amount,
                    advance_cap,
                ),
                attachment_point,
                participation_cap,
                participation_rate,
                scale,
            ) == 0,
{
    let approved = approved_advance_amount(
        eligible_invoice,
        retention_amount,
        discount_amount,
        advance_cap,
    );
    assert(approved == min_int(sat_sub(sat_sub(eligible_invoice, retention_amount), discount_amount), advance_cap));
    if approved <= attachment_point {
        assert(sat_sub(approved, attachment_point) == 0);
        assert(fee_base(approved, attachment_point, participation_cap) == 0);
        assert(fee_amount(
            approved,
            attachment_point,
            participation_cap,
            participation_rate,
            scale,
        ) == 0);
    }
}

pub proof fn action_derivation_soundness(
    eligible: bool,
    inconsistency_hit: bool,
    risk_review_hit: bool,
    manual_review_hit: bool,
    approved_advance: int,
)
    requires
        approved_advance >= 0,
    ensures
        0 <= action_class_code(eligible, inconsistency_hit, risk_review_hit, manual_review_hit) <= 4,
        human_review_required(eligible, inconsistency_hit, risk_review_hit, manual_review_hit)
            == (action_class_code(eligible, inconsistency_hit, risk_review_hit, manual_review_hit) != 0),
        eligible_for_midnight_settlement(
            eligible,
            inconsistency_hit,
            risk_review_hit,
            manual_review_hit,
            approved_advance,
        )
            ==> action_class_code(eligible, inconsistency_hit, risk_review_hit, manual_review_hit) == 0
                && approved_advance > 0,
{
}

pub proof fn settlement_binding_soundness(
    approved_advance: int,
    reserve: int,
    action_class: int,
    destination_commitment: int,
    reserve_account_commitment: int,
    settlement_blinding0: int,
    settlement_blinding1: int,
    invoice_packet_commitment: int,
    eligibility_commitment: int,
    public_blinding1: int,
)
    ensures
        settlement_binding_digest(
            approved_advance,
            reserve,
            action_class,
            destination_commitment,
            reserve_account_commitment,
            settlement_blinding0,
            settlement_blinding1,
            invoice_packet_commitment,
            eligibility_commitment,
            public_blinding1,
        )
            == symbolic_hash4(
                symbolic_hash4(
                    symbolic_hash4(
                        approved_advance,
                        reserve,
                        action_class,
                        destination_commitment,
                    ),
                    reserve_account_commitment,
                    settlement_blinding0,
                    settlement_blinding1,
                ),
                invoice_packet_commitment,
                eligibility_commitment,
                public_blinding1,
            ),
{
}

pub proof fn disclosure_role_binding_soundness(
    role: int,
    settlement_commitment: int,
    advance_commitment: int,
    invoice_commitment: int,
    reserve_commitment: int,
    eligibility_commitment: int,
    consistency_commitment: int,
    duplicate_risk_commitment: int,
)
    requires
        0 <= role < trade_finance_role_count(),
    ensures
        role == 0 ==> (
            disclosure_value_a(
                role,
                settlement_commitment,
                advance_commitment,
                invoice_commitment,
                reserve_commitment,
            ) == settlement_commitment
                && disclosure_value_b(
                    role,
                    advance_commitment,
                    eligibility_commitment,
                    consistency_commitment,
                    reserve_commitment,
                    duplicate_risk_commitment,
                ) == advance_commitment
        ),
        role == 1 ==> (
            disclosure_value_a(
                role,
                settlement_commitment,
                advance_commitment,
                invoice_commitment,
                reserve_commitment,
            ) == advance_commitment
                && disclosure_value_b(
                    role,
                    advance_commitment,
                    eligibility_commitment,
                    consistency_commitment,
                    reserve_commitment,
                    duplicate_risk_commitment,
                ) == reserve_commitment
        ),
        role == 2 ==> (
            disclosure_value_a(
                role,
                settlement_commitment,
                advance_commitment,
                invoice_commitment,
                reserve_commitment,
            ) == invoice_commitment
                && disclosure_value_b(
                    role,
                    advance_commitment,
                    eligibility_commitment,
                    consistency_commitment,
                    reserve_commitment,
                    duplicate_risk_commitment,
                ) == eligibility_commitment
        ),
        role == 3 ==> (
            disclosure_value_a(
                role,
                settlement_commitment,
                advance_commitment,
                invoice_commitment,
                reserve_commitment,
            ) == advance_commitment
                && disclosure_value_b(
                    role,
                    advance_commitment,
                    eligibility_commitment,
                    consistency_commitment,
                    reserve_commitment,
                    duplicate_risk_commitment,
                ) == consistency_commitment
        ),
        role == 4 ==> (
            disclosure_value_a(
                role,
                settlement_commitment,
                advance_commitment,
                invoice_commitment,
                reserve_commitment,
            ) == reserve_commitment
                && disclosure_value_b(
                    role,
                    advance_commitment,
                    eligibility_commitment,
                    consistency_commitment,
                    reserve_commitment,
                    duplicate_risk_commitment,
                ) == duplicate_risk_commitment
        ),
{
}

pub proof fn disclosure_authorization_binding_soundness(
    role: int,
    credential_commitment: int,
    request_id_hash: int,
    caller_commitment: int,
    view_commitment: int,
    public_blinding: int,
)
    ensures
        disclosure_authorization_commitment(
            role,
            credential_commitment,
            request_id_hash,
            caller_commitment,
            view_commitment,
            public_blinding,
        ) == symbolic_hash4(
            disclosure_authorization_inner(role, credential_commitment, request_id_hash),
            caller_commitment,
            view_commitment,
            public_blinding,
        ),
        disclosure_authorization_inner(role, credential_commitment, request_id_hash)
            == symbolic_hash4(
                trade_finance_disclosure_authorization_domain(),
                role,
                credential_commitment,
                request_id_hash,
            ),
{
}

pub proof fn duplicate_registry_handoff_soundness(
    commitment0: int,
    commitment1: int,
    commitment2: int,
    commitment3: int,
    blinding0: int,
    blinding1: int,
    shard_count: int,
)
    requires
        shard_count > 0,
        commitment0 >= 0,
        commitment1 >= 0,
        commitment2 >= 0,
        commitment3 >= 0,
    ensures
        duplicate_registry_batch_root(
            commitment0,
            commitment1,
            commitment2,
            commitment3,
            blinding0,
            blinding1,
        )
            == symbolic_hash4(
                symbolic_hash4(trade_finance_batch_domain(), commitment0, commitment1, commitment2),
                commitment3,
                blinding0,
                blinding1,
            ),
        0 <= shard_assignment(commitment0, shard_count) < shard_count,
        shard_count == 2 ==> (
            shard_assignment(commitment0, shard_count) == 0
                || shard_assignment(commitment0, shard_count) == 1
        ),
{
    assert(0 <= commitment0 % shard_count < shard_count) by (nonlinear_arith)
        requires
            commitment0 >= 0,
            shard_count > 0,
    ;
    if shard_count == 2 {
        assert(0 <= shard_assignment(commitment0, shard_count) < 2);
        if shard_assignment(commitment0, shard_count) == 0 {
        } else {
            assert(shard_assignment(commitment0, shard_count) == 1) by (nonlinear_arith)
                requires
                    0 <= shard_assignment(commitment0, shard_count),
                    shard_assignment(commitment0, shard_count) < 2,
                    shard_assignment(commitment0, shard_count) != 0,
            ;
        }
    }
}

pub proof fn generated_circuit_certificate_acceptance_soundness(
    field_is_pastafq: bool,
    poseidon_nodes_width4: bool,
    program_digest_linkage: bool,
    disclosure_authorization_bound: bool,
    emitted_noninterference_bound: bool,
)
    requires
        generated_circuit_certificate_accepts(
            field_is_pastafq,
            poseidon_nodes_width4,
            program_digest_linkage,
            disclosure_authorization_bound,
            emitted_noninterference_bound,
        ),
    ensures
        field_is_pastafq,
        poseidon_nodes_width4,
        program_digest_linkage,
        disclosure_authorization_bound,
        emitted_noninterference_bound,
{
}

} // verus!

fn main() {}
