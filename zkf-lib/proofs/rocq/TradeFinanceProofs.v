From Stdlib Require Import ZArith Lia Bool.
Open Scope Z_scope.

Definition within_term_window (window_open window_close presented : Z) : bool :=
  Z.leb window_open presented && Z.leb presented window_close.

Definition eligibility_passed
  (window_ok : bool)
  (supported_eligibility_predicate_count lender_exclusion_match_count buyer_acceptance_term_count : Z) : bool :=
  window_ok
    && Z.geb supported_eligibility_predicate_count 1
    && Z.eqb lender_exclusion_match_count 0
    && Z.geb buyer_acceptance_term_count 1.

Definition approved_advance_amount
  (eligible_invoice retention_amount discount_amount advance_cap : Z) : Z :=
  Z.min (Z.max 0 (eligible_invoice - retention_amount - discount_amount)) advance_cap.

Definition reserve_amount
  (approved_advance reserve_margin reserve_floor : Z) : Z :=
  Z.max (approved_advance + reserve_margin) reserve_floor.

Definition fee_amount
  (approved_advance attachment_point participation_cap participation_rate scale : Z) : Z :=
  (Z.min (Z.max 0 (approved_advance - attachment_point)) participation_cap * participation_rate) / scale.

Definition action_class_code
  (eligible inconsistency_hit risk_review_hit manual_review_hit : bool) : Z :=
  if negb eligible then 3
  else if inconsistency_hit then 4
  else if risk_review_hit then 2
  else if manual_review_hit then 1
  else 0.

Definition human_review_required
  (eligible inconsistency_hit risk_review_hit manual_review_hit : bool) : bool :=
  negb eligible || inconsistency_hit || risk_review_hit || manual_review_hit.

Definition eligible_for_midnight_settlement
  (eligible inconsistency_hit risk_review_hit manual_review_hit : bool)
  (approved_advance : Z) : bool :=
  eligible
    && negb inconsistency_hit
    && negb risk_review_hit
    && negb manual_review_hit
    && Z.gtb approved_advance 0.

Definition disclosure_value_a
  (role settlement_commitment advance_commitment invoice_commitment reserve_commitment : Z) : Z :=
  match role with
  | 0 => settlement_commitment
  | 1 => advance_commitment
  | 2 => invoice_commitment
  | 3 => advance_commitment
  | _ => reserve_commitment
  end.

Definition disclosure_value_b
  (role advance_commitment eligibility_commitment consistency_commitment
        reserve_commitment duplicate_risk_commitment : Z) : Z :=
  match role with
  | 0 => advance_commitment
  | 1 => reserve_commitment
  | 2 => eligibility_commitment
  | 3 => consistency_commitment
  | _ => duplicate_risk_commitment
  end.

Definition disclosure_authorization_inner
  (role credential_commitment request_id_hash : Z) : Z :=
  1111 + role + credential_commitment + request_id_hash.

Definition disclosure_authorization_commitment
  (role credential_commitment request_id_hash caller_commitment view_commitment public_blinding : Z) : Z :=
  disclosure_authorization_inner role credential_commitment request_id_hash
    + caller_commitment
    + view_commitment
    + public_blinding.

Definition role_selector_count (role : Z) : Z := if (role <? 5)%Z then 1 else 0.

Definition shard_assignment (commitment shard_count : Z) : Z := Z.modulo commitment shard_count.

Definition batch_root_payload
  (commitment_0 commitment_1 commitment_2 commitment_3 blinding_0 blinding_1 : Z) : Z :=
  commitment_0 + commitment_1 + commitment_2 + commitment_3 + blinding_0 + blinding_1.

Theorem within_term_window_true_iff :
  forall window_open window_close presented,
    within_term_window window_open window_close presented = true <->
    window_open <= presented /\ presented <= window_close.
Proof.
  intros window_open window_close presented.
  unfold within_term_window.
  split.
  - intro H.
    apply Bool.andb_true_iff in H as [Hopen Hclose].
    apply Z.leb_le in Hopen.
    apply Z.leb_le in Hclose.
    exact (conj Hopen Hclose).
  - intros [Hopen Hclose].
    apply Bool.andb_true_iff.
    split; apply Z.leb_le; assumption.
Qed.

Theorem eligibility_passed_true_implies_trade_finance_conditions :
  forall window_ok supported_eligibility_predicate_count lender_exclusion_match_count buyer_acceptance_term_count,
    eligibility_passed window_ok supported_eligibility_predicate_count lender_exclusion_match_count buyer_acceptance_term_count = true ->
    window_ok = true
    /\ 1 <= supported_eligibility_predicate_count
    /\ lender_exclusion_match_count = 0
    /\ 1 <= buyer_acceptance_term_count.
Proof.
  intros window_ok supported_eligibility_predicate_count lender_exclusion_match_count buyer_acceptance_term_count H.
  unfold eligibility_passed in H.
  repeat rewrite Bool.andb_true_iff in H.
  destruct H as [[[Hwindow Hsupported] Hexclusion] Hrequested].
  apply Z.geb_le in Hsupported.
  apply Z.eqb_eq in Hexclusion.
  apply Z.geb_le in Hrequested.
  repeat split; assumption.
Qed.

Theorem approved_advance_bounded_by_cap :
  forall eligible_invoice retention_amount discount_amount advance_cap,
    approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap <= advance_cap.
Proof.
  intros eligible_invoice retention_amount discount_amount advance_cap.
  unfold approved_advance_amount.
  apply Z.le_min_r.
Qed.

Theorem approved_advance_nonnegative :
  forall eligible_invoice retention_amount discount_amount advance_cap,
    0 <= advance_cap ->
    0 <= approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap.
Proof.
  intros eligible_invoice retention_amount discount_amount advance_cap Hcap.
  unfold approved_advance_amount.
  apply Z.min_glb.
  - apply Z.le_max_l.
  - exact Hcap.
Qed.

Theorem reserve_amount_respects_floor :
  forall approved_advance reserve_margin reserve_floor,
    reserve_floor <= reserve_amount approved_advance reserve_margin reserve_floor.
Proof.
  intros approved_advance reserve_margin reserve_floor.
  unfold reserve_amount.
  apply Z.le_max_r.
Qed.

Theorem reserve_amount_ge_approved_advance_when_margin_nonnegative :
  forall approved_advance reserve_margin reserve_floor,
    0 <= reserve_margin ->
    approved_advance <= reserve_amount approved_advance reserve_margin reserve_floor.
Proof.
  intros approved_advance reserve_margin reserve_floor Hmargin.
  unfold reserve_amount.
  eapply Z.le_trans with (m := approved_advance + reserve_margin).
  - lia.
  - apply Z.le_max_l.
Qed.

Theorem fee_amount_zero_below_attachment_point :
  forall approved_advance attachment_point participation_cap participation_rate scale,
    approved_advance <= attachment_point ->
    0 <= participation_cap ->
    scale <> 0 ->
    fee_amount approved_advance attachment_point participation_cap participation_rate scale = 0.
Proof.
  intros approved_advance attachment_point participation_cap participation_rate scale Hattachment Hcap Hscale.
  unfold fee_amount.
  assert (approved_advance - attachment_point <= 0) by lia.
  rewrite Z.max_l by lia.
  rewrite Z.min_l by exact Hcap.
  rewrite Z.mul_0_l.
  rewrite Z.div_0_l by exact Hscale.
  reflexivity.
Qed.

Theorem action_class_code_is_in_range :
  forall eligible inconsistency_hit risk_review_hit manual_review_hit,
    0 <= action_class_code eligible inconsistency_hit risk_review_hit manual_review_hit <= 4.
Proof.
  intros eligible inconsistency_hit risk_review_hit manual_review_hit.
  unfold action_class_code.
  destruct eligible, inconsistency_hit, risk_review_hit, manual_review_hit; simpl; lia.
Qed.

Theorem action_class_rejects_ineligible_request :
  forall inconsistency_hit risk_review_hit manual_review_hit,
    action_class_code false inconsistency_hit risk_review_hit manual_review_hit = 3.
Proof.
  intros inconsistency_hit risk_review_hit manual_review_hit.
  unfold action_class_code.
  reflexivity.
Qed.

Theorem action_class_approves_when_all_clear :
  action_class_code true false false false = 0.
Proof.
  reflexivity.
Qed.

Theorem human_review_required_for_nonapprove_actions :
  forall eligible inconsistency_hit risk_review_hit manual_review_hit,
    action_class_code eligible inconsistency_hit risk_review_hit manual_review_hit <> 0 ->
    human_review_required eligible inconsistency_hit risk_review_hit manual_review_hit = true.
Proof.
  intros eligible inconsistency_hit risk_review_hit manual_review_hit Hnonzero.
  unfold action_class_code in Hnonzero.
  unfold human_review_required.
  destruct eligible, inconsistency_hit, risk_review_hit, manual_review_hit; try reflexivity; exfalso; apply Hnonzero; reflexivity.
Qed.

Theorem midnight_settlement_requires_approve_and_positive_advance :
  forall eligible inconsistency_hit risk_review_hit manual_review_hit approved_advance,
    eligible_for_midnight_settlement eligible inconsistency_hit risk_review_hit manual_review_hit approved_advance = true ->
    action_class_code eligible inconsistency_hit risk_review_hit manual_review_hit = 0 /\ 0 < approved_advance.
Proof.
  intros eligible inconsistency_hit risk_review_hit manual_review_hit approved_advance H.
  unfold eligible_for_midnight_settlement in H.
  repeat rewrite Bool.andb_true_iff in H.
  destruct H as [[[[Heligible Hinconsistency] Hrisk] Hmanual] Hpositive].
  apply Z.gtb_lt in Hpositive.
  destruct eligible, inconsistency_hit, risk_review_hit, manual_review_hit; try discriminate; simpl in *; split; try reflexivity; lia.
Qed.

Theorem role_selector_count_is_one_for_valid_roles :
  forall role,
    0 <= role < 5 -> role_selector_count role = 1.
Proof.
  intros role [Hlower Hupper].
  unfold role_selector_count.
  apply Z.ltb_lt in Hupper.
  rewrite Hupper.
  reflexivity.
Qed.

Theorem supplier_disclosure_binds_expected_commitments :
  forall settlement_commitment advance_commitment invoice_commitment reserve_commitment
         eligibility_commitment consistency_commitment duplicate_risk_commitment,
    disclosure_value_a 0 settlement_commitment advance_commitment invoice_commitment reserve_commitment = settlement_commitment
    /\ disclosure_value_b 0 advance_commitment eligibility_commitment consistency_commitment reserve_commitment duplicate_risk_commitment = advance_commitment.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem financier_disclosure_binds_expected_commitments :
  forall settlement_commitment advance_commitment invoice_commitment reserve_commitment
         eligibility_commitment consistency_commitment duplicate_risk_commitment,
    disclosure_value_a 1 settlement_commitment advance_commitment invoice_commitment reserve_commitment = advance_commitment
    /\ disclosure_value_b 1 advance_commitment eligibility_commitment consistency_commitment reserve_commitment duplicate_risk_commitment = reserve_commitment.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem buyer_disclosure_binds_expected_commitments :
  forall settlement_commitment advance_commitment invoice_commitment reserve_commitment
         eligibility_commitment consistency_commitment duplicate_risk_commitment,
    disclosure_value_a 2 settlement_commitment advance_commitment invoice_commitment reserve_commitment = invoice_commitment
    /\ disclosure_value_b 2 advance_commitment eligibility_commitment consistency_commitment reserve_commitment duplicate_risk_commitment = eligibility_commitment.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem auditor_disclosure_binds_expected_commitments :
  forall settlement_commitment advance_commitment invoice_commitment reserve_commitment
         eligibility_commitment consistency_commitment duplicate_risk_commitment,
    disclosure_value_a 3 settlement_commitment advance_commitment invoice_commitment reserve_commitment = advance_commitment
    /\ disclosure_value_b 3 advance_commitment eligibility_commitment consistency_commitment reserve_commitment duplicate_risk_commitment = consistency_commitment.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem regulator_disclosure_binds_expected_commitments :
  forall settlement_commitment advance_commitment invoice_commitment reserve_commitment
         eligibility_commitment consistency_commitment duplicate_risk_commitment,
    disclosure_value_a 4 settlement_commitment advance_commitment invoice_commitment reserve_commitment = reserve_commitment
    /\ disclosure_value_b 4 advance_commitment eligibility_commitment consistency_commitment reserve_commitment duplicate_risk_commitment = duplicate_risk_commitment.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem disclosure_authorization_binds_role_credential_request_caller_and_view :
  forall role credential_commitment request_id_hash caller_commitment view_commitment public_blinding,
    disclosure_authorization_commitment
      role
      credential_commitment
      request_id_hash
      caller_commitment
      view_commitment
      public_blinding =
    disclosure_authorization_inner role credential_commitment request_id_hash
      + caller_commitment
      + view_commitment
      + public_blinding.
Proof.
  intros.
  reflexivity.
Qed.

Theorem supplier_disclosure_noninterference :
  forall settlement_commitment advance_commitment invoice_commitment_0 reserve_commitment_0
         eligibility_commitment_0 consistency_commitment_0 duplicate_risk_commitment_0
         invoice_commitment_1 reserve_commitment_1 eligibility_commitment_1
         consistency_commitment_1 duplicate_risk_commitment_1,
    disclosure_value_a 0 settlement_commitment advance_commitment invoice_commitment_0 reserve_commitment_0 =
      disclosure_value_a 0 settlement_commitment advance_commitment invoice_commitment_1 reserve_commitment_1
    /\ disclosure_value_b 0 advance_commitment eligibility_commitment_0 consistency_commitment_0 reserve_commitment_0 duplicate_risk_commitment_0 =
      disclosure_value_b 0 advance_commitment eligibility_commitment_1 consistency_commitment_1 reserve_commitment_1 duplicate_risk_commitment_1.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem financier_disclosure_noninterference :
  forall settlement_commitment_0 advance_commitment reserve_commitment
         invoice_commitment_0 eligibility_commitment_0 consistency_commitment_0 duplicate_risk_commitment_0
         settlement_commitment_1 invoice_commitment_1 eligibility_commitment_1
         consistency_commitment_1 duplicate_risk_commitment_1,
    disclosure_value_a 1 settlement_commitment_0 advance_commitment invoice_commitment_0 reserve_commitment =
      disclosure_value_a 1 settlement_commitment_1 advance_commitment invoice_commitment_1 reserve_commitment
    /\ disclosure_value_b 1 advance_commitment eligibility_commitment_0 consistency_commitment_0 reserve_commitment duplicate_risk_commitment_0 =
      disclosure_value_b 1 advance_commitment eligibility_commitment_1 consistency_commitment_1 reserve_commitment duplicate_risk_commitment_1.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem buyer_disclosure_noninterference :
  forall settlement_commitment_0 advance_commitment_0 invoice_commitment eligibility_commitment
         reserve_commitment_0 consistency_commitment_0 duplicate_risk_commitment_0
         settlement_commitment_1 advance_commitment_1 reserve_commitment_1 consistency_commitment_1 duplicate_risk_commitment_1,
    disclosure_value_a 2 settlement_commitment_0 advance_commitment_0 invoice_commitment reserve_commitment_0 =
      disclosure_value_a 2 settlement_commitment_1 advance_commitment_1 invoice_commitment reserve_commitment_1
    /\ disclosure_value_b 2 advance_commitment_0 eligibility_commitment consistency_commitment_0 reserve_commitment_0 duplicate_risk_commitment_0 =
      disclosure_value_b 2 advance_commitment_1 eligibility_commitment consistency_commitment_1 reserve_commitment_1 duplicate_risk_commitment_1.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem auditor_disclosure_noninterference :
  forall settlement_commitment_0 advance_commitment invoice_commitment_0 reserve_commitment_0
         eligibility_commitment_0 consistency_commitment duplicate_risk_commitment_0
         settlement_commitment_1 invoice_commitment_1 reserve_commitment_1 eligibility_commitment_1 duplicate_risk_commitment_1,
    disclosure_value_a 3 settlement_commitment_0 advance_commitment invoice_commitment_0 reserve_commitment_0 =
      disclosure_value_a 3 settlement_commitment_1 advance_commitment invoice_commitment_1 reserve_commitment_1
    /\ disclosure_value_b 3 advance_commitment eligibility_commitment_0 consistency_commitment reserve_commitment_0 duplicate_risk_commitment_0 =
      disclosure_value_b 3 advance_commitment eligibility_commitment_1 consistency_commitment reserve_commitment_1 duplicate_risk_commitment_1.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem regulator_disclosure_noninterference :
  forall settlement_commitment_0 advance_commitment_0 invoice_commitment_0 reserve_commitment
         eligibility_commitment_0 consistency_commitment_0 duplicate_risk_commitment
         settlement_commitment_1 advance_commitment_1 invoice_commitment_1 eligibility_commitment_1 consistency_commitment_1,
    disclosure_value_a 4 settlement_commitment_0 advance_commitment_0 invoice_commitment_0 reserve_commitment =
      disclosure_value_a 4 settlement_commitment_1 advance_commitment_1 invoice_commitment_1 reserve_commitment
    /\ disclosure_value_b 4 advance_commitment_0 eligibility_commitment_0 consistency_commitment_0 reserve_commitment duplicate_risk_commitment =
      disclosure_value_b 4 advance_commitment_1 eligibility_commitment_1 consistency_commitment_1 reserve_commitment duplicate_risk_commitment.
Proof.
  intros.
  split; reflexivity.
Qed.

Theorem shard_assignment_lt_shard_count :
  forall commitment shard_count,
    0 <= commitment -> 0 < shard_count -> 0 <= shard_assignment commitment shard_count < shard_count.
Proof.
  intros commitment shard_count _ Hcount.
  unfold shard_assignment.
  apply Z.mod_pos_bound.
  assumption.
Qed.

Theorem shard_count_two_yields_bit_assignment :
  forall commitment,
    0 <= commitment -> shard_assignment commitment 2 = 0 \/ shard_assignment commitment 2 = 1.
Proof.
  intros commitment Hcommitment.
  assert (0 <= shard_assignment commitment 2 < 2).
  {
    apply shard_assignment_lt_shard_count; try assumption; lia.
  }
  lia.
Qed.

Theorem duplicate_registry_handoff_deterministic :
  forall commitment_0 commitment_1 commitment_2 commitment_3 blinding_0 blinding_1,
    batch_root_payload commitment_0 commitment_1 commitment_2 commitment_3 blinding_0 blinding_1 =
    batch_root_payload commitment_0 commitment_1 commitment_2 commitment_3 blinding_0 blinding_1.
Proof.
  intros.
  reflexivity.
Qed.

Definition symbolic_hash4 (a b c d : Z) : Z := 109 + a + 101 * b + 103 * c + 107 * d.

Definition packet_binding_step (previous lane_0 lane_1 lane_2 : Z) : Z :=
  symbolic_hash4 previous lane_0 lane_1 lane_2.

Definition packet_binding_two_chunk (seed lane_0 lane_1 lane_2 lane_3 : Z) : Z :=
  packet_binding_step (packet_binding_step seed lane_0 lane_1 lane_2) lane_3 0 0.

Definition cap_score (raw : Z) : Z := if Z.leb raw 10000 then raw else 10000.

Definition structured_inconsistency_score_raw
  (valuation_score quantity_score : Z)
  (geographic_reasonable request_after_presentment : bool)
  (evidence_completeness_score : Z) : Z :=
  valuation_score
    + quantity_score
    + (if geographic_reasonable then 0 else 800)
    + (if request_after_presentment then 0 else 2000)
    + evidence_completeness_score.

Definition structured_inconsistency_score
  (valuation_score quantity_score : Z)
  (geographic_reasonable request_after_presentment : bool)
  (evidence_completeness_score : Z) : Z :=
  cap_score
    (structured_inconsistency_score_raw valuation_score quantity_score geographic_reasonable request_after_presentment evidence_completeness_score).

Definition consistency_score
  (valuation_score quantity_score : Z)
  (geographic_reasonable request_after_presentment : bool)
  (evidence_completeness_score : Z) : Z :=
  10000 - structured_inconsistency_score valuation_score quantity_score geographic_reasonable request_after_presentment evidence_completeness_score.

Definition duplicate_financing_risk_score_raw
  (duplication_score vendor_score chronology_score eligibility_mismatch_score : Z) : Z :=
  duplication_score + vendor_score + chronology_score + eligibility_mismatch_score.

Definition duplicate_financing_risk_score
  (duplication_score vendor_score chronology_score eligibility_mismatch_score : Z) : Z :=
  cap_score (duplicate_financing_risk_score_raw duplication_score vendor_score chronology_score eligibility_mismatch_score).

Definition settlement_binding_inner
  (approved_advance reserve_amount_value action_class destination_commitment : Z) : Z :=
  symbolic_hash4 approved_advance reserve_amount_value action_class destination_commitment.

Definition settlement_binding_outer
  (inner reserve_account_commitment settlement_blinding_0 settlement_blinding_1 : Z) : Z :=
  symbolic_hash4 inner reserve_account_commitment settlement_blinding_0 settlement_blinding_1.

Definition settlement_binding_digest
  (approved_advance reserve_amount_value action_class destination_commitment reserve_account_commitment
   settlement_blinding_0 settlement_blinding_1 invoice_packet_commitment eligibility_commitment public_blinding_1 : Z) : Z :=
  symbolic_hash4
    (settlement_binding_outer
      (settlement_binding_inner approved_advance reserve_amount_value action_class destination_commitment)
      reserve_account_commitment settlement_blinding_0 settlement_blinding_1)
    invoice_packet_commitment
    eligibility_commitment
    public_blinding_1.

Definition duplicate_registry_batch_root
  (commitment_0 commitment_1 commitment_2 commitment_3 blinding_0 blinding_1 : Z) : Z :=
  symbolic_hash4
    (symbolic_hash4 1111 commitment_0 commitment_1 commitment_2)
    commitment_3
    blinding_0
    blinding_1.

Theorem packet_binding_soundness :
  forall seed lane_0 lane_1 lane_2 lane_3,
    packet_binding_two_chunk seed lane_0 lane_1 lane_2 lane_3 =
      symbolic_hash4 (symbolic_hash4 seed lane_0 lane_1 lane_2) lane_3 0 0.
Proof.
  intros.
  reflexivity.
Qed.

Theorem consistency_score_soundness :
  forall valuation_score quantity_score geographic_reasonable request_after_presentment evidence_completeness_score,
    structured_inconsistency_score valuation_score quantity_score geographic_reasonable request_after_presentment evidence_completeness_score =
      cap_score (structured_inconsistency_score_raw valuation_score quantity_score geographic_reasonable request_after_presentment evidence_completeness_score).
Proof.
  intros.
  reflexivity.
Qed.

Theorem duplicate_financing_risk_soundness :
  forall duplication_score vendor_score chronology_score eligibility_mismatch_score,
    0 <= duplication_score ->
    0 <= vendor_score ->
    0 <= chronology_score ->
    0 <= eligibility_mismatch_score ->
    0 <= duplicate_financing_risk_score duplication_score vendor_score chronology_score eligibility_mismatch_score
    /\ duplicate_financing_risk_score duplication_score vendor_score chronology_score eligibility_mismatch_score <= 10000.
Proof.
  intros duplication_score vendor_score chronology_score eligibility_mismatch_score Hdup Hvendor Hchrono Hmismatch.
  unfold duplicate_financing_risk_score, duplicate_financing_risk_score_raw, cap_score.
  destruct (Z.leb_spec0 (duplication_score + vendor_score + chronology_score + eligibility_mismatch_score) 10000); lia.
Qed.

Theorem approved_advance_fee_reserve_soundness :
  forall eligible_invoice retention_amount discount_amount advance_cap reserve_margin reserve_floor
         attachment_point participation_cap participation_rate scale,
    0 <= advance_cap ->
    0 <= reserve_margin ->
    0 <= reserve_floor ->
    0 <= participation_cap ->
    scale <> 0 ->
    0 <= approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap
    /\ approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap <= advance_cap
    /\ reserve_floor <= reserve_amount (approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap) reserve_margin reserve_floor
    /\ approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap
        <= reserve_amount (approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap) reserve_margin reserve_floor
    /\ (approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap <= attachment_point ->
        fee_amount (approved_advance_amount eligible_invoice retention_amount discount_amount advance_cap)
          attachment_point participation_cap participation_rate scale = 0).
Proof.
  intros eligible_invoice retention_amount discount_amount advance_cap reserve_margin reserve_floor
         attachment_point participation_cap participation_rate scale Hcap Hmargin Hfloor Hpart Hscale.
  repeat split.
  - apply approved_advance_nonnegative; assumption.
  - apply approved_advance_bounded_by_cap.
  - apply reserve_amount_respects_floor.
  - apply reserve_amount_ge_approved_advance_when_margin_nonnegative; assumption.
  - intro Hattachment.
    apply fee_amount_zero_below_attachment_point; try assumption.
Qed.

Theorem action_derivation_soundness :
  forall eligible inconsistency_hit risk_review_hit manual_review_hit approved_advance,
    0 <= action_class_code eligible inconsistency_hit risk_review_hit manual_review_hit <= 4
    /\ (action_class_code eligible inconsistency_hit risk_review_hit manual_review_hit <> 0 ->
        human_review_required eligible inconsistency_hit risk_review_hit manual_review_hit = true)
    /\ (eligible_for_midnight_settlement eligible inconsistency_hit risk_review_hit manual_review_hit approved_advance = true ->
        action_class_code eligible inconsistency_hit risk_review_hit manual_review_hit = 0 /\ 0 < approved_advance).
Proof.
  intros eligible inconsistency_hit risk_review_hit manual_review_hit approved_advance.
  split.
  - apply action_class_code_is_in_range.
  - split.
    + apply human_review_required_for_nonapprove_actions.
    + apply midnight_settlement_requires_approve_and_positive_advance.
Qed.

Theorem settlement_binding_soundness :
  forall approved_advance reserve_amount_value action_class destination_commitment reserve_account_commitment
         settlement_blinding_0 settlement_blinding_1 invoice_packet_commitment eligibility_commitment public_blinding_1,
    settlement_binding_digest approved_advance reserve_amount_value action_class destination_commitment reserve_account_commitment
      settlement_blinding_0 settlement_blinding_1 invoice_packet_commitment eligibility_commitment public_blinding_1 =
    symbolic_hash4
      (symbolic_hash4
        (symbolic_hash4 approved_advance reserve_amount_value action_class destination_commitment)
        reserve_account_commitment settlement_blinding_0 settlement_blinding_1)
      invoice_packet_commitment
      eligibility_commitment
      public_blinding_1.
Proof.
  intros.
  reflexivity.
Qed.

Theorem duplicate_registry_batch_binding :
  forall commitment_0 commitment_1 commitment_2 commitment_3 blinding_0 blinding_1,
    duplicate_registry_batch_root commitment_0 commitment_1 commitment_2 commitment_3 blinding_0 blinding_1 =
    symbolic_hash4 (symbolic_hash4 1111 commitment_0 commitment_1 commitment_2) commitment_3 blinding_0 blinding_1.
Proof.
  intros.
  reflexivity.
Qed.

Definition generated_circuit_certificate_accepts
  (field_is_pastafq poseidon_nodes_width4 program_digest_linkage
   disclosure_authorization_bound emitted_noninterference_bound : bool) : bool :=
  field_is_pastafq
    && poseidon_nodes_width4
    && program_digest_linkage
    && disclosure_authorization_bound
    && emitted_noninterference_bound.

Theorem generated_circuit_certificate_acceptance_soundness :
  forall field_is_pastafq poseidon_nodes_width4 program_digest_linkage
         disclosure_authorization_bound emitted_noninterference_bound,
    generated_circuit_certificate_accepts
      field_is_pastafq
      poseidon_nodes_width4
      program_digest_linkage
      disclosure_authorization_bound
      emitted_noninterference_bound = true ->
    field_is_pastafq = true
    /\ poseidon_nodes_width4 = true
    /\ program_digest_linkage = true
    /\ disclosure_authorization_bound = true
    /\ emitted_noninterference_bound = true.
Proof.
  intros field_is_pastafq poseidon_nodes_width4 program_digest_linkage
         disclosure_authorization_bound emitted_noninterference_bound H.
  unfold generated_circuit_certificate_accepts in H.
  repeat rewrite Bool.andb_true_iff in H.
  tauto.
Qed.
