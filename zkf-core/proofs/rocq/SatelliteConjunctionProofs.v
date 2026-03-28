From Stdlib Require Import ZArith Lia.

Open Scope Z_scope.

Definition satellite_spacecraft_count : Z := 2.
Definition satellite_step_count : Z := 1440.
Definition satellite_private_input_count : Z := 22.
Definition satellite_public_input_count : Z := 2.
Definition satellite_public_output_count : Z := 5.
Definition satellite_pair_count : Z :=
  satellite_spacecraft_count * (satellite_spacecraft_count - 1) / 2.

Definition satellite_final_state_payload (px py pz vx vy vz tag step : Z) :
  Z * Z * Z * Z * Z * Z * Z * Z :=
  (px, py, pz, vx, vy, vz, tag, step).

Definition satellite_plan_leaf_payload (dvx dvy dvz burn_step : Z) : Z * Z * Z * Z :=
  (dvx, dvy, dvz, burn_step).

Definition burn_selector (claimed_step actual_step : Z) : Z :=
  if Z.eq_dec claimed_step actual_step then 1 else 0.

Definition propagated_velocity (v dv selector : Z) : Z :=
  v + selector * dv.

Definition propagated_position (x v_next a : Z) : Z :=
  x + v_next + a / 2.

Definition propagated_velocity_next (v_next a_now a_next : Z) : Z :=
  v_next + (a_now + a_next) / 2.

Definition running_min (previous current : Z) : Z := Z.min previous current.

Definition threshold_slack (minimum threshold : Z) : Z :=
  minimum - threshold.

Definition budget_slack (budget total : Z) : Z :=
  budget - total.

Lemma satellite_spacecraft_count_exact :
  satellite_spacecraft_count = 2.
Proof. reflexivity. Qed.

Lemma satellite_step_count_exact :
  satellite_step_count = 1440.
Proof. reflexivity. Qed.

Lemma satellite_private_input_count_exact :
  satellite_private_input_count = 22.
Proof. reflexivity. Qed.

Lemma satellite_public_input_count_exact :
  satellite_public_input_count = 2.
Proof. reflexivity. Qed.

Lemma satellite_public_output_count_exact :
  satellite_public_output_count = 5.
Proof. reflexivity. Qed.

Lemma satellite_pair_count_exact :
  satellite_pair_count = 1.
Proof. reflexivity. Qed.

Lemma satellite_final_state_payload_domain_separated :
  forall px py pz vx vy vz tag1 tag2 step,
    tag1 <> tag2 ->
    satellite_final_state_payload px py pz vx vy vz tag1 step <>
    satellite_final_state_payload px py pz vx vy vz tag2 step.
Proof.
  intros px py pz vx vy vz tag1 tag2 step Hneq Heq.
  inversion Heq.
  apply Hneq.
  assumption.
Qed.

Lemma satellite_plan_leaf_payload_domain_separated :
  forall dvx dvy dvz burn1 burn2,
    burn1 <> burn2 ->
    satellite_plan_leaf_payload dvx dvy dvz burn1 <>
    satellite_plan_leaf_payload dvx dvy dvz burn2.
Proof.
  intros dvx dvy dvz burn1 burn2 Hneq Heq.
  inversion Heq.
  apply Hneq.
  assumption.
Qed.

Lemma burn_selector_hit :
  forall claimed_step,
    burn_selector claimed_step claimed_step = 1.
Proof.
  intros claimed_step.
  unfold burn_selector.
  destruct (Z.eq_dec claimed_step claimed_step); congruence.
Qed.

Lemma burn_selector_miss :
  forall claimed_step actual_step,
    claimed_step <> actual_step ->
    burn_selector claimed_step actual_step = 0.
Proof.
  intros claimed_step actual_step Hneq.
  unfold burn_selector.
  destruct (Z.eq_dec claimed_step actual_step); congruence.
Qed.

Lemma burn_selector_boolean :
  forall claimed_step actual_step,
    burn_selector claimed_step actual_step *
    (1 - burn_selector claimed_step actual_step) = 0.
Proof.
  intros claimed_step actual_step.
  unfold burn_selector.
  destruct (Z.eq_dec claimed_step actual_step); lia.
Qed.

Lemma propagated_velocity_equation :
  forall v dv selector,
    propagated_velocity v dv selector = v + selector * dv.
Proof.
  intros; reflexivity.
Qed.

Lemma propagated_position_equation :
  forall x v_next a,
    propagated_position x v_next a = x + v_next + a / 2.
Proof.
  intros; reflexivity.
Qed.

Lemma propagated_velocity_next_equation :
  forall v_next a_now a_next,
    propagated_velocity_next v_next a_now a_next =
    v_next + (a_now + a_next) / 2.
Proof.
  intros; reflexivity.
Qed.

Lemma running_min_prev_slack :
  forall previous current,
    running_min previous current +
    threshold_slack previous (running_min previous current) = previous.
Proof.
  intros previous current.
  unfold running_min, threshold_slack.
  destruct (Z_le_gt_dec previous current); lia.
Qed.

Lemma running_min_curr_slack :
  forall previous current,
    running_min previous current +
    threshold_slack current (running_min previous current) = current.
Proof.
  intros previous current.
  unfold running_min, threshold_slack.
  destruct (Z_le_gt_dec previous current); lia.
Qed.

Lemma running_min_lower_bound_left :
  forall previous current,
    running_min previous current <= previous.
Proof.
  intros previous current.
  unfold running_min.
  destruct (Z_le_gt_dec previous current); lia.
Qed.

Lemma running_min_lower_bound_right :
  forall previous current,
    running_min previous current <= current.
Proof.
  intros previous current.
  unfold running_min.
  destruct (Z_le_gt_dec previous current); lia.
Qed.

Lemma threshold_slack_reconstruction :
  forall minimum threshold,
    threshold_slack minimum threshold + threshold = minimum.
Proof.
  intros minimum threshold.
  unfold threshold_slack.
  lia.
Qed.

Lemma budget_slack_reconstruction :
  forall budget total,
    budget_slack budget total + total = budget.
Proof.
  intros budget total.
  unfold budget_slack.
  lia.
Qed.

Lemma threshold_slack_nonnegative :
  forall minimum threshold,
    threshold <= minimum ->
    0 <= threshold_slack minimum threshold.
Proof.
  intros minimum threshold Hle.
  unfold threshold_slack.
  lia.
Qed.

Lemma budget_slack_nonnegative :
  forall budget total,
    total <= budget ->
    0 <= budget_slack budget total.
Proof.
  intros budget total Hle.
  unfold budget_slack.
  lia.
Qed.
