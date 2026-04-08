Require Import ZArith Lia Bool.

Open Scope Z_scope.

Definition turbine_default_step_count : Z := 500.
Definition turbine_control_sections : Z := 3.
Definition turbine_geometry_stations : Z := 8.

Definition thermal_strain_relation
  (alpha metal_temp radius strain : Z) : Prop :=
  strain = alpha * (metal_temp + radius).

Definition equivalent_stress_relation
  (sigma_cf sigma_pr sigma_th sigma_eq : Z) : Prop :=
  sigma_eq = sigma_cf + sigma_pr + sigma_th.

Definition damage_update_relation
  (previous fatigue creep next : Z) : Prop :=
  next = previous + fatigue + creep.

Definition crack_update_relation
  (previous increment next : Z) : Prop :=
  next = previous + increment.

Definition safe_decision_relation
  (damage crack min_margin damage_limit crack_limit reserve_margin : Z)
  (operating_bounds_ok safe : bool) : Prop :=
  safe =
    Z.leb damage damage_limit
    && Z.leb crack crack_limit
    && Z.leb reserve_margin min_margin
    && operating_bounds_ok.

Lemma turbine_surface_constants :
  turbine_default_step_count = 500 /\
  turbine_control_sections = 3 /\
  turbine_geometry_stations = 8.
Proof.
  repeat split; reflexivity.
Qed.

Lemma thermal_strain_unique :
  forall alpha metal_temp radius strain_a strain_b,
    thermal_strain_relation alpha metal_temp radius strain_a ->
    thermal_strain_relation alpha metal_temp radius strain_b ->
    strain_a = strain_b.
Proof.
  intros; unfold thermal_strain_relation in *; lia.
Qed.

Lemma equivalent_stress_nonnegative :
  forall sigma_cf sigma_pr sigma_th sigma_eq,
    0 <= sigma_cf ->
    0 <= sigma_pr ->
    0 <= sigma_th ->
    equivalent_stress_relation sigma_cf sigma_pr sigma_th sigma_eq ->
    0 <= sigma_eq.
Proof.
  intros; unfold equivalent_stress_relation in *; lia.
Qed.

Lemma damage_update_monotone :
  forall previous fatigue creep next,
    0 <= fatigue ->
    0 <= creep ->
    damage_update_relation previous fatigue creep next ->
    previous <= next.
Proof.
  intros; unfold damage_update_relation in *; lia.
Qed.

Lemma crack_update_monotone :
  forall previous increment next,
    0 <= increment ->
    crack_update_relation previous increment next ->
    previous <= next.
Proof.
  intros; unfold crack_update_relation in *; lia.
Qed.

Lemma safe_decision_sound :
  forall damage crack min_margin damage_limit crack_limit reserve_margin bounds_ok safe,
    safe_decision_relation
      damage crack min_margin damage_limit crack_limit reserve_margin bounds_ok safe ->
    safe = true ->
    damage <= damage_limit /\
    crack <= crack_limit /\
    reserve_margin <= min_margin /\
    bounds_ok = true.
Proof.
  intros damage crack min_margin damage_limit crack_limit reserve_margin bounds_ok safe
         Hrel Hsafe.
  unfold safe_decision_relation in Hrel.
  rewrite Hrel in Hsafe.
  repeat rewrite andb_true_iff in Hsafe.
  repeat rewrite Z.leb_le in Hsafe.
  tauto.
Qed.
