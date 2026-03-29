Require Import ZArith Lia.

Open Scope Z_scope.

Definition orbital_body_count : Z := 5.
Definition orbital_step_count : Z := 1000.
Definition orbital_private_input_count : Z := 35.
Definition orbital_public_output_count : Z := 5.
Definition orbital_pair_count : Z :=
  orbital_body_count * (orbital_body_count - 1) / 2.

Definition pairwise_delta (ri rj : Z) : Z := rj - ri.

Definition velocity_verlet_position_next (x v a : Z) : Z :=
  x + v + a / 2.

Definition velocity_verlet_velocity_next (v a_now a_next : Z) : Z :=
  v + (a_now + a_next) / 2.

Definition orbital_commitment_payload (x y z tag : Z) : Z * Z * Z * Z :=
  (x, y, z, tag).

Lemma orbital_body_count_exact :
  orbital_body_count = 5.
Proof. reflexivity. Qed.

Lemma orbital_step_count_exact :
  orbital_step_count = 1000.
Proof. reflexivity. Qed.

Lemma orbital_private_input_count_exact :
  orbital_private_input_count = 35.
Proof. reflexivity. Qed.

Lemma orbital_public_output_count_exact :
  orbital_public_output_count = 5.
Proof. reflexivity. Qed.

Lemma orbital_pair_count_exact :
  orbital_pair_count = 10.
Proof. reflexivity. Qed.

Lemma orbital_pairwise_delta_zero_self :
  forall r, pairwise_delta r r = 0.
Proof.
  intros r.
  unfold pairwise_delta.
  lia.
Qed.

Lemma orbital_pairwise_delta_antisymmetric :
  forall ri rj, pairwise_delta ri rj + pairwise_delta rj ri = 0.
Proof.
  intros ri rj.
  unfold pairwise_delta.
  lia.
Qed.

Lemma velocity_verlet_position_next_deterministic :
  forall x v a,
    velocity_verlet_position_next x v a =
    velocity_verlet_position_next x v a.
Proof.
  intros; reflexivity.
Qed.

Lemma velocity_verlet_velocity_next_deterministic :
  forall v a_now a_next,
    velocity_verlet_velocity_next v a_now a_next =
    velocity_verlet_velocity_next v a_now a_next.
Proof.
  intros; reflexivity.
Qed.

Lemma orbital_commitment_payload_domain_separated :
  forall x y z tag1 tag2,
    tag1 <> tag2 ->
    orbital_commitment_payload x y z tag1 <>
    orbital_commitment_payload x y z tag2.
Proof.
  intros x y z tag1 tag2 Hneq Heq.
  inversion Heq.
  apply Hneq.
  assumption.
Qed.
