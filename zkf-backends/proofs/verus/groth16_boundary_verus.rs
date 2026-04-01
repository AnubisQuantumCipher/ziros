// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

use vstd::prelude::*;
use vstd::seq::*;

verus! {

pub struct MatrixTermModel {
    pub variable: int,
    pub coeff_tag: int,
}

pub struct MatrixRowModel {
    pub a: Seq<MatrixTermModel>,
    pub b: Seq<MatrixTermModel>,
    pub c: Seq<MatrixTermModel>,
}

pub struct ConstraintMatricesModel {
    pub num_instance_variables: nat,
    pub num_witness_variables: nat,
    pub rows: Seq<MatrixRowModel>,
}

pub struct Groth16OutlinedLcModel {
    pub num_instance_variables: nat,
    pub num_witness_variables: nat,
    pub expanded_rows: Seq<MatrixRowModel>,
}

pub open spec fn matrix_term_valid(term: MatrixTermModel) -> bool {
    term.variable >= 0
}

pub open spec fn matrix_row_valid(row: MatrixRowModel) -> bool {
    &&& forall|i: int| 0 <= i < row.a.len() ==> matrix_term_valid(row.a[i])
    &&& forall|i: int| 0 <= i < row.b.len() ==> matrix_term_valid(row.b[i])
    &&& forall|i: int| 0 <= i < row.c.len() ==> matrix_term_valid(row.c[i])
}

pub open spec fn groth16_matrix_model_valid(model: Groth16OutlinedLcModel) -> bool {
    forall|i: int| 0 <= i < model.expanded_rows.len() ==> matrix_row_valid(model.expanded_rows[i])
}

pub open spec fn materialized_matrices(model: Groth16OutlinedLcModel) -> ConstraintMatricesModel {
    ConstraintMatricesModel {
        num_instance_variables: model.num_instance_variables,
        num_witness_variables: model.num_witness_variables,
        rows: model.expanded_rows,
    }
}

pub open spec fn streaming_matrices(model: Groth16OutlinedLcModel) -> ConstraintMatricesModel {
    ConstraintMatricesModel {
        num_instance_variables: model.num_instance_variables,
        num_witness_variables: model.num_witness_variables,
        rows: model.expanded_rows,
    }
}

pub open spec fn draining_matrices(model: Groth16OutlinedLcModel) -> ConstraintMatricesModel {
    ConstraintMatricesModel {
        num_instance_variables: model.num_instance_variables,
        num_witness_variables: model.num_witness_variables,
        rows: model.expanded_rows,
    }
}

pub proof fn groth16_matrix_equivalence_surface_ok(model: Groth16OutlinedLcModel)
    requires
        groth16_matrix_model_valid(model),
    ensures
        materialized_matrices(model) == streaming_matrices(model),
        materialized_matrices(model) == draining_matrices(model),
        streaming_matrices(model) == draining_matrices(model),
{
}

pub enum Groth16SynthesisModeModel {
    Setup,
    Prove { construct_matrices: bool },
}

pub open spec fn should_debug_check_constraint_system_mode_model(
    debug_build: bool,
    construct_matrices: bool,
    env_forced: bool,
    num_constraints: nat,
) -> bool {
    &&& debug_build
    &&& construct_matrices
    &&& (env_forced || num_constraints <= 50_000)
}

pub open spec fn matrix_free_satisfaction_check_rejected(mode: Groth16SynthesisModeModel) -> bool {
    match mode {
        Groth16SynthesisModeModel::Setup => true,
        Groth16SynthesisModeModel::Prove { construct_matrices } => !construct_matrices,
    }
}

pub proof fn groth16_cached_shape_matrix_free_fail_closed_ok(
    debug_build: bool,
    env_forced: bool,
    num_constraints: nat,
)
    ensures
        !should_debug_check_constraint_system_mode_model(
            debug_build,
            false,
            env_forced,
            num_constraints,
        ),
        matrix_free_satisfaction_check_rejected(Groth16SynthesisModeModel::Setup),
        matrix_free_satisfaction_check_rejected(
            Groth16SynthesisModeModel::Prove { construct_matrices: false },
        ),
        !matrix_free_satisfaction_check_rejected(
            Groth16SynthesisModeModel::Prove { construct_matrices: true },
        ),
{
}

pub open spec fn groth16_security_covered_setup(
    imported_setup: bool,
    streamed_local_ceremony: bool,
    auto_ceremony: bool,
    deterministic_dev_setup: bool,
    allow_dev_override: bool,
) -> bool {
    imported_setup
        || streamed_local_ceremony
        || auto_ceremony
        || (deterministic_dev_setup && allow_dev_override)
}

pub proof fn groth16_deterministic_production_gate_strict_ok(
    imported_setup: bool,
    streamed_local_ceremony: bool,
    auto_ceremony: bool,
    deterministic_dev_setup: bool,
    allow_dev_override: bool,
)
    ensures
        groth16_security_covered_setup(
            imported_setup,
            streamed_local_ceremony,
            auto_ceremony,
            deterministic_dev_setup,
            allow_dev_override,
        ) == (
            imported_setup
                || streamed_local_ceremony
                || auto_ceremony
                || (deterministic_dev_setup && allow_dev_override)
        ),
        deterministic_dev_setup && !allow_dev_override ==> (
            groth16_security_covered_setup(
                imported_setup,
                streamed_local_ceremony,
                auto_ceremony,
                deterministic_dev_setup,
                allow_dev_override,
            ) == (imported_setup || streamed_local_ceremony || auto_ceremony)
        ),
        deterministic_dev_setup && !allow_dev_override && !imported_setup
            && !streamed_local_ceremony && !auto_ceremony ==> !groth16_security_covered_setup(
                imported_setup,
                streamed_local_ceremony,
                auto_ceremony,
                deterministic_dev_setup,
                allow_dev_override,
            ),
{
}

pub struct Halo2IpaBindingModel {
    pub proof_count: nat,
    pub proof_hash_count: nat,
    pub bound_g_point_count: nat,
    pub malformed_g_point_count: nat,
}

pub open spec fn halo2_ipa_binding_accepts(model: Halo2IpaBindingModel) -> bool {
    &&& model.proof_count > 0
    &&& model.proof_hash_count == model.proof_count
    &&& model.bound_g_point_count == model.proof_count
    &&& model.malformed_g_point_count == 0
}

pub proof fn halo2_ipa_accumulation_binding_surface_ok(model: Halo2IpaBindingModel)
    ensures
        halo2_ipa_binding_accepts(model) <==> (
            model.proof_count > 0
                && model.proof_hash_count == model.proof_count
                && model.bound_g_point_count == model.proof_count
                && model.malformed_g_point_count == 0
        ),
{
}

} // verus!
