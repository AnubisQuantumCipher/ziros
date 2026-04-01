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

verus! {

pub enum BackendKindModel {
    ArkworksGroth16,
    Plonky3,
    Nova,
    HyperNova,
    Halo2,
    Halo2Bls12381,
    Sp1,
    RiscZero,
    MidnightCompact,
}

pub enum JobKindModel {
    Prove,
    Fold,
    Wrap,
}

pub enum FieldIdModel {
    Bn254,
    Bls12_381,
    PastaFp,
    PastaFq,
    Goldilocks,
    BabyBear,
    Mersenne31,
}

pub enum BackendRouteModel {
    Auto,
    ExplicitCompat,
}

pub open spec fn max_int(lhs: int, rhs: int) -> int {
    if lhs >= rhs { lhs } else { rhs }
}

pub open spec fn min_int(lhs: int, rhs: int) -> int {
    if lhs <= rhs { lhs } else { rhs }
}

pub open spec fn field_backend_candidates(field: FieldIdModel) -> Seq<BackendKindModel> {
    match field {
        FieldIdModel::Bn254 => seq![
            BackendKindModel::ArkworksGroth16,
            BackendKindModel::Plonky3,
            BackendKindModel::Nova,
            BackendKindModel::HyperNova,
            BackendKindModel::Halo2,
            BackendKindModel::Halo2Bls12381,
            BackendKindModel::Sp1,
            BackendKindModel::RiscZero,
            BackendKindModel::MidnightCompact,
        ],
        FieldIdModel::Bls12_381 => seq![
            BackendKindModel::Halo2Bls12381,
            BackendKindModel::ArkworksGroth16,
            BackendKindModel::Plonky3,
            BackendKindModel::Nova,
            BackendKindModel::HyperNova,
            BackendKindModel::Halo2,
            BackendKindModel::Sp1,
            BackendKindModel::RiscZero,
            BackendKindModel::MidnightCompact,
        ],
        FieldIdModel::PastaFp | FieldIdModel::PastaFq => seq![
            BackendKindModel::Halo2,
            BackendKindModel::ArkworksGroth16,
            BackendKindModel::Plonky3,
            BackendKindModel::Nova,
            BackendKindModel::HyperNova,
            BackendKindModel::Halo2Bls12381,
            BackendKindModel::Sp1,
            BackendKindModel::RiscZero,
            BackendKindModel::MidnightCompact,
        ],
        FieldIdModel::Goldilocks | FieldIdModel::BabyBear | FieldIdModel::Mersenne31 => seq![
            BackendKindModel::Plonky3,
            BackendKindModel::ArkworksGroth16,
            BackendKindModel::Nova,
            BackendKindModel::HyperNova,
            BackendKindModel::Halo2,
            BackendKindModel::Halo2Bls12381,
            BackendKindModel::Sp1,
            BackendKindModel::RiscZero,
            BackendKindModel::MidnightCompact,
        ],
    }
}

pub open spec fn default_backend_candidates(
    has_compiled: bool,
    compiled_backend: BackendKindModel,
    has_program: bool,
    field: FieldIdModel,
) -> Seq<BackendKindModel> {
    if has_compiled {
        seq![compiled_backend]
    } else if has_program {
        field_backend_candidates(field)
    } else {
        seq![BackendKindModel::ArkworksGroth16]
    }
}

pub open spec fn project_requested_backend(
    job_kind: JobKindModel,
    has_wrapper_target: bool,
    wrapper_target: BackendKindModel,
    has_requested_backend: bool,
    requested_backend: BackendKindModel,
    has_compiled: bool,
    compiled_backend: BackendKindModel,
) -> Option<BackendKindModel> {
    match job_kind {
        JobKindModel::Wrap => {
            if has_wrapper_target {
                Some(wrapper_target)
            } else if has_requested_backend {
                Some(requested_backend)
            } else if has_compiled {
                Some(compiled_backend)
            } else {
                None
            }
        }
        JobKindModel::Fold | JobKindModel::Prove => {
            if has_requested_backend {
                Some(requested_backend)
            } else if has_compiled {
                Some(compiled_backend)
            } else {
                None
            }
        }
    }
}

pub open spec fn project_backend_route(
    has_requested_route: bool,
    requested_route: BackendRouteModel,
    has_compiled_route: bool,
    compiled_route: BackendRouteModel,
) -> Option<BackendRouteModel> {
    if has_requested_route {
        Some(requested_route)
    } else if has_compiled_route {
        Some(compiled_route)
    } else {
        None
    }
}

pub open spec fn project_backend_candidates(
    job_kind: JobKindModel,
    has_wrapper_target: bool,
    wrapper_target: BackendKindModel,
    has_requested_candidates: bool,
    requested_candidates: Seq<BackendKindModel>,
    has_compiled: bool,
    compiled_backend: BackendKindModel,
    has_program: bool,
    field: FieldIdModel,
) -> Seq<BackendKindModel> {
    match job_kind {
        JobKindModel::Wrap => {
            if has_wrapper_target {
                seq![wrapper_target]
            } else {
                seq![]
            }
        }
        JobKindModel::Fold | JobKindModel::Prove => {
            if has_requested_candidates {
                requested_candidates
            } else {
                default_backend_candidates(has_compiled, compiled_backend, has_program, field)
            }
        }
    }
}

pub open spec fn scheduled_jobs(total_jobs: int, requested_jobs: int) -> int {
    max_int(min_int(total_jobs, requested_jobs), 1)
}

pub proof fn runtime_api_control_plane_request_projection(
    job_kind: JobKindModel,
    has_wrapper_target: bool,
    wrapper_target: BackendKindModel,
    has_requested_backend: bool,
    requested_backend: BackendKindModel,
    has_compiled: bool,
    compiled_backend: BackendKindModel,
    has_requested_route: bool,
    requested_route: BackendRouteModel,
    has_compiled_route: bool,
    compiled_route: BackendRouteModel,
)
    ensures
        job_kind == JobKindModel::Wrap && has_wrapper_target ==> project_requested_backend(
            job_kind,
            has_wrapper_target,
            wrapper_target,
            has_requested_backend,
            requested_backend,
            has_compiled,
            compiled_backend,
        ) == Some(wrapper_target),
        job_kind != JobKindModel::Wrap && has_requested_backend ==> project_requested_backend(
            job_kind,
            has_wrapper_target,
            wrapper_target,
            has_requested_backend,
            requested_backend,
            has_compiled,
            compiled_backend,
        ) == Some(requested_backend),
        !has_requested_route && has_compiled_route ==> project_backend_route(
            has_requested_route,
            requested_route,
            has_compiled_route,
            compiled_route,
        ) == Some(compiled_route),
        has_requested_route ==> project_backend_route(
            has_requested_route,
            requested_route,
            has_compiled_route,
            compiled_route,
        ) == Some(requested_route),
{
}

pub proof fn runtime_api_backend_candidate_selection(
    job_kind: JobKindModel,
    has_wrapper_target: bool,
    wrapper_target: BackendKindModel,
    has_requested_candidates: bool,
    requested_candidates: Seq<BackendKindModel>,
    has_compiled: bool,
    compiled_backend: BackendKindModel,
    has_program: bool,
    field: FieldIdModel,
)
    ensures
        job_kind == JobKindModel::Wrap && has_wrapper_target ==> project_backend_candidates(
            job_kind,
            has_wrapper_target,
            wrapper_target,
            has_requested_candidates,
            requested_candidates,
            has_compiled,
            compiled_backend,
            has_program,
            field,
        ) == seq![wrapper_target],
        job_kind != JobKindModel::Wrap && has_requested_candidates ==> project_backend_candidates(
            job_kind,
            has_wrapper_target,
            wrapper_target,
            has_requested_candidates,
            requested_candidates,
            has_compiled,
            compiled_backend,
            has_program,
            field,
        ) == requested_candidates,
        job_kind != JobKindModel::Wrap && !has_requested_candidates && has_compiled ==> project_backend_candidates(
            job_kind,
            has_wrapper_target,
            wrapper_target,
            has_requested_candidates,
            requested_candidates,
            has_compiled,
            compiled_backend,
            has_program,
            field,
        ) == seq![compiled_backend],
        job_kind != JobKindModel::Wrap && !has_requested_candidates && !has_compiled && has_program ==> project_backend_candidates(
            job_kind,
            has_wrapper_target,
            wrapper_target,
            has_requested_candidates,
            requested_candidates,
            has_compiled,
            compiled_backend,
            has_program,
            field,
        ).len() > 0,
        job_kind != JobKindModel::Wrap && !has_requested_candidates && !has_compiled && !has_program ==> project_backend_candidates(
            job_kind,
            has_wrapper_target,
            wrapper_target,
            has_requested_candidates,
            requested_candidates,
            has_compiled,
            compiled_backend,
            has_program,
            field,
        ) == seq![BackendKindModel::ArkworksGroth16],
{
}

pub proof fn runtime_api_batch_scheduler_determinism(
    total_jobs: int,
    requested_jobs: int,
)
    requires
        total_jobs >= 0,
        requested_jobs >= 0,
    ensures
        scheduled_jobs(total_jobs, requested_jobs) >= 1,
        scheduled_jobs(total_jobs, requested_jobs) <= max_int(total_jobs, 1),
        scheduled_jobs(total_jobs, requested_jobs) == max_int(min_int(total_jobs, requested_jobs), 1),
{
}

} // verus!
