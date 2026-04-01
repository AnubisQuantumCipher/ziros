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

#![allow(dead_code)]

use crate::launch_contracts::{
    CurveFamily, FieldFamily, MsmContractInput, MsmRouteClass, NttContractInput,
    Poseidon2ContractInput, certified_bn254_routes, hash_contract_accepts, msm_contract_accepts,
    ntt_contract_accepts, poseidon2_contract_accepts,
};
use crate::msm::pippenger::optimal_window_size as bn254_optimal_window_size;

#[kani::proof]
fn hash_contract_rejects_zero_input_len() {
    let batch_count: u8 = kani::any();
    kani::assume(batch_count > 0);
    assert!(!hash_contract_accepts(
        usize::from(batch_count),
        0,
        0,
        usize::from(batch_count) * 32,
    ));
}

#[kani::proof]
fn hash_contract_rejects_short_output_buffer() {
    let batch_count: u8 = kani::any();
    let input_len: u8 = kani::any();
    kani::assume(batch_count > 0);
    kani::assume(input_len > 0);
    let batch_count = usize::from(batch_count);
    let input_len = usize::from(input_len);
    assert!(!hash_contract_accepts(
        batch_count,
        input_len,
        batch_count * input_len,
        batch_count * 31,
    ));
}

#[kani::proof]
fn hash_contract_accepts_valid_shape() {
    let batch_count: u8 = kani::any();
    let input_len: u8 = kani::any();
    kani::assume(batch_count > 0);
    kani::assume(input_len > 0);
    let batch_count = usize::from(batch_count);
    let input_len = usize::from(input_len);
    assert!(hash_contract_accepts(
        batch_count,
        input_len,
        batch_count * input_len,
        batch_count * 32,
    ));
}

#[kani::proof]
fn poseidon2_contract_rejects_misaligned_state_width() {
    let state_elements: u8 = kani::any();
    kani::assume(state_elements % 16 != 0);
    assert!(!poseidon2_contract_accepts(&Poseidon2ContractInput {
        kernel: "poseidon2_goldilocks",
        field: FieldFamily::Goldilocks,
        simd: false,
        state_elements: usize::from(state_elements).max(1),
        round_constants: 8,
        n_external_rounds: 8,
        n_internal_rounds: 13,
        element_bytes: 8,
        max_threads_per_group: 256,
        requested_zero_copy: false,
        zero_copy_eligible: false,
    }));
}

#[kani::proof]
fn poseidon2_contract_rejects_bad_zero_copy_request() {
    let perms: u8 = kani::any();
    kani::assume(perms > 0);
    assert!(!poseidon2_contract_accepts(&Poseidon2ContractInput {
        kernel: "poseidon2_babybear_simd",
        field: FieldFamily::BabyBear,
        simd: true,
        state_elements: usize::from(perms) * 16,
        round_constants: 8,
        n_external_rounds: 8,
        n_internal_rounds: 13,
        element_bytes: 4,
        max_threads_per_group: 256,
        requested_zero_copy: true,
        zero_copy_eligible: false,
    }));
}

#[kani::proof]
fn poseidon2_contract_accepts_valid_shape() {
    let perms: u8 = kani::any();
    kani::assume(perms > 0);
    assert!(poseidon2_contract_accepts(&Poseidon2ContractInput {
        kernel: "poseidon2_babybear_simd",
        field: FieldFamily::BabyBear,
        simd: true,
        state_elements: usize::from(perms) * 16,
        round_constants: 8,
        n_external_rounds: 8,
        n_internal_rounds: 13,
        element_bytes: 4,
        max_threads_per_group: 256,
        requested_zero_copy: false,
        zero_copy_eligible: true,
    }));
}

#[kani::proof]
fn ntt_contract_rejects_non_power_of_two_height() {
    let height: u8 = kani::any();
    kani::assume(height > 2);
    kani::assume((height as usize).count_ones() > 1);
    assert!(!ntt_contract_accepts(&NttContractInput {
        kernel: "ntt_butterfly_goldilocks",
        field: FieldFamily::Goldilocks,
        height: usize::from(height),
        width: 1,
        twiddle_elements: usize::from(height),
        element_bytes: 8,
        max_threads_per_group: 256,
        inverse: false,
        batched: false,
    }));
}

#[kani::proof]
fn ntt_contract_rejects_short_twiddle_region() {
    let height: u8 = kani::any();
    kani::assume(height >= 2);
    kani::assume((height as usize).is_power_of_two());
    assert!(!ntt_contract_accepts(&NttContractInput {
        kernel: "ntt_butterfly_babybear_batch",
        field: FieldFamily::BabyBear,
        height: usize::from(height),
        width: 2,
        twiddle_elements: usize::from(height.saturating_sub(1)),
        element_bytes: 4,
        max_threads_per_group: 256,
        inverse: true,
        batched: true,
    }));
}

#[kani::proof]
fn ntt_contract_accepts_valid_shape() {
    let pow: u8 = kani::any();
    kani::assume(pow >= 1);
    kani::assume(pow <= 7);
    let height = 1usize << pow;
    assert!(ntt_contract_accepts(&NttContractInput {
        kernel: "ntt_butterfly_babybear_batch",
        field: FieldFamily::BabyBear,
        height,
        width: 2,
        twiddle_elements: height,
        element_bytes: 4,
        max_threads_per_group: 256,
        inverse: false,
        batched: true,
    }));
}

#[kani::proof]
fn msm_contract_rejects_short_bucket_map() {
    let point_count: u8 = kani::any();
    kani::assume(point_count > 0);
    let num_windows = 4u32;
    let num_buckets = 16usize;
    let point_count = usize::from(point_count);
    assert!(!msm_contract_accepts(&MsmContractInput {
        kernel: "msm_bucket_acc",
        curve: CurveFamily::Pallas,
        route: MsmRouteClass::Classic,
        point_count,
        scalar_limbs: 4,
        base_coordinate_limbs: 4,
        map_entries: point_count * num_windows as usize - 1,
        bucket_entries: num_windows as usize * num_buckets * 12,
        window_entries: 0,
        final_entries: 0,
        num_windows,
        num_buckets,
        max_threads_per_group: 256,
        certified_route: true,
    }));
}

#[kani::proof]
fn msm_contract_accepts_certified_bn254_classic_shape() {
    let point_count: u8 = kani::any();
    kani::assume(point_count > 0);
    let point_count = usize::from(point_count);
    let num_windows = 4u32;
    let num_buckets = 16usize;
    assert!(msm_contract_accepts(&MsmContractInput {
        kernel: "msm_bucket_acc",
        curve: CurveFamily::Bn254,
        route: MsmRouteClass::Classic,
        point_count,
        scalar_limbs: 4,
        base_coordinate_limbs: 4,
        map_entries: point_count * num_windows as usize,
        bucket_entries: num_windows as usize * num_buckets * 12,
        window_entries: 0,
        final_entries: 0,
        num_windows,
        num_buckets,
        max_threads_per_group: 256,
        certified_route: true,
    }));
}

#[kani::proof]
fn bn254_strict_window_schedule_excludes_uncertified_c16() {
    let n: u32 = kani::any();
    let c = bn254_optimal_window_size(n.max(1) as usize);
    assert!(c <= 15);
}

#[kani::proof]
fn msm_contract_rejects_invalid_naf_bucket_shape() {
    let point_count: u8 = kani::any();
    kani::assume(point_count > 0);
    let num_windows = 5u32;
    let num_buckets = 7usize;
    let point_count = usize::from(point_count);
    assert!(!msm_contract_accepts(&MsmContractInput {
        kernel: "msm_bucket_acc_naf",
        curve: CurveFamily::Vesta,
        route: MsmRouteClass::Naf,
        point_count,
        scalar_limbs: 4,
        base_coordinate_limbs: 4,
        map_entries: point_count * num_windows as usize,
        bucket_entries: num_windows as usize * num_buckets * 12 - 1,
        window_entries: 0,
        final_entries: 0,
        num_windows,
        num_buckets,
        max_threads_per_group: 256,
        certified_route: true,
    }));
}

#[kani::proof]
fn certified_bn254_surface_excludes_hybrid_and_full_gpu_routes() {
    assert!(certified_bn254_routes().contains(&MsmRouteClass::Classic));
    assert!(!certified_bn254_routes().contains(&MsmRouteClass::Hybrid));
    assert!(!certified_bn254_routes().contains(&MsmRouteClass::FullGpu));
    assert!(!certified_bn254_routes().contains(&MsmRouteClass::Tensor));
}
