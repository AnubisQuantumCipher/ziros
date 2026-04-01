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

//! Shader compilation and pipeline caching utilities.

/// Available kernel functions in the main shader library.
pub mod kernels {
    pub const NTT_BUTTERFLY_GOLDILOCKS: &str = "ntt_butterfly_goldilocks";
    pub const NTT_BUTTERFLY_BABYBEAR: &str = "ntt_butterfly_babybear";
    pub const NTT_BUTTERFLY_BN254: &str = "ntt_butterfly_bn254";
    pub const NTT_SMALL_GOLDILOCKS: &str = "ntt_small_goldilocks";
    pub const NTT_SMALL_BN254: &str = "ntt_small_bn254";
    pub const POSEIDON2_GOLDILOCKS: &str = "poseidon2_goldilocks";
    pub const POSEIDON2_BABYBEAR: &str = "poseidon2_babybear";
    pub const POSEIDON2_BABYBEAR_SIMD: &str = "poseidon2_babybear_simd";
    pub const NTT_BUTTERFLY_GOLDILOCKS_BATCH: &str = "ntt_butterfly_goldilocks_batch";
    pub const NTT_BUTTERFLY_BABYBEAR_BATCH: &str = "ntt_butterfly_babybear_batch";
    pub const POSEIDON2_GOLDILOCKS_SIMD: &str = "poseidon2_goldilocks_simd";
    pub const NTT_HYBRID_GOLDILOCKS: &str = "ntt_hybrid_goldilocks";
    pub const NTT_HYBRID_BN254: &str = "ntt_hybrid_bn254";
    pub const BATCH_SHA256: &str = "batch_sha256";
    pub const BATCH_KECCAK256: &str = "batch_keccak256";

    // Batch field operations
    pub const BATCH_ADD_GOLDILOCKS: &str = "batch_add_goldilocks";
    pub const BATCH_SUB_GOLDILOCKS: &str = "batch_sub_goldilocks";
    pub const BATCH_MUL_GOLDILOCKS: &str = "batch_mul_goldilocks";
    pub const BATCH_INV_PREFIX_GOLDILOCKS: &str = "batch_inv_prefix_goldilocks";
    pub const BATCH_INV_BACKPROP_GOLDILOCKS: &str = "batch_inv_backprop_goldilocks";
    pub const BATCH_ADD_BABYBEAR: &str = "batch_add_babybear";
    pub const BATCH_SUB_BABYBEAR: &str = "batch_sub_babybear";
    pub const BATCH_MUL_BABYBEAR: &str = "batch_mul_babybear";

    // Polynomial operations
    pub const POLY_EVAL_GOLDILOCKS: &str = "poly_eval_goldilocks";
    pub const POLY_BATCH_EVAL_GOLDILOCKS: &str = "poly_batch_eval_goldilocks";
    pub const POLY_QUOTIENT_GOLDILOCKS: &str = "poly_quotient_goldilocks";
    pub const POLY_COSET_SHIFT_GOLDILOCKS: &str = "poly_coset_shift_goldilocks";
    pub const POLY_EVAL_BABYBEAR: &str = "poly_eval_babybear";

    // FRI folding
    pub const FRI_FOLD_GOLDILOCKS: &str = "fri_fold_goldilocks";
    pub const FRI_FOLD_BABYBEAR: &str = "fri_fold_babybear";

    // Constraint evaluation
    pub const CONSTRAINT_EVAL_GOLDILOCKS: &str = "constraint_eval_goldilocks";
}

/// Available kernel functions in the MSM shader library (compiled separately).
pub mod msm_kernels {
    pub const BUCKET_ASSIGN: &str = "msm_bucket_assign";
    pub const BUCKET_ACC: &str = "msm_bucket_acc";
    pub const BUCKET_ACC_SIMD: &str = "msm_bucket_acc_simd";
    pub const BUCKET_REDUCE: &str = "msm_bucket_reduce";
    pub const WINDOW_COMBINE: &str = "msm_window_combine";
    pub const SORT_COUNT: &str = "msm_sort_count";
    pub const SORT_SCATTER: &str = "msm_sort_scatter";
    pub const BUCKET_ACC_SORTED: &str = "msm_bucket_acc_sorted";
    pub const SORT_COUNT_NAF: &str = "msm_sort_count_naf";
    pub const SORT_SCATTER_NAF: &str = "msm_sort_scatter_naf";
    pub const BUCKET_ACC_SORTED_NAF: &str = "msm_bucket_acc_sorted_naf";
}
