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

//! Verified Metal artifact attestation inventory.
#![allow(deprecated)]

use objc2_foundation::NSArray;
use objc2_metal::{MTLArgument, MTLArgumentAccess, MTLArgumentType, MTLComputePipelineDescriptor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PUBLIC_REFLECTION_DIGEST_SCHEME_V1: &str = "public-v1-no-arg-names";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolchainIdentity {
    pub metal_compiler_version: String,
    pub xcode_version: String,
    pub sdk_version: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedArgumentKind {
    Buffer,
    ThreadgroupMemory,
}

impl ExpectedArgumentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Buffer => "buffer",
            Self::ThreadgroupMemory => "threadgroup_memory",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedBindingAccess {
    ReadOnly,
    ReadWrite,
    WriteOnly,
}

impl ExpectedBindingAccess {
    fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::ReadWrite => "read_write",
            Self::WriteOnly => "write_only",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpectedArgument {
    pub name: String,
    pub index: usize,
    pub kind: ExpectedArgumentKind,
    pub access: ExpectedBindingAccess,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExpectedKernelAttestation {
    pub library_id: String,
    pub entrypoint: String,
    pub metallib_sha256: String,
    pub reflection_sha256: String,
    pub public_reflection_sha256: String,
    pub pipeline_descriptor_sha256: String,
    pub toolchain: ToolchainIdentity,
    pub arguments: Vec<ExpectedArgument>,
}

fn sha256_hex(input: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_ref());
    format!("{:x}", hasher.finalize())
}

fn canonical_library_id(library_id: &str) -> Option<&'static str> {
    match library_id {
        "main_library" => Some("main_library"),
        "hash_library" => Some("hash_library"),
        "msm_library" | "bn254_msm_library" => Some("bn254_msm_library"),
        "pallas_msm_library" => Some("pallas_msm_library"),
        "vesta_msm_library" => Some("vesta_msm_library"),
        _ => None,
    }
}

pub fn normalize_library_id(library_id: &str) -> Option<&'static str> {
    canonical_library_id(library_id)
}

pub fn current_toolchain_identity() -> ToolchainIdentity {
    ToolchainIdentity {
        metal_compiler_version: option_env!("ZKF_METAL_COMPILER_VERSION")
            .unwrap_or_default()
            .to_string(),
        xcode_version: option_env!("ZKF_METAL_XCODE_VERSION")
            .unwrap_or_default()
            .to_string(),
        sdk_version: option_env!("ZKF_METAL_SDK_VERSION")
            .unwrap_or_default()
            .to_string(),
    }
}

pub fn expected_metallib_sha256(library_id: &str) -> Option<String> {
    match canonical_library_id(library_id)? {
        "main_library" => option_env!("METALLIB_MAIN_SHA256"),
        "hash_library" => option_env!("METALLIB_HASH_SHA256"),
        "bn254_msm_library" => option_env!("METALLIB_MSM_SHA256"),
        "pallas_msm_library" => option_env!("METALLIB_MSM_PALLAS_SHA256"),
        "vesta_msm_library" => option_env!("METALLIB_MSM_VESTA_SHA256"),
        _ => None,
    }
    .map(str::to_string)
}

fn expected_argument(
    name: &str,
    index: usize,
    kind: ExpectedArgumentKind,
    access: ExpectedBindingAccess,
) -> ExpectedArgument {
    ExpectedArgument {
        name: name.to_string(),
        index,
        kind,
        access,
    }
}

fn ro_buffer(name: &str, index: usize) -> ExpectedArgument {
    expected_argument(
        name,
        index,
        ExpectedArgumentKind::Buffer,
        ExpectedBindingAccess::ReadOnly,
    )
}

fn rw_buffer(name: &str, index: usize) -> ExpectedArgument {
    expected_argument(
        name,
        index,
        ExpectedArgumentKind::Buffer,
        ExpectedBindingAccess::ReadWrite,
    )
}

fn tg_memory(name: &str, index: usize) -> ExpectedArgument {
    expected_argument(
        name,
        index,
        ExpectedArgumentKind::ThreadgroupMemory,
        ExpectedBindingAccess::ReadWrite,
    )
}

fn hash_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("inputs", 0),
        rw_buffer("outputs", 1),
        ro_buffer("n_inputs", 2),
        ro_buffer("input_len", 3),
    ]
}

fn field_binary_arguments() -> Vec<ExpectedArgument> {
    vec![rw_buffer("a", 0), ro_buffer("b", 1), ro_buffer("count", 2)]
}

fn field_inv_prefix_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("input", 0),
        rw_buffer("prefix", 1),
        ro_buffer("count", 2),
        ro_buffer("chunk_size", 3),
    ]
}

fn field_inv_backprop_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("input", 0),
        rw_buffer("prefix", 1),
        rw_buffer("output", 2),
        ro_buffer("count", 3),
        ro_buffer("chunk_size", 4),
    ]
}

fn poseidon_arguments() -> Vec<ExpectedArgument> {
    vec![
        rw_buffer("states", 0),
        ro_buffer("round_constants", 1),
        ro_buffer("n_perms", 2),
        ro_buffer("n_external_rounds", 3),
        ro_buffer("n_internal_rounds", 4),
        ro_buffer("internal_diag", 5),
    ]
}

fn ntt_butterfly_arguments() -> Vec<ExpectedArgument> {
    vec![
        rw_buffer("data", 0),
        ro_buffer("twiddles", 1),
        ro_buffer("stage", 2),
        ro_buffer("n", 3),
    ]
}

fn ntt_batch_arguments() -> Vec<ExpectedArgument> {
    vec![
        rw_buffer("data", 0),
        ro_buffer("twiddles", 1),
        ro_buffer("stage", 2),
        ro_buffer("n", 3),
        ro_buffer("stride", 4),
    ]
}

fn ntt_small_arguments() -> Vec<ExpectedArgument> {
    vec![
        rw_buffer("data", 0),
        ro_buffer("twiddles", 1),
        ro_buffer("log_n", 2),
        tg_memory("shared", 0),
    ]
}

fn ntt_hybrid_arguments() -> Vec<ExpectedArgument> {
    vec![
        rw_buffer("data", 0),
        ro_buffer("twiddles", 1),
        ro_buffer("log_n", 2),
        ro_buffer("log_tg_size", 3),
        tg_memory("shared", 0),
    ]
}

fn poly_eval_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("coeffs", 0),
        ro_buffer("points", 1),
        rw_buffer("output", 2),
        ro_buffer("degree", 3),
        ro_buffer("n_points", 4),
    ]
}

fn poly_batch_eval_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("coeffs_flat", 0),
        ro_buffer("points", 1),
        rw_buffer("output", 2),
        ro_buffer("degree", 3),
        ro_buffer("n_points", 4),
        ro_buffer("n_polys", 5),
    ]
}

fn poly_quotient_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("evals", 0),
        rw_buffer("output", 1),
        ro_buffer("z", 2),
        ro_buffer("f_z", 3),
        ro_buffer("generator", 4),
        ro_buffer("n", 5),
    ]
}

fn poly_coset_shift_arguments() -> Vec<ExpectedArgument> {
    vec![
        rw_buffer("coeffs", 0),
        ro_buffer("shift", 1),
        ro_buffer("n", 2),
    ]
}

fn fri_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("evals", 0),
        rw_buffer("output", 1),
        ro_buffer("alpha", 2),
        ro_buffer("inv_twiddles", 3),
        ro_buffer("n_output", 4),
    ]
}

fn constraint_eval_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("trace", 0),
        ro_buffer("bytecode", 1),
        ro_buffer("constants", 2),
        rw_buffer("output", 3),
        ro_buffer("width", 4),
        ro_buffer("n_instructions", 5),
        ro_buffer("n_constraints", 6),
    ]
}

fn msm_bn254_assign_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("scalars", 0),
        rw_buffer("point_bucket_map", 1),
        ro_buffer("n_points", 2),
        ro_buffer("c", 3),
        ro_buffer("num_windows", 4),
        ro_buffer("window_offset", 5),
    ]
}

fn msm_curve_assign_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("scalars", 0),
        rw_buffer("point_bucket_map", 1),
        ro_buffer("n_points", 2),
        ro_buffer("c", 3),
        ro_buffer("num_windows", 4),
    ]
}

fn msm_bucket_acc_arguments(map_name: &str) -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("bases_x", 0),
        ro_buffer("bases_y", 1),
        ro_buffer(map_name, 2),
        rw_buffer("bucket_results", 3),
        ro_buffer("n_points", 4),
        ro_buffer("c", 5),
        ro_buffer("num_windows", 6),
    ]
}

fn msm_bucket_acc_naf_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("bases_x", 0),
        ro_buffer("bases_y", 1),
        ro_buffer("naf_map", 2),
        rw_buffer("bucket_results", 3),
        ro_buffer("n_points", 4),
        ro_buffer("c", 5),
        ro_buffer("num_windows", 6),
        ro_buffer("num_buckets_naf", 7),
    ]
}

fn msm_reduce_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("bucket_data", 0),
        rw_buffer("window_results", 1),
        ro_buffer("num_buckets", 2),
        ro_buffer("num_windows", 3),
    ]
}

fn msm_combine_arguments() -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("window_results", 0),
        rw_buffer("final_result", 1),
        ro_buffer("num_windows", 2),
        ro_buffer("window_bits", 3),
    ]
}

fn msm_bucket_acc_simd_arguments() -> Vec<ExpectedArgument> {
    msm_bucket_acc_arguments("point_bucket_map")
}

fn msm_sort_count_arguments(map_name: &str, bucket_name: &str) -> Vec<ExpectedArgument> {
    vec![
        ro_buffer(map_name, 0),
        rw_buffer(bucket_name, 1),
        ro_buffer("n_points", 2),
        ro_buffer("num_buckets", 3),
        ro_buffer("num_windows", 4),
    ]
}

fn msm_sort_scatter_arguments(map_name: &str) -> Vec<ExpectedArgument> {
    vec![
        ro_buffer(map_name, 0),
        ro_buffer("bucket_offsets", 1),
        rw_buffer("write_cursors", 2),
        rw_buffer("sorted_indices", 3),
        ro_buffer("n_points", 4),
        ro_buffer("num_buckets", 5),
        ro_buffer("num_windows", 6),
    ]
}

fn msm_sorted_acc_arguments(num_buckets_name: &str) -> Vec<ExpectedArgument> {
    vec![
        ro_buffer("bases_x", 0),
        ro_buffer("bases_y", 1),
        ro_buffer("sorted_indices", 2),
        ro_buffer("bucket_offsets", 3),
        ro_buffer("bucket_counts", 4),
        rw_buffer("bucket_results", 5),
        ro_buffer(num_buckets_name, 6),
        ro_buffer("num_windows", 7),
    ]
}

fn expected_arguments(library_id: &str, entrypoint: &str) -> Option<Vec<ExpectedArgument>> {
    match (canonical_library_id(library_id)?, entrypoint) {
        ("hash_library", "batch_sha256" | "batch_keccak256") => Some(hash_arguments()),
        (
            "main_library",
            "batch_add_goldilocks"
            | "batch_sub_goldilocks"
            | "batch_mul_goldilocks"
            | "batch_add_babybear"
            | "batch_sub_babybear"
            | "batch_mul_babybear",
        ) => Some(field_binary_arguments()),
        ("main_library", "batch_inv_prefix_goldilocks") => Some(field_inv_prefix_arguments()),
        ("main_library", "batch_inv_backprop_goldilocks") => Some(field_inv_backprop_arguments()),
        (
            "main_library",
            "poseidon2_goldilocks"
            | "poseidon2_goldilocks_simd"
            | "poseidon2_babybear"
            | "poseidon2_babybear_simd",
        ) => Some(poseidon_arguments()),
        (
            "main_library",
            "ntt_butterfly_goldilocks" | "ntt_butterfly_babybear" | "ntt_butterfly_bn254",
        ) => Some(ntt_butterfly_arguments()),
        ("main_library", "ntt_butterfly_goldilocks_batch" | "ntt_butterfly_babybear_batch") => {
            Some(ntt_batch_arguments())
        }
        ("main_library", "ntt_small_goldilocks" | "ntt_small_bn254") => Some(ntt_small_arguments()),
        ("main_library", "ntt_hybrid_goldilocks" | "ntt_hybrid_bn254") => {
            Some(ntt_hybrid_arguments())
        }
        ("main_library", "poly_eval_goldilocks" | "poly_eval_babybear") => {
            Some(poly_eval_arguments())
        }
        ("main_library", "poly_batch_eval_goldilocks") => Some(poly_batch_eval_arguments()),
        ("main_library", "poly_quotient_goldilocks") => Some(poly_quotient_arguments()),
        ("main_library", "poly_coset_shift_goldilocks") => Some(poly_coset_shift_arguments()),
        ("main_library", "fri_fold_goldilocks" | "fri_fold_babybear") => Some(fri_arguments()),
        ("main_library", "constraint_eval_goldilocks") => Some(constraint_eval_arguments()),
        ("bn254_msm_library", "msm_bucket_assign") => Some(msm_bn254_assign_arguments()),
        ("bn254_msm_library", "msm_bucket_acc") => {
            Some(msm_bucket_acc_arguments("point_bucket_map"))
        }
        ("bn254_msm_library", "msm_bucket_acc_simd") => Some(msm_bucket_acc_simd_arguments()),
        ("bn254_msm_library", "msm_bucket_reduce") => Some(msm_reduce_arguments()),
        ("bn254_msm_library", "msm_window_combine") => Some(msm_combine_arguments()),
        ("bn254_msm_library", "msm_sort_count") => Some(msm_sort_count_arguments(
            "point_bucket_map",
            "bucket_counts",
        )),
        ("bn254_msm_library", "msm_sort_scatter") => {
            Some(msm_sort_scatter_arguments("point_bucket_map"))
        }
        ("bn254_msm_library", "msm_bucket_acc_sorted") => {
            Some(msm_sorted_acc_arguments("num_buckets"))
        }
        ("bn254_msm_library", "msm_sort_count_naf") => {
            Some(msm_sort_count_arguments("naf_map", "bucket_counts"))
        }
        ("bn254_msm_library", "msm_sort_scatter_naf") => {
            Some(msm_sort_scatter_arguments("naf_map"))
        }
        ("bn254_msm_library", "msm_bucket_acc_sorted_naf") => {
            Some(msm_sorted_acc_arguments("num_buckets_naf"))
        }
        ("pallas_msm_library" | "vesta_msm_library", "msm_bucket_assign") => {
            Some(msm_curve_assign_arguments())
        }
        ("pallas_msm_library" | "vesta_msm_library", "msm_bucket_acc") => {
            Some(msm_bucket_acc_arguments("point_bucket_map"))
        }
        ("pallas_msm_library" | "vesta_msm_library", "msm_bucket_acc_simd") => {
            Some(msm_bucket_acc_simd_arguments())
        }
        ("pallas_msm_library" | "vesta_msm_library", "msm_bucket_acc_naf") => {
            Some(msm_bucket_acc_naf_arguments())
        }
        _ => None,
    }
}

fn reflection_materialization(arguments: &[ExpectedArgument]) -> String {
    let mut parts = arguments
        .iter()
        .map(|argument| {
            format!(
                "{}|{}|{}|{}",
                argument.index,
                argument.name,
                argument.kind.as_str(),
                argument.access.as_str()
            )
        })
        .collect::<Vec<_>>();
    parts.sort();
    parts.join("\n")
}

fn public_reflection_materialization(arguments: &[ExpectedArgument]) -> String {
    let mut parts = arguments
        .iter()
        .map(|argument| {
            format!(
                "{}|{}|{}",
                argument.index,
                argument.kind.as_str(),
                argument.access.as_str()
            )
        })
        .collect::<Vec<_>>();
    parts.sort();
    format!(
        "scheme={PUBLIC_REFLECTION_DIGEST_SCHEME_V1}\ncount={}\n{}",
        parts.len(),
        parts.join("\n")
    )
}

pub fn reflection_sha256_from_expected(arguments: &[ExpectedArgument]) -> String {
    sha256_hex(reflection_materialization(arguments))
}

pub fn public_reflection_sha256_from_expected(arguments: &[ExpectedArgument]) -> String {
    sha256_hex(public_reflection_materialization(arguments))
}

fn runtime_argument_kind_name(argument_type: MTLArgumentType) -> String {
    if argument_type == MTLArgumentType::Buffer {
        "buffer".to_string()
    } else if argument_type == MTLArgumentType::ThreadgroupMemory {
        "threadgroup_memory".to_string()
    } else {
        format!("other_{}", argument_type.0)
    }
}

fn runtime_binding_access_name(access: MTLArgumentAccess) -> &'static str {
    if access == MTLArgumentAccess::ReadOnly {
        "read_only"
    } else if access == MTLArgumentAccess::ReadWrite {
        "read_write"
    } else if access == MTLArgumentAccess::WriteOnly {
        "write_only"
    } else {
        "unknown"
    }
}

#[allow(deprecated)]
pub fn reflection_sha256_from_runtime_arguments(arguments: &NSArray<MTLArgument>) -> String {
    let mut parts = Vec::with_capacity(arguments.count());
    for index in 0..arguments.count() {
        let argument = arguments.objectAtIndex(index);
        parts.push(format!(
            "{}|{}|{}|{}",
            argument.index(),
            argument.name(),
            runtime_argument_kind_name(argument.r#type()),
            runtime_binding_access_name(argument.access())
        ));
    }
    parts.sort();
    sha256_hex(parts.join("\n"))
}

pub fn pipeline_descriptor_label(library_id: &str, entrypoint: &str) -> String {
    format!(
        "zkf.verified.{}.{}",
        canonical_library_id(library_id).unwrap_or(library_id),
        entrypoint
    )
}

fn descriptor_materialization(
    library_id: &str,
    entrypoint: &str,
    label: &str,
    support_indirect_command_buffers: bool,
    max_total_threads_per_threadgroup: usize,
    threadgroup_multiple_of_execution_width: bool,
) -> String {
    format!(
        "library={};entrypoint={};label={};support_indirect_command_buffers={};max_total_threads_per_threadgroup={};threadgroup_multiple_of_execution_width={}",
        canonical_library_id(library_id).unwrap_or(library_id),
        entrypoint,
        label,
        support_indirect_command_buffers,
        max_total_threads_per_threadgroup,
        threadgroup_multiple_of_execution_width
    )
}

pub fn pipeline_descriptor_sha256(library_id: &str, entrypoint: &str) -> String {
    sha256_hex(descriptor_materialization(
        library_id,
        entrypoint,
        &pipeline_descriptor_label(library_id, entrypoint),
        false,
        0,
        false,
    ))
}

pub fn pipeline_descriptor_sha256_from_runtime(
    library_id: &str,
    entrypoint: &str,
    descriptor: &MTLComputePipelineDescriptor,
) -> String {
    let label = descriptor
        .label()
        .map(|value| value.to_string())
        .unwrap_or_default();
    sha256_hex(descriptor_materialization(
        library_id,
        entrypoint,
        &label,
        descriptor.supportIndirectCommandBuffers(),
        descriptor.maxTotalThreadsPerThreadgroup(),
        descriptor.threadGroupSizeIsMultipleOfThreadExecutionWidth(),
    ))
}

pub fn expected_kernel_attestation(
    library_id: &str,
    entrypoint: &str,
) -> Option<ExpectedKernelAttestation> {
    let library_id = canonical_library_id(library_id)?;
    let arguments = expected_arguments(library_id, entrypoint)?;
    let metallib_sha256 = expected_metallib_sha256(library_id)?;
    let toolchain = current_toolchain_identity();
    Some(ExpectedKernelAttestation {
        library_id: library_id.to_string(),
        entrypoint: entrypoint.to_string(),
        reflection_sha256: reflection_sha256_from_expected(&arguments),
        public_reflection_sha256: public_reflection_sha256_from_expected(&arguments),
        pipeline_descriptor_sha256: pipeline_descriptor_sha256(library_id, entrypoint),
        metallib_sha256,
        toolchain,
        arguments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_bn254_msm_aliases() {
        assert_eq!(
            normalize_library_id("msm_library"),
            Some("bn254_msm_library")
        );
        assert_eq!(
            normalize_library_id("bn254_msm_library"),
            Some("bn254_msm_library")
        );
    }

    #[test]
    fn every_shipped_verified_entrypoint_has_attestation_shape() {
        if option_env!("METALLIB_MAIN_SHA256").is_none() {
            return;
        }
        let covered = [
            ("hash_library", "batch_sha256"),
            ("hash_library", "batch_keccak256"),
            ("main_library", "batch_add_goldilocks"),
            ("main_library", "batch_sub_goldilocks"),
            ("main_library", "batch_mul_goldilocks"),
            ("main_library", "batch_inv_prefix_goldilocks"),
            ("main_library", "batch_inv_backprop_goldilocks"),
            ("main_library", "batch_add_babybear"),
            ("main_library", "batch_sub_babybear"),
            ("main_library", "batch_mul_babybear"),
            ("main_library", "poseidon2_goldilocks"),
            ("main_library", "poseidon2_goldilocks_simd"),
            ("main_library", "poseidon2_babybear"),
            ("main_library", "poseidon2_babybear_simd"),
            ("main_library", "ntt_butterfly_goldilocks"),
            ("main_library", "ntt_butterfly_goldilocks_batch"),
            ("main_library", "ntt_small_goldilocks"),
            ("main_library", "ntt_hybrid_goldilocks"),
            ("main_library", "ntt_butterfly_babybear"),
            ("main_library", "ntt_butterfly_babybear_batch"),
            ("main_library", "ntt_butterfly_bn254"),
            ("main_library", "ntt_small_bn254"),
            ("main_library", "ntt_hybrid_bn254"),
            ("main_library", "poly_eval_goldilocks"),
            ("main_library", "poly_batch_eval_goldilocks"),
            ("main_library", "poly_quotient_goldilocks"),
            ("main_library", "poly_coset_shift_goldilocks"),
            ("main_library", "poly_eval_babybear"),
            ("main_library", "fri_fold_goldilocks"),
            ("main_library", "fri_fold_babybear"),
            ("main_library", "constraint_eval_goldilocks"),
            ("bn254_msm_library", "msm_bucket_assign"),
            ("bn254_msm_library", "msm_bucket_acc"),
            ("bn254_msm_library", "msm_bucket_acc_simd"),
            ("bn254_msm_library", "msm_bucket_reduce"),
            ("bn254_msm_library", "msm_window_combine"),
            ("bn254_msm_library", "msm_sort_count"),
            ("bn254_msm_library", "msm_sort_scatter"),
            ("bn254_msm_library", "msm_bucket_acc_sorted"),
            ("bn254_msm_library", "msm_sort_count_naf"),
            ("bn254_msm_library", "msm_sort_scatter_naf"),
            ("bn254_msm_library", "msm_bucket_acc_sorted_naf"),
            ("pallas_msm_library", "msm_bucket_assign"),
            ("pallas_msm_library", "msm_bucket_acc"),
            ("pallas_msm_library", "msm_bucket_acc_simd"),
            ("pallas_msm_library", "msm_bucket_acc_naf"),
            ("vesta_msm_library", "msm_bucket_assign"),
            ("vesta_msm_library", "msm_bucket_acc"),
            ("vesta_msm_library", "msm_bucket_acc_simd"),
            ("vesta_msm_library", "msm_bucket_acc_naf"),
        ];

        for (library_id, entrypoint) in covered {
            let attestation = expected_kernel_attestation(library_id, entrypoint)
                .unwrap_or_else(|| panic!("missing attestation for {library_id}:{entrypoint}"));
            assert_eq!(
                attestation.library_id,
                normalize_library_id(library_id).unwrap()
            );
            assert!(!attestation.arguments.is_empty());
            assert!(!attestation.reflection_sha256.is_empty());
            assert!(!attestation.public_reflection_sha256.is_empty());
            assert!(!attestation.pipeline_descriptor_sha256.is_empty());
        }
    }
}
