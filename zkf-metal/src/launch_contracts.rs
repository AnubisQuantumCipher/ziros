//! Checked host-side launch contracts for the Metal proof surface.
//!
//! The contracts in this module are pure Rust and intentionally avoid touching
//! the Objective-C/Metal bindings. That keeps them available to the proof IR,
//! Kani harnesses, and host dispatch code as a common source of truth.

use serde::{Deserialize, Serialize};
use std::fmt;

const PAGE_SIZE_BYTES: usize = 4096;
const DIGEST_BYTES: usize = 32;
const POSEIDON2_STATE_WIDTH: usize = 16;
const MAX_HOST_THREADS_PER_GROUP: usize = 256;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelFamily {
    Hash,
    Poseidon2,
    Ntt,
    Msm,
    FieldOps,
    Poly,
    Fri,
    ConstraintEval,
    MsmAux,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CurveFamily {
    Bn254,
    Pallas,
    Vesta,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldFamily {
    Bytes,
    Goldilocks,
    BabyBear,
    Bn254Scalar,
    PallasScalar,
    VestaScalar,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MsmRouteClass {
    Classic,
    Naf,
    Hybrid,
    FullGpu,
    Tensor,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DispatchGrid {
    pub threadgroups_x: usize,
    pub threadgroups_y: usize,
    pub threads_per_group_x: usize,
    pub threads_per_group_y: usize,
    pub total_threads: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct BufferRegion {
    pub name: String,
    pub elements: usize,
    pub element_bytes: usize,
}

impl BufferRegion {
    fn byte_len(&self) -> usize {
        self.elements.saturating_mul(self.element_bytes)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValidatedDispatch {
    pub family: KernelFamily,
    pub kernel: String,
    pub route: Option<String>,
    pub field: Option<FieldFamily>,
    pub curve: Option<CurveFamily>,
    pub certified_route: bool,
    pub zero_copy: bool,
    pub scratch_bytes: usize,
    pub dispatch: DispatchGrid,
    pub read_regions: Vec<BufferRegion>,
    pub write_regions: Vec<BufferRegion>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LaunchContract {
    family: KernelFamily,
    kernel: String,
    route: Option<String>,
    field: Option<FieldFamily>,
    curve: Option<CurveFamily>,
    certified_route: bool,
    zero_copy: bool,
    scratch_bytes: usize,
    dispatch: DispatchGrid,
    read_regions: Vec<BufferRegion>,
    write_regions: Vec<BufferRegion>,
    errors: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LaunchContractError {
    pub family: KernelFamily,
    pub kernel: String,
    pub detail: String,
}

impl fmt::Display for LaunchContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} launch rejected for {:?}: {}",
            self.kernel, self.family, self.detail
        )
    }
}

impl std::error::Error for LaunchContractError {}

impl LaunchContract {
    fn validate(self) -> Result<ValidatedDispatch, LaunchContractError> {
        if let Some(detail) = self.errors.first() {
            return Err(LaunchContractError {
                family: self.family,
                kernel: self.kernel,
                detail: detail.clone(),
            });
        }

        Ok(ValidatedDispatch {
            family: self.family,
            kernel: self.kernel,
            route: self.route,
            field: self.field,
            curve: self.curve,
            certified_route: self.certified_route,
            zero_copy: self.zero_copy,
            scratch_bytes: self.scratch_bytes,
            dispatch: self.dispatch,
            read_regions: self.read_regions,
            write_regions: self.write_regions,
        })
    }
}

pub fn validate_dispatch_or_reject(
    contract: LaunchContract,
) -> Result<ValidatedDispatch, LaunchContractError> {
    contract.validate()
}

pub fn page_aligned_for_zero_copy<T>(slice: &[T]) -> bool {
    let ptr = slice.as_ptr() as usize;
    ptr.is_multiple_of(PAGE_SIZE_BYTES)
}

pub fn certified_bn254_routes() -> &'static [MsmRouteClass] {
    &[MsmRouteClass::Classic]
}

pub fn hash_contract(
    kernel: &str,
    batch_count: usize,
    input_len: usize,
    input_bytes: usize,
    output_bytes: usize,
    max_threads_per_group: usize,
) -> Result<ValidatedDispatch, LaunchContractError> {
    let capped_tpg = max_threads_per_group.clamp(1, MAX_HOST_THREADS_PER_GROUP);
    let threadgroups_x = batch_count.div_ceil(capped_tpg.max(1));
    let mut errors = Vec::new();
    if !hash_contract_accepts(batch_count, input_len, input_bytes, output_bytes) {
        if input_len == 0 {
            errors.push("input_len must be non-zero".to_string());
        }
        if batch_count == 0 {
            errors.push("batch_count must be non-zero".to_string());
        }
        if input_len != 0 && batch_count.saturating_mul(input_len) != input_bytes {
            errors.push("input bytes must equal batch_count * input_len".to_string());
        }
        if batch_count.saturating_mul(DIGEST_BYTES) != output_bytes {
            errors.push("output bytes must equal batch_count * 32".to_string());
        }
    }

    let contract = LaunchContract {
        family: KernelFamily::Hash,
        kernel: kernel.to_string(),
        route: None,
        field: Some(FieldFamily::Bytes),
        curve: None,
        certified_route: true,
        zero_copy: false,
        scratch_bytes: 0,
        dispatch: DispatchGrid {
            threadgroups_x,
            threadgroups_y: 1,
            threads_per_group_x: capped_tpg,
            threads_per_group_y: 1,
            total_threads: threadgroups_x.saturating_mul(capped_tpg),
        },
        read_regions: vec![BufferRegion {
            name: "inputs".to_string(),
            elements: input_bytes,
            element_bytes: 1,
        }],
        write_regions: vec![BufferRegion {
            name: "digests".to_string(),
            elements: output_bytes,
            element_bytes: 1,
        }],
        errors,
    };
    validate_dispatch_or_reject(contract)
}

pub fn hash_contract_accepts(
    batch_count: usize,
    input_len: usize,
    input_bytes: usize,
    output_bytes: usize,
) -> bool {
    batch_count > 0
        && input_len > 0
        && batch_count.saturating_mul(input_len) == input_bytes
        && batch_count.saturating_mul(DIGEST_BYTES) == output_bytes
}

pub fn poseidon2_contract_accepts(input: &Poseidon2ContractInput<'_>) -> bool {
    input.state_elements > 0
        && input.state_elements.is_multiple_of(POSEIDON2_STATE_WIDTH)
        && input.round_constants > 0
        && input.n_external_rounds > 0
        && input.n_internal_rounds > 0
        && (!input.requested_zero_copy || input.zero_copy_eligible)
}

pub fn ntt_contract_accepts(input: &NttContractInput<'_>) -> bool {
    input.height >= 2
        && input.height.is_power_of_two()
        && input.width > 0
        && input.twiddle_elements >= input.height
}

pub fn msm_contract_accepts(input: &MsmContractInput<'_>) -> bool {
    let total_buckets = (input.num_windows as usize).saturating_mul(input.num_buckets);
    input.point_count > 0
        && input.map_entries >= input.point_count.saturating_mul(input.num_windows as usize)
        && input.bucket_entries >= total_buckets.saturating_mul(12)
        && (input.window_entries == 0
            || input.window_entries >= (input.num_windows as usize).saturating_mul(12))
        && (input.final_entries == 0 || input.final_entries >= 12)
        && !(input.certified_route
            && input.curve == CurveFamily::Bn254
            && !certified_bn254_routes().contains(&input.route))
}

pub fn poseidon2_contract(
    input: Poseidon2ContractInput<'_>,
) -> Result<ValidatedDispatch, LaunchContractError> {
    let n_perms = input.state_elements / POSEIDON2_STATE_WIDTH;
    let capped_tpg = input
        .max_threads_per_group
        .clamp(1, MAX_HOST_THREADS_PER_GROUP);
    let (threadgroups_x, threads_per_group_x, total_threads, scratch_bytes) = if input.simd {
        let tpg = (capped_tpg / POSEIDON2_STATE_WIDTH) * POSEIDON2_STATE_WIDTH;
        let tpg = tpg.max(POSEIDON2_STATE_WIDTH);
        let total_threads = n_perms.saturating_mul(POSEIDON2_STATE_WIDTH);
        let groups = total_threads.div_ceil(tpg);
        (
            groups,
            tpg,
            groups.saturating_mul(tpg),
            POSEIDON2_STATE_WIDTH * input.element_bytes,
        )
    } else {
        let groups = n_perms.div_ceil(capped_tpg);
        (groups, capped_tpg, groups.saturating_mul(capped_tpg), 0)
    };

    let mut errors = Vec::new();
    if !poseidon2_contract_accepts(&input) {
        if input.state_elements == 0 {
            errors.push("state_elements must be non-zero".to_string());
        }
        if !input.state_elements.is_multiple_of(POSEIDON2_STATE_WIDTH) {
            errors.push("state_elements must be a multiple of 16".to_string());
        }
        if input.round_constants == 0 {
            errors.push("round_constants must be non-zero".to_string());
        }
        if input.n_external_rounds == 0 || input.n_internal_rounds == 0 {
            errors.push("Poseidon2 requires non-zero external and internal rounds".to_string());
        }
        if input.requested_zero_copy && !input.zero_copy_eligible {
            errors.push("zero-copy was requested on a non-page-aligned state slice".to_string());
        }
    }

    let contract = LaunchContract {
        family: KernelFamily::Poseidon2,
        kernel: input.kernel.to_string(),
        route: Some(if input.simd {
            "simd".to_string()
        } else {
            "scalar".to_string()
        }),
        field: Some(input.field),
        curve: None,
        certified_route: true,
        zero_copy: input.requested_zero_copy && input.zero_copy_eligible,
        scratch_bytes,
        dispatch: DispatchGrid {
            threadgroups_x,
            threadgroups_y: 1,
            threads_per_group_x,
            threads_per_group_y: 1,
            total_threads,
        },
        read_regions: vec![
            BufferRegion {
                name: "state".to_string(),
                elements: input.state_elements,
                element_bytes: input.element_bytes,
            },
            BufferRegion {
                name: "round_constants".to_string(),
                elements: input.round_constants,
                element_bytes: input.element_bytes,
            },
            BufferRegion {
                name: "matrix_diag".to_string(),
                elements: POSEIDON2_STATE_WIDTH,
                element_bytes: input.element_bytes,
            },
        ],
        write_regions: vec![BufferRegion {
            name: "state".to_string(),
            elements: input.state_elements,
            element_bytes: input.element_bytes,
        }],
        errors,
    };
    validate_dispatch_or_reject(contract)
}

pub fn ntt_contract(input: NttContractInput<'_>) -> Result<ValidatedDispatch, LaunchContractError> {
    let capped_tpg = input
        .max_threads_per_group
        .clamp(1, MAX_HOST_THREADS_PER_GROUP);
    let num_butterflies = input.height / 2;
    let threadgroups_x = num_butterflies.div_ceil(capped_tpg.max(1));
    let threadgroups_y = if input.batched { input.width.max(1) } else { 1 };
    let total_threads = threadgroups_x
        .saturating_mul(threadgroups_y)
        .saturating_mul(capped_tpg);
    let mut errors = Vec::new();
    if !ntt_contract_accepts(&input) {
        if input.height < 2 {
            errors.push("height must be at least 2".to_string());
        }
        if !input.height.is_power_of_two() {
            errors.push("height must be a power of two".to_string());
        }
        if input.width == 0 {
            errors.push("width must be non-zero".to_string());
        }
        if input.twiddle_elements < input.height {
            errors.push("twiddle buffer must cover at least `height` elements".to_string());
        }
    }

    let total_elements = input.height.saturating_mul(input.width);
    let contract = LaunchContract {
        family: KernelFamily::Ntt,
        kernel: input.kernel.to_string(),
        route: Some(if input.batched {
            if input.inverse {
                "inverse-batch".to_string()
            } else {
                "forward-batch".to_string()
            }
        } else if input.inverse {
            "inverse-single".to_string()
        } else {
            "forward-single".to_string()
        }),
        field: Some(input.field),
        curve: None,
        certified_route: true,
        zero_copy: false,
        scratch_bytes: 0,
        dispatch: DispatchGrid {
            threadgroups_x,
            threadgroups_y,
            threads_per_group_x: capped_tpg,
            threads_per_group_y: 1,
            total_threads,
        },
        read_regions: vec![
            BufferRegion {
                name: "values".to_string(),
                elements: total_elements,
                element_bytes: input.element_bytes,
            },
            BufferRegion {
                name: "twiddles".to_string(),
                elements: input.twiddle_elements,
                element_bytes: input.element_bytes,
            },
        ],
        write_regions: vec![BufferRegion {
            name: "values".to_string(),
            elements: total_elements,
            element_bytes: input.element_bytes,
        }],
        errors,
    };
    validate_dispatch_or_reject(contract)
}

pub fn msm_contract(input: MsmContractInput<'_>) -> Result<ValidatedDispatch, LaunchContractError> {
    let capped_tpg = input
        .max_threads_per_group
        .clamp(1, MAX_HOST_THREADS_PER_GROUP);
    let total_buckets = (input.num_windows as usize).saturating_mul(input.num_buckets);
    let dispatch_items = match input.route {
        MsmRouteClass::Classic | MsmRouteClass::Hybrid | MsmRouteClass::Tensor => total_buckets,
        MsmRouteClass::Naf => total_buckets,
        MsmRouteClass::FullGpu => total_buckets.max(1),
    };
    let threadgroups_x = dispatch_items.div_ceil(capped_tpg);
    let mut errors = Vec::new();
    if !msm_contract_accepts(&input) {
        if input.point_count == 0 {
            errors.push("point_count must be non-zero".to_string());
        }
        if input.point_count != 0
            && input.map_entries < input.point_count.saturating_mul(input.num_windows as usize)
        {
            errors.push("bucket map must cover point_count * num_windows entries".to_string());
        }
        if input.bucket_entries < total_buckets.saturating_mul(12) {
            errors.push("bucket storage must cover all projective bucket outputs".to_string());
        }
        if input.window_entries != 0
            && input.window_entries < (input.num_windows as usize).saturating_mul(12)
        {
            errors.push("window buffer must cover one projective point per window".to_string());
        }
        if input.final_entries != 0 && input.final_entries < 12 {
            errors.push("final MSM result buffer must cover one projective point".to_string());
        }
        if input.certified_route
            && !certified_bn254_routes().contains(&input.route)
            && input.curve == CurveFamily::Bn254
        {
            errors
                .push("certified BN254 route excludes hybrid/full-gpu/tensor dispatch".to_string());
        }
    }

    let contract = LaunchContract {
        family: KernelFamily::Msm,
        kernel: input.kernel.to_string(),
        route: Some(format!("{:?}", input.route).to_ascii_lowercase()),
        field: None,
        curve: Some(input.curve),
        certified_route: input.certified_route,
        zero_copy: false,
        scratch_bytes: 0,
        dispatch: DispatchGrid {
            threadgroups_x,
            threadgroups_y: 1,
            threads_per_group_x: capped_tpg,
            threads_per_group_y: 1,
            total_threads: threadgroups_x.saturating_mul(capped_tpg),
        },
        read_regions: vec![
            BufferRegion {
                name: "scalars".to_string(),
                elements: input.point_count.saturating_mul(input.scalar_limbs),
                element_bytes: std::mem::size_of::<u64>(),
            },
            BufferRegion {
                name: "bases_x".to_string(),
                elements: input
                    .point_count
                    .saturating_mul(input.base_coordinate_limbs),
                element_bytes: std::mem::size_of::<u64>(),
            },
            BufferRegion {
                name: "bases_y".to_string(),
                elements: input
                    .point_count
                    .saturating_mul(input.base_coordinate_limbs),
                element_bytes: std::mem::size_of::<u64>(),
            },
            BufferRegion {
                name: "bucket_map".to_string(),
                elements: input.map_entries,
                element_bytes: std::mem::size_of::<u32>(),
            },
        ],
        write_regions: vec![
            BufferRegion {
                name: "buckets".to_string(),
                elements: input.bucket_entries,
                element_bytes: std::mem::size_of::<u64>(),
            },
            BufferRegion {
                name: "window_results".to_string(),
                elements: input.window_entries,
                element_bytes: std::mem::size_of::<u64>(),
            },
            BufferRegion {
                name: "final_result".to_string(),
                elements: input.final_entries,
                element_bytes: std::mem::size_of::<u64>(),
            },
        ],
        errors,
    };
    validate_dispatch_or_reject(contract)
}

pub struct Poseidon2ContractInput<'a> {
    pub kernel: &'a str,
    pub field: FieldFamily,
    pub simd: bool,
    pub state_elements: usize,
    pub round_constants: usize,
    pub n_external_rounds: u32,
    pub n_internal_rounds: u32,
    pub element_bytes: usize,
    pub max_threads_per_group: usize,
    pub requested_zero_copy: bool,
    pub zero_copy_eligible: bool,
}

pub struct NttContractInput<'a> {
    pub kernel: &'a str,
    pub field: FieldFamily,
    pub height: usize,
    pub width: usize,
    pub twiddle_elements: usize,
    pub element_bytes: usize,
    pub max_threads_per_group: usize,
    pub inverse: bool,
    pub batched: bool,
}

pub struct MsmContractInput<'a> {
    pub kernel: &'a str,
    pub curve: CurveFamily,
    pub route: MsmRouteClass,
    pub point_count: usize,
    pub scalar_limbs: usize,
    pub base_coordinate_limbs: usize,
    pub map_entries: usize,
    pub bucket_entries: usize,
    pub window_entries: usize,
    pub final_entries: usize,
    pub num_windows: u32,
    pub num_buckets: usize,
    pub max_threads_per_group: usize,
    pub certified_route: bool,
}

pub fn total_region_bytes(regions: &[BufferRegion]) -> usize {
    regions.iter().map(BufferRegion::byte_len).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_contract_rejects_short_outputs() {
        let err = hash_contract("batch_sha256", 4, 64, 256, 64, 128)
            .expect_err("short digest buffers must fail");
        assert!(err.detail.contains("output bytes"));
    }

    #[test]
    fn poseidon2_simd_contract_requires_multiple_of_state_width() {
        let err = poseidon2_contract(Poseidon2ContractInput {
            kernel: "poseidon2_goldilocks_simd",
            field: FieldFamily::Goldilocks,
            simd: true,
            state_elements: 17,
            round_constants: 8,
            n_external_rounds: 8,
            n_internal_rounds: 13,
            element_bytes: 8,
            max_threads_per_group: 256,
            requested_zero_copy: false,
            zero_copy_eligible: false,
        })
        .expect_err("mis-sized state must fail");
        assert!(err.detail.contains("multiple of 16"));
    }

    #[test]
    fn ntt_contract_requires_twiddles_cover_height() {
        let err = ntt_contract(NttContractInput {
            kernel: "ntt_butterfly_goldilocks",
            field: FieldFamily::Goldilocks,
            height: 16,
            width: 1,
            twiddle_elements: 8,
            element_bytes: 8,
            max_threads_per_group: 256,
            inverse: false,
            batched: false,
        })
        .expect_err("short twiddle buffers must fail");
        assert!(err.detail.contains("twiddle buffer"));
    }

    #[test]
    fn certified_bn254_routes_exclude_hybrid_full_gpu() {
        let err = msm_contract(MsmContractInput {
            kernel: "msm_bucket_acc",
            curve: CurveFamily::Bn254,
            route: MsmRouteClass::Hybrid,
            point_count: 1024,
            scalar_limbs: 4,
            base_coordinate_limbs: 4,
            map_entries: 1024 * 4,
            bucket_entries: 4 * 16 * 12,
            window_entries: 4 * 12,
            final_entries: 12,
            num_windows: 4,
            num_buckets: 16,
            max_threads_per_group: 256,
            certified_route: true,
        })
        .expect_err("certified route must reject hybrid");
        assert!(err.detail.contains("certified BN254 route"));
    }
}
