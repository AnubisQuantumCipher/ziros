use vstd::prelude::*;

verus! {

pub open spec fn max_host_threads_per_group() -> nat { 256 }
pub open spec fn digest_bytes() -> nat { 32 }
pub open spec fn poseidon2_state_width() -> nat { 16 }

pub enum KernelFamilyModel {
    Hash,
    Poseidon2,
    Ntt,
    Msm,
}

pub enum FieldFamilyModel {
    Bytes,
    Goldilocks,
    BabyBear,
    Bn254Scalar,
    PallasScalar,
    VestaScalar,
}

pub enum CurveFamilyModel {
    Bn254,
    Pallas,
    Vesta,
}

pub enum MsmRouteModel {
    Classic,
    Naf,
    Hybrid,
    FullGpu,
    Tensor,
}

pub struct DispatchGridModel {
    pub threadgroups_x: nat,
    pub threadgroups_y: nat,
    pub threads_per_group_x: nat,
    pub threads_per_group_y: nat,
    pub total_threads: nat,
}

pub struct BufferRegionModel {
    pub elements: nat,
    pub element_bytes: nat,
}

pub struct ValidatedDispatchModel {
    pub family: KernelFamilyModel,
    pub field: Option<FieldFamilyModel>,
    pub curve: Option<CurveFamilyModel>,
    pub route: Option<MsmRouteModel>,
    pub certified_route: bool,
    pub zero_copy: bool,
    pub scratch_bytes: nat,
    pub dispatch: DispatchGridModel,
    pub read_regions: Seq<BufferRegionModel>,
    pub write_regions: Seq<BufferRegionModel>,
}

pub struct HashContractInputModel {
    pub batch_count: nat,
    pub input_len: nat,
    pub input_bytes: nat,
    pub output_bytes: nat,
    pub max_threads_per_group: nat,
}

pub struct Poseidon2ContractInputModel {
    pub field: FieldFamilyModel,
    pub simd: bool,
    pub state_elements: nat,
    pub round_constants: nat,
    pub n_external_rounds: nat,
    pub n_internal_rounds: nat,
    pub element_bytes: nat,
    pub max_threads_per_group: nat,
    pub requested_zero_copy: bool,
    pub zero_copy_eligible: bool,
}

pub struct NttContractInputModel {
    pub field: FieldFamilyModel,
    pub height: nat,
    pub width: nat,
    pub twiddle_elements: nat,
    pub element_bytes: nat,
    pub max_threads_per_group: nat,
    pub inverse: bool,
    pub batched: bool,
}

pub struct MsmContractInputModel {
    pub curve: CurveFamilyModel,
    pub route: MsmRouteModel,
    pub point_count: nat,
    pub scalar_limbs: nat,
    pub base_coordinate_limbs: nat,
    pub map_entries: nat,
    pub bucket_entries: nat,
    pub window_entries: nat,
    pub final_entries: nat,
    pub num_windows: nat,
    pub num_buckets: nat,
    pub max_threads_per_group: nat,
    pub certified_route: bool,
}

pub open spec fn div_ceil_nat(lhs: nat, rhs: nat) -> nat {
    if rhs == 0 as nat { 0 as nat } else { (((lhs as int) + (rhs as int) - 1) / (rhs as int)) as nat }
}

pub open spec fn pow2_nat(exp: nat) -> nat
    decreases exp
{
    if exp == 0 as nat { 1 as nat } else { (2 * pow2_nat((exp - 1) as nat)) as nat }
}

pub open spec fn cap_threads(max_threads: nat) -> nat {
    if max_threads < 1 as nat {
        1 as nat
    } else if max_threads > max_host_threads_per_group() {
        max_host_threads_per_group()
    } else {
        max_threads
    }
}

pub open spec fn region_bytes(region: BufferRegionModel) -> nat {
    region.elements * region.element_bytes
}

pub open spec fn grid_nonzero(grid: DispatchGridModel) -> bool {
    &&& grid.threadgroups_x > 0
    &&& grid.threadgroups_y > 0
    &&& grid.threads_per_group_x > 0
    &&& grid.threads_per_group_y > 0
}

pub open spec fn certified_bn254_route_ok(route: MsmRouteModel) -> bool {
    matches!(route, MsmRouteModel::Classic)
}

pub open spec fn certified_dispatch_route_ok(dispatch: ValidatedDispatchModel) -> bool {
    if !dispatch.certified_route {
        true
    } else {
        match dispatch.curve {
            Option::Some(CurveFamilyModel::Bn254) =>
                match dispatch.route {
                    Option::Some(route) => certified_bn254_route_ok(route),
                    Option::None => false,
                },
            _ => true,
        }
    }
}

pub open spec fn validated_dispatch_ok(dispatch: ValidatedDispatchModel) -> bool {
    &&& grid_nonzero(dispatch.dispatch)
    &&& dispatch.read_regions.len() > 0
    &&& dispatch.write_regions.len() > 0
    &&& certified_dispatch_route_ok(dispatch)
}

pub open spec fn hash_contract_accepts(input: HashContractInputModel) -> bool {
    &&& input.batch_count > 0
    &&& input.input_len > 0
    &&& input.batch_count * input.input_len == input.input_bytes
    &&& input.batch_count * digest_bytes() == input.output_bytes
}

pub open spec fn validated_hash_dispatch(input: HashContractInputModel) -> ValidatedDispatchModel {
    let threads = cap_threads(input.max_threads_per_group);
    let groups = div_ceil_nat(input.batch_count, threads);
    ValidatedDispatchModel {
        family: KernelFamilyModel::Hash,
        field: Option::Some(FieldFamilyModel::Bytes),
        curve: Option::None,
        route: Option::None,
        certified_route: true,
        zero_copy: false,
        scratch_bytes: 0,
        dispatch: DispatchGridModel {
            threadgroups_x: groups,
            threadgroups_y: 1,
            threads_per_group_x: threads,
            threads_per_group_y: 1,
            total_threads: groups * threads,
        },
        read_regions: seq![BufferRegionModel { elements: input.input_bytes, element_bytes: 1 }],
        write_regions: seq![BufferRegionModel { elements: input.output_bytes, element_bytes: 1 }],
    }
}

pub open spec fn poseidon2_contract_accepts(input: Poseidon2ContractInputModel) -> bool {
    &&& input.state_elements > 0
    &&& input.state_elements % poseidon2_state_width() == 0
    &&& input.round_constants > 0
    &&& input.n_external_rounds > 0
    &&& input.n_internal_rounds > 0
    &&& (!input.requested_zero_copy || input.zero_copy_eligible)
}

pub open spec fn validated_poseidon2_dispatch(input: Poseidon2ContractInputModel) -> ValidatedDispatchModel {
    let capped = cap_threads(input.max_threads_per_group);
    let perms = input.state_elements / poseidon2_state_width();
    let threads = if input.simd {
        if (capped / poseidon2_state_width()) * poseidon2_state_width() < poseidon2_state_width() {
            poseidon2_state_width()
        } else {
            (capped / poseidon2_state_width()) * poseidon2_state_width()
        }
    } else {
        capped
    };
    let total_threads = if input.simd { perms * poseidon2_state_width() } else { perms };
    let groups = div_ceil_nat(total_threads, threads);
    ValidatedDispatchModel {
        family: KernelFamilyModel::Poseidon2,
        field: Option::Some(input.field),
        curve: Option::None,
        route: Option::None,
        certified_route: true,
        zero_copy: input.requested_zero_copy && input.zero_copy_eligible,
        scratch_bytes: if input.simd { poseidon2_state_width() * input.element_bytes } else { 0 },
        dispatch: DispatchGridModel {
            threadgroups_x: groups,
            threadgroups_y: 1,
            threads_per_group_x: threads,
            threads_per_group_y: 1,
            total_threads: groups * threads,
        },
        read_regions: seq![
            BufferRegionModel { elements: input.state_elements, element_bytes: input.element_bytes },
            BufferRegionModel { elements: input.round_constants, element_bytes: input.element_bytes },
            BufferRegionModel { elements: poseidon2_state_width(), element_bytes: input.element_bytes }
        ],
        write_regions: seq![
            BufferRegionModel { elements: input.state_elements, element_bytes: input.element_bytes }
        ],
    }
}

pub open spec fn ntt_contract_accepts(input: NttContractInputModel) -> bool {
    &&& input.height >= 2
    &&& exists|k: nat| input.height == pow2_nat(k)
    &&& input.width > 0
    &&& input.twiddle_elements >= input.height
}

pub open spec fn validated_ntt_dispatch(input: NttContractInputModel) -> ValidatedDispatchModel {
    let capped = cap_threads(input.max_threads_per_group);
    let butterflies = input.height / 2;
    let groups_x = div_ceil_nat(butterflies, capped);
    let groups_y = if input.batched { input.width } else { 1 };
    ValidatedDispatchModel {
        family: KernelFamilyModel::Ntt,
        field: Option::Some(input.field),
        curve: Option::None,
        route: Option::None,
        certified_route: true,
        zero_copy: false,
        scratch_bytes: 0,
        dispatch: DispatchGridModel {
            threadgroups_x: groups_x,
            threadgroups_y: groups_y,
            threads_per_group_x: capped,
            threads_per_group_y: 1,
            total_threads: groups_x * groups_y * capped,
        },
        read_regions: seq![
            BufferRegionModel { elements: input.height * input.width, element_bytes: input.element_bytes },
            BufferRegionModel { elements: input.twiddle_elements, element_bytes: input.element_bytes }
        ],
        write_regions: seq![
            BufferRegionModel { elements: input.height * input.width, element_bytes: input.element_bytes }
        ],
    }
}

pub open spec fn msm_contract_accepts(input: MsmContractInputModel) -> bool {
    let total_buckets = input.num_windows * input.num_buckets;
    &&& input.point_count > 0
    &&& input.map_entries >= input.point_count * input.num_windows
    &&& input.bucket_entries >= total_buckets * 12
    &&& (input.window_entries == 0 || input.window_entries >= input.num_windows * 12)
    &&& (input.final_entries == 0 || input.final_entries >= 12)
    &&& !(input.certified_route
        && input.curve == CurveFamilyModel::Bn254
        && !certified_bn254_route_ok(input.route))
}

pub open spec fn validated_msm_dispatch(input: MsmContractInputModel) -> ValidatedDispatchModel {
    let capped = cap_threads(input.max_threads_per_group);
    let dispatch_items = input.num_windows * input.num_buckets;
    let groups = div_ceil_nat(dispatch_items, capped);
    ValidatedDispatchModel {
        family: KernelFamilyModel::Msm,
        field: Option::None,
        curve: Option::Some(input.curve),
        route: Option::Some(input.route),
        certified_route: input.certified_route,
        zero_copy: false,
        scratch_bytes: 0,
        dispatch: DispatchGridModel {
            threadgroups_x: groups,
            threadgroups_y: 1,
            threads_per_group_x: capped,
            threads_per_group_y: 1,
            total_threads: groups * capped,
        },
        read_regions: seq![
            BufferRegionModel { elements: input.point_count * input.scalar_limbs, element_bytes: 8 },
            BufferRegionModel { elements: input.point_count * input.base_coordinate_limbs, element_bytes: 8 },
            BufferRegionModel { elements: input.point_count * input.base_coordinate_limbs, element_bytes: 8 },
            BufferRegionModel { elements: input.map_entries, element_bytes: 4 }
        ],
        write_regions: seq![
            BufferRegionModel { elements: input.bucket_entries, element_bytes: 8 },
            BufferRegionModel { elements: input.window_entries, element_bytes: 8 },
            BufferRegionModel { elements: input.final_entries, element_bytes: 8 }
        ],
    }
}

pub proof fn hash_accepts_implies_validated_surface(input: HashContractInputModel)
    requires
        hash_contract_accepts(input),
    ensures
        validated_hash_dispatch(input).read_regions[0].elements == input.input_bytes,
        validated_hash_dispatch(input).write_regions[0].elements == input.output_bytes,
{
}

pub proof fn poseidon2_accepts_implies_validated_surface(input: Poseidon2ContractInputModel)
    requires
        poseidon2_contract_accepts(input),
    ensures
        validated_poseidon2_dispatch(input).read_regions[0].elements == input.state_elements,
        validated_poseidon2_dispatch(input).write_regions[0].elements == input.state_elements,
        input.simd ==> validated_poseidon2_dispatch(input).scratch_bytes == poseidon2_state_width() * input.element_bytes,
{
}

pub proof fn ntt_accepts_implies_validated_surface(input: NttContractInputModel)
    requires
        ntt_contract_accepts(input),
    ensures
        validated_ntt_dispatch(input).read_regions[0].elements == input.height * input.width,
        validated_ntt_dispatch(input).write_regions[0].elements == input.height * input.width,
{
}

pub proof fn msm_accepts_implies_validated_surface(input: MsmContractInputModel)
    requires
        msm_contract_accepts(input),
    ensures
        validated_msm_dispatch(input).read_regions[3].elements == input.map_entries,
        validated_msm_dispatch(input).write_regions[0].elements == input.bucket_entries,
{
}

}
