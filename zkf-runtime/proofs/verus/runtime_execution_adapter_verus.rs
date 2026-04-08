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

pub open spec fn max_nat(lhs: nat, rhs: nat) -> nat {
    if lhs >= rhs { lhs } else { rhs }
}

pub open spec fn min_nat(lhs: nat, rhs: nat) -> nat {
    if lhs <= rhs { lhs } else { rhs }
}

pub open spec fn clamp_nat(value: nat, lower: nat, upper: nat) -> nat {
    min_nat(max_nat(value, lower), upper)
}

pub open spec fn unique(slots: Seq<int>) -> bool {
    forall |i: int, j: int|
        0 <= i < j < slots.len() as int ==> slots[i] != slots[j]
}

pub open spec fn backend_prove_slot_plan() -> Seq<int> {
    seq![0, 1, 2, 3]
}

pub open spec fn wrapper_slot_plan() -> Seq<int> {
    seq![0, 1, 2, 3, 4]
}

pub open spec fn backend_dependency_order(slots: Seq<int>) -> bool {
    slots.len() == 4
        && slots[0] < slots[1]
        && slots[1] < slots[2]
        && slots[2] < slots[3]
}

pub open spec fn wrapper_dependency_order(slots: Seq<int>) -> bool {
    slots.len() == 5
        && slots[0] < slots[1]
        && slots[1] < slots[2]
        && slots[2] < slots[3]
        && slots[3] < slots[4]
}

pub open spec fn delegated_backend_artifact_bytes(
    backend: BackendKindModel,
    constraints: nat,
) -> nat {
    let base = match backend {
        BackendKindModel::ArkworksGroth16
        | BackendKindModel::Halo2
        | BackendKindModel::Halo2Bls12381 => 512 * 1024,
        BackendKindModel::Plonky3 => 8 * 1024 * 1024,
        BackendKindModel::Nova => 4 * 1024 * 1024,
        BackendKindModel::HyperNova => 48 * 1024 * 1024,
        BackendKindModel::Sp1
        | BackendKindModel::RiscZero
        | BackendKindModel::MidnightCompact => 2 * 1024 * 1024,
    };
    let upper = match backend {
        BackendKindModel::Plonky3 => 64 * 1024 * 1024,
        BackendKindModel::HyperNova => 128 * 1024 * 1024,
        _ => 16 * 1024 * 1024,
    };
    clamp_nat(max_nat(base, constraints * 64), 256 * 1024, upper)
}

pub open spec fn backend_witness_bytes(signal_count: nat) -> nat {
    signal_count * 32
}

pub open spec fn backend_transcript_bytes() -> nat {
    32
}

pub open spec fn backend_prove_bytes() -> nat {
    32
}

pub open spec fn wrapper_working_bytes(
    has_estimated_memory: bool,
    estimated_memory_bytes: nat,
) -> nat {
    max_nat(if has_estimated_memory { estimated_memory_bytes } else { 64 * 1024 * 1024 }, 4 * 1024 * 1024)
}

pub open spec fn wrapper_source_bytes(
    has_estimated_memory: bool,
    estimated_memory_bytes: nat,
) -> nat {
    max_nat(wrapper_working_bytes(has_estimated_memory, estimated_memory_bytes) / 4, 64 * 1024)
}

pub open spec fn wrapper_verifier_bytes() -> nat {
    2048
}

pub open spec fn wrapper_proof_bytes() -> nat {
    4096
}

pub proof fn runtime_adapter_backend_graph_emission(
    signal_count: nat,
    constraints: nat,
    backend: BackendKindModel,
)
    requires
        signal_count > 0,
        constraints > 0,
    ensures
        backend_witness_bytes(signal_count) > 0,
        backend_transcript_bytes() == 32,
        backend_prove_bytes() == 32,
        delegated_backend_artifact_bytes(backend, constraints) >= 256 * 1024,
        delegated_backend_artifact_bytes(backend, constraints)
            <= if backend == BackendKindModel::HyperNova {
                128 * 1024 * 1024
            } else if backend == BackendKindModel::Plonky3 {
                64 * 1024 * 1024
            } else {
                16 * 1024 * 1024
            },
        unique(backend_prove_slot_plan()),
        backend_dependency_order(backend_prove_slot_plan()),
{
}

pub proof fn runtime_adapter_wrapper_graph_emission(
    estimated_constraints: nat,
    has_estimated_memory: bool,
    estimated_memory_bytes: nat,
)
    requires
        estimated_constraints > 0,
    ensures
        wrapper_working_bytes(has_estimated_memory, estimated_memory_bytes) >= 4 * 1024 * 1024,
        wrapper_source_bytes(has_estimated_memory, estimated_memory_bytes) >= 64 * 1024,
        wrapper_verifier_bytes() == 2048,
        wrapper_proof_bytes() == 4096,
        unique(wrapper_slot_plan()),
        wrapper_dependency_order(wrapper_slot_plan()),
{
}

} // verus!
