use vstd::prelude::*;

verus! {

pub enum TrustLaneModel {
    Cryptographic,
    Attestation,
    MetadataOnly,
}

pub open spec fn weaken(lhs: TrustLaneModel, rhs: TrustLaneModel) -> TrustLaneModel {
    match (lhs, rhs) {
        (TrustLaneModel::MetadataOnly, _) | (_, TrustLaneModel::MetadataOnly) => TrustLaneModel::MetadataOnly,
        (TrustLaneModel::Attestation, _) | (_, TrustLaneModel::Attestation) => TrustLaneModel::Attestation,
        _ => TrustLaneModel::Cryptographic,
    }
}

pub struct EdgeModel {
    pub dep: int,
    pub node: int,
}

pub open spec fn trust_rank(lane: TrustLaneModel) -> nat {
    match lane {
        TrustLaneModel::Cryptographic => 0,
        TrustLaneModel::Attestation => 1,
        TrustLaneModel::MetadataOnly => 2,
    }
}

pub open spec fn unique(order: Seq<int>) -> bool {
    forall |i: int, j: int|
        0 <= i < j < order.len() as int ==> order[i] != order[j]
}

pub open spec fn node_in_output(order: Seq<int>, node: int) -> bool {
    exists |i: int| 0 <= i < order.len() as int && order[i] == node
}

pub open spec fn topological_output_complete(order: Seq<int>, node_count: nat) -> bool {
    order.len() == node_count
        && unique(order)
        && forall |node: int|
            0 <= node < node_count as int ==> node_in_output(order, node)
}

pub open spec fn edge_respected(order: Seq<int>, dep: int, node: int) -> bool {
    exists |i: int, j: int|
        0 <= i < j < order.len() as int
            && order[i] == dep
            && order[j] == node
}

pub open spec fn edges_respected(order: Seq<int>, deps: Seq<EdgeModel>) -> bool {
    forall |k: int|
        0 <= k < deps.len() as int ==> edge_respected(order, deps[k].dep, deps[k].node)
}

pub open spec fn topological_output_sound(
    order: Seq<int>,
    node_count: nat,
    deps: Seq<EdgeModel>,
) -> bool {
    topological_output_complete(order, node_count) && edges_respected(order, deps)
}

pub proof fn runtime_graph_topological_order_soundness(
    order: Seq<int>,
    node_count: nat,
    deps: Seq<EdgeModel>,
)
    requires
        topological_output_sound(order, node_count, deps),
    ensures
        topological_output_complete(order, node_count),
        edges_respected(order, deps),
        order.len() == node_count,
        unique(order),
        forall |node: int|
            0 <= node < node_count as int ==> node_in_output(order, node),
{
}

pub proof fn runtime_graph_trust_propagation_monotonicity(
    current: TrustLaneModel,
    inherited: TrustLaneModel,
)
    ensures
        trust_rank(weaken(current, inherited)) >= trust_rank(current),
        trust_rank(weaken(current, inherited)) >= trust_rank(inherited),
        weaken(current, inherited) == weaken(inherited, current),
        weaken(current, inherited) == TrustLaneModel::MetadataOnly ==> current == TrustLaneModel::MetadataOnly || inherited == TrustLaneModel::MetadataOnly,
{
}

} // verus!
