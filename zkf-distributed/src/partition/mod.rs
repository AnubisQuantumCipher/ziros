//! Graph partitioning: split a ProverGraph into distributable subgraphs.

pub mod cost_model;
pub mod strategy;

use crate::error::DistributedError;
use crate::identity::PeerId;
use crate::partition::cost_model::is_distribution_profitable;
use crate::partition::strategy::PartitionStrategy;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use zkf_runtime::graph::{ProverGraph, ProverOp};
use zkf_runtime::memory::NodeId;

/// A partition of the prover graph assigned to a single node.
#[derive(Debug, Clone)]
pub struct GraphPartition {
    pub partition_id: u32,
    pub node_ids: Vec<NodeId>,
    /// Input boundary: (buffer_slot, size_bytes) this partition needs to receive.
    pub input_boundary_slots: Vec<(u32, usize)>,
    /// Output boundary: (buffer_slot, size_bytes) this partition produces.
    pub output_boundary_slots: Vec<(u32, usize)>,
    pub estimated_work: u64,
    pub assigned_peer: Option<PeerId>,
    /// Whether this partition must stay on the coordinator.
    pub local_only: bool,
    /// Dominant phase for placement scoring.
    pub dominant_phase: u32,
}

/// Trait for partitioning a prover graph.
pub trait GraphPartitioner: Send {
    fn partition(
        &self,
        graph: &ProverGraph,
        strategy: PartitionStrategy,
    ) -> Result<Vec<GraphPartition>, DistributedError>;

    fn name(&self) -> &'static str;
}

/// Default graph partitioner implementing the PhaseBoundary strategy.
pub struct DefaultGraphPartitioner {
    pub bandwidth_gbps: f64,
    pub local_throughput_units_per_ms: f64,
}

impl DefaultGraphPartitioner {
    pub fn new() -> Self {
        Self {
            bandwidth_gbps: 80.0, // TB5 default
            local_throughput_units_per_ms: 1000.0,
        }
    }
}

impl Default for DefaultGraphPartitioner {
    fn default() -> Self {
        Self::new()
    }
}

/// Classify a ProverOp into a phase bucket.
/// P0: Witness, P1: NTT/LDE, P2: MSM, P3: Hash/Commit, P4: FRI,
/// P5: Backend, P6: Finalize.
fn classify_phase(op: &ProverOp) -> u32 {
    match op {
        ProverOp::WitnessSolve { .. }
        | ProverOp::BooleanizeSignals { .. }
        | ProverOp::RangeCheckExpand { .. }
        | ProverOp::LookupExpand { .. } => 0,
        ProverOp::Ntt { .. } | ProverOp::Lde { .. } => 1,
        ProverOp::Msm { .. } => 2,
        ProverOp::PoseidonBatch { .. }
        | ProverOp::Sha256Batch { .. }
        | ProverOp::MerkleLayer { .. } => 3,
        ProverOp::FriFold { .. } | ProverOp::FriQueryOpen { .. } => 4,
        ProverOp::BackendProve { .. }
        | ProverOp::BackendFold { .. }
        | ProverOp::OuterProve { .. } => 5,
        ProverOp::TranscriptUpdate | ProverOp::ProofEncode | ProverOp::VerifierEmbed { .. } => 6,
        ProverOp::Barrier { .. } | ProverOp::Noop => 6,
    }
}

impl GraphPartitioner for DefaultGraphPartitioner {
    fn partition(
        &self,
        graph: &ProverGraph,
        strategy: PartitionStrategy,
    ) -> Result<Vec<GraphPartition>, DistributedError> {
        match strategy {
            PartitionStrategy::None => {
                // Single partition: everything local.
                let all_ids: Vec<NodeId> = graph.topological_order().unwrap_or_default();
                Ok(vec![GraphPartition {
                    partition_id: 0,
                    node_ids: all_ids,
                    input_boundary_slots: Vec::new(),
                    output_boundary_slots: Vec::new(),
                    estimated_work: graph.node_count() as u64,
                    assigned_peer: None,
                    local_only: true,
                    dominant_phase: 0,
                }])
            }
            PartitionStrategy::PhaseBoundary => self.partition_by_phase(graph),
            PartitionStrategy::PlacementAffinity | PartitionStrategy::Balanced => {
                // Fall back to phase boundary for now.
                self.partition_by_phase(graph)
            }
        }
    }

    fn name(&self) -> &'static str {
        "default-phase-boundary"
    }
}

impl DefaultGraphPartitioner {
    fn partition_by_phase(
        &self,
        graph: &ProverGraph,
    ) -> Result<Vec<GraphPartition>, DistributedError> {
        let topo = graph.topological_order().unwrap_or_default();

        let mut partitions = Vec::new();
        let mut partition_id = 0u32;
        let mut current_phase = None;
        let mut current_nodes = Vec::new();

        for node_id in topo {
            let Some(node) = graph.node(node_id) else {
                continue;
            };
            let phase = classify_phase(&node.op);
            if current_phase == Some(phase) {
                current_nodes.push(node_id);
                continue;
            }

            if let Some(prev_phase) = current_phase.take()
                && !current_nodes.is_empty()
            {
                let estimated_work = current_nodes.len() as u64;
                partitions.push(GraphPartition {
                    partition_id,
                    node_ids: std::mem::take(&mut current_nodes),
                    input_boundary_slots: Vec::new(),
                    output_boundary_slots: Vec::new(),
                    estimated_work,
                    assigned_peer: None,
                    local_only: prev_phase == 0 || prev_phase == 6,
                    dominant_phase: prev_phase,
                });
                partition_id += 1;
            }

            current_phase = Some(phase);
            current_nodes.push(node_id);
        }

        if let Some(phase) = current_phase
            && !current_nodes.is_empty()
        {
            partitions.push(GraphPartition {
                partition_id,
                estimated_work: current_nodes.len() as u64,
                node_ids: current_nodes,
                input_boundary_slots: Vec::new(),
                output_boundary_slots: Vec::new(),
                assigned_peer: None,
                local_only: phase == 0 || phase == 6,
                dominant_phase: phase,
            });
        }

        // Merge adjacent partitions where transfer cost exceeds savings.
        let with_boundaries = assign_boundary_slots(graph, partitions);
        let merged = self.merge_unprofitable(with_boundaries);

        Ok(assign_boundary_slots(graph, merged))
    }

    fn merge_unprofitable(&self, partitions: Vec<GraphPartition>) -> Vec<GraphPartition> {
        if partitions.len() <= 1 {
            return partitions;
        }

        let mut result: Vec<GraphPartition> = Vec::new();
        let mut current = partitions.into_iter();

        if let Some(first) = current.next() {
            let mut acc = first;

            for next in current {
                let boundary_bytes: usize = acc
                    .output_boundary_slots
                    .iter()
                    .chain(next.input_boundary_slots.iter())
                    .map(|&(_, sz)| sz)
                    .sum();

                let profitable = is_distribution_profitable(
                    next.estimated_work,
                    boundary_bytes,
                    self.bandwidth_gbps,
                    self.local_throughput_units_per_ms,
                );

                if !profitable && !acc.local_only && !next.local_only {
                    // Merge: combine nodes into accumulator.
                    acc.node_ids.extend(next.node_ids);
                    acc.output_boundary_slots = next.output_boundary_slots;
                    acc.estimated_work += next.estimated_work;
                } else {
                    result.push(acc);
                    acc = next;
                }
            }
            result.push(acc);
        }

        result
    }
}

fn assign_boundary_slots(
    graph: &ProverGraph,
    mut partitions: Vec<GraphPartition>,
) -> Vec<GraphPartition> {
    for (index, partition) in partitions.iter_mut().enumerate() {
        partition.partition_id = index as u32;
        partition.input_boundary_slots.clear();
        partition.output_boundary_slots.clear();
    }

    let mut producer_by_slot: HashMap<u32, (usize, usize)> = HashMap::new();
    let mut consumers_by_slot: BTreeMap<u32, BTreeSet<usize>> = BTreeMap::new();
    let mut slot_sizes: BTreeMap<u32, usize> = BTreeMap::new();

    for (partition_index, partition) in partitions.iter().enumerate() {
        for &node_id in &partition.node_ids {
            let Some(node) = graph.node(node_id) else {
                continue;
            };
            for handle in &node.output_buffers {
                producer_by_slot.insert(handle.slot, (partition_index, handle.size_bytes));
                slot_sizes.insert(handle.slot, handle.size_bytes);
            }
            for handle in &node.input_buffers {
                consumers_by_slot
                    .entry(handle.slot)
                    .or_default()
                    .insert(partition_index);
                slot_sizes.entry(handle.slot).or_insert(handle.size_bytes);
            }
        }
    }

    let mut input_boundaries: Vec<BTreeMap<u32, usize>> = vec![BTreeMap::new(); partitions.len()];
    let mut output_boundaries: Vec<BTreeMap<u32, usize>> = vec![BTreeMap::new(); partitions.len()];

    for (&slot, consumers) in &consumers_by_slot {
        let Some(&size_bytes) = slot_sizes.get(&slot) else {
            continue;
        };
        match producer_by_slot.get(&slot).copied() {
            Some((producer_partition, _)) => {
                let crosses_partition = consumers
                    .iter()
                    .any(|&consumer_partition| consumer_partition != producer_partition);
                if crosses_partition {
                    output_boundaries[producer_partition].insert(slot, size_bytes);
                    for &consumer_partition in consumers {
                        if consumer_partition != producer_partition {
                            input_boundaries[consumer_partition].insert(slot, size_bytes);
                        }
                    }
                }
            }
            None => {
                for &consumer_partition in consumers {
                    input_boundaries[consumer_partition].insert(slot, size_bytes);
                }
            }
        }
    }

    for (&slot, (producer_partition, producer_size)) in &producer_by_slot {
        let size_bytes = slot_sizes.get(&slot).copied().unwrap_or(*producer_size);
        if consumers_by_slot
            .get(&slot)
            .is_none_or(|consumers| consumers.is_empty())
        {
            output_boundaries[*producer_partition].insert(slot, size_bytes);
        }
    }

    for (index, partition) in partitions.iter_mut().enumerate() {
        partition.input_boundary_slots = input_boundaries[index].iter().map(copy_slot).collect();
        partition.output_boundary_slots = output_boundaries[index].iter().map(copy_slot).collect();
    }

    partitions
}

fn copy_slot((slot, size_bytes): (&u32, &usize)) -> (u32, usize) {
    (*slot, *size_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_runtime::memory::{BufferHandle, MemoryClass};

    fn scratch(slot: u32, size_bytes: usize) -> BufferHandle {
        BufferHandle {
            slot,
            size_bytes,
            class: MemoryClass::EphemeralScratch,
        }
    }

    #[test]
    fn classify_phase_witness() {
        let op = ProverOp::WitnessSolve {
            constraint_count: 100,
            signal_count: 50,
        };
        assert_eq!(classify_phase(&op), 0);
    }

    #[test]
    fn classify_phase_ntt() {
        let op = ProverOp::Ntt {
            size: 1024,
            field: "bn254",
            inverse: false,
        };
        assert_eq!(classify_phase(&op), 1);
    }

    #[test]
    fn classify_phase_fri() {
        let op = ProverOp::FriFold {
            folding_factor: 2,
            codeword_len: 4096,
        };
        assert_eq!(classify_phase(&op), 4);
    }

    #[test]
    fn classify_phase_finalize() {
        assert_eq!(classify_phase(&ProverOp::ProofEncode), 6);
        assert_eq!(classify_phase(&ProverOp::TranscriptUpdate), 6);
    }

    #[test]
    fn single_partition_strategy_none() {
        let graph = ProverGraph::new();
        let partitioner = DefaultGraphPartitioner::new();
        let partitions = partitioner
            .partition(&graph, PartitionStrategy::None)
            .unwrap();
        assert_eq!(partitions.len(), 1);
        assert!(partitions[0].local_only);
    }

    #[test]
    fn phase_boundary_partition_tracks_cross_partition_buffers() {
        let mut graph = ProverGraph::new();
        let witness = graph.add_node(
            zkf_runtime::graph::ProverNode::new(ProverOp::WitnessSolve {
                constraint_count: 4,
                signal_count: 2,
            })
            .with_outputs([scratch(10, 64)]),
        );
        let ntt = graph.add_node(
            zkf_runtime::graph::ProverNode::new(ProverOp::Ntt {
                size: 1024,
                field: "bn254",
                inverse: false,
            })
            .with_inputs([scratch(10, 64)])
            .with_outputs([scratch(20, 128)]),
        );
        let msm = graph.add_node(
            zkf_runtime::graph::ProverNode::new(ProverOp::Msm {
                num_scalars: 256,
                curve: "bn254",
            })
            .with_inputs([scratch(20, 128)])
            .with_outputs([scratch(30, 96)]),
        );
        let finalize = graph.add_node(
            zkf_runtime::graph::ProverNode::new(ProverOp::ProofEncode)
                .with_inputs([scratch(30, 96)])
                .with_outputs([scratch(40, 48)]),
        );

        graph.add_dep(witness, ntt);
        graph.add_dep(ntt, msm);
        graph.add_dep(msm, finalize);

        let partitions = DefaultGraphPartitioner::new()
            .partition(&graph, PartitionStrategy::PhaseBoundary)
            .unwrap();

        assert_eq!(partitions.len(), 4);
        assert_eq!(partitions[0].output_boundary_slots, vec![(10, 64)]);
        assert_eq!(partitions[1].input_boundary_slots, vec![(10, 64)]);
        assert_eq!(partitions[1].output_boundary_slots, vec![(20, 128)]);
        assert_eq!(partitions[2].input_boundary_slots, vec![(20, 128)]);
        assert_eq!(partitions[2].output_boundary_slots, vec![(30, 96)]);
        assert_eq!(partitions[3].input_boundary_slots, vec![(30, 96)]);
        assert_eq!(partitions[3].output_boundary_slots, vec![(40, 48)]);
    }

    #[test]
    fn phase_boundary_partition_marks_initial_inputs_as_boundary_slots() {
        let mut graph = ProverGraph::new();
        graph.add_node(
            zkf_runtime::graph::ProverNode::new(ProverOp::Ntt {
                size: 512,
                field: "bn254",
                inverse: false,
            })
            .with_inputs([scratch(77, 256)])
            .with_outputs([scratch(88, 256)]),
        );

        let partitions = DefaultGraphPartitioner::new()
            .partition(&graph, PartitionStrategy::PhaseBoundary)
            .unwrap();

        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].input_boundary_slots, vec![(77, 256)]);
        assert_eq!(partitions[0].output_boundary_slots, vec![(88, 256)]);
    }
}
