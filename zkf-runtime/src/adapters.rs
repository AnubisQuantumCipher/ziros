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

//! Backend graph adapter trait and reference implementations.

use crate::adapter_core;
use crate::error::RuntimeError;
use crate::execution::{ExecutionContext, NodePayload, ProofOutputKind};
use crate::graph::{ProverGraph, ProverNode, ProverOp};
use crate::memory::{MemoryClass, UnifiedBufferPool};
use crate::trust::TrustModel;
use std::sync::Arc;
use zkf_backends::BackendRoute;
use zkf_core::Witness;
use zkf_core::artifact::{BackendKind, CompiledProgram};
use zkf_core::ir::Program;
use zkf_core::witness::WitnessInputs;
use zkf_core::wrapping::WrapperPreview;

/// Parameters describing the size and field of a proving job.
#[derive(Debug, Clone)]
pub struct GraphParams {
    pub constraint_count: usize,
    pub field: &'static str,
    pub deterministic: bool,
    pub declared_trust: TrustModel,
}

/// Result of graph emission: both topology and execution payloads.
pub struct GraphEmission {
    pub graph: ProverGraph,
    pub exec_ctx: ExecutionContext,
}

fn deterministic_bn254_bases_bytes(count: usize) -> Vec<u8> {
    #[cfg(feature = "cpu-backends")]
    {
        use ark_bn254::{Fr, G1Projective};
        use ark_ec::{CurveGroup, PrimeGroup};
        use ark_ff::PrimeField;
        use ark_serialize::CanonicalSerialize;

        let generator = G1Projective::generator();
        let mut bytes = Vec::with_capacity(count * 32);
        for i in 0..count {
            let scalar = Fr::from((i as u64) + 1);
            let point = generator.mul_bigint(scalar.into_bigint()).into_affine();
            if point.serialize_compressed(&mut bytes).is_err() {
                return vec![0u8; count * 32];
            }
        }
        bytes
    }

    #[cfg(not(feature = "cpu-backends"))]
    {
        vec![0u8; count * 32]
    }
}

fn goldilocks_u64_bytes(values: impl IntoIterator<Item = u64>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

/// Trait that each ZK backend implements to expose its work as a graph.
pub trait GraphAdapter: Send + Sync {
    fn backend_name(&self) -> &str;
    fn emit_graph(
        &self,
        pool: &mut UnifiedBufferPool,
        params: &GraphParams,
    ) -> Result<ProverGraph, RuntimeError>;

    /// Emit graph with execution payloads attached.
    /// Default implementation calls `emit_graph` and returns an empty context.
    fn emit_graph_with_context(
        &self,
        pool: &mut UnifiedBufferPool,
        params: &GraphParams,
        program: Option<Arc<Program>>,
        inputs: Option<Arc<WitnessInputs>>,
    ) -> Result<GraphEmission, RuntimeError> {
        let graph = self.emit_graph(pool, params)?;
        let mut exec_ctx = ExecutionContext::new();
        if let Some(p) = program {
            exec_ctx.program = Some(p);
        }
        if let Some(i) = inputs {
            exec_ctx.witness_inputs = Some(i);
        }
        Ok(GraphEmission { graph, exec_ctx })
    }
}

/// Backwards-compatible alias for GraphAdapter.
pub type BackendGraphAdapter = dyn GraphAdapter;

fn backend_kind_name(kind: zkf_core::BackendKind) -> &'static str {
    adapter_core::backend_kind_name(kind)
}

#[allow(clippy::too_many_arguments)]
pub fn emit_backend_prove_graph_with_context(
    pool: &mut UnifiedBufferPool,
    backend: BackendKind,
    route: BackendRoute,
    program: Arc<Program>,
    inputs: Option<Arc<WitnessInputs>>,
    witness: Option<Arc<Witness>>,
    declared_trust: TrustModel,
    deterministic: bool,
) -> Result<GraphEmission, RuntimeError> {
    let spec = adapter_core::backend_prove_graph_spec(
        program.signals.len().max(1),
        program.constraints.len().max(1),
        backend,
    );
    let mut g = ProverGraph::new();
    let mut exec_ctx = ExecutionContext::new().with_program(Arc::clone(&program));
    if let Some(inputs) = inputs {
        exec_ctx = exec_ctx.with_inputs(inputs);
    }
    if let Some(witness) = witness {
        exec_ctx = exec_ctx.with_witness(witness);
    }

    let witness_buf = pool
        .alloc(spec.witness_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.witness_bytes,
        })?;
    let mut witness_node = ProverNode::new(ProverOp::WitnessSolve {
        constraint_count: spec.constraints,
        signal_count: spec.signal_count,
    })
    .with_outputs([witness_buf])
    .with_trust(declared_trust);
    if deterministic {
        witness_node = witness_node.deterministic();
    }
    let witness_id = g.add_node(witness_node);
    if let (Some(payload_program), Some(payload_inputs)) =
        (&exec_ctx.program, &exec_ctx.witness_inputs)
    {
        exec_ctx.set_payload(
            witness_id,
            NodePayload::WitnessSolve {
                program: Arc::clone(payload_program),
                inputs: Arc::clone(payload_inputs),
            },
        );
    } else {
        exec_ctx.set_payload(witness_id, NodePayload::Noop);
    }

    let transcript_buf = pool
        .alloc(spec.transcript_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.transcript_bytes,
        })?;
    let mut transcript = ProverNode::new(ProverOp::TranscriptUpdate)
        .with_deps([witness_id])
        .with_inputs([witness_buf])
        .with_outputs([transcript_buf])
        .with_trust(declared_trust);
    if deterministic {
        transcript = transcript.deterministic();
    }
    let transcript_id = g.add_node(transcript);
    exec_ctx.set_payload(
        transcript_id,
        NodePayload::TranscriptUpdate {
            state_slot: witness_buf.slot,
        },
    );

    let prove_buf = pool
        .alloc(spec.prove_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.prove_bytes,
        })?;
    let mut backend_prove = ProverNode::new(ProverOp::BackendProve {
        backend: backend.as_str(),
    })
    .with_deps([transcript_id])
    .with_inputs([transcript_buf])
    .with_outputs([prove_buf])
    .with_trust(declared_trust);
    if deterministic {
        backend_prove = backend_prove.deterministic();
    }
    let backend_prove_id = g.add_node(backend_prove);
    exec_ctx.set_payload(
        backend_prove_id,
        NodePayload::BackendProve {
            backend: backend.as_str().to_string(),
            route,
            transcript_slot: transcript_buf.slot,
        },
    );

    let artifact_buf = pool
        .alloc(spec.artifact_bytes, MemoryClass::Spillable)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.artifact_bytes,
        })?;
    let mut encode = ProverNode::new(ProverOp::ProofEncode)
        .with_deps([backend_prove_id])
        .with_outputs([artifact_buf])
        .with_trust(declared_trust);
    if deterministic {
        encode = encode.deterministic();
    }
    let encode_id = g.add_node(encode);
    exec_ctx.set_payload(
        encode_id,
        NodePayload::ProofEncode {
            input_slots: Vec::new(),
            output_kind: ProofOutputKind::BackendArtifact,
        },
    );

    Ok(GraphEmission { graph: g, exec_ctx })
}

pub fn emit_backend_fold_graph_with_context(
    pool: &mut UnifiedBufferPool,
    compiled: Arc<CompiledProgram>,
    witnesses: Arc<Vec<Witness>>,
    compress: bool,
    declared_trust: TrustModel,
    deterministic: bool,
) -> Result<GraphEmission, RuntimeError> {
    let backend = compiled.backend;
    let spec =
        adapter_core::backend_fold_graph_spec(compiled.program.constraints.len().max(1), backend);
    let mut g = ProverGraph::new();
    let mut exec_ctx = ExecutionContext::new()
        .with_program(Arc::new(compiled.program.clone()))
        .with_compiled(Arc::clone(&compiled))
        .with_fold_witnesses(witnesses);

    let transcript_seed_buf = pool
        .alloc(spec.transcript_seed_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.transcript_seed_bytes,
        })?;
    let transcript_buf = pool
        .alloc(spec.transcript_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.transcript_bytes,
        })?;
    let mut transcript = ProverNode::new(ProverOp::TranscriptUpdate)
        .with_inputs([transcript_seed_buf])
        .with_outputs([transcript_buf])
        .with_trust(declared_trust);
    if deterministic {
        transcript = transcript.deterministic();
    }
    let transcript_id = g.add_node(transcript);
    exec_ctx.set_payload(
        transcript_id,
        NodePayload::TranscriptUpdate {
            state_slot: transcript_seed_buf.slot,
        },
    );
    exec_ctx.set_initial_buffer(
        transcript_seed_buf.slot,
        format!(
            "umpg-fold-v1:{}:{}:{}",
            backend.as_str(),
            compiled.program_digest,
            compiled.program.signals.len()
        )
        .into_bytes(),
    );

    let fold_buf = pool
        .alloc(spec.fold_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.fold_bytes,
        })?;
    let mut backend_fold = ProverNode::new(ProverOp::BackendFold {
        backend: backend.as_str(),
    })
    .with_deps([transcript_id])
    .with_inputs([transcript_buf])
    .with_outputs([fold_buf])
    .with_trust(declared_trust);
    if deterministic {
        backend_fold = backend_fold.deterministic();
    }
    let backend_fold_id = g.add_node(backend_fold);
    exec_ctx.set_payload(
        backend_fold_id,
        NodePayload::BackendFold {
            backend: backend.as_str().to_string(),
            compress,
            transcript_slot: transcript_buf.slot,
        },
    );

    let artifact_buf = pool
        .alloc(spec.artifact_bytes, MemoryClass::Spillable)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.artifact_bytes,
        })?;
    let mut encode = ProverNode::new(ProverOp::ProofEncode)
        .with_deps([backend_fold_id])
        .with_outputs([artifact_buf])
        .with_trust(declared_trust);
    if deterministic {
        encode = encode.deterministic();
    }
    let encode_id = g.add_node(encode);
    exec_ctx.set_payload(
        encode_id,
        NodePayload::ProofEncode {
            input_slots: Vec::new(),
            output_kind: ProofOutputKind::BackendArtifact,
        },
    );

    Ok(GraphEmission { graph: g, exec_ctx })
}

/// Emit a wrapper graph with execution context payloads.
pub fn emit_wrapper_graph_with_context(
    pool: &mut UnifiedBufferPool,
    preview: &WrapperPreview,
    deterministic: bool,
) -> Result<GraphEmission, RuntimeError> {
    let graph = emit_wrapper_graph(pool, preview, deterministic)?;
    let mut exec_ctx = ExecutionContext::new();
    exec_ctx.wrapper_preview = Some(preview.clone());

    // Attach payloads to wrapper-specific nodes
    for node in graph.iter_nodes() {
        match &node.op {
            ProverOp::WitnessSolve { .. } => {
                exec_ctx.set_payload(node.id, NodePayload::Noop);
            }
            ProverOp::TranscriptUpdate => {
                let state_slot = node.input_buffers.first().map(|h| h.slot).unwrap_or(0);
                exec_ctx.set_payload(node.id, NodePayload::TranscriptUpdate { state_slot });
            }
            ProverOp::VerifierEmbed { inner_scheme } => {
                let wrapper_input_slot = node.input_buffers.first().map(|h| h.slot).unwrap_or(0);
                exec_ctx.set_payload(
                    node.id,
                    NodePayload::VerifierEmbed {
                        wrapper_input_slot,
                        scheme: inner_scheme.to_string(),
                    },
                );
            }
            ProverOp::OuterProve { outer_scheme } => {
                let proving_input_slot = node.input_buffers.first().map(|h| h.slot).unwrap_or(0);
                exec_ctx.set_payload(
                    node.id,
                    NodePayload::OuterProve {
                        proving_input_slot,
                        scheme: outer_scheme.to_string(),
                    },
                );
            }
            ProverOp::ProofEncode => {
                let input_slots: Vec<u32> = node.input_buffers.iter().map(|h| h.slot).collect();
                exec_ctx.set_payload(
                    node.id,
                    NodePayload::ProofEncode {
                        input_slots,
                        output_kind: ProofOutputKind::WrappedProof,
                    },
                );
            }
            ProverOp::Sha256Batch { count } => {
                if let Some(input_buf) = node.input_buffers.first() {
                    exec_ctx.set_payload(
                        node.id,
                        NodePayload::Sha256Batch {
                            inputs_slot: input_buf.slot,
                            count: *count,
                            input_len: input_buf.size_bytes / (*count).max(1),
                        },
                    );
                }
            }
            _ => {}
        }
    }

    Ok(GraphEmission { graph, exec_ctx })
}

pub fn emit_wrapper_graph(
    pool: &mut UnifiedBufferPool,
    preview: &WrapperPreview,
    deterministic: bool,
) -> Result<ProverGraph, RuntimeError> {
    let mut g = ProverGraph::new();
    let spec = adapter_core::wrapper_graph_spec(preview);
    let trust = spec.trust;

    let source_buf = pool
        .alloc(spec.source_bytes, MemoryClass::Spillable)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.source_bytes,
        })?;
    let mut parse = ProverNode::new(ProverOp::WitnessSolve {
        constraint_count: spec.estimated_constraints,
        signal_count: spec.estimated_constraints.saturating_add(1),
    })
    .with_outputs([source_buf])
    .with_trust(trust);
    if deterministic {
        parse = parse.deterministic();
    }
    let parse_id = g.add_node(parse);

    let transcript_buf = pool
        .alloc(spec.transcript_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.transcript_bytes,
        })?;
    let mut transcript = ProverNode::new(ProverOp::TranscriptUpdate)
        .with_deps([parse_id])
        .with_inputs([source_buf])
        .with_outputs([transcript_buf])
        .with_trust(trust);
    if deterministic {
        transcript = transcript.deterministic();
    }
    let transcript_id = g.add_node(transcript);

    let verifier_buf = pool
        .alloc(spec.verifier_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.verifier_bytes,
        })?;
    let mut verifier_embed = ProverNode::new(ProverOp::VerifierEmbed {
        inner_scheme: backend_kind_name(preview.source_backend),
    })
    .with_deps([transcript_id])
    .with_inputs([transcript_buf])
    .with_outputs([verifier_buf])
    .with_trust(trust);
    if deterministic {
        verifier_embed = verifier_embed.deterministic();
    }
    let verifier_embed_id = g.add_node(verifier_embed);

    let proof_buf = pool
        .alloc(spec.proof_bytes, MemoryClass::EphemeralScratch)
        .ok_or(RuntimeError::BufferExhausted {
            needed_bytes: spec.proof_bytes,
        })?;

    let mut outer = ProverNode::new(ProverOp::OuterProve {
        outer_scheme: "groth16",
    })
    .with_deps([verifier_embed_id])
    .with_inputs([verifier_buf])
    .with_outputs([proof_buf])
    .with_trust(trust);
    if deterministic {
        outer = outer.deterministic();
    }
    let outer_id = g.add_node(outer);

    let mut encode = ProverNode::new(ProverOp::ProofEncode)
        .with_deps([outer_id])
        .with_inputs([proof_buf])
        .with_outputs([proof_buf])
        .with_trust(trust);
    if deterministic {
        encode = encode.deterministic();
    }
    g.add_node(encode);

    Ok(g)
}

/// Reference `GraphAdapter` for a Groth16 proving job.
pub struct Groth16GraphAdapter;

impl GraphAdapter for Groth16GraphAdapter {
    fn backend_name(&self) -> &str {
        "groth16"
    }

    fn emit_graph(
        &self,
        pool: &mut UnifiedBufferPool,
        params: &GraphParams,
    ) -> Result<ProverGraph, RuntimeError> {
        let n = params.constraint_count;
        let mut g = ProverGraph::new();

        // Split shared ntt_buf / msm_buf into semantically distinct buffers
        let w_buf = pool
            .alloc((n + 1) * 32, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted {
                needed_bytes: (n + 1) * 32,
            })?;
        let witness = g.add_node(
            ProverNode::new(ProverOp::WitnessSolve {
                constraint_count: n,
                signal_count: n + 1,
            })
            .with_trust(params.declared_trust)
            .with_outputs([w_buf]),
        );

        // Separate NTT buffers per polynomial (A, B, C)
        let ntt_a_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;
        let ntt_b_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;
        let ntt_c_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;

        let ntt_a = g.add_node(
            ProverNode::new(ProverOp::Ntt {
                size: n.next_power_of_two(),
                field: params.field,
                inverse: false,
            })
            .with_deps([witness])
            .with_inputs([w_buf])
            .with_outputs([ntt_a_buf]),
        );
        let ntt_b = g.add_node(
            ProverNode::new(ProverOp::Ntt {
                size: n.next_power_of_two(),
                field: params.field,
                inverse: false,
            })
            .with_deps([witness])
            .with_inputs([w_buf])
            .with_outputs([ntt_b_buf]),
        );
        let ntt_c = g.add_node(
            ProverNode::new(ProverOp::Ntt {
                size: n.next_power_of_two(),
                field: params.field,
                inverse: false,
            })
            .with_deps([witness])
            .with_inputs([w_buf])
            .with_outputs([ntt_c_buf]),
        );

        // Separate MSM base buffers (bases are the SRS/CRS points)
        let msm_bases_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;

        // Separate MSM result buffers per commitment
        let msm_a_result = pool
            .alloc(96, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 96 })?;
        let msm_b_result = pool
            .alloc(96, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 96 })?;
        let msm_c_result = pool
            .alloc(96, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 96 })?;

        let msm_a = g.add_node(
            ProverNode::new(ProverOp::Msm {
                num_scalars: n,
                curve: "bn254",
            })
            .with_deps([ntt_a])
            .with_inputs([ntt_a_buf, msm_bases_buf])
            .with_outputs([msm_a_result]),
        );
        let msm_b = g.add_node(
            ProverNode::new(ProverOp::Msm {
                num_scalars: n,
                curve: "bn254",
            })
            .with_deps([ntt_b])
            .with_inputs([ntt_b_buf, msm_bases_buf])
            .with_outputs([msm_b_result]),
        );
        let msm_c = g.add_node(
            ProverNode::new(ProverOp::Msm {
                num_scalars: n,
                curve: "bn254",
            })
            .with_deps([ntt_c])
            .with_inputs([ntt_c_buf, msm_bases_buf])
            .with_outputs([msm_c_result]),
        );

        let proof_buf = pool
            .alloc(288, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 288 })?;
        g.add_node(
            ProverNode::new(ProverOp::ProofEncode)
                .with_deps([msm_a, msm_b, msm_c])
                .with_inputs([msm_a_result, msm_b_result, msm_c_result])
                .with_outputs([proof_buf])
                .with_trust(params.declared_trust),
        );

        Ok(g)
    }

    fn emit_graph_with_context(
        &self,
        pool: &mut UnifiedBufferPool,
        params: &GraphParams,
        program: Option<Arc<Program>>,
        inputs: Option<Arc<WitnessInputs>>,
    ) -> Result<GraphEmission, RuntimeError> {
        let n = params.constraint_count;
        let signal_count = program
            .as_ref()
            .map(|program| program.signals.len().max(1))
            .unwrap_or(n + 1);
        let mut g = ProverGraph::new();
        let mut exec_ctx = ExecutionContext::new();

        if let Some(ref p) = program {
            exec_ctx.program = Some(Arc::clone(p));
        }
        if let Some(ref i) = inputs {
            exec_ctx.witness_inputs = Some(Arc::clone(i));
        }

        // ── Witness ──
        let w_buf = pool
            .alloc(signal_count * 32, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted {
                needed_bytes: signal_count * 32,
            })?;
        let witness = g.add_node(
            ProverNode::new(ProverOp::WitnessSolve {
                constraint_count: n,
                signal_count,
            })
            .with_trust(params.declared_trust)
            .with_outputs([w_buf]),
        );
        if let (Some(p), Some(i)) = (&program, &inputs) {
            exec_ctx.set_payload(
                witness,
                NodePayload::WitnessSolve {
                    program: Arc::clone(p),
                    inputs: Arc::clone(i),
                },
            );
        }

        // ── NTT (separate buffers per polynomial) ──
        let ntt_a_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;
        let ntt_b_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;
        let ntt_c_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;

        let ntt_a = g.add_node(
            ProverNode::new(ProverOp::Ntt {
                size: n.next_power_of_two(),
                field: params.field,
                inverse: false,
            })
            .with_deps([witness])
            .with_inputs([w_buf])
            .with_outputs([ntt_a_buf]),
        );
        exec_ctx.set_payload(
            ntt_a,
            NodePayload::NttBn254 {
                values_slot: w_buf.slot,
            },
        );

        let ntt_b = g.add_node(
            ProverNode::new(ProverOp::Ntt {
                size: n.next_power_of_two(),
                field: params.field,
                inverse: false,
            })
            .with_deps([witness])
            .with_inputs([w_buf])
            .with_outputs([ntt_b_buf]),
        );
        exec_ctx.set_payload(
            ntt_b,
            NodePayload::NttBn254 {
                values_slot: w_buf.slot,
            },
        );

        let ntt_c = g.add_node(
            ProverNode::new(ProverOp::Ntt {
                size: n.next_power_of_two(),
                field: params.field,
                inverse: false,
            })
            .with_deps([witness])
            .with_inputs([w_buf])
            .with_outputs([ntt_c_buf]),
        );
        exec_ctx.set_payload(
            ntt_c,
            NodePayload::NttBn254 {
                values_slot: w_buf.slot,
            },
        );

        // ── MSM (separate scalar/base/result slots) ──
        let msm_bases_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;
        exec_ctx.set_initial_buffer(msm_bases_buf.slot, deterministic_bn254_bases_bytes(n));
        let msm_a_result = pool
            .alloc(96, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 96 })?;
        let msm_b_result = pool
            .alloc(96, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 96 })?;
        let msm_c_result = pool
            .alloc(96, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 96 })?;

        let msm_a = g.add_node(
            ProverNode::new(ProverOp::Msm {
                num_scalars: n,
                curve: "bn254",
            })
            .with_deps([ntt_a])
            .with_inputs([ntt_a_buf, msm_bases_buf])
            .with_outputs([msm_a_result]),
        );
        exec_ctx.set_payload(
            msm_a,
            NodePayload::MsmBn254 {
                scalars_slot: ntt_a_buf.slot,
                bases_slot: msm_bases_buf.slot,
            },
        );

        let msm_b = g.add_node(
            ProverNode::new(ProverOp::Msm {
                num_scalars: n,
                curve: "bn254",
            })
            .with_deps([ntt_b])
            .with_inputs([ntt_b_buf, msm_bases_buf])
            .with_outputs([msm_b_result]),
        );
        exec_ctx.set_payload(
            msm_b,
            NodePayload::MsmBn254 {
                scalars_slot: ntt_b_buf.slot,
                bases_slot: msm_bases_buf.slot,
            },
        );

        let msm_c = g.add_node(
            ProverNode::new(ProverOp::Msm {
                num_scalars: n,
                curve: "bn254",
            })
            .with_deps([ntt_c])
            .with_inputs([ntt_c_buf, msm_bases_buf])
            .with_outputs([msm_c_result]),
        );
        exec_ctx.set_payload(
            msm_c,
            NodePayload::MsmBn254 {
                scalars_slot: ntt_c_buf.slot,
                bases_slot: msm_bases_buf.slot,
            },
        );

        // ── Proof encode ──
        let proof_buf = pool
            .alloc(288, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 288 })?;
        let encode = g.add_node(
            ProverNode::new(ProverOp::ProofEncode)
                .with_deps([msm_a, msm_b, msm_c])
                .with_inputs([msm_a_result, msm_b_result, msm_c_result])
                .with_outputs([proof_buf])
                .with_trust(params.declared_trust),
        );
        exec_ctx.set_payload(
            encode,
            NodePayload::ProofEncode {
                input_slots: vec![msm_a_result.slot, msm_b_result.slot, msm_c_result.slot],
                output_kind: ProofOutputKind::Groth16Proof,
            },
        );

        Ok(GraphEmission { graph: g, exec_ctx })
    }
}

/// Reference `GraphAdapter` for a Plonky3 / STARK proving job.
pub struct Plonky3GraphAdapter;

impl GraphAdapter for Plonky3GraphAdapter {
    fn backend_name(&self) -> &str {
        "plonky3"
    }

    fn emit_graph(
        &self,
        pool: &mut UnifiedBufferPool,
        params: &GraphParams,
    ) -> Result<ProverGraph, RuntimeError> {
        let n = params.constraint_count;
        let mut g = ProverGraph::new();

        let trace_buf =
            pool.alloc(n * 8, MemoryClass::Spillable)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 8,
                })?;
        let trace = g.add_node(
            ProverNode::new(ProverOp::WitnessSolve {
                constraint_count: n,
                signal_count: n,
            })
            .with_outputs([trace_buf])
            .with_trust(params.declared_trust),
        );

        let lde_buf = pool.alloc(n * 8 * 4, MemoryClass::EphemeralScratch).ok_or(
            RuntimeError::BufferExhausted {
                needed_bytes: n * 8 * 4,
            },
        )?;
        let lde = g.add_node(
            ProverNode::new(ProverOp::Lde {
                size: n,
                blowup: 4,
                field: params.field,
            })
            .with_deps([trace])
            .with_inputs([trace_buf])
            .with_outputs([lde_buf]),
        );

        let merkle_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;
        let _digest_buf = pool
            .alloc(n * 32 / 2, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted {
                needed_bytes: n * 32 / 2,
            })?;
        let merkle = g.add_node(
            ProverNode::new(ProverOp::MerkleLayer {
                level: 0,
                leaf_count: n * 4,
            })
            .with_deps([lde])
            .with_inputs([lde_buf])
            .with_outputs([merkle_buf]),
        );

        // FRI folding: separate alpha/twiddle slots
        let fri_buf = pool.alloc(n * 8, MemoryClass::EphemeralScratch).ok_or(
            RuntimeError::BufferExhausted {
                needed_bytes: n * 8,
            },
        )?;
        let _alpha_buf = pool
            .alloc(8, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 8 })?;
        let _twiddle_buf =
            pool.alloc(n * 8, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 8,
                })?;

        let mut prev = merkle;
        for _ in 0..3 {
            let fri = g.add_node(
                ProverNode::new(ProverOp::FriFold {
                    folding_factor: 2,
                    codeword_len: n * 4,
                })
                .with_deps([prev])
                .with_inputs([lde_buf])
                .with_outputs([fri_buf]),
            );
            prev = fri;
        }

        let query_buf = pool
            .alloc(1024, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 1024 })?;
        let queries = g.add_node(
            ProverNode::new(ProverOp::FriQueryOpen {
                query_count: 32,
                tree_depth: 20,
            })
            .with_deps([prev])
            .with_inputs([merkle_buf, fri_buf])
            .with_outputs([query_buf]),
        );

        let proof_buf = pool
            .alloc(4096, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 4096 })?;
        g.add_node(
            ProverNode::new(ProverOp::ProofEncode)
                .with_deps([queries])
                .with_inputs([query_buf])
                .with_outputs([proof_buf])
                .with_trust(params.declared_trust),
        );

        Ok(g)
    }

    fn emit_graph_with_context(
        &self,
        pool: &mut UnifiedBufferPool,
        params: &GraphParams,
        program: Option<Arc<Program>>,
        inputs: Option<Arc<WitnessInputs>>,
    ) -> Result<GraphEmission, RuntimeError> {
        let n = params.constraint_count;
        let signal_count = program
            .as_ref()
            .map(|program| program.signals.len().max(1))
            .unwrap_or(n);
        let mut g = ProverGraph::new();
        let mut exec_ctx = ExecutionContext::new();

        if let Some(ref p) = program {
            exec_ctx.program = Some(Arc::clone(p));
        }
        if let Some(ref i) = inputs {
            exec_ctx.witness_inputs = Some(Arc::clone(i));
        }

        // ── Trace generation (WitnessSolve) ──
        let trace_buf = pool.alloc(signal_count * 8, MemoryClass::Spillable).ok_or(
            RuntimeError::BufferExhausted {
                needed_bytes: signal_count * 8,
            },
        )?;
        let trace = g.add_node(
            ProverNode::new(ProverOp::WitnessSolve {
                constraint_count: n,
                signal_count,
            })
            .with_outputs([trace_buf])
            .with_trust(params.declared_trust),
        );
        if let (Some(p), Some(i)) = (&program, &inputs) {
            exec_ctx.set_payload(
                trace,
                NodePayload::WitnessSolve {
                    program: Arc::clone(p),
                    inputs: Arc::clone(i),
                },
            );
        }

        // ── LDE ──
        let lde_buf = pool.alloc(n * 8 * 4, MemoryClass::EphemeralScratch).ok_or(
            RuntimeError::BufferExhausted {
                needed_bytes: n * 8 * 4,
            },
        )?;
        let lde = g.add_node(
            ProverNode::new(ProverOp::Lde {
                size: n,
                blowup: 4,
                field: params.field,
            })
            .with_deps([trace])
            .with_inputs([trace_buf])
            .with_outputs([lde_buf]),
        );
        exec_ctx.set_payload(
            lde,
            NodePayload::LdeGoldilocks {
                values_slot: trace_buf.slot,
                blowup: 4,
            },
        );

        // ── Merkle leaves ──
        let merkle_buf =
            pool.alloc(n * 32, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 32,
                })?;
        let digest_buf = pool
            .alloc(n * 32 / 2, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted {
                needed_bytes: n * 32 / 2,
            })?;
        let merkle = g.add_node(
            ProverNode::new(ProverOp::MerkleLayer {
                level: 0,
                leaf_count: n * 4,
            })
            .with_deps([lde])
            .with_inputs([lde_buf])
            .with_outputs([merkle_buf]),
        );
        exec_ctx.set_payload(
            merkle,
            NodePayload::MerkleGoldilocks {
                leaves_slot: lde_buf.slot,
                digest_slot: digest_buf.slot,
                leaf_count: n * 4,
                hash_fn: crate::execution::MerkleHashFn::Poseidon2Goldilocks,
            },
        );

        // ── FRI folds ──
        let fri_buf = pool.alloc(n * 8 * 2, MemoryClass::EphemeralScratch).ok_or(
            RuntimeError::BufferExhausted {
                needed_bytes: n * 8 * 2,
            },
        )?;
        let alpha_buf = pool
            .alloc(8, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 8 })?;
        let twiddle_buf =
            pool.alloc(n * 8, MemoryClass::HotResident)
                .ok_or(RuntimeError::BufferExhausted {
                    needed_bytes: n * 8,
                })?;
        exec_ctx.set_initial_buffer(alpha_buf.slot, goldilocks_u64_bytes([7]));
        exec_ctx.set_initial_buffer(
            twiddle_buf.slot,
            goldilocks_u64_bytes((0..n).map(|i| (i as u64) + 1)),
        );

        let mut prev = merkle;
        for _ in 0..3 {
            let fri = g.add_node(
                ProverNode::new(ProverOp::FriFold {
                    folding_factor: 2,
                    codeword_len: n * 4,
                })
                .with_deps([prev])
                .with_inputs([lde_buf])
                .with_outputs([fri_buf]),
            );
            exec_ctx.set_payload(
                fri,
                NodePayload::FriFoldGoldilocks {
                    evals_slot: lde_buf.slot,
                    alpha_slot: alpha_buf.slot,
                    twiddles_slot: twiddle_buf.slot,
                },
            );
            prev = fri;
        }

        // ── Query opening ──
        let query_buf = pool
            .alloc(1024, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 1024 })?;
        let queries = g.add_node(
            ProverNode::new(ProverOp::FriQueryOpen {
                query_count: 32,
                tree_depth: 20,
            })
            .with_deps([prev])
            .with_inputs([merkle_buf, fri_buf])
            .with_outputs([query_buf]),
        );
        exec_ctx.set_payload(
            queries,
            NodePayload::FriQueryOpen {
                proof_slot: merkle_buf.slot,
                query_slot: fri_buf.slot,
                query_count: 32,
                tree_depth: 20,
            },
        );

        // ── Proof encode ──
        let proof_buf = pool
            .alloc(4096, MemoryClass::EphemeralScratch)
            .ok_or(RuntimeError::BufferExhausted { needed_bytes: 4096 })?;
        let encode = g.add_node(
            ProverNode::new(ProverOp::ProofEncode)
                .with_deps([queries])
                .with_inputs([query_buf])
                .with_outputs([proof_buf])
                .with_trust(params.declared_trust),
        );
        exec_ctx.set_payload(
            encode,
            NodePayload::ProofEncode {
                input_slots: vec![query_buf.slot],
                output_kind: ProofOutputKind::Plonky3Proof,
            },
        );

        Ok(GraphEmission { graph: g, exec_ctx })
    }
}
