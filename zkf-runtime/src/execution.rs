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

//! Execution payload plane: per-run data that ProverOp nodes execute against.
//!
//! `ProverOp` remains the scheduling/type layer.  `NodePayload` is the
//! execution language — it carries the actual operands (buffer slots,
//! program references, parameters) that a driver needs to do real work.

use crate::control_plane::OptimizationObjective;
use crate::execution_core;
use crate::memory::NodeId;
use std::collections::HashMap;
use std::sync::Arc;
use zkf_backends::BackendRoute;
use zkf_core::Witness;
use zkf_core::artifact::{CompiledProgram, ProofArtifact};
use zkf_core::ir::Program;
use zkf_core::witness::WitnessInputs;
use zkf_core::wrapping::{WrapperExecutionPolicy, WrapperPreview};

// ─── Node Payloads ────────────────────────────────────────────────────────

/// Typed execution payload for a single graph node.
///
/// Each variant carries the concrete operands the driver needs.
/// Buffer slots (`u32`) are logical keys into `BufferBridge`.
#[derive(Debug, Clone)]
pub enum NodePayload {
    // ── Witness / constraint ──
    WitnessSolve {
        program: Arc<Program>,
        inputs: Arc<WitnessInputs>,
    },
    BooleanizeSignals {
        signals_slot: u32,
        count: usize,
    },
    RangeCheckExpand {
        signals_slot: u32,
        bits: u32,
        count: usize,
    },
    LookupExpand {
        table_slot: u32,
        inputs_slot: u32,
        table_rows: usize,
        table_cols: usize,
        query_cols: usize,
        output_col_offset: usize,
        output_cols: usize,
    },

    // ── NTT ──
    NttBn254 {
        values_slot: u32,
    },
    NttGoldilocks {
        values_slot: u32,
    },

    // ── LDE ──
    LdeGoldilocks {
        values_slot: u32,
        blowup: usize,
    },

    // ── MSM ──
    MsmBn254 {
        scalars_slot: u32,
        bases_slot: u32,
    },

    // ── Hashing / commitment ──
    PoseidonGoldilocks {
        states_slot: u32,
        round_constants_slot: u32,
        n_ext: u32,
        n_int: u32,
    },
    Sha256Batch {
        inputs_slot: u32,
        count: usize,
        input_len: usize,
    },
    MerkleGoldilocks {
        leaves_slot: u32,
        digest_slot: u32,
        leaf_count: usize,
        hash_fn: MerkleHashFn,
    },

    // ── FRI ──
    FriFoldGoldilocks {
        evals_slot: u32,
        alpha_slot: u32,
        twiddles_slot: u32,
    },
    FriFoldBabyBear {
        evals_slot: u32,
        alpha_slot: u32,
        twiddles_slot: u32,
    },
    FriQueryOpen {
        proof_slot: u32,
        query_slot: u32,
        query_count: usize,
        tree_depth: usize,
    },

    // ── Recursive / wrapping ──
    VerifierEmbed {
        wrapper_input_slot: u32,
        scheme: String,
    },
    BackendProve {
        backend: String,
        route: BackendRoute,
        transcript_slot: u32,
    },
    BackendFold {
        backend: String,
        compress: bool,
        transcript_slot: u32,
    },
    OuterProve {
        proving_input_slot: u32,
        scheme: String,
    },

    // ── Finalization ──
    TranscriptUpdate {
        state_slot: u32,
    },
    ProofEncode {
        input_slots: Vec<u32>,
        output_kind: ProofOutputKind,
    },

    // ── Scheduling ──
    Barrier,
    Noop,
}

/// Hash function selector for Merkle tree construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleHashFn {
    Poseidon2Goldilocks,
    Poseidon2BabyBear,
    Sha256,
    Keccak256,
}

/// Output format for ProofEncode nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofOutputKind {
    Groth16Proof,
    Plonky3Proof,
    BackendArtifact,
    WrappedProof,
    RawBytes,
}

// ─── Execution Context ────────────────────────────────────────────────────

/// Per-run data plane.  Carries everything a driver needs beyond the
/// scheduling topology in `ProverGraph`.
pub struct ExecutionContext {
    /// Source proof artifact for wrapper executions.
    pub source_proof: Option<Arc<ProofArtifact>>,
    /// Source program (when the graph is a primary prove job).
    pub program: Option<Arc<Program>>,
    /// Compiled artifact (proving key, circuit data) when available.
    pub compiled: Option<Arc<CompiledProgram>>,
    /// Witness inputs for the run.
    pub witness_inputs: Option<Arc<WitnessInputs>>,
    /// Precomputed witness for delegated or solver-backed proving.
    pub witness: Option<Arc<Witness>>,
    /// Precomputed witnesses for native fold/IVC execution.
    pub fold_witnesses: Option<Arc<Vec<Witness>>>,
    /// Wrapper preview context (for wrapper graphs).
    pub wrapper_preview: Option<WrapperPreview>,
    /// Policy to use when executing a wrapper outer prove node.
    pub wrapper_policy: Option<WrapperExecutionPolicy>,
    /// Wrapped artifact materialized during execution.
    pub wrapped_artifact: Option<ProofArtifact>,
    /// Primary proof artifact materialized during execution.
    pub proof_artifact: Option<ProofArtifact>,
    /// Per-node execution payloads, keyed by `NodeId`.
    pub node_payloads: HashMap<NodeId, NodePayload>,
    /// Initial slot contents that must be materialized before execution.
    pub initial_buffers: HashMap<u32, Vec<u8>>,
    /// Output manifest: named output blobs produced during execution.
    pub outputs: HashMap<String, Vec<u8>>,
    /// Requested control-plane optimization target for this execution.
    pub optimization_objective: OptimizationObjective,
    /// Explicit backend selected for this execution, if any.
    pub requested_backend: Option<zkf_core::BackendKind>,
    /// Explicit backend route selected for this execution, if any.
    pub requested_backend_route: Option<BackendRoute>,
    /// Explicit backend candidate set to constrain control-plane scoring.
    pub requested_backend_candidates: Option<Vec<zkf_core::BackendKind>>,
}

impl ExecutionContext {
    pub fn new() -> Self {
        Self {
            source_proof: None,
            program: None,
            compiled: None,
            witness_inputs: None,
            witness: None,
            fold_witnesses: None,
            wrapper_preview: None,
            wrapper_policy: None,
            wrapped_artifact: None,
            proof_artifact: None,
            node_payloads: HashMap::new(),
            initial_buffers: HashMap::new(),
            outputs: HashMap::new(),
            optimization_objective: OptimizationObjective::FastestProve,
            requested_backend: None,
            requested_backend_route: None,
            requested_backend_candidates: None,
        }
    }

    /// Attach a payload for a specific node.
    pub fn set_payload(&mut self, node_id: NodeId, payload: NodePayload) {
        self.node_payloads.insert(node_id, payload);
    }

    /// Retrieve the payload for a node, if present.
    pub fn payload(&self, node_id: NodeId) -> Option<&NodePayload> {
        self.node_payloads.get(&node_id)
    }

    /// Seed a buffer slot with initial data before the scheduler begins.
    pub fn set_initial_buffer(&mut self, slot: u32, data: Vec<u8>) {
        self.initial_buffers.insert(slot, data);
    }

    /// Retrieve initial data for a slot, if present.
    pub fn initial_buffer(&self, slot: u32) -> Option<&[u8]> {
        self.initial_buffers
            .get(&slot)
            .map(|bytes| bytes.as_slice())
    }

    /// Store a named output blob.
    pub fn set_output(&mut self, name: impl Into<String>, data: Vec<u8>) {
        self.outputs.insert(name.into(), data);
    }

    /// Retrieve a named output blob.
    pub fn output(&self, name: &str) -> Option<&[u8]> {
        self.outputs.get(name).map(|v| v.as_slice())
    }

    /// Classify the active execution surface for orchestration.
    pub fn job_kind(&self) -> crate::control_plane::JobKind {
        execution_core::classify_job(self)
    }

    /// The effective source program visible to orchestration and control-plane logic.
    pub fn effective_program(&self) -> Option<&Program> {
        execution_core::effective_program(self)
    }

    /// Validate the minimal artifact requirements for wrapper execution.
    pub fn verify_wrapper_source_artifacts(&self) -> Result<(), crate::error::RuntimeError> {
        execution_core::verify_wrapper_source_artifacts(self)
    }

    /// Attach the wrapper execution policy for this run.
    pub fn set_wrapper_policy(&mut self, policy: WrapperExecutionPolicy) {
        self.wrapper_policy = Some(policy);
    }

    /// Record the wrapped artifact produced during execution.
    pub fn set_wrapped_artifact(&mut self, artifact: ProofArtifact) {
        self.wrapped_artifact = Some(artifact);
    }

    /// Borrow the wrapped artifact produced during execution.
    pub fn wrapped_artifact(&self) -> Option<&ProofArtifact> {
        self.wrapped_artifact.as_ref()
    }

    /// Consume the wrapped artifact produced during execution.
    pub fn take_wrapped_artifact(&mut self) -> Option<ProofArtifact> {
        self.wrapped_artifact.take()
    }

    /// Set the source program for this execution.
    pub fn with_program(mut self, program: Arc<Program>) -> Self {
        self.program = Some(program);
        self
    }

    /// Set the source proof artifact for this execution.
    pub fn with_source_proof(mut self, proof: Arc<ProofArtifact>) -> Self {
        self.source_proof = Some(proof);
        self
    }

    /// Set the compiled artifact for this execution.
    pub fn with_compiled(mut self, compiled: Arc<CompiledProgram>) -> Self {
        self.compiled = Some(compiled);
        self
    }

    /// Set the requested optimization objective for this execution.
    pub fn with_optimization_objective(mut self, objective: OptimizationObjective) -> Self {
        self.optimization_objective = objective;
        self
    }

    /// Set the explicit requested backend for this execution.
    pub fn with_requested_backend(mut self, backend: zkf_core::BackendKind) -> Self {
        self.requested_backend = Some(backend);
        self
    }

    /// Set the explicit requested backend route for this execution.
    pub fn with_requested_backend_route(mut self, route: BackendRoute) -> Self {
        self.requested_backend_route = Some(route);
        self
    }

    /// Set the explicit control-plane backend candidates for this execution.
    pub fn with_requested_backend_candidates(
        mut self,
        candidates: Vec<zkf_core::BackendKind>,
    ) -> Self {
        self.requested_backend_candidates = Some(candidates);
        self
    }

    /// Set witness inputs for this execution.
    pub fn with_inputs(mut self, inputs: Arc<WitnessInputs>) -> Self {
        self.witness_inputs = Some(inputs);
        self
    }

    /// Set a precomputed witness for this execution.
    pub fn with_witness(mut self, witness: Arc<Witness>) -> Self {
        self.witness = Some(witness);
        self
    }

    /// Set precomputed witnesses for a fold/IVC execution.
    pub fn with_fold_witnesses(mut self, witnesses: Arc<Vec<Witness>>) -> Self {
        self.fold_witnesses = Some(witnesses);
        self
    }

    /// Set wrapper preview context.
    pub fn with_wrapper_preview(mut self, preview: WrapperPreview) -> Self {
        self.wrapper_preview = Some(preview);
        self
    }

    /// Record the primary proof artifact produced during execution.
    pub fn set_proof_artifact(&mut self, artifact: ProofArtifact) {
        self.proof_artifact = Some(artifact);
    }

    /// Borrow the primary proof artifact produced during execution.
    pub fn proof_artifact(&self) -> Option<&ProofArtifact> {
        self.proof_artifact.as_ref()
    }

    /// Consume the primary proof artifact produced during execution.
    pub fn take_proof_artifact(&mut self) -> Option<ProofArtifact> {
        self.proof_artifact.take()
    }
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ExecutionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutionContext")
            .field("has_source_proof", &self.source_proof.is_some())
            .field("has_program", &self.program.is_some())
            .field("has_compiled", &self.compiled.is_some())
            .field("has_witness_inputs", &self.witness_inputs.is_some())
            .field("has_witness", &self.witness.is_some())
            .field("has_fold_witnesses", &self.fold_witnesses.is_some())
            .field("has_wrapper_preview", &self.wrapper_preview.is_some())
            .field("has_wrapper_policy", &self.wrapper_policy.is_some())
            .field("has_wrapped_artifact", &self.wrapped_artifact.is_some())
            .field("has_proof_artifact", &self.proof_artifact.is_some())
            .field("node_payloads", &self.node_payloads.len())
            .field("initial_buffers", &self.initial_buffers.len())
            .field("outputs", &self.outputs.len())
            .field("requested_backend", &self.requested_backend)
            .field("requested_backend_route", &self.requested_backend_route)
            .field(
                "requested_backend_candidates",
                &self.requested_backend_candidates,
            )
            .finish()
    }
}
