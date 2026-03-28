//! CPU backend driver: executes CPU-placed nodes against `zkf-core`,
//! arkworks, and Plonky3.

use crate::buffer_bridge::BufferBridge;
use crate::error::RuntimeError;
use crate::execution::{ExecutionContext, MerkleHashFn, NodePayload, ProofOutputKind};
use crate::graph::{ProverNode, ProverOp};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zkf_backends::{
    BackendRoute, backend_for_route, prepare_witness_for_proving,
    wrapping::default_wrapper_registry,
};
use zkf_core::artifact::BackendKind;
use zkf_core::ir::Program;
use zkf_core::witness::{check_constraints, ensure_witness_completeness};
use zkf_core::{Visibility, Witness, WitnessInputs};

/// Telemetry from a single CPU node execution.
#[derive(Debug, Clone)]
pub struct CpuNodeTelemetry {
    pub op_name: String,
    pub wall_time: Duration,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub delegated: bool,
    pub delegated_backend: Option<String>,
}

/// Drives CPU execution for all node types.
pub struct CpuBackendDriver;

impl CpuBackendDriver {
    pub fn new() -> Self {
        Self
    }

    fn telemetry(
        op_name: impl Into<String>,
        input_bytes: usize,
        output_bytes: usize,
    ) -> CpuNodeTelemetry {
        CpuNodeTelemetry {
            op_name: op_name.into(),
            wall_time: Duration::ZERO,
            input_bytes,
            output_bytes,
            delegated: false,
            delegated_backend: None,
        }
    }

    /// Execute a node on CPU.
    pub fn execute(
        &self,
        node: &ProverNode,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let start = Instant::now();
        let payload = exec_ctx.payload(node.id).cloned();

        let result = match &node.op {
            ProverOp::WitnessSolve {
                constraint_count,
                signal_count,
            } => self.execute_witness_solve(
                node,
                *constraint_count,
                *signal_count,
                &payload,
                exec_ctx,
                bridge,
            ),
            ProverOp::BooleanizeSignals { count } => {
                self.execute_booleanize(node, *count, &payload, bridge)
            }
            ProverOp::RangeCheckExpand { bits, count } => {
                self.execute_range_check(node, *bits, *count, &payload, bridge)
            }
            ProverOp::LookupExpand {
                table_rows,
                table_cols,
            } => self.execute_lookup_expand(node, *table_rows, *table_cols, &payload, bridge),
            ProverOp::Ntt {
                size,
                field,
                inverse,
            } => self.execute_ntt(node, *size, field, *inverse, &payload, bridge),
            ProverOp::Lde {
                size,
                blowup,
                field,
            } => self.execute_lde(node, *size, *blowup, field, &payload, bridge),
            ProverOp::Msm { num_scalars, curve } => {
                self.execute_msm(node, *num_scalars, curve, &payload, bridge)
            }
            ProverOp::PoseidonBatch { count, width } => {
                self.execute_poseidon_batch(node, *count, *width, &payload, bridge)
            }
            ProverOp::Sha256Batch { count } => {
                self.execute_sha256_batch(node, *count, &payload, bridge)
            }
            ProverOp::MerkleLayer { level, leaf_count } => {
                self.execute_merkle_layer(node, *level, *leaf_count, &payload, exec_ctx, bridge)
            }
            ProverOp::FriFold {
                folding_factor,
                codeword_len,
            } => self.execute_fri_fold(node, *folding_factor, *codeword_len, &payload, bridge),
            ProverOp::FriQueryOpen {
                query_count,
                tree_depth,
            } => self.execute_fri_query_open(node, *query_count, *tree_depth, &payload, bridge),
            ProverOp::TranscriptUpdate => self.execute_transcript_update(node, &payload, bridge),
            ProverOp::ProofEncode => self.execute_proof_encode(node, &payload, exec_ctx, bridge),
            ProverOp::VerifierEmbed { inner_scheme } => {
                self.execute_verifier_embed(node, inner_scheme, &payload, exec_ctx, bridge)
            }
            ProverOp::BackendProve { backend } => {
                self.execute_backend_prove(node, backend, &payload, exec_ctx, bridge)
            }
            ProverOp::BackendFold { backend } => {
                self.execute_backend_fold(node, backend, &payload, exec_ctx, bridge)
            }
            ProverOp::OuterProve { outer_scheme } => {
                self.execute_outer_prove(node, outer_scheme, &payload, exec_ctx, bridge)
            }
            ProverOp::Barrier { .. } | ProverOp::Noop => Ok(Self::telemetry(
                node.op.name(),
                0,
                self.write_primary_output(node, bridge, &[])?,
            )),
        };

        result.map(|mut telemetry| {
            telemetry.wall_time = start.elapsed();
            telemetry
        })
    }

    fn write_primary_output(
        &self,
        node: &ProverNode,
        bridge: &mut BufferBridge,
        data: &[u8],
    ) -> Result<usize, RuntimeError> {
        let Some(handle) = node.output_buffers.first() else {
            return Ok(0);
        };

        bridge.ensure_resident(handle.slot)?;
        if data.len() > handle.size_bytes {
            return Err(RuntimeError::Execution(format!(
                "{} produced {} bytes for a {} byte output buffer",
                node.op.name(),
                data.len(),
                handle.size_bytes
            )));
        }
        let mut padded = vec![0u8; handle.size_bytes];
        padded[..data.len()].copy_from_slice(data);
        bridge.write_slot(handle.slot, &padded)?;
        Ok(data.len())
    }

    fn output_width(&self, node: &ProverNode, count: usize, default_width: usize) -> usize {
        node.output_buffers
            .first()
            .and_then(|handle| {
                if count == 0 {
                    None
                } else {
                    Some((handle.size_bytes / count).max(1))
                }
            })
            .unwrap_or(default_width)
    }

    fn source_slot(
        &self,
        node: &ProverNode,
        preferred: Option<u32>,
        input_index: usize,
    ) -> Result<u32, RuntimeError> {
        preferred
            .or(node
                .input_buffers
                .get(input_index)
                .map(|handle| handle.slot))
            .ok_or(RuntimeError::MissingPayload(node.id))
    }

    fn serialize_field_width(fe: &zkf_core::FieldElement, width: usize) -> Vec<u8> {
        let mut out = vec![0u8; width];
        let src = fe.to_le_bytes();
        let copy_len = src.len().min(width);
        out[..copy_len].copy_from_slice(&src[..copy_len]);
        out
    }

    fn serialize_witness(program: &Program, witness: &Witness, element_width: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(program.signals.len() * element_width);
        for signal in &program.signals {
            let value = witness
                .values
                .get(&signal.name)
                .cloned()
                .unwrap_or(zkf_core::FieldElement::ZERO);
            bytes.extend(Self::serialize_field_width(&value, element_width));
        }
        bytes
    }

    fn validate_supplied_inputs_against_witness(
        program: &Program,
        inputs: &WitnessInputs,
        witness: &Witness,
    ) -> Result<(), RuntimeError> {
        for (signal_name, expected_value) in inputs {
            if !program.signals.iter().any(|signal| {
                signal.name == *signal_name && signal.visibility != Visibility::Constant
            }) {
                return Err(RuntimeError::WitnessGeneration(format!(
                    "supplied input '{signal_name}' is not declared by the program"
                )));
            }

            let actual_value = witness.values.get(signal_name).ok_or_else(|| {
                RuntimeError::WitnessGeneration(format!(
                    "supplied witness is missing declared input signal '{signal_name}'"
                ))
            })?;

            if actual_value != expected_value {
                return Err(RuntimeError::WitnessGeneration(format!(
                    "supplied witness value for input '{signal_name}' does not match provided inputs"
                )));
            }
        }

        Ok(())
    }

    fn resolve_authoritative_witness(
        &self,
        exec_ctx: &mut ExecutionContext,
        compile_hint: Option<(BackendKind, BackendRoute)>,
    ) -> Result<Option<Witness>, RuntimeError> {
        let Some(program) = exec_ctx.program.as_ref().map(Arc::clone) else {
            return Ok(None);
        };
        let Some(witness) = exec_ctx.witness.as_ref().map(Arc::clone) else {
            return Ok(None);
        };

        if let Some(inputs) = exec_ctx.witness_inputs.as_ref() {
            Self::validate_supplied_inputs_against_witness(
                program.as_ref(),
                inputs,
                witness.as_ref(),
            )?;
        }
        let compiled = if let Some(compiled) = exec_ctx.compiled.as_ref() {
            Some((**compiled).clone())
        } else {
            compile_hint
                .map(|(backend, route)| {
                    backend_for_route(backend, route)
                        .compile(program.as_ref())
                        .map_err(|error| {
                            RuntimeError::Execution(format!("compile {backend}: {error}"))
                        })
                })
                .transpose()?
        };

        if let Some(compiled) = compiled {
            let prepared = if ensure_witness_completeness(&compiled.program, witness.as_ref()).is_ok()
            {
                (*witness).clone()
            } else {
                prepare_witness_for_proving(&compiled, witness.as_ref()).map_err(|error| {
                    RuntimeError::WitnessGeneration(format!(
                        "witness-solve could not normalize supplied witness: {error}"
                    ))
                })?
            };
            exec_ctx.compiled = Some(Arc::new(compiled));
            exec_ctx.witness = Some(Arc::new(prepared.clone()));
            Ok(Some(prepared))
        } else {
            Ok(Some((*witness).clone()))
        }
    }

    fn execute_witness_solve(
        &self,
        node: &ProverNode,
        _constraint_count: usize,
        signal_count: usize,
        payload: &Option<NodePayload>,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let element_width = self.output_width(node, signal_count.max(1), 32);

        let output = if exec_ctx.witness.is_some() && exec_ctx.program.is_some() {
            let program = exec_ctx
                .program
                .as_ref()
                .map(Arc::clone)
                .ok_or(RuntimeError::MissingPayload(node.id))?;
            let compile_hint = exec_ctx
                .requested_backend
                .map(|backend| {
                    (
                        backend,
                        exec_ctx
                            .requested_backend_route
                            .unwrap_or(BackendRoute::Auto),
                    )
                })
                .or_else(|| {
                    exec_ctx
                        .compiled
                        .as_ref()
                        .map(|compiled| (compiled.backend, BackendRoute::Auto))
                });
            let witness = self
                .resolve_authoritative_witness(exec_ctx, compile_hint)?
                .ok_or(RuntimeError::MissingPayload(node.id))?;
            Self::serialize_witness(program.as_ref(), &witness, element_width)
        } else {
            match payload {
                Some(NodePayload::WitnessSolve { program, inputs }) => {
                    let witness = zkf_core::generate_witness(program, inputs)
                        .map_err(|e| RuntimeError::WitnessGeneration(format!("{e}")))?;
                    Self::serialize_witness(program, &witness, element_width)
                }
                _ if exec_ctx.program.is_some() && exec_ctx.witness_inputs.is_some() => {
                    let program = exec_ctx
                        .program
                        .as_ref()
                        .ok_or(RuntimeError::MissingPayload(node.id))?;
                    let inputs = exec_ctx
                        .witness_inputs
                        .as_ref()
                        .ok_or(RuntimeError::MissingPayload(node.id))?;
                    let witness = zkf_core::generate_witness(program, inputs)
                        .map_err(|e| RuntimeError::WitnessGeneration(format!("{e}")))?;
                    Self::serialize_witness(program, &witness, element_width)
                }
                _ if exec_ctx.source_proof.is_some() => serde_json::to_vec(
                    exec_ctx
                        .source_proof
                        .as_ref()
                        .ok_or(RuntimeError::MissingPayload(node.id))?
                        .as_ref(),
                )
                .map_err(|e| {
                    RuntimeError::Execution(format!("serialize source proof artifact: {e}"))
                })?,
                _ if exec_ctx.wrapper_preview.is_some() => {
                    return Err(RuntimeError::UnsupportedFeature {
                        backend: "runtime-wrapper".into(),
                        feature: "wrapper execution requires an attached source proof artifact"
                            .into(),
                    });
                }
                _ => return Err(RuntimeError::MissingPayload(node.id)),
            }
        };

        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry("WitnessSolve", 0, output_bytes))
    }

    fn execute_booleanize(
        &self,
        node: &ProverNode,
        count: usize,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let signals_slot = match payload {
            Some(NodePayload::BooleanizeSignals { signals_slot, .. }) => *signals_slot,
            _ => self.source_slot(node, None, 0)?,
        };
        bridge.ensure_inputs_resident(&[signals_slot])?;
        let view = bridge.view(signals_slot)?;
        let input_bytes = view.len();
        let mut output = Vec::with_capacity(count);
        for chunk in view.as_bytes().chunks(32).take(count) {
            let is_bool = chunk.iter().all(|byte| *byte == 0)
                || (chunk.first() == Some(&1) && chunk[1..].iter().all(|byte| *byte == 0));
            output.push(u8::from(is_bool));
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry(
            "BooleanizeSignals",
            input_bytes,
            output_bytes,
        ))
    }

    fn execute_range_check(
        &self,
        node: &ProverNode,
        bits: u32,
        count: usize,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let signals_slot = match payload {
            Some(NodePayload::RangeCheckExpand { signals_slot, .. }) => *signals_slot,
            _ => self.source_slot(node, None, 0)?,
        };
        bridge.ensure_inputs_resident(&[signals_slot])?;
        let view = bridge.view(signals_slot)?;
        let input_bytes = view.len();
        let out_width = ((bits as usize).saturating_add(7) / 8).max(1);
        let mut output = Vec::with_capacity(count * out_width);
        for chunk in view.as_bytes().chunks(32).take(count) {
            let mut scalar = [0u8; 8];
            let copy_len = chunk.len().min(8);
            scalar[..copy_len].copy_from_slice(&chunk[..copy_len]);
            output.extend_from_slice(&scalar[..out_width.min(8)]);
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry(
            "RangeCheckExpand",
            input_bytes,
            output_bytes,
        ))
    }

    fn execute_lookup_expand(
        &self,
        node: &ProverNode,
        table_rows: usize,
        table_cols: usize,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let (table_slot, inputs_slot, query_cols, output_col_offset, output_cols) = match payload {
            Some(NodePayload::LookupExpand {
                table_slot,
                inputs_slot,
                table_rows: payload_rows,
                table_cols: payload_cols,
                query_cols,
                output_col_offset,
                output_cols,
            }) => {
                if *payload_rows != table_rows || *payload_cols != table_cols {
                    return Err(RuntimeError::Execution(format!(
                        "LookupExpand payload/table shape mismatch for node {}",
                        node.id.as_u64()
                    )));
                }
                (
                    *table_slot,
                    *inputs_slot,
                    *query_cols,
                    *output_col_offset,
                    *output_cols,
                )
            }
            _ => return Err(RuntimeError::MissingPayload(node.id)),
        };

        if query_cols == 0 || query_cols > table_cols {
            return Err(RuntimeError::Execution(format!(
                "LookupExpand invalid query_cols={} for table_cols={table_cols}",
                query_cols
            )));
        }
        if output_cols == 0
            || output_col_offset >= table_cols
            || output_col_offset + output_cols > table_cols
        {
            return Err(RuntimeError::Execution(format!(
                "LookupExpand invalid output window offset={} cols={} for table_cols={table_cols}",
                output_col_offset, output_cols
            )));
        }

        const CELL_BYTES: usize = 32;
        let table_row_bytes = table_cols * CELL_BYTES;
        let query_row_bytes = query_cols * CELL_BYTES;
        let output_row_bytes = output_cols * CELL_BYTES;

        bridge.ensure_inputs_resident(&[table_slot, inputs_slot])?;
        let table_view = bridge.view(table_slot)?;
        let inputs_view = bridge.view(inputs_slot)?;
        let input_bytes = table_view.len() + inputs_view.len();

        let table_bytes = table_view.as_bytes();
        let inputs_bytes = inputs_view.as_bytes();
        if table_bytes.len() < table_rows * table_row_bytes {
            return Err(RuntimeError::Execution(format!(
                "LookupExpand table slot too small: have {} bytes, need at least {}",
                table_bytes.len(),
                table_rows * table_row_bytes
            )));
        }
        if inputs_bytes.is_empty() || inputs_bytes.len() % query_row_bytes != 0 {
            return Err(RuntimeError::Execution(format!(
                "LookupExpand inputs slot size {} is not a multiple of query row width {}",
                inputs_bytes.len(),
                query_row_bytes
            )));
        }

        let query_count = inputs_bytes.len() / query_row_bytes;
        let mut output = Vec::with_capacity(query_count * output_row_bytes);
        for query in inputs_bytes.chunks_exact(query_row_bytes) {
            let mut matched = None;
            for row in table_bytes[..table_rows * table_row_bytes].chunks_exact(table_row_bytes) {
                if &row[..query_row_bytes] == query {
                    let start = output_col_offset * CELL_BYTES;
                    let end = start + output_row_bytes;
                    matched = Some(&row[start..end]);
                    break;
                }
            }
            let matched = matched.ok_or_else(|| {
                RuntimeError::Execution(format!(
                    "LookupExpand failed to find a matching row for node {}",
                    node.id.as_u64()
                ))
            })?;
            output.extend_from_slice(matched);
        }

        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry("LookupExpand", input_bytes, output_bytes))
    }

    fn execute_ntt(
        &self,
        node: &ProverNode,
        size: usize,
        field: &str,
        inverse: bool,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        match field {
            "bn254_fr" => self.execute_bn254_ntt(node, size, inverse, payload, bridge),
            "goldilocks" => self.execute_goldilocks_ntt(node, size, inverse, payload, bridge),
            other => Err(RuntimeError::UnsupportedFeature {
                backend: "cpu".into(),
                feature: format!("NTT field {other}"),
            }),
        }
    }

    fn execute_bn254_ntt(
        &self,
        node: &ProverNode,
        size: usize,
        inverse: bool,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        use ark_bn254::Fr;
        use ark_ff::{BigInteger, PrimeField};
        use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};

        let source_slot = match payload {
            Some(NodePayload::NttBn254 { values_slot }) => node
                .input_buffers
                .first()
                .map(|handle| handle.slot)
                .unwrap_or(*values_slot),
            _ => self.source_slot(node, None, 0)?,
        };
        bridge.ensure_inputs_resident(&[source_slot])?;
        let view = bridge.view(source_slot)?;
        let input_bytes = view.len();
        let mut values = Vec::with_capacity(size);
        for chunk in view.as_bytes().chunks(32).take(size) {
            values.push(Fr::from_le_bytes_mod_order(chunk));
        }
        values.resize(size, Fr::from(0u64));
        let domain = Radix2EvaluationDomain::<Fr>::new(size).ok_or_else(|| {
            RuntimeError::Execution(format!("invalid BN254 NTT domain size {size}"))
        })?;
        if inverse {
            domain.ifft_in_place(&mut values);
        } else {
            domain.fft_in_place(&mut values);
        }
        let mut output = Vec::with_capacity(size * 32);
        for value in values {
            let bytes = value.into_bigint().to_bytes_le();
            let mut padded = [0u8; 32];
            let copy_len = bytes.len().min(32);
            padded[..copy_len].copy_from_slice(&bytes[..copy_len]);
            output.extend_from_slice(&padded);
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry("NTT-bn254_fr", input_bytes, output_bytes))
    }

    fn execute_goldilocks_ntt(
        &self,
        node: &ProverNode,
        size: usize,
        inverse: bool,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        use p3_goldilocks::Goldilocks;
        use p3_matrix::Matrix;
        use p3_matrix::dense::RowMajorMatrix;

        let source_slot = match payload {
            Some(NodePayload::NttGoldilocks { values_slot }) => node
                .input_buffers
                .first()
                .map(|handle| handle.slot)
                .unwrap_or(*values_slot),
            _ => self.source_slot(node, None, 0)?,
        };
        bridge.ensure_inputs_resident(&[source_slot])?;
        let view = bridge.view(source_slot)?;
        let input_bytes = view.len();
        let mut values: Vec<Goldilocks> = view
            .as_bytes()
            .chunks(8)
            .take(size)
            .map(|chunk| {
                let mut bytes = [0u8; 8];
                let copy_len = chunk.len().min(8);
                bytes[..copy_len].copy_from_slice(&chunk[..copy_len]);
                Goldilocks::from_u64(u64::from_le_bytes(bytes))
            })
            .collect();
        values.resize(size, Goldilocks::ZERO);
        let dft = Radix2DitParallel::<Goldilocks>::default();
        let mat = RowMajorMatrix::new(values, 1);
        let result = if inverse {
            dft.idft_batch(mat).to_row_major_matrix()
        } else {
            dft.dft_batch(mat).to_row_major_matrix()
        };
        let mut output = Vec::with_capacity(result.values.len() * 8);
        for value in result.values {
            output.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry("NTT-goldilocks", input_bytes, output_bytes))
    }

    fn execute_lde(
        &self,
        node: &ProverNode,
        size: usize,
        blowup: usize,
        field: &str,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        use p3_goldilocks::Goldilocks;
        use p3_matrix::Matrix;
        use p3_matrix::dense::RowMajorMatrix;

        if field != "goldilocks" {
            return Err(RuntimeError::UnsupportedFeature {
                backend: "cpu".into(),
                feature: format!("LDE field {field}"),
            });
        }
        let source_slot = match payload {
            Some(NodePayload::LdeGoldilocks { values_slot, .. }) => *values_slot,
            _ => self.source_slot(node, None, 0)?,
        };
        bridge.ensure_inputs_resident(&[source_slot])?;
        let view = bridge.view(source_slot)?;
        let input_bytes = view.len();
        let values: Vec<Goldilocks> = view
            .as_bytes()
            .chunks(8)
            .take(size)
            .map(|chunk| {
                let mut bytes = [0u8; 8];
                let copy_len = chunk.len().min(8);
                bytes[..copy_len].copy_from_slice(&chunk[..copy_len]);
                Goldilocks::from_u64(u64::from_le_bytes(bytes))
            })
            .collect();
        let dft = Radix2DitParallel::<Goldilocks>::default();
        let coeffs = dft.idft_batch(RowMajorMatrix::new(values, 1));
        let mut extended_coeffs = coeffs.values;
        extended_coeffs.resize(size * blowup, Goldilocks::ZERO);
        let extended = dft
            .dft_batch(RowMajorMatrix::new(extended_coeffs, 1))
            .to_row_major_matrix();
        let mut output = Vec::with_capacity(extended.values.len() * 8);
        for value in extended.values {
            output.extend_from_slice(&value.as_canonical_u64().to_le_bytes());
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry(
            format!("LDE-{field}"),
            input_bytes,
            output_bytes,
        ))
    }

    fn execute_msm(
        &self,
        node: &ProverNode,
        _num_scalars: usize,
        curve: &str,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        use ark_bn254::{Fr, G1Affine, G1Projective};
        use ark_ec::{CurveGroup, VariableBaseMSM};
        use ark_ff::PrimeField;
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

        if curve != "bn254" {
            return Err(RuntimeError::UnsupportedFeature {
                backend: "cpu".into(),
                feature: format!("MSM curve {curve}"),
            });
        }
        let (scalars_slot, bases_slot) = match payload {
            Some(NodePayload::MsmBn254 {
                scalars_slot,
                bases_slot,
            }) => (*scalars_slot, *bases_slot),
            _ => (
                self.source_slot(node, None, 0)?,
                self.source_slot(node, None, 1)?,
            ),
        };

        bridge.ensure_inputs_resident(&[scalars_slot, bases_slot])?;
        let scalars_view = bridge.view(scalars_slot)?;
        let bases_view = bridge.view(bases_slot)?;
        let input_bytes = scalars_view.len() + bases_view.len();
        let scalars: Vec<Fr> = scalars_view
            .as_bytes()
            .chunks(32)
            .map(Fr::from_le_bytes_mod_order)
            .collect();
        let mut bases = Vec::new();
        for chunk in bases_view.as_bytes().chunks(32) {
            if chunk.iter().all(|byte| *byte == 0) {
                continue;
            }
            let base = G1Affine::deserialize_compressed(chunk)
                .map_err(|e| RuntimeError::Execution(format!("deserialize BN254 MSM base: {e}")))?;
            bases.push(base);
        }
        let len = scalars.len().min(bases.len());
        let result = G1Projective::msm(&bases[..len], &scalars[..len]).map_err(|len_mismatch| {
            RuntimeError::Execution(format!("BN254 MSM length mismatch at {len_mismatch}"))
        })?;
        let affine = result.into_affine();
        let mut output = Vec::new();
        affine
            .serialize_compressed(&mut output)
            .map_err(|e| RuntimeError::Execution(format!("serialize BN254 MSM result: {e}")))?;
        while output.len() < 96 {
            output.push(0);
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry(
            format!("MSM-{curve}"),
            input_bytes,
            output_bytes,
        ))
    }

    fn execute_poseidon_batch(
        &self,
        node: &ProverNode,
        count: usize,
        width: usize,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        match payload {
            Some(NodePayload::PoseidonGoldilocks { states_slot, .. }) => {
                self.execute_poseidon_batch_goldilocks(node, count, width, *states_slot, bridge)
            }
            _ => Err(RuntimeError::UnsupportedFeature {
                backend: "cpu".into(),
                feature: "PoseidonBatch without PoseidonGoldilocks payload".into(),
            }),
        }
    }

    fn execute_sha256_batch(
        &self,
        node: &ProverNode,
        _count: usize,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let (inputs_slot, batch_count, input_len) = match payload {
            Some(NodePayload::Sha256Batch {
                inputs_slot,
                count,
                input_len,
            }) => (*inputs_slot, *count, *input_len),
            _ => return Err(RuntimeError::MissingPayload(node.id)),
        };

        bridge.ensure_inputs_resident(&[inputs_slot])?;
        let view = bridge.view(inputs_slot)?;
        let input_bytes = view.len();
        let mut output = Vec::with_capacity(batch_count * 32);
        for i in 0..batch_count {
            let start = i * input_len;
            let end = (start + input_len).min(view.len());
            if start >= view.len() {
                break;
            }
            let digest = Sha256::digest(&view.as_bytes()[start..end]);
            output.extend_from_slice(&digest);
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry("Sha256Batch", input_bytes, output_bytes))
    }

    fn execute_merkle_layer(
        &self,
        node: &ProverNode,
        _level: usize,
        _leaf_count: usize,
        payload: &Option<NodePayload>,
        exec_ctx: &ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let (leaves_slot, _digest_slot, hash_fn, leaf_count) = match payload {
            Some(NodePayload::MerkleGoldilocks {
                leaves_slot,
                digest_slot,
                hash_fn,
                leaf_count,
                ..
            }) => (*leaves_slot, *digest_slot, *hash_fn, *leaf_count),
            _ => return Err(RuntimeError::MissingPayload(node.id)),
        };
        bridge.ensure_inputs_resident(&[leaves_slot])?;
        let leaves_view = bridge.view(leaves_slot)?;
        let input_bytes = leaves_view.len();
        let output = match hash_fn {
            MerkleHashFn::Sha256 => {
                let mut output = Vec::new();
                let mut chunks = leaves_view.as_bytes().chunks(32);
                while let Some(left) = chunks.next() {
                    let right = chunks.next().unwrap_or(left);
                    let digest = Sha256::digest([left, right].concat());
                    output.extend_from_slice(&digest);
                }
                output
            }
            MerkleHashFn::Poseidon2Goldilocks => self.poseidon2_goldilocks_merkle_layer(
                node,
                exec_ctx,
                leaves_view.as_bytes(),
                leaf_count,
            )?,
            other => {
                return Err(RuntimeError::UnsupportedFeature {
                    backend: "cpu".into(),
                    feature: format!("Merkle hash {other:?}"),
                });
            }
        };
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry("MerkleLayer", input_bytes, output_bytes))
    }

    fn execute_fri_fold(
        &self,
        node: &ProverNode,
        _folding_factor: usize,
        _codeword_len: usize,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        use p3_baby_bear::BabyBear;
        use p3_field::{Field, PrimeCharacteristicRing, PrimeField32, PrimeField64};
        use p3_goldilocks::Goldilocks;

        match payload {
            Some(NodePayload::FriFoldGoldilocks {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            }) => {
                bridge.ensure_inputs_resident(&[*evals_slot, *alpha_slot, *twiddles_slot])?;
                let evals = bridge.view(*evals_slot)?;
                let alpha = bridge.view(*alpha_slot)?;
                let twiddles = bridge.view(*twiddles_slot)?;
                let alpha_value = alpha.as_u64_slice().first().copied().unwrap_or(0);
                let alpha = Goldilocks::from_u64(alpha_value);
                let inv_two = Goldilocks::from_u64(2).inverse();
                let evals: Vec<Goldilocks> = evals
                    .as_u64_slice()
                    .iter()
                    .copied()
                    .map(Goldilocks::from_u64)
                    .collect();
                let twiddles: Vec<Goldilocks> = twiddles
                    .as_u64_slice()
                    .iter()
                    .copied()
                    .map(Goldilocks::from_u64)
                    .collect();
                let mut output = Vec::with_capacity(evals.len() / 2 * 8);
                for i in 0..(evals.len() / 2) {
                    let left = evals[2 * i];
                    let right = evals[2 * i + 1];
                    let twiddle = twiddles.get(i).copied().unwrap_or(Goldilocks::ONE);
                    let folded = (left + right) * inv_two + alpha * (left - right) * twiddle;
                    output.extend_from_slice(&folded.as_canonical_u64().to_le_bytes());
                }
                let output_bytes = self.write_primary_output(node, bridge, &output)?;
                Ok(Self::telemetry(
                    "FriFold-Goldilocks",
                    evals.len() * 8,
                    output_bytes,
                ))
            }
            Some(NodePayload::FriFoldBabyBear {
                evals_slot,
                alpha_slot,
                twiddles_slot,
            }) => {
                bridge.ensure_inputs_resident(&[*evals_slot, *alpha_slot, *twiddles_slot])?;
                let evals = bridge.view(*evals_slot)?;
                let alpha = bridge.view(*alpha_slot)?;
                let twiddles = bridge.view(*twiddles_slot)?;
                let alpha_value = alpha.as_u32_slice().first().copied().unwrap_or(0);
                let alpha = BabyBear::from_u32(alpha_value);
                let inv_two = BabyBear::from_u32(2).inverse();
                let evals: Vec<BabyBear> = evals
                    .as_u32_slice()
                    .iter()
                    .copied()
                    .map(BabyBear::from_u32)
                    .collect();
                let twiddles: Vec<BabyBear> = twiddles
                    .as_u32_slice()
                    .iter()
                    .copied()
                    .map(BabyBear::from_u32)
                    .collect();
                let mut output = Vec::with_capacity(evals.len() / 2 * 4);
                for i in 0..(evals.len() / 2) {
                    let left = evals[2 * i];
                    let right = evals[2 * i + 1];
                    let twiddle = twiddles.get(i).copied().unwrap_or(BabyBear::ONE);
                    let folded = (left + right) * inv_two + alpha * (left - right) * twiddle;
                    output.extend_from_slice(&folded.as_canonical_u32().to_le_bytes());
                }
                let output_bytes = self.write_primary_output(node, bridge, &output)?;
                Ok(Self::telemetry(
                    "FriFold-BabyBear",
                    evals.len() * 4,
                    output_bytes,
                ))
            }
            _ => Err(RuntimeError::MissingPayload(node.id)),
        }
    }

    fn execute_fri_query_open(
        &self,
        node: &ProverNode,
        query_count: usize,
        tree_depth: usize,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let (proof_slot, query_slot) = match payload {
            Some(NodePayload::FriQueryOpen {
                proof_slot,
                query_slot,
                ..
            }) => (*proof_slot, *query_slot),
            _ => (
                self.source_slot(node, None, 0)?,
                self.source_slot(node, None, 1)?,
            ),
        };
        bridge.ensure_inputs_resident(&[proof_slot, query_slot])?;
        let proof_view = bridge.view(proof_slot)?;
        let query_view = bridge.view(query_slot)?;
        let input_bytes = proof_view.len() + query_view.len();
        let mut output = Vec::new();
        for i in 0..query_count {
            let digest = Sha256::digest(
                [
                    proof_view.as_bytes(),
                    query_view.as_bytes(),
                    &(i as u64).to_le_bytes(),
                    &(tree_depth as u64).to_le_bytes(),
                ]
                .concat(),
            );
            output.extend_from_slice(&digest);
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry("FriQueryOpen", input_bytes, output_bytes))
    }

    fn execute_transcript_update(
        &self,
        node: &ProverNode,
        payload: &Option<NodePayload>,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let state_slot = match payload {
            Some(NodePayload::TranscriptUpdate { state_slot }) => *state_slot,
            _ => {
                return Ok(Self::telemetry("TranscriptUpdate", 0, 0));
            }
        };
        bridge.ensure_inputs_resident(&[state_slot])?;
        let state = bridge.view(state_slot)?;
        let input_bytes = state.len();
        let digest = Sha256::digest(state.as_bytes());
        let output_bytes = self.write_primary_output(node, bridge, &digest)?;
        Ok(Self::telemetry(
            "TranscriptUpdate",
            input_bytes,
            output_bytes,
        ))
    }

    fn execute_proof_encode(
        &self,
        node: &ProverNode,
        payload: &Option<NodePayload>,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let (input_slots, output_kind) = match payload {
            Some(NodePayload::ProofEncode {
                input_slots,
                output_kind,
            }) => (input_slots.clone(), *output_kind),
            _ => (
                node.input_buffers
                    .iter()
                    .map(|handle| handle.slot)
                    .collect(),
                ProofOutputKind::RawBytes,
            ),
        };

        let mut assembled = Vec::new();
        let mut input_bytes = 0usize;
        for slot in input_slots {
            if bridge.is_resident(slot) {
                let view = bridge.view(slot)?;
                input_bytes += view.len();
                assembled.extend_from_slice(view.as_bytes());
            }
        }

        let output_name = match output_kind {
            ProofOutputKind::Groth16Proof => "groth16_proof",
            ProofOutputKind::Plonky3Proof => "plonky3_proof",
            ProofOutputKind::BackendArtifact => "proof_artifact",
            ProofOutputKind::WrappedProof => "wrapped_proof",
            ProofOutputKind::RawBytes => "raw_proof",
        };
        if output_kind == ProofOutputKind::BackendArtifact
            && assembled.is_empty()
            && exec_ctx.proof_artifact().is_some()
        {
            let serialized = serde_json::to_vec(exec_ctx.proof_artifact().ok_or_else(|| {
                RuntimeError::Execution("proof artifact disappeared during proof encode".into())
            })?)
            .map_err(|e| RuntimeError::Execution(format!("serialize proof artifact: {e}")))?;
            let output_bytes = self.write_primary_output(node, bridge, &serialized)?;
            exec_ctx.set_output(output_name, serialized);
            return Ok(Self::telemetry("ProofEncode", input_bytes, output_bytes));
        }
        let output_bytes = self.write_primary_output(node, bridge, &assembled)?;
        exec_ctx.set_output(output_name, assembled);
        Ok(Self::telemetry("ProofEncode", input_bytes, output_bytes))
    }

    fn execute_verifier_embed(
        &self,
        node: &ProverNode,
        inner_scheme: &str,
        payload: &Option<NodePayload>,
        exec_ctx: &ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let wrapper_input_slot = match payload {
            Some(NodePayload::VerifierEmbed {
                wrapper_input_slot, ..
            }) => *wrapper_input_slot,
            _ => self.source_slot(node, None, 0)?,
        };
        bridge.ensure_inputs_resident(&[wrapper_input_slot])?;
        let view = bridge.view(wrapper_input_slot)?;
        let input_bytes = view.len();
        let transcript_sha256 = format!("{:x}", Sha256::digest(view.as_bytes()));

        let mut context = serde_json::Map::new();
        context.insert(
            "inner_scheme".to_string(),
            serde_json::Value::String(inner_scheme.to_string()),
        );
        context.insert(
            "transcript_sha256".to_string(),
            serde_json::Value::String(transcript_sha256),
        );
        if let Some(source_proof) = exec_ctx.source_proof.as_ref() {
            context.insert(
                "source_backend".to_string(),
                serde_json::Value::String(source_proof.backend.as_str().to_string()),
            );
            context.insert(
                "source_program_digest".to_string(),
                serde_json::Value::String(source_proof.program_digest.clone()),
            );
            context.insert(
                "source_public_inputs_count".to_string(),
                serde_json::Value::from(source_proof.public_inputs.len() as u64),
            );
        }
        if let Some(compiled) = exec_ctx.compiled.as_ref() {
            context.insert(
                "compiled_backend".to_string(),
                serde_json::Value::String(compiled.backend.as_str().to_string()),
            );
            context.insert(
                "compiled_program_digest".to_string(),
                serde_json::Value::String(compiled.program_digest.clone()),
            );
        }
        if let Some(preview) = exec_ctx.wrapper_preview.as_ref() {
            context.insert(
                "wrapper".to_string(),
                serde_json::Value::String(preview.wrapper.clone()),
            );
            context.insert(
                "wrapper_strategy".to_string(),
                serde_json::Value::String(preview.strategy.clone()),
            );
            context.insert(
                "wrapper_trust_model".to_string(),
                serde_json::Value::String(preview.trust_model.clone()),
            );
        }
        let output = serde_json::to_vec(&serde_json::Value::Object(context)).map_err(|e| {
            RuntimeError::Execution(format!("serialize verifier embed context: {e}"))
        })?;
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry(
            format!("VerifierEmbed-{inner_scheme}"),
            input_bytes,
            output_bytes,
        ))
    }

    fn execute_outer_prove(
        &self,
        node: &ProverNode,
        outer_scheme: &str,
        payload: &Option<NodePayload>,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let proving_input_slot = match payload {
            Some(NodePayload::OuterProve {
                proving_input_slot, ..
            }) => *proving_input_slot,
            _ => self.source_slot(node, None, 0)?,
        };
        bridge.ensure_inputs_resident(&[proving_input_slot])?;
        let view = bridge.view(proving_input_slot)?;
        let proving_input = view.as_bytes().to_vec();
        let input_bytes = proving_input.len();
        if exec_ctx.wrapper_preview.is_some() {
            if outer_scheme != "groth16" {
                return Err(RuntimeError::UnsupportedFeature {
                    backend: "runtime-wrapper".into(),
                    feature: format!("outer scheme {outer_scheme}"),
                });
            }

            let source_proof = exec_ctx.source_proof.as_ref().ok_or_else(|| {
                RuntimeError::UnsupportedFeature {
                    backend: "runtime-wrapper".into(),
                    feature:
                        "wrapper outer prove requires a source proof artifact in the ExecutionContext"
                            .to_string(),
                }
            })?;
            let compiled =
                exec_ctx
                    .compiled
                    .as_ref()
                    .ok_or_else(|| {
                        RuntimeError::UnsupportedFeature {
                    backend: "runtime-wrapper".into(),
                    feature:
                        "wrapper outer prove requires a compiled artifact in the ExecutionContext"
                            .to_string(),
                }
                    })?;
            let policy = exec_ctx.wrapper_policy.ok_or_else(|| RuntimeError::UnsupportedFeature {
                backend: "runtime-wrapper".into(),
                feature:
                    "wrapper outer prove requires a wrapper execution policy in the ExecutionContext"
                        .to_string(),
            })?;

            let registry = default_wrapper_registry();
            let wrapper = registry
                .find(source_proof.backend, zkf_core::BackendKind::ArkworksGroth16)
                .ok_or_else(|| RuntimeError::UnsupportedFeature {
                    backend: "runtime-wrapper".into(),
                    feature: format!("wrapper {} -> arkworks-groth16", source_proof.backend),
                })?;

            let mut artifact = wrapper
                .wrap_with_policy(source_proof, compiled, policy)
                .map_err(|e| RuntimeError::Execution(e.to_string()))?;
            let mut proving_input_hasher = Sha256::new();
            proving_input_hasher.update(&proving_input);
            artifact.metadata.insert(
                "runtime_outer_input_sha256".to_string(),
                format!("{:x}", proving_input_hasher.finalize()),
            );
            let output = if artifact.proof.is_empty() {
                serde_json::to_vec(&artifact).map_err(|e| {
                    RuntimeError::Execution(format!(
                        "serialize wrapped artifact for runtime output: {e}"
                    ))
                })?
            } else {
                artifact.proof.clone()
            };
            let output_bytes = self.write_primary_output(node, bridge, &output)?;
            exec_ctx.set_output("wrapped_proof_runtime", output.clone());
            exec_ctx.set_wrapped_artifact(artifact);
            return Ok(Self::telemetry(
                format!("OuterProve-{outer_scheme}"),
                input_bytes,
                output_bytes,
            ));
        }

        let mut preimage = Vec::new();
        preimage.extend_from_slice(outer_scheme.as_bytes());
        preimage.extend_from_slice(&proving_input);
        let output = Sha256::digest(&preimage).to_vec();
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry(
            format!("OuterProve-{outer_scheme}"),
            input_bytes,
            output_bytes,
        ))
    }

    fn execute_backend_prove(
        &self,
        node: &ProverNode,
        backend_name: &str,
        payload: &Option<NodePayload>,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let transcript_slot = match payload {
            Some(NodePayload::BackendProve {
                transcript_slot, ..
            }) => *transcript_slot,
            _ => self.source_slot(node, None, 0)?,
        };
        bridge.ensure_inputs_resident(&[transcript_slot])?;
        let transcript = bridge.view(transcript_slot)?;
        let input_bytes = transcript.len();
        let route = match payload {
            Some(NodePayload::BackendProve { route, .. }) => *route,
            _ => BackendRoute::Auto,
        };

        let backend = backend_name.parse::<BackendKind>().map_err(|e| {
            RuntimeError::Execution(format!("parse runtime backend '{backend_name}': {e}"))
        })?;
        let program = exec_ctx.program.as_ref().map(Arc::clone).ok_or_else(|| {
            RuntimeError::UnsupportedFeature {
                backend: "runtime".into(),
                feature: "backend proving requires a source program in the ExecutionContext".into(),
            }
        })?;
        let compiled = if let Some(compiled) = exec_ctx.compiled.as_ref() {
            (**compiled).clone()
        } else {
            backend_for_route(backend, route)
                .compile(program.as_ref())
                .map_err(|e| RuntimeError::Execution(format!("compile {backend}: {e}")))?
        };
        let source_witness = if let Some(witness) = exec_ctx.witness.as_ref().map(Arc::clone) {
            if let Some(inputs) = exec_ctx.witness_inputs.as_ref() {
                Self::validate_supplied_inputs_against_witness(
                    program.as_ref(),
                    inputs,
                    witness.as_ref(),
                )?;
            }
            (*witness).clone()
        } else if let Some(inputs) = exec_ctx.witness_inputs.as_ref() {
            zkf_core::generate_witness(program.as_ref(), inputs)
                .map_err(|e| RuntimeError::WitnessGeneration(format!("{e}")))?
        } else {
            return Err(RuntimeError::UnsupportedFeature {
                backend: "runtime".into(),
                feature:
                    "backend proving requires witness inputs or a precomputed witness in the ExecutionContext"
                        .into(),
            });
        };
        let witness = if ensure_witness_completeness(&compiled.program, &source_witness).is_ok() {
            source_witness
        } else {
            prepare_witness_for_proving(&compiled, &source_witness).map_err(|error| {
                RuntimeError::WitnessGeneration(format!(
                    "backend prove could not normalize witness: {error}"
                ))
            })?
        };
        ensure_witness_completeness(&compiled.program, &witness).map_err(|error| {
            RuntimeError::WitnessGeneration(format!(
                "backend prove normalized witness is incomplete: {error}"
            ))
        })?;
        check_constraints(&compiled.program, &witness).map_err(|error| {
            RuntimeError::WitnessGeneration(format!(
                "backend prove normalized witness failed compiled constraints: {error}"
            ))
        })?;
        exec_ctx.compiled = Some(std::sync::Arc::new(compiled.clone()));
        exec_ctx.witness = Some(std::sync::Arc::new(witness.clone()));

        let mut artifact = backend_for_route(backend, route)
            .prove(&compiled, &witness)
            .map_err(|e| RuntimeError::Execution(format!("prove {backend}: {e}")))?;
        artifact
            .metadata
            .insert("umpg_execution".into(), "true".into());
        artifact
            .metadata
            .insert("umpg_backend_prove".into(), "true".into());
        artifact.metadata.insert(
            "umpg_backend_prove_backend".into(),
            backend.as_str().to_string(),
        );
        artifact.metadata.insert(
            "umpg_backend_prove_transcript_sha256".into(),
            format!("{:x}", Sha256::digest(transcript.as_bytes())),
        );

        let digest = Sha256::digest(&artifact.proof);
        let output_bytes = self.write_primary_output(node, bridge, digest.as_slice())?;
        exec_ctx.set_output("backend_proof_runtime", artifact.proof.clone());
        exec_ctx.set_proof_artifact(artifact);

        Ok(CpuNodeTelemetry {
            op_name: format!("BackendProve-{backend}"),
            wall_time: Duration::ZERO,
            input_bytes,
            output_bytes,
            delegated: true,
            delegated_backend: Some(backend.as_str().to_string()),
        })
    }

    fn execute_backend_fold(
        &self,
        node: &ProverNode,
        backend_name: &str,
        payload: &Option<NodePayload>,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        let (transcript_slot, compress) = match payload {
            Some(NodePayload::BackendFold {
                transcript_slot,
                compress,
                ..
            }) => (*transcript_slot, *compress),
            _ => (self.source_slot(node, None, 0)?, true),
        };
        bridge.ensure_inputs_resident(&[transcript_slot])?;
        let transcript = bridge.view(transcript_slot)?;
        let input_bytes = transcript.len();

        let backend = backend_name.parse::<BackendKind>().map_err(|e| {
            RuntimeError::Execution(format!("parse runtime backend '{backend_name}': {e}"))
        })?;
        let compiled =
            exec_ctx
                .compiled
                .as_ref()
                .ok_or_else(|| RuntimeError::UnsupportedFeature {
                    backend: "runtime".into(),
                    feature: "backend folding requires a compiled artifact in the ExecutionContext"
                        .into(),
                })?;
        let witnesses =
            exec_ctx
                .fold_witnesses
                .as_ref()
                .ok_or_else(|| RuntimeError::UnsupportedFeature {
                    backend: "runtime".into(),
                    feature: "backend folding requires per-step witnesses in the ExecutionContext"
                        .into(),
                })?;

        let fold_result = zkf_backends::try_fold_native(compiled, witnesses.as_slice(), compress)
            .ok_or_else(|| RuntimeError::UnsupportedFeature {
                backend: backend.as_str().to_string(),
                feature: "native fold/IVC is not compiled into this runtime".into(),
            })?
            .map_err(|e| RuntimeError::Execution(format!("fold {backend}: {e}")))?;

        let mut artifact = fold_result.artifact;
        artifact
            .metadata
            .insert("umpg_execution".into(), "true".into());
        artifact
            .metadata
            .insert("umpg_backend_fold".into(), "true".into());
        artifact.metadata.insert(
            "umpg_backend_fold_backend".into(),
            backend.as_str().to_string(),
        );
        artifact.metadata.insert(
            "umpg_backend_fold_steps".into(),
            fold_result.steps.to_string(),
        );
        artifact.metadata.insert(
            "umpg_backend_fold_compressed".into(),
            fold_result.compressed.to_string(),
        );
        artifact.metadata.insert(
            "umpg_backend_fold_transcript_sha256".into(),
            format!("{:x}", Sha256::digest(transcript.as_bytes())),
        );

        let digest = Sha256::digest(&artifact.proof);
        let output_bytes = self.write_primary_output(node, bridge, digest.as_slice())?;
        exec_ctx.set_output("backend_fold_runtime", artifact.proof.clone());
        exec_ctx.set_proof_artifact(artifact);

        Ok(CpuNodeTelemetry {
            op_name: format!("BackendFold-{backend}"),
            wall_time: Duration::ZERO,
            input_bytes,
            output_bytes,
            delegated: true,
            delegated_backend: Some(backend.as_str().to_string()),
        })
    }

    fn execute_poseidon_batch_goldilocks(
        &self,
        node: &ProverNode,
        count: usize,
        width: usize,
        states_slot: u32,
        bridge: &mut BufferBridge,
    ) -> Result<CpuNodeTelemetry, RuntimeError> {
        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
        use p3_symmetric::Permutation;
        use rand09::SeedableRng;

        if width > 16 {
            return Err(RuntimeError::UnsupportedFeature {
                backend: "cpu".into(),
                feature: format!("PoseidonBatch width {width}"),
            });
        }

        bridge.ensure_inputs_resident(&[states_slot])?;
        let view = bridge.view(states_slot)?;
        let input_bytes = view.len();
        let mut rng = rand09::rngs::SmallRng::seed_from_u64(42);
        let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
        let mut output = Vec::with_capacity(count * width * 8);
        for chunk in view.as_u64_slice().chunks(width).take(count) {
            let mut state = [Goldilocks::ZERO; 16];
            for (idx, value) in chunk.iter().enumerate() {
                state[idx] = Goldilocks::from_u64(*value);
            }
            perm.permute_mut(&mut state);
            for item in state.iter().take(width) {
                output.extend_from_slice(&item.as_canonical_u64().to_le_bytes());
            }
        }
        let output_bytes = self.write_primary_output(node, bridge, &output)?;
        Ok(Self::telemetry("PoseidonBatch", input_bytes, output_bytes))
    }

    fn poseidon2_goldilocks_merkle_layer(
        &self,
        node: &ProverNode,
        exec_ctx: &ExecutionContext,
        leaves_bytes: &[u8],
        leaf_count: usize,
    ) -> Result<Vec<u8>, RuntimeError> {
        use p3_field::{PrimeCharacteristicRing, PrimeField64};
        use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
        use p3_symmetric::Permutation;
        use rand09::SeedableRng;

        let input_values: Vec<u64> = leaves_bytes
            .chunks(8)
            .map(|chunk| {
                let mut bytes = [0u8; 8];
                let copy_len = chunk.len().min(8);
                bytes[..copy_len].copy_from_slice(&chunk[..copy_len]);
                u64::from_le_bytes(bytes)
            })
            .collect();
        let leaf_width = (input_values.len() / leaf_count.max(1)).max(1);
        let parent_count = leaf_count.max(1).div_ceil(2);
        let output_u64_width = node
            .output_buffers
            .first()
            .map(|handle| (handle.size_bytes / 8) / parent_count.max(1))
            .unwrap_or(1)
            .clamp(1, 8);
        let seed = runtime_poseidon_seed(exec_ctx);
        let mut rng = rand09::rngs::SmallRng::seed_from_u64(seed);
        let perm = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);

        let mut output = Vec::with_capacity(parent_count * output_u64_width * 8);
        for parent_idx in 0..parent_count {
            let left_start = (2 * parent_idx) * leaf_width;
            let right_leaf = (2 * parent_idx + 1).min(leaf_count.saturating_sub(1));
            let right_start = right_leaf * leaf_width;
            let mut state = [Goldilocks::ZERO; 16];
            for i in 0..leaf_width.min(8) {
                if let Some(value) = input_values.get(left_start + i) {
                    state[i] = Goldilocks::from_u64(*value);
                }
                if let Some(value) = input_values.get(right_start + i) {
                    state[8 + i] = Goldilocks::from_u64(*value);
                }
            }
            perm.permute_mut(&mut state);
            for item in state.iter().take(output_u64_width) {
                output.extend_from_slice(&item.as_canonical_u64().to_le_bytes());
            }
        }
        Ok(output)
    }
}

fn runtime_poseidon_seed(exec_ctx: &ExecutionContext) -> u64 {
    let digest_owned = exec_ctx
        .program
        .as_ref()
        .map(|program| program.digest_hex());
    let digest = exec_ctx
        .compiled
        .as_ref()
        .map(|compiled| compiled.program_digest.as_str())
        .or({
            exec_ctx
                .source_proof
                .as_ref()
                .map(|proof| proof.program_digest.as_str())
        })
        .or(digest_owned.as_deref())
        .unwrap_or("zkf-runtime-default-seed");
    let mut hasher = Sha256::new();
    hasher.update(digest.as_bytes());
    let hash = hasher.finalize();
    let mut seed_bytes = [0u8; 8];
    seed_bytes.copy_from_slice(&hash[..8]);
    u64::from_le_bytes(seed_bytes)
}

impl Default for CpuBackendDriver {
    fn default() -> Self {
        Self::new()
    }
}
