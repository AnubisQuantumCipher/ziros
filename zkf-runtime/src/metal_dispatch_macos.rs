use crate::buffer_bridge::{BufferBridge, GpuBufferAllocator, ResidencyClass};
use crate::error::RuntimeError;
use crate::execution::{ExecutionContext, MerkleHashFn, NodePayload};
use crate::graph::{ProverNode, ProverOp};
use crate::metal_driver::{
    DispatchResult, FallbackSignal, GpuDispatchDriver, GpuNodeTelemetry, GpuVerificationMode,
};
use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_metal::MTLBuffer;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zkf_core::FieldElement;
use zkf_core::acceleration::{MsmAccelerator, NttAccelerator};
use zkf_metal::poseidon2;
use zkf_metal::{
    MetalBn254Ntt, MetalContext, MetalFri, MetalHasher, MetalMsmAccelerator, MetalNttAccelerator,
    MetalPoseidon2, current_thresholds, global_context,
};

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

struct BufferMap(HashMap<u64, Retained<ProtocolObject<dyn MTLBuffer>>>);

unsafe impl Send for BufferMap {}
unsafe impl Sync for BufferMap {}

static BUFFER_REGISTRY: Mutex<Option<BufferMap>> = Mutex::new(None);

fn registry_insert(token: u64, buffer: Retained<ProtocolObject<dyn MTLBuffer>>) {
    let mut guard = BUFFER_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(|| BufferMap(HashMap::new()));
    map.0.insert(token, buffer);
}

fn registry_remove(token: u64) {
    let mut guard = BUFFER_REGISTRY.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(map) = guard.as_mut() {
        map.0.remove(&token);
    }
}

struct RuntimeMetalBufferAllocator {
    ctx: &'static MetalContext,
}

impl RuntimeMetalBufferAllocator {
    fn new() -> Option<Self> {
        let ctx = global_context()?;
        Some(Self { ctx })
    }
}

impl GpuBufferAllocator for RuntimeMetalBufferAllocator {
    fn alloc_shared(&self, size_bytes: usize) -> Option<(*mut u8, u64)> {
        let buffer = self.ctx.new_buffer(size_bytes)?;
        let ptr = buffer.contents().as_ptr() as *mut u8;
        let token = NEXT_TOKEN.fetch_add(1, Ordering::Relaxed);
        registry_insert(token, buffer);
        Some((ptr, token))
    }

    fn free_shared(&self, gpu_token: u64) {
        registry_remove(gpu_token);
    }

    fn is_available(&self) -> bool {
        self.ctx.dispatch_allowed()
    }
}

struct RuntimeMetalDispatchDriver {
    ctx: &'static MetalContext,
    verification_mode: GpuVerificationMode,
}

impl RuntimeMetalDispatchDriver {
    fn new(verification_mode: GpuVerificationMode) -> Option<Self> {
        let ctx = global_context()?;
        Some(Self {
            ctx,
            verification_mode,
        })
    }
}

fn fallback(node: &ProverNode, reason: impl Into<String>) -> DispatchResult {
    Err(FallbackSignal {
        node_id: node.id,
        reason: reason.into(),
    })
}

fn ok_telemetry(
    accelerator_name: &str,
    wall_time: Duration,
    input_bytes: usize,
    output_bytes: usize,
    residency_class: &str,
) -> DispatchResult {
    Ok(GpuNodeTelemetry {
        accelerator_name: accelerator_name.to_string(),
        fell_back: false,
        wall_time,
        input_bytes,
        output_bytes,
        residency_class: residency_class.to_string(),
    })
}

fn residency_label(rc: Option<ResidencyClass>) -> &'static str {
    match rc {
        Some(ResidencyClass::MetalShared) => "metal-shared",
        Some(ResidencyClass::Cpu) => "cpu",
        Some(ResidencyClass::Spilled) => "spilled",
        None => "unknown",
    }
}

fn runtime_poseidon_seed(exec_ctx: &ExecutionContext) -> u64 {
    use sha2::{Digest, Sha256};

    let digest_owned = exec_ctx
        .program
        .as_ref()
        .map(|program| program.digest_hex());
    let digest = exec_ctx
        .compiled
        .as_ref()
        .map(|compiled| compiled.program_digest.as_str())
        .or_else(|| {
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

fn verified_pinned_gpu_lane_supports(node: &ProverNode) -> bool {
    match node.op {
        ProverOp::Msm { curve: "bn254", .. } => true,
        ProverOp::Ntt {
            field: "bn254_fr" | "goldilocks",
            ..
        } => true,
        ProverOp::PoseidonBatch { width, .. } => width <= 16,
        ProverOp::Sha256Batch { .. } => true,
        _ => false,
    }
}

fn should_try_metal_for_node(node: &ProverNode, verification_mode: GpuVerificationMode) -> bool {
    if verification_mode == GpuVerificationMode::VerifiedPinned
        && !verified_pinned_gpu_lane_supports(node)
    {
        return false;
    }

    let thresholds = current_thresholds();

    match node.op {
        ProverOp::Msm {
            num_scalars,
            curve: "bn254",
        } => num_scalars >= thresholds.msm,
        ProverOp::Ntt {
            size,
            field: "bn254_fr" | "goldilocks",
            ..
        } => size >= thresholds.ntt,
        ProverOp::PoseidonBatch { count, .. } => count >= thresholds.poseidon2,
        ProverOp::Sha256Batch { count } => count >= thresholds.poseidon2.max(256),
        ProverOp::FriFold { codeword_len, .. } => codeword_len >= thresholds.ntt,
        _ => false,
    }
}

fn write_primary_output(
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
            "{} produced {} bytes for a {} byte Metal output buffer",
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

fn verified_attestation_error(node: &ProverNode, reason: impl Into<String>) -> RuntimeError {
    RuntimeError::GpuFallbackRejected {
        node: format!("{:?} ({}) {}", node.id, node.op.name(), reason.into()),
    }
}

impl RuntimeMetalDispatchDriver {
    fn attest_verified_dispatch(
        &self,
        node: &ProverNode,
        payload: Option<&NodePayload>,
    ) -> Result<(), RuntimeError> {
        if self.verification_mode != GpuVerificationMode::VerifiedPinned {
            return Ok(());
        }

        let attest = |library_id: &str, entrypoint: &str| {
            self.ctx
                .attest_verified_pipeline(library_id, entrypoint)
                .map(|_| ())
                .map_err(|err| {
                    verified_attestation_error(node, format!("attestation failed: {err}"))
                })
        };

        match (&node.op, payload) {
            (ProverOp::Msm { curve: "bn254", .. }, Some(NodePayload::MsmBn254 { .. })) => {
                attest("bn254_msm_library", "msm_bucket_assign")?;
                attest("bn254_msm_library", "msm_bucket_acc")?;
                attest("bn254_msm_library", "msm_bucket_reduce")?;
                attest("bn254_msm_library", "msm_window_combine")?;
                Ok(())
            }
            (
                ProverOp::Ntt {
                    field: "bn254_fr", ..
                },
                Some(NodePayload::NttBn254 { .. }),
            ) => {
                attest("main_library", "ntt_small_bn254")?;
                attest("main_library", "ntt_hybrid_bn254")?;
                attest("main_library", "ntt_butterfly_bn254")?;
                Ok(())
            }
            (
                ProverOp::Ntt {
                    field: "goldilocks",
                    ..
                },
                Some(NodePayload::NttGoldilocks { .. }),
            ) => {
                attest("main_library", "ntt_small_goldilocks")?;
                attest("main_library", "ntt_hybrid_goldilocks")?;
                attest("main_library", "ntt_butterfly_goldilocks")?;
                Ok(())
            }
            (
                ProverOp::PoseidonBatch { width, .. },
                Some(NodePayload::PoseidonGoldilocks { .. }),
            ) if *width <= 16 => attest("main_library", "poseidon2_goldilocks"),
            (ProverOp::Sha256Batch { .. }, Some(NodePayload::Sha256Batch { .. })) => {
                attest("hash_library", "batch_sha256")
            }
            _ => Err(verified_attestation_error(
                node,
                "payload is outside the pinned verified GPU surface",
            )),
        }
    }
}

impl GpuDispatchDriver for RuntimeMetalDispatchDriver {
    fn is_available(&self) -> bool {
        self.ctx.dispatch_allowed()
    }

    fn verification_mode(&self) -> GpuVerificationMode {
        self.verification_mode
    }

    fn verified_lane_allows(&self, node: &ProverNode) -> bool {
        if self.verification_mode == GpuVerificationMode::VerifiedPinned {
            verified_pinned_gpu_lane_supports(node)
        } else {
            true
        }
    }

    fn should_try_on_either(&self, node: &ProverNode) -> bool {
        should_try_metal_for_node(node, self.verification_mode)
    }

    fn execute(
        &self,
        node: &ProverNode,
        exec_ctx: &mut ExecutionContext,
        bridge: &mut BufferBridge,
    ) -> Result<DispatchResult, RuntimeError> {
        if self.verification_mode == GpuVerificationMode::VerifiedPinned
            && !verified_pinned_gpu_lane_supports(node)
        {
            return Err(RuntimeError::GpuFallbackRejected {
                node: format!(
                    "{:?} ({}) is outside the pinned verified GPU whitelist",
                    node.id,
                    node.op.name()
                ),
            });
        }

        let payload = exec_ctx.payload(node.id);
        self.attest_verified_dispatch(node, payload)?;

        let result = match (&node.op, payload) {
            (
                ProverOp::Msm { curve: "bn254", .. },
                Some(NodePayload::MsmBn254 {
                    scalars_slot,
                    bases_slot,
                }),
            ) => {
                let scalars_slot = *scalars_slot;
                let bases_slot = *bases_slot;
                bridge.ensure_inputs_resident(&[scalars_slot, bases_slot])?;
                let rc = residency_label(bridge.residency(scalars_slot));
                let scalars_view = bridge.view(scalars_slot)?;
                let bases_view = bridge.view(bases_slot)?;
                let input_bytes = scalars_view.len() + bases_view.len();
                let scalars: Vec<FieldElement> = scalars_view
                    .as_bytes()
                    .chunks(32)
                    .map(FieldElement::from_le_bytes)
                    .collect();
                let bases: Vec<Vec<u8>> = bases_view
                    .as_bytes()
                    .chunks(32)
                    .filter(|chunk| !chunk.iter().all(|byte| *byte == 0))
                    .map(|chunk| chunk.to_vec())
                    .collect();

                let start = Instant::now();
                let Some(msm) = MetalMsmAccelerator::new() else {
                    return Ok(fallback(node, "MetalMsmAccelerator unavailable"));
                };
                let result = msm
                    .msm_g1(
                        &scalars[..scalars.len().min(bases.len())],
                        &bases[..bases.len().min(scalars.len())],
                    )
                    .map_err(|e| RuntimeError::DriverDispatch {
                        node: node.op.name().to_string(),
                        reason: e.to_string(),
                    })?;
                let output_bytes = write_primary_output(node, bridge, &result)?;
                ok_telemetry(
                    "metal-msm-bn254",
                    start.elapsed(),
                    input_bytes,
                    output_bytes,
                    rc,
                )
            }
            (
                ProverOp::Ntt {
                    field: "bn254_fr",
                    inverse,
                    ..
                },
                Some(NodePayload::NttBn254 { values_slot }),
            ) => {
                let values_slot = *values_slot;
                bridge.ensure_inputs_resident(&[values_slot])?;
                let rc = residency_label(bridge.residency(values_slot));
                let input_view = bridge.view(values_slot)?;
                let input_bytes = input_view.len();
                let mut values: Vec<Fr> = input_view
                    .as_bytes()
                    .chunks(32)
                    .map(Fr::from_le_bytes_mod_order)
                    .collect();
                let target_size = match &node.op {
                    ProverOp::Ntt { size, .. } => *size,
                    _ => values.len(),
                };
                values.resize(target_size, Fr::from(0u64));

                let start = Instant::now();
                let Some(ntt) = MetalBn254Ntt::new() else {
                    return Ok(fallback(node, "MetalNttAccelerator unavailable"));
                };
                if *inverse {
                    ntt.ifft_in_place(&mut values, Fr::ONE).ok_or_else(|| {
                        RuntimeError::DriverDispatch {
                            node: node.op.name().to_string(),
                            reason: "Metal BN254 inverse NTT failed".to_string(),
                        }
                    })?;
                } else {
                    ntt.fft_in_place(&mut values, Fr::ONE).ok_or_else(|| {
                        RuntimeError::DriverDispatch {
                            node: node.op.name().to_string(),
                            reason: "Metal BN254 forward NTT failed".to_string(),
                        }
                    })?;
                }
                let mut output = Vec::with_capacity(values.len() * 32);
                for value in values {
                    let bytes = value.into_bigint().to_bytes_le();
                    let mut padded = [0u8; 32];
                    let copy_len = bytes.len().min(32);
                    padded[..copy_len].copy_from_slice(&bytes[..copy_len]);
                    output.extend_from_slice(&padded);
                }
                let output_bytes = write_primary_output(node, bridge, &output)?;
                ok_telemetry(
                    "metal-ntt-bn254",
                    start.elapsed(),
                    input_bytes,
                    output_bytes,
                    rc,
                )
            }
            (
                ProverOp::Ntt {
                    field: "goldilocks",
                    inverse,
                    ..
                },
                Some(NodePayload::NttGoldilocks { values_slot }),
            ) => {
                let values_slot = *values_slot;
                bridge.ensure_inputs_resident(&[values_slot])?;
                let rc = residency_label(bridge.residency(values_slot));
                let input_view = bridge.view(values_slot)?;
                let input_bytes = input_view.len();
                let mut values: Vec<FieldElement> = input_view
                    .as_bytes()
                    .chunks(8)
                    .map(|chunk| {
                        let mut bytes = [0u8; 8];
                        let copy_len = chunk.len().min(8);
                        bytes[..copy_len].copy_from_slice(&chunk[..copy_len]);
                        FieldElement::from_u64(u64::from_le_bytes(bytes))
                    })
                    .collect();

                let start = Instant::now();
                let Some(ntt) = MetalNttAccelerator::new() else {
                    return Ok(fallback(node, "MetalNttAccelerator unavailable"));
                };
                if *inverse {
                    ntt.inverse_ntt(&mut values)
                        .map_err(|e| RuntimeError::DriverDispatch {
                            node: node.op.name().to_string(),
                            reason: e.to_string(),
                        })?;
                } else {
                    ntt.forward_ntt(&mut values)
                        .map_err(|e| RuntimeError::DriverDispatch {
                            node: node.op.name().to_string(),
                            reason: e.to_string(),
                        })?;
                }
                let mut output = Vec::with_capacity(values.len() * 8);
                for value in values {
                    let mut bytes = [0u8; 8];
                    let src = value.to_le_bytes();
                    let copy_len = src.len().min(8);
                    bytes[..copy_len].copy_from_slice(&src[..copy_len]);
                    output.extend_from_slice(&bytes);
                }
                let output_bytes = write_primary_output(node, bridge, &output)?;
                ok_telemetry(
                    "metal-ntt-goldilocks",
                    start.elapsed(),
                    input_bytes,
                    output_bytes,
                    rc,
                )
            }
            (
                ProverOp::PoseidonBatch { .. },
                Some(NodePayload::PoseidonGoldilocks {
                    states_slot,
                    round_constants_slot,
                    n_ext,
                    n_int,
                }),
            ) => {
                let states_slot = *states_slot;
                bridge.ensure_inputs_resident(&[states_slot])?;
                let rc = residency_label(bridge.residency(states_slot));
                let input_view = bridge.view(states_slot)?;
                let input_bytes = input_view.len();
                let (count, width) = match node.op {
                    ProverOp::PoseidonBatch { count, width } => (count, width),
                    _ => unreachable!(),
                };
                if width > 16 {
                    return Ok(fallback(
                        node,
                        format!("PoseidonBatch width {width} exceeds 16"),
                    ));
                }

                let mut states = vec![0u64; count * 16];
                for (perm_idx, chunk) in input_view
                    .as_u64_slice()
                    .chunks(width.max(1))
                    .take(count)
                    .enumerate()
                {
                    let state_offset = perm_idx * 16;
                    for (idx, value) in chunk.iter().take(width).enumerate() {
                        states[state_offset + idx] = *value;
                    }
                }

                let round_constants = if *round_constants_slot != 0
                    && bridge.ensure_resident(*round_constants_slot).is_ok()
                {
                    bridge
                        .view(*round_constants_slot)
                        .map(|view| view.as_u64_slice().to_vec())
                        .unwrap_or_default()
                } else {
                    let (rcs, _, _) = poseidon2::goldilocks::flatten_round_constants(42);
                    rcs
                };
                if round_constants.is_empty() {
                    return Ok(fallback(node, "Poseidon round constants unavailable"));
                }

                let start = Instant::now();
                let Some(poseidon) = MetalPoseidon2::new() else {
                    return Ok(fallback(node, "MetalPoseidon2 unavailable"));
                };
                if !poseidon.batch_permute_goldilocks(&mut states, &round_constants, *n_ext, *n_int)
                {
                    return Ok(fallback(
                        node,
                        "MetalPoseidon2 Goldilocks permutation failed",
                    ));
                }

                let mut output = Vec::with_capacity(count * width * 8);
                for perm_idx in 0..count {
                    let state_offset = perm_idx * 16;
                    for i in 0..width {
                        output.extend_from_slice(&states[state_offset + i].to_le_bytes());
                    }
                }
                let output_bytes = write_primary_output(node, bridge, &output)?;
                ok_telemetry(
                    "metal-poseidon2-goldilocks",
                    start.elapsed(),
                    input_bytes,
                    output_bytes,
                    rc,
                )
            }
            (
                ProverOp::Sha256Batch { .. },
                Some(NodePayload::Sha256Batch {
                    inputs_slot,
                    count,
                    input_len,
                }),
            ) => {
                let inputs_slot = *inputs_slot;
                let count = *count;
                let input_len = *input_len;
                bridge.ensure_inputs_resident(&[inputs_slot])?;
                let rc = residency_label(bridge.residency(inputs_slot));

                let start = Instant::now();
                match MetalHasher::new() {
                    Some(hasher) => {
                        let input_view = bridge.view(inputs_slot)?;
                        let digests = hasher.batch_sha256(input_view.as_bytes(), input_len);
                        let in_bytes = count * input_len;
                        let out_bytes = digests.as_ref().map(|d| d.len()).unwrap_or(0);
                        if let Some(bytes) = digests {
                            let _ = write_primary_output(node, bridge, &bytes)?;
                            ok_telemetry("metal-sha256", start.elapsed(), in_bytes, out_bytes, rc)
                        } else {
                            fallback(node, "MetalHasher::batch_sha256 returned None")
                        }
                    }
                    None => fallback(node, "MetalHasher unavailable"),
                }
            }
            (
                ProverOp::FriFold { .. },
                Some(NodePayload::FriFoldGoldilocks {
                    evals_slot,
                    alpha_slot,
                    twiddles_slot,
                }),
            ) => {
                let evals_slot = *evals_slot;
                let alpha_slot = *alpha_slot;
                let twiddles_slot = *twiddles_slot;
                bridge.ensure_inputs_resident(&[evals_slot, alpha_slot, twiddles_slot])?;
                let rc = residency_label(bridge.residency(evals_slot));
                let evals_view = bridge.view(evals_slot)?;
                let alpha_view = bridge.view(alpha_slot)?;
                let twiddles_view = bridge.view(twiddles_slot)?;
                let input_bytes = evals_view.len();
                let alpha = alpha_view.as_u64_slice().first().copied().unwrap_or(0);
                let inv_twiddles = twiddles_view.as_u64_slice().to_vec();
                let evals = evals_view.as_u64_slice().to_vec();

                let start = Instant::now();
                let Some(fri) = MetalFri::new() else {
                    return Ok(fallback(node, "MetalFri unavailable"));
                };
                let Some(folded) = fri.fold_goldilocks(&evals, alpha, &inv_twiddles) else {
                    return Ok(fallback(node, "MetalFri Goldilocks fold returned None"));
                };
                let mut output = Vec::with_capacity(folded.len() * 8);
                for value in folded {
                    output.extend_from_slice(&value.to_le_bytes());
                }
                let output_bytes = write_primary_output(node, bridge, &output)?;
                ok_telemetry(
                    "metal-fri-fold-goldilocks",
                    start.elapsed(),
                    input_bytes,
                    output_bytes,
                    rc,
                )
            }
            (ProverOp::FriFold { .. }, Some(NodePayload::FriFoldBabyBear { .. })) => {
                let (evals_slot, alpha_slot, twiddles_slot) = match payload {
                    Some(NodePayload::FriFoldBabyBear {
                        evals_slot,
                        alpha_slot,
                        twiddles_slot,
                    }) => (*evals_slot, *alpha_slot, *twiddles_slot),
                    _ => unreachable!(),
                };
                bridge.ensure_inputs_resident(&[evals_slot, alpha_slot, twiddles_slot])?;
                let rc = residency_label(bridge.residency(evals_slot));
                let evals_view = bridge.view(evals_slot)?;
                let alpha_view = bridge.view(alpha_slot)?;
                let twiddles_view = bridge.view(twiddles_slot)?;
                let input_bytes = evals_view.len();
                let alpha = alpha_view.as_u32_slice().first().copied().unwrap_or(0);
                let evals = evals_view.as_u32_slice().to_vec();
                let inv_twiddles = twiddles_view.as_u32_slice().to_vec();

                let start = Instant::now();
                let Some(fri) = MetalFri::new() else {
                    return Ok(fallback(node, "MetalFri unavailable for BabyBear"));
                };
                let Some(folded) = fri.fold_babybear(&evals, alpha, &inv_twiddles) else {
                    return Ok(fallback(node, "MetalFri BabyBear fold returned None"));
                };
                let mut output = Vec::with_capacity(folded.len() * 4);
                for value in folded {
                    output.extend_from_slice(&value.to_le_bytes());
                }
                let output_bytes = write_primary_output(node, bridge, &output)?;
                ok_telemetry(
                    "metal-fri-fold-babybear",
                    start.elapsed(),
                    input_bytes,
                    output_bytes,
                    rc,
                )
            }
            (
                ProverOp::MerkleLayer { .. },
                Some(NodePayload::MerkleGoldilocks {
                    leaves_slot,
                    leaf_count,
                    hash_fn: MerkleHashFn::Poseidon2Goldilocks,
                    ..
                }),
            ) => {
                let leaves_slot = *leaves_slot;
                let leaf_count = *leaf_count;
                bridge.ensure_inputs_resident(&[leaves_slot])?;
                let rc = residency_label(bridge.residency(leaves_slot));
                let leaves_view = bridge.view(leaves_slot)?;
                let input_bytes = leaves_view.len();
                let input_values = leaves_view.as_u64_slice().to_vec();
                if input_values.is_empty() || leaf_count == 0 {
                    return Ok(fallback(node, "MerkleLayer missing Goldilocks leaves"));
                }
                let leaf_width = (input_values.len() / leaf_count).max(1);
                let parent_count = leaf_count.div_ceil(2);
                let output_u64_width = node
                    .output_buffers
                    .first()
                    .map(|handle| (handle.size_bytes / 8) / parent_count.max(1))
                    .unwrap_or(1)
                    .clamp(1, 8);

                let seed = runtime_poseidon_seed(exec_ctx);
                let (round_constants, n_ext, n_int) =
                    poseidon2::goldilocks::flatten_round_constants(seed);
                let mut states = vec![0u64; parent_count * 16];
                for parent_idx in 0..parent_count {
                    let left_start = (2 * parent_idx) * leaf_width;
                    let right_leaf = (2 * parent_idx + 1).min(leaf_count.saturating_sub(1));
                    let right_start = right_leaf * leaf_width;
                    let state_offset = parent_idx * 16;
                    for i in 0..leaf_width.min(8) {
                        if let Some(value) = input_values.get(left_start + i) {
                            states[state_offset + i] = *value;
                        }
                        if let Some(value) = input_values.get(right_start + i) {
                            states[state_offset + 8 + i] = *value;
                        }
                    }
                }

                let start = Instant::now();
                let Some(poseidon) = MetalPoseidon2::new() else {
                    return Ok(fallback(node, "MetalPoseidon2 unavailable for MerkleLayer"));
                };
                if !poseidon.batch_permute_goldilocks(&mut states, &round_constants, n_ext, n_int) {
                    return Ok(fallback(
                        node,
                        "MetalPoseidon2 Goldilocks Merkle compression failed",
                    ));
                }

                let mut output = Vec::with_capacity(parent_count * output_u64_width * 8);
                for parent_idx in 0..parent_count {
                    let state_offset = parent_idx * 16;
                    for i in 0..output_u64_width {
                        output.extend_from_slice(&states[state_offset + i].to_le_bytes());
                    }
                }
                let output_bytes = write_primary_output(node, bridge, &output)?;
                ok_telemetry(
                    "metal-merkle-goldilocks-poseidon2",
                    start.elapsed(),
                    input_bytes,
                    output_bytes,
                    rc,
                )
            }
            (ProverOp::MerkleLayer { .. }, _) => {
                fallback(node, "MerkleLayer payload is unsupported on Metal")
            }
            _ => fallback(node, format!("no Metal dispatch for op {}", node.op.name())),
        };

        if self.verification_mode.fail_closed()
            && let Err(ref signal) = result
        {
            return Err(RuntimeError::GpuFallbackRejected {
                node: format!(
                    "{:?} ({}): {}",
                    signal.node_id,
                    node.op.name(),
                    signal.reason
                ),
            });
        }

        Ok(result)
    }
}

pub(crate) fn create_metal_dispatch_driver(
    verification_mode: GpuVerificationMode,
) -> Option<Box<dyn GpuDispatchDriver>> {
    RuntimeMetalDispatchDriver::new(verification_mode)
        .map(|driver| Box::new(driver) as Box<dyn GpuDispatchDriver>)
}

pub(crate) fn create_metal_buffer_allocator() -> Option<Box<dyn GpuBufferAllocator>> {
    RuntimeMetalBufferAllocator::new()
        .map(|allocator| Box::new(allocator) as Box<dyn GpuBufferAllocator>)
}
