#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from lean_toolchain import lake_cmd_prefix, lean_cmd_prefix
from rocq_toolchain import rocq_tool


REPO_ROOT = Path(__file__).resolve().parents[1]
LEDGER_PATH = REPO_ROOT / "zkf-ir-spec" / "verification-ledger.json"
PROTOCOL_CLOSURE_GATE = REPO_ROOT / "scripts" / "check_protocol_proof_closure.py"
RUNTIME_COVERAGE_GATE = REPO_ROOT / "scripts" / "check_runtime_proof_coverage.py"
STATUS_ARTIFACT_GENERATOR = (
    REPO_ROOT / "scripts" / "generate_verification_status_artifacts.py"
)
GPU_PROOF_MANIFEST_GATE = REPO_ROOT / "scripts" / "verify_gpu_proof_manifest.py"
GPU_BUNDLE_ATTESTATION_GATE = REPO_ROOT / "scripts" / "verify_gpu_bundle_attestation.py"
MONTGOMERY_ASSURANCE_GATE = REPO_ROOT / "scripts" / "run_montgomery_assurance.sh"
PROTOCOL_SNAPSHOT_GENERATOR = (
    REPO_ROOT / "scripts" / "generate_protocol_parameter_snapshots.py"
)
CORE_ROCQ_DIR = REPO_ROOT / "zkf-core" / "proofs" / "rocq"
BACKEND_ROCQ_DIR = REPO_ROOT / "zkf-backends" / "proofs" / "rocq"
FRONTEND_ROCQ_DIR = REPO_ROOT / "zkf-frontends" / "proofs" / "rocq"
RUNTIME_ROCQ_DIR = REPO_ROOT / "zkf-runtime" / "proofs" / "rocq"
LIB_ROCQ_DIR = REPO_ROOT / "zkf-lib" / "proofs" / "rocq"
DISTRIBUTED_ROCQ_DIR = REPO_ROOT / "zkf-distributed" / "proofs" / "rocq"
RUNTIME_VERUS_DIR = REPO_ROOT / "zkf-runtime" / "proofs" / "verus"
BACKEND_VERUS_DIR = REPO_ROOT / "zkf-backends" / "proofs" / "verus"
GPU_LEAN_DIR = REPO_ROOT / "zkf-metal" / "proofs" / "lean"
IR_LEAN_DIR = REPO_ROOT / "zkf-ir-spec" / "proofs" / "lean"
PROTOCOL_WORKSPACE = REPO_ROOT / "zkf-protocol-proofs"
PROTOCOL_LIBRARY = "ZkfProtocolProofs"
HAX_CORE_DIR = (
    REPO_ROOT
    / ".zkf-tools"
    / "hax"
    / "src"
    / "hax"
    / "hax-lib"
    / "proof-libs"
    / "coq"
    / "coq"
    / "generated-core"
)
COMMON_CORE_LOADPATH = [
    "-Q",
    str(HAX_CORE_DIR / "src"),
    "Core",
    "-Q",
    str(HAX_CORE_DIR / "spec"),
    "Core",
    "-Q",
    str(HAX_CORE_DIR / "phase_library"),
    "Core",
]
LEAN_APPROVED_AXIOMS = {"Classical.choice", "Quot.sound", "propext"}
RELEASE_GRADE_STRICT_THEOREMS = {
    "witness.kernel_expr_eval_relative_soundness",
    "witness.kernel_constraint_relative_soundness",
    "field.large_prime_runtime_generated",
    "field.bn254_strict_lane_generated",
    "gpu.shader_bundle_provenance",
    "gpu.runtime_fail_closed",
    "pipeline.cli_runtime_path_composition",
    "orbital.surface_constants",
    "orbital.position_update_half_step_soundness",
    "orbital.velocity_update_half_step_soundness",
    "orbital.residual_split_soundness",
    "orbital.field_embedding_nonwrap_bounds",
    "orbital.commitment_body_tag_domain_separation",
}


CORE_ROCQ_THEOREM_MAP = {
    "normalization.add_zero": {
        "cwd": REPO_ROOT / "zkf-ir-spec" / "proofs" / "rocq",
        "require": "Require Import Normalization.",
        "symbol": "normalization_add_zero",
        "loadpath": [],
    },
    "ccs.fail_closed_conversion": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import CcsProofs.",
        "symbol": "synthesize_ccs_program_fail_closed_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "ccs.supported_conversion_soundness": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import CcsProofs.",
        "symbol": "synthesize_ccs_program_supported_conversion_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "normalization.witness_preservation": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import TransformProofs.",
        "symbol": "normalize_supported_program_preserves_checks_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "normalization.witness_preservation_bounded": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import TransformProofs.",
        "symbol": "normalize_supported_program_preserves_checks_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "optimizer.ir_witness_preservation": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import TransformProofs.",
        "symbol": "optimize_supported_ir_program_preserves_checks_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "optimizer.ir_witness_preservation_bounded": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import TransformProofs.",
        "symbol": "optimize_supported_ir_program_preserves_checks_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "optimizer.zir_witness_preservation": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import TransformProofs.",
        "symbol": "optimize_supported_zir_program_preserves_checks_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "optimizer.zir_witness_preservation_bounded": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import TransformProofs.",
        "symbol": "optimize_supported_zir_program_preserves_checks_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "field.small_field_runtime_semantics": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import KernelFieldEncodingProofs.",
        "symbol": "small_field_runtime_semantics_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "pipeline.cli_runtime_path_composition": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import PipelineComposition.",
        "symbol": "cli_runtime_pipeline_to_kernel_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "pipeline.embedded_default_path_composition": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import PipelineComposition.",
        "symbol": "embedded_default_pipeline_to_kernel_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "witness.kernel_expr_eval_relative_soundness": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import KernelProofs.",
        "symbol": "eval_expr_sound_relative_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "witness.kernel_expr_eval_soundness": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import KernelProofs.",
        "symbol": "eval_expr_sound_relative_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "witness.kernel_constraint_relative_soundness": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import KernelProofs.",
        "symbol": "check_program_sound_relative_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "witness.kernel_constraint_soundness": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import KernelProofs.",
        "symbol": "check_program_sound_relative_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "witness.kernel_adapter_preservation": {
        "cwd": CORE_ROCQ_DIR,
        "require": "Require Import WitnessAdapterProofs.",
        "symbol": "witness_kernel_adapter_preservation_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "field.large_prime_runtime_generated": {
        "cwd": CORE_ROCQ_DIR,
        "require": "Require Import FieldGenerationProvenance.",
        "symbol": "large_prime_runtime_fiat_binding_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "field.bn254_strict_lane_generated": {
        "cwd": CORE_ROCQ_DIR,
        "require": "Require Import Bn254MontgomeryStrictLane.",
        "symbol": "bn254_strict_lane_bug_class_closed_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "witness.generate_witness_non_blackbox_soundness": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import WitnessGenerationProofs.",
        "symbol": "generate_non_blackbox_witness_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "witness.generate_witness_soundness": {
        "cwd": REPO_ROOT / "zkf-core" / "proofs" / "rocq",
        "require": "Require Import WitnessGenerationProofs.",
        "symbol": "generate_non_blackbox_witness_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfCoreExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
}

BACKEND_ROCQ_THEOREM_MAP = {
    "backend.plonky3_lowering_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import Plonky3Proofs.",
        "symbol": "plonky3_lowering_witness_preservation_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "lowering.lookup_preservation_bounded": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import LookupLoweringProofs.",
        "symbol": "lookup_lowering_witness_preservation_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "backend.poseidon_lowering_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxHashProofs.",
        "symbol": "poseidon_bn254_width4_lowering_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "backend.poseidon_aux_witness_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxHashProofs.",
        "symbol": "poseidon_bn254_width4_aux_witness_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "backend.sha256_lowering_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxHashProofs.",
        "symbol": "sha256_bytes_to_digest_lowering_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "backend.sha256_aux_witness_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxHashProofs.",
        "symbol": "sha256_bytes_to_digest_aux_witness_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "backend.ecdsa_secp256k1_lowering_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxEcdsaProofs.",
        "symbol": "ecdsa_secp256k1_byte_abi_lowering_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "backend.ecdsa_secp256k1_aux_witness_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxEcdsaProofs.",
        "symbol": "ecdsa_secp256k1_byte_abi_aux_witness_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "backend.ecdsa_secp256r1_lowering_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxEcdsaProofs.",
        "symbol": "ecdsa_secp256r1_byte_abi_lowering_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "backend.ecdsa_secp256r1_aux_witness_soundness": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxEcdsaProofs.",
        "symbol": "ecdsa_secp256r1_byte_abi_aux_witness_sound_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
    "witness.blackbox_runtime_checks": {
        "cwd": BACKEND_ROCQ_DIR,
        "require": "Require Import BlackboxRuntimeProofs.",
        "symbol": "blackbox_runtime_checks_critical_surface_ok",
        "loadpath": [
            "-Q",
            "./extraction",
            "ZkfBackendsExtraction",
            "-Q",
            str(HAX_CORE_DIR / "src"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "spec"),
            "Core",
            "-Q",
            str(HAX_CORE_DIR / "phase_library"),
            "Core",
        ],
    },
}

FRONTEND_ROCQ_THEOREM_MAP = {
    "frontend.acir_translation_differential_bounded": {
        "cwd": FRONTEND_ROCQ_DIR,
        "require": "Require Import NoirRecheckProofs.",
        "symbol": "noir_acir_recheck_wrapper_sound_ok",
        "loadpath": [],
    },
}

EXTRA_ROCQ_THEOREM_MAP = {
    "pipeline.cli_runtime_path_composition": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import RuntimePipelineComposition.",
        "symbol": "cli_runtime_path_composition_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "pipeline.embedded_default_path_composition": {
        "cwd": LIB_ROCQ_DIR,
        "require": "Require Import EmbeddedPipelineComposition.",
        "symbol": "embedded_default_path_composition_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfLibExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "app.alias_resolution_correctness_bounded": {
        "cwd": LIB_ROCQ_DIR,
        "require": "Require Import EmbeddedPipelineComposition.",
        "symbol": "canonical_input_key_string_resolves_alias_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfLibExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "app.digest_mismatch_rejection_bounded": {
        "cwd": LIB_ROCQ_DIR,
        "require": "Require Import EmbeddedPipelineComposition.",
        "symbol": "program_digest_guard_rejects_mismatch_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfLibExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "app.error_propagation_completeness_bounded": {
        "cwd": LIB_ROCQ_DIR,
        "require": "Require Import EmbeddedPipelineComposition.",
        "symbol": "program_mismatch_fields_preserve_expected_and_found_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfLibExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "app.default_backend_validity_bounded": {
        "cwd": LIB_ROCQ_DIR,
        "require": "Require Import EmbeddedPipelineComposition.",
        "symbol": "default_backend_for_proof_field_spec_total_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfLibExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "hybrid.and_verification_semantics_bounded": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import RuntimePipelineComposition.",
        "symbol": "hybrid_verify_decision_is_logical_and_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "hybrid.transcript_hash_binding_bounded": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import RuntimePipelineComposition.",
        "symbol": "digest_matches_recorded_hash_spec_rejects_missing_or_explicit_mismatch_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "hybrid.hardware_probe_rejection_bounded": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import RuntimePipelineComposition.",
        "symbol": "hardware_probes_clean_spec_rejects_unhealthy_or_mismatched_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "hybrid.primary_leg_outer_artifact_binding_bounded": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import RuntimePipelineComposition.",
        "symbol": "hybrid_primary_leg_byte_components_match_spec_rejects_component_divergence_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "hybrid.replay_manifest_determinism_bounded": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import RuntimePipelineComposition.",
        "symbol": "replay_manifest_identity_is_deterministic_spec_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "hybrid.ml_dsa_bundle_verification_bounded": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "hybrid_signature_material_complete_is_logical_and_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "hybrid.admission_pow_identity_bytes_bounded": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "hybrid_admission_pow_identity_prefers_bundle_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "distributed.acceptance_soundness": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "distributed_acceptance_surface_requires_all_preconditions_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "distributed.hybrid_signature_verification": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "hybrid_bundle_surface_complete_is_logical_and_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "distributed.encrypted_gossip_tamper_rejection_bounded": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmEpochProofs.",
        "symbol": "distributed_encrypted_gossip_fail_closed_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "distributed.snapshot_authenticated_roundtrip_bounded": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmEpochProofs.",
        "symbol": "snapshot_authenticated_roundtrip_helper_surface_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.kill_switch_equivalence": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import SwarmProofs.",
        "symbol": "disabled_surface_state_is_dormant_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.escalation_monotonicity": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import SwarmProofs.",
        "symbol": "cooldown_tick_non_deescalating_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.gossip_boundedness": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "bounded_gossip_count_spec_selects_pending_or_cap_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.coordinator_compromise_resilience": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "median_activation_level_three_honest_majority_alert_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.sybil_probationary_threshold": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "probationary_peer_score_basis_points_is_capped_addition_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.admission_pow_cost": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "admission_pow_total_cost_is_exact_product_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.controller_delegation_equivalence": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import SwarmProofs.",
        "symbol": "controller_artifact_path_matches_pure_helper_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.controller_no_artifact_mutation_surface": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import SwarmProofs.",
        "symbol": "controller_artifact_mutation_surface_absent_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.encrypted_gossip_non_interference": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import SwarmProofs.",
        "symbol": "swarm_encrypted_gossip_non_interference_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.encrypted_gossip_fail_closed": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import SwarmProofs.",
        "symbol": "swarm_encrypted_gossip_fail_closed_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.non_interference": {
        "cwd": RUNTIME_ROCQ_DIR,
        "require": "Require Import SwarmProofs.",
        "symbol": "swarm_non_interference_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfRuntimeExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "swarm.reputation_boundedness": {
        "cwd": DISTRIBUTED_ROCQ_DIR,
        "require": "Require Import SwarmReputationProofs.",
        "symbol": "swarm_reputation_boundedness_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfDistributedExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "private_identity.merkle_direction_fail_closed_bounded": {
        "cwd": LIB_ROCQ_DIR,
        "require": "Require Import EmbeddedPipelineComposition.",
        "symbol": "private_identity_merkle_direction_binary_guard_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfLibExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
    "private_identity.public_input_arity_fail_closed_bounded": {
        "cwd": LIB_ROCQ_DIR,
        "require": "Require Import EmbeddedPipelineComposition.",
        "symbol": "private_identity_public_input_arity_guard_ok",
        "loadpath": [
            "-R",
            str(CORE_ROCQ_DIR),
            "",
            "-Q",
            str(CORE_ROCQ_DIR / "extraction"),
            "ZkfCoreExtraction",
            "-Q",
            "./extraction",
            "ZkfLibExtraction",
            *COMMON_CORE_LOADPATH,
        ],
    },
}

ROCQ_THEOREM_MAP = {
    **CORE_ROCQ_THEOREM_MAP,
    **BACKEND_ROCQ_THEOREM_MAP,
    **FRONTEND_ROCQ_THEOREM_MAP,
    **EXTRA_ROCQ_THEOREM_MAP,
}

FSTAR_WORKSPACE_MAP = {
    "security.constant_time_secret_independence": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_fstar_proofs.sh"],
    },
    "swarm.constant_time_eval_equivalence": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_fstar_proofs.sh"],
    },
}

VERUS_WORKSPACE_MAP = {
    "swarm.non_interference": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_swarm_proofs.sh"],
    },
    "swarm.entrypoint_signal_routing": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_swarm_proofs.sh"],
    },
    "swarm.builder_rule_state_machine": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_swarm_proofs.sh"],
    },
    "swarm.escalation_monotonicity": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_swarm_proofs.sh"],
    },
    "swarm.weighted_network_pressure_median": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_swarm_proofs.sh"],
    },
    "swarm.sentinel_rate_limit_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_swarm_proofs.sh"],
    },
    "swarm.sentinel_baseline_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_swarm_proofs.sh"],
    },
    "swarm.warrior_quorum_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_swarm_proofs.sh"],
    },
    "swarm.protocol_digest_codec_determinism": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.consensus_two_thirds_threshold": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.gossip_boundedness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.diplomat_intelligence_root_determinism": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.epoch_negotiation_fail_closed": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.identity_bundle_pow_binding": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.reputation_boundedness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.memory_snapshot_identity": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.coordinator_acceptance_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "swarm.transport_integrity_fail_closed": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "backend.audit_retains_original_on_digest_mismatch": {
        "cwd": REPO_ROOT,
        "cmd": [
            "./scripts/run_verus_workspace.sh",
            "backend-audited",
            str(BACKEND_VERUS_DIR.relative_to(REPO_ROOT) / "audited_backend_verus.rs"),
        ],
    },
    "distributed.frame_transport_bounded": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "distributed.lz4_chunk_roundtrip_bounded": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "orbital.surface_constants": {
        "cwd": REPO_ROOT,
        "cmd": ["bash", "./scripts/run_verus_orbital_proofs.sh"],
    },
    "orbital.position_update_half_step_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["bash", "./scripts/run_verus_orbital_proofs.sh"],
    },
    "orbital.velocity_update_half_step_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["bash", "./scripts/run_verus_orbital_proofs.sh"],
    },
    "orbital.residual_split_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["bash", "./scripts/run_verus_orbital_proofs.sh"],
    },
    "orbital.field_embedding_nonwrap_bounds": {
        "cwd": REPO_ROOT,
        "cmd": ["bash", "./scripts/run_verus_orbital_proofs.sh"],
    },
    "orbital.commitment_body_tag_domain_separation": {
        "cwd": REPO_ROOT,
        "cmd": ["bash", "./scripts/run_verus_orbital_proofs.sh"],
    },
    "distributed.integrity_digest_corruption_bounded": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_distributed_swarm_proofs.sh"],
    },
    "runtime.buffer_read_write_bounded": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_buffer_proofs.sh"],
    },
    "runtime.buffer_residency_transition_bounded": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_buffer_proofs.sh"],
    },
    "runtime.buffer_alias_separation_bounded": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_buffer_proofs.sh"],
    },
    "runtime.buffer_typed_views": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_buffer_proofs.sh"],
    },
    "runtime.buffer_spill_reload_roundtrip": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_buffer_proofs.sh"],
    },
    "runtime.buffer_typed_views_bounded": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_buffer_proofs.sh"],
    },
    "runtime.buffer_spill_reload_roundtrip_bounded": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_buffer_proofs.sh"],
    },
    "swarm.jitter_detection_boundedness": {
        "cwd": REPO_ROOT,
        "cmd": [
            "./scripts/run_verus_workspace.sh",
            "sentinel",
            str(RUNTIME_VERUS_DIR.relative_to(REPO_ROOT) / "swarm_sentinel_verus.rs"),
        ],
    },
    "backend.groth16_matrix_equivalence_bounded": {
        "cwd": REPO_ROOT,
        "cmd": [
            "./scripts/run_verus_workspace.sh",
            "backend-groth16",
            str(BACKEND_VERUS_DIR.relative_to(REPO_ROOT) / "groth16_boundary_verus.rs"),
        ],
    },
    "wrapping.groth16_cached_shape_matrix_free_fail_closed": {
        "cwd": REPO_ROOT,
        "cmd": [
            "./scripts/run_verus_workspace.sh",
            "backend-groth16",
            str(BACKEND_VERUS_DIR.relative_to(REPO_ROOT) / "groth16_boundary_verus.rs"),
        ],
    },
    "aggregation.halo2_ipa_accumulation_bounded": {
        "cwd": REPO_ROOT,
        "cmd": [
            "./scripts/run_verus_workspace.sh",
            "backend-groth16",
            str(BACKEND_VERUS_DIR.relative_to(REPO_ROOT) / "groth16_boundary_verus.rs"),
        ],
    },
    "runtime.graph_topological_order_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.graph_trust_propagation_monotonicity": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.scheduler_placement_resolution": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.scheduler_gpu_fallback_fail_closed": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.scheduler_trace_accounting": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "gpu.runtime_fail_closed": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "gpu.cpu_gpu_partition_equivalence": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.execution_context_artifact_state_machine": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.api_control_plane_request_projection": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.api_backend_candidate_selection": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.api_batch_scheduler_determinism": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.adapter_backend_graph_emission": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.adapter_wrapper_graph_emission": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.hybrid_verification_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "runtime.hybrid_replay_manifest_determinism": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_runtime_execution_proofs.sh"],
    },
    "app.powered_descent_euler_step_determinism": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_powered_descent_proofs.sh"],
    },
    "app.powered_descent_thrust_magnitude_sq_nonnegative": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_powered_descent_proofs.sh"],
    },
    "app.powered_descent_glide_slope_squaring_soundness": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_powered_descent_proofs.sh"],
    },
    "app.powered_descent_mass_positivity_under_bounded_burn": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_powered_descent_proofs.sh"],
    },
    "app.powered_descent_running_min_monotonicity": {
        "cwd": REPO_ROOT,
        "cmd": ["./scripts/run_verus_powered_descent_proofs.sh"],
    },
}

LEAN_THEOREM_MAP = {
    "normalization.mul_one": {
        "runner": "direct",
        "cwd": IR_LEAN_DIR,
        "import_stmt": "import Normalization",
        "qualified_symbol": "normalization_mul_one",
        "file": IR_LEAN_DIR / "Normalization.lean",
        "marker": "theorem normalization_mul_one",
        "lean_path": [IR_LEAN_DIR],
    },
    "normalization.sub_zero": {
        "runner": "direct",
        "cwd": IR_LEAN_DIR,
        "import_stmt": "import Normalization",
        "qualified_symbol": "normalization_sub_zero",
        "file": IR_LEAN_DIR / "Normalization.lean",
        "marker": "theorem normalization_sub_zero",
        "lean_path": [IR_LEAN_DIR],
    },
    "swarm.memory_append_only_convergence": {
        "runner": "lake",
        "cwd": PROTOCOL_WORKSPACE,
        "import_stmt": f"import {PROTOCOL_LIBRARY}.SwarmIntelligence",
        "qualified_symbol": f"{PROTOCOL_LIBRARY}.memory_append_only_convergence",
        "file": PROTOCOL_WORKSPACE / "ZkfProtocolProofs" / "SwarmIntelligence.lean",
        "marker": "theorem memory_append_only_convergence",
    },
    "swarm.intelligence_root_convergence": {
        "runner": "lake",
        "cwd": PROTOCOL_WORKSPACE,
        "import_stmt": f"import {PROTOCOL_LIBRARY}.SwarmIntelligence",
        "qualified_symbol": f"{PROTOCOL_LIBRARY}.intelligence_root_convergence",
        "file": PROTOCOL_WORKSPACE / "ZkfProtocolProofs" / "SwarmIntelligence.lean",
        "marker": "theorem intelligence_root_convergence",
    },
    "normalization.idempotence_bounded": {
        "runner": "direct",
        "cwd": IR_LEAN_DIR,
        "import_stmt": "import Normalization",
        "qualified_symbol": "normalization_supported_program_idempotent",
        "file": IR_LEAN_DIR / "Normalization.lean",
        "marker": "theorem normalization_supported_program_idempotent",
        "lean_path": [IR_LEAN_DIR],
    },
    "normalization.canonical_digest_stability_bounded": {
        "runner": "direct",
        "cwd": IR_LEAN_DIR,
        "import_stmt": "import Normalization",
        "qualified_symbol": "normalization_supported_program_digest_stable",
        "file": IR_LEAN_DIR / "Normalization.lean",
        "marker": "theorem normalization_supported_program_digest_stable",
        "lean_path": [IR_LEAN_DIR],
    },
    "gpu.hash_differential_bounded": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import Hash",
        "qualified_symbol": "ZkfMetalProofs.hash_family_exact_digest_sound",
        "file": GPU_LEAN_DIR / "Hash.lean",
        "marker": "theorem hash_family_exact_digest_sound",
        "lean_path": [GPU_LEAN_DIR],
    },
    "gpu.poseidon2_differential_bounded": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import Poseidon2",
        "qualified_symbol": "ZkfMetalProofs.poseidon2_family_exact_permutation_sound",
        "file": GPU_LEAN_DIR / "Poseidon2.lean",
        "marker": "theorem poseidon2_family_exact_permutation_sound",
        "lean_path": [GPU_LEAN_DIR],
    },
    "gpu.ntt_differential_bounded": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import Ntt",
        "qualified_symbol": "ZkfMetalProofs.ntt_family_exact_transform_sound",
        "file": GPU_LEAN_DIR / "Ntt.lean",
        "marker": "theorem ntt_family_exact_transform_sound",
        "lean_path": [GPU_LEAN_DIR],
    },
    "gpu.ntt_bn254_butterfly_arithmetic_sound": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import Ntt",
        "qualified_symbol": "ZkfMetalProofs.gpu_bn254_ntt_butterfly_arithmetic_sound",
        "file": GPU_LEAN_DIR / "Ntt.lean",
        "marker": "theorem gpu_bn254_ntt_butterfly_arithmetic_sound",
        "lean_path": [GPU_LEAN_DIR],
    },
    "gpu.msm_differential_bounded": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import Msm",
        "qualified_symbol": "ZkfMetalProofs.msm_family_exact_pippenger_sound",
        "file": GPU_LEAN_DIR / "Msm.lean",
        "marker": "theorem msm_family_exact_pippenger_sound",
        "lean_path": [GPU_LEAN_DIR],
    },
    "gpu.launch_contract_sound": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import LaunchSafety",
        "qualified_symbol": "ZkfMetalProofs.gpu_launch_contract_sound",
        "file": GPU_LEAN_DIR / "LaunchSafety.lean",
        "marker": "theorem gpu_launch_contract_sound",
        "lean_path": [GPU_LEAN_DIR],
    },
    "gpu.buffer_layout_sound": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import MemoryModel",
        "qualified_symbol": "ZkfMetalProofs.gpu_buffer_layout_sound",
        "file": GPU_LEAN_DIR / "MemoryModel.lean",
        "marker": "theorem gpu_buffer_layout_sound",
        "lean_path": [GPU_LEAN_DIR],
    },
    "gpu.dispatch_schedule_sound": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import CodegenSoundness",
        "qualified_symbol": "ZkfMetalProofs.gpu_dispatch_schedule_sound",
        "file": GPU_LEAN_DIR / "CodegenSoundness.lean",
        "marker": "theorem gpu_dispatch_schedule_sound",
        "lean_path": [GPU_LEAN_DIR],
    },
    "gpu.shader_bundle_provenance": {
        "runner": "direct",
        "cwd": GPU_LEAN_DIR,
        "import_stmt": "import CodegenSoundness",
        "qualified_symbol": "ZkfMetalProofs.gpu_shader_bundle_provenance",
        "file": GPU_LEAN_DIR / "CodegenSoundness.lean",
        "marker": "theorem gpu_shader_bundle_provenance",
        "lean_path": [GPU_LEAN_DIR],
    },
}


def load_ledger() -> dict:
    with LEDGER_PATH.open() as handle:
        return json.load(handle)


def run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def check_json_sync() -> None:
    result = run(
        [
            "cargo",
            "test",
            "-p",
            "zkf-ir-spec",
            "--lib",
            "json_export_stays_in_sync",
        ],
        REPO_ROOT,
    )
    combined = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0 or "running 0 tests" in combined:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("verification ledger JSON is out of sync with zkf-ir-spec/src/verification.rs")


def check_generated_status_sync() -> None:
    result = run(["python3", str(STATUS_ARTIFACT_GENERATOR), "--check"], REPO_ROOT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(
            "generated verification status artifacts are out of sync with the ledger"
        )


def audit_trusted_assumptions_shape(ledger: dict) -> None:
    for entry in ledger["entries"]:
        assumptions = entry.get("trusted_assumptions")
        if not isinstance(assumptions, list):
            raise SystemExit(f"{entry['theorem_id']} must define trusted_assumptions as a list")
        if entry["status"] in {"pending", "assumed_external"} and not assumptions:
            raise SystemExit(
                f"{entry['theorem_id']} should document its remaining trust boundary in trusted_assumptions"
            )


def audit_assurance_class_shape(ledger: dict) -> None:
    valid_classes = {
        "mechanized_implementation_claim",
        "bounded_check",
        "attestation_backed_lane",
        "model_only_claim",
        "hypothesis_carried_theorem",
    }
    for entry in ledger["entries"]:
        assurance_class = entry.get("assurance_class")
        if assurance_class not in valid_classes:
            raise SystemExit(
                f"{entry['theorem_id']} must define a valid assurance_class"
            )
        if entry["status"] == "bounded_checked" and assurance_class != "bounded_check":
            raise SystemExit(
                f"{entry['theorem_id']} is bounded_checked but assurance_class={assurance_class}"
            )
        if entry["theorem_id"].startswith("protocol.") and assurance_class != "hypothesis_carried_theorem":
            raise SystemExit(
                f"{entry['theorem_id']} must be classified as hypothesis_carried_theorem"
            )


def print_assumptions(entry: dict) -> str:
    theorem = ROCQ_THEOREM_MAP.get(entry["theorem_id"])
    if theorem is None:
        raise SystemExit(
            f"missing Rocq theorem mapping for trust-free entry {entry['theorem_id']}"
        )

    if theorem["cwd"].name == "rocq" and theorem["cwd"].parents[1].name == "zkf-core":
        required_dirs = [HAX_CORE_DIR / "src", HAX_CORE_DIR / "spec", HAX_CORE_DIR / "phase_library"]
        missing = [path for path in required_dirs if not path.exists()]
        if missing:
            joined = ", ".join(str(path) for path in missing)
            raise SystemExit(
                f"cannot audit Rocq assumptions for {entry['theorem_id']}: missing generated-core path(s): {joined}"
            )

    input_text = f"{theorem['require']}\nPrint Assumptions {theorem['symbol']}.\n"
    cmd = [rocq_tool("coqtop"), "-quiet", *theorem["loadpath"]]
    result = subprocess.run(
        cmd,
        cwd=theorem["cwd"],
        text=True,
        input=input_text,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"failed to inspect Rocq assumptions for {entry['theorem_id']}")
    return result.stdout + result.stderr


def audit_rocq_assumptions(ledger: dict) -> None:
    for entry in ledger["entries"]:
        if entry["checker"] != "rocq":
            continue
        if entry["status"] != "mechanized_local":
            continue
        if entry["trusted_assumptions"]:
            continue

        output = print_assumptions(entry)
        if "Axioms:" in output or "dropped_body" in output:
            raise SystemExit(
                f"{entry['theorem_id']} declares no trusted assumptions but Rocq still reports axioms:\n{output}"
            )


def audit_rocq_workspaces(ledger: dict) -> None:
    if not any(
        entry["checker"] == "rocq" and entry["status"] == "mechanized_local"
        for entry in ledger["entries"]
    ):
        return

    result = run(["./scripts/run_rocq_proofs.sh"], REPO_ROOT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("failed to validate Rocq proof runner")


def audit_fstar_workspaces(ledger: dict) -> None:
    checked_workspaces: set[tuple[Path, tuple[str, ...]]] = set()
    for entry in ledger["entries"]:
        if entry["checker"] != "fstar":
            continue
        if entry["status"] != "mechanized_local":
            continue

        workspace = FSTAR_WORKSPACE_MAP.get(entry["theorem_id"])
        if workspace is None:
            raise SystemExit(
                f"missing F* workspace mapping for mechanized entry {entry['theorem_id']}"
            )

        key = (workspace["cwd"], tuple(workspace["cmd"]))
        if key in checked_workspaces:
            continue
        checked_workspaces.add(key)

        result = run(workspace["cmd"], workspace["cwd"])
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise SystemExit(f"failed to validate F* workspace for {entry['theorem_id']}")


def audit_verus_workspaces(ledger: dict) -> None:
    checked_workspaces: set[tuple[Path, tuple[str, ...]]] = set()
    for entry in ledger["entries"]:
        if entry["checker"] != "verus":
            continue
        if entry["status"] != "mechanized_local":
            continue

        workspace = VERUS_WORKSPACE_MAP.get(entry["theorem_id"])
        if workspace is None:
            raise SystemExit(
                f"missing Verus workspace mapping for mechanized entry {entry['theorem_id']}"
            )

        key = (workspace["cwd"], tuple(workspace["cmd"]))
        if key in checked_workspaces:
            continue
        checked_workspaces.add(key)

        result = run(workspace["cmd"], workspace["cwd"])
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise SystemExit(f"failed to validate Verus workspace for {entry['theorem_id']}")


def audit_fiat_field_generation(ledger: dict) -> None:
    if not any(
        entry["theorem_id"] == "field.large_prime_runtime_generated"
        and entry["status"] == "mechanized_local"
        for entry in ledger["entries"]
    ):
        return

    result = run(["./scripts/regenerate_fiat_fields.sh", "--check"], REPO_ROOT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("failed to validate Fiat-generated large-prime field modules")


def audit_montgomery_assurance(ledger: dict, release_grade: bool) -> None:
    if not release_grade:
        return

    if not any(
        entry["theorem_id"] == "field.large_prime_runtime_generated"
        and entry["status"] == "mechanized_local"
        for entry in ledger["entries"]
    ):
        return

    result = run(["bash", str(MONTGOMERY_ASSURANCE_GATE)], REPO_ROOT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("failed to validate Montgomery regression backstops")


def lean_axiom_output(theorem: dict) -> str:
    file_path = theorem["file"]
    if not file_path.exists():
        raise SystemExit(f"missing Lean evidence file {file_path}")
    file_text = file_path.read_text(encoding="utf-8")
    marker = theorem["marker"]
    if marker not in file_text:
        raise SystemExit(f"{file_path} is missing theorem marker `{marker}`")

    with tempfile.NamedTemporaryFile(
        "w",
        suffix=".lean",
        prefix="LeanAudit.",
        dir=theorem["cwd"],
        delete=False,
        encoding="utf-8",
    ) as temp_file:
        temp_path = Path(temp_file.name)
        if theorem["runner"] == "lake":
            temp_file.write(theorem["import_stmt"] + "\n")
        else:
            temp_file.write(file_text)
            if not file_text.endswith("\n"):
                temp_file.write("\n")
        temp_file.write(f"#check {theorem['qualified_symbol']}\n")
        temp_file.write(f"#print axioms {theorem['qualified_symbol']}\n")

    try:
        if theorem["runner"] == "lake":
            result = subprocess.run(
                [*lake_cmd_prefix(), "env", "lean", temp_path.name],
                cwd=theorem["cwd"],
                text=True,
                capture_output=True,
                check=False,
            )
        else:
            env = os.environ.copy()
            lean_paths = [str(path) for path in theorem.get("lean_path", [])]
            if env.get("LEAN_PATH"):
                lean_paths.append(env["LEAN_PATH"])
            env["LEAN_PATH"] = ":".join(lean_paths)
            result = subprocess.run(
                [*lean_cmd_prefix(), temp_path.name],
                cwd=theorem["cwd"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
    finally:
        temp_path.unlink(missing_ok=True)

    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"failed to inspect Lean theorem {theorem['qualified_symbol']}")

    return result.stdout + result.stderr


def audit_lean_theorem(entry: dict, theorem: dict) -> None:
    expected_path = theorem["file"].relative_to(REPO_ROOT).as_posix()
    if entry["evidence_path"] != expected_path:
        raise SystemExit(
            f"{entry['theorem_id']} evidence_path mismatch: expected {expected_path}, got {entry['evidence_path']}"
        )

    output = lean_axiom_output(theorem)
    pattern = re.compile(
        rf"'?{re.escape(theorem['qualified_symbol'])}'? "
        rf"(does not depend on any axioms|depends on axioms: (?P<axioms>[^\n]+))"
    )
    match = pattern.search(output)
    if match is None:
        raise SystemExit(
            f"Lean axiom audit did not report `{theorem['qualified_symbol']}`:\n{output}"
        )

    axioms_str = match.group("axioms")
    if axioms_str is None:
        return

    axioms = {
        axiom.strip().strip("[]")
        for axiom in axioms_str.split(",")
        if axiom.strip().strip("[]")
    }
    disallowed_axioms = sorted(axiom for axiom in axioms if axiom not in LEAN_APPROVED_AXIOMS)
    if disallowed_axioms:
        raise SystemExit(
            f"{entry['theorem_id']} declares no trusted assumptions but Lean still reports axioms: "
            + ", ".join(disallowed_axioms)
        )


def audit_lean_workspaces(ledger: dict) -> None:
    lean_entries = [
        entry
        for entry in ledger["entries"]
        if entry["checker"] == "lean"
        and entry["status"] == "mechanized_local"
        and not entry["theorem_id"].startswith("protocol.")
    ]
    if not lean_entries:
        return

    if any(LEAN_THEOREM_MAP.get(entry["theorem_id"], {}).get("runner") == "direct" for entry in lean_entries):
        result = run(["bash", str(REPO_ROOT / "scripts" / "run_lean_proofs.sh")], REPO_ROOT)
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise SystemExit("failed to validate non-protocol Lean workspaces")

    for entry in lean_entries:
        theorem = LEAN_THEOREM_MAP.get(entry["theorem_id"])
        if theorem is None:
            raise SystemExit(
                f"missing Lean theorem mapping for mechanized entry {entry['theorem_id']}"
            )
        audit_lean_theorem(entry, theorem)


def audit_protocol_closure_gate() -> None:
    result = run(["python3", str(PROTOCOL_CLOSURE_GATE)], REPO_ROOT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("protocol closure gate failed")


def audit_protocol_parameter_snapshots(release_grade: bool) -> None:
    if not release_grade:
        return

    result = run(["python3", str(PROTOCOL_SNAPSHOT_GENERATOR), "--check"], REPO_ROOT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("protocol parameter snapshots are out of sync")

    result = run(
        [
            "cargo",
            "test",
            "--manifest-path",
            str(REPO_ROOT / "Cargo.toml"),
            "-p",
            "zkf-ir-spec",
            "--test",
            "protocol_parameter_snapshots",
        ],
        REPO_ROOT,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("failed to validate protocol parameter snapshot regression")


def audit_runtime_proof_coverage(require_complete: bool) -> None:
    cmd = ["python3", str(RUNTIME_COVERAGE_GATE)]
    if require_complete:
        cmd.append("--require-complete")
    result = run(cmd, REPO_ROOT)
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("runtime proof coverage gate failed")


def audit_gpu_boundary_gates(ledger: dict) -> None:
    if not any(entry["theorem_id"].startswith("gpu.") for entry in ledger["entries"]):
        return

    for cmd, label in (
        (["bash", "./scripts/run_verus_gpu_checks.sh"], "Verus GPU launch workspace"),
        (["python3", str(GPU_PROOF_MANIFEST_GATE)], "GPU proof manifest gate"),
        (["python3", str(GPU_BUNDLE_ATTESTATION_GATE)], "GPU bundle attestation gate"),
    ):
        result = run(cmd, REPO_ROOT)
        if result.returncode != 0:
            sys.stderr.write(result.stdout)
            sys.stderr.write(result.stderr)
            raise SystemExit(f"{label} failed")


def audit_release_grade(ledger: dict) -> None:
    mechanized_generated_rows = [
        entry["theorem_id"]
        for entry in ledger["entries"]
        if entry["status"] == "mechanized_generated"
    ]
    assumed_external_rows = [
        entry["theorem_id"]
        for entry in ledger["entries"]
        if entry["status"] == "assumed_external"
    ]
    bounded_checked_rows = [
        entry["theorem_id"]
        for entry in ledger["entries"]
        if entry["status"] == "bounded_checked"
    ]
    trusted_rows = [
        entry["theorem_id"]
        for entry in ledger["entries"]
        if entry.get("trusted_assumptions")
    ]
    strict_assurance_failures = [
        entry["theorem_id"]
        for entry in ledger["entries"]
        if entry["theorem_id"] in RELEASE_GRADE_STRICT_THEOREMS
        and entry.get("assurance_class") != "mechanized_implementation_claim"
    ]
    failures: list[str] = []
    if mechanized_generated_rows:
        failures.append(
            f"{len(mechanized_generated_rows)} mechanized_generated row(s) remain: "
            + ", ".join(mechanized_generated_rows)
        )
    if assumed_external_rows:
        failures.append(
            f"{len(assumed_external_rows)} assumed_external row(s) remain: "
            + ", ".join(assumed_external_rows)
        )
    if bounded_checked_rows:
        failures.append(
            f"{len(bounded_checked_rows)} bounded_checked row(s) remain: "
            + ", ".join(bounded_checked_rows)
        )
    if trusted_rows:
        failures.append(
            f"{len(trusted_rows)} row(s) still carry trusted_assumptions: "
            + ", ".join(trusted_rows)
        )
    if strict_assurance_failures:
        failures.append(
            f"{len(strict_assurance_failures)} release-grade strict theorem(s) remain non-mechanized-implementation claims: "
            + ", ".join(strict_assurance_failures)
        )
    if failures:
        raise SystemExit("release-grade audit failed: " + "; ".join(failures))


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit the ZKF proof ledger and trust boundary.")
    parser.add_argument(
        "--skip-rocq",
        action="store_true",
        help="only validate the ledger schema and JSON sync; skip the Rocq assumption audit",
    )
    parser.add_argument(
        "--release-grade",
        action="store_true",
        help="fail unless the ledger has zero mechanized_generated, zero assumed_external rows, zero bounded_checked rows, and zero non-empty trusted_assumptions",
    )
    args = parser.parse_args()

    ledger = load_ledger()
    audit_trusted_assumptions_shape(ledger)
    audit_assurance_class_shape(ledger)
    check_json_sync()
    check_generated_status_sync()
    audit_runtime_proof_coverage(args.release_grade)
    audit_protocol_parameter_snapshots(args.release_grade)
    audit_protocol_closure_gate()
    audit_gpu_boundary_gates(ledger)
    audit_lean_workspaces(ledger)
    audit_fstar_workspaces(ledger)
    audit_verus_workspaces(ledger)
    audit_fiat_field_generation(ledger)
    audit_montgomery_assurance(ledger, args.release_grade)
    if not args.skip_rocq:
        audit_rocq_workspaces(ledger)
        audit_rocq_assumptions(ledger)
    if args.release_grade:
        audit_release_grade(ledger)


if __name__ == "__main__":
    main()
