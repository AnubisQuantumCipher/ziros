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

use clap::Parser;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use zkf_backends::{
    metal_runtime_report, strict_bn254_auto_route_ready_with_runtime,
    with_groth16_setup_blob_path_override, with_proof_seed_override, with_setup_seed_override,
    GROTH16_LOCAL_CEREMONY_STREAMED_PROVENANCE,
    GROTH16_LOCAL_CEREMONY_STREAMED_SECURITY_BOUNDARY,
    GROTH16_STREAMED_SETUP_STORAGE_METADATA_KEY, GROTH16_STREAMED_SETUP_STORAGE_VALUE,
};
use zkf_backends::ceremony::{PtauData, ceremony_phase2_setup};
use zkf_lib::{
    compile, prove_with_inputs, verify, Expr, FieldElement, FieldId, Program, ProgramBuilder,
    WitnessInputs,
};
use zkf_metal_public_proof_lib::{
    expected_public_values, validate_bundle_evidence, validate_public_groth16_proving_lane,
    validate_public_input_bytes, BundleWitness, ProofGenerationPlan, PublicGroth16ProofBundle,
    PublicGroth16ProvingLane, PROOF_PLAN_SCHEMA, PUBLIC_GROTH16_PROOF_SCHEMA, PUBLIC_INPUT_SCHEMA,
    PUBLIC_PROOF_BACKEND, PUBLIC_PROOF_SYSTEM,
};

const BUNDLE_PROGRAM_NAME: &str = "zkf_metal_public_bundle_commitment_v1";
const PROOF_SEED_LABEL_PREFIX: &str = "zkf-metal-public-bundle-proof:prove:v1:";
const LOCAL_CEREMONY_POWER: u32 = 8;
const LOCAL_CEREMONY_CONTRIBUTOR: &str = "zkf-metal-public-proof-local-ceremony";
const QAP_PADDING_STEPS: usize = 1024;
const SETUP_SECURITY_BOUNDARY_KEY: &str = "groth16_setup_security_boundary";
const SETUP_PROVENANCE_KEY: &str = "groth16_setup_provenance";
const TRUSTED_IMPORTED_BOUNDARY: &str = "trusted-imported";
const TRUSTED_IMPORTED_PROVENANCE: &str = "trusted-imported-blob";

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    plan: PathBuf,
    #[arg(long)]
    out_dir: PathBuf,
    #[arg(long)]
    proof_mode: Option<String>,
    #[arg(long)]
    preflight_only: bool,
}

fn main() {
    let args = Args::parse();
    if let Err(err) = run(args) {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run(args: Args) -> Result<(), String> {
    let plan: ProofGenerationPlan = serde_json::from_slice(
        &fs::read(&args.plan).map_err(|err| format!("read plan {}: {err}", args.plan.display()))?,
    )
    .map_err(|err| format!("parse plan {}: {err}", args.plan.display()))?;
    if plan.schema != PROOF_PLAN_SCHEMA {
        return Err(format!(
            "{} has unexpected plan schema: {}",
            args.plan.display(),
            plan.schema
        ));
    }
    if plan.requests.is_empty() {
        return Err("proof plan has no requests".to_string());
    }

    let selected_mode = args
        .proof_mode
        .as_deref()
        .unwrap_or(plan.proof_mode.as_str());
    if selected_mode != "groth16" {
        return Err(format!(
            "public zkf-metal bundle proofs only support groth16; got `{selected_mode}`"
        ));
    }

    let runtime = metal_runtime_report();
    if !strict_bn254_auto_route_ready_with_runtime(&runtime) {
        return Err(format!(
            "strict BN254 Metal proving lane is not release-ready on this host: metal_available={}, metal_device={:?}, threshold_profile={:?}, metal_no_cpu_fallback={}, gpu_busy_ratio={}",
            runtime.metal_available,
            runtime.metal_device,
            runtime.threshold_profile,
            runtime.metal_no_cpu_fallback,
            runtime.metal_gpu_busy_ratio,
        ));
    }

    let program = build_public_bundle_program()?;
    let (compiled, setup_blob_path) = compile_public_bundle_program(&program, &args.out_dir)?;

    for request in &plan.requests {
        build_inputs_for_request(request)?;
    }

    if args.preflight_only {
        return Ok(());
    }

    let proof_dir = args.out_dir.join("zkproofs");
    let vk_dir = args.out_dir.join("verification_keys");
    fs::create_dir_all(&proof_dir)
        .map_err(|err| format!("create proof output dir {}: {err}", proof_dir.display()))?;
    fs::create_dir_all(&vk_dir).map_err(|err| {
        format!(
            "create verification-key output dir {}: {err}",
            vk_dir.display()
        )
    })?;

    for request in &plan.requests {
        let inputs = build_inputs_for_request(request)?;
        let proof_seed =
            seed_from_label(&format!("{PROOF_SEED_LABEL_PREFIX}{}", request.bundle_id));
        let artifact = with_proof_seed_override(Some(proof_seed), || {
            prove_with_inputs(&program, &compiled, &inputs, None)
        })
        .map_err(|err| {
            format!(
                "prove bundle {} with {PUBLIC_PROOF_BACKEND}: {err}",
                request.bundle_id
            )
        })?;

        let verified = verify(&compiled, &artifact)
            .map_err(|err| format!("verify bundle {} after proving: {err}", request.bundle_id))?;
        if !verified {
            return Err(format!(
                "native Groth16 verification returned false for bundle {}",
                request.bundle_id
            ));
        }

        let expected_public_bytes = expected_public_bytes_for_request(request)?;
        let public_input_bytes = public_input_bytes_from_artifact(&artifact)?;
        if public_input_bytes != expected_public_bytes {
            return Err(format!(
                "public input bytes mismatched for {}",
                request.bundle_id
            ));
        }

        let proving_lane = proving_lane_from_artifact(&artifact, request, setup_blob_path.as_deref())?;
        let public_bundle = PublicGroth16ProofBundle {
            schema: PUBLIC_GROTH16_PROOF_SCHEMA.to_string(),
            proof_system: PUBLIC_PROOF_SYSTEM.to_string(),
            backend: PUBLIC_PROOF_BACKEND.to_string(),
            proof_bytes: artifact.proof.clone(),
            public_input_bytes,
            proving_lane,
        };

        fs::write(
            proof_dir.join(format!("{}.bin", request.bundle_id)),
            bincode::serialize(&public_bundle).map_err(|err| {
                format!(
                    "serialize public Groth16 proof bundle {}: {err}",
                    request.bundle_id
                )
            })?,
        )
        .map_err(|err| format!("write proof bundle {}: {err}", request.bundle_id))?;
        fs::write(
            vk_dir.join(format!("{}.bin", request.bundle_id)),
            artifact.verification_key.as_slice(),
        )
        .map_err(|err| format!("write verification key {}: {err}", request.bundle_id))?;
    }

    Ok(())
}

fn build_public_bundle_program() -> Result<Program, String> {
    let mut builder = ProgramBuilder::new(BUNDLE_PROGRAM_NAME, FieldId::Bn254);
    builder
        .metadata_entry("public_input_schema", PUBLIC_INPUT_SCHEMA)
        .map_err(|err| err.to_string())?;
    builder
        .metadata_entry(
            "bundle_public_input_bytes",
            zkf_metal_public_proof_lib::EXPECTED_PUBLIC_INPUT_BYTES.to_string(),
        )
        .map_err(|err| err.to_string())?;

    for index in 0..zkf_metal_public_proof_lib::EXPECTED_PUBLIC_INPUT_BYTES {
        let witness_name = witness_byte_name(index);
        let public_name = public_byte_name(index);
        builder
            .private_input(&witness_name)
            .and_then(|builder| builder.public_output(&public_name))
            .and_then(|builder| {
                builder.bind_labeled(
                    &public_name,
                    Expr::signal(&witness_name),
                    Some(format!("public-byte-{index}")),
                )
            })
            .and_then(|builder| {
                builder.constrain_range_labeled(
                    &witness_name,
                    8,
                    Some(format!("witness-byte-range-{index}")),
                )
            })
            .map_err(|err| err.to_string())?;

        let acc_name = accumulator_name(index);
        builder
            .private_signal(&acc_name)
            .map_err(|err| err.to_string())?;
        let accumulator_expr = if index == 0 {
            Expr::signal(&witness_name)
        } else {
            Expr::Add(vec![
                Expr::signal(accumulator_name(index - 1)),
                Expr::signal(&witness_name),
            ])
        };
        builder
            .bind_labeled(
                &acc_name,
                accumulator_expr,
                Some(format!("accumulator-step-{index}")),
            )
            .map_err(|err| err.to_string())?;
    }

    let mut previous_padding_source =
        accumulator_name(zkf_metal_public_proof_lib::EXPECTED_PUBLIC_INPUT_BYTES - 1);
    for index in 0..QAP_PADDING_STEPS {
        let pad_name = padding_signal_name(index);
        let witness_name =
            witness_byte_name(index % zkf_metal_public_proof_lib::EXPECTED_PUBLIC_INPUT_BYTES);
        builder
            .private_signal(&pad_name)
            .map_err(|err| err.to_string())?;
        builder
            .bind_labeled(
                &pad_name,
                Expr::Add(vec![
                    Expr::signal(&previous_padding_source),
                    Expr::signal(&witness_name),
                ]),
                Some(format!("qap-padding-step-{index}")),
            )
            .map_err(|err| err.to_string())?;
        previous_padding_source = pad_name;
    }

    builder.build().map_err(|err| err.to_string())
}

fn compile_public_bundle_program(
    program: &Program,
    _out_dir: &Path,
) -> Result<(zkf_lib::CompiledProgram, Option<PathBuf>), String> {
    if let Some(path) = std::env::var_os("ZKF_GROTH16_SETUP_BLOB_PATH") {
        let path_buf = PathBuf::from(path);
        let compiled = compile_with_imported_setup_blob(program, &path_buf)?;
        return Ok((compiled, Some(path_buf)));
    }

    let compiled = compile_with_local_ceremony_streamed_setup(program)?;
    Ok((compiled, None))
}

fn compile_with_local_ceremony_streamed_setup(
    program: &Program,
) -> Result<zkf_lib::CompiledProgram, String> {
    let mut ptau = PtauData::new(LOCAL_CEREMONY_POWER);
    ptau.contribute(None, LOCAL_CEREMONY_CONTRIBUTOR)
        .map_err(|err| format!("generate local ceremony contribution: {err}"))?;
    let setup_seed = ceremony_phase2_setup(&ptau, &program.digest_hex())
        .map_err(|err| format!("derive local ceremony phase-2 seed: {err}"))?;
    let mut compiled = with_setup_seed_override(Some(setup_seed), || {
        compile(program, PUBLIC_PROOF_BACKEND, None)
    })
    .map_err(|err| {
        format!(
            "compile local ceremony streamed setup for public bundle program with {PUBLIC_PROOF_BACKEND}: {err}"
        )
    })?;
    compiled.metadata.insert(
        SETUP_SECURITY_BOUNDARY_KEY.to_string(),
        GROTH16_LOCAL_CEREMONY_STREAMED_SECURITY_BOUNDARY.to_string(),
    );
    compiled.metadata.insert(
        SETUP_PROVENANCE_KEY.to_string(),
        GROTH16_LOCAL_CEREMONY_STREAMED_PROVENANCE.to_string(),
    );
    ensure_local_ceremony_streamed_setup_boundary(&compiled)?;
    Ok(compiled)
}

fn compile_with_imported_setup_blob(
    program: &Program,
    setup_blob_path: &Path,
) -> Result<zkf_lib::CompiledProgram, String> {
    let setup_blob_display = setup_blob_path.display().to_string();
    let compiled = with_groth16_setup_blob_path_override(Some(setup_blob_display.clone()), || {
        compile(program, PUBLIC_PROOF_BACKEND, None)
    })
    .map_err(|err| {
        format!(
            "compile public bundle program with imported setup blob {} and backend {PUBLIC_PROOF_BACKEND}: {err}",
            setup_blob_path.display()
        )
    })?;
    ensure_imported_setup_boundary(&compiled, &setup_blob_display)?;
    Ok(compiled)
}

fn ensure_imported_setup_boundary(
    compiled: &zkf_lib::CompiledProgram,
    setup_blob_display: &str,
) -> Result<(), String> {
    let boundary = compiled
        .metadata
        .get(SETUP_SECURITY_BOUNDARY_KEY)
        .map(String::as_str)
        .unwrap_or("missing");
    let provenance = compiled
        .metadata
        .get(SETUP_PROVENANCE_KEY)
        .map(String::as_str)
        .unwrap_or("missing");
    if boundary != TRUSTED_IMPORTED_BOUNDARY || provenance != TRUSTED_IMPORTED_PROVENANCE {
        return Err(format!(
            "compiled public bundle program did not close over an imported setup blob for {}: boundary={}, provenance={}",
            setup_blob_display, boundary, provenance
        ));
    }
    Ok(())
}

fn ensure_local_ceremony_streamed_setup_boundary(
    compiled: &zkf_lib::CompiledProgram,
) -> Result<(), String> {
    let boundary = compiled
        .metadata
        .get(SETUP_SECURITY_BOUNDARY_KEY)
        .map(String::as_str)
        .unwrap_or("missing");
    let provenance = compiled
        .metadata
        .get(SETUP_PROVENANCE_KEY)
        .map(String::as_str)
        .unwrap_or("missing");
    let storage = compiled
        .metadata
        .get(GROTH16_STREAMED_SETUP_STORAGE_METADATA_KEY)
        .map(String::as_str)
        .unwrap_or("missing");
    if boundary != GROTH16_LOCAL_CEREMONY_STREAMED_SECURITY_BOUNDARY
        || provenance != GROTH16_LOCAL_CEREMONY_STREAMED_PROVENANCE
        || storage != GROTH16_STREAMED_SETUP_STORAGE_VALUE
    {
        return Err(format!(
            "compiled public bundle program did not close over the local ceremony streamed setup boundary: boundary={boundary}, provenance={provenance}, storage={storage}"
        ));
    }
    Ok(())
}

fn build_inputs_for_request(request: &BundleWitness) -> Result<WitnessInputs, String> {
    let expected_public_bytes = expected_public_bytes_for_request(request)?;
    let mut inputs = WitnessInputs::new();
    for (index, byte) in expected_public_bytes.iter().enumerate() {
        inputs.insert(
            witness_byte_name(index),
            FieldElement::from_u64(u64::from(*byte)),
        );
    }
    Ok(inputs)
}

fn expected_public_bytes_for_request(request: &BundleWitness) -> Result<Vec<u8>, String> {
    let bundle_evidence_digest = validate_bundle_evidence(request)?;
    expected_public_values(
        &request.statement_bundle_digest,
        &request.private_source_commitment_root,
        &request.metallib_digest_set_root,
        &request.attestation_manifest_digest,
        &request.toolchain_identity_digest,
        &bundle_evidence_digest,
    )
}

fn proving_lane_from_artifact(
    artifact: &zkf_lib::ProofArtifact,
    request: &BundleWitness,
    setup_blob_path: Option<&Path>,
) -> Result<PublicGroth16ProvingLane, String> {
    if artifact.backend.as_str() != PUBLIC_PROOF_BACKEND {
        return Err(format!(
            "bundle {} used unexpected backend {}",
            request.bundle_id,
            artifact.backend.as_str()
        ));
    }
    let groth16_msm_engine = required_metadata(artifact, "groth16_msm_engine")?;
    let qap_witness_map_engine = required_metadata(artifact, "qap_witness_map_engine")?;
    let metal_no_cpu_fallback = required_metadata(artifact, "metal_no_cpu_fallback")?
        .parse::<bool>()
        .map_err(|err| {
            format!(
                "parse metal_no_cpu_fallback for {}: {err}",
                request.bundle_id
            )
        })?;
    let metal_gpu_busy_ratio = required_metadata(artifact, "metal_gpu_busy_ratio")?;
    let metal_counter_source = required_metadata(artifact, "metal_counter_source")?;

    let mut release_metadata = BTreeMap::new();
    release_metadata.insert("bundle_id".to_string(), request.bundle_id.clone());
    release_metadata.insert(
        "program_digest".to_string(),
        artifact.program_digest.clone(),
    );
    release_metadata.insert(
        "public_input_schema".to_string(),
        PUBLIC_INPUT_SCHEMA.to_string(),
    );
    if let Some(path) = setup_blob_path {
        release_metadata.insert(
            "groth16_setup_blob_path".to_string(),
            path.display().to_string(),
        );
    }
    if let Some(boundary) = artifact.metadata.get(SETUP_SECURITY_BOUNDARY_KEY) {
        release_metadata.insert(SETUP_SECURITY_BOUNDARY_KEY.to_string(), boundary.clone());
    }
    if let Some(provenance) = artifact.metadata.get(SETUP_PROVENANCE_KEY) {
        release_metadata.insert(SETUP_PROVENANCE_KEY.to_string(), provenance.clone());
    }

    let proving_lane = PublicGroth16ProvingLane {
        backend: PUBLIC_PROOF_BACKEND.to_string(),
        curve: required_metadata(artifact, "curve")?,
        groth16_msm_engine,
        qap_witness_map_engine,
        metal_no_cpu_fallback,
        metal_gpu_busy_ratio,
        metal_counter_source,
        release_metadata,
    };
    validate_public_groth16_proving_lane(&proving_lane).map_err(|err| {
        format!(
            "{err}; bundle={}, msm_engine={}, msm_reason={}, msm_fallback_state={}, witness_map_engine={}, witness_map_reason={}, witness_map_fallback_state={}, metal_no_cpu_fallback={}, metal_gpu_busy_ratio={}, metal_counter_source={}",
            request.bundle_id,
            proving_lane.groth16_msm_engine,
            artifact
                .metadata
                .get("groth16_msm_reason")
                .map(String::as_str)
                .unwrap_or("missing"),
            artifact
                .metadata
                .get("groth16_msm_fallback_state")
                .map(String::as_str)
                .unwrap_or("missing"),
            proving_lane.qap_witness_map_engine,
            artifact
                .metadata
                .get("qap_witness_map_reason")
                .map(String::as_str)
                .unwrap_or("missing"),
            artifact
                .metadata
                .get("qap_witness_map_fallback_state")
                .map(String::as_str)
                .unwrap_or("missing"),
            proving_lane.metal_no_cpu_fallback,
            proving_lane.metal_gpu_busy_ratio,
            proving_lane.metal_counter_source,
        )
    })?;
    Ok(proving_lane)
}

fn required_metadata(artifact: &zkf_lib::ProofArtifact, key: &str) -> Result<String, String> {
    artifact
        .metadata
        .get(key)
        .cloned()
        .ok_or_else(|| format!("proof artifact metadata is missing `{key}`"))
}

fn public_input_bytes_from_artifact(artifact: &zkf_lib::ProofArtifact) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::with_capacity(artifact.public_inputs.len());
    for (index, value) in artifact.public_inputs.iter().enumerate() {
        let byte = field_element_byte(value).map_err(|err| {
            format!("public_inputs[{index}] is not an admitted byte value: {err}")
        })?;
        bytes.push(byte);
    }
    validate_public_input_bytes(&bytes)?;
    Ok(bytes)
}

fn field_element_byte(value: &FieldElement) -> Result<u8, String> {
    let bytes = value.to_le_bytes();
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.iter().skip(1).any(|byte| *byte != 0) {
        return Err("non-zero high bytes".to_string());
    }
    Ok(bytes[0])
}

fn seed_from_label(label: &str) -> [u8; 32] {
    let digest = Sha256::digest(label.as_bytes());
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

fn witness_byte_name(index: usize) -> String {
    format!("bundle_byte_{index}")
}

fn public_byte_name(index: usize) -> String {
    format!("public_byte_{index}")
}

fn accumulator_name(index: usize) -> String {
    format!("bundle_acc_{index}")
}

fn padding_signal_name(index: usize) -> String {
    format!("bundle_qap_pad_{index}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_metal_public_proof_lib::{
        BuildIntegrityBundleEvidence, BundleEvidence, TheoremClosureBundleEvidence, TheoremRecord,
    };

    fn sample_request() -> BundleWitness {
        BundleWitness {
            bundle_id: "kernel-families".to_string(),
            theorem_ids: vec![
                "gpu.hash_differential_bounded".to_string(),
                "gpu.ntt_differential_bounded".to_string(),
            ],
            statement_bundle_digest:
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            private_source_commitment_root:
                "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            metallib_digest_set_root:
                "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            attestation_manifest_digest:
                "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
            toolchain_identity_digest:
                "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
            bundle_evidence: BundleEvidence::TheoremClosure(TheoremClosureBundleEvidence {
                bundle_id: "kernel-families".to_string(),
                theorem_ids: vec![
                    "gpu.hash_differential_bounded".to_string(),
                    "gpu.ntt_differential_bounded".to_string(),
                ],
                toolchain_identity_digest:
                    "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
                theorem_records: vec![
                    TheoremRecord {
                        theorem_id: "gpu.hash_differential_bounded".to_string(),
                        checker: "lean4".to_string(),
                        decl_name: "hash_family_exact_digest_sound".to_string(),
                        module_name: "ZkfMetal.Hash".to_string(),
                        proof_artifact_kind: "lean_theorem".to_string(),
                        proof_artifact_digest:
                            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                .to_string(),
                        allowed_axioms_only: true,
                        axioms: vec![],
                    },
                    TheoremRecord {
                        theorem_id: "gpu.ntt_differential_bounded".to_string(),
                        checker: "lean4".to_string(),
                        decl_name: "ntt_family_exact_transform_sound".to_string(),
                        module_name: "ZkfMetal.Ntt".to_string(),
                        proof_artifact_kind: "lean_theorem".to_string(),
                        proof_artifact_digest:
                            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                                .to_string(),
                        allowed_axioms_only: true,
                        axioms: vec![],
                    },
                ],
            }),
        }
    }

    #[test]
    fn build_public_bundle_program_creates_gpu_sized_surface() {
        let program = build_public_bundle_program().expect("program");
        assert_eq!(program.field, FieldId::Bn254);
        assert_eq!(program.name, BUNDLE_PROGRAM_NAME);
        assert!(program.signals.len() > 512);
        assert!(program.constraints.len() > 512);
    }

    #[test]
    fn bundle_inputs_match_expected_public_bytes() {
        let request = sample_request();
        let expected = expected_public_bytes_for_request(&request).expect("expected bytes");
        let inputs = build_inputs_for_request(&request).expect("inputs");
        assert_eq!(
            inputs.len(),
            zkf_metal_public_proof_lib::EXPECTED_PUBLIC_INPUT_BYTES
        );
        for (index, expected_byte) in expected.iter().enumerate() {
            let value = inputs
                .get(&witness_byte_name(index))
                .expect("witness input present");
            assert_eq!(
                field_element_byte(value).expect("byte value"),
                *expected_byte
            );
        }
    }

    #[test]
    fn proving_lane_from_artifact_requires_metal_metadata() {
        let request = BundleWitness {
            bundle_id: "build-integrity".to_string(),
            theorem_ids: vec!["public.build_integrity_commitment".to_string()],
            statement_bundle_digest:
                "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            private_source_commitment_root:
                "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            metallib_digest_set_root:
                "3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            attestation_manifest_digest:
                "4444444444444444444444444444444444444444444444444444444444444444".to_string(),
            toolchain_identity_digest:
                "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
            bundle_evidence: BundleEvidence::BuildIntegrity(BuildIntegrityBundleEvidence {
                bundle_id: "build-integrity".to_string(),
                theorem_ids: vec!["public.build_integrity_commitment".to_string()],
                private_source_commitment_root:
                    "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
                toolchain_identity_digest:
                    "5555555555555555555555555555555555555555555555555555555555555555".to_string(),
                metallib_digests: vec![
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                ],
            }),
        };
        let mut metadata = BTreeMap::new();
        metadata.insert("curve".to_string(), "bn254".to_string());
        metadata.insert(
            "groth16_msm_engine".to_string(),
            "metal-bn254-msm".to_string(),
        );
        metadata.insert(
            "qap_witness_map_engine".to_string(),
            "metal-bn254-ntt+streamed-reduction".to_string(),
        );
        metadata.insert("metal_no_cpu_fallback".to_string(), "true".to_string());
        metadata.insert("metal_gpu_busy_ratio".to_string(), "1.000".to_string());
        metadata.insert(
            "metal_counter_source".to_string(),
            "release-proof".to_string(),
        );
        let artifact = zkf_lib::ProofArtifact {
            backend: zkf_lib::BackendKind::ArkworksGroth16,
            program_digest: "abcd".to_string(),
            proof: vec![],
            verification_key: vec![],
            public_inputs: vec![],
            metadata,
            security_profile: None,
            hybrid_bundle: None,
            credential_bundle: None,
            archive_metadata: None,
            proof_origin_signature: None,
            proof_origin_public_keys: None,
        };
        let lane =
            proving_lane_from_artifact(&artifact, &request, None).expect("proving lane");
        assert_eq!(lane.groth16_msm_engine, "metal-bn254-msm");
    }
}
