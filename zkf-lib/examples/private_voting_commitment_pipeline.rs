use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;
use zkf_backends::blackbox_gadgets::enrich_witness_for_proving;
use zkf_backends::foundry_test::{generate_foundry_test_from_artifact, proof_to_calldata_json};
use zkf_backends::metal_runtime::metal_runtime_report;
use zkf_backends::{with_allow_dev_deterministic_groth16_override, with_proof_seed_override};
use zkf_core::{BackendKind, FieldElement, Program, Witness, WitnessInputs};
use zkf_core::{check_constraints, optimize_program};
use zkf_lib::evidence::{
    audit_entry_included, collect_formal_evidence_for_generated_app,
    effective_gpu_attribution_summary, ensure_file_exists, ensure_foundry_layout,
    foundry_project_dir, generated_app_closure_bundle_summary, json_pretty,
    persist_artifacts_to_cloudfs, two_tier_audit_record, write_json, write_text,
};
use zkf_lib::templates::private_vote_commitment_three_candidate;
use zkf_lib::{
    ZkfError, ZkfResult, audit_program_with_live_capabilities, compile,
    export_groth16_solidity_verifier, verify,
};

const SETUP_SEED: [u8; 32] = [0x11; 32];
const PROOF_SEED: [u8; 32] = [0x22; 32];

#[derive(Debug, Serialize)]
struct ProgramStats {
    signals: usize,
    constraints: usize,
    public_outputs: usize,
    blackbox_constraints: usize,
}

#[derive(Debug, Serialize)]
struct TimingSummary {
    compile_ms: f64,
    witness_enrichment_ms: f64,
    first_prove_ms: f64,
    first_verify_ms: f64,
    second_prove_ms: f64,
    second_verify_ms: f64,
}

#[derive(Debug, Serialize)]
struct DeterminismSummary {
    same_proof_bytes: bool,
    same_public_inputs: bool,
    same_verification_key: bool,
}

#[derive(Debug, Serialize)]
struct ArtifactPaths {
    program_original: String,
    program_optimized: String,
    program_compiled: String,
    inputs_valid: String,
    inputs_invalid_candidate_5: String,
    witness_valid: String,
    proof_first: String,
    proof_second: String,
    verifier_solidity: String,
    verifier_foundry_project: String,
    proof_calldata: String,
    summary: String,
    audit: String,
    evidence_manifest: String,
    report: String,
    formal_status: String,
}

#[derive(Debug, Serialize)]
struct Summary {
    circuit_name: String,
    backend: String,
    candidate_choice: String,
    original_program: ProgramStats,
    optimized_program: ProgramStats,
    compiled_program: ProgramStats,
    optimizer_report: zkf_core::OptimizeReport,
    timings: TimingSummary,
    determinism: DeterminismSummary,
    public_outputs: BTreeMap<String, String>,
    proof_sizes: BTreeMap<String, usize>,
    invalid_candidate_5_error: String,
    groth16_setup: serde_json::Value,
    proof_metadata: BTreeMap<String, String>,
    effective_gpu_attribution: serde_json::Value,
    generated_closure: serde_json::Value,
    formal_evidence: serde_json::Value,
    audit_coverage: serde_json::Value,
    metal_runtime: zkf_backends::metal_runtime::MetalRuntimeReport,
    paths: ArtifactPaths,
}

fn stats(program: &Program) -> ProgramStats {
    ProgramStats {
        signals: program.signals.len(),
        constraints: program.constraints.len(),
        public_outputs: program
            .signals
            .iter()
            .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
            .count(),
        blackbox_constraints: program
            .constraints
            .iter()
            .filter(|constraint| matches!(constraint, zkf_core::Constraint::BlackBox { .. }))
            .count(),
    }
}

fn output_dir() -> PathBuf {
    env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/zkf-private-voting"))
}

fn public_outputs(program: &Program, witness: &Witness) -> BTreeMap<String, String> {
    program
        .signals
        .iter()
        .filter(|signal| signal.visibility == zkf_core::Visibility::Public)
        .filter_map(|signal| {
            witness
                .values
                .get(&signal.name)
                .map(|value| (signal.name.clone(), value.to_decimal_string()))
        })
        .collect()
}

fn report_markdown(
    compiled: &zkf_core::CompiledProgram,
    summary: &Summary,
    audit_summary: &serde_json::Value,
    evidence_manifest: &serde_json::Value,
) -> String {
    format!(
        r#"# ZirOS Private Voting Commitment Pipeline

## Summary

This bundle contains a deterministic private-voting application exported through the ZirOS Groth16 application surface. It includes the compiled program, the valid and invalid input sets, the enriched proving witness, two deterministic proof artifacts, Solidity verifier assets, Foundry assets, structured audit coverage, and bundled formal proof evidence.

The compiled program digest for this run was `{compiled_digest}`.

## Evidence

Formal evidence:

`{formal_evidence}`

Audit coverage:

`{audit_summary}`

Generated implementation-closure extract:

`{generated_closure}`

## Determinism

`same_proof_bytes = {same_proof_bytes}`
`same_public_inputs = {same_public_inputs}`
`same_verification_key = {same_verification_key}`

## GPU Attribution

`{gpu_attribution}`
"#,
        compiled_digest = compiled.program_digest,
        formal_evidence = json_pretty(
            evidence_manifest
                .get("formal_evidence")
                .expect("formal evidence")
        ),
        audit_summary = json_pretty(audit_summary),
        generated_closure = json_pretty(
            evidence_manifest
                .get("generated_closure")
                .expect("generated closure")
        ),
        same_proof_bytes = summary.determinism.same_proof_bytes,
        same_public_inputs = summary.determinism.same_public_inputs,
        same_verification_key = summary.determinism.same_verification_key,
        gpu_attribution = json_pretty(&summary.effective_gpu_attribution),
    )
}

fn main() -> ZkfResult<()> {
    let out_dir = output_dir();
    fs::create_dir_all(&out_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", out_dir.display())))?;

    let template = private_vote_commitment_three_candidate()?;
    let original_program = template.program.clone();
    let valid_inputs = template.sample_inputs.clone();
    let invalid_inputs = WitnessInputs::from([
        ("candidate".to_string(), FieldElement::from_i64(5)),
        ("blinding".to_string(), FieldElement::from_u64(424_242)),
    ]);
    let (optimized_program, optimizer_report) = optimize_program(&original_program);

    let compile_start = Instant::now();
    let compiled = with_allow_dev_deterministic_groth16_override(Some(true), || {
        compile(&optimized_program, "arkworks-groth16", Some(SETUP_SEED))
    })?;
    let compile_ms = compile_start.elapsed().as_secs_f64() * 1_000.0;

    let witness_start = Instant::now();
    let base_witness = Witness {
        values: valid_inputs.clone(),
    };
    let enriched_witness = enrich_witness_for_proving(&compiled, &base_witness)?;
    check_constraints(&compiled.program, &enriched_witness)?;
    let witness_enrichment_ms = witness_start.elapsed().as_secs_f64() * 1_000.0;

    let invalid_candidate_5_error = {
        let invalid_base = Witness {
            values: invalid_inputs.clone(),
        };
        let invalid_enriched = enrich_witness_for_proving(&compiled, &invalid_base)?;
        match check_constraints(&compiled.program, &invalid_enriched) {
            Ok(()) => "candidate=5 unexpectedly satisfied the circuit".to_string(),
            Err(error) => error.to_string(),
        }
    };

    let first_prove_start = Instant::now();
    let proof_first = with_allow_dev_deterministic_groth16_override(Some(true), || {
        with_proof_seed_override(Some(PROOF_SEED), || {
            zkf_lib::prove(&compiled, &enriched_witness)
        })
    })?;
    let first_prove_ms = first_prove_start.elapsed().as_secs_f64() * 1_000.0;

    let first_verify_start = Instant::now();
    let first_verify = verify(&compiled, &proof_first)?;
    let first_verify_ms = first_verify_start.elapsed().as_secs_f64() * 1_000.0;
    if !first_verify {
        return Err(ZkfError::Backend(
            "first proof verification returned false".to_string(),
        ));
    }

    let second_prove_start = Instant::now();
    let proof_second = with_allow_dev_deterministic_groth16_override(Some(true), || {
        with_proof_seed_override(Some(PROOF_SEED), || {
            zkf_lib::prove(&compiled, &enriched_witness)
        })
    })?;
    let second_prove_ms = second_prove_start.elapsed().as_secs_f64() * 1_000.0;

    let second_verify_start = Instant::now();
    let second_verify = verify(&compiled, &proof_second)?;
    let second_verify_ms = second_verify_start.elapsed().as_secs_f64() * 1_000.0;
    if !second_verify {
        return Err(ZkfError::Backend(
            "second proof verification returned false".to_string(),
        ));
    }

    let verifier_source =
        export_groth16_solidity_verifier(&proof_first, Some("PrivateVotingVerifier"))?;
    let calldata = proof_to_calldata_json(&proof_first.proof, &proof_first.public_inputs)
        .map_err(ZkfError::Backend)?;
    let foundry_test = generate_foundry_test_from_artifact(
        &proof_first.proof,
        &proof_first.public_inputs,
        "../src/PrivateVotingVerifier.sol",
        "PrivateVotingVerifier",
    )
    .map_err(ZkfError::Backend)?;

    let project_dir = foundry_project_dir(&out_dir);
    ensure_foundry_layout(&project_dir)?;

    let program_original_path = out_dir.join("private_vote.original.program.json");
    let program_optimized_path = out_dir.join("private_vote.optimized.program.json");
    let compiled_path = out_dir.join("private_vote.compiled.json");
    let inputs_valid_path = out_dir.join("private_vote.valid.inputs.json");
    let inputs_invalid_path = out_dir.join("private_vote.invalid_candidate_5.inputs.json");
    let witness_path = out_dir.join("private_vote.valid.witness.json");
    let proof_first_path = out_dir.join("private_vote.proof.first.json");
    let proof_second_path = out_dir.join("private_vote.proof.second.json");
    let verifier_path = out_dir.join("PrivateVotingVerifier.sol");
    let calldata_path = out_dir.join("private_vote.proof.calldata.json");
    let summary_path = out_dir.join("private_vote.summary.json");
    let audit_path = out_dir.join("private_vote.audit.json");
    let evidence_manifest_path = out_dir.join("private_vote.evidence_manifest.json");
    let report_path = out_dir.join("private_vote.report.md");
    let audit_dir = out_dir.join("audit");
    let source_audit_path = audit_dir.join("private_vote.source_audit.json");
    let compiled_audit_path = audit_dir.join("private_vote.compiled_audit.json");
    let foundry_verifier_path = project_dir.join("src/PrivateVotingVerifier.sol");
    let foundry_test_path = project_dir.join("test/PrivateVotingVerifier.t.sol");

    write_json(&program_original_path, &original_program)?;
    write_json(&program_optimized_path, &optimized_program)?;
    write_json(&compiled_path, &compiled)?;
    write_json(&inputs_valid_path, &valid_inputs)?;
    write_json(&inputs_invalid_path, &invalid_inputs)?;
    write_json(&witness_path, &enriched_witness)?;
    write_json(&proof_first_path, &proof_first)?;
    write_json(&proof_second_path, &proof_second)?;
    write_text(&verifier_path, &verifier_source)?;
    write_json(&calldata_path, &calldata)?;
    write_text(&foundry_verifier_path, &verifier_source)?;
    write_text(&foundry_test_path, &foundry_test.source)?;

    let (generated_closure, formal_evidence) =
        collect_formal_evidence_for_generated_app(&out_dir, "private_voting_commitment_pipeline")?;
    let generated_closure_summary =
        generated_app_closure_bundle_summary("private_voting_commitment_pipeline")?;
    let effective_gpu_attribution =
        effective_gpu_attribution_summary(0, 0.0, &proof_first.metadata);

    fs::create_dir_all(&audit_dir)
        .map_err(|error| ZkfError::Io(format!("create {}: {error}", audit_dir.display())))?;
    let source_audit =
        audit_program_with_live_capabilities(&original_program, Some(BackendKind::ArkworksGroth16));
    let compiled_audit =
        audit_program_with_live_capabilities(&compiled.program, Some(BackendKind::ArkworksGroth16));
    write_json(&source_audit_path, &source_audit)?;
    write_json(&compiled_audit_path, &compiled_audit)?;
    let audit_summary = two_tier_audit_record(
        "zkf-application-audit-v1",
        json!({
            "status": "included",
            "original": {
                "program_digest": original_program.digest_hex(),
                "program_stats": stats(&original_program),
            },
            "optimized": {
                "program_digest": optimized_program.digest_hex(),
                "program_stats": stats(&optimized_program),
            },
            "compiled": {
                "program_digest": compiled.program_digest,
                "program_stats": stats(&compiled.program),
            },
        }),
        audit_entry_included(
            "included by default for the finished private-voting application bundle",
            "audit/private_vote.source_audit.json",
            "audit_program_with_live_capabilities(original_program, Some(arkworks-groth16))",
            serde_json::to_value(&source_audit.summary).unwrap_or_else(|_| json!({})),
        ),
        audit_entry_included(
            "included by default for the finished private-voting application bundle",
            "audit/private_vote.compiled_audit.json",
            "audit_program_with_live_capabilities(compiled_program, Some(arkworks-groth16))",
            serde_json::to_value(&compiled_audit.summary).unwrap_or_else(|_| json!({})),
        ),
    );

    let groth16_setup = json!({
        "trusted_setup_requested": false,
        "trusted_setup_used": false,
        "provenance": "deterministic-dev",
        "security_boundary": "development-only",
    });
    let evidence_manifest = json!({
        "bundle_evidence_version": "zkf-application-evidence-v1",
        "generated_closure": generated_closure_summary,
        "formal_evidence": formal_evidence,
        "audit_coverage": audit_summary,
        "gpu_attribution": effective_gpu_attribution,
        "trusted_setup": groth16_setup,
    });

    let summary = Summary {
        circuit_name: optimized_program.name.clone(),
        backend: BackendKind::ArkworksGroth16.as_str().to_string(),
        candidate_choice: "candidate 2 of 3 (one-indexed)".to_string(),
        original_program: stats(&original_program),
        optimized_program: stats(&optimized_program),
        compiled_program: stats(&compiled.program),
        optimizer_report,
        timings: TimingSummary {
            compile_ms,
            witness_enrichment_ms,
            first_prove_ms,
            first_verify_ms,
            second_prove_ms,
            second_verify_ms,
        },
        determinism: DeterminismSummary {
            same_proof_bytes: proof_first.proof == proof_second.proof,
            same_public_inputs: proof_first.public_inputs == proof_second.public_inputs,
            same_verification_key: proof_first.verification_key == proof_second.verification_key,
        },
        public_outputs: public_outputs(&compiled.program, &enriched_witness),
        proof_sizes: BTreeMap::from([
            ("first_proof_bytes".to_string(), proof_first.proof.len()),
            ("second_proof_bytes".to_string(), proof_second.proof.len()),
            (
                "verification_key_bytes".to_string(),
                proof_first.verification_key.len(),
            ),
        ]),
        invalid_candidate_5_error,
        groth16_setup,
        proof_metadata: proof_first.metadata.clone(),
        effective_gpu_attribution,
        generated_closure: generated_closure,
        formal_evidence: evidence_manifest["formal_evidence"].clone(),
        audit_coverage: evidence_manifest["audit_coverage"].clone(),
        metal_runtime: metal_runtime_report(),
        paths: ArtifactPaths {
            program_original: program_original_path.display().to_string(),
            program_optimized: program_optimized_path.display().to_string(),
            program_compiled: compiled_path.display().to_string(),
            inputs_valid: inputs_valid_path.display().to_string(),
            inputs_invalid_candidate_5: inputs_invalid_path.display().to_string(),
            witness_valid: witness_path.display().to_string(),
            proof_first: proof_first_path.display().to_string(),
            proof_second: proof_second_path.display().to_string(),
            verifier_solidity: verifier_path.display().to_string(),
            verifier_foundry_project: project_dir.display().to_string(),
            proof_calldata: calldata_path.display().to_string(),
            summary: summary_path.display().to_string(),
            audit: audit_path.display().to_string(),
            evidence_manifest: evidence_manifest_path.display().to_string(),
            report: report_path.display().to_string(),
            formal_status: out_dir.join("formal/STATUS.md").display().to_string(),
        },
    };
    write_json(&summary_path, &summary)?;
    write_json(&audit_path, &audit_summary)?;
    write_json(&evidence_manifest_path, &evidence_manifest)?;
    write_text(
        &report_path,
        &report_markdown(&compiled, &summary, &audit_summary, &evidence_manifest),
    )?;

    ensure_file_exists(&compiled_path)?;
    ensure_file_exists(&summary_path)?;
    ensure_file_exists(&audit_path)?;
    ensure_file_exists(&evidence_manifest_path)?;
    ensure_file_exists(&report_path)?;
    ensure_file_exists(&out_dir.join("formal/STATUS.md"))?;
    let _cloud_paths = persist_artifacts_to_cloudfs(
        "private_voting_commitment_pipeline",
        &[
            ("proofs".to_string(), proof_first_path.clone()),
            ("proofs".to_string(), proof_second_path.clone()),
            ("verifiers".to_string(), verifier_path.clone()),
            ("verifiers".to_string(), calldata_path.clone()),
            ("reports".to_string(), summary_path.clone()),
            ("audits".to_string(), audit_path.clone()),
            ("reports".to_string(), evidence_manifest_path.clone()),
            ("reports".to_string(), report_path.clone()),
        ],
    )?;

    println!("{}", summary_path.display());
    println!("{}", verifier_path.display());
    println!("{}", calldata_path.display());
    println!("{}", evidence_manifest_path.display());
    println!("{}", report_path.display());
    println!("{}", project_dir.display());
    Ok(())
}
