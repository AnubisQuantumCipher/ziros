use std::path::PathBuf;

pub(crate) fn handle_explore(proof: PathBuf, backend: String, json: bool) -> Result<(), String> {
    let artifact_data = std::fs::read(&proof)
        .map_err(|e| format!("failed to read proof artifact: {}: {}", proof.display(), e))?;

    let artifact: zkf_core::ProofArtifact = serde_json::from_slice(&artifact_data)
        .map_err(|e| format!("failed to parse proof artifact: {}", e))?;

    let proof_bytes = artifact.proof.len();
    let public_input_count = artifact.public_inputs.len();

    let vk_hash = artifact
        .metadata
        .get("vk_hash")
        .cloned()
        .unwrap_or_else(|| "n/a".to_string());

    let scheme = artifact
        .metadata
        .get("scheme")
        .cloned()
        .unwrap_or_else(|| backend.clone());
    let trust_model = artifact
        .metadata
        .get("trust_model")
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());
    let proof_semantics = artifact.metadata.get("proof_semantics").cloned();
    let algebraic_binding = artifact.metadata.get("algebraic_binding").cloned();
    let in_circuit_verification = artifact.metadata.get("in_circuit_verification").cloned();
    let aggregation_semantics = artifact.metadata.get("aggregation_semantics").cloned();
    let trust_boundary_note = algebraic_binding
        .as_deref()
        .filter(|value| *value == "false")
        .map(|_| {
            "algebraic_binding=false: this artifact is metadata/trust-model limited and does not claim a fully algebraically bound in-circuit accumulator verification"
                .to_string()
        });

    if json {
        let report = serde_json::json!({
            "backend": backend,
            "scheme": scheme,
            "proof_size_bytes": proof_bytes,
            "public_input_count": public_input_count,
            "vk_hash": vk_hash,
            "trust_model": trust_model,
            "proof_semantics": proof_semantics,
            "algebraic_binding": algebraic_binding,
            "in_circuit_verification": in_circuit_verification,
            "aggregation_semantics": aggregation_semantics,
            "trust_boundary_note": trust_boundary_note,
            "metadata": artifact.metadata,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("Proof Explorer");
        println!("==============");
        println!("Backend:           {}", backend);
        println!("Scheme:            {}", scheme);
        println!("Proof size:        {} bytes", proof_bytes);
        println!("Public inputs:     {}", public_input_count);
        println!("VK hash:           {}", vk_hash);
        println!("Trust model:       {}", trust_model);
        if let Some(value) = proof_semantics.as_deref() {
            println!("Proof semantics:   {}", value);
        }
        if let Some(value) = algebraic_binding.as_deref() {
            println!("Algebraic binding: {}", value);
        }
        if let Some(value) = in_circuit_verification.as_deref() {
            println!("In-circuit verify: {}", value);
        }
        if let Some(value) = aggregation_semantics.as_deref() {
            println!("Aggregation:       {}", value);
        }
        if let Some(note) = trust_boundary_note.as_deref() {
            println!("Trust note:        {}", note);
        }
        if !artifact.metadata.is_empty() {
            println!("\nMetadata:");
            for (k, v) in &artifact.metadata {
                println!("  {}: {}", k, v);
            }
        }
    }

    Ok(())
}
