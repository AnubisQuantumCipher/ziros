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

use std::path::PathBuf;

use crate::util::{
    BackendRequest, backend_for_request, ensure_backend_request_allowed,
    ensure_manifest_v2_metadata_for_command, parse_backend_request, parse_setup_seed,
};

pub(crate) fn compile_package(
    manifest_path: &std::path::Path,
    request: &BackendRequest,
    seed: Option<[u8; 32]>,
) -> Result<crate::CompileResult, String> {
    let mut manifest: zkf_core::PackageManifest = crate::util::read_json(manifest_path)?;
    ensure_manifest_v2_metadata_for_command(manifest_path, &manifest, "zkf package compile")?;
    let root = manifest_path.parent().ok_or_else(|| {
        format!(
            "manifest has no parent directory: {}",
            manifest_path.display()
        )
    })?;
    let backend = request.backend;
    let program = crate::util::load_program_v2_for_backend(root, &manifest, backend)?;
    let engine = backend_for_request(request);
    let compiled = crate::util::with_setup_seed_override(seed, || {
        engine
            .compile(&program)
            .map_err(crate::util::render_zkf_error)
    })?;
    let compiled_path =
        crate::package_io::write_compiled_artifact(root, &mut manifest, backend, &compiled)?;
    crate::util::write_json(manifest_path, &manifest)?;

    Ok(crate::CompileResult {
        manifest: manifest_path.display().to_string(),
        backend: backend.as_str().to_string(),
        compiled_path: compiled_path.display().to_string(),
        compiled_data_bytes: compiled.compiled_data.as_ref().map_or(0, Vec::len),
        metadata_entries: compiled.metadata.len(),
        program_digest: compiled.program_digest,
    })
}

pub(crate) fn handle_compile(
    manifest: PathBuf,
    backend: String,
    json: bool,
    seed: Option<String>,
    allow_compat: bool,
) -> Result<(), String> {
    let request = parse_backend_request(&backend)?;
    ensure_backend_request_allowed(&request, allow_compat)?;
    let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
    let report = compile_package(&manifest, &request, seed)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "package compile: backend={} compiled_data_bytes={} metadata_entries={}",
            request.requested_name, report.compiled_data_bytes, report.metadata_entries
        );
    }
    Ok(())
}
