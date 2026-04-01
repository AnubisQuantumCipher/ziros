use std::path::PathBuf;

use zkf_core::Program;

use crate::util::{
    attach_groth16_setup_blob_path, backend_for_request, ensure_backend_request_allowed,
    ensure_backend_supports_program_constraints, load_program_v2, parse_backend_request,
    parse_setup_seed, render_zkf_error, warn_if_r1cs_lookup_limit_exceeded,
    with_allow_dev_deterministic_groth16_override, with_setup_seed_override, write_json,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_compile(
    program: Option<PathBuf>,
    spec: Option<PathBuf>,
    backend: String,
    out: PathBuf,
    seed: Option<String>,
    groth16_setup_blob: Option<PathBuf>,
    allow_dev_deterministic_groth16: bool,
    allow_compat: bool,
) -> Result<(), String> {
    let program_path = match (program, spec) {
        (Some(program), None) => program,
        (None, Some(spec)) => spec,
        (Some(_), Some(_)) => {
            return Err("pass either --program <path> or --spec <zirapp.json>, not both".into());
        }
        (None, None) => {
            return Err(
                "missing input program: pass --program <path> or --spec <zirapp.json>".into(),
            );
        }
    };
    let mut program: Program = load_program_v2(&program_path)?;
    let request = parse_backend_request(&backend)?;
    ensure_backend_request_allowed(&request, allow_compat)?;
    ensure_backend_supports_program_constraints(request.backend, &program)?;
    warn_if_r1cs_lookup_limit_exceeded(request.backend, &program, "zkf compile");
    attach_groth16_setup_blob_path(&mut program, request.backend, groth16_setup_blob.as_deref());
    let engine = backend_for_request(&request);
    let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
    let compiled = with_allow_dev_deterministic_groth16_override(
        allow_dev_deterministic_groth16.then_some(true),
        || {
            with_setup_seed_override(seed, || {
                let compiled = engine.compile(&program).map_err(render_zkf_error)?;
                zkf_backends::ensure_security_covered_groth16_setup(&compiled)
                    .map_err(render_zkf_error)?;
                Ok(compiled)
            })
        },
    )?;
    write_json(&out, &compiled)?;
    println!("compiled {} -> {}", request.requested_name, out.display());
    Ok(())
}
