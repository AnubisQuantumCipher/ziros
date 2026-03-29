use crate::cli::PackageCommands;

pub(crate) mod aggregate;
pub(crate) mod bundle;
pub(crate) mod compile;
pub(crate) mod compose;
pub(crate) mod fold;
pub(crate) mod prove;
pub(crate) mod verify;
pub(crate) mod verify_proof;

pub(crate) fn handle_package(command: PackageCommands, allow_compat: bool) -> Result<(), String> {
    match command {
        PackageCommands::Migrate {
            manifest,
            from,
            to,
            json,
        } => verify::handle_migrate(manifest, from, to, json),
        PackageCommands::Verify { manifest, json } => verify::handle_verify(manifest, json),
        PackageCommands::Compile {
            manifest,
            backend,
            json,
            seed,
        } => compile::handle_compile(manifest, backend, json, seed, allow_compat),
        PackageCommands::Prove {
            manifest,
            backend,
            objective,
            mode,
            run_id,
            json,
            seed,
            hybrid,
        } => prove::handle_prove(prove::ProveOptions {
            manifest,
            backend,
            objective,
            mode,
            run_id,
            json,
            seed,
            hybrid,
            allow_compat,
        }),
        PackageCommands::ProveAll {
            manifest,
            backends,
            mode,
            run_id,
            parallel,
            jobs,
            json,
            seed,
        } => prove::handle_prove_all(prove::ProveAllOptions {
            manifest,
            backends,
            mode,
            run_id,
            parallel,
            jobs,
            json,
            seed,
            allow_compat,
        }),
        PackageCommands::VerifyProof {
            manifest,
            backend,
            run_id,
            solidity_verifier,
            json,
            seed,
            hybrid,
        } => verify_proof::handle_verify_proof(
            manifest,
            backend,
            run_id,
            solidity_verifier,
            json,
            seed,
            hybrid,
            allow_compat,
        ),
        PackageCommands::Bundle {
            manifest,
            backends,
            run_id,
            json,
        } => bundle::handle_bundle(manifest, backends, run_id, json),
        PackageCommands::VerifyBundle {
            manifest,
            run_id,
            json,
        } => bundle::handle_verify_bundle(manifest, run_id, json),
        PackageCommands::Aggregate {
            manifest,
            backend,
            input_run_ids,
            run_id,
            json,
            crypto,
        } => aggregate::handle_aggregate(manifest, backend, input_run_ids, run_id, json, crypto),
        PackageCommands::VerifyAggregate {
            manifest,
            backend,
            run_id,
            json,
        } => aggregate::handle_verify_aggregate(manifest, backend, run_id, json),
        PackageCommands::Compose {
            manifest,
            run_id,
            backend,
            json,
            seed,
        } => compose::handle_compose(manifest, run_id, backend, json, seed, allow_compat),
        PackageCommands::VerifyCompose {
            manifest,
            run_id,
            backend,
            json,
            seed,
        } => compose::handle_verify_compose(manifest, run_id, backend, json, seed, allow_compat),
    }
}
