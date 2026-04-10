pub(crate) mod aerospace_qualification;
pub(crate) mod app;
pub(crate) mod agent;
pub(crate) mod audit;
pub(crate) mod capabilities;
pub(crate) mod circuit;
pub(crate) mod compile;
pub(crate) mod conformance;
pub(crate) mod credential;
pub(crate) mod debug;
pub(crate) mod demo;
pub(crate) mod deploy;
pub(crate) mod distributed;
pub(crate) mod equivalence;
pub(crate) mod evm;
pub(crate) mod estimate_gas;
pub(crate) mod explore;
pub(crate) mod gateway;
pub(crate) mod import;
pub(crate) mod ir;
pub(crate) mod keys;
pub(crate) mod lang;
pub(crate) mod model;
pub(crate) mod midnight;
pub(crate) mod optimize;
pub(crate) mod package;
pub(crate) mod prove;
pub(crate) mod registry;
pub(crate) mod retrain;
pub(crate) mod runtime;
pub(crate) mod setup;
pub(crate) mod sovereign_economic_defense;
pub(crate) mod storage;
pub(crate) mod subsystem;
pub(crate) mod swarm;
pub(crate) mod telemetry;
pub(crate) mod test_vectors;
pub(crate) mod chat;
pub(crate) mod update;
pub(crate) mod wallet;
pub(crate) mod witness;

use crate::benchmark::{BenchmarkOptions, render_markdown_table, run_benchmarks};
use crate::cli::{
    AgentCommands, AppCommands, CircuitCommands, ClusterCommands, Commands, CredentialCommands,
    EvmCommands, EvmFoundryCommands, EvmVerifierCommands, GatewayCommands, IrCommands,
    LangCommands, MidnightCommands, MidnightContractCommands, MidnightProofServerCommands,
    ModelAddCommands, ModelCommands, SubsystemCommands, TelemetryCommands, UpdateCommands,
    WalletCommands,
};
use crate::util::{
    parse_backend_request, parse_benchmark_backends, parse_optimization_objective,
    parse_setup_seed, parse_step_mode, write_json,
};
use zkf_runtime::{EntrypointGuard, EntrypointSurface, RuntimeSecurityContext};

pub(crate) fn handle(command: Commands, allow_compat: bool) -> Result<(), String> {
    let guard = EntrypointGuard::begin(EntrypointSurface::Cli, command_name(&command));
    let result = match command {
        Commands::Setup {
            json,
            non_interactive,
            provider,
            profile,
            model,
            reasoning_effort,
            base_url,
            project,
            organization,
            api_key_stdin,
            set_default,
            start_daemon,
        } => setup::handle_setup(setup::SetupCommand {
            json,
            non_interactive,
            provider,
            profile,
            model,
            reasoning_effort,
            base_url,
            project,
            organization,
            api_key_stdin,
            set_default,
            start_daemon,
        }),
        Commands::Chat {
            project,
            provider,
            model,
            strict,
            allow_compat,
        } => chat::handle_chat(chat::ChatCommand {
            project_root: project,
            provider,
            model,
            strict,
            compat_allowed: allow_compat,
        }),
        Commands::Model { json, command } => model::handle_model(json, command),
        Commands::Gateway { command } => gateway::handle_gateway(command),
        Commands::Update { command } => update::handle_update(command),
        Commands::Version { json } => update::handle_version(json),
        Commands::App { command } => app::handle_app(command),
        Commands::Subsystem { command } => match command {
            SubsystemCommands::Scaffold {
                name,
                style,
                out,
                json,
            } => subsystem::handle_scaffold(&name, &style, out, json),
            SubsystemCommands::VerifyCompleteness { root, json } => {
                subsystem::handle_verify_completeness(root, json)
            }
            SubsystemCommands::VerifyReleasePin { pin, binary, json } => {
                subsystem::handle_verify_release_pin(pin, binary, json)
            }
            SubsystemCommands::Validate { root, json } => subsystem::handle_validate(root, json),
            SubsystemCommands::Prove { root, json } => subsystem::handle_prove(root, json),
            SubsystemCommands::Verify { root, json } => subsystem::handle_verify(root, json),
            SubsystemCommands::BundlePublic { root, json } => {
                subsystem::handle_bundle_public(root, json)
            }
            SubsystemCommands::DeployPrepare {
                root,
                network,
                json,
            } => subsystem::handle_deploy_prepare(root, network, json),
            SubsystemCommands::CallPrepare {
                root,
                call,
                inputs,
                network,
                json,
            } => subsystem::handle_call_prepare(root, call, inputs, network, json),
            SubsystemCommands::EvmExport {
                root,
                evm_target,
                contract_name,
                json,
            } => subsystem::handle_evm_export(root, evm_target, contract_name, json),
        },
        Commands::Midnight { command } => midnight::handle_midnight(command),
        Commands::Evm { command } => evm::handle_evm(command),
        Commands::Wallet {
            network,
            persistent_root,
            cache_root,
            json,
            events_jsonl,
            command,
        } => wallet::handle_wallet(network, persistent_root, cache_root, json, events_jsonl, command),
        Commands::Agent {
            json,
            events_jsonl,
            command,
        } => agent::handle_agent(json, events_jsonl, command),
        Commands::Credential { command } => credential::handle_credential(command),
        Commands::Capabilities { json: _ } => capabilities::handle_capabilities(),
        Commands::Frontends { json: _ } => capabilities::handle_frontends(),
        Commands::Lang { command } => match command {
            LangCommands::Check { source, json } => lang::handle_lang_check(source, json),
            LangCommands::Lower {
                source,
                out,
                to,
                json,
            } => lang::handle_lang_lower(source, out, to, json),
            LangCommands::Obligations { source, json } => {
                lang::handle_lang_obligations(source, json)
            }
            LangCommands::Fmt { source, out, check } => lang::handle_lang_fmt(source, out, check),
            LangCommands::Prove {
                source,
                inputs,
                json,
                backend,
                objective,
                mode,
                export,
                allow_attestation,
                out,
                compiled_out,
                solver,
                seed,
                groth16_setup_blob,
                allow_dev_deterministic_groth16,
                hybrid,
            } => lang::handle_lang_prove(
                lang::LangProveArgs {
                    source,
                    inputs,
                    json,
                    backend,
                    objective,
                    mode,
                    export,
                    allow_attestation,
                    out,
                    compiled_out,
                    solver,
                    seed,
                    groth16_setup_blob,
                    allow_dev_deterministic_groth16,
                    hybrid,
                },
                allow_compat,
            ),
            LangCommands::Verify {
                source,
                artifact,
                backend,
                compiled,
                seed,
                groth16_setup_blob,
                allow_dev_deterministic_groth16,
                hybrid,
            } => lang::handle_lang_verify(
                lang::LangVerifyArgs {
                    source,
                    artifact,
                    backend,
                    compiled,
                    seed,
                    groth16_setup_blob,
                    allow_dev_deterministic_groth16,
                    hybrid,
                },
                allow_compat,
            ),
        },
        Commands::SupportMatrix { out } => capabilities::handle_support_matrix(out),
        Commands::Doctor { json } => capabilities::handle_doctor(json),
        Commands::MetalDoctor { json, strict } => capabilities::handle_metal_doctor(json, strict),
        Commands::Import {
            frontend,
            input,
            out,
            name,
            field,
            ir_family,
            allow_unsupported_version,
            package_out,
            json,
        } => import::handle_import(import::HandleImportArgs {
            frontend,
            input,
            out,
            name,
            field,
            ir_family,
            allow_unsupported_version,
            package_out,
            json,
        }),
        Commands::Inspect {
            frontend,
            input,
            json,
        } => import::handle_inspect(frontend, input, json),
        Commands::Circuit { command } => match command {
            CircuitCommands::Show {
                program,
                json,
                show_assignments,
                show_flow,
            } => circuit::handle_circuit_show(program, json, show_assignments, show_flow),
        },
        Commands::ImportAcir {
            input,
            out,
            name,
            field,
            ir_family,
            package_out,
        } => import::handle_import_acir(input, out, name, field, ir_family, package_out),
        Commands::EmitExample { out, field } => import::handle_emit_example(out, field),
        Commands::Compile {
            program,
            spec,
            backend,
            out,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
        } => compile::handle_compile(
            program,
            spec,
            backend,
            out,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            allow_compat,
        ),
        Commands::Witness {
            program,
            inputs,
            out,
        } => witness::handle_witness(program, inputs, out),
        Commands::Optimize { program, out, json } => optimize::handle_optimize(program, out, json),
        Commands::Audit {
            program,
            backend,
            out,
            json,
        } => audit::handle_audit(program, backend, out, json),
        Commands::Conformance {
            backend,
            json,
            export_json,
            export_cbor,
        } => conformance::handle_conformance(backend, json, export_json, export_cbor),
        Commands::Demo { out, json } => demo::handle_demo(out, json),
        Commands::Equivalence {
            program,
            inputs,
            backends,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            json,
        } => equivalence::handle_equivalence(
            program,
            inputs,
            backends,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            json,
            allow_compat,
        ),
        Commands::Ir { command } => match command {
            IrCommands::Validate { program, json } => ir::handle_ir_validate(program, json),
            IrCommands::Normalize { program, out, json } => {
                ir::handle_ir_normalize(program, out, json)
            }
            IrCommands::TypeCheck { program, json } => ir::handle_ir_type_check(program, json),
        },
        Commands::Run {
            manifest,
            inputs,
            run_id,
            solver,
            json,
        } => witness::handle_run(manifest, inputs, run_id, solver, json),
        Commands::Debug {
            program,
            inputs,
            out,
            continue_on_failure,
            poseidon_trace,
            solver,
        } => debug::handle_debug(
            program,
            inputs,
            out,
            continue_on_failure,
            poseidon_trace,
            solver,
        ),
        Commands::Prove {
            program,
            inputs,
            json,
            backend,
            objective,
            mode,
            export,
            allow_attestation,
            out,
            compiled_out,
            solver,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            hybrid,
            distributed,
        } => {
            if distributed {
                prove::handle_distributed_prove(
                    prove::ProveArgs {
                        program,
                        inputs,
                        json,
                        backend,
                        objective,
                        mode,
                        export,
                        allow_attestation,
                        out,
                        compiled_out,
                        solver,
                        seed,
                        groth16_setup_blob,
                        allow_dev_deterministic_groth16,
                        hybrid,
                    },
                    allow_compat,
                )
            } else {
                prove::handle_prove(
                    prove::ProveArgs {
                        program,
                        inputs,
                        json,
                        backend,
                        objective,
                        mode,
                        export,
                        allow_attestation,
                        out,
                        compiled_out,
                        solver,
                        seed,
                        groth16_setup_blob,
                        allow_dev_deterministic_groth16,
                        hybrid,
                    },
                    allow_compat,
                )
            }
        }
        Commands::Verify {
            program,
            artifact,
            backend,
            compiled,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            hybrid,
        } => prove::handle_verify(
            program,
            artifact,
            backend,
            compiled,
            seed,
            groth16_setup_blob,
            allow_dev_deterministic_groth16,
            hybrid,
            allow_compat,
        ),
        Commands::Wrap {
            proof,
            compiled,
            hardware_profile,
            allow_attestation,
            compress,
            dry_run,
            out,
            trace_out,
        } => prove::handle_wrap(
            proof,
            compiled,
            hardware_profile,
            allow_attestation,
            compress,
            dry_run,
            out,
            trace_out,
        ),
        Commands::Benchmark {
            out,
            markdown_out,
            mode,
            backends,
            iterations,
            skip_large,
            continue_on_error,
            parallel,
            distributed,
        } => {
            if distributed {
                let backends = parse_benchmark_backends(backends, mode.as_deref())?;
                distributed::handle_distributed_benchmark(
                    out,
                    markdown_out,
                    backends,
                    iterations,
                    continue_on_error,
                )
            } else {
                let backends = parse_benchmark_backends(backends, mode.as_deref())?;
                let options = BenchmarkOptions {
                    backends: backends.clone(),
                    iterations,
                    skip_large,
                    continue_on_error,
                    parallel,
                    metal_first: crate::util::parse_prove_mode(mode.as_deref())?
                        == Some("metal-first"),
                };

                let report = run_benchmarks(&options)?;
                write_json(&out, &report)?;

                if let Some(markdown_path) = markdown_out {
                    let table = render_markdown_table(&report);
                    std::fs::write(&markdown_path, table)
                        .map_err(|e| format!("{}: {e}", markdown_path.display()))?;
                    println!(
                        "wrote markdown benchmark report: {}",
                        markdown_path.display()
                    );
                }

                println!(
                    "benchmark completed for {} backends across {} cases (iterations={}) -> {}",
                    options.backends.len(),
                    report.cases.len(),
                    options.iterations,
                    out.display()
                );
                Ok(())
            }
        }
        Commands::EstimateGas {
            backend,
            artifact,
            proof_size,
            evm_target,
            json,
        } => estimate_gas::handle_estimate_gas(backend, artifact, proof_size, evm_target, json),
        Commands::Fold {
            manifest,
            inputs,
            steps,
            backend,
            objective,
            solver,
            step_mode,
            json,
            seed,
        } => {
            let step_mode = step_mode.as_deref().map(parse_step_mode).transpose()?;
            let seed = seed.as_deref().map(parse_setup_seed).transpose()?;
            let objective = parse_optimization_objective(Some(&objective))?;
            let backend = match backend.as_deref() {
                None | Some("auto") => None,
                Some(backend) => {
                    let request = parse_backend_request(backend)?;
                    crate::util::ensure_backend_request_allowed(&request, allow_compat)?;
                    Some(request.backend)
                }
            };
            package::fold::handle_fold(package::fold::FoldOptions {
                manifest,
                inputs,
                steps,
                backend,
                objective,
                solver,
                step_mode,
                json,
                seed,
            })
        }
        Commands::Cluster { command } => match command {
            ClusterCommands::Start { json } => distributed::handle_cluster_start(json),
            ClusterCommands::Status { json } => distributed::handle_cluster_status(json),
            ClusterCommands::Benchmark { out, json } => {
                distributed::handle_cluster_benchmark(out, json)
            }
        },
        Commands::Swarm { command } => swarm::handle_swarm(command),
        Commands::Storage { command } => storage::handle_storage(command),
        Commands::Keys { command } => keys::handle_keys(command),
        Commands::Retrain {
            input,
            profile,
            model_dir,
            corpus_out,
            summary_out,
            manifest_out,
            threshold_out,
            skip_threshold_optimizer,
            json,
        } => retrain::handle_retrain(retrain::RetrainArgs {
            input,
            profile,
            model_dir,
            corpus_out,
            summary_out,
            manifest_out,
            threshold_out,
            skip_threshold_optimizer,
            json,
        }),
        Commands::Telemetry { command } => match command {
            TelemetryCommands::Stats { dir, json } => telemetry::handle_stats(dir, json),
            TelemetryCommands::Export { input, out, json } => {
                telemetry::handle_export(input, out, json)
            }
        },
        Commands::Runtime { command } => runtime::handle_runtime(command),
        Commands::Package { command } => package::handle_package(command, allow_compat),
        Commands::Explore {
            proof,
            backend,
            json,
        } => explore::handle_explore(proof, backend, json),
        Commands::Deploy {
            artifact,
            backend,
            out,
            contract_name,
            evm_target,
            json,
        } => deploy::handle_deploy(artifact, backend, out, contract_name, evm_target, json),
        Commands::Registry { command } => registry::handle_registry(command),
        Commands::TestVectors {
            program,
            vectors,
            backends,
            json,
        } => test_vectors::handle_test_vectors(program, vectors, backends, json),
    };

    let detail = result.as_ref().err().cloned();
    let _ = guard.finish(
        RuntimeSecurityContext {
            caller_class: Some("cli".to_string()),
            ..RuntimeSecurityContext::default()
        },
        result.is_ok(),
        None,
        detail,
    );
    result
}

pub(crate) fn handle_default_ziros() -> Result<(), String> {
    if setup::setup_is_complete() {
        chat::handle_chat(chat::ChatCommand::default())
    } else {
        setup::handle_setup(setup::SetupCommand::default())
    }
}

fn command_name(command: &Commands) -> String {
    match command {
        Commands::Setup { .. } => "setup".to_string(),
        Commands::Chat { .. } => "chat".to_string(),
        Commands::Model { command, .. } => match command {
            ModelCommands::List => "model:list".to_string(),
            ModelCommands::Add { command } => match command {
                ModelAddCommands::Openai { .. } => "model:add-openai".to_string(),
                ModelAddCommands::Mlx { .. } => "model:add-mlx".to_string(),
                ModelAddCommands::OpenaiCompatible { .. } => {
                    "model:add-openai-compatible".to_string()
                }
                ModelAddCommands::Ollama { .. } => "model:add-ollama".to_string(),
            },
            ModelCommands::Use { .. } => "model:use".to_string(),
            ModelCommands::Test { .. } => "model:test".to_string(),
            ModelCommands::Remove { .. } => "model:remove".to_string(),
        },
        Commands::Gateway { command } => match command {
            GatewayCommands::Setup { .. } => "gateway:setup".to_string(),
            GatewayCommands::Install { .. } => "gateway:install".to_string(),
            GatewayCommands::Start { .. } => "gateway:start".to_string(),
            GatewayCommands::Stop { .. } => "gateway:stop".to_string(),
            GatewayCommands::Restart { .. } => "gateway:restart".to_string(),
            GatewayCommands::Status { .. } => "gateway:status".to_string(),
            GatewayCommands::Serve { .. } => "gateway:serve".to_string(),
        },
        Commands::Update { command } => match command {
            None => "update".to_string(),
            Some(UpdateCommands::Status { .. }) => "update:status".to_string(),
            Some(UpdateCommands::Apply { .. }) => "update:apply".to_string(),
        },
        Commands::Version { .. } => "version".to_string(),
        Commands::App { command } => match command {
            AppCommands::Init { .. } => "app:init".to_string(),
            AppCommands::Gallery => "app:gallery".to_string(),
            AppCommands::Templates { .. } => "app:templates".to_string(),
            AppCommands::PoweredDescent { .. } => "app:powered-descent".to_string(),
            AppCommands::ReentryAssurance(args) => match &args.command {
                Some(crate::cli::ReentryAssuranceCommands::SignPack { .. }) => {
                    "app:reentry-assurance:sign-pack".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::ValidatePack { .. }) => {
                    "app:reentry-assurance:validate-pack".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::Prove { .. }) => {
                    "app:reentry-assurance:prove".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::Verify { .. }) => {
                    "app:reentry-assurance:verify".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::Report { .. }) => {
                    "app:reentry-assurance:report".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::ExportBundle { .. }) => {
                    "app:reentry-assurance:export-bundle".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::IngestGmat { .. }) => {
                    "app:reentry-assurance:ingest-gmat".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::IngestSpice { .. }) => {
                    "app:reentry-assurance:ingest-spice".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::IngestOpenMdao { .. }) => {
                    "app:reentry-assurance:ingest-openmdao".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::IngestTrick { .. }) => {
                    "app:reentry-assurance:ingest-trick".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::DeriveModel { .. }) => {
                    "app:reentry-assurance:derive-model".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::QualifyModel { .. }) => {
                    "app:reentry-assurance:qualify-model".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::PublishAnnex { .. }) => {
                    "app:reentry-assurance:publish-annex".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::BuildDashboard { .. }) => {
                    "app:reentry-assurance:build-dashboard".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::HandoffCfs { .. }) => {
                    "app:reentry-assurance:handoff-cfs".to_string()
                }
                Some(crate::cli::ReentryAssuranceCommands::HandoffFprime { .. }) => {
                    "app:reentry-assurance:handoff-fprime".to_string()
                }
                None => "app:reentry-assurance".to_string(),
            },
            AppCommands::SovereignEconomicDefense(args) => match &args.command {
                crate::cli::SovereignEconomicDefenseCommands::Prove { .. } => {
                    "app:sovereign-economic-defense:prove".to_string()
                }
                crate::cli::SovereignEconomicDefenseCommands::Verify { .. } => {
                    "app:sovereign-economic-defense:verify".to_string()
                }
                crate::cli::SovereignEconomicDefenseCommands::Report { .. } => {
                    "app:sovereign-economic-defense:report".to_string()
                }
                crate::cli::SovereignEconomicDefenseCommands::ExportBundle { .. } => {
                    "app:sovereign-economic-defense:export-bundle".to_string()
                }
            },
            AppCommands::AerospaceQualification(args) => match &args.command {
                crate::cli::AerospaceQualificationCommands::Prove { .. } => {
                    "app:aerospace-qualification:prove".to_string()
                }
                crate::cli::AerospaceQualificationCommands::Verify { .. } => {
                    "app:aerospace-qualification:verify".to_string()
                }
                crate::cli::AerospaceQualificationCommands::Report { .. } => {
                    "app:aerospace-qualification:report".to_string()
                }
                crate::cli::AerospaceQualificationCommands::ExportBundle { .. } => {
                    "app:aerospace-qualification:export-bundle".to_string()
                }
            },
        },
        Commands::Subsystem { command } => match command {
            SubsystemCommands::Scaffold { .. } => "subsystem:scaffold".to_string(),
            SubsystemCommands::VerifyCompleteness { .. } => {
                "subsystem:verify-completeness".to_string()
            }
            SubsystemCommands::VerifyReleasePin { .. } => {
                "subsystem:verify-release-pin".to_string()
            }
            SubsystemCommands::Validate { .. } => "subsystem:validate".to_string(),
            SubsystemCommands::Prove { .. } => "subsystem:prove".to_string(),
            SubsystemCommands::Verify { .. } => "subsystem:verify".to_string(),
            SubsystemCommands::BundlePublic { .. } => "subsystem:bundle-public".to_string(),
            SubsystemCommands::DeployPrepare { .. } => "subsystem:deploy-prepare".to_string(),
            SubsystemCommands::CallPrepare { .. } => "subsystem:call-prepare".to_string(),
            SubsystemCommands::EvmExport { .. } => "subsystem:evm-export".to_string(),
        },
        Commands::Midnight { command } => match command {
            MidnightCommands::Status { .. } => "midnight:status".to_string(),
            MidnightCommands::ProofServer { command } => match command {
                MidnightProofServerCommands::Serve { .. } => {
                    "midnight:proof-server:serve".to_string()
                }
            },
            MidnightCommands::Gateway { command } => match command {
                crate::cli::MidnightGatewayCommands::Serve { .. } => {
                    "midnight:gateway:serve".to_string()
                }
            },
            MidnightCommands::Templates { .. } => "midnight:templates".to_string(),
            MidnightCommands::Init { .. } => "midnight:init".to_string(),
            MidnightCommands::Doctor { .. } => "midnight:doctor".to_string(),
            MidnightCommands::Disclosure { .. } => "midnight:disclosure".to_string(),
            MidnightCommands::Resolve { .. } => "midnight:resolve".to_string(),
            MidnightCommands::Contract { command } => match command {
                MidnightContractCommands::Compile { .. } => {
                    "midnight:contract:compile".to_string()
                }
                MidnightContractCommands::DeployPrepare { .. } => {
                    "midnight:contract:deploy-prepare".to_string()
                }
                MidnightContractCommands::CallPrepare { .. } => {
                    "midnight:contract:call-prepare".to_string()
                }
                MidnightContractCommands::Test { .. } => {
                    "midnight:contract:test".to_string()
                }
                MidnightContractCommands::Deploy { .. } => {
                    "midnight:contract:deploy".to_string()
                }
                MidnightContractCommands::Call { .. } => {
                    "midnight:contract:call".to_string()
                }
                MidnightContractCommands::VerifyExplorer { .. } => {
                    "midnight:contract:verify-explorer".to_string()
                }
                MidnightContractCommands::Diagnose { .. } => {
                    "midnight:contract:diagnose".to_string()
                }
            },
        },
        Commands::Evm { command } => match command {
            EvmCommands::Verifier { command } => match command {
                EvmVerifierCommands::Export { .. } => "evm:verifier:export".to_string(),
            },
            EvmCommands::EstimateGas { .. } => "evm:estimate-gas".to_string(),
            EvmCommands::Foundry { command } => match command {
                EvmFoundryCommands::Init { .. } => "evm:foundry:init".to_string(),
            },
            EvmCommands::Deploy { .. } => "evm:deploy".to_string(),
            EvmCommands::Call { .. } => "evm:call".to_string(),
            EvmCommands::Test { .. } => "evm:test".to_string(),
            EvmCommands::Diagnose { .. } => "evm:diagnose".to_string(),
        },
        Commands::Wallet { command, .. } => match command {
            WalletCommands::Snapshot => "wallet:snapshot".to_string(),
            WalletCommands::Unlock { .. } => "wallet:unlock".to_string(),
            WalletCommands::Lock => "wallet:lock".to_string(),
            WalletCommands::SyncHealth => "wallet:sync-health".to_string(),
            WalletCommands::Origin { .. } => "wallet:origin".to_string(),
            WalletCommands::Session { .. } => "wallet:session".to_string(),
            WalletCommands::Pending { .. } => "wallet:pending".to_string(),
            WalletCommands::Grant { .. } => "wallet:grant".to_string(),
        },
        Commands::Agent { command, .. } => match command {
            AgentCommands::Doctor { .. } => "agent:doctor".to_string(),
            AgentCommands::Status { .. } => "agent:status".to_string(),
            AgentCommands::Plan { .. } => "agent:plan".to_string(),
            AgentCommands::Run { .. } => "agent:run".to_string(),
            AgentCommands::Resume { .. } => "agent:resume".to_string(),
            AgentCommands::Cancel { .. } => "agent:cancel".to_string(),
            AgentCommands::Explain { .. } => "agent:explain".to_string(),
            AgentCommands::Logs { .. } => "agent:logs".to_string(),
            AgentCommands::Approve { .. } => "agent:approve".to_string(),
            AgentCommands::Reject { .. } => "agent:reject".to_string(),
            AgentCommands::Memory { .. } => "agent:memory".to_string(),
            AgentCommands::Approvals { .. } => "agent:approvals".to_string(),
            AgentCommands::Project { .. } => "agent:project".to_string(),
            AgentCommands::Bridge { .. } => "agent:bridge".to_string(),
            AgentCommands::Workflow { .. } => "agent:workflow".to_string(),
            AgentCommands::Worktree { .. } => "agent:worktree".to_string(),
            AgentCommands::Checkpoint { .. } => "agent:checkpoint".to_string(),
            AgentCommands::Provider { .. } => "agent:provider".to_string(),
            AgentCommands::Mcp { .. } => "agent:mcp".to_string(),
        },
        Commands::Credential { command } => match command {
            CredentialCommands::Issue { .. } => "credential:issue".to_string(),
            CredentialCommands::Prove { .. } => "credential:prove".to_string(),
            CredentialCommands::Verify { .. } => "credential:verify".to_string(),
        },
        Commands::Capabilities { .. } => "capabilities".to_string(),
        Commands::Frontends { .. } => "frontends".to_string(),
        Commands::Lang { command } => match command {
            LangCommands::Check { .. } => "lang:check".to_string(),
            LangCommands::Lower { .. } => "lang:lower".to_string(),
            LangCommands::Obligations { .. } => "lang:obligations".to_string(),
            LangCommands::Fmt { .. } => "lang:fmt".to_string(),
            LangCommands::Prove { .. } => "lang:prove".to_string(),
            LangCommands::Verify { .. } => "lang:verify".to_string(),
        },
        Commands::SupportMatrix { .. } => "support-matrix".to_string(),
        Commands::Doctor { .. } => "doctor".to_string(),
        Commands::MetalDoctor { .. } => "metal-doctor".to_string(),
        Commands::Import { .. } => "import".to_string(),
        Commands::Inspect { .. } => "inspect".to_string(),
        Commands::Circuit { command } => match command {
            CircuitCommands::Show { .. } => "circuit:show".to_string(),
        },
        Commands::ImportAcir { .. } => "import-acir".to_string(),
        Commands::EmitExample { .. } => "emit-example".to_string(),
        Commands::Compile { .. } => "compile".to_string(),
        Commands::Witness { .. } => "witness".to_string(),
        Commands::Optimize { .. } => "optimize".to_string(),
        Commands::Audit { .. } => "audit".to_string(),
        Commands::Conformance { .. } => "conformance".to_string(),
        Commands::Demo { .. } => "demo".to_string(),
        Commands::Equivalence { .. } => "equivalence".to_string(),
        Commands::Ir { command } => match command {
            IrCommands::Validate { .. } => "ir:validate".to_string(),
            IrCommands::Normalize { .. } => "ir:normalize".to_string(),
            IrCommands::TypeCheck { .. } => "ir:type-check".to_string(),
        },
        Commands::Run { .. } => "run".to_string(),
        Commands::Debug { .. } => "debug".to_string(),
        Commands::Prove { distributed, .. } => {
            if *distributed {
                "prove:distributed".to_string()
            } else {
                "prove".to_string()
            }
        }
        Commands::Verify { .. } => "verify".to_string(),
        Commands::Wrap { .. } => "wrap".to_string(),
        Commands::Benchmark { distributed, .. } => {
            if *distributed {
                "benchmark:distributed".to_string()
            } else {
                "benchmark".to_string()
            }
        }
        Commands::EstimateGas { .. } => "estimate-gas".to_string(),
        Commands::Fold { .. } => "fold".to_string(),
        Commands::Cluster { command } => match command {
            ClusterCommands::Start { .. } => "cluster:start".to_string(),
            ClusterCommands::Status { .. } => "cluster:status".to_string(),
            ClusterCommands::Benchmark { .. } => "cluster:benchmark".to_string(),
        },
        Commands::Swarm { command } => format!("swarm:{}", swarm_command_name(command)),
        Commands::Storage { command } => format!("storage:{}", storage_command_name(command)),
        Commands::Keys { command } => format!("keys:{}", keys_command_name(command)),
        Commands::Retrain { .. } => "retrain".to_string(),
        Commands::Telemetry { command } => match command {
            TelemetryCommands::Stats { .. } => "telemetry:stats".to_string(),
            TelemetryCommands::Export { .. } => "telemetry:export".to_string(),
        },
        Commands::Runtime { .. } => "runtime".to_string(),
        Commands::Package { .. } => "package".to_string(),
        Commands::Explore { .. } => "explore".to_string(),
        Commands::Deploy { .. } => "deploy".to_string(),
        Commands::Registry { .. } => "registry".to_string(),
        Commands::TestVectors { .. } => "test-vectors".to_string(),
    }
}

fn swarm_command_name(command: &crate::cli::SwarmCommands) -> &'static str {
    match command {
        crate::cli::SwarmCommands::Status { .. } => "status",
        crate::cli::SwarmCommands::RotateKey { .. } => "rotate-key",
        crate::cli::SwarmCommands::RegenerateKey { .. } => "regenerate-key",
        crate::cli::SwarmCommands::ListRules { .. } => "list-rules",
        crate::cli::SwarmCommands::ShadowRule { .. } => "shadow-rule",
        crate::cli::SwarmCommands::PromoteRule { .. } => "promote-rule",
        crate::cli::SwarmCommands::RevokeRule { .. } => "revoke-rule",
        crate::cli::SwarmCommands::RuleHistory { .. } => "rule-history",
        crate::cli::SwarmCommands::Reputation { .. } => "reputation",
        crate::cli::SwarmCommands::ReputationLog { .. } => "reputation-log",
        crate::cli::SwarmCommands::ReputationVerify { .. } => "reputation-verify",
    }
}

fn storage_command_name(command: &crate::cli::StorageCommands) -> &'static str {
    match command {
        crate::cli::StorageCommands::Status { .. } => "status",
        crate::cli::StorageCommands::MigrateToIcloud => "migrate-to-icloud",
        crate::cli::StorageCommands::Warm => "warm",
        crate::cli::StorageCommands::Evict => "evict",
        crate::cli::StorageCommands::Install => "install",
    }
}

fn keys_command_name(command: &crate::cli::KeysCommands) -> &'static str {
    match command {
        crate::cli::KeysCommands::List { .. } => "list",
        crate::cli::KeysCommands::Inspect { .. } => "inspect",
        crate::cli::KeysCommands::Rotate { .. } => "rotate",
        crate::cli::KeysCommands::Audit { .. } => "audit",
        crate::cli::KeysCommands::Revoke { .. } => "revoke",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::with_temp_home_and_env;
    use std::path::PathBuf;

    #[test]
    fn cluster_status_command_is_wired() {
        let result = with_temp_home_and_env(
            &[
                ("ZKF_SWARM", "1"),
                ("ZKF_DISTRIBUTED", "1"),
                ("ZKF_DISTRIBUTED_ROLE", "coordinator"),
                ("ZKF_DISTRIBUTED_DISCOVERY", "static"),
                ("ZKF_DISTRIBUTED_TRANSPORT", "tcp"),
                ("ZKF_DISTRIBUTED_BIND", "127.0.0.1:0"),
                ("ZKF_DISTRIBUTED_PEERS", ""),
            ],
            || {
                handle(
                    Commands::Cluster {
                        command: ClusterCommands::Status { json: false },
                    },
                    false,
                )
            },
        );

        assert!(result.is_ok());
    }

    #[test]
    fn distributed_benchmark_requires_positive_iterations() {
        let result = distributed::handle_distributed_benchmark(
            PathBuf::from("bench.json"),
            None,
            vec![zkf_core::BackendKind::ArkworksGroth16],
            0,
            false,
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("iterations must be >= 1"));
    }
}
