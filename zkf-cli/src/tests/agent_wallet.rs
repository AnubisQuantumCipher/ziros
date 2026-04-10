use clap::Parser;

#[test]
fn wallet_cli_parses_snapshot_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "wallet",
        "--network",
        "preprod",
        "--json",
        "snapshot",
    ]);
    match cli.command {
        crate::cli::Commands::Wallet {
            network,
            json,
            command,
            ..
        } => {
            assert_eq!(network, "preprod");
            assert!(json);
            assert!(matches!(command, crate::cli::WalletCommands::Snapshot));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_run_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "--json",
        "run",
        "--goal",
        "build a midnight contract",
        "--strict",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { json, command, .. } => {
            assert!(json);
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Run { goal, strict: true, .. }
                if goal == "build a midnight contract"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_workflow_override_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "plan",
        "--goal",
        "prepare benchmark evidence",
        "--workflow",
        "benchmark-report",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Plan {
                    goal,
                    workflow: Some(ref workflow),
                    ..
                } if goal == "prepare benchmark evidence" && workflow == "benchmark-report"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_mcp_serve_surface() {
    let cli = crate::cli::Cli::parse_from(["zkf", "agent", "mcp", "serve"]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Mcp {
                    command: crate::cli::AgentMcpCommands::Serve
                }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_memory_artifacts_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "memory",
        "artifacts",
        "--session-id",
        "session-123",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Memory {
                    command: crate::cli::AgentMemoryCommands::Artifacts { session_id: Some(ref value) }
                } if value == "session-123"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_approvals_list_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "approvals",
        "list",
        "--session-id",
        "session-123",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Approvals {
                    command: crate::cli::AgentApprovalCommands::List { session_id: Some(ref value) }
                } if value == "session-123"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_workflow_list_surface() {
    let cli = crate::cli::Cli::parse_from(["zkf", "agent", "workflow", "list"]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Workflow {
                    command: crate::cli::AgentWorkflowCommands::List
                }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_worktree_list_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "worktree",
        "list",
        "--session-id",
        "session-123",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Worktree {
                    command: crate::cli::AgentWorktreeCommands::List { session_id: Some(ref value) }
                } if value == "session-123"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_checkpoint_create_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "checkpoint",
        "create",
        "--session-id",
        "session-123",
        "--label",
        "before-deploy",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Checkpoint {
                    command: crate::cli::AgentCheckpointCommands::Create { session_id, label }
                } if session_id == "session-123" && label == "before-deploy"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_provider_status_surface() {
    let cli = crate::cli::Cli::parse_from(["zkf", "agent", "provider", "status"]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Provider {
                    command: crate::cli::AgentProviderCommands::Status { session_id: None }
                }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_bridge_prepare_surface() {
    let cli = crate::cli::Cli::parse_from([
        "ziros",
        "agent",
        "--json",
        "bridge",
        "prepare",
        "--goal",
        "Prepare a Midnight-first subsystem plan",
        "--provider",
        "openai-api",
        "--model",
        "gpt-5.3-codex",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { json, command, .. } => {
            assert!(json);
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Bridge {
                    command: crate::cli::AgentBridgeCommands::Prepare {
                        goal,
                        provider: Some(ref provider),
                        model: Some(ref model),
                        ..
                    }
                } if goal == "Prepare a Midnight-first subsystem plan"
                    && provider == "openai-api"
                    && model == "gpt-5.3-codex"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn gateway_cli_parses_allow_remote_writes_surface() {
    let cli = crate::cli::Cli::parse_from([
        "ziros",
        "gateway",
        "serve",
        "--bind",
        "127.0.0.1:8788",
        "--allow-remote-writes",
    ]);
    match cli.command {
        crate::cli::Commands::Gateway { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::GatewayCommands::Serve {
                    bind,
                    allow_remote_writes: true,
                    ..
                } if bind == "127.0.0.1:8788"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn gateway_cli_parses_setup_surface() {
    let cli = crate::cli::Cli::parse_from([
        "ziros",
        "gateway",
        "setup",
        "--bind",
        "127.0.0.1:8788",
        "--json",
    ]);
    match cli.command {
        crate::cli::Commands::Gateway { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::GatewayCommands::Setup {
                    bind,
                    json: true,
                    copy_url: true,
                    open_chatgpt: true,
                } if bind == "127.0.0.1:8788"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn gateway_cli_parses_install_surface() {
    let cli = crate::cli::Cli::parse_from([
        "ziros",
        "gateway",
        "install",
        "--bind",
        "127.0.0.1:8788",
        "--json",
    ]);
    match cli.command {
        crate::cli::Commands::Gateway { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::GatewayCommands::Install {
                    bind,
                    json: true,
                } if bind == "127.0.0.1:8788"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn gateway_cli_parses_start_surface() {
    let cli = crate::cli::Cli::parse_from(["ziros", "gateway", "start", "--json"]);
    match cli.command {
        crate::cli::Commands::Gateway { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::GatewayCommands::Start { json: true }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn gateway_cli_parses_stop_surface() {
    let cli = crate::cli::Cli::parse_from(["ziros", "gateway", "stop", "--json"]);
    match cli.command {
        crate::cli::Commands::Gateway { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::GatewayCommands::Stop { json: true }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn gateway_cli_parses_restart_surface() {
    let cli = crate::cli::Cli::parse_from(["ziros", "gateway", "restart", "--json"]);
    match cli.command {
        crate::cli::Commands::Gateway { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::GatewayCommands::Restart { json: true }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn gateway_cli_parses_status_surface() {
    let cli = crate::cli::Cli::parse_from(["ziros", "gateway", "status", "--json"]);
    match cli.command {
        crate::cli::Commands::Gateway { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::GatewayCommands::Status { json: true }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn setup_cli_parses_public_setup_surface() {
    let cli = crate::cli::Cli::parse_from([
        "ziros",
        "setup",
        "--non-interactive",
        "--provider",
        "openai",
        "--model",
        "gpt-5.2-codex",
    ]);
    match cli.command {
        crate::cli::Commands::Setup {
            non_interactive,
            provider,
            model,
            ..
        } => {
            assert!(non_interactive);
            assert_eq!(provider.as_deref(), Some("openai"));
            assert_eq!(model.as_deref(), Some("gpt-5.2-codex"));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn model_cli_parses_openai_profile_surface() {
    let cli = crate::cli::Cli::parse_from([
        "ziros",
        "model",
        "add",
        "openai",
        "--profile",
        "dev-openai",
        "--model",
        "gpt-5.2-codex",
    ]);
    match cli.command {
        crate::cli::Commands::Model { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::ModelCommands::Add {
                    command: crate::cli::ModelAddCommands::Openai {
                        profile: Some(ref profile),
                        model: Some(ref model),
                        ..
                    }
                } if profile == "dev-openai" && model == "gpt-5.2-codex"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn gateway_cli_parses_serve_surface() {
    let cli =
        crate::cli::Cli::parse_from(["ziros", "gateway", "serve", "--bind", "127.0.0.1:8787"]);
    match cli.command {
        crate::cli::Commands::Gateway { command } => {
            assert!(matches!(
                command,
                crate::cli::GatewayCommands::Serve { ref bind, .. } if bind == "127.0.0.1:8787"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn update_cli_defaults_to_apply_surface() {
    let cli = crate::cli::Cli::parse_from(["ziros", "update"]);
    match cli.command {
        crate::cli::Commands::Update { command } => {
            assert!(command.is_none());
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_provider_route_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "provider",
        "route",
        "--session-id",
        "session-123",
        "--provider",
        "mlx-local",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Provider {
                    command: crate::cli::AgentProviderCommands::Route {
                        session_id: Some(ref session_id),
                        provider: Some(ref provider),
                        ..
                    }
                } if session_id == "session-123" && provider == "mlx-local"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_provider_test_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "provider",
        "test",
        "--provider",
        "ollama-local",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Provider {
                    command: crate::cli::AgentProviderCommands::Test {
                        session_id: None,
                        provider: Some(ref provider),
                        ..
                    }
                } if provider == "ollama-local"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn agent_cli_parses_approve_bridge_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "agent",
        "approve",
        "--session-id",
        "session-123",
        "--pending-id",
        "pending-123",
        "--primary-prompt",
        "Approve transfer",
        "--bridge-session-id",
        "bridge-session-123",
    ]);
    match cli.command {
        crate::cli::Commands::Agent { command, .. } => {
            assert!(matches!(
                command,
                crate::cli::AgentCommands::Approve {
                    session_id: Some(ref session_id),
                    ref pending_id,
                    bridge_session_id: Some(ref bridge_session_id),
                    ..
                } if session_id == "session-123"
                    && pending_id == "pending-123"
                    && bridge_session_id == "bridge-session-123"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn evm_cli_parses_verifier_export_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "evm",
        "verifier",
        "export",
        "--artifact",
        "proof.json",
        "--backend",
        "arkworks-groth16",
        "--out",
        "Verifier.sol",
        "--json",
    ]);
    match cli.command {
        crate::cli::Commands::Evm { command } => {
            assert!(matches!(
                command,
                crate::cli::EvmCommands::Verifier {
                    command: crate::cli::EvmVerifierCommands::Export {
                        backend,
                        json: true,
                        ..
                    }
                } if backend == "arkworks-groth16"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn evm_cli_parses_foundry_init_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "evm",
        "foundry",
        "init",
        "--solidity",
        "Verifier.sol",
        "--out",
        "bundle",
        "--artifact",
        "proof.json",
        "--backend",
        "arkworks-groth16",
        "--json",
    ]);
    match cli.command {
        crate::cli::Commands::Evm { command } => {
            assert!(matches!(
                command,
                crate::cli::EvmCommands::Foundry {
                    command: crate::cli::EvmFoundryCommands::Init {
                        backend: Some(ref backend),
                        json: true,
                        ..
                    }
                } if backend == "arkworks-groth16"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn subsystem_cli_parses_bundle_public_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "subsystem",
        "bundle-public",
        "--root",
        "/tmp/subsystem",
        "--json",
    ]);
    match cli.command {
        crate::cli::Commands::Subsystem { command } => {
            assert!(matches!(
                command,
                crate::cli::SubsystemCommands::BundlePublic { json: true, .. }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn subsystem_cli_parses_evm_export_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "subsystem",
        "evm-export",
        "--root",
        "/tmp/subsystem",
        "--evm-target",
        "generic-evm",
        "--json",
    ]);
    match cli.command {
        crate::cli::Commands::Subsystem { command } => {
            assert!(matches!(
                command,
                crate::cli::SubsystemCommands::EvmExport {
                    evm_target,
                    json: true,
                    ..
                } if evm_target == "generic-evm"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn midnight_cli_parses_contract_diagnose_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "midnight",
        "contract",
        "diagnose",
        "--project",
        "/tmp/midnight-project",
        "--json",
    ]);
    match cli.command {
        crate::cli::Commands::Midnight { command } => {
            assert!(matches!(
                command,
                crate::cli::MidnightCommands::Contract {
                    command: crate::cli::MidnightContractCommands::Diagnose { json: true, .. }
                }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn subsystem_cli_parses_scaffold_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "subsystem",
        "scaffold",
        "--name",
        "demo-subsystem",
        "--style",
        "full",
        "--json",
    ]);
    match cli.command {
        crate::cli::Commands::Subsystem { command } => {
            assert!(matches!(
                command,
                crate::cli::SubsystemCommands::Scaffold { name, style, json: true, .. }
                if name == "demo-subsystem" && style == "full"
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn midnight_contract_cli_parses_deploy_prepare_surface() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "midnight",
        "contract",
        "deploy-prepare",
        "--source",
        "/tmp/contract.compact",
        "--out",
        "/tmp/deploy-prepare.json",
    ]);
    match cli.command {
        crate::cli::Commands::Midnight { command } => {
            assert!(matches!(
                command,
                crate::cli::MidnightCommands::Contract {
                    command: crate::cli::MidnightContractCommands::DeployPrepare { .. }
                }
            ));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}
