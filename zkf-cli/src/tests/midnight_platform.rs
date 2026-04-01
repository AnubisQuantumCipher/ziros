use clap::Parser;

#[test]
fn midnight_templates_command_name_is_wired() {
    let result = super::cmd::handle(
        crate::cli::Commands::Midnight {
            command: crate::cli::MidnightCommands::Templates { json: true },
        },
        false,
    );
    assert!(result.is_ok());
}

#[test]
fn midnight_package_manifest_tracks_22_pinned_packages() {
    let manifest = crate::cmd::midnight::shared::midnight_package_manifest()
        .expect("Midnight package manifest");
    assert_eq!(
        manifest.compact,
        crate::cmd::midnight::shared::REQUIRED_COMPACT_MANAGER_VERSION
    );
    assert_eq!(
        manifest.compactc,
        crate::cmd::midnight::shared::REQUIRED_COMPACTC_VERSION
    );
    assert_eq!(
        manifest.packages.len(),
        crate::cmd::midnight::shared::expected_midnight_package_count()
    );
    assert!(
        manifest
            .packages
            .iter()
            .any(|entry| entry.name == "@midnight-ntwrk/compact-runtime"
                && entry.version == crate::cmd::midnight::shared::REQUIRED_COMPACT_RUNTIME_VERSION)
    );
}

#[test]
fn midnight_template_catalog_lists_all_shipped_templates() {
    let catalog = crate::cmd::midnight::shared::midnight_template_catalog()
        .expect("Midnight template catalog");
    let ids = catalog
        .iter()
        .map(|entry| entry.template_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(catalog.len(), 6);
    assert_eq!(
        ids,
        vec![
            "token-transfer",
            "cooperative-treasury",
            "private-voting",
            "credential-verification",
            "private-auction",
            "supply-chain-provenance",
        ]
    );
    for entry in &catalog {
        assert_eq!(
            entry.package_pins.len(),
            crate::cmd::midnight::shared::expected_midnight_package_count()
        );
        assert!(
            entry.package_pins.iter().any(|pin| {
                pin == &format!(
                    "@midnight-ntwrk/compact-js@{}",
                    crate::cmd::midnight::shared::REQUIRED_COMPACT_JS_VERSION
                )
            }),
            "template {} should advertise the pinned compact-js lane",
            entry.template_id
        );
    }
}

#[test]
fn cli_parses_midnight_init_command() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "midnight",
        "init",
        "--name",
        "my-dapp",
        "--template",
        "token-transfer",
        "--out",
        "/tmp/my-dapp",
        "--network",
        "local",
    ]);

    match cli.command {
        crate::cli::Commands::Midnight {
            command:
                crate::cli::MidnightCommands::Init {
                    name,
                    template,
                    out,
                    network,
                },
        } => {
            assert_eq!(name, "my-dapp");
            assert_eq!(template, "token-transfer");
            assert_eq!(out, Some(std::path::PathBuf::from("/tmp/my-dapp")));
            assert_eq!(network, "local");
        }
        other => panic!("expected midnight init command, got {other:?}"),
    }
}

#[test]
fn cli_parses_midnight_doctor_command() {
    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "midnight",
        "doctor",
        "--json",
        "--strict",
        "--project",
        "/tmp/my-dapp",
        "--network",
        "preprod",
        "--proof-server-url",
        "http://127.0.0.1:6300",
        "--gateway-url",
        "http://127.0.0.1:6311",
        "--no-browser-check",
        "--require-wallet",
    ]);

    match cli.command {
        crate::cli::Commands::Midnight {
            command:
                crate::cli::MidnightCommands::Doctor {
                    json,
                    strict,
                    project,
                    network,
                    proof_server_url,
                    gateway_url,
                    browser_check,
                    no_browser_check,
                    require_wallet,
                },
        } => {
            assert!(json);
            assert!(strict);
            assert_eq!(project, Some(std::path::PathBuf::from("/tmp/my-dapp")));
            assert_eq!(network, "preprod");
            assert_eq!(proof_server_url.as_deref(), Some("http://127.0.0.1:6300"));
            assert_eq!(gateway_url.as_deref(), Some("http://127.0.0.1:6311"));
            assert!(!browser_check);
            assert!(no_browser_check);
            assert!(require_wallet);
        }
        other => panic!("expected midnight doctor command, got {other:?}"),
    }
}

#[test]
fn cli_parses_midnight_gateway_serve_command() {
    let cli = crate::cli::Cli::parse_from([
        "zkf", "midnight", "gateway", "serve", "--port", "6311", "--json",
    ]);

    match cli.command {
        crate::cli::Commands::Midnight {
            command:
                crate::cli::MidnightCommands::Gateway {
                    command: crate::cli::MidnightGatewayCommands::Serve { port, json },
                },
        } => {
            assert_eq!(port, 6311);
            assert!(json);
        }
        other => panic!("expected midnight gateway serve command, got {other:?}"),
    }
}
