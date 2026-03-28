#[test]
fn app_init_command_name_is_wired() {
    let temp = tempfile::tempdir().expect("tempdir");
    let label = super::cmd::handle(
        crate::cli::Commands::App {
            command: crate::cli::AppCommands::Init {
                name: Some("demo-app".to_string()),
                name_positional: None,
                template: "range-proof".to_string(),
                template_arg: Vec::new(),
                style: "colored".to_string(),
                out: Some(temp.path().join("demo-app")),
            },
        },
        false,
    );
    assert!(label.is_ok());
}

#[test]
fn app_templates_command_name_is_wired() {
    let label = super::cmd::handle(
        crate::cli::Commands::App {
            command: crate::cli::AppCommands::Templates { json: false },
        },
        false,
    );
    assert!(label.is_ok());
}

#[test]
fn app_gallery_command_name_is_wired() {
    let label = super::cmd::handle(
        crate::cli::Commands::App {
            command: crate::cli::AppCommands::Gallery,
        },
        false,
    );
    assert!(label.is_ok());
}

#[test]
fn app_init_accepts_name_flag() {
    use clap::Parser;

    let cli = crate::cli::Cli::parse_from([
        "zkf",
        "app",
        "init",
        "--template",
        "range-proof",
        "--name",
        "flag-app",
        "--out",
        "/tmp/flag-app",
    ]);

    match cli.command {
        crate::cli::Commands::App {
            command:
                crate::cli::AppCommands::Init {
                    name,
                    name_positional,
                    template,
                    out,
                    ..
                },
        } => {
            assert_eq!(name.as_deref(), Some("flag-app"));
            assert_eq!(name_positional, None);
            assert_eq!(template, "range-proof");
            assert_eq!(out, Some(std::path::PathBuf::from("/tmp/flag-app")));
        }
        other => panic!("expected app init command, got {other:?}"),
    }
}
