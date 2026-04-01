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
fn app_init_generates_updated_readme_and_input_files() {
    let temp = tempfile::tempdir().expect("tempdir");
    let out = temp.path().join("demo-app");
    let label = super::cmd::handle(
        crate::cli::Commands::App {
            command: crate::cli::AppCommands::Init {
                name: Some("demo-app".to_string()),
                name_positional: None,
                template: "range-proof".to_string(),
                template_arg: Vec::new(),
                style: "colored".to_string(),
                out: Some(out.clone()),
            },
        },
        false,
    );
    assert!(label.is_ok());

    let readme = std::fs::read_to_string(out.join("README.md")).expect("readme");
    assert!(readme.contains("inputs.compliant.json"));
    assert!(readme.contains("inputs.violation.json"));
    assert!(readme.contains("docs/APPSPEC_REFERENCE.md"));
    assert!(readme.contains("ziros app gallery"));

    assert!(out.join("inputs.compliant.json").is_file());
    assert!(out.join("inputs.violation.json").is_file());
}

#[test]
fn aerospace_app_init_generates_scripts_and_public_bundle_dirs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let out = temp.path().join("starship-app");
    let label = super::cmd::handle(
        crate::cli::Commands::App {
            command: crate::cli::AppCommands::Init {
                name: Some("starship-app".to_string()),
                name_positional: None,
                template: "private-starship-flip-catch".to_string(),
                template_arg: vec![
                    "steps=2".to_string(),
                    "samples=4".to_string(),
                    "profile=tower-catch".to_string(),
                ],
                style: "minimal".to_string(),
                out: Some(out.clone()),
            },
        },
        false,
    );
    assert!(label.is_ok());

    let readme = std::fs::read_to_string(out.join("README.md")).expect("readme");
    assert!(readme.contains("scripts/benchmark.sh"));
    assert!(readme.contains("scripts/generate_report.sh"));
    assert!(readme.contains("scripts/export_public_bundle.sh"));

    assert!(out.join("scripts/benchmark.sh").is_file());
    assert!(out.join("scripts/generate_report.sh").is_file());
    assert!(out.join("scripts/export_public_bundle.sh").is_file());
    assert!(out.join("artifacts/public").is_dir());
    assert!(out.join("artifacts/reports").is_dir());
    assert!(out.join("artifacts/benchmarks").is_dir());
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
