use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use crate::cli::AppCommands;
use crate::util::{read_json, write_json, write_text};
use owo_colors::OwoColorize;
use serde_json::Value;
use zkf_backends::GROTH16_SETUP_BLOB_PATH_ENV;
use zkf_core::FieldId;
use zkf_lib::PRIVATE_POWERED_DESCENT_DEFAULT_STEPS;
use zkf_lib::app::descent::PrivatePoweredDescentRequestV1;
use zkf_ui::ZkTheme;

const POWERED_DESCENT_PRODUCTION_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_PRODUCTION";
const POWERED_DESCENT_BUNDLE_MODE_ENV: &str = "ZKF_PRIVATE_POWERED_DESCENT_BUNDLE_MODE";
const POWERED_DESCENT_TRUSTED_SETUP_MANIFEST_ENV: &str =
    "ZKF_PRIVATE_POWERED_DESCENT_TRUSTED_SETUP_MANIFEST";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum AppStyle {
    Minimal,
    Colored,
    Tui,
}

impl AppStyle {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "minimal" => Ok(Self::Minimal),
            "colored" => Ok(Self::Colored),
            "tui" => Ok(Self::Tui),
            other => Err(format!(
                "unknown app style '{other}' (expected minimal, colored, or tui)"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Minimal => "minimal",
            Self::Colored => "colored",
            Self::Tui => "tui",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Minimal => "Minimal",
            Self::Colored => "Colored",
            Self::Tui => "TUI",
        }
    }

    fn one_line_description(self) -> &'static str {
        match self {
            Self::Minimal => "Plain-text scaffold for scripts, CI, and low-noise terminals.",
            Self::Colored => {
                "Colorized scaffold with proof banners, audit output, and live progress."
            }
            Self::Tui => "Interactive dashboard scaffold with ratatui panels and prove modals.",
        }
    }

    fn audience(self) -> &'static str {
        match self {
            Self::Minimal => "Automation-first developers, CI lanes, and shell-heavy workflows.",
            Self::Colored => {
                "Default app developers who want a polished proving flow without a full TUI."
            }
            Self::Tui => {
                "Teams shipping terminal-native apps like AegisVault, SolvencyGuard, and operator consoles."
            }
        }
    }

    fn experience_summary(self) -> &'static str {
        match self {
            Self::Minimal => "Generates a lean `main.rs` with plain check/prove/verify output.",
            Self::Colored => {
                "Generates a styled `main.rs` that uses `zkf-ui` rendering plus progress reporting."
            }
            Self::Tui => {
                "Generates `main.rs` + `dashboard.rs` wired through `zkf-tui` and the local proof worker."
            }
        }
    }

    fn example_command(self) -> &'static str {
        match self {
            Self::Minimal => "zkf app init --name my-zk-app --template range-proof --style minimal",
            Self::Colored => "zkf app init --name my-zk-app --template range-proof --style colored",
            Self::Tui => "zkf app init --name my-zk-app --template range-proof --style tui",
        }
    }
}

fn gallery_paint(theme: &ZkTheme, style: AppStyle, text: impl AsRef<str>) -> String {
    let text = text.as_ref();
    if !theme.colors_enabled {
        return text.to_string();
    }
    match style {
        AppStyle::Minimal => text.dimmed().to_string(),
        AppStyle::Colored => text.green().bold().to_string(),
        AppStyle::Tui => text.cyan().bold().to_string(),
    }
}

fn gallery_box_chars(
    theme: &ZkTheme,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    if theme.unicode_enabled {
        ("┌", "┐", "└", "┘", "│")
    } else {
        ("+", "+", "+", "+", "|")
    }
}

fn gallery_horizontal(theme: &ZkTheme, width: usize) -> String {
    if theme.unicode_enabled {
        "─".repeat(width)
    } else {
        "-".repeat(width)
    }
}

fn render_gallery_card(style: AppStyle, theme: &ZkTheme) -> String {
    let raw_title = format!("{} Style", style.display_name());
    let title = gallery_paint(theme, style, &raw_title);
    let lines = vec![
        style.one_line_description().to_string(),
        format!("Best for: {}", style.audience()),
        format!("Generated surface: {}", style.experience_summary()),
        format!("Try: {}", style.example_command()),
    ];
    let (tl, tr, bl, br, v) = gallery_box_chars(theme);
    let mut width = raw_title.len();
    for line in &lines {
        width = width.max(line.len());
    }
    let border = gallery_horizontal(theme, width + 2);
    let mut rendered = Vec::with_capacity(lines.len() + 3);
    rendered.push(format!("{tl}{border}{tr}"));
    rendered.push(format!("{v} {:width$} {v}", title, width = width));
    for line in lines {
        rendered.push(format!("{v} {:width$} {v}", line, width = width));
    }
    rendered.push(format!("{bl}{border}{br}"));
    rendered.join("\n")
}

fn render_gallery() -> String {
    let theme = ZkTheme::default();
    let intro = gallery_paint(&theme, AppStyle::Colored, "ZirOS App Gallery");
    [
        intro,
        "Choose the scaffold style that matches your app surface.".to_string(),
        render_gallery_card(AppStyle::Minimal, &theme),
        render_gallery_card(AppStyle::Colored, &theme),
        render_gallery_card(AppStyle::Tui, &theme),
        "Flagship example: cargo run -p zkf-tui --example aegisvault".to_string(),
    ]
    .join("\n\n")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("zkf-cli lives under the workspace root")
        .to_path_buf()
}

fn parse_template_args(values: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut parsed = BTreeMap::new();
    for value in values {
        let (key, value) = value
            .split_once('=')
            .ok_or_else(|| format!("invalid --template-arg '{value}' (expected key=value)"))?;
        if key.trim().is_empty() {
            return Err(format!("invalid --template-arg '{value}' (empty key)"));
        }
        parsed.insert(key.trim().to_string(), value.trim().to_string());
    }
    Ok(parsed)
}

fn template_spec(
    template: &str,
    template_args: &BTreeMap<String, String>,
) -> Result<zkf_lib::AppSpecV1, String> {
    zkf_lib::instantiate_template(template, template_args).map_err(|error| error.to_string())
}

fn render_templates(json: bool) -> Result<String, String> {
    let registry = zkf_lib::template_registry();
    if json {
        return serde_json::to_string_pretty(&registry)
            .map_err(|error| format!("failed to serialize template registry: {error}"));
    }

    Ok(registry
        .into_iter()
        .map(|entry| {
            let args = if entry.template_args.is_empty() {
                "args: none".to_string()
            } else {
                let rendered = entry
                    .template_args
                    .iter()
                    .map(|arg| {
                        let default = arg
                            .default_value
                            .as_deref()
                            .map(|value| format!(" default={value}"))
                            .unwrap_or_default();
                        format!("{}{}", arg.name, default)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("args: {rendered}")
            };
            format!("- {}: {} ({args})", entry.id, entry.description)
        })
        .collect::<Vec<_>>()
        .join("\n"))
}

fn crate_name(name: &str) -> String {
    name.replace(' ', "-")
}

fn out_dir(name: &str, out: Option<PathBuf>) -> Result<PathBuf, String> {
    let path = match out {
        Some(path) => path,
        None => std::env::current_dir()
            .map_err(|error| format!("failed to read current directory: {error}"))?
            .join(name),
    };
    if path.exists() {
        let mut entries = path
            .read_dir()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if entries
            .next()
            .transpose()
            .map_err(|error| error.to_string())?
            .is_some()
        {
            return Err(format!(
                "refusing to scaffold into non-empty directory '{}'",
                path.display()
            ));
        }
    }
    Ok(path)
}

fn cargo_toml_content(package_name: &str, style: AppStyle) -> String {
    let root = repo_root();
    let mut dependencies = vec![
        format!(
            "zkf-lib = {{ path = \"{}\" }}",
            root.join("zkf-lib").display()
        ),
        format!(
            "zkf-backends = {{ path = \"{}\" }}",
            root.join("zkf-backends").display()
        ),
        "serde_json = \"1\"".to_string(),
    ];
    if matches!(style, AppStyle::Colored | AppStyle::Tui) {
        dependencies.push(format!(
            "zkf-ui = {{ path = \"{}\" }}",
            root.join("zkf-ui").display()
        ));
    }
    if style == AppStyle::Tui {
        dependencies.push(format!(
            "zkf-tui = {{ path = \"{}\" }}",
            root.join("zkf-tui").display()
        ));
        dependencies.push("crossterm = \"0.28\"".to_string());
        dependencies.push("ratatui = { version = \"0.29\", default-features = false, features = [\"crossterm\"] }".to_string());
    }

    format!(
        r#"[package]
name = "{package_name}"
version = "0.1.0"
edition = "2024"

[workspace]

[dependencies]
{}
"#,
        dependencies.join("\n")
    )
}

fn spec_rs_content() -> &'static str {
    r#"pub fn load_app_spec() -> Result<zkf_lib::AppSpecV1, Box<dyn std::error::Error>> {
    let spec_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("zirapp.json");
    let spec_json = std::fs::read_to_string(spec_path)?;
    let spec = serde_json::from_str(&spec_json)?;
    Ok(spec)
}

pub fn load_program() -> Result<(zkf_lib::AppSpecV1, zkf_lib::Program), Box<dyn std::error::Error>>
{
    let spec = load_app_spec()?;
    let program = zkf_lib::build_app_spec(&spec)?;
    Ok((spec, program))
}
"#
}

fn scaffold_backend(field: FieldId) -> &'static str {
    match field {
        FieldId::Goldilocks | FieldId::BabyBear | FieldId::Mersenne31 => "plonky3",
        FieldId::PastaFp | FieldId::PastaFq => "halo2",
        FieldId::Bls12_381 => "halo2-bls12381",
        FieldId::Bn254 => "arkworks-groth16",
    }
}

fn backend_setup_note(backend: &str) -> &'static str {
    match backend {
        "plonky3" => "No trusted setup is required. This is the zero-friction starter lane.",
        "halo2" | "halo2-bls12381" => {
            "This scaffold uses an explicit Halo2 lane. Keep the backend explicit in production automation."
        }
        "arkworks-groth16" => {
            "This scaffold uses an explicit Groth16 lane. Import trusted setup material before production or switch to `range-proof` for the transparent starter path."
        }
        _ => "Keep the selected backend explicit in automation and CI.",
    }
}

fn minimal_main_rs_content(backend: &str) -> String {
    r#"mod spec;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = "__BACKEND__";
    let (spec, program) = spec::load_program()?;
    let inputs_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
    let inputs = zkf_lib::load_inputs(inputs_path.to_str().expect("manifest path must be utf-8"))?;
    let checked = zkf_lib::check_with_backend(&program, &inputs, backend, None, None)?;
    let embedded = zkf_lib::compile_and_prove(&program, &inputs, backend, None, None)?;
    let verified = zkf_lib::verify(&embedded.compiled, &embedded.artifact)?;
    if !verified {
        return Err("verification failed".into());
    }

    println!(
        "template={} backend={} public_outputs={:?} checked_public_inputs={:?}",
        program.name,
        embedded.compiled.backend,
        spec.public_outputs,
        checked.public_inputs
    );
    Ok(())
}
 "#
    .replace("__BACKEND__", backend)
}

fn colored_main_rs_content(backend: &str) -> String {
    r#"mod spec;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = "__BACKEND__";
    let theme = zkf_ui::ZkTheme::default();
    let (spec, program) = spec::load_program()?;
    let inputs_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
    let inputs = zkf_lib::load_inputs(inputs_path.to_str().expect("manifest path must be utf-8"))?;

    println!(
        "{}",
        zkf_ui::render_proof_banner(
            &program.name,
            program.signals.len(),
            program.constraints.len(),
            &theme
        )
    );

    let checked = zkf_lib::check_with_backend(&program, &inputs, backend, None, None)?;
    println!("{}", zkf_ui::render_check_result(&checked, &theme));

    let mut reporter = zkf_ui::ProofProgressReporter::default();
    let embedded = zkf_lib::compile_and_prove_with_progress_backend(
        &program,
        &inputs,
        backend,
        None,
        None,
        |event| reporter.observe(event),
    )?;
    reporter.clear();

    println!("{}", zkf_ui::render_proof_result(&embedded, &theme));
    let verified = zkf_lib::verify(&embedded.compiled, &embedded.artifact)?;
    if !verified {
        return Err("verification failed".into());
    }

    let labels = spec
        .public_outputs
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    println!(
        "{}",
        zkf_ui::render_credential(&embedded.artifact.public_inputs, &labels, &theme)
    );
    println!("Verification: {} VALID", theme.success_symbol);
    Ok(())
}
 "#
    .replace("__BACKEND__", backend)
}

fn tui_main_rs_content(backend: &str) -> String {
    r#"mod spec;
mod dashboard;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let inputs_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
    let inputs = zkf_lib::load_inputs(inputs_path.to_str().expect("manifest path must be utf-8"))?;
    let (_spec, program) = spec::load_program()?;
    dashboard::run(program, inputs, "__BACKEND__")
}
 "#
    .replace("__BACKEND__", backend)
}

fn tui_dashboard_rs_content() -> &'static str {
    r#"use std::time::Duration;

use crossterm::{
    event::{self, Event},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use zkf_tui::{DashboardAction, DashboardState, ProofJobUpdate, VaultEntry, ZkDashboard};

fn sample_state() -> DashboardState {
    DashboardState {
        entries: vec![
            VaultEntry {
                id: "1".to_string(),
                site: "mail.zir".to_string(),
                username: "alice".to_string(),
                category: "email".to_string(),
                strength: 94,
                proof_status: "Ready".to_string(),
            },
            VaultEntry {
                id: "2".to_string(),
                site: "bank.zir".to_string(),
                username: "alice.reserve".to_string(),
                category: "finance".to_string(),
                strength: 88,
                proof_status: "Ready".to_string(),
            },
        ],
        selected: 0,
        health_score: 91,
        proof_percent: 0,
        proof_stage_label: "Idle".to_string(),
        proof_activity_samples: Vec::new(),
        proof_running: false,
        audit_lines: vec![
            "Audit pipeline: PASS".to_string(),
            "Constraint surface: tight".to_string(),
            "Swarm defense: active".to_string(),
        ],
        status_line: "Press P to prove the selected credential.".to_string(),
        proof_modal: Default::default(),
    }
}

pub fn run(
    program: zkf_lib::Program,
    sample_inputs: zkf_lib::WitnessInputs,
    backend: &'static str,
) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let terminal_backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(terminal_backend)?;
    let dashboard = ZkDashboard::new();
    let mut state = sample_state();
    let mut receiver: Option<std::sync::mpsc::Receiver<ProofJobUpdate>> = None;

    let result = loop {
        terminal.draw(|frame| dashboard.draw(frame, &state))?;

        let mut clear_receiver = false;
        if let Some(active) = receiver.as_ref() {
            while let Ok(message) = active.try_recv() {
                match message {
                    ProofJobUpdate::Event(event) => {
                        state.apply_proof_event(&event);
                    }
                    ProofJobUpdate::Finished(result) => {
                        state.entries[state.selected].proof_status =
                            if result.verified { "Verified" } else { "Invalid" }.to_string();
                        state.finish_proof(result.verified);
                        state.open_modal(
                            "Proof Result",
                            result
                                .progress_lines
                                .into_iter()
                                .chain([
                                    String::new(),
                                    result.proof_summary,
                                    String::new(),
                                    result.credential,
                                ])
                                .collect(),
                        );
                        state.status_line = "Proof completed.".to_string();
                        clear_receiver = true;
                    }
                    ProofJobUpdate::Failed(message) => {
                        state.fail_proof(&message);
                        state.open_modal("Proof Failed", vec![message.clone()]);
                        clear_receiver = true;
                    }
                }
            }
        }
        if clear_receiver {
            receiver = None;
        }

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match dashboard.handle_key(&mut state, key) {
                    DashboardAction::None => {}
                    DashboardAction::Quit => break Ok(()),
                    DashboardAction::TriggerProof => {
                        if receiver.is_none() {
                            state.begin_proof();
                            receiver = Some(zkf_tui::spawn_local_proof_job_with_backend(
                                program.clone(),
                                sample_inputs.clone(),
                                backend.to_string(),
                            ));
                        }
                    }
                }
            }
        }
    };

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}
"#
}

fn smoke_test_content(style: AppStyle, backend: &str) -> String {
    match style {
        AppStyle::Minimal => format!(
            r#"#[path = "../src/spec.rs"]
mod spec;

#[test]
fn template_proves_and_verifies_and_rejects_violation() {{
    let handle = std::thread::Builder::new()
        .name("scaffold-smoke".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {{
            let backend = "{backend}";
            let (_spec, program) = spec::load_program().expect("program");
            let inputs_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
            let inputs = zkf_lib::load_inputs(
                inputs_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("sample inputs should load");
            let checked = zkf_lib::check_with_backend(&program, &inputs, backend, None, None)
                .expect("template should validate without proving");
            assert!(!checked.public_inputs.is_empty());
            let embedded = zkf_lib::compile_and_prove(&program, &inputs, backend, None, None)
                .expect("template should compile and prove");

            assert!(zkf_lib::verify(&embedded.compiled, &embedded.artifact).expect("verify"));
            let violation_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.violation.json");
            let violation_inputs = zkf_lib::load_inputs(
                violation_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("violation inputs should load");
            zkf_lib::compile_and_prove(&program, &violation_inputs, backend, None, None)
                .expect_err("violation inputs must fail closed");
        }})
        .expect("spawn scaffold smoke thread");
    handle.join().expect("scaffold smoke should succeed");
}}
"#
        ),
        AppStyle::Colored => format!(
            r#"#[path = "../src/spec.rs"]
mod spec;

#[test]
fn template_proves_and_verifies_with_progress_and_rejects_violation() {{
    let handle = std::thread::Builder::new()
        .name("scaffold-colored-smoke".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {{
            let backend = "{backend}";
            let (_spec, program) = spec::load_program().expect("program");
            let inputs_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
            let inputs = zkf_lib::load_inputs(
                inputs_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("sample inputs should load");
            let checked = zkf_lib::check_with_backend(&program, &inputs, backend, None, None)
                .expect("template should validate without proving");
            assert!(!checked.public_inputs.is_empty());
            let mut reporter = zkf_ui::ProofProgressReporter::new(true);
            let embedded = zkf_lib::compile_and_prove_with_progress_backend(
                &program,
                &inputs,
                backend,
                None,
                None,
                |event| reporter.observe(event),
            )
            .expect("template should compile and prove");

            assert!(zkf_lib::verify(&embedded.compiled, &embedded.artifact).expect("verify"));
            assert_eq!(reporter.lines().len(), 4);
            let violation_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.violation.json");
            let violation_inputs = zkf_lib::load_inputs(
                violation_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("violation inputs should load");
            zkf_lib::compile_and_prove_with_progress_backend(
                &program,
                &violation_inputs,
                backend,
                None,
                None,
                |_| {{}},
            )
            .expect_err("violation inputs must fail closed");
        }})
        .expect("spawn scaffold smoke thread");
    handle.join().expect("scaffold smoke should succeed");
}}
"#
        ),
        AppStyle::Tui => format!(
            r#"#[path = "../src/spec.rs"]
mod spec;

#[test]
fn template_proves_and_verifies_through_tui_worker_and_rejects_violation() {{
    let handle = std::thread::Builder::new()
        .name("scaffold-tui-smoke".to_string())
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {{
            let backend = "{backend}";
            let (_spec, program) = spec::load_program().expect("program");
            let compliant_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.compliant.json");
            let compliant_inputs = zkf_lib::load_inputs(
                compliant_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("compliant inputs should load");
            let result = zkf_tui::run_local_proof_demo_with_backend(
                &program,
                &compliant_inputs,
                backend,
            )
            .expect("proof demo");
            assert!(result.verified);
            assert_eq!(result.progress_lines.len(), 4);
            let violation_path =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("inputs.violation.json");
            let violation_inputs = zkf_lib::load_inputs(
                violation_path.to_str().expect("manifest path must be utf-8"),
            )
            .expect("violation inputs should load");
            zkf_tui::run_local_proof_demo_with_backend(&program, &violation_inputs, backend)
                .expect_err("violation inputs must fail closed");
        }})
        .expect("spawn scaffold smoke thread");
    handle.join().expect("scaffold smoke should succeed");
}}
"#
        ),
    }
}

fn readme_content(
    name: &str,
    template: &str,
    style: AppStyle,
    spec: &zkf_lib::AppSpecV1,
) -> String {
    let backend = scaffold_backend(spec.program.field);
    let extra = match style {
        AppStyle::Minimal => {
            "- `src/main.rs`: validates with `zkf_lib::check_with_backend(...)`, then proves and verifies in-process with `zkf-lib`."
        }
        AppStyle::Colored => {
            "- `src/main.rs`: uses `zkf-ui` plus explicit-backend progress proving to render a styled proof banner, audit surface, proof summary, and credential output."
        }
        AppStyle::Tui => {
            "- `src/dashboard.rs`: wires a ratatui-style dashboard shell through `zkf-tui` and the explicit-backend local proof worker surface."
        }
    };

    format!(
        r#"# {name}

This standalone app was scaffolded with `zkf app init` against the local ZirOS checkout.

Template: `{template}`
Style: `{style}`
Style description: {style_description}

## What You Got

- `zirapp.json`: canonical declarative app spec edited by default for app changes.
- `src/spec.rs`: generic loader that turns `zirapp.json` into a `zkf_lib::Program` at runtime.
{extra}
- `inputs.compliant.json`: known-good inputs that should compile, prove, and verify.
- `inputs.violation.json`: intentionally bad inputs that should fail closed.
- `tests/smoke.rs`: proves the compliant inputs and asserts that the violation inputs are rejected.
- Rust `ProgramBuilder` remains available as the escape hatch when you need advanced authoring.

## Current Template Contract

- Backend: `{backend}`
- Backend note: {backend_note}
- Expected private inputs: {expected_inputs:?}
- Public outputs: {public_outputs:?}
- Description: {description}
- Template args: {template_args:?}

## Run

```bash
cargo run
cargo test
```

Explore other scaffold variants with `zkf app gallery`.
List declarative templates with `zkf app templates`.
"#,
        style = style.as_str(),
        style_description = style.one_line_description(),
        backend = backend,
        backend_note = backend_setup_note(backend),
        expected_inputs = spec.expected_inputs,
        public_outputs = spec.public_outputs,
        description = spec.description.as_deref().unwrap_or("n/a"),
        template_args = spec.template_args,
    )
}

fn scaffold_app(
    name: &str,
    template_name: &str,
    template_args: &BTreeMap<String, String>,
    style: AppStyle,
    out: Option<PathBuf>,
) -> Result<PathBuf, String> {
    let spec = template_spec(template_name, template_args)?;
    zkf_lib::build_app_spec(&spec).map_err(|error| error.to_string())?;
    let backend = scaffold_backend(spec.program.field);
    let root = out_dir(name, out)?;
    std::fs::create_dir_all(root.join("src"))
        .map_err(|error| format!("{}: {error}", root.join("src").display()))?;
    std::fs::create_dir_all(root.join("tests"))
        .map_err(|error| format!("{}: {error}", root.join("tests").display()))?;

    write_text(
        &root.join("Cargo.toml"),
        &cargo_toml_content(&crate_name(name), style),
    )?;
    write_text(&root.join("src/spec.rs"), spec_rs_content())?;
    let main_rs = match style {
        AppStyle::Minimal => minimal_main_rs_content(backend),
        AppStyle::Colored => colored_main_rs_content(backend),
        AppStyle::Tui => tui_main_rs_content(backend),
    };
    write_text(&root.join("src/main.rs"), &main_rs)?;
    if style == AppStyle::Tui {
        write_text(&root.join("src/dashboard.rs"), tui_dashboard_rs_content())?;
    }
    let smoke_test = smoke_test_content(style, backend);
    write_text(&root.join("tests/smoke.rs"), &smoke_test)?;
    write_json(&root.join("zirapp.json"), &spec)?;
    write_json(&root.join("inputs.compliant.json"), &spec.sample_inputs)?;
    write_json(&root.join("inputs.violation.json"), &spec.violation_inputs)?;
    write_text(
        &root.join("README.md"),
        &readme_content(name, template_name, style, &spec),
    )?;

    Ok(root)
}

fn resolve_cli_path(path: PathBuf) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path)
    } else {
        let cwd = std::env::current_dir()
            .map_err(|error| format!("failed to read current directory: {error}"))?;
        let joined = cwd.join(path);
        match joined.canonicalize() {
            Ok(canonical) => Ok(canonical),
            Err(_) => Ok(joined),
        }
    }
}

fn cargo_target_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(path);
    }

    let config_path = repo_root().join(".cargo/config.toml");
    if let Ok(contents) = std::fs::read_to_string(&config_path) {
        for line in contents.lines() {
            let trimmed = line.trim();
            if let Some(value) = trimmed.strip_prefix("target-dir") {
                let configured = value
                    .split_once('=')
                    .map(|(_, value)| value.trim().trim_matches('"'));
                if let Some(configured) = configured.filter(|value| !value.is_empty()) {
                    return repo_root().join(configured);
                }
            }
        }
    }

    let target_local = repo_root().join("target-local");
    if target_local.exists() {
        target_local
    } else {
        repo_root().join("target")
    }
}

fn apply_toolchain_env(command: &mut Command) {
    if let Some(value) = std::env::var_os("CARGO_HOME") {
        command.env("CARGO_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("CARGO_HOME", PathBuf::from(home).join(".cargo"));
    }

    if let Some(value) = std::env::var_os("RUSTUP_HOME") {
        command.env("RUSTUP_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("RUSTUP_HOME", PathBuf::from(home).join(".rustup"));
    }

    if let Some(value) = std::env::var_os("OPAMROOT") {
        command.env("OPAMROOT", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("OPAMROOT", PathBuf::from(home).join(".opam"));
    }

    if let Some(value) = std::env::var_os("ELAN_HOME") {
        command.env("ELAN_HOME", value);
    } else if let Some(home) = std::env::var_os("HOME") {
        command.env("ELAN_HOME", PathBuf::from(home).join(".elan"));
    }
}

fn handle_powered_descent(
    inputs: PathBuf,
    out: PathBuf,
    full_audit: bool,
    bundle_mode: String,
    trusted_setup_blob: Option<PathBuf>,
    trusted_setup_manifest: Option<PathBuf>,
) -> Result<(), String> {
    let inputs = resolve_cli_path(inputs)?;
    let out = resolve_cli_path(out)?;
    let _: Value = read_json(&inputs)?;
    let request: PrivatePoweredDescentRequestV1 = read_json(&inputs)?;
    match bundle_mode.as_str() {
        "debug" | "public" => {}
        other => {
            return Err(format!(
                "unsupported --bundle-mode '{other}' (expected debug or public)"
            ));
        }
    }
    if trusted_setup_manifest.is_some() && trusted_setup_blob.is_none() {
        return Err(
            "--trusted-setup-manifest requires --trusted-setup-blob so the importer can bind both artifacts"
                .to_string(),
        );
    }
    let trusted_setup_blob = trusted_setup_blob.map(resolve_cli_path).transpose()?;
    let trusted_setup_manifest = trusted_setup_manifest.map(resolve_cli_path).transpose()?;

    let example_name = "private_powered_descent_showcase";
    let example_source = repo_root()
        .join("zkf-lib")
        .join("examples")
        .join(format!("{example_name}.rs"));
    if !example_source.is_file() {
        return Err(format!(
            "powered descent exporter is not available in this checkout yet (missing {})",
            example_source.display()
        ));
    }

    let debug_example = cargo_target_dir()
        .join("debug")
        .join("examples")
        .join(example_name);
    let release_example = cargo_target_dir()
        .join("release")
        .join("examples")
        .join(example_name);

    let prefer_release_example =
        full_audit || request.public.step_count >= PRIVATE_POWERED_DESCENT_DEFAULT_STEPS;

    let mut command = if prefer_release_example && release_example.is_file() {
        Command::new(release_example)
    } else if debug_example.is_file() {
        Command::new(debug_example)
    } else if release_example.is_file() {
        Command::new(release_example)
    } else {
        let mut cargo = Command::new("cargo");
        cargo
            .current_dir(repo_root())
            .arg("run")
            .arg("-p")
            .arg("zkf-lib")
            .arg("--example")
            .arg(example_name)
            .arg("--");
        cargo
    };
    command
        .current_dir(repo_root())
        .arg(&out)
        .env("ZKF_PRIVATE_POWERED_DESCENT_INPUTS_JSON", &inputs)
        .env(POWERED_DESCENT_BUNDLE_MODE_ENV, &bundle_mode)
        .env("ZKF_SWARM", "1")
        .env("ZKF_SWARM_KEY_BACKEND", "file")
        .env("ZKF_SECURITY_POLICY_MODE", "observe");
    apply_toolchain_env(&mut command);
    if cfg!(target_os = "macos") && prefer_release_example {
        command
            .env("MallocNanoZone", "0")
            .env("MallocSpaceEfficient", "1");
    }
    if full_audit {
        command.env("ZKF_PRIVATE_POWERED_DESCENT_FULL_AUDIT", "1");
    }
    if let Some(path) = trusted_setup_blob.as_ref() {
        command
            .env(GROTH16_SETUP_BLOB_PATH_ENV, path)
            .env(POWERED_DESCENT_PRODUCTION_ENV, "1");
    }
    if let Some(path) = trusted_setup_manifest.as_ref() {
        command
            .env(POWERED_DESCENT_TRUSTED_SETUP_MANIFEST_ENV, path)
            .env(POWERED_DESCENT_PRODUCTION_ENV, "1");
    }

    let status = command
        .status()
        .map_err(|error| format!("failed to launch powered descent exporter: {error}"))?;
    if !status.success() {
        return Err(format!(
            "powered descent exporter failed via `cargo run -p zkf-lib --example {example_name}`"
        ));
    }

    println!(
        "powered descent bundle exported to {} (steps={}, circuit=private_powered_descent_showcase_{}_step, full_audit={}, bundle_mode={}, trusted_setup={})",
        out.display(),
        request.public.step_count,
        request.public.step_count,
        full_audit,
        bundle_mode,
        trusted_setup_blob.is_some()
    );
    Ok(())
}

pub(crate) fn handle_app(command: AppCommands) -> Result<(), String> {
    match command {
        AppCommands::Init {
            name,
            name_positional,
            template,
            template_arg,
            style,
            out,
        } => {
            let name = name
                .or(name_positional)
                .ok_or_else(|| "app init requires a name".to_string())?;
            let template_args = parse_template_args(&template_arg)?;
            let style = AppStyle::parse(&style)?;
            let path = scaffold_app(&name, &template, &template_args, style, out)?;
            println!(
                "app scaffold created: template={} style={} -> {}",
                template,
                style.as_str(),
                path.display()
            );
            Ok(())
        }
        AppCommands::Gallery => {
            println!("{}", render_gallery());
            Ok(())
        }
        AppCommands::Templates { json } => {
            println!("{}", render_templates(json)?);
            Ok(())
        }
        AppCommands::PoweredDescent {
            inputs,
            out,
            full_audit,
            bundle_mode,
            trusted_setup_blob,
            trusted_setup_manifest,
        } => handle_powered_descent(
            inputs,
            out,
            full_audit,
            bundle_mode,
            trusted_setup_blob,
            trusted_setup_manifest,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scaffold_creates_expected_files_for_all_styles() {
        let temp = tempfile::tempdir().expect("tempdir");

        for (style, needs_dashboard) in [
            (AppStyle::Minimal, false),
            (AppStyle::Colored, false),
            (AppStyle::Tui, true),
        ] {
            let root = scaffold_app(
                &format!("dx-smoke-{}", style.as_str()),
                "range-proof",
                &BTreeMap::new(),
                style,
                Some(temp.path().join(format!("dx-smoke-{}", style.as_str()))),
            )
            .expect("scaffold");

            for path in [
                root.join("Cargo.toml"),
                root.join("src/spec.rs"),
                root.join("src/main.rs"),
                root.join("tests/smoke.rs"),
                root.join("zirapp.json"),
                root.join("inputs.compliant.json"),
                root.join("inputs.violation.json"),
                root.join("README.md"),
            ] {
                assert!(path.exists(), "missing scaffold file {}", path.display());
            }
            if needs_dashboard {
                assert!(root.join("src/dashboard.rs").exists());
            }

            let cargo_toml =
                std::fs::read_to_string(root.join("Cargo.toml")).expect("cargo toml should exist");
            assert!(cargo_toml.contains("[workspace]"));
            assert!(cargo_toml.contains(&repo_root().join("zkf-lib").display().to_string()));
            match style {
                AppStyle::Minimal => {
                    assert!(!cargo_toml.contains("zkf-ui"));
                    assert!(!cargo_toml.contains("zkf-tui"));
                }
                AppStyle::Colored => {
                    assert!(cargo_toml.contains("zkf-ui"));
                    assert!(!cargo_toml.contains("zkf-tui"));
                }
                AppStyle::Tui => {
                    assert!(cargo_toml.contains("zkf-ui"));
                    assert!(cargo_toml.contains("zkf-tui"));
                }
            }
        }
    }

    #[test]
    fn gallery_output_lists_all_styles_and_commands() {
        let gallery = render_gallery();
        assert!(gallery.contains("Minimal Style"));
        assert!(gallery.contains("Colored Style"));
        assert!(gallery.contains("TUI Style"));
        assert!(gallery.contains("--style minimal"));
        assert!(gallery.contains("--style colored"));
        assert!(gallery.contains("--style tui"));
        assert!(gallery.contains("aegisvault"));
    }

    #[test]
    fn scaffolded_apps_run_smoke_tests_outside_workspace() {
        let temp = tempfile::tempdir().expect("tempdir");
        for style in [AppStyle::Minimal, AppStyle::Colored, AppStyle::Tui] {
            let root = scaffold_app(
                &format!("poseidon-{}", style.as_str()),
                "range-proof",
                &BTreeMap::new(),
                style,
                Some(temp.path().join(format!("poseidon-{}", style.as_str()))),
            )
            .expect("scaffold");

            let status = std::process::Command::new("cargo")
                .arg("test")
                .arg("--manifest-path")
                .arg(root.join("Cargo.toml"))
                .arg("--quiet")
                .status()
                .expect("cargo test should run");

            assert!(
                status.success(),
                "generated app smoke test failed for style={}",
                style.as_str()
            );
        }
    }

    #[test]
    fn template_registry_renders_json_and_text() {
        let text = render_templates(false).expect("text templates");
        assert!(text.contains("poseidon-commitment"));
        assert!(text.contains("private-vote"));

        let json = render_templates(true).expect("json templates");
        assert!(json.contains("\"private-identity\""));
    }
}
