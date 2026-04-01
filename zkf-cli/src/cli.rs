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

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "zkf")]
#[command(about = "ZirOS CLI (formerly ZKF): proving, wrapping, certification, and monitoring")]
pub(crate) struct Cli {
    #[arg(long, global = true)]
    pub(crate) allow_compat: bool,
    #[command(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Scaffold a standalone application that embeds `zkf-lib`.
    App {
        #[command(subcommand)]
        command: AppCommands,
    },
    /// Operate black-box subsystem bundles and validate their closure contract.
    Subsystem {
        #[command(subcommand)]
        command: SubsystemCommands,
    },
    /// Operate Midnight-compatible proof-server and integration surfaces.
    Midnight {
        #[command(subcommand)]
        command: MidnightCommands,
    },
    /// Issue and prove private-identity credentials.
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },
    /// List supported backends, fields, and framework capabilities.
    Capabilities {
        #[arg(long)]
        json: bool,
    },
    /// List available ZK frontends (Noir, Circom, Cairo, Halo2, etc.) and their status.
    Frontends {
        #[arg(long)]
        json: bool,
    },
    /// Emit the repo support matrix from live backend/frontend/gadget metadata.
    SupportMatrix {
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Check system health: toolchains, backends, UMPG routing, GPU readiness, and dependencies.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Diagnose Metal GPU acceleration and strict production readiness for the certified host lane.
    MetalDoctor {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        strict: bool,
    },
    /// Import a ZK circuit from a frontend (Noir, Circom, etc.) into the ZKF IR format.
    Import {
        #[arg(long, default_value = "noir")]
        frontend: String,
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        field: Option<String>,
        #[arg(long, default_value = "auto")]
        ir_family: String,
        #[arg(long)]
        allow_unsupported_version: bool,
        #[arg(long)]
        package_out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect a frontend artifact without importing: show signals, constraints, and metadata.
    Inspect {
        #[arg(long, default_value = "auto")]
        frontend: String,
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show native ZKF IR circuit structure and debugging summaries.
    Circuit {
        #[command(subcommand)]
        command: CircuitCommands,
    },
    /// Import a raw ACIR bytecode file directly into the ZKF IR format.
    #[command(name = "import-acir")]
    ImportAcir {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        field: Option<String>,
        #[arg(long, default_value = "auto")]
        ir_family: String,
        #[arg(long)]
        package_out: Option<PathBuf>,
    },
    /// Emit a sample ZKF IR program for testing and experimentation.
    EmitExample {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        field: Option<String>,
    },
    /// Compile a ZKF IR program for a specific backend (Groth16, Halo2, Plonky3, etc.).
    Compile {
        #[arg(long)]
        program: Option<PathBuf>,
        #[arg(long, conflicts_with = "program")]
        spec: Option<PathBuf>,
        #[arg(long)]
        backend: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        seed: Option<String>,
        #[arg(long)]
        groth16_setup_blob: Option<PathBuf>,
        #[arg(long)]
        allow_dev_deterministic_groth16: bool,
    },
    /// Generate a witness from a program and input values.
    Witness {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Optimize a ZKF IR program: constant folding, dead signal elimination, and constraint reduction.
    Optimize {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Generate a machine-verifiable audit report for a ZKF program.
    Audit {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Run the backend conformance suite and report compile/prove/verify results.
    Conformance {
        #[arg(long)]
        backend: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        export_json: Option<PathBuf>,
        #[arg(long)]
        export_cbor: Option<PathBuf>,
    },
    /// Run the end-to-end demo pipeline.
    Demo {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Run the same program across multiple backends and compare public outputs.
    Equivalence {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long, value_delimiter = ',')]
        backends: Vec<String>,
        #[arg(long)]
        seed: Option<String>,
        #[arg(long)]
        groth16_setup_blob: Option<PathBuf>,
        #[arg(long)]
        allow_dev_deterministic_groth16: bool,
        #[arg(long)]
        json: bool,
    },
    /// Validate, normalize, and type-check program-family IR artifacts.
    Ir {
        #[command(subcommand)]
        command: IrCommands,
    },
    /// Run a package manifest: solve the witness and check all constraints.
    Run {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long)]
        solver: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Debug a program: step through constraints, report first failure, and dump diagnostics.
    Debug {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        continue_on_failure: bool,
        #[arg(long)]
        poseidon_trace: bool,
        #[arg(long)]
        solver: Option<String>,
    },
    /// Generate a ZK proof through UMPG: compile, solve witness, and prove in one step.
    Prove {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long, default_value = "fastest-prove")]
        objective: String,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        export: Option<String>,
        /// Allow export wrappers that produce attestation-level proofs.
        #[arg(long)]
        allow_attestation: bool,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        compiled_out: Option<PathBuf>,
        #[arg(long)]
        solver: Option<String>,
        #[arg(long)]
        seed: Option<String>,
        #[arg(long)]
        groth16_setup_blob: Option<PathBuf>,
        #[arg(long)]
        allow_dev_deterministic_groth16: bool,
        /// Produce a hybrid artifact: Plonky3 STARK companion leg plus Groth16 wrapped primary leg.
        #[arg(long)]
        hybrid: bool,
        /// Route proving through the distributed cluster coordinator.
        #[arg(long)]
        distributed: bool,
    },
    /// Verify a ZK proof artifact against its source program.
    Verify {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        backend: String,
        #[arg(long)]
        compiled: Option<PathBuf>,
        #[arg(long)]
        seed: Option<String>,
        #[arg(long)]
        groth16_setup_blob: Option<PathBuf>,
        #[arg(long)]
        allow_dev_deterministic_groth16: bool,
        /// Require AND-verification of hybrid proof bundles when present.
        #[arg(long)]
        hybrid: bool,
    },
    /// Wrap a Plonky3 STARK proof into a Groth16 proof through UMPG.
    Wrap {
        /// Path to the Plonky3 proof artifact JSON.
        #[arg(long)]
        proof: PathBuf,
        /// Path to the Plonky3 compiled program JSON.
        #[arg(long)]
        compiled: PathBuf,
        /// Certified hardware profile for production wrapper execution.
        #[arg(long)]
        hardware_profile: Option<String>,
        /// Allow attestation-level wrapped proofs when a cryptographic wrap is not feasible.
        #[arg(long)]
        allow_attestation: bool,
        /// Force the Nova-compressed wrapping path instead of direct FRI wrapping.
        #[arg(long)]
        compress: bool,
        /// Preview the wrap strategy and exit without proving.
        #[arg(long)]
        dry_run: bool,
        /// Output path for the wrapped Groth16 proof.
        #[arg(long)]
        out: PathBuf,
        /// Optional path to write a structured runtime trace JSON for the wrap.
        #[arg(long)]
        trace_out: Option<PathBuf>,
    },
    /// Run proof performance benchmarks across backends and constraint sizes.
    Benchmark {
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        markdown_out: Option<PathBuf>,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long, value_delimiter = ',')]
        backends: Option<Vec<String>>,
        #[arg(long, default_value_t = 1)]
        iterations: usize,
        #[arg(long)]
        skip_large: bool,
        #[arg(long)]
        continue_on_error: bool,
        #[arg(long)]
        parallel: bool,
        /// Include distributed cluster telemetry in benchmark output.
        #[arg(long)]
        distributed: bool,
    },
    /// Estimate on-chain gas cost for verifying a proof on Ethereum.
    EstimateGas {
        #[arg(long)]
        backend: String,
        #[arg(long)]
        artifact: Option<PathBuf>,
        #[arg(long)]
        proof_size: Option<usize>,
        #[arg(long, default_value = "ethereum")]
        evm_target: String,
        #[arg(long)]
        json: bool,
    },
    /// Incrementally fold multiple proof steps using Nova/HyperNova IVC.
    Fold {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long, default_value_t = 1)]
        steps: usize,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long, default_value = "fastest-prove")]
        objective: String,
        #[arg(long)]
        solver: Option<String>,
        /// Step chaining mode. `chain-public-outputs` copies public outputs back
        /// into the next step by signal position. For Nova recursive state
        /// handoff, declare `nova_ivc_in` and `nova_ivc_out` metadata instead.
        #[arg(long)]
        step_mode: Option<String>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        seed: Option<String>,
    },
    /// Multi-node distributed proving cluster management.
    Cluster {
        #[command(subcommand)]
        command: ClusterCommands,
    },
    /// Swarm defense identity, builder rules, and reputation controls.
    Swarm {
        #[command(subcommand)]
        command: SwarmCommands,
    },
    /// iCloud-native persistent storage and local cache management.
    Storage {
        #[command(subcommand)]
        command: StorageCommands,
    },
    /// iCloud Keychain-backed private key management.
    Keys {
        #[command(subcommand)]
        command: KeysCommands,
    },
    /// Retrain the Neural Engine control-plane models from telemetry and publish a fresh bundle.
    Retrain {
        #[arg(long, action = clap::ArgAction::Append)]
        input: Vec<String>,
        #[arg(long, default_value = "production")]
        profile: String,
        #[arg(long)]
        model_dir: Option<PathBuf>,
        #[arg(long)]
        corpus_out: Option<PathBuf>,
        #[arg(long)]
        summary_out: Option<PathBuf>,
        #[arg(long)]
        manifest_out: Option<PathBuf>,
        #[arg(long)]
        threshold_out: Option<PathBuf>,
        #[arg(long)]
        skip_threshold_optimizer: bool,
        #[arg(long)]
        json: bool,
    },
    /// Inspect telemetry corpus state and tooling metadata.
    Telemetry {
        #[command(subcommand)]
        command: TelemetryCommands,
    },
    /// Unified Memory Prover Graph (UMPG) planning, execution, certification, and policy tools.
    Runtime {
        #[command(subcommand)]
        command: RuntimeCommands,
    },
    /// Package workflows routed through UMPG: compile, prove, verify, aggregate, and compose within a manifest.
    Package {
        #[command(subcommand)]
        command: PackageCommands,
    },
    /// Generate a Solidity verifier contract from a cryptographic proof artifact.
    Deploy {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        backend: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        contract_name: Option<String>,
        #[arg(long, default_value = "ethereum")]
        evm_target: String,
        #[arg(long)]
        json: bool,
    },
    /// Inspect proof internals: proof size, public inputs, VK hash, etc.
    Explore {
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        backend: String,
        #[arg(long)]
        json: bool,
    },
    /// Manage gadget registry.
    Registry {
        #[command(subcommand)]
        command: RegistryCommands,
    },
    /// Run test vectors across backends and compare runtime results.
    #[command(name = "test-vectors")]
    TestVectors {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        vectors: PathBuf,
        #[arg(long, value_delimiter = ',')]
        backends: Option<Vec<String>>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum RegistryCommands {
    /// Add a gadget from the registry.
    Add {
        #[arg()]
        gadget: String,
    },
    /// List available gadgets.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Publish a gadget to the local registry.
    Publish {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        content: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum AppCommands {
    /// Create a standalone Rust app wired to this local ZirOS checkout.
    Init {
        #[arg(long, conflicts_with = "name_positional")]
        name: Option<String>,
        #[arg(value_name = "NAME", required_unless_present = "name")]
        name_positional: Option<String>,
        #[arg(long, default_value = "range-proof")]
        template: String,
        #[arg(long = "template-arg")]
        template_arg: Vec<String>,
        #[arg(long, default_value = "auto")]
        style: String,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Show the available standalone app scaffold styles.
    Gallery,
    /// List scaffoldable declarative app templates.
    Templates {
        #[arg(long)]
        json: bool,
    },
    /// Run the private powered descent showcase exporter from a JSON request bundle.
    #[command(name = "powered-descent")]
    PoweredDescent {
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        full_audit: bool,
        #[arg(long, default_value = "debug")]
        bundle_mode: String,
        #[arg(long)]
        trusted_setup_blob: Option<PathBuf>,
        #[arg(long)]
        trusted_setup_manifest: Option<PathBuf>,
    },
    /// Operate the theorem-first reentry mission-assurance surface.
    #[command(
        name = "reentry-assurance",
        about = "Theorem-first reentry mission assurance for ground-side mission operations. Targets NASA Class D, uses normalized-export-based ingestion, and does not natively replace GMAT, SPICE, Dymos/OpenMDAO, Trick/JEOD, Basilisk, cFS, or F Prime."
    )]
    ReentryAssurance(ReentryAssuranceArgs),
    /// Operate the sovereign economic defense theorem surface.
    #[command(
        name = "sovereign-economic-defense",
        about = "Run the five-circuit sovereign economic defense app powered by ZirOS: cooperative treasury assurance, community land trust governance, anti-extraction shield, wealth trajectory assurance, and recirculation sovereignty scoring."
    )]
    SovereignEconomicDefense(SovereignEconomicDefenseArgs),
    /// Operate the aerospace qualification, digital thread, and flight-readiness exchange.
    #[command(
        name = "aerospace-qualification",
        about = "Run the six-circuit aerospace qualification subsystem powered by ZirOS with Midnight governance: thermal qualification, vibration/shock qualification, lot genealogy, firmware provenance, test campaign compliance, and flight-readiness assembly."
    )]
    AerospaceQualification(AerospaceQualificationArgs),
}

#[derive(Debug, Subcommand)]
pub(crate) enum SubsystemCommands {
    /// Verify that a subsystem bundle is complete against the canonical 20-slot contract.
    #[command(name = "verify-completeness")]
    VerifyCompleteness {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify the pinned zkf binary checksum and signature carried by a subsystem bundle.
    #[command(name = "verify-release-pin")]
    VerifyReleasePin {
        #[arg(long)]
        pin: PathBuf,
        #[arg(long)]
        binary: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum MidnightCommands {
    /// Run the Midnight proof-server compatibility surface on port 6300.
    #[command(name = "proof-server")]
    ProofServer {
        #[command(subcommand)]
        command: MidnightProofServerCommands,
    },
    /// Serve the Midnight Compact admission gateway on port 6311.
    #[command(name = "gateway")]
    Gateway {
        #[command(subcommand)]
        command: MidnightGatewayCommands,
    },
    /// List the built-in ZirOS Midnight DApp templates.
    #[command(name = "templates")]
    Templates {
        #[arg(long)]
        json: bool,
    },
    /// Generate a pinned Midnight DApp project from a verified template.
    #[command(name = "init")]
    Init {
        #[arg(long)]
        name: String,
        #[arg(long)]
        template: String,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long, default_value = "preprod")]
        network: String,
    },
    /// Diagnose Midnight-specific toolchain, package, wallet, and network readiness.
    #[command(name = "doctor")]
    Doctor {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        strict: bool,
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long, default_value = "preprod")]
        network: String,
        #[arg(long)]
        proof_server_url: Option<String>,
        #[arg(long)]
        gateway_url: Option<String>,
        #[arg(long, conflicts_with = "no_browser_check")]
        browser_check: bool,
        #[arg(long, conflicts_with = "browser_check")]
        no_browser_check: bool,
        #[arg(long)]
        require_wallet: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum MidnightProofServerCommands {
    /// Serve the official Midnight proof-server wire contract through the ZirOS CLI.
    Serve {
        #[arg(
            short,
            long,
            default_value_t = 6300,
            env = "MIDNIGHT_PROOF_SERVER_PORT"
        )]
        port: u16,
        #[arg(long, default_value_t = 0, env = "MIDNIGHT_PROOF_SERVER_JOB_CAPACITY")]
        job_capacity: usize,
        #[arg(long, default_value_t = 2, env = "MIDNIGHT_PROOF_SERVER_NUM_WORKERS")]
        num_workers: usize,
        #[arg(long, default_value = "umpg", env = "MIDNIGHT_PROOF_SERVER_ENGINE")]
        engine: String,
        #[arg(
            long,
            default_value_t = 600.0,
            env = "MIDNIGHT_PROOF_SERVER_JOB_TIMEOUT"
        )]
        job_timeout: f64,
        #[arg(
            long,
            default_value_t = false,
            env = "MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS"
        )]
        no_fetch_params: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum MidnightGatewayCommands {
    /// Serve the verified-admission Compact gateway.
    Serve {
        #[arg(short, long, default_value_t = 6311, env = "MIDNIGHT_GATEWAY_PORT")]
        port: u16,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Args)]
pub(crate) struct AerospaceQualificationArgs {
    #[command(subcommand)]
    pub(crate) command: AerospaceQualificationCommands,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum AerospaceQualificationCircuitSelector {
    One,
    Two,
    Three,
    Four,
    Five,
    Six,
    All,
}

impl std::str::FromStr for AerospaceQualificationCircuitSelector {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "1" | "one" | "thermal" => Ok(Self::One),
            "2" | "two" | "vibration" => Ok(Self::Two),
            "3" | "three" | "genealogy" => Ok(Self::Three),
            "4" | "four" | "firmware" => Ok(Self::Four),
            "5" | "five" | "campaign" => Ok(Self::Five),
            "6" | "six" | "readiness" => Ok(Self::Six),
            "all" => Ok(Self::All),
            _ => Err(format!("unknown circuit selector: {value}")),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum AerospaceQualificationCommands {
    /// Prove one circuit or the full six-circuit aerospace qualification bundle.
    Prove {
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "all")]
        circuit: AerospaceQualificationCircuitSelector,
        #[arg(long)]
        groth16_setup_blob: Option<PathBuf>,
        #[arg(long)]
        allow_dev_deterministic_groth16: bool,
        #[arg(long, default_value = "ethereum")]
        evm_target: String,
        #[arg(long)]
        seed: Option<String>,
    },
    /// Verify an existing aerospace qualification bundle.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Render the mission report from an existing bundle.
    Report {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Export a release-safe bundle.
    #[command(name = "export-bundle")]
    ExportBundle {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Args)]
#[command(subcommand_negates_reqs = true)]
#[command(
    about = "Theorem-first reentry mission assurance for ground-side mission operations. Targets NASA Class D, uses normalized-export-based ingestion, and does not natively replace GMAT, SPICE, Dymos/OpenMDAO, Trick/JEOD, Basilisk, cFS, or F Prime."
)]
pub(crate) struct ReentryAssuranceArgs {
    #[command(subcommand)]
    pub(crate) command: Option<ReentryAssuranceCommands>,
    #[arg(long, required = true)]
    pub(crate) inputs: Option<PathBuf>,
    #[arg(long, required = true)]
    pub(crate) out: Option<PathBuf>,
    #[arg(long)]
    pub(crate) production: bool,
}

#[derive(Debug, Subcommand)]
pub(crate) enum ReentryAssuranceCommands {
    /// Sign a reentry mission pack v2 with a hybrid Ed25519 + ML-DSA-44 signer bundle.
    #[command(name = "sign-pack")]
    SignPack {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        signer_key: PathBuf,
        #[arg(long = "source-model-manifest")]
        source_model_manifests: Vec<PathBuf>,
        #[arg(long)]
        derived_model_package: Option<PathBuf>,
        #[arg(long)]
        scenario_library_manifest: Option<PathBuf>,
        #[arg(long)]
        assurance_trace_matrix: Option<PathBuf>,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        not_before_unix_epoch_seconds: u64,
        #[arg(long)]
        not_after_unix_epoch_seconds: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// Validate a signed reentry mission pack against the pinned signer manifest.
    #[command(name = "validate-pack")]
    ValidatePack {
        #[arg(long)]
        signed_pack: PathBuf,
        #[arg(long)]
        signer_manifest: PathBuf,
        #[arg(long)]
        unix_time: Option<u64>,
    },
    /// Prove a signed reentry mission pack against the accepted Plonky3 theorem lane.
    Prove {
        #[arg(long)]
        signed_pack: PathBuf,
        #[arg(long)]
        signer_manifest: PathBuf,
        #[arg(long = "source-model-manifest")]
        source_model_manifests: Vec<PathBuf>,
        #[arg(long)]
        derived_model_package: Option<PathBuf>,
        #[arg(long)]
        scenario_library_manifest: Option<PathBuf>,
        #[arg(long)]
        assurance_trace_matrix: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        unix_time: Option<u64>,
    },
    /// Verify an existing reentry mission-assurance bundle without regenerating the proof.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Render the operator-facing Markdown report from an existing reentry bundle.
    Report {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Export a release-safe reentry assurance bundle.
    #[command(name = "export-bundle")]
    ExportBundle {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        include_private: bool,
    },
    /// Ingest a normalized GMAT export into a pinned source model manifest.
    #[command(name = "ingest-gmat")]
    IngestGmat {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Ingest a normalized SPICE export into a pinned source model manifest.
    #[command(name = "ingest-spice")]
    IngestSpice {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Ingest a normalized OpenMDAO/Dymos export into a pinned source model manifest.
    #[command(name = "ingest-openmdao")]
    IngestOpenMdao {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Ingest a normalized Trick/JEOD or Basilisk export into a pinned source model manifest.
    #[command(name = "ingest-trick")]
    IngestTrick {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Derive a proof-safe reduced-order model package and mission pack from pinned upstream manifests.
    #[command(name = "derive-model")]
    DeriveModel {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Qualify a derived model package against a scenario library and emit the assurance trace matrix.
    #[command(name = "qualify-model")]
    QualifyModel {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        scenario_library: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Publish annex-only operational evidence such as Metal Doctor, runtime policy, telemetry, and security outputs.
    #[command(name = "publish-annex")]
    PublishAnnex {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        metal_doctor: Option<PathBuf>,
        #[arg(long)]
        runtime_policy: Option<PathBuf>,
        #[arg(long)]
        telemetry: Option<PathBuf>,
        #[arg(long)]
        security: Option<PathBuf>,
    },
    /// Build an Open MCT-facing dashboard configuration from a reentry assurance bundle and annex.
    #[command(name = "build-dashboard")]
    BuildDashboard {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        annex: Option<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Export a downstream cFS handoff bundle with receipt, proof, and operator metadata.
    #[command(name = "handoff-cfs")]
    HandoffCfs {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Export a downstream F Prime handoff bundle with receipt, proof, and operator metadata.
    #[command(name = "handoff-fprime")]
    HandoffFprime {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Args)]
pub(crate) struct SovereignEconomicDefenseArgs {
    #[command(subcommand)]
    pub(crate) command: SovereignEconomicDefenseCommands,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SovereignEconomicDefenseCircuitSelector {
    One,
    Two,
    Three,
    Four,
    Five,
    All,
}

impl std::str::FromStr for SovereignEconomicDefenseCircuitSelector {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "1" | "one" | "cooperative-treasury-assurance" | "cooperative-treasury" => {
                Ok(Self::One)
            }
            "2" | "two" | "community-land-trust-governance" | "community-land-trust" => {
                Ok(Self::Two)
            }
            "3" | "three" | "anti-extraction-shield" | "anti-extraction" => Ok(Self::Three),
            "4" | "four" | "wealth-trajectory-assurance" | "wealth-trajectory" => Ok(Self::Four),
            "5" | "five" | "recirculation-sovereignty-score" | "recirculation" => Ok(Self::Five),
            "all" => Ok(Self::All),
            other => Err(format!(
                "unknown sovereign economic defense circuit selector '{other}' (expected 1, 2, 3, 4, 5, or all)"
            )),
        }
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum SovereignEconomicDefenseCommands {
    /// Prove one circuit or the full five-circuit sovereign economic defense bundle.
    Prove {
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "all")]
        circuit: SovereignEconomicDefenseCircuitSelector,
        #[arg(long)]
        groth16_setup_blob: Option<PathBuf>,
        #[arg(long)]
        allow_dev_deterministic_groth16: bool,
        #[arg(long, default_value = "ethereum")]
        evm_target: String,
        /// Allow attestation-level wrapped proofs for STARK circuits.
        /// When combined with wrapping, the app may emit `wrapped-v3` Nova-compressed
        /// Groth16 artifacts whose trust model remains attestation, not strict cryptographic.
        #[arg(long)]
        allow_attestation: bool,
        /// Force the Nova-compressed wrapper path instead of direct FRI wrapping.
        #[arg(long)]
        compress: bool,
        /// Retained for CLI stability. The repo-constrained sovereign economic defense bundle
        /// omits STARK-to-Groth16 wrapping either way and ships STARK proofs as the primary
        /// deliverable. Circuit 3 remains the native BN254 Groth16 on-chain lane.
        #[arg(long)]
        no_wrap: bool,
    },
    /// Verify an existing sovereign economic defense bundle.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Regenerate the operator report from an existing sovereign economic defense bundle.
    Report {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Export a release-safe sovereign economic defense bundle.
    #[command(name = "export-bundle")]
    ExportBundle {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        include_private: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum CredentialCommands {
    /// Issue a signed private-identity credential and update the local registries.
    Issue {
        #[arg(long)]
        secret: String,
        #[arg(long)]
        salt: String,
        #[arg(long)]
        age_years: u8,
        #[arg(long)]
        status_flags: u32,
        #[arg(long)]
        expires_at_epoch_day: u32,
        #[arg(long)]
        issuer_registry: PathBuf,
        #[arg(long)]
        active_registry: PathBuf,
        #[arg(long)]
        issuer_key: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 0)]
        slot: usize,
    },
    /// Prove policy compliance for a signed private-identity credential.
    Prove {
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        salt: String,
        #[arg(long)]
        issuer_registry: PathBuf,
        #[arg(long)]
        active_registry: PathBuf,
        #[arg(long)]
        required_age: u8,
        #[arg(long)]
        required_status_mask: u32,
        #[arg(long)]
        current_epoch_day: u32,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        groth16_setup_blob: Option<PathBuf>,
        #[arg(long)]
        allow_dev_deterministic_groth16: bool,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        compiled_out: Option<PathBuf>,
    },
    /// Verify a private-identity proof artifact and its attached signed credential.
    Verify {
        #[arg(long)]
        artifact: PathBuf,
        #[arg(long)]
        issuer_root: Option<String>,
        #[arg(long)]
        active_root: Option<String>,
        #[arg(long)]
        required_age: Option<u8>,
        #[arg(long)]
        required_status_mask: Option<u32>,
        #[arg(long)]
        current_epoch_day: Option<u32>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum CircuitCommands {
    /// Show a native IR program summary, assignments, and optional witness flow.
    Show {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        show_assignments: bool,
        #[arg(long)]
        show_flow: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum IrCommands {
    /// Parse a ZKF program and report schema/type validity.
    Validate {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Normalize a ZKF program and write the normalized result.
    Normalize {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Type-check a ZKF program.
    #[command(name = "type-check")]
    TypeCheck {
        #[arg(long)]
        program: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum RuntimeCommands {
    /// Build a UMPG prover graph plan for a generic backend job or wrapper job.
    Plan {
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        constraints: Option<usize>,
        #[arg(long)]
        field: Option<String>,
        /// Source program for a replayable generic runtime plan.
        #[arg(long)]
        program: Option<std::path::PathBuf>,
        /// Witness inputs for a replayable generic runtime plan.
        #[arg(long)]
        inputs: Option<std::path::PathBuf>,
        #[arg(long)]
        trust: Option<String>,
        #[arg(long)]
        hardware_profile: Option<String>,
        /// Optional proof artifact to plan a wrapper job instead of a generic backend job.
        #[arg(long)]
        proof: Option<std::path::PathBuf>,
        /// Compiled program for the source proof when planning a wrapper job.
        #[arg(long)]
        compiled: Option<std::path::PathBuf>,
        #[arg(long)]
        output: Option<std::path::PathBuf>,
    },
    /// Prepare strict wrapper caches and direct-wrap bundles without generating a wrapped proof.
    Prepare {
        #[arg(long)]
        proof: std::path::PathBuf,
        #[arg(long)]
        compiled: std::path::PathBuf,
        #[arg(long)]
        trust: Option<String>,
        #[arg(long)]
        hardware_profile: Option<String>,
        /// Allow large direct strict-cache materialization on the certified host.
        #[arg(long)]
        allow_large_direct_materialization: bool,
        /// Install a prepared direct-wrap cache bundle for this proof/compiled pair.
        #[arg(long)]
        install_bundle: Option<std::path::PathBuf>,
        /// Export the current ready direct-wrap cache into a portable bundle directory.
        #[arg(long)]
        export_bundle: Option<std::path::PathBuf>,
        #[arg(long)]
        output: Option<std::path::PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Execute a UMPG prover graph plan or direct generic/wrapper runtime job.
    Execute {
        #[arg(long)]
        plan: Option<std::path::PathBuf>,
        /// Backend for a direct generic runtime execution.
        #[arg(long)]
        backend: Option<String>,
        /// Source program for a direct generic runtime execution.
        #[arg(long)]
        program: Option<std::path::PathBuf>,
        /// Witness inputs for a direct generic runtime execution.
        #[arg(long)]
        inputs: Option<std::path::PathBuf>,
        #[arg(long)]
        witness: Option<std::path::PathBuf>,
        /// Output path for a wrapped proof when executing a wrapper runtime job.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
        /// Optional proof artifact to execute a wrapper runtime plan directly.
        #[arg(long)]
        proof: Option<std::path::PathBuf>,
        /// Compiled program for the source proof when executing a wrapper runtime plan directly.
        #[arg(long)]
        compiled: Option<std::path::PathBuf>,
        #[arg(long)]
        trust: Option<String>,
        #[arg(long)]
        hardware_profile: Option<String>,
        #[arg(long)]
        trace: Option<std::path::PathBuf>,
    },
    /// Display or validate the UMPG execution trace embedded in a proof artifact.
    Trace {
        #[arg(long)]
        proof: std::path::PathBuf,
        /// Optional runtime plan to verify against runtime provenance metadata embedded in the proof.
        #[arg(long)]
        plan: Option<std::path::PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Run gate or soak certification for the strict certified M4 Max production lane.
    Certify {
        #[arg(long)]
        mode: String,
        #[arg(long)]
        proof: std::path::PathBuf,
        #[arg(long)]
        compiled: std::path::PathBuf,
        #[arg(long)]
        out_dir: Option<std::path::PathBuf>,
        #[arg(long)]
        json_out: Option<std::path::PathBuf>,
        #[arg(long, default_value = "auto")]
        parallel_jobs: String,
        #[arg(long, default_value_t = 12)]
        hours: u64,
        #[arg(long, default_value_t = 20)]
        cycles: usize,
    },
    /// Evaluate the local ANE/Core ML control-plane policy for routing and scheduler decisions.
    Policy {
        /// Optional runtime trace JSON to use as policy features.
        #[arg(long)]
        trace: Option<std::path::PathBuf>,
        /// Optional field hint for backend recommendation.
        #[arg(long)]
        field: Option<String>,
        /// Optional comma-separated backend candidates.
        #[arg(long)]
        backends: Option<String>,
        /// Backend selection objective for auto recommendation.
        #[arg(long, default_value = "fastest-prove")]
        objective: String,
        /// Estimated constraint count for scheduler recommendation.
        #[arg(long)]
        constraints: Option<usize>,
        /// Estimated signal count for scheduler recommendation.
        #[arg(long)]
        signals: Option<usize>,
        /// Requested parallel jobs before policy adjustment.
        #[arg(long)]
        requested_jobs: Option<usize>,
        /// Total jobs available in the batch.
        #[arg(long)]
        total_jobs: Option<usize>,
        /// Optional Core ML model (.mlpackage, .mlmodel, or .mlmodelc).
        #[arg(long)]
        model: Option<std::path::PathBuf>,
        /// Core ML compute units: all, cpu-and-neural-engine, or cpu-only.
        #[arg(long, default_value = "cpu-and-neural-engine")]
        compute_units: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum TelemetryCommands {
    /// Summarize the current telemetry corpus and its stable hash.
    Stats {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Export anonymized telemetry suitable for cross-device aggregation.
    Export {
        #[arg(long, action = clap::ArgAction::Append)]
        input: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum PackageCommands {
    /// Migrate a package manifest between schema versions.
    Migrate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "2")]
        from: String,
        #[arg(long, default_value = "3")]
        to: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify a package manifest: check schema, signals, constraints, and run configurations.
    Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Compile a package program for a specific backend.
    Compile {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        backend: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        seed: Option<String>,
    },
    /// Prove a single package run configuration through UMPG.
    Prove {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long, default_value = "fastest-prove")]
        objective: String,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        seed: Option<String>,
        #[arg(long)]
        hybrid: bool,
    },
    /// Prove all package run configurations through UMPG across selected backends.
    #[command(name = "prove-all")]
    ProveAll {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, value_delimiter = ',')]
        backends: Option<Vec<String>>,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long)]
        parallel: bool,
        #[arg(long)]
        jobs: Option<usize>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        seed: Option<String>,
    },
    /// Verify a proof artifact against its package manifest and backend.
    #[command(name = "verify-proof")]
    VerifyProof {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        backend: String,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long)]
        solidity_verifier: Option<PathBuf>,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        seed: Option<String>,
        #[arg(long)]
        hybrid: bool,
    },
    /// Emit a metadata-binding bundle artifact across multiple package proofs.
    #[command(name = "bundle")]
    Bundle {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, value_delimiter = ',')]
        backends: Option<Vec<String>>,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Verify a metadata-binding bundle artifact against its package manifest.
    #[command(name = "verify-bundle")]
    VerifyBundle {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Emit a cryptographic aggregate artifact across multiple same-backend package proofs.
    Aggregate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        backend: String,
        #[arg(long, value_delimiter = ',')]
        input_run_ids: Vec<String>,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long)]
        json: bool,
        /// Deprecated: cryptographic aggregation is now the only meaning of this command.
        #[arg(long)]
        crypto: bool,
    },
    /// Verify a cryptographic aggregate artifact against its package manifest.
    #[command(name = "verify-aggregate")]
    VerifyAggregate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        backend: String,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Compose package proofs into a proof-carrying digest-binding artifact.
    /// This verifies digest/linkage constraints in-circuit and treats
    /// `recursive_aggregation_marker` as a host-validated metadata marker,
    /// not as cryptographic recursive proof verification.
    Compose {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long, default_value = "nova")]
        backend: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        seed: Option<String>,
    },
    /// Verify a composed digest-binding proof against its package manifest.
    #[command(name = "verify-compose")]
    VerifyCompose {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "main")]
        run_id: String,
        #[arg(long, default_value = "nova")]
        backend: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        seed: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum ClusterCommands {
    /// Start this node as a distributed cluster worker (or coordinator).
    Start {
        #[arg(long)]
        json: bool,
    },
    /// Show discovered peers, their capabilities, and health status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Run a distributed benchmark across the cluster.
    Benchmark {
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum SwarmCommands {
    /// Show local swarm identity, rule, and reputation status.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Rotate the local swarm signing key.
    #[command(name = "rotate-key")]
    RotateKey {
        #[arg(long)]
        json: bool,
    },
    /// Force regeneration of the local swarm signing key.
    #[command(name = "regenerate-key")]
    RegenerateKey {
        #[arg(long)]
        force: bool,
        #[arg(long)]
        json: bool,
    },
    /// List persisted detection rules.
    #[command(name = "list-rules")]
    ListRules {
        #[arg(long)]
        json: bool,
    },
    /// Move a rule into shadow mode.
    #[command(name = "shadow-rule")]
    ShadowRule {
        #[arg()]
        rule_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Promote a rule to live mode.
    #[command(name = "promote-rule")]
    PromoteRule {
        #[arg()]
        rule_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Revoke a rule.
    #[command(name = "revoke-rule")]
    RevokeRule {
        #[arg()]
        rule_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the persisted history for one rule.
    #[command(name = "rule-history")]
    RuleHistory {
        #[arg()]
        rule_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Show the current peer reputation table.
    Reputation {
        #[arg()]
        peer_id: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Show the persisted reputation evidence log.
    #[command(name = "reputation-log")]
    ReputationLog {
        #[arg()]
        peer_id: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
    /// Verify the reputation evidence log is internally consistent.
    #[command(name = "reputation-verify")]
    ReputationVerify {
        #[arg()]
        peer_id: Option<String>,
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub(crate) enum StorageCommands {
    /// Show iCloud sync state, local cache usage, and key health.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// One-time migration from ~/.zkf to the iCloud-native ZirOS layout.
    #[command(name = "migrate-to-icloud")]
    MigrateToIcloud,
    /// Pre-fetch frequently used files into the local cache.
    Warm,
    /// Evict stale files from the local cache while leaving iCloud copies intact.
    Evict,
    /// Install the macOS cache-manager launch agent.
    Install,
}

#[derive(Debug, Subcommand)]
pub(crate) enum KeysCommands {
    /// List all private keys tracked through Keychain metadata.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Inspect a single key by id.
    Inspect {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Rotate a key in place and update its metadata.
    Rotate { id: String },
    /// Audit every tracked key for presence and sync health.
    Audit {
        #[arg(long)]
        json: bool,
    },
    /// Revoke a key from the backend and metadata index.
    Revoke {
        id: String,
        #[arg(long)]
        force: bool,
    },
}
