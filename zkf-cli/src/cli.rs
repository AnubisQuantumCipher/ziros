use clap::{Parser, Subcommand};
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
    /// Issue and prove private-identity credentials.
    Credential {
        #[command(subcommand)]
        command: CredentialCommands,
    },
    /// List supported backends, fields, and framework capabilities.
    Capabilities,
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
    /// SSD guardian: archive, purge, health, policy, and daemon management.
    Storage {
        #[command(subcommand)]
        command: StorageCommands,
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
        #[arg(long, default_value = "colored")]
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
pub(crate) enum StorageCommands {
    /// Report disk free state, cache usage, and recoverable storage.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Archive showcase artifacts and telemetry into the iCloud ZirOS archive.
    Archive {
        #[arg(long)]
        dry_run: bool,
    },
    /// Purge ephemeral artifacts such as debug caches and witness files.
    Purge {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        include_release: bool,
    },
    /// Archive then purge recoverable storage.
    Sweep {
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        auto: bool,
    },
    /// Monitor SSD health and trigger archive or sweep actions based on thresholds.
    Watch {
        #[arg(long, default_value = "3600")]
        interval: u64,
    },
    /// Restore an archived file to the local machine.
    Restore {
        #[arg()]
        path: PathBuf,
    },
    /// Emit structured SSD and storage-health diagnostics.
    Doctor {
        #[arg(long)]
        json: bool,
    },
    /// Show the effective retention policy and active storage profile.
    Policy {
        #[arg(long)]
        json: bool,
    },
    /// Install or remove the background launchd storage guardian agent.
    Install {
        #[arg(long)]
        uninstall: bool,
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
