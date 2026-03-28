pub mod dashboard;
pub mod proof_jobs;
pub mod reference_apps;
pub mod validation;
pub mod widgets;

pub use dashboard::{DashboardAction, DashboardState, ProofModalState, VaultEntry, ZkDashboard};
pub use proof_jobs::{
    DemoProofResult, ProofJobUpdate, run_local_proof_demo, run_local_proof_demo_with_backend,
    spawn_local_proof_job, spawn_local_proof_job_with_backend,
};
pub use reference_apps::{aegisvault_state, aegisvault_template, apply_reference_proof_update};
pub use validation::{
    TerminalProfile, TerminalValidationResult, render_dashboard_snapshot, resize_smoke_profiles,
    supported_terminal_profiles, validate_reference_dashboard, validate_reference_proof_demo,
};
