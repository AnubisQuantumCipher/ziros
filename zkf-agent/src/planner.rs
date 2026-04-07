use crate::types::{
    CapabilityRequirementV1, ExecutionPolicyV1, GoalIntentV1, IntentScopeV1,
    SuccessPredicateV1, TrustGateReportV1, WorkgraphNodeV1, WorkgraphV1,
    WorkflowRequirementsV1,
};
use zkf_command_surface::{RiskClassV1, new_operation_id};

pub fn workflow_catalog() -> Vec<GoalIntentV1> {
    vec![
        workflow(
            "subsystem-scaffold",
            IntentScopeV1::Project,
            "Scaffold or update a ZirOS subsystem bundle, then validate its completeness contract.",
            &[
                "02_manifest/subsystem_manifest.json",
                "17_report/report.md",
                "20_release/zkf-release-pin.json",
            ],
        ),
        workflow(
            "subsystem-proof",
            IntentScopeV1::Project,
            "Materialize a proof-bearing subsystem bundle and verify its closure surfaces.",
            &[
                "08_proofs/proof.json",
                "09_verification/verification.json",
                "10_audit/audit.json",
            ],
        ),
        workflow(
            "subsystem-midnight-ops",
            IntentScopeV1::Project,
            "Scaffold or reuse a subsystem bundle, then compile Compact contracts and prepare Midnight deployment artifacts.",
            &[
                "16_compact/contract.compact",
                "deploy-prepare.json",
                "20_release/zkf-release-pin.json",
            ],
        ),
        workflow(
            "subsystem-benchmark",
            IntentScopeV1::Project,
            "Run subsystem-oriented benchmark and Metal truth capture workflows.",
            &["benchmark-report.json"],
        ),
        workflow(
            "subsystem-evidence-release",
            IntentScopeV1::Release,
            "Validate a subsystem bundle and package its release/evidence artifacts.",
            &["evidence-bundle.json"],
        ),
        workflow(
            "proof-app-build",
            IntentScopeV1::Project,
            "Scaffold or update a ZirOS proof app, then compile, prove, and verify it.",
            &["zirapp.json", "proof.json", "verification.json"],
        ),
        workflow(
            "midnight-contract-ops",
            IntentScopeV1::Project,
            "Scaffold or reuse a Midnight project, compile a Compact contract, and prepare deploy artifacts.",
            &["contract.zkir", "deploy-prepare.json"],
        ),
        workflow(
            "midnight-proof-server-ops",
            IntentScopeV1::Host,
            "Inspect Midnight proof-server and gateway readiness on the current host.",
            &["midnight-status.json"],
        ),
        workflow(
            "benchmark-report",
            IntentScopeV1::Project,
            "Run a benchmark workflow with honest Metal truth capture.",
            &["benchmark-report.json"],
        ),
        workflow(
            "evidence-bundle",
            IntentScopeV1::Release,
            "Package session artifacts into a reusable evidence bundle.",
            &["evidence-bundle.json"],
        ),
        workflow(
            "host-readiness",
            IntentScopeV1::Host,
            "Inspect truth surfaces, capabilities, and readiness on the current ZirOS host.",
            &["truth-snapshot.json", "capabilities.json"],
        ),
        workflow(
            "generic-investigation",
            IntentScopeV1::Project,
            "Compile a generic investigative workgraph for operator review.",
            &["workgraph.json"],
        ),
    ]
}

pub fn compile_goal_intent(goal: &str, workflow_override: Option<&str>) -> GoalIntentV1 {
    if let Some(workflow_kind) = workflow_override {
        return workflow_from_kind(workflow_kind, goal);
    }

    let lower = goal.to_ascii_lowercase();
    if lower.contains("proof server") || lower.contains("gateway") {
        return workflow_from_kind("midnight-proof-server-ops", goal);
    }
    if lower.contains("subsystem") || lower.contains("component") || lower.contains("module") {
        if lower.contains("benchmark") || lower.contains("metal") || lower.contains("gpu") {
            return workflow_from_kind("subsystem-benchmark", goal);
        }
        if lower.contains("release") || lower.contains("bundle") || lower.contains("evidence") {
            return workflow_from_kind("subsystem-evidence-release", goal);
        }
        if lower.contains("midnight")
            || lower.contains("compact")
            || lower.contains("contract")
            || lower.contains("deploy")
        {
            return workflow_from_kind("subsystem-midnight-ops", goal);
        }
        if lower.contains("prove") || lower.contains("proof") || lower.contains("verify") {
            return workflow_from_kind("subsystem-proof", goal);
        }
        return workflow_from_kind("subsystem-scaffold", goal);
    }
    if lower.contains("midnight")
        || lower.contains("compact")
        || lower.contains("dapp")
        || lower.contains("contract")
    {
        return workflow_from_kind("midnight-contract-ops", goal);
    }
    if lower.contains("bundle")
        || lower.contains("release")
        || lower.contains("artifact")
        || lower.contains("evidence")
    {
        return workflow_from_kind("evidence-bundle", goal);
    }
    if lower.contains("benchmark") || lower.contains("metal") || lower.contains("gpu") {
        return workflow_from_kind("benchmark-report", goal);
    }
    if lower.contains("prove")
        || lower.contains("proof")
        || lower.contains("verify")
        || lower.contains("zirapp")
    {
        return workflow_from_kind("proof-app-build", goal);
    }
    if lower.contains("doctor") || lower.contains("status") || lower.contains("inspect") {
        return workflow_from_kind("host-readiness", goal);
    }
    workflow_from_kind("generic-investigation", goal)
}

pub fn build_workgraph(
    goal: &str,
    intent: &GoalIntentV1,
    requirements: &WorkflowRequirementsV1,
    trust_gate: &TrustGateReportV1,
) -> WorkgraphV1 {
    let mut nodes = Vec::new();
    let inspect = node(
        "inspect-repo",
        "Inspect repo and truth surfaces",
        "truth.inspect",
        RiskClassV1::ReadOnly,
        false,
        Vec::new(),
        vec!["truth-snapshot.json"],
        vec![success("truth-ready", "A truth snapshot is recorded for the run")],
    );
    let inspect_id = inspect.node_id.clone();
    nodes.push(inspect);

    match intent.workflow_kind.as_str() {
        "subsystem-scaffold" => {
            let scaffold = node(
                "subsystem-scaffold",
                "Scaffold subsystem bundle",
                "subsystem.scaffold",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![inspect_id.clone()],
                vec![
                    "02_manifest/subsystem_manifest.json",
                    "20_release/zkf-release-pin.json",
                ],
                vec![success("subsystem-scaffolded", "A subsystem bundle exists")],
            );
            let scaffold_id = scaffold.node_id.clone();
            nodes.push(scaffold);
            nodes.push(node(
                "subsystem-completeness",
                "Verify subsystem completeness",
                "subsystem.verify-completeness",
                RiskClassV1::ReadOnly,
                false,
                vec![scaffold_id],
                vec!["17_report/report.md"],
                vec![success(
                    "subsystem-complete",
                    "The subsystem bundle satisfies the canonical slot contract",
                )],
            ));
        }
        "subsystem-proof" => {
            let scaffold = node(
                "subsystem-scaffold",
                "Scaffold subsystem bundle",
                "subsystem.scaffold",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![inspect_id.clone()],
                vec!["08_proofs/proof.json", "09_verification/verification.json"],
                vec![success("subsystem-scaffolded", "A subsystem bundle exists")],
            );
            let scaffold_id = scaffold.node_id.clone();
            nodes.push(scaffold);
            let completeness = node(
                "subsystem-completeness",
                "Verify subsystem completeness",
                "subsystem.verify-completeness",
                RiskClassV1::ReadOnly,
                false,
                vec![scaffold_id.clone()],
                vec!["17_report/report.md"],
                vec![success("subsystem-complete", "The subsystem bundle is complete")],
            );
            let completeness_id = completeness.node_id.clone();
            nodes.push(completeness);
            nodes.push(node(
                "subsystem-release-pin",
                "Verify subsystem release pin",
                "subsystem.verify-release-pin",
                RiskClassV1::ReadOnly,
                false,
                vec![completeness_id],
                vec!["20_release/zkf-release-pin.json"],
                vec![success(
                    "subsystem-pinned",
                    "The subsystem bundle carries a valid pinned ZirOS binary reference",
                )],
            ));
        }
        "subsystem-midnight-ops" => {
            let scaffold = node(
                "subsystem-scaffold",
                "Scaffold subsystem bundle",
                "subsystem.scaffold",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![inspect_id.clone()],
                vec!["16_compact/contract.compact", "20_release/zkf-release-pin.json"],
                vec![success("subsystem-scaffolded", "A subsystem bundle exists")],
            );
            let scaffold_id = scaffold.node_id.clone();
            nodes.push(scaffold);
            let completeness = node(
                "subsystem-completeness",
                "Verify subsystem completeness",
                "subsystem.verify-completeness",
                RiskClassV1::ReadOnly,
                false,
                vec![scaffold_id.clone()],
                vec!["17_report/report.md"],
                vec![success("subsystem-complete", "The subsystem bundle is complete")],
            );
            let completeness_id = completeness.node_id.clone();
            nodes.push(completeness);
            let midnight = node(
                "midnight-status",
                "Resolve Midnight readiness",
                "midnight.status",
                RiskClassV1::ReadOnly,
                false,
                vec![completeness_id.clone()],
                vec!["midnight-status.json"],
                vec![success("midnight-ready", "Midnight status is captured")],
            );
            let midnight_id = midnight.node_id.clone();
            nodes.push(midnight);
            if requirements.require_wallet {
                nodes.push(node(
                    "wallet-readiness",
                    "Resolve wallet readiness",
                    "wallet.snapshot",
                    RiskClassV1::ReadOnly,
                    false,
                    vec![midnight_id.clone()],
                    vec!["wallet-snapshot.json"],
                    vec![success("wallet-ready", "Wallet state is captured for the session")],
                ));
            }
            let compile = node(
                "compile-contract",
                "Compile Compact contract",
                "midnight.contract.compile",
                RiskClassV1::LocalBuildTest,
                false,
                vec![midnight_id.clone()],
                vec!["contract.zkir"],
                vec![success("contract-compiled", "A Compact contract compiles to ZKIR")],
            );
            let compile_id = compile.node_id.clone();
            nodes.push(compile);
            let deploy_prepare = node(
                "deploy-prepare",
                "Prepare deploy artifacts",
                "midnight.contract.deploy-prepare",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![compile_id.clone()],
                vec!["deploy-prepare.json"],
                vec![success("deploy-prepared", "Deploy preparation output is generated")],
            );
            let deploy_prepare_id = deploy_prepare.node_id.clone();
            nodes.push(deploy_prepare);
            if requirements.require_wallet {
                let approval = node(
                    "wallet-approval",
                    "Approve Midnight submission",
                    "wallet.pending.approve",
                    RiskClassV1::WalletSignOrSubmit,
                    true,
                    vec![deploy_prepare_id],
                    vec!["approval-token.json"],
                    vec![success("approval-issued", "A wallet approval token is issued")],
                );
                let approval_id = approval.node_id.clone();
                nodes.push(approval);
                nodes.push(node(
                    "wallet-submission-grant",
                    "Issue submission grant from approved wallet token",
                    "wallet.submission-grant.issue",
                    RiskClassV1::WalletSignOrSubmit,
                    false,
                    vec![approval_id],
                    vec!["submission-grant.json"],
                    vec![success(
                        "submission-grant-issued",
                        "A wallet submission grant is issued for the prepared deploy payload",
                    )],
                ));
            }
        }
        "subsystem-benchmark" => {
            let scaffold = node(
                "subsystem-scaffold",
                "Scaffold subsystem bundle",
                "subsystem.scaffold",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![inspect_id.clone()],
                vec!["02_manifest/subsystem_manifest.json"],
                vec![success("subsystem-scaffolded", "A subsystem bundle exists")],
            );
            let scaffold_id = scaffold.node_id.clone();
            nodes.push(scaffold);
            let metal = node(
                "metal-truth",
                "Resolve Metal truth on the current host",
                "truth.metal",
                RiskClassV1::ReadOnly,
                false,
                vec![scaffold_id],
                vec!["metal-status.json"],
                vec![success("metal-truth", "Metal truth is recorded for the benchmark")],
            );
            let metal_id = metal.node_id.clone();
            nodes.push(metal);
            nodes.push(node(
                "runtime-benchmark",
                "Run benchmark workflow",
                "runtime.benchmark",
                RiskClassV1::LocalBuildTest,
                false,
                vec![metal_id],
                vec!["benchmark-report.json"],
                vec![success("benchmark-report", "A benchmark report is generated")],
            ));
        }
        "subsystem-evidence-release" => {
            let completeness = node(
                "subsystem-completeness",
                "Verify subsystem completeness",
                "subsystem.verify-completeness",
                RiskClassV1::ReadOnly,
                false,
                vec![inspect_id.clone()],
                vec!["17_report/report.md"],
                vec![success("subsystem-complete", "The subsystem bundle is complete")],
            );
            let completeness_id = completeness.node_id.clone();
            nodes.push(completeness);
            nodes.push(node(
                "evidence-bundle",
                "Package current session artifacts into an evidence bundle",
                "release.evidence-bundle",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![completeness_id],
                vec!["evidence-bundle.json"],
                vec![success("bundle-ready", "An evidence bundle summary is generated")],
            ));
        }
        "midnight-proof-server-ops" => {
            nodes.push(node(
                "midnight-status",
                "Resolve Midnight readiness",
                "midnight.status",
                RiskClassV1::ReadOnly,
                false,
                vec![inspect_id],
                vec!["midnight-status.json"],
                vec![success("midnight-ready", "Midnight status is captured")],
            ));
        }
        "midnight-contract-ops" => {
            let midnight = node(
                "midnight-status",
                "Resolve Midnight readiness",
                "midnight.status",
                RiskClassV1::ReadOnly,
                false,
                vec![inspect_id.clone()],
                vec!["midnight-status.json"],
                vec![success("midnight-ready", "Midnight status is captured")],
            );
            let midnight_id = midnight.node_id.clone();
            nodes.push(midnight);
            let scaffold = node(
                "midnight-scaffold",
                "Scaffold or reuse Midnight project",
                "midnight.project.scaffold",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![midnight_id.clone()],
                vec!["contracts/compact"],
                vec![success("midnight-project", "A Midnight project exists at the project root")],
            );
            let scaffold_id = scaffold.node_id.clone();
            nodes.push(scaffold);
            if requirements.require_wallet {
                let wallet = node(
                    "wallet-readiness",
                    "Resolve wallet readiness",
                    "wallet.snapshot",
                    RiskClassV1::ReadOnly,
                    false,
                    vec![midnight_id.clone()],
                    vec!["wallet-snapshot.json"],
                    vec![success("wallet-ready", "Wallet state is captured for the session")],
                );
                nodes.push(wallet);
            }
            let compile = node(
                "compile-contract",
                "Compile Compact contract",
                "midnight.contract.compile",
                RiskClassV1::LocalBuildTest,
                false,
                vec![scaffold_id.clone()],
                vec!["contract.zkir"],
                vec![success("contract-compiled", "A Compact contract compiles to ZKIR")],
            );
            let compile_id = compile.node_id.clone();
            nodes.push(compile);
            let deploy_prepare = node(
                "deploy-prepare",
                "Prepare deploy artifacts",
                "midnight.contract.deploy-prepare",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![compile_id.clone()],
                vec!["deploy-prepare.json"],
                vec![success("deploy-prepared", "Deploy preparation output is generated")],
            );
            let deploy_prepare_id = deploy_prepare.node_id.clone();
            nodes.push(deploy_prepare);
            if requirements.require_wallet {
                let approval = node(
                    "wallet-approval",
                    "Approve Midnight submission",
                    "wallet.pending.approve",
                    RiskClassV1::WalletSignOrSubmit,
                    true,
                    vec![deploy_prepare_id.clone()],
                    vec!["approval-token.json"],
                    vec![success("approval-issued", "A wallet approval token is issued")],
                );
                let approval_id = approval.node_id.clone();
                nodes.push(approval);
                nodes.push(node(
                    "wallet-submission-grant",
                    "Issue submission grant from approved wallet token",
                    "wallet.submission-grant.issue",
                    RiskClassV1::WalletSignOrSubmit,
                    false,
                    vec![approval_id],
                    vec!["submission-grant.json"],
                    vec![success(
                        "submission-grant-issued",
                        "A wallet submission grant is issued for the prepared deploy payload",
                    )],
                ));
            }
        }
        "benchmark-report" => {
            let metal = node(
                "metal-truth",
                "Resolve Metal truth on the current host",
                "truth.metal",
                RiskClassV1::ReadOnly,
                false,
                vec![inspect_id.clone()],
                vec!["metal-status.json"],
                vec![success("metal-truth", "Metal truth is recorded for the benchmark")],
            );
            let metal_id = metal.node_id.clone();
            nodes.push(metal);
            nodes.push(node(
                "runtime-benchmark",
                "Run benchmark workflow",
                "runtime.benchmark",
                RiskClassV1::LocalBuildTest,
                false,
                vec![metal_id],
                vec!["benchmark-report.json"],
                vec![success("benchmark-report", "A benchmark report is generated")],
            ));
        }
        "proof-app-build" => {
            let scaffold = node(
                "scaffold-proof-app",
                "Scaffold or update proof app",
                "app.scaffold",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![inspect_id.clone()],
                vec!["zirapp.json"],
                vec![success("proof-app", "A ZirOS app scaffold exists")],
            );
            let scaffold_id = scaffold.node_id.clone();
            nodes.push(scaffold);
            nodes.push(node(
                "prove-verify",
                "Compile, prove, and verify",
                "proof.compile-prove-verify",
                RiskClassV1::LocalBuildTest,
                false,
                vec![scaffold_id],
                vec!["proof.json", "verification.json"],
                vec![success("proof-verified", "Proof and verification artifacts are produced")],
            ));
        }
        "evidence-bundle" => {
            nodes.push(node(
                "evidence-bundle",
                "Package current session artifacts into an evidence bundle",
                "release.evidence-bundle",
                RiskClassV1::WorkspaceMutation,
                false,
                vec![inspect_id],
                vec!["evidence-bundle.json"],
                vec![success("bundle-ready", "An evidence bundle summary is generated")],
            ));
        }
        "host-readiness" => {
            nodes.push(node(
                "capability-scan",
                "Render system capability scan",
                "truth.capabilities",
                RiskClassV1::ReadOnly,
                false,
                vec![inspect_id],
                vec!["capabilities.json"],
                vec![success("capabilities", "A capability scan is captured")],
            ));
        }
        _ => {
            nodes.push(node(
                "generic-plan",
                "Compile generic execution plan",
                "agent.plan",
                RiskClassV1::ReadOnly,
                false,
                vec![inspect_id],
                vec!["workgraph.json"],
                vec![success("generic-plan", "A generic plan is produced for operator review")],
            ));
        }
    }

    let status = if trust_gate.blocked { "blocked" } else { "planned" };
    let node_status = if trust_gate.blocked { "blocked" } else { "pending" }.to_string();
    for node in &mut nodes {
        node.status = node_status.clone();
    }
    WorkgraphV1 {
        schema: "ziros-workgraph-v1".to_string(),
        workgraph_id: new_operation_id("workgraph"),
        session_id: None,
        workflow_kind: intent.workflow_kind.clone(),
        status: status.to_string(),
        goal: goal.to_string(),
        intent: intent.clone(),
        execution_policy: ExecutionPolicyV1 {
            strict: requirements.strict,
            compat_allowed: requirements.compat_allowed,
            stop_on_first_failure: true,
            require_explicit_approval_for_high_risk: true,
        },
        capability_requirements: capability_requirements(intent, requirements),
        blocked_prerequisites: trust_gate.prerequisites.clone(),
        nodes,
    }
}

fn workflow(
    workflow_kind: &str,
    scope: IntentScopeV1,
    summary: &str,
    requested_outputs: &[&str],
) -> GoalIntentV1 {
    GoalIntentV1 {
        summary: summary.to_string(),
        workflow_kind: workflow_kind.to_string(),
        scope,
        requested_outputs: requested_outputs.iter().map(|value| value.to_string()).collect(),
        hints: None,
    }
}

fn workflow_from_kind(workflow_kind: &str, goal: &str) -> GoalIntentV1 {
    let mut intent = workflow_catalog()
        .into_iter()
        .find(|candidate| candidate.workflow_kind == workflow_kind)
        .unwrap_or_else(|| {
            workflow(
                workflow_kind,
                IntentScopeV1::Project,
                "User-specified workflow.",
                &["workgraph.json"],
            )
        });
    intent.summary = goal.to_string();
    intent
}

fn capability_requirements(
    intent: &GoalIntentV1,
    requirements: &WorkflowRequirementsV1,
) -> Vec<CapabilityRequirementV1> {
    let mut values = vec![CapabilityRequirementV1 {
        id: "truth".to_string(),
        required: true,
        description: "Current ZirOS truth surfaces must be readable.".to_string(),
    }];
    if requirements.require_midnight || intent.workflow_kind.starts_with("midnight-") {
        values.push(CapabilityRequirementV1 {
            id: "midnight".to_string(),
            required: true,
            description: "Midnight proof-server, gateway, and Compact toolchain must be ready."
                .to_string(),
        });
    }
    if requirements.require_wallet {
        values.push(CapabilityRequirementV1 {
            id: "wallet".to_string(),
            required: true,
            description: "Wallet seed material and service health must be available.".to_string(),
        });
    }
    if requirements.require_metal {
        values.push(CapabilityRequirementV1 {
            id: "metal".to_string(),
            required: true,
            description: "Metal acceleration must be available on the current host.".to_string(),
        });
    }
    values
}

fn node(
    id_suffix: &str,
    label: &str,
    action_name: &str,
    risk_class: RiskClassV1,
    approval_required: bool,
    depends_on: Vec<String>,
    expected_artifacts: Vec<&str>,
    success_predicates: Vec<SuccessPredicateV1>,
) -> WorkgraphNodeV1 {
    WorkgraphNodeV1 {
        node_id: format!("node-{id_suffix}"),
        label: label.to_string(),
        action_name: action_name.to_string(),
        status: "pending".to_string(),
        approval_required,
        risk_class,
        success_predicates,
        depends_on,
        expected_artifacts: expected_artifacts.into_iter().map(str::to_string).collect(),
    }
}

fn success(id: &str, description: &str) -> SuccessPredicateV1 {
    SuccessPredicateV1 {
        id: id.to_string(),
        description: description.to_string(),
    }
}
