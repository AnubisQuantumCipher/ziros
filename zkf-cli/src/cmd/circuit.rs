use std::fmt::Write as _;
use std::path::PathBuf;

use crate::util::load_program_v2;

pub(crate) fn handle_circuit_show(
    program: PathBuf,
    json: bool,
    show_assignments: bool,
    show_flow: bool,
) -> Result<(), String> {
    let program = load_program_v2(&program)?;
    let summary = zkf_core::summarize_program(
        &program,
        zkf_core::CircuitSummaryOptions {
            include_assignments: show_assignments,
            include_flow: show_flow,
        },
    );

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary)
                .map_err(|error| format!("failed to serialize circuit summary: {error}"))?
        );
    } else {
        print!("{}", render_circuit_summary(&summary)?);
    }

    Ok(())
}

pub(crate) fn render_circuit_summary(summary: &zkf_core::CircuitSummary) -> Result<String, String> {
    let mut out = String::new();
    writeln!(&mut out, "Circuit Summary").map_err(|error| error.to_string())?;
    writeln!(&mut out, "===============").map_err(|error| error.to_string())?;
    writeln!(&mut out, "Program: {}", summary.program_name).map_err(|error| error.to_string())?;
    writeln!(&mut out, "Digest:  {}", summary.program_digest).map_err(|error| error.to_string())?;
    writeln!(&mut out, "Field:   {}", summary.field).map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Signals: total={} public={} private={} constant={}",
        summary.signal_count,
        summary.signals_by_visibility.public,
        summary.signals_by_visibility.private,
        summary.signals_by_visibility.constant,
    )
    .map_err(|error| error.to_string())?;
    writeln!(&mut out, "Constraints: total={}", summary.constraint_count)
        .map_err(|error| error.to_string())?;
    for (kind, count) in &summary.constraint_kinds {
        writeln!(&mut out, "  - {}: {}", kind, count).map_err(|error| error.to_string())?;
    }

    writeln!(&mut out).map_err(|error| error.to_string())?;
    writeln!(
        &mut out,
        "Witness assignments: {}",
        summary.witness_assignment_count
    )
    .map_err(|error| error.to_string())?;
    if let Some(targets) = &summary.witness_assignment_targets {
        let rendered_targets = if targets.is_empty() {
            "none".to_string()
        } else {
            targets.join(", ")
        };
        writeln!(&mut out, "Targets: {}", rendered_targets).map_err(|error| error.to_string())?;
    }

    writeln!(&mut out).map_err(|error| error.to_string())?;
    if summary.blackbox_ops.is_empty() {
        writeln!(&mut out, "BlackBox ops: none").map_err(|error| error.to_string())?;
    } else {
        writeln!(&mut out, "BlackBox ops:").map_err(|error| error.to_string())?;
        for (op, count) in &summary.blackbox_ops {
            writeln!(&mut out, "  - {}: {}", op, count).map_err(|error| error.to_string())?;
        }
    }

    writeln!(&mut out).map_err(|error| error.to_string())?;
    if summary.unconstrained_private_signals.is_empty() {
        writeln!(&mut out, "Unconstrained private signals: none")
            .map_err(|error| error.to_string())?;
    } else {
        writeln!(
            &mut out,
            "Unconstrained private signals: {}",
            summary.unconstrained_private_signals.join(", ")
        )
        .map_err(|error| error.to_string())?;
    }

    if let Some(flow) = &summary.witness_flow {
        writeln!(&mut out).map_err(|error| error.to_string())?;
        writeln!(
            &mut out,
            "Witness flow: nodes={} edges={} assignments={}",
            flow.nodes.len(),
            flow.edges.len(),
            flow.assignments.len()
        )
        .map_err(|error| error.to_string())?;
        for step in &flow.assignments {
            let dependencies = if step.dependencies.is_empty() {
                "<none>".to_string()
            } else {
                step.dependencies.join(", ")
            };
            writeln!(&mut out, "  - {} <- {}", step.target, dependencies)
                .map_err(|error| error.to_string())?;
        }
    }

    Ok(out)
}
