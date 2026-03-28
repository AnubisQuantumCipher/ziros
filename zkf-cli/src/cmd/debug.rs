use std::path::PathBuf;

use zkf_core::{
    DebugOptions, Program, analyze_program, debug_program, generate_witness_unchecked,
    solve_witness, solver_by_name,
};

use crate::util::{
    load_program_v2, read_inputs, render_zkf_error, resolve_input_aliases, write_json,
};

pub(crate) fn handle_debug(
    program: PathBuf,
    inputs: PathBuf,
    out: PathBuf,
    continue_on_failure: bool,
    solver: Option<String>,
) -> Result<(), String> {
    let program: Program = load_program_v2(&program)?;
    let diagnostics = analyze_program(&program);
    if !diagnostics.unconstrained_private_signals.is_empty() {
        eprintln!(
            "warning: unconstrained private signals: {}",
            diagnostics.unconstrained_private_signals.join(", ")
        );
    }

    let mut inputs = read_inputs(&inputs)?;
    resolve_input_aliases(&mut inputs, &program);

    let solver_name = solver
        .as_deref()
        .or_else(|| program.metadata.get("solver").map(String::as_str));

    let witness = if let Some(solver_name) = solver_name {
        let solver = solver_by_name(solver_name).map_err(render_zkf_error)?;
        solve_witness(&program, &inputs, solver.as_ref()).map_err(render_zkf_error)?
    } else {
        generate_witness_unchecked(&program, &inputs).map_err(render_zkf_error)?
    };
    let report = debug_program(
        &program,
        &witness,
        DebugOptions {
            stop_on_first_failure: !continue_on_failure,
        },
    );
    write_json(&out, &report)?;

    if report.passed {
        println!("debug: OK -> {}", out.display());
    } else if let Some(index) = report.first_failure_index {
        println!(
            "debug: FAILED at constraint {} (evaluated={}/{}) -> {}",
            index,
            report.evaluated_constraints,
            report.total_constraints,
            out.display()
        );
    } else {
        println!("debug: FAILED -> {}", out.display());
    }

    Ok(())
}
