use std::path::PathBuf;

use zkf_core::{Program, optimize_program};

use crate::util::{load_program_v2, write_json};

pub(crate) fn handle_optimize(program: PathBuf, out: PathBuf, json: bool) -> Result<(), String> {
    let program: Program = load_program_v2(&program)?;
    let (optimized, report) = optimize_program(&program);
    write_json(&out, &optimized)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!(
            "optimized program: signals {} -> {}, constraints {} -> {}, output={}",
            report.input_signals,
            report.output_signals,
            report.input_constraints,
            report.output_constraints,
            out.display()
        );
    }
    Ok(())
}
