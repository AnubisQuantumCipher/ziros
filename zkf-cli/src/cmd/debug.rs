use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use zkf_cloudfs::CloudFS;
use zkf_core::{
    DebugOptions, PoseidonTraceEntry, Program, analyze_program, debug_program,
    ensure_witness_completeness, generate_partial_witness, solve_witness, solver_by_name,
};

use crate::util::{
    load_program_v2, read_inputs, render_zkf_error, resolve_input_aliases, write_json,
};

pub(crate) fn handle_debug(
    program: PathBuf,
    inputs: PathBuf,
    out: PathBuf,
    continue_on_failure: bool,
    poseidon_trace: bool,
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

    let (witness, used_partial_fallback) = if let Some(solver_name) = solver_name {
        let solver = solver_by_name(solver_name).map_err(render_zkf_error)?;
        match solve_witness(&program, &inputs, solver.as_ref()) {
            Ok(witness) => (witness, false),
            Err(error) => {
                eprintln!(
                    "warning: solver-assisted debug witness generation failed ({}); falling back to partial witness generation",
                    render_zkf_error(error)
                );
                (
                    generate_partial_witness(&program, &inputs).map_err(render_zkf_error)?,
                    true,
                )
            }
        }
    } else {
        (
            generate_partial_witness(&program, &inputs).map_err(render_zkf_error)?,
            false,
        )
    };
    let witness_is_partial = ensure_witness_completeness(&program, &witness).is_err();
    let report = debug_program(
        &program,
        &witness,
        DebugOptions {
            stop_on_first_failure: !(continue_on_failure || witness_is_partial),
            include_poseidon_trace: poseidon_trace,
        },
    );
    let mut report = report;
    let poseidon_trace_path = if poseidon_trace && !report.poseidon_trace.is_empty() {
        let trace = std::mem::take(&mut report.poseidon_trace);
        Some(persist_poseidon_trace_local(&program, &trace)?)
    } else {
        None
    };
    write_json(&out, &report)?;

    let first_concrete_failure = report
        .constraints
        .iter()
        .find(|trace| !trace.passed && trace.error.is_none())
        .map(|trace| trace.index);

    if report.passed {
        println!("debug: OK -> {}", out.display());
    } else if witness_is_partial {
        match first_concrete_failure.or(report.first_failure_index) {
            Some(index) => println!(
                "debug: PARTIAL witness{}; first failing known constraint {} (evaluated={}/{}) -> {}",
                if used_partial_fallback {
                    " (fallback path used)"
                } else {
                    ""
                },
                index,
                report.evaluated_constraints,
                report.total_constraints,
                out.display()
            ),
            None => println!(
                "debug: PARTIAL witness{} -> {}",
                if used_partial_fallback {
                    " (fallback path used)"
                } else {
                    ""
                },
                out.display()
            ),
        }
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
    if let Some(path) = poseidon_trace_path {
        println!(
            "debug: poseidon trace written to local cache only -> {}",
            path.display()
        );
    }

    Ok(())
}

const POSEIDON_TRACE_CACHE_DIR: &str = "debug/poseidon";
const POSEIDON_TRACE_MAX_AGE: Duration = Duration::from_secs(60 * 60);

fn persist_poseidon_trace_local(
    program: &Program,
    trace: &[PoseidonTraceEntry],
) -> Result<PathBuf, String> {
    let cloudfs = CloudFS::new().map_err(|error| error.to_string())?;
    prune_stale_poseidon_traces(cloudfs.cache_root().join(POSEIDON_TRACE_CACHE_DIR));
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let slug = program
        .name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    let relative = format!(
        "{POSEIDON_TRACE_CACHE_DIR}/{}-{}-{now}.json",
        if slug.is_empty() { "program" } else { &slug },
        &program.digest_hex()[..16]
    );
    let payload = serde_json::json!({
        "schema": "zkf-poseidon-trace-v1",
        "program_name": program.name.clone(),
        "program_digest": program.digest_hex(),
        "generated_at_unix_seconds": now,
        "trace": trace,
    });
    let bytes = serde_json::to_vec_pretty(&payload).map_err(|error| error.to_string())?;
    cloudfs
        .write_local_only(&relative, &bytes)
        .map_err(|error| error.to_string())?;
    Ok(cloudfs.cache_root().join(relative))
}

fn prune_stale_poseidon_traces(root: PathBuf) {
    let Ok(entries) = fs::read_dir(&root) else {
        return;
    };
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if now
            .duration_since(modified)
            .unwrap_or_default()
            .gt(&POSEIDON_TRACE_MAX_AGE)
        {
            let _ = fs::remove_file(path);
        }
    }
}
