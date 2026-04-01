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

use std::path::{Path, PathBuf};

use crate::util::{load_program_zir, read_program_artifact, write_json};
use zkf_core::normalize::normalize;
use zkf_core::type_check::type_check;

/// Handle `zkf ir validate`: parse a ZKF program (ZIR v1 or IR v2) and report schema validity.
pub(crate) fn handle_ir_validate(program: PathBuf, json: bool) -> Result<(), String> {
    match read_program_artifact(&program) {
        Ok(crate::util::ProgramArtifact::ZirV1(prog)) => report_validate(
            &program,
            ValidateReport {
                name: &prog.name,
                field: prog.field,
                signals: prog.signals.len(),
                constraints: prog.constraints.len(),
                ir_format: "zir-v1",
                type_result: type_check(&prog),
            },
            json,
        ),
        Ok(crate::util::ProgramArtifact::IrV2(prog)) => {
            let zir = zkf_core::program_v2_to_zir(&prog);
            report_validate(
                &program,
                ValidateReport {
                    name: &prog.name,
                    field: prog.field,
                    signals: prog.signals.len(),
                    constraints: prog.constraints.len(),
                    ir_format: "ir-v2",
                    type_result: type_check(&zir),
                },
                json,
            )
        }
        Err(err_msg) => {
            if json {
                let report = serde_json::json!({
                    "valid": false,
                    "program": program.display().to_string(),
                    "error": err_msg,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
                );
                Ok(())
            } else {
                Err(format!(
                    "invalid ZKF program {}: {err_msg}",
                    program.display()
                ))
            }
        }
    }
}

struct ValidateReport<'a> {
    name: &'a str,
    field: zkf_core::FieldId,
    signals: usize,
    constraints: usize,
    ir_format: &'a str,
    type_result: Result<(), Vec<zkf_core::TypeError>>,
}

fn report_validate(path: &Path, report: ValidateReport<'_>, json: bool) -> Result<(), String> {
    let ValidateReport {
        name,
        field,
        signals,
        constraints,
        ir_format,
        type_result,
    } = report;
    if json {
        let report = serde_json::json!({
            "valid": type_result.is_ok(),
            "program": path.display().to_string(),
            "name": name,
            "field": format!("{field:?}"),
            "ir_format": ir_format,
            "signals": signals,
            "constraints": constraints,
            "type_errors": match &type_result {
                Ok(()) => serde_json::Value::Array(vec![]),
                Err(errors) => serde_json::to_value(errors).unwrap_or_default(),
            },
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("IR Validate");
        println!("===========");
        println!("File:        {}", path.display());
        println!("Name:        {name}");
        println!("Format:      {ir_format}");
        println!("Field:       {field:?}");
        println!("Signals:     {signals}");
        println!("Constraints: {constraints}");
        match type_result {
            Ok(()) => println!("Status:      VALID (schema + type check pass)"),
            Err(errors) => {
                println!("Status:      INVALID ({} type error(s))", errors.len());
                for err in &errors {
                    eprintln!("  - {err}");
                }
            }
        }
    }
    Ok(())
}

/// Handle `zkf ir normalize`: normalize a ZKF program and write the result.
pub(crate) fn handle_ir_normalize(
    program: PathBuf,
    out: PathBuf,
    json: bool,
) -> Result<(), String> {
    let prog: zkf_core::zir_v1::Program = load_program_zir(&program)?;
    let (normalized, report) = normalize(&prog);
    write_json(&out, &normalized)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        println!("IR Normalize");
        println!("============");
        println!("Input:              {}", program.display());
        println!("Output:             {}", out.display());
        println!("Algebraic rewrites: {}", report.algebraic_rewrites);
        println!("Constant folds:     {}", report.constant_folds);
        println!("CSE eliminations:   {}", report.cse_eliminations);
        println!("Dead signals:       {}", report.dead_signals_removed);
        println!("Input digest:       {}", &report.input_digest[..16]);
        println!("Output digest:      {}", &report.output_digest[..16]);
    }
    Ok(())
}

/// Handle `zkf ir type-check`: type-check a ZKF program.
pub(crate) fn handle_ir_type_check(program: PathBuf, json: bool) -> Result<(), String> {
    let prog: zkf_core::zir_v1::Program = load_program_zir(&program)?;
    let result = type_check(&prog);

    if json {
        let report = match &result {
            Ok(()) => serde_json::json!({
                "well_typed": true,
                "program": program.display().to_string(),
                "errors": [],
            }),
            Err(errors) => serde_json::json!({
                "well_typed": false,
                "program": program.display().to_string(),
                "error_count": errors.len(),
                "errors": serde_json::to_value(errors).unwrap_or_default(),
            }),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
        );
    } else {
        match result {
            Ok(()) => {
                println!("type-check passed: {}", program.display());
            }
            Err(errors) => {
                eprintln!(
                    "type-check failed: {} error(s) in {}",
                    errors.len(),
                    program.display()
                );
                for err in &errors {
                    eprintln!("  - {}", err);
                }
                return Err(format!("type-check failed with {} error(s)", errors.len()));
            }
        }
    }
    Ok(())
}
