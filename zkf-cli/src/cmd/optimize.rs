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
