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

use crate::FrontendImportOptions;
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use zkf_core::{
    BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility,
    WitnessAssignment, WitnessHint, WitnessHintKind, ZkfError, ZkfResult,
};

const COMPACT_FRONTEND_NAME: &str = "compact";
const COMPACT_TARGET_BACKEND: &str = "halo2-bls12-381";

#[derive(Debug, Clone, Deserialize)]
struct ZkirVersion {
    major: u32,
    minor: u32,
}

#[derive(Debug, Clone, Deserialize)]
struct ZkirProgram {
    version: ZkirVersion,
    #[serde(default)]
    do_communications_commitment: bool,
    num_inputs: usize,
    instructions: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct CompactContractInfo {
    #[serde(rename = "compiler-version")]
    compiler_version: String,
    #[serde(rename = "language-version")]
    language_version: String,
    #[serde(default)]
    circuits: Vec<CompactCircuitInfo>,
}

#[derive(Debug, Clone, Deserialize)]
struct CompactCircuitInfo {
    name: String,
    #[serde(default)]
    arguments: Vec<CompactCircuitArgument>,
}

#[derive(Debug, Clone, Deserialize)]
struct CompactCircuitArgument {
    name: String,
    #[serde(rename = "type")]
    ty: Value,
}

#[derive(Debug, Clone)]
struct CompactImportContext {
    zkir_path: Option<PathBuf>,
    contract_info_path: Option<PathBuf>,
    contract_types_path: Option<PathBuf>,
    circuit_name: String,
    contract_info: Option<CompactContractInfo>,
}

#[derive(Debug, Clone)]
struct CompactVar {
    expr: Expr,
    signal_name: Option<String>,
    visibility: Visibility,
    ty: Option<String>,
}

#[derive(Debug)]
struct CompactBuilder {
    program: Program,
    vars: BTreeMap<usize, CompactVar>,
    next_result_var: usize,
    next_internal_signal: usize,
    next_public_signal: usize,
    next_private_input: usize,
    next_public_input: usize,
    next_blackbox_output: usize,
    next_output_signal: usize,
    used_signal_names: BTreeSet<String>,
    public_transcript_order: Vec<String>,
    pi_skip_events: Vec<String>,
}

impl CompactBuilder {
    fn new(name: String, field: FieldId) -> Self {
        Self {
            program: Program {
                name,
                field,
                ..Default::default()
            },
            vars: BTreeMap::new(),
            next_result_var: 0,
            next_internal_signal: 0,
            next_public_signal: 0,
            next_private_input: 0,
            next_public_input: 0,
            next_blackbox_output: 0,
            next_output_signal: 0,
            used_signal_names: BTreeSet::new(),
            public_transcript_order: Vec::new(),
            pi_skip_events: Vec::new(),
        }
    }

    fn finish(mut self, context: &CompactImportContext) -> Program {
        self.program
            .metadata
            .insert("frontend".to_string(), COMPACT_FRONTEND_NAME.to_string());
        self.program.metadata.insert(
            "preferred_backend".to_string(),
            COMPACT_TARGET_BACKEND.to_string(),
        );
        self.program.metadata.insert(
            "compact_target_backend".to_string(),
            COMPACT_TARGET_BACKEND.to_string(),
        );
        self.program
            .metadata
            .insert("compact_zkir_version".to_string(), format!("{}.{}", 2, 0));
        self.program.metadata.insert(
            "compact_circuit_name".to_string(),
            context.circuit_name.clone(),
        );
        self.program.metadata.insert(
            "compact_public_transcript_json".to_string(),
            serde_json::to_string(&self.public_transcript_order)
                .unwrap_or_else(|_| "[]".to_string()),
        );
        self.program.metadata.insert(
            "compact_pi_skip_json".to_string(),
            serde_json::to_string(&self.pi_skip_events).unwrap_or_else(|_| "[]".to_string()),
        );
        if let Some(path) = context.zkir_path.as_ref() {
            self.program
                .metadata
                .insert("compact_zkir_path".to_string(), path.display().to_string());
        }
        if let Some(path) = context.contract_info_path.as_ref() {
            self.program.metadata.insert(
                "compact_contract_info_path".to_string(),
                path.display().to_string(),
            );
        }
        if let Some(path) = context.contract_types_path.as_ref() {
            self.program.metadata.insert(
                "compact_contract_types_path".to_string(),
                path.display().to_string(),
            );
        }
        if let Some(contract_info) = context.contract_info.as_ref() {
            self.program.metadata.insert(
                "compact_compiler_version".to_string(),
                contract_info.compiler_version.clone(),
            );
            self.program.metadata.insert(
                "compact_language_version".to_string(),
                contract_info.language_version.clone(),
            );
        }
        self.program
    }

    fn reserve_result_var(&mut self) -> usize {
        let var = self.next_result_var;
        self.next_result_var += 1;
        var
    }

    fn make_unique_signal_name(&mut self, raw: impl Into<String>) -> String {
        let raw = raw.into();
        let mut base = sanitize_signal_name(&raw);
        if base.is_empty() {
            base = "compact_signal".to_string();
        }
        if self.used_signal_names.insert(base.clone()) {
            return base;
        }

        let mut suffix = 1usize;
        loop {
            let candidate = format!("{base}_{suffix}");
            if self.used_signal_names.insert(candidate.clone()) {
                return candidate;
            }
            suffix += 1;
        }
    }

    fn push_signal(
        &mut self,
        preferred_name: impl Into<String>,
        visibility: Visibility,
        constant: Option<FieldElement>,
        ty: Option<String>,
    ) -> String {
        let name = self.make_unique_signal_name(preferred_name);
        self.program.signals.push(Signal {
            name: name.clone(),
            visibility,
            constant,
            ty,
        });
        name
    }

    fn bind_var(&mut self, var: usize, entry: CompactVar) {
        self.vars.insert(var, entry);
    }

    fn expr_for_var(&self, var: usize) -> ZkfResult<Expr> {
        self.vars
            .get(&var)
            .map(|entry| entry.expr.clone())
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!("compact zkir references unknown var {var}"))
            })
    }

    fn var_ty(&self, var: usize) -> Option<String> {
        self.vars.get(&var).and_then(|entry| entry.ty.clone())
    }

    fn var_visibility(&self, var: usize) -> ZkfResult<Visibility> {
        self.vars
            .get(&var)
            .map(|entry| entry.visibility.clone())
            .ok_or_else(|| {
                ZkfError::InvalidArtifact(format!("compact zkir references unknown var {var}"))
            })
    }

    fn bind_input_var(
        &mut self,
        var: usize,
        preferred_name: impl Into<String>,
        visibility: Visibility,
        ty: Option<String>,
    ) -> String {
        let name = self.push_signal(preferred_name, visibility.clone(), None, ty.clone());
        self.bind_var(
            var,
            CompactVar {
                expr: Expr::Signal(name.clone()),
                signal_name: Some(name.clone()),
                visibility,
                ty,
            },
        );
        name
    }

    fn add_assignment_and_equality(&mut self, target: &str, expr: Expr, label: impl Into<String>) {
        let label = label.into();
        self.program
            .witness_plan
            .assignments
            .push(WitnessAssignment {
                target: target.to_string(),
                expr: expr.clone(),
            });
        self.program.constraints.push(Constraint::Equal {
            lhs: Expr::Signal(target.to_string()),
            rhs: expr,
            label: Some(label),
        });
    }

    fn materialize_var_signal(
        &mut self,
        var: usize,
        preferred_name: impl Into<String>,
    ) -> ZkfResult<String> {
        let Some(entry) = self.vars.get(&var).cloned() else {
            return Err(ZkfError::InvalidArtifact(format!(
                "compact zkir references unknown var {var}"
            )));
        };
        if let Some(name) = entry.signal_name {
            return Ok(name);
        }

        let name = match &entry.expr {
            Expr::Const(value) => self.push_signal(
                preferred_name,
                Visibility::Constant,
                Some(value.clone()),
                entry.ty.clone(),
            ),
            expr => {
                let name = self.push_signal(
                    preferred_name,
                    entry.visibility.clone(),
                    None,
                    entry.ty.clone(),
                );
                self.add_assignment_and_equality(
                    &name,
                    expr.clone(),
                    format!("compact_materialize_var_{var}"),
                );
                name
            }
        };

        self.bind_var(
            var,
            CompactVar {
                expr: Expr::Signal(name.clone()),
                signal_name: Some(name.clone()),
                visibility: entry.visibility,
                ty: entry.ty,
            },
        );

        Ok(name)
    }

    fn add_public_alias_for_var(
        &mut self,
        var: usize,
        preferred_name: impl Into<String>,
        label_prefix: &str,
    ) -> ZkfResult<String> {
        let expr = self.expr_for_var(var)?;
        let signal_name =
            self.push_signal(preferred_name, Visibility::Public, None, self.var_ty(var));
        self.program
            .witness_plan
            .assignments
            .push(WitnessAssignment {
                target: signal_name.clone(),
                expr: expr.clone(),
            });
        self.program.constraints.push(Constraint::Equal {
            lhs: Expr::Signal(signal_name.clone()),
            rhs: expr,
            label: Some(format!(
                "{label_prefix}_{}",
                self.public_transcript_order.len()
            )),
        });
        self.public_transcript_order.push(signal_name.clone());
        Ok(signal_name)
    }

    fn bind_private_expr_result(
        &mut self,
        expr: Expr,
        ty: Option<String>,
        visibility: Visibility,
    ) -> usize {
        let var = self.reserve_result_var();
        self.bind_var(
            var,
            CompactVar {
                expr,
                signal_name: None,
                visibility,
                ty,
            },
        );
        var
    }

    fn create_private_bound_signal(
        &mut self,
        preferred_name: impl Into<String>,
        expr: Expr,
        ty: Option<String>,
        label: impl Into<String>,
    ) -> String {
        let name = self.push_signal(preferred_name, Visibility::Private, None, ty);
        self.add_assignment_and_equality(&name, expr, label.into());
        name
    }
}

pub(crate) fn is_probable_zkir_value(value: &Value) -> bool {
    if let Some(object) = value.as_object() {
        if object.contains_key("version")
            && object.contains_key("instructions")
            && object.contains_key("num_inputs")
        {
            return true;
        }

        if object.contains_key("zkir")
            || object.contains_key("zkir_path")
            || object
                .get("compiled_ir_path")
                .and_then(Value::as_str)
                .is_some_and(|path| path.ends_with(".zkir"))
        {
            return true;
        }
    }
    false
}

pub(crate) fn compile_from_value(
    value: &Value,
    options: &FrontendImportOptions,
) -> ZkfResult<Option<Program>> {
    let Some((zkir, context)) = load_zkir_context(value, options)? else {
        return Ok(None);
    };

    if zkir.version.major != 2 || zkir.version.minor != 0 {
        return Err(ZkfError::InvalidArtifact(format!(
            "compact zkir importer only supports schema version 2.0, found {}.{}",
            zkir.version.major, zkir.version.minor
        )));
    }

    let field = options.field.unwrap_or(FieldId::Bls12_381);
    if field != FieldId::Bls12_381 {
        return Err(ZkfError::InvalidArtifact(format!(
            "compact imports are pinned to Bls12_381 / halo2-bls12-381; refusing override to {field}"
        )));
    }

    let circuit_info = context.contract_info.as_ref().and_then(|info| {
        info.circuits
            .iter()
            .find(|circuit| circuit.name == context.circuit_name)
    });
    let program_name = options
        .program_name
        .clone()
        .unwrap_or_else(|| context.circuit_name.clone());

    let mut builder = CompactBuilder::new(program_name, field);
    builder.next_result_var = zkir.num_inputs;
    builder.program.metadata.insert(
        "compact_do_communications_commitment".to_string(),
        zkir.do_communications_commitment.to_string(),
    );

    for index in 0..zkir.num_inputs {
        let (arg_name, arg_ty) = circuit_info
            .and_then(|circuit| circuit.arguments.get(index))
            .map(|argument| (argument.name.clone(), compact_type_label(&argument.ty)))
            .unwrap_or_else(|| (format!("arg_{index}"), None));
        let signal_name =
            builder.bind_input_var(index, arg_name.clone(), Visibility::Private, arg_ty);
        builder
            .program
            .witness_plan
            .input_aliases
            .insert(arg_name, signal_name);
    }

    for instruction in &zkir.instructions {
        apply_instruction(&mut builder, instruction)?;
    }

    Ok(Some(builder.finish(&context)))
}

fn load_zkir_context(
    value: &Value,
    options: &FrontendImportOptions,
) -> ZkfResult<Option<(ZkirProgram, CompactImportContext)>> {
    let base_path = options
        .source_path
        .as_ref()
        .and_then(|path| path.parent())
        .map(Path::to_path_buf);
    let zkir_path_from_value = descriptor_path(value, "zkir_path", base_path.as_deref())
        .or_else(|| descriptor_path(value, "compiled_ir_path", base_path.as_deref()));

    let zkir_value = if is_raw_zkir(value) {
        Some(value.clone())
    } else if let Some(embedded) = value.get("zkir") {
        Some(embedded.clone())
    } else if let Some(path) = zkir_path_from_value.as_ref() {
        let content = fs::read_to_string(path).map_err(|err| {
            ZkfError::Io(format!(
                "failed reading Compact zkir '{}': {err}",
                path.display()
            ))
        })?;
        Some(serde_json::from_str::<Value>(&content).map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "failed to parse Compact zkir JSON from '{}': {err}",
                path.display()
            ))
        })?)
    } else {
        None
    };

    let Some(zkir_value) = zkir_value else {
        return Ok(None);
    };

    let zkir = serde_json::from_value::<ZkirProgram>(zkir_value).map_err(|err| {
        ZkfError::InvalidArtifact(format!("failed to deserialize Compact zkir payload: {err}"))
    })?;

    let zkir_path = zkir_path_from_value.or_else(|| {
        options
            .source_path
            .clone()
            .filter(|path| path.extension().is_some_and(|ext| ext == "zkir"))
    });
    let contract_info_path = descriptor_path(value, "contract_info_path", base_path.as_deref())
        .or_else(|| discover_contract_info_path(zkir_path.as_deref()));
    let contract_types_path = descriptor_path(value, "contract_types_path", base_path.as_deref())
        .or_else(|| discover_contract_types_path(zkir_path.as_deref()));
    let contract_info = match contract_info_path.as_deref() {
        Some(path) => read_contract_info(path)?,
        None => None,
    };
    let circuit_name = value
        .get("circuit_name")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            zkir_path
                .as_ref()
                .and_then(|path| file_stem_string(path.as_path()))
        })
        .or_else(|| {
            contract_info
                .as_ref()
                .and_then(|info| (info.circuits.len() == 1).then(|| info.circuits[0].name.clone()))
        })
        .unwrap_or_else(|| "compact_circuit".to_string());

    Ok(Some((
        zkir,
        CompactImportContext {
            zkir_path,
            contract_info_path,
            contract_types_path,
            circuit_name,
            contract_info,
        },
    )))
}

fn apply_instruction(builder: &mut CompactBuilder, instruction: &Value) -> ZkfResult<()> {
    let object = instruction.as_object().ok_or_else(|| {
        ZkfError::InvalidArtifact("compact zkir instruction must be a JSON object".to_string())
    })?;
    let op = object.get("op").and_then(Value::as_str).ok_or_else(|| {
        ZkfError::InvalidArtifact("compact zkir instruction is missing `op`".to_string())
    })?;

    match op {
        "load_imm" => {
            let imm = object.get("imm").and_then(Value::as_str).ok_or_else(|| {
                ZkfError::InvalidArtifact("compact load_imm missing `imm`".to_string())
            })?;
            let field_value = field_element_from_hex(imm, builder.program.field)?;
            let var = builder.reserve_result_var();
            builder.bind_var(
                var,
                CompactVar {
                    expr: Expr::Const(field_value),
                    signal_name: None,
                    visibility: Visibility::Constant,
                    ty: None,
                },
            );
        }
        "copy" => {
            let source = parse_var_like(object, &["var", "src", "source"])?;
            let expr = builder.expr_for_var(source)?;
            let visibility = builder.var_visibility(source)?;
            let ty = builder.var_ty(source);
            builder.bind_private_expr_result(expr, ty, visibility);
        }
        "add" | "sub" | "mul" | "div" => {
            let left_var = parse_var_like(object, &["a", "lhs", "left"])?;
            let right_var = parse_var_like(object, &["b", "rhs", "right"])?;
            let left = builder.expr_for_var(left_var)?;
            let right = builder.expr_for_var(right_var)?;
            let expr = match op {
                "add" => Expr::Add(vec![left, right]),
                "sub" => Expr::Sub(Box::new(left), Box::new(right)),
                "mul" => Expr::Mul(Box::new(left), Box::new(right)),
                "div" => Expr::Div(Box::new(left), Box::new(right)),
                _ => unreachable!("handled above"),
            };
            let visibility = merge_visibility(&[
                builder.var_visibility(left_var)?,
                builder.var_visibility(right_var)?,
            ]);
            builder.bind_private_expr_result(expr, None, visibility);
        }
        "constrain_bits" => {
            let var = parse_var_like(object, &["var", "value"])?;
            let bits = parse_u32(object, "bits")?;
            let signal = builder.materialize_var_signal(
                var,
                format!("compact_range_{}", builder.next_internal_signal),
            )?;
            builder.next_internal_signal += 1;
            builder.program.constraints.push(Constraint::Range {
                signal,
                bits,
                label: Some(format!("compact_range_var_{var}_{bits}")),
            });
        }
        "declare_pub_input" => {
            let var = parse_var_like(object, &["var", "value"])?;
            builder.add_public_alias_for_var(
                var,
                format!("compact_public_{}", builder.next_public_signal),
                "compact_declare_pub_input",
            )?;
            builder.next_public_signal += 1;
        }
        "public_input" => {
            if let Some(existing_var) = parse_var_like_optional(object, &["var", "value"])? {
                builder.add_public_alias_for_var(
                    existing_var,
                    format!("compact_public_input_{}", builder.next_public_input),
                    "compact_public_input_alias",
                )?;
                builder.next_public_input += 1;
            } else {
                let var = builder.reserve_result_var();
                let raw_name = object
                    .get("name")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| {
                        format!("compact_public_input_{}", builder.next_public_input)
                    });
                let signal_name = builder.bind_input_var(var, raw_name, Visibility::Public, None);
                builder.public_transcript_order.push(signal_name);
                builder.next_public_input += 1;
            }
        }
        "private_input" => {
            let var = builder.reserve_result_var();
            let raw_name = object
                .get("name")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(|| format!("compact_private_input_{}", builder.next_private_input));
            builder.bind_input_var(var, raw_name.clone(), Visibility::Private, None);
            builder
                .program
                .witness_plan
                .input_aliases
                .entry(raw_name.clone())
                .or_insert(raw_name);
            builder.next_private_input += 1;
        }
        "assert" => {
            let left = parse_expr_operand(builder, object, &["var", "value", "a", "lhs", "left"])?;
            let right = if let Some(var) = parse_var_like_optional(object, &["b", "rhs", "right"])?
            {
                builder.expr_for_var(var)?
            } else {
                Expr::Const(FieldElement::ONE)
            };
            builder.program.constraints.push(Constraint::Equal {
                lhs: left,
                rhs: right,
                label: Some("compact_assert".to_string()),
            });
        }
        "pi_skip" => {
            let guard_var = parse_var_like(object, &["guard", "var"])?;
            let guard = guard_is_compile_time_bool(builder, guard_var)?;
            let count = parse_u64(object, "count")?;
            builder
                .pi_skip_events
                .push(format!("{guard}:{count}:{guard_var}"));
        }
        "cond_select" => {
            let guard_var = parse_var_like(object, &["guard", "cond", "selector"])?;
            let then_var = parse_var_like(object, &["then", "if_true", "a", "left"])?;
            let else_var = parse_var_like(object, &["else", "if_false", "b", "right"])?;
            let guard_signal = builder.materialize_var_signal(
                guard_var,
                format!("compact_cond_guard_{}", builder.next_internal_signal),
            )?;
            builder.next_internal_signal += 1;
            builder.program.constraints.push(Constraint::Boolean {
                signal: guard_signal.clone(),
                label: Some(format!("compact_cond_select_guard_{guard_var}")),
            });
            let then_expr = builder.expr_for_var(then_var)?;
            let else_expr = builder.expr_for_var(else_var)?;
            let one_minus_guard = Expr::Sub(
                Box::new(Expr::Const(FieldElement::ONE)),
                Box::new(Expr::Signal(guard_signal.clone())),
            );
            let expr = Expr::Add(vec![
                Expr::Mul(Box::new(Expr::Signal(guard_signal)), Box::new(then_expr)),
                Expr::Mul(Box::new(one_minus_guard), Box::new(else_expr)),
            ]);
            let visibility = merge_visibility(&[
                builder.var_visibility(guard_var)?,
                builder.var_visibility(then_var)?,
                builder.var_visibility(else_var)?,
            ]);
            builder.bind_private_expr_result(expr, None, visibility);
        }
        "test_eq" => {
            let left_var = parse_var_like(object, &["a", "lhs", "left"])?;
            let right_var = parse_var_like(object, &["b", "rhs", "right"])?;
            let left = builder.expr_for_var(left_var)?;
            let right = builder.expr_for_var(right_var)?;
            let delta_name = builder.create_private_bound_signal(
                format!("compact_test_eq_delta_{}", builder.next_internal_signal),
                Expr::Sub(Box::new(left), Box::new(right)),
                None,
                format!("compact_test_eq_delta_{left_var}_{right_var}"),
            );
            builder.next_internal_signal += 1;
            let inverse_name = builder.push_signal(
                format!("compact_test_eq_inv_{}", builder.next_internal_signal),
                Visibility::Private,
                None,
                None,
            );
            builder.next_internal_signal += 1;
            builder.program.witness_plan.hints.push(WitnessHint {
                target: inverse_name.clone(),
                source: delta_name.clone(),
                kind: WitnessHintKind::InverseOrZero,
            });
            let eq_name = builder.push_signal(
                format!("compact_test_eq_{}", builder.next_internal_signal),
                Visibility::Private,
                None,
                Some("Bool".to_string()),
            );
            builder.next_internal_signal += 1;
            let eq_expr = Expr::Sub(
                Box::new(Expr::Const(FieldElement::ONE)),
                Box::new(Expr::Mul(
                    Box::new(Expr::Signal(delta_name.clone())),
                    Box::new(Expr::Signal(inverse_name.clone())),
                )),
            );
            builder
                .program
                .witness_plan
                .assignments
                .push(WitnessAssignment {
                    target: eq_name.clone(),
                    expr: eq_expr.clone(),
                });
            builder.program.constraints.push(Constraint::Equal {
                lhs: Expr::Signal(eq_name.clone()),
                rhs: eq_expr,
                label: Some(format!("compact_test_eq_assign_{left_var}_{right_var}")),
            });
            builder.program.constraints.push(Constraint::Boolean {
                signal: eq_name.clone(),
                label: Some(format!("compact_test_eq_boolean_{left_var}_{right_var}")),
            });
            builder.program.constraints.push(Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal(delta_name)),
                    Box::new(Expr::Signal(eq_name.clone())),
                ),
                rhs: Expr::Const(FieldElement::ZERO),
                label: Some(format!(
                    "compact_test_eq_zero_product_{left_var}_{right_var}"
                )),
            });
            let var = builder.reserve_result_var();
            builder.bind_var(
                var,
                CompactVar {
                    expr: Expr::Signal(eq_name.clone()),
                    signal_name: Some(eq_name),
                    visibility: Visibility::Private,
                    ty: Some("Bool".to_string()),
                },
            );
        }
        "div_mod_power_of_two" => {
            let value_var = parse_var_like(object, &["var", "value", "a"])?;
            let bits = parse_u32_flexible(object, &["bits", "power", "shift"])?;
            let base =
                FieldElement::from_bigint_with_field(BigInt::one() << bits, builder.program.field);
            let value_expr = builder.expr_for_var(value_var)?;
            let quotient_name = builder.push_signal(
                format!("compact_div_quotient_{}", builder.next_internal_signal),
                Visibility::Private,
                None,
                None,
            );
            builder.next_internal_signal += 1;
            let quotient_expr = Expr::Div(
                Box::new(value_expr.clone()),
                Box::new(Expr::Const(base.clone())),
            );
            builder
                .program
                .witness_plan
                .assignments
                .push(WitnessAssignment {
                    target: quotient_name.clone(),
                    expr: quotient_expr,
                });
            let remainder_name = builder.push_signal(
                format!("compact_div_remainder_{}", builder.next_internal_signal),
                Visibility::Private,
                None,
                None,
            );
            builder.next_internal_signal += 1;
            let remainder_expr = Expr::Sub(
                Box::new(value_expr.clone()),
                Box::new(Expr::Mul(
                    Box::new(Expr::Const(base.clone())),
                    Box::new(Expr::Signal(quotient_name.clone())),
                )),
            );
            builder
                .program
                .witness_plan
                .assignments
                .push(WitnessAssignment {
                    target: remainder_name.clone(),
                    expr: remainder_expr,
                });
            builder.program.constraints.push(Constraint::Range {
                signal: remainder_name.clone(),
                bits,
                label: Some(format!("compact_div_mod_pow2_range_{value_var}_{bits}")),
            });
            builder.program.constraints.push(Constraint::Equal {
                lhs: value_expr,
                rhs: Expr::Add(vec![
                    Expr::Signal(remainder_name.clone()),
                    Expr::Mul(
                        Box::new(Expr::Const(base)),
                        Box::new(Expr::Signal(quotient_name.clone())),
                    ),
                ]),
                label: Some(format!("compact_div_mod_pow2_recompose_{value_var}_{bits}")),
            });
            let quotient_var = builder.reserve_result_var();
            builder.bind_var(
                quotient_var,
                CompactVar {
                    expr: Expr::Signal(quotient_name.clone()),
                    signal_name: Some(quotient_name),
                    visibility: Visibility::Private,
                    ty: None,
                },
            );
            let remainder_var = builder.reserve_result_var();
            builder.bind_var(
                remainder_var,
                CompactVar {
                    expr: Expr::Signal(remainder_name.clone()),
                    signal_name: Some(remainder_name),
                    visibility: Visibility::Private,
                    ty: None,
                },
            );
        }
        "persistent_hash" => {
            let input_vars = parse_var_list(object, &["inputs", "vars", "args"])?;
            let inputs = input_vars
                .iter()
                .map(|var| builder.expr_for_var(*var))
                .collect::<ZkfResult<Vec<_>>>()?;
            let state_len = object
                .get("state_len")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .unwrap_or(input_vars.len());
            if state_len != input_vars.len() {
                return Err(ZkfError::InvalidArtifact(format!(
                    "compact persistent_hash only supports state_len matching input count; got state_len={state_len}, inputs={}",
                    input_vars.len()
                )));
            }
            if state_len != 4 {
                return Err(ZkfError::InvalidArtifact(format!(
                    "compact persistent_hash currently only supports BLS12-381 Poseidon width-4 surfaces; got width {state_len}"
                )));
            }
            let mut outputs = Vec::with_capacity(state_len);
            for _ in 0..state_len {
                let output_name = builder.push_signal(
                    format!("compact_poseidon_out_{}", builder.next_blackbox_output),
                    Visibility::Private,
                    None,
                    None,
                );
                builder.next_blackbox_output += 1;
                outputs.push(output_name);
            }
            builder.program.constraints.push(Constraint::BlackBox {
                op: BlackBoxOp::Poseidon,
                inputs,
                outputs: outputs.clone(),
                params: BTreeMap::from([
                    ("state_len".to_string(), state_len.to_string()),
                    ("compact_op".to_string(), "persistent_hash".to_string()),
                ]),
                label: Some(format!(
                    "compact_persistent_hash_{}",
                    builder.next_blackbox_output
                )),
            });
            for output_name in outputs {
                let var = builder.reserve_result_var();
                builder.bind_var(
                    var,
                    CompactVar {
                        expr: Expr::Signal(output_name.clone()),
                        signal_name: Some(output_name),
                        visibility: Visibility::Private,
                        ty: None,
                    },
                );
            }
        }
        "output" => {
            let var = parse_var_like(object, &["var", "value", "source"])?;
            builder.add_public_alias_for_var(
                var,
                format!("compact_output_{}", builder.next_output_signal),
                "compact_output",
            )?;
            builder.next_output_signal += 1;
        }
        other => {
            return Err(ZkfError::InvalidArtifact(format!(
                "unsupported Compact zkir opcode '{other}'"
            )));
        }
    }

    Ok(())
}

fn parse_expr_operand(
    builder: &CompactBuilder,
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> ZkfResult<Expr> {
    let var = parse_var_like(object, keys)?;
    builder.expr_for_var(var)
}

fn parse_var_like(object: &serde_json::Map<String, Value>, keys: &[&str]) -> ZkfResult<usize> {
    parse_var_like_optional(object, keys)?.ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "compact zkir instruction is missing one of required keys {:?}",
            keys
        ))
    })
}

fn parse_var_like_optional(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> ZkfResult<Option<usize>> {
    for key in keys {
        if let Some(value) = object.get(*key) {
            return Ok(Some(parse_usize_value(value, key)?));
        }
    }
    Ok(None)
}

fn parse_var_list(object: &serde_json::Map<String, Value>, keys: &[&str]) -> ZkfResult<Vec<usize>> {
    for key in keys {
        if let Some(value) = object.get(*key) {
            let items = value.as_array().ok_or_else(|| {
                ZkfError::InvalidArtifact(format!(
                    "compact zkir field `{key}` must be an array of variable ids"
                ))
            })?;
            return items
                .iter()
                .map(|item| parse_usize_value(item, key))
                .collect();
        }
    }

    Err(ZkfError::InvalidArtifact(format!(
        "compact zkir instruction is missing one of required array keys {:?}",
        keys
    )))
}

fn parse_usize_value(value: &Value, key: &str) -> ZkfResult<usize> {
    if let Some(number) = value.as_u64() {
        return Ok(number as usize);
    }
    if let Some(text) = value.as_str() {
        return text.parse::<usize>().map_err(|err| {
            ZkfError::InvalidArtifact(format!(
                "compact zkir field `{key}` must be a usize-compatible value: {err}"
            ))
        });
    }
    Err(ZkfError::InvalidArtifact(format!(
        "compact zkir field `{key}` must be a variable id"
    )))
}

fn parse_u64(object: &serde_json::Map<String, Value>, key: &str) -> ZkfResult<u64> {
    object.get(key).and_then(Value::as_u64).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "compact zkir instruction is missing numeric `{key}`"
        ))
    })
}

fn parse_u32(object: &serde_json::Map<String, Value>, key: &str) -> ZkfResult<u32> {
    parse_u64(object, key).map(|value| value as u32)
}

fn parse_u32_flexible(object: &serde_json::Map<String, Value>, keys: &[&str]) -> ZkfResult<u32> {
    for key in keys {
        if object.get(*key).is_some() {
            return parse_u32(object, key);
        }
    }
    Err(ZkfError::InvalidArtifact(format!(
        "compact zkir instruction is missing one of required numeric keys {:?}",
        keys
    )))
}

fn descriptor_path(value: &Value, key: &str, base: Option<&Path>) -> Option<PathBuf> {
    let raw = value.get(key)?.as_str()?;
    Some(resolve_relative_path(raw, base))
}

fn resolve_relative_path(raw: &str, base: Option<&Path>) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else if let Some(base) = base {
        base.join(path)
    } else {
        path
    }
}

fn discover_contract_info_path(zkir_path: Option<&Path>) -> Option<PathBuf> {
    let zkir_path = zkir_path?;
    let parent = zkir_path.parent()?;
    let compiler = parent.parent()?.join("compiler").join("contract-info.json");
    compiler.exists().then_some(compiler)
}

fn discover_contract_types_path(zkir_path: Option<&Path>) -> Option<PathBuf> {
    let zkir_path = zkir_path?;
    let parent = zkir_path.parent()?;
    let dts = parent.parent()?.join("contract").join("index.d.ts");
    dts.exists().then_some(dts)
}

fn read_contract_info(path: &Path) -> ZkfResult<Option<CompactContractInfo>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).map_err(|err| {
        ZkfError::Io(format!(
            "failed reading Compact contract-info sidecar '{}': {err}",
            path.display()
        ))
    })?;
    let info = serde_json::from_str::<CompactContractInfo>(&content).map_err(|err| {
        ZkfError::InvalidArtifact(format!(
            "failed to parse Compact contract-info sidecar '{}': {err}",
            path.display()
        ))
    })?;
    Ok(Some(info))
}

fn file_stem_string(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|stem| stem.to_str())
        .map(ToOwned::to_owned)
}

fn sanitize_signal_name(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (index, ch) in value.chars().enumerate() {
        let valid = ch.is_ascii_alphanumeric() || ch == '_';
        if index == 0 {
            if ch.is_ascii_alphabetic() || ch == '_' {
                out.push(ch);
            } else if valid {
                out.push('_');
                out.push(ch);
            } else {
                out.push('_');
            }
        } else if valid {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

fn is_raw_zkir(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key("version") && object.contains_key("instructions"))
}

fn field_element_from_hex(raw: &str, field: FieldId) -> ZkfResult<FieldElement> {
    let normalized = if raw.is_empty() { "0" } else { raw };
    let bigint = BigInt::parse_bytes(normalized.as_bytes(), 16).ok_or_else(|| {
        ZkfError::InvalidArtifact(format!(
            "compact zkir load_imm literal '{raw}' is not valid hex"
        ))
    })?;
    Ok(FieldElement::from_bigint_with_field(bigint, field))
}

fn merge_visibility(values: &[Visibility]) -> Visibility {
    if values.contains(&Visibility::Private) {
        Visibility::Private
    } else if values.contains(&Visibility::Public) {
        Visibility::Public
    } else {
        Visibility::Constant
    }
}

fn guard_is_compile_time_bool(builder: &CompactBuilder, var: usize) -> ZkfResult<bool> {
    let expr = builder.expr_for_var(var)?;
    let Expr::Const(value) = expr else {
        return Err(ZkfError::InvalidArtifact(format!(
            "compact pi_skip guard var {var} is not a compile-time constant"
        )));
    };
    let normalized = value.normalized_bigint(builder.program.field)?;
    if normalized.is_zero() {
        Ok(false)
    } else if normalized.is_one() {
        Ok(true)
    } else {
        Err(ZkfError::InvalidArtifact(format!(
            "compact pi_skip guard var {var} must be 0 or 1, found {normalized}"
        )))
    }
}

fn compact_type_label(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    let type_name = object.get("type-name")?.as_str()?;
    if type_name == "Uint" {
        let maxval = object.get("maxval")?;
        let maxval = if let Some(text) = maxval.as_str() {
            BigInt::parse_bytes(text.as_bytes(), 10)?
        } else if let Some(number) = maxval.as_u64() {
            BigInt::from(number)
        } else {
            return None;
        };
        let mut bits = 0usize;
        let mut limit = maxval;
        while limit > BigInt::zero() {
            limit >>= 1usize;
            bits += 1;
        }
        if bits == 0 {
            bits = 1;
        }
        return Some(format!("Uint<{bits}>"));
    }
    Some(type_name.to_string())
}
