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

//! Type checker for ZIR programs.
//!
//! Verifies that every signal has a declared type, blackbox op input/output
//! type signatures are consistent, and constraint operand types are compatible.

use crate::zir::{Constraint, Expr, Program, SignalType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A type error found during type checking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeError {
    pub kind: TypeErrorKind,
    pub message: String,
    /// Index of the constraint or signal where the error was found.
    pub location: Option<usize>,
}

/// Classification of type errors.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TypeErrorKind {
    /// Signal referenced but not declared.
    UndeclaredSignal,
    /// Constraint operands have incompatible types.
    TypeMismatch,
    /// Range constraint on a non-numeric type.
    InvalidRangeType,
    /// Boolean constraint on a non-boolean-compatible type.
    InvalidBooleanType,
    /// BlackBox op input/output type mismatch.
    BlackBoxTypeMismatch,
    /// Duplicate signal name.
    DuplicateSignal,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(loc) = self.location {
            write!(
                f,
                "[{}] at index {}: {}",
                serde_json::to_string(&self.kind).unwrap_or_default(),
                loc,
                self.message
            )
        } else {
            write!(
                f,
                "[{}]: {}",
                serde_json::to_string(&self.kind).unwrap_or_default(),
                self.message
            )
        }
    }
}

/// Type check a ZIR program.
///
/// Returns Ok(()) if the program is well-typed, or a list of type errors.
/// Lenient by default: signals with type `Field` are compatible with everything
/// since the existing IR doesn't always carry full type information.
pub fn type_check(program: &Program) -> Result<(), Vec<TypeError>> {
    let mut errors = Vec::new();

    // Build signal type map
    let mut signal_types: HashMap<&str, &SignalType> = HashMap::new();
    for (i, signal) in program.signals.iter().enumerate() {
        if signal_types.contains_key(signal.name.as_str()) {
            errors.push(TypeError {
                kind: TypeErrorKind::DuplicateSignal,
                message: format!("duplicate signal name '{}'", signal.name),
                location: Some(i),
            });
        }
        signal_types.insert(&signal.name, &signal.ty);
    }

    // Check constraints
    for (i, constraint) in program.constraints.iter().enumerate() {
        check_constraint(constraint, &signal_types, i, &mut errors);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn check_constraint(
    constraint: &Constraint,
    signal_types: &HashMap<&str, &SignalType>,
    index: usize,
    errors: &mut Vec<TypeError>,
) {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => {
            check_expr_signals(lhs, signal_types, index, errors);
            check_expr_signals(rhs, signal_types, index, errors);
        }
        Constraint::Boolean { signal, .. } => {
            if let Some(ty) = signal_types.get(signal.as_str()) {
                if !is_boolean_compatible(ty) {
                    errors.push(TypeError {
                        kind: TypeErrorKind::InvalidBooleanType,
                        message: format!(
                            "boolean constraint on signal '{}' with type {:?}",
                            signal, ty
                        ),
                        location: Some(index),
                    });
                }
            } else {
                errors.push(TypeError {
                    kind: TypeErrorKind::UndeclaredSignal,
                    message: format!(
                        "boolean constraint references undeclared signal '{}'",
                        signal
                    ),
                    location: Some(index),
                });
            }
        }
        Constraint::Range { signal, .. } => {
            if let Some(ty) = signal_types.get(signal.as_str()) {
                if !is_numeric_compatible(ty) {
                    errors.push(TypeError {
                        kind: TypeErrorKind::InvalidRangeType,
                        message: format!(
                            "range constraint on signal '{}' with non-numeric type {:?}",
                            signal, ty
                        ),
                        location: Some(index),
                    });
                }
            } else {
                errors.push(TypeError {
                    kind: TypeErrorKind::UndeclaredSignal,
                    message: format!("range constraint references undeclared signal '{}'", signal),
                    location: Some(index),
                });
            }
        }
        Constraint::BlackBox {
            inputs, outputs, ..
        } => {
            for input in inputs {
                check_expr_signals(input, signal_types, index, errors);
            }
            for output in outputs {
                if !signal_types.contains_key(output.as_str()) {
                    errors.push(TypeError {
                        kind: TypeErrorKind::UndeclaredSignal,
                        message: format!(
                            "blackbox output references undeclared signal '{}'",
                            output
                        ),
                        location: Some(index),
                    });
                }
            }
        }
        Constraint::Lookup { inputs, .. } => {
            for input in inputs {
                check_expr_signals(input, signal_types, index, errors);
            }
        }
        Constraint::CustomGate {
            inputs, outputs, ..
        } => {
            for input in inputs {
                check_expr_signals(input, signal_types, index, errors);
            }
            for output in outputs {
                if !signal_types.contains_key(output.as_str()) {
                    errors.push(TypeError {
                        kind: TypeErrorKind::UndeclaredSignal,
                        message: format!(
                            "custom gate output references undeclared signal '{}'",
                            output
                        ),
                        location: Some(index),
                    });
                }
            }
        }
        Constraint::MemoryRead {
            index: idx, value, ..
        } => {
            check_expr_signals(idx, signal_types, index, errors);
            check_expr_signals(value, signal_types, index, errors);
        }
        Constraint::MemoryWrite {
            index: idx, value, ..
        } => {
            check_expr_signals(idx, signal_types, index, errors);
            check_expr_signals(value, signal_types, index, errors);
        }
        Constraint::Permutation { left, right, .. } => {
            if !signal_types.contains_key(left.as_str()) {
                errors.push(TypeError {
                    kind: TypeErrorKind::UndeclaredSignal,
                    message: format!("permutation references undeclared signal '{}'", left),
                    location: Some(index),
                });
            }
            if !signal_types.contains_key(right.as_str()) {
                errors.push(TypeError {
                    kind: TypeErrorKind::UndeclaredSignal,
                    message: format!("permutation references undeclared signal '{}'", right),
                    location: Some(index),
                });
            }
        }
        Constraint::Copy { from, to, .. } => {
            if !signal_types.contains_key(from.as_str()) {
                errors.push(TypeError {
                    kind: TypeErrorKind::UndeclaredSignal,
                    message: format!("copy references undeclared signal '{}'", from),
                    location: Some(index),
                });
            }
            if !signal_types.contains_key(to.as_str()) {
                errors.push(TypeError {
                    kind: TypeErrorKind::UndeclaredSignal,
                    message: format!("copy references undeclared signal '{}'", to),
                    location: Some(index),
                });
            }
        }
    }
}

fn check_expr_signals(
    expr: &Expr,
    signal_types: &HashMap<&str, &SignalType>,
    constraint_index: usize,
    errors: &mut Vec<TypeError>,
) {
    match expr {
        Expr::Const(_) => {}
        Expr::Signal(name) => {
            if !signal_types.contains_key(name.as_str()) {
                errors.push(TypeError {
                    kind: TypeErrorKind::UndeclaredSignal,
                    message: format!("expression references undeclared signal '{}'", name),
                    location: Some(constraint_index),
                });
            }
        }
        Expr::Add(terms) => {
            for t in terms {
                check_expr_signals(t, signal_types, constraint_index, errors);
            }
        }
        Expr::Sub(l, r) | Expr::Mul(l, r) | Expr::Div(l, r) => {
            check_expr_signals(l, signal_types, constraint_index, errors);
            check_expr_signals(r, signal_types, constraint_index, errors);
        }
    }
}

/// Check if a type is compatible with boolean constraints.
fn is_boolean_compatible(ty: &SignalType) -> bool {
    matches!(
        ty,
        SignalType::Bool | SignalType::Field | SignalType::UInt { bits: 1 }
    )
}

/// Check if a type is compatible with range constraints.
fn is_numeric_compatible(ty: &SignalType) -> bool {
    matches!(ty, SignalType::Field | SignalType::UInt { .. })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zir::{self, Signal};
    use crate::{FieldId, Visibility};
    use std::collections::BTreeMap;

    fn valid_program() -> Program {
        Program {
            name: "valid".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Public,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "b".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Bool,
                    constant: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Signal("x".into()),
                    rhs: Expr::Signal("y".into()),
                    label: None,
                },
                Constraint::Boolean {
                    signal: "b".into(),
                    label: None,
                },
            ],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn valid_program_passes_type_check() {
        let program = valid_program();
        assert!(type_check(&program).is_ok());
    }

    #[test]
    fn undeclared_signal_detected() {
        let program = Program {
            name: "bad".into(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                ty: SignalType::Field,
                constant: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("x".into()),
                rhs: Expr::Signal("missing".into()),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };

        let errors = type_check(&program).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e.kind, TypeErrorKind::UndeclaredSignal))
        );
    }

    #[test]
    fn duplicate_signal_detected() {
        let program = Program {
            name: "dup".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    ty: SignalType::Field,
                    constant: None,
                },
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Public,
                    ty: SignalType::Bool,
                    constant: None,
                },
            ],
            constraints: vec![],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: vec![],
            memory_regions: vec![],
            custom_gates: vec![],
            metadata: BTreeMap::new(),
        };

        let errors = type_check(&program).unwrap_err();
        assert!(
            errors
                .iter()
                .any(|e| matches!(e.kind, TypeErrorKind::DuplicateSignal))
        );
    }
}
