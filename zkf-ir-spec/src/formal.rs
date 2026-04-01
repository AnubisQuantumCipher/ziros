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

//! Formal denotational semantics for ZKF IR.
//!
//! This module defines the mathematical semantics of ZKF IR programs
//! in a style amenable to later translation into Lean 4 or Coq.
//! Each IR construct has a denotation as a mathematical object.
//!
//! # Semantic domains
//!
//! - **Expressions** are denoted as functions from assignments to field values:
//!   `[[e]](sigma) : F_p` where sigma is an assignment and F_p is the field.
//!
//! - **Constraints** are denoted as predicates on assignments:
//!   `[[C]](sigma) : bool` -- true iff the constraint is satisfied.
//!
//! - **Programs** are denoted as the set of satisfying assignments:
//!   `[[P]] = { sigma : Signals -> F_p | forall C in P.constraints, [[C]](sigma) }`
//!
//! # Normalization soundness
//!
//! The key theorem is that normalization preserves semantics:
//! `forall P: [[normalize(P)]] = [[P]]`
//!
//! This module provides the theorem *statements* and proof sketches.
//! Full mechanized proofs are deferred to Lean 4 translation.

use serde::{Deserialize, Serialize};

/// A field element in the abstract semantics (modeled as arbitrary-precision).
/// In the formal model, all arithmetic is modular over the program's field.
pub type SemValue = num_bigint::BigInt;

/// An assignment maps signal names to field values.
pub type Assignment = std::collections::BTreeMap<String, SemValue>;

// ---------------------------------------------------------------------------
// Expression semantics
// ---------------------------------------------------------------------------

/// Semantic domain: the denotation of an expression is a function
/// from assignments to field values.
///
/// `[[e]](sigma) : F_p` where sigma is an assignment and F_p is the field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExprSemantics {
    /// Human-readable description of the denotation.
    pub description: String,
    /// The kind of expression.
    pub kind: ExprSemKind,
}

/// The semantic kind of an expression denotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExprSemKind {
    /// `[[c]](sigma) = c`
    Constant { value: String },
    /// `[[x]](sigma) = sigma(x)`
    Variable { name: String },
    /// `[[e1 + e2 + ...]](sigma) = [[e1]](sigma) + [[e2]](sigma) + ... (mod p)`
    Sum { operands: Vec<ExprSemantics> },
    /// `[[e1 - e2]](sigma) = [[e1]](sigma) - [[e2]](sigma) (mod p)`
    Difference {
        left: Box<ExprSemantics>,
        right: Box<ExprSemantics>,
    },
    /// `[[e1 * e2]](sigma) = [[e1]](sigma) * [[e2]](sigma) (mod p)`
    Product {
        left: Box<ExprSemantics>,
        right: Box<ExprSemantics>,
    },
    /// `[[e1 / e2]](sigma) = [[e1]](sigma) * [[e2]](sigma)^{-1} (mod p)`,
    /// undefined if `[[e2]](sigma) = 0`.
    Quotient {
        left: Box<ExprSemantics>,
        right: Box<ExprSemantics>,
    },
}

// ---------------------------------------------------------------------------
// Constraint semantics
// ---------------------------------------------------------------------------

/// The denotation of a constraint: a predicate on assignments.
///
/// `[[C]](sigma) : bool` -- true iff the constraint is satisfied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintSemantics {
    /// Human-readable description.
    pub description: String,
    /// The semantic kind.
    pub kind: ConstraintSemKind,
}

/// The semantic kind of a constraint denotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintSemKind {
    /// `[[lhs = rhs]](sigma)  <=>  [[lhs]](sigma) = [[rhs]](sigma)`
    Equal {
        lhs: ExprSemantics,
        rhs: ExprSemantics,
    },
    /// `[[boolean(x)]](sigma)  <=>  sigma(x) in {0, 1}`
    Boolean { signal: String },
    /// `[[range(x, n)]](sigma)  <=>  0 <= sigma(x) < 2^n`
    Range { signal: String, bits: u32 },
    /// `[[blackbox(op, inputs, outputs)]](sigma)  <=>  outputs = op(inputs)`
    ///
    /// Inputs are full expression denotations (not just signal names).
    BlackBox {
        op: String,
        inputs: Vec<ExprSemantics>,
        outputs: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Signal semantics
// ---------------------------------------------------------------------------

/// The denotation of a signal declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalSemantics {
    /// Signal name.
    pub name: String,
    /// Visibility class (`"public"`, `"private"`, or `"constant"`).
    pub visibility: String,
    /// Semantic domain, e.g., `"F_p"`, `"{0,1}"`, or `"[0, 2^n)"`.
    pub domain: String,
}

// ---------------------------------------------------------------------------
// Program semantics
// ---------------------------------------------------------------------------

/// The denotation of a program: the set of satisfying assignments.
///
/// `[[P]] = { sigma : Signals -> F_p | forall C in P.constraints, [[C]](sigma) }`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramSemantics {
    /// Program name.
    pub name: String,
    /// The field modulus (as a decimal string), or `"unknown"` if not resolvable.
    pub field_modulus: String,
    /// Denotations of all signal declarations.
    pub signals: Vec<SignalSemantics>,
    /// Denotations of all constraints.
    pub constraints: Vec<ConstraintSemantics>,
}

// ---------------------------------------------------------------------------
// Equivalence theorems
// ---------------------------------------------------------------------------

/// Semantic equivalence theorem statement.
///
/// Two programs P1 and P2 are semantically equivalent iff
/// for all assignments sigma: `[[P1]](sigma) <=> [[P2]](sigma)`.
///
/// Normalization preserves semantics:
/// `forall P: [[normalize(P)]] = [[P]]`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivalenceTheorem {
    /// Theorem name (machine-readable identifier).
    pub name: String,
    /// Formal statement in mathematical notation.
    pub statement: String,
    /// Proof sketch or justification.
    pub proof_sketch: String,
    /// Current verification status.
    pub status: TheoremStatus,
}

/// The verification status of a theorem.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TheoremStatus {
    /// Conjectured but not formally proven.
    Conjectured,
    /// Proven by testing (property-based tests pass).
    TestedNotProven,
    /// Formally proven in Lean 4 / Coq.
    FormallyProven,
}

// ---------------------------------------------------------------------------
// Normalization soundness theorems
// ---------------------------------------------------------------------------

/// Return the normalization soundness theorems.
///
/// Each theorem states a semantic preservation property of a specific
/// normalization rewrite rule, plus the top-level composition theorem.
pub fn normalization_theorems() -> Vec<EquivalenceTheorem> {
    vec![
        EquivalenceTheorem {
            name: "algebraic_identity_mul_one".into(),
            statement: "forall e: [[Mul(1, e)]](sigma) = [[e]](sigma)".into(),
            proof_sketch: "1 * x = x in any field F_p".into(),
            status: TheoremStatus::TestedNotProven,
        },
        EquivalenceTheorem {
            name: "algebraic_identity_add_zero".into(),
            statement: "forall e: [[Add(0, e)]](sigma) = [[e]](sigma)".into(),
            proof_sketch: "0 + x = x in any field F_p".into(),
            status: TheoremStatus::TestedNotProven,
        },
        EquivalenceTheorem {
            name: "algebraic_identity_mul_zero".into(),
            statement: "forall e: [[Mul(0, e)]](sigma) = 0".into(),
            proof_sketch: "0 * x = 0 in any field F_p".into(),
            status: TheoremStatus::TestedNotProven,
        },
        EquivalenceTheorem {
            name: "algebraic_identity_sub_zero".into(),
            statement: "forall e: [[Sub(e, 0)]](sigma) = [[e]](sigma)".into(),
            proof_sketch: "x - 0 = x in any field F_p".into(),
            status: TheoremStatus::TestedNotProven,
        },
        EquivalenceTheorem {
            name: "algebraic_identity_div_one".into(),
            statement: "forall e: [[Div(e, 1)]](sigma) = [[e]](sigma)".into(),
            proof_sketch: "x / 1 = x in any field F_p".into(),
            status: TheoremStatus::TestedNotProven,
        },
        EquivalenceTheorem {
            name: "dead_signal_elimination".into(),
            statement: "forall P, forall s not in constraints(P): [[remove_signal(P, s)]] = [[P]]"
                .into(),
            proof_sketch: "Unused signals do not affect constraint satisfaction. \
                           The satisfying-assignment set projected onto live signals is unchanged."
                .into(),
            status: TheoremStatus::TestedNotProven,
        },
        EquivalenceTheorem {
            name: "normalization_preserves_semantics".into(),
            statement: "forall P: [[normalize(P)]] = [[P]]".into(),
            proof_sketch:
                "Composition of sound rewrites. Each algebraic identity preserves [[.]], \
                           dead signal elimination preserves [[.]], canonical ordering is purely \
                           syntactic and does not alter the constraint set."
                    .into(),
            status: TheoremStatus::TestedNotProven,
        },
        EquivalenceTheorem {
            name: "normalization_idempotent".into(),
            statement: "forall P: normalize(normalize(P)) = normalize(P)".into(),
            proof_sketch: "All rewrites reach a fixed point; canonical ordering is deterministic."
                .into(),
            status: TheoremStatus::TestedNotProven,
        },
    ]
}

// ---------------------------------------------------------------------------
// Denotation functions: IR v2 -> Semantics
// ---------------------------------------------------------------------------

/// Generate a denotation for an IR v2 expression.
///
/// Maps each syntactic `Expr` node to its corresponding semantic description.
pub fn denote_expr(expr: &zkf_core::Expr) -> ExprSemantics {
    match expr {
        zkf_core::Expr::Const(c) => ExprSemantics {
            description: format!("constant {}", c.to_decimal_string()),
            kind: ExprSemKind::Constant {
                value: c.to_decimal_string(),
            },
        },
        zkf_core::Expr::Signal(name) => ExprSemantics {
            description: format!("sigma({name})"),
            kind: ExprSemKind::Variable { name: name.clone() },
        },
        zkf_core::Expr::Add(terms) => ExprSemantics {
            description: format!("sum of {} terms", terms.len()),
            kind: ExprSemKind::Sum {
                operands: terms.iter().map(denote_expr).collect(),
            },
        },
        zkf_core::Expr::Sub(a, b) => ExprSemantics {
            description: "difference".into(),
            kind: ExprSemKind::Difference {
                left: Box::new(denote_expr(a)),
                right: Box::new(denote_expr(b)),
            },
        },
        zkf_core::Expr::Mul(a, b) => ExprSemantics {
            description: "product".into(),
            kind: ExprSemKind::Product {
                left: Box::new(denote_expr(a)),
                right: Box::new(denote_expr(b)),
            },
        },
        zkf_core::Expr::Div(a, b) => ExprSemantics {
            description: "quotient".into(),
            kind: ExprSemKind::Quotient {
                left: Box::new(denote_expr(a)),
                right: Box::new(denote_expr(b)),
            },
        },
    }
}

/// Generate a denotation for an IR v2 constraint.
///
/// Maps each syntactic `Constraint` node to its corresponding semantic predicate.
pub fn denote_constraint(c: &zkf_core::Constraint) -> ConstraintSemantics {
    match c {
        zkf_core::Constraint::Equal { lhs, rhs, label } => ConstraintSemantics {
            description: format!(
                "equality{}",
                label
                    .as_ref()
                    .map(|l| format!(" ({l})"))
                    .unwrap_or_default()
            ),
            kind: ConstraintSemKind::Equal {
                lhs: denote_expr(lhs),
                rhs: denote_expr(rhs),
            },
        },
        zkf_core::Constraint::Boolean { signal, .. } => ConstraintSemantics {
            description: format!("{signal} in {{0, 1}}"),
            kind: ConstraintSemKind::Boolean {
                signal: signal.clone(),
            },
        },
        zkf_core::Constraint::Range { signal, bits, .. } => ConstraintSemantics {
            description: format!("0 <= {signal} < 2^{bits}"),
            kind: ConstraintSemKind::Range {
                signal: signal.clone(),
                bits: *bits,
            },
        },
        zkf_core::Constraint::BlackBox {
            op,
            inputs,
            outputs,
            ..
        } => ConstraintSemantics {
            description: format!(
                "{op:?}({} -> {})",
                inputs
                    .iter()
                    .map(expr_summary)
                    .collect::<Vec<_>>()
                    .join(", "),
                outputs.join(", ")
            ),
            kind: ConstraintSemKind::BlackBox {
                op: format!("{op:?}"),
                inputs: inputs.iter().map(denote_expr).collect(),
                outputs: outputs.clone(),
            },
        },
        zkf_core::Constraint::Lookup {
            inputs,
            table,
            outputs,
            label,
        } => ConstraintSemantics {
            description: format!(
                "lookup({}){}",
                table,
                label
                    .as_ref()
                    .map(|l| format!(" ({l})"))
                    .unwrap_or_default()
            ),
            kind: ConstraintSemKind::BlackBox {
                op: format!("Lookup({})", table),
                inputs: inputs.iter().map(denote_expr).collect(),
                outputs: outputs.clone().unwrap_or_default(),
            },
        },
    }
}

/// Generate a denotation for an IR v2 signal.
pub fn denote_signal(s: &zkf_core::Signal) -> SignalSemantics {
    let visibility = format!("{:?}", s.visibility).to_lowercase();
    let domain = match s.visibility {
        zkf_core::Visibility::Constant => {
            if let Some(ref val) = s.constant {
                format!("{{{}}}", val.to_decimal_string())
            } else {
                "F_p".into()
            }
        }
        _ => "F_p".into(),
    };
    SignalSemantics {
        name: s.name.clone(),
        visibility,
        domain,
    }
}

/// Generate a full denotation for an IR v2 program.
pub fn denote_program(p: &zkf_core::Program) -> ProgramSemantics {
    let field_modulus = match p.field {
        zkf_core::FieldId::Bn254 => {
            "21888242871839275222246405745257275088548364400416034343698204186575808495617".into()
        }
        zkf_core::FieldId::Bls12_381 => {
            "52435875175126190479447740508185965837690552500527637822603658699938581184513".into()
        }
        _ => format!("modulus_of({:?})", p.field),
    };
    ProgramSemantics {
        name: p.name.clone(),
        field_modulus,
        signals: p.signals.iter().map(denote_signal).collect(),
        constraints: p.constraints.iter().map(denote_constraint).collect(),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Short summary of an expression for description strings.
fn expr_summary(expr: &zkf_core::Expr) -> String {
    match expr {
        zkf_core::Expr::Const(c) => c.to_decimal_string(),
        zkf_core::Expr::Signal(name) => name.clone(),
        zkf_core::Expr::Add(terms) => format!("add({})", terms.len()),
        zkf_core::Expr::Sub(..) => "sub(..)".into(),
        zkf_core::Expr::Mul(..) => "mul(..)".into(),
        zkf_core::Expr::Div(..) => "div(..)".into(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{BlackBoxOp, Constraint, Expr, FieldElement, FieldId, Signal, Visibility};

    // -- denote_expr tests --------------------------------------------------

    #[test]
    fn denote_const_expr() {
        let e = Expr::Const(FieldElement::from_i64(42));
        let sem = denote_expr(&e);
        assert_eq!(sem.description, "constant 42");
        match &sem.kind {
            ExprSemKind::Constant { value } => assert_eq!(value, "42"),
            other => panic!("expected Constant, got {other:?}"),
        }
    }

    #[test]
    fn denote_signal_expr() {
        let e = Expr::Signal("x".into());
        let sem = denote_expr(&e);
        assert_eq!(sem.description, "sigma(x)");
        match &sem.kind {
            ExprSemKind::Variable { name } => assert_eq!(name, "x"),
            other => panic!("expected Variable, got {other:?}"),
        }
    }

    #[test]
    fn denote_add_expr() {
        let e = Expr::Add(vec![
            Expr::Signal("a".into()),
            Expr::Signal("b".into()),
            Expr::Const(FieldElement::from_i64(1)),
        ]);
        let sem = denote_expr(&e);
        assert_eq!(sem.description, "sum of 3 terms");
        match &sem.kind {
            ExprSemKind::Sum { operands } => assert_eq!(operands.len(), 3),
            other => panic!("expected Sum, got {other:?}"),
        }
    }

    #[test]
    fn denote_sub_expr() {
        let e = Expr::Sub(
            Box::new(Expr::Signal("x".into())),
            Box::new(Expr::Const(FieldElement::from_i64(5))),
        );
        let sem = denote_expr(&e);
        assert_eq!(sem.description, "difference");
        match &sem.kind {
            ExprSemKind::Difference { left, right } => {
                assert!(matches!(&left.kind, ExprSemKind::Variable { name } if name == "x"));
                assert!(matches!(&right.kind, ExprSemKind::Constant { value } if value == "5"));
            }
            other => panic!("expected Difference, got {other:?}"),
        }
    }

    #[test]
    fn denote_mul_expr() {
        let e = Expr::Mul(
            Box::new(Expr::Signal("a".into())),
            Box::new(Expr::Signal("b".into())),
        );
        let sem = denote_expr(&e);
        assert_eq!(sem.description, "product");
        match &sem.kind {
            ExprSemKind::Product { left, right } => {
                assert!(matches!(&left.kind, ExprSemKind::Variable { name } if name == "a"));
                assert!(matches!(&right.kind, ExprSemKind::Variable { name } if name == "b"));
            }
            other => panic!("expected Product, got {other:?}"),
        }
    }

    #[test]
    fn denote_div_expr() {
        let e = Expr::Div(
            Box::new(Expr::Signal("n".into())),
            Box::new(Expr::Const(FieldElement::from_i64(3))),
        );
        let sem = denote_expr(&e);
        assert_eq!(sem.description, "quotient");
        match &sem.kind {
            ExprSemKind::Quotient { left, right } => {
                assert!(matches!(&left.kind, ExprSemKind::Variable { name } if name == "n"));
                assert!(matches!(&right.kind, ExprSemKind::Constant { value } if value == "3"));
            }
            other => panic!("expected Quotient, got {other:?}"),
        }
    }

    // -- denote_constraint tests --------------------------------------------

    #[test]
    fn denote_equal_constraint() {
        let c = Constraint::Equal {
            lhs: Expr::Signal("x".into()),
            rhs: Expr::Const(FieldElement::from_i64(7)),
            label: Some("test_eq".into()),
        };
        let sem = denote_constraint(&c);
        assert!(sem.description.contains("equality"));
        assert!(sem.description.contains("test_eq"));
        match &sem.kind {
            ConstraintSemKind::Equal { lhs, rhs } => {
                assert!(matches!(&lhs.kind, ExprSemKind::Variable { name } if name == "x"));
                assert!(matches!(&rhs.kind, ExprSemKind::Constant { value } if value == "7"));
            }
            other => panic!("expected Equal, got {other:?}"),
        }
    }

    #[test]
    fn denote_equal_constraint_no_label() {
        let c = Constraint::Equal {
            lhs: Expr::Signal("a".into()),
            rhs: Expr::Signal("b".into()),
            label: None,
        };
        let sem = denote_constraint(&c);
        assert_eq!(sem.description, "equality");
    }

    #[test]
    fn denote_boolean_constraint() {
        let c = Constraint::Boolean {
            signal: "flag".into(),
            label: None,
        };
        let sem = denote_constraint(&c);
        assert!(sem.description.contains("flag"));
        match &sem.kind {
            ConstraintSemKind::Boolean { signal } => assert_eq!(signal, "flag"),
            other => panic!("expected Boolean, got {other:?}"),
        }
    }

    #[test]
    fn denote_range_constraint() {
        let c = Constraint::Range {
            signal: "val".into(),
            bits: 8,
            label: None,
        };
        let sem = denote_constraint(&c);
        assert!(sem.description.contains("val"));
        assert!(sem.description.contains("2^8"));
        match &sem.kind {
            ConstraintSemKind::Range { signal, bits } => {
                assert_eq!(signal, "val");
                assert_eq!(*bits, 8);
            }
            other => panic!("expected Range, got {other:?}"),
        }
    }

    #[test]
    fn denote_blackbox_constraint() {
        let c = Constraint::BlackBox {
            op: BlackBoxOp::Poseidon,
            inputs: vec![Expr::Signal("in1".into()), Expr::Signal("in2".into())],
            outputs: vec!["out".into()],
            params: Default::default(),
            label: None,
        };
        let sem = denote_constraint(&c);
        assert!(sem.description.contains("Poseidon"));
        match &sem.kind {
            ConstraintSemKind::BlackBox {
                op,
                inputs,
                outputs,
            } => {
                assert_eq!(op, "Poseidon");
                assert_eq!(inputs.len(), 2);
                assert_eq!(outputs, &["out"]);
            }
            other => panic!("expected BlackBox, got {other:?}"),
        }
    }

    // -- denote_signal tests ------------------------------------------------

    #[test]
    fn denote_public_signal() {
        let s = Signal {
            name: "pub_input".into(),
            visibility: Visibility::Public,
            constant: None,
            ty: None,
        };
        let sem = denote_signal(&s);
        assert_eq!(sem.name, "pub_input");
        assert_eq!(sem.visibility, "public");
        assert_eq!(sem.domain, "F_p");
    }

    #[test]
    fn denote_constant_signal() {
        let s = Signal {
            name: "c".into(),
            visibility: Visibility::Constant,
            constant: Some(FieldElement::from_i64(99)),
            ty: None,
        };
        let sem = denote_signal(&s);
        assert_eq!(sem.name, "c");
        assert_eq!(sem.visibility, "constant");
        assert_eq!(sem.domain, "{99}");
    }

    #[test]
    fn denote_private_signal() {
        let s = Signal {
            name: "witness".into(),
            visibility: Visibility::Private,
            constant: None,
            ty: None,
        };
        let sem = denote_signal(&s);
        assert_eq!(sem.visibility, "private");
        assert_eq!(sem.domain, "F_p");
    }

    // -- denote_program tests -----------------------------------------------

    #[test]
    fn denote_program_basic() {
        let p = zkf_core::Program {
            name: "test_circuit".into(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("x".into()),
                rhs: Expr::Signal("y".into()),
                label: None,
            }],
            ..Default::default()
        };
        let sem = denote_program(&p);
        assert_eq!(sem.name, "test_circuit");
        assert!(sem.field_modulus.starts_with("2188824287"));
        assert_eq!(sem.signals.len(), 2);
        assert_eq!(sem.constraints.len(), 1);
    }

    // -- normalization_theorems tests ---------------------------------------

    #[test]
    fn normalization_theorems_count() {
        let theorems = normalization_theorems();
        assert_eq!(theorems.len(), 8);
    }

    #[test]
    fn normalization_theorems_names_unique() {
        let theorems = normalization_theorems();
        let mut names: Vec<&str> = theorems.iter().map(|t| t.name.as_str()).collect();
        let original_len = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), original_len, "theorem names must be unique");
    }

    #[test]
    fn normalization_theorems_all_tested() {
        let theorems = normalization_theorems();
        for t in &theorems {
            assert_eq!(
                t.status,
                TheoremStatus::TestedNotProven,
                "theorem {} should be TestedNotProven",
                t.name
            );
        }
    }

    #[test]
    fn normalization_theorems_have_expected_names() {
        let theorems = normalization_theorems();
        let names: Vec<&str> = theorems.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"algebraic_identity_mul_one"));
        assert!(names.contains(&"algebraic_identity_add_zero"));
        assert!(names.contains(&"algebraic_identity_mul_zero"));
        assert!(names.contains(&"algebraic_identity_sub_zero"));
        assert!(names.contains(&"algebraic_identity_div_one"));
        assert!(names.contains(&"dead_signal_elimination"));
        assert!(names.contains(&"normalization_preserves_semantics"));
        assert!(names.contains(&"normalization_idempotent"));
    }

    // -- serialization roundtrip tests --------------------------------------

    #[test]
    fn expr_semantics_roundtrip() {
        let sem = ExprSemantics {
            description: "test constant".into(),
            kind: ExprSemKind::Constant { value: "42".into() },
        };
        let json = serde_json::to_string(&sem).unwrap();
        let back: ExprSemantics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.description, "test constant");
        match &back.kind {
            ExprSemKind::Constant { value } => assert_eq!(value, "42"),
            other => panic!("expected Constant after roundtrip, got {other:?}"),
        }
    }

    #[test]
    fn constraint_semantics_roundtrip() {
        let sem = ConstraintSemantics {
            description: "test boolean".into(),
            kind: ConstraintSemKind::Boolean { signal: "b".into() },
        };
        let json = serde_json::to_string(&sem).unwrap();
        let back: ConstraintSemantics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.description, "test boolean");
        match &back.kind {
            ConstraintSemKind::Boolean { signal } => assert_eq!(signal, "b"),
            other => panic!("expected Boolean after roundtrip, got {other:?}"),
        }
    }

    #[test]
    fn program_semantics_roundtrip() {
        let sem = ProgramSemantics {
            name: "roundtrip_test".into(),
            field_modulus:
                "21888242871839275222246405745257275088548364400416034343698204186575808495617"
                    .into(),
            signals: vec![SignalSemantics {
                name: "x".into(),
                visibility: "public".into(),
                domain: "F_p".into(),
            }],
            constraints: vec![ConstraintSemantics {
                description: "equality".into(),
                kind: ConstraintSemKind::Equal {
                    lhs: ExprSemantics {
                        description: "sigma(x)".into(),
                        kind: ExprSemKind::Variable { name: "x".into() },
                    },
                    rhs: ExprSemantics {
                        description: "constant 0".into(),
                        kind: ExprSemKind::Constant { value: "0".into() },
                    },
                },
            }],
        };
        let json = serde_json::to_string_pretty(&sem).unwrap();
        let back: ProgramSemantics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "roundtrip_test");
        assert_eq!(back.signals.len(), 1);
        assert_eq!(back.constraints.len(), 1);
    }

    #[test]
    fn equivalence_theorem_roundtrip() {
        let theorem = EquivalenceTheorem {
            name: "test_theorem".into(),
            statement: "forall x: x = x".into(),
            proof_sketch: "reflexivity".into(),
            status: TheoremStatus::Conjectured,
        };
        let json = serde_json::to_string(&theorem).unwrap();
        let back: EquivalenceTheorem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "test_theorem");
        assert_eq!(back.status, TheoremStatus::Conjectured);
    }

    #[test]
    fn theorem_status_roundtrip() {
        for status in [
            TheoremStatus::Conjectured,
            TheoremStatus::TestedNotProven,
            TheoremStatus::FormallyProven,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: TheoremStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, status);
        }
    }

    #[test]
    fn nested_expr_semantics_roundtrip() {
        let sem = ExprSemantics {
            description: "product".into(),
            kind: ExprSemKind::Product {
                left: Box::new(ExprSemantics {
                    description: "sum of 2 terms".into(),
                    kind: ExprSemKind::Sum {
                        operands: vec![
                            ExprSemantics {
                                description: "sigma(a)".into(),
                                kind: ExprSemKind::Variable { name: "a".into() },
                            },
                            ExprSemantics {
                                description: "constant 1".into(),
                                kind: ExprSemKind::Constant { value: "1".into() },
                            },
                        ],
                    },
                }),
                right: Box::new(ExprSemantics {
                    description: "sigma(b)".into(),
                    kind: ExprSemKind::Variable { name: "b".into() },
                }),
            },
        };
        let json = serde_json::to_string(&sem).unwrap();
        let back: ExprSemantics = serde_json::from_str(&json).unwrap();
        match &back.kind {
            ExprSemKind::Product { left, right } => {
                match &left.kind {
                    ExprSemKind::Sum { operands } => assert_eq!(operands.len(), 2),
                    other => panic!("expected Sum in left, got {other:?}"),
                }
                assert!(matches!(&right.kind, ExprSemKind::Variable { name } if name == "b"));
            }
            other => panic!("expected Product after roundtrip, got {other:?}"),
        }
    }

    #[test]
    fn denote_expr_nested_structure() {
        // Build: (x + 1) * y
        let e = Expr::Mul(
            Box::new(Expr::Add(vec![
                Expr::Signal("x".into()),
                Expr::Const(FieldElement::from_i64(1)),
            ])),
            Box::new(Expr::Signal("y".into())),
        );
        let sem = denote_expr(&e);
        match &sem.kind {
            ExprSemKind::Product { left, right } => {
                match &left.kind {
                    ExprSemKind::Sum { operands } => {
                        assert_eq!(operands.len(), 2);
                        assert!(
                            matches!(&operands[0].kind, ExprSemKind::Variable { name } if name == "x")
                        );
                        assert!(
                            matches!(&operands[1].kind, ExprSemKind::Constant { value } if value == "1")
                        );
                    }
                    other => panic!("expected Sum, got {other:?}"),
                }
                assert!(matches!(&right.kind, ExprSemKind::Variable { name } if name == "y"));
            }
            other => panic!("expected Product, got {other:?}"),
        }
    }

    #[test]
    fn blackbox_constraint_with_expr_inputs() {
        // Verify that BlackBox inputs (which are Expr, not just signal names)
        // are properly denoted.
        let c = Constraint::BlackBox {
            op: BlackBoxOp::Sha256,
            inputs: vec![
                Expr::Add(vec![Expr::Signal("a".into()), Expr::Signal("b".into())]),
                Expr::Const(FieldElement::from_i64(0)),
            ],
            outputs: vec!["hash_out".into()],
            params: Default::default(),
            label: Some("hash_check".into()),
        };
        let sem = denote_constraint(&c);
        match &sem.kind {
            ConstraintSemKind::BlackBox {
                op,
                inputs,
                outputs,
            } => {
                assert_eq!(op, "Sha256");
                assert_eq!(inputs.len(), 2);
                assert!(
                    matches!(&inputs[0].kind, ExprSemKind::Sum { operands } if operands.len() == 2)
                );
                assert!(matches!(&inputs[1].kind, ExprSemKind::Constant { value } if value == "0"));
                assert_eq!(outputs, &["hash_out"]);
            }
            other => panic!("expected BlackBox, got {other:?}"),
        }
    }
}
