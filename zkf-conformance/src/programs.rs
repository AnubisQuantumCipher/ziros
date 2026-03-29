//! Canonical conformance test programs at increasing complexity.
//!
//! Each program is a self-contained [`ConformanceProgram`] with inputs and expected
//! outputs, ranging from trivial identity to quadratic sum-of-squares.

use std::collections::BTreeMap;
use zkf_core::{
    Constraint, Expr, FieldElement, FieldId, Program, Signal, Visibility, WitnessAssignment,
    WitnessInputs, WitnessPlan,
};

/// A conformance test program with its expected inputs.
pub struct ConformanceProgram {
    pub name: String,
    pub description: String,
    pub program: Program,
    pub inputs: WitnessInputs,
    pub expected_public_outputs: Vec<FieldElement>,
}

/// Return all conformance test programs for the given field.
pub fn all_conformance_programs(field: FieldId) -> Vec<ConformanceProgram> {
    vec![
        identity(field),
        multiply(field),
        range_check(field),
        boolean(field),
        add_chain(field),
        quadratic(field),
    ]
}

/// Identity: 1 signal, 1 constraint (x == x).
fn identity(field: FieldId) -> ConformanceProgram {
    ConformanceProgram {
        name: "identity".into(),
        description: "Simplest possible circuit: x == x".into(),
        program: Program {
            name: "identity".into(),
            field,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Signal("x".into()),
                rhs: Expr::Signal("x".into()),
                label: Some("identity".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        },
        inputs: BTreeMap::from([("x".into(), FieldElement::from_i64(42))]),
        expected_public_outputs: vec![FieldElement::from_i64(42)],
    }
}

/// Multiply: x * y == out.
fn multiply(field: FieldId) -> ConformanceProgram {
    ConformanceProgram {
        name: "multiply".into(),
        description: "Basic multiplication: x * y == out".into(),
        program: Program {
            name: "multiply".into(),
            field,
            signals: vec![
                Signal {
                    name: "x".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal("x".into())),
                    Box::new(Expr::Signal("y".into())),
                ),
                rhs: Expr::Signal("out".into()),
                label: Some("multiply".into()),
            }],
            witness_plan: WitnessPlan {
                assignments: vec![WitnessAssignment {
                    target: "out".into(),
                    expr: Expr::Mul(
                        Box::new(Expr::Signal("x".into())),
                        Box::new(Expr::Signal("y".into())),
                    ),
                }],
                ..Default::default()
            },
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        },
        inputs: BTreeMap::from([
            ("x".into(), FieldElement::from_i64(3)),
            ("y".into(), FieldElement::from_i64(7)),
        ]),
        expected_public_outputs: vec![FieldElement::from_i64(21)],
    }
}

/// Range check: value < 2^8.
fn range_check(field: FieldId) -> ConformanceProgram {
    ConformanceProgram {
        name: "range_check".into(),
        description: "Range constraint: value < 2^8".into(),
        program: Program {
            name: "range_check".into(),
            field,
            signals: vec![Signal {
                name: "value".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Range {
                signal: "value".into(),
                bits: 8,
                label: Some("range_8bit".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        },
        inputs: BTreeMap::from([("value".into(), FieldElement::from_i64(200))]),
        expected_public_outputs: vec![FieldElement::from_i64(200)],
    }
}

/// Boolean constraint: b is 0 or 1.
fn boolean(field: FieldId) -> ConformanceProgram {
    ConformanceProgram {
        name: "boolean".into(),
        description: "Boolean constraint: b in {0, 1}".into(),
        program: Program {
            name: "boolean".into(),
            field,
            signals: vec![Signal {
                name: "b".into(),
                visibility: Visibility::Public,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Boolean {
                signal: "b".into(),
                label: Some("boolean".into()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        },
        inputs: BTreeMap::from([("b".into(), FieldElement::from_i64(1))]),
        expected_public_outputs: vec![FieldElement::from_i64(1)],
    }
}

/// Add chain: a + b == c, c + d == out, with a nonlinear anchor on b*d.
fn add_chain(field: FieldId) -> ConformanceProgram {
    ConformanceProgram {
        name: "add_chain".into(),
        description: "Chained addition: a + b == c, c + d == out, plus nonlinear anchoring on b*d"
            .into(),
        program: Program {
            name: "add_chain".into(),
            field,
            signals: vec![
                Signal {
                    name: "a".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "b".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "c".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "d".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "anchor".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Add(vec![Expr::Signal("a".into()), Expr::Signal("b".into())]),
                    rhs: Expr::Signal("c".into()),
                    label: Some("sum_ab".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Add(vec![Expr::Signal("c".into()), Expr::Signal("d".into())]),
                    rhs: Expr::Signal("out".into()),
                    label: Some("sum_cd".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Signal("anchor".into()),
                    rhs: Expr::Mul(
                        Box::new(Expr::Signal("b".into())),
                        Box::new(Expr::Signal("d".into())),
                    ),
                    label: Some("nonlinear_anchor".into()),
                },
            ],
            witness_plan: WitnessPlan {
                assignments: vec![
                    WitnessAssignment {
                        target: "c".into(),
                        expr: Expr::Add(vec![Expr::Signal("a".into()), Expr::Signal("b".into())]),
                    },
                    WitnessAssignment {
                        target: "out".into(),
                        expr: Expr::Add(vec![Expr::Signal("c".into()), Expr::Signal("d".into())]),
                    },
                    WitnessAssignment {
                        target: "anchor".into(),
                        expr: Expr::Mul(
                            Box::new(Expr::Signal("b".into())),
                            Box::new(Expr::Signal("d".into())),
                        ),
                    },
                ],
                ..Default::default()
            },
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        },
        inputs: BTreeMap::from([
            ("a".into(), FieldElement::from_i64(10)),
            ("b".into(), FieldElement::from_i64(20)),
            ("d".into(), FieldElement::from_i64(5)),
        ]),
        expected_public_outputs: vec![FieldElement::from_i64(35)],
    }
}

/// Quadratic: a^2 + b^2 == c.
fn quadratic(field: FieldId) -> ConformanceProgram {
    ConformanceProgram {
        name: "quadratic".into(),
        description: "Quadratic: a^2 + b^2 == c".into(),
        program: Program {
            name: "quadratic".into(),
            field,
            signals: vec![
                Signal {
                    name: "a".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "b".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "a_sq".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "b_sq".into(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "c".into(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![
                Constraint::Equal {
                    lhs: Expr::Mul(
                        Box::new(Expr::Signal("a".into())),
                        Box::new(Expr::Signal("a".into())),
                    ),
                    rhs: Expr::Signal("a_sq".into()),
                    label: Some("a_squared".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Mul(
                        Box::new(Expr::Signal("b".into())),
                        Box::new(Expr::Signal("b".into())),
                    ),
                    rhs: Expr::Signal("b_sq".into()),
                    label: Some("b_squared".into()),
                },
                Constraint::Equal {
                    lhs: Expr::Add(vec![
                        Expr::Signal("a_sq".into()),
                        Expr::Signal("b_sq".into()),
                    ]),
                    rhs: Expr::Signal("c".into()),
                    label: Some("sum_of_squares".into()),
                },
            ],
            witness_plan: WitnessPlan {
                assignments: vec![
                    WitnessAssignment {
                        target: "a_sq".into(),
                        expr: Expr::Mul(
                            Box::new(Expr::Signal("a".into())),
                            Box::new(Expr::Signal("a".into())),
                        ),
                    },
                    WitnessAssignment {
                        target: "b_sq".into(),
                        expr: Expr::Mul(
                            Box::new(Expr::Signal("b".into())),
                            Box::new(Expr::Signal("b".into())),
                        ),
                    },
                    WitnessAssignment {
                        target: "c".into(),
                        expr: Expr::Add(vec![
                            Expr::Signal("a_sq".into()),
                            Expr::Signal("b_sq".into()),
                        ]),
                    },
                ],
                ..Default::default()
            },
            lookup_tables: vec![],
            metadata: BTreeMap::new(),
        },
        inputs: BTreeMap::from([
            ("a".into(), FieldElement::from_i64(3)),
            ("b".into(), FieldElement::from_i64(4)),
        ]),
        expected_public_outputs: vec![FieldElement::from_i64(25)],
    }
}
