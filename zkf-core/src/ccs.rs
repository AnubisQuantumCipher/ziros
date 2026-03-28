//! Customizable Constraint Systems (CCS) — a unified constraint representation.
//!
//! CCS generalizes R1CS, PLONKish, and AIR constraint systems into a single
//! framework. This enables targeting HyperNova, ProtoGalaxy, and future folding
//! schemes from a single IR.
//!
//! A CCS instance is defined by:
//! - A set of matrices M_1, ..., M_t over the field
//! - A multiset S_1, ..., S_q where each S_j ⊆ {1, ..., t}
//! - Scalar coefficients c_1, ..., c_q
//! - The relation: ∑_j c_j · ∏_{i ∈ S_j} M_i · z = 0
//!
//! Special cases:
//! - R1CS: t=3, q=2, S_1={1,2}, S_2={3}, c_1=1, c_2=-1 → A·z ∘ B·z - C·z = 0
//! - PLONKish: custom gate equations map to CCS multisets
//! - AIR: transition constraints over adjacent rows

use crate::ir::{BlackBoxOp, Constraint, Expr, Program, Visibility};
use crate::proof_ccs_spec::{
    SpecCcsBlackBoxKind, SpecCcsConstraint, SpecCcsConstraintProgram, SpecCcsExpr,
    SpecCcsProgram as ProofSpecCcsProgram, SpecCcsSignal, SpecCcsSynthesisError,
    SpecCcsSynthesisErrorKind, SpecCcsVisibility,
};
use crate::proof_kernel_spec::SpecFieldValue;
use crate::{FieldElement, FieldId, ZkfError, ZkfResult, normalize_mod};
use num_bigint::BigInt;
use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[allow(dead_code)]
type LinearExpr = BTreeMap<usize, BigInt>;

/// A sparse matrix in coordinate (COO) format.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CcsMatrix {
    /// Number of rows.
    pub rows: usize,
    /// Number of columns.
    pub cols: usize,
    /// Non-zero entries as (row, col, value) triples.
    pub entries: Vec<(usize, usize, FieldElement)>,
}

impl CcsMatrix {
    pub fn new(rows: usize, cols: usize) -> Self {
        Self {
            rows,
            cols,
            entries: Vec::new(),
        }
    }

    pub fn push(&mut self, row: usize, col: usize, value: FieldElement) {
        self.entries.push((row, col, value));
    }

    pub fn nnz(&self) -> usize {
        self.entries.len()
    }
}

/// A multiset entry: coefficient * product of matrix-vector products.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CcsMultiset {
    /// Indices into the matrix list (0-based).
    pub matrix_indices: Vec<usize>,
    /// Scalar coefficient for this term.
    pub coefficient: FieldElement,
}

/// A complete CCS program ready for proving.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct CcsProgram {
    pub name: String,
    pub field: FieldId,
    /// Number of constraints (rows in the matrices).
    pub num_constraints: usize,
    /// Total number of variables (columns in the matrices), including
    /// the constant-1 wire at index 0.
    pub num_variables: usize,
    /// Number of public input/output variables.
    pub num_public: usize,
    /// The constraint matrices M_1, ..., M_t.
    pub matrices: Vec<CcsMatrix>,
    /// The multisets S_1, ..., S_q with their coefficients.
    pub multisets: Vec<CcsMultiset>,
}

impl CcsProgram {
    /// Create an empty CCS program.
    pub fn new(name: &str, field: FieldId, num_constraints: usize, num_variables: usize) -> Self {
        Self {
            name: name.to_string(),
            field,
            num_constraints,
            num_variables,
            num_public: 0,
            matrices: Vec::new(),
            multisets: Vec::new(),
        }
    }

    /// Number of matrices (t).
    pub fn num_matrices(&self) -> usize {
        self.matrices.len()
    }

    /// Number of multiset terms (q).
    pub fn num_terms(&self) -> usize {
        self.multisets.len()
    }

    /// Maximum degree of any multiset term (max |S_j|).
    pub fn degree(&self) -> usize {
        self.multisets
            .iter()
            .map(|ms| ms.matrix_indices.len())
            .max()
            .unwrap_or(0)
    }

    /// Build an exact CCS program from a ZKF `Program`.
    ///
    /// This conversion is fail-closed: unsupported constructs return an error
    /// instead of silently weakening the resulting system.
    pub fn try_from_program(program: &Program) -> ZkfResult<Self> {
        let proof_program = translate_program_to_proof_ccs(program)?;
        let synthesized = crate::proof_ccs_spec::synthesize_ccs_program(&proof_program)
            .map_err(|error| map_proof_ccs_error(program, error))?;
        Ok(ccs_program_from_proof_spec(&program.name, synthesized))
    }

    /// Deprecated compatibility wrapper. Prefer [`Self::try_from_program`].
    #[deprecated(note = "use try_from_program() for fail-closed CCS synthesis")]
    pub fn from_program(program: &Program) -> ZkfResult<Self> {
        Self::try_from_program(program)
    }

    /// Build a CCS instance equivalent to an R1CS system.
    ///
    /// R1CS: A·z ∘ B·z = C·z, which in CCS form is:
    /// M_1=A, M_2=B, M_3=C; S_1={0,1} c_1=1, S_2={2} c_2=-1
    pub fn from_r1cs(
        name: &str,
        field: FieldId,
        num_constraints: usize,
        num_variables: usize,
        a: CcsMatrix,
        b: CcsMatrix,
        c: CcsMatrix,
    ) -> Self {
        Self {
            name: name.to_string(),
            field,
            num_constraints,
            num_variables,
            num_public: 0,
            matrices: vec![a, b, c],
            multisets: vec![
                CcsMultiset {
                    matrix_indices: vec![0, 1],
                    coefficient: FieldElement::from_i64(1),
                },
                CcsMultiset {
                    matrix_indices: vec![2],
                    coefficient: FieldElement::from_i64(-1),
                },
            ],
        }
    }
}

pub fn program_constraint_degree(program: &Program) -> usize {
    program
        .constraints
        .iter()
        .map(constraint_degree)
        .max()
        .unwrap_or(0)
}

pub fn constraint_degree(constraint: &Constraint) -> usize {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => expr_degree(lhs).max(expr_degree(rhs)),
        Constraint::Boolean { .. } => 2,
        Constraint::Range { .. } => 1,
        Constraint::BlackBox {
            op: BlackBoxOp::RecursiveAggregationMarker,
            ..
        } => 0,
        Constraint::BlackBox { .. } => 1,
        Constraint::Lookup { inputs, .. } => inputs.iter().map(expr_degree).max().unwrap_or(1),
    }
}

pub fn expr_degree(expr: &Expr) -> usize {
    match expr {
        Expr::Const(_) => 0,
        Expr::Signal(_) => 1,
        Expr::Add(values) => values.iter().map(expr_degree).max().unwrap_or(0),
        Expr::Sub(left, right) => expr_degree(left).max(expr_degree(right)),
        Expr::Mul(left, right) => expr_degree(left).saturating_add(expr_degree(right)),
        Expr::Div(left, right) => expr_degree(left).max(expr_degree(right)),
    }
}

fn translate_expr_to_indexed_proof_ccs(
    expr: &Expr,
    signal_indices: &BTreeMap<String, usize>,
) -> ZkfResult<SpecCcsExpr> {
    Ok(match expr {
        Expr::Const(value) => SpecCcsExpr::Const(SpecFieldValue::from_runtime(value)),
        Expr::Signal(name) => {
            SpecCcsExpr::Signal(signal_indices.get(name).copied().ok_or_else(|| {
                ZkfError::UnknownSignal {
                    signal: name.clone(),
                }
            })?)
        }
        Expr::Add(values) => SpecCcsExpr::Add(
            values
                .iter()
                .map(|value| translate_expr_to_indexed_proof_ccs(value, signal_indices))
                .collect::<ZkfResult<Vec<_>>>()?,
        ),
        Expr::Sub(left, right) => SpecCcsExpr::Sub(
            Box::new(translate_expr_to_indexed_proof_ccs(left, signal_indices)?),
            Box::new(translate_expr_to_indexed_proof_ccs(right, signal_indices)?),
        ),
        Expr::Mul(left, right) => SpecCcsExpr::Mul(
            Box::new(translate_expr_to_indexed_proof_ccs(left, signal_indices)?),
            Box::new(translate_expr_to_indexed_proof_ccs(right, signal_indices)?),
        ),
        Expr::Div(left, right) => SpecCcsExpr::Div(
            Box::new(translate_expr_to_indexed_proof_ccs(left, signal_indices)?),
            Box::new(translate_expr_to_indexed_proof_ccs(right, signal_indices)?),
        ),
    })
}

fn translate_program_to_proof_ccs(program: &Program) -> ZkfResult<SpecCcsConstraintProgram> {
    let signal_indices = program
        .signals
        .iter()
        .enumerate()
        .map(|(index, signal)| (signal.name.clone(), index))
        .collect::<BTreeMap<_, _>>();

    let constraints = program
        .constraints
        .iter()
        .map(|constraint| match constraint {
            Constraint::Equal { lhs, rhs, .. } => Ok(SpecCcsConstraint::Equal {
                lhs: translate_expr_to_indexed_proof_ccs(lhs, &signal_indices)?,
                rhs: translate_expr_to_indexed_proof_ccs(rhs, &signal_indices)?,
            }),
            Constraint::Boolean { signal, .. } => Ok(SpecCcsConstraint::Boolean {
                signal_index: signal_indices.get(signal).copied().ok_or_else(|| {
                    ZkfError::UnknownSignal {
                        signal: signal.clone(),
                    }
                })?,
            }),
            Constraint::Range { signal, bits, .. } => Ok(SpecCcsConstraint::Range {
                signal_index: signal_indices.get(signal).copied().ok_or_else(|| {
                    ZkfError::UnknownSignal {
                        signal: signal.clone(),
                    }
                })?,
                bits: *bits,
            }),
            Constraint::Lookup { .. } => Ok(SpecCcsConstraint::Lookup),
            Constraint::BlackBox {
                op: BlackBoxOp::RecursiveAggregationMarker,
                ..
            } => Ok(SpecCcsConstraint::BlackBox {
                kind: SpecCcsBlackBoxKind::RecursiveAggregationMarker,
            }),
            Constraint::BlackBox { .. } => Ok(SpecCcsConstraint::BlackBox {
                kind: SpecCcsBlackBoxKind::Other,
            }),
        })
        .collect::<ZkfResult<Vec<_>>>()?;

    Ok(SpecCcsConstraintProgram {
        field: program.field,
        signals: program
            .signals
            .iter()
            .map(|signal| SpecCcsSignal {
                visibility: if signal.visibility == Visibility::Public {
                    SpecCcsVisibility::Public
                } else {
                    SpecCcsVisibility::NonPublic
                },
            })
            .collect::<Vec<_>>(),
        constraints,
    })
}

fn map_proof_ccs_error(program: &Program, error: SpecCcsSynthesisError) -> ZkfError {
    let label = program
        .constraints
        .get(error.constraint_index)
        .and_then(|constraint| constraint.label().cloned());
    let reason = match error.kind {
        SpecCcsSynthesisErrorKind::InvalidSignalIndex => {
            "constraint references an invalid signal index during proof-side CCS synthesis"
                .to_string()
        }
        SpecCcsSynthesisErrorKind::LookupRequiresLowering => {
            "lookup constraints must be lowered before CCS synthesis".to_string()
        }
        SpecCcsSynthesisErrorKind::BlackBoxRequiresLowering => {
            "blackbox constraints must be lowered before CCS synthesis".to_string()
        }
    };

    ZkfError::UnsupportedCcsEncoding {
        index: error.constraint_index,
        label,
        reason,
    }
}

fn ccs_program_from_proof_spec(name: &str, spec_program: ProofSpecCcsProgram) -> CcsProgram {
    CcsProgram {
        name: name.to_string(),
        field: spec_program.field,
        num_constraints: spec_program.num_constraints,
        num_variables: spec_program.num_variables,
        num_public: spec_program.num_public,
        matrices: spec_program
            .matrices
            .into_iter()
            .map(|matrix| CcsMatrix {
                rows: matrix.rows,
                cols: matrix.cols,
                entries: matrix
                    .entries
                    .into_iter()
                    .map(|entry| (entry.row, entry.col, entry.value.to_runtime()))
                    .collect::<Vec<_>>(),
            })
            .collect::<Vec<_>>(),
        multisets: spec_program
            .multisets
            .into_iter()
            .map(|multiset| CcsMultiset {
                matrix_indices: multiset.matrix_indices,
                coefficient: multiset.coefficient.to_runtime(),
            })
            .collect::<Vec<_>>(),
    }
}

#[allow(dead_code)]
#[derive(Debug)]
struct R1csBuilder {
    field: FieldId,
    signal_index: BTreeMap<String, usize>,
    next_col: usize,
    num_public: usize,
    row: usize,
    a_entries: Vec<(usize, usize, FieldElement)>,
    b_entries: Vec<(usize, usize, FieldElement)>,
    c_entries: Vec<(usize, usize, FieldElement)>,
}

#[allow(dead_code)]
impl R1csBuilder {
    fn new(program: &Program) -> Self {
        let mut signal_index = BTreeMap::new();
        let mut next_col = 1usize;
        let mut num_public = 0usize;

        for signal in &program.signals {
            if signal.visibility == Visibility::Public {
                signal_index.insert(signal.name.clone(), next_col);
                next_col += 1;
                num_public += 1;
            }
        }

        for signal in &program.signals {
            if signal.visibility != Visibility::Public {
                signal_index.insert(signal.name.clone(), next_col);
                next_col += 1;
            }
        }

        Self {
            field: program.field,
            signal_index,
            next_col,
            num_public,
            row: 0,
            a_entries: Vec::new(),
            b_entries: Vec::new(),
            c_entries: Vec::new(),
        }
    }

    #[allow(dead_code)]
    fn finish(self, program: &Program) -> CcsProgram {
        let num_constraints = self.row;
        let a = CcsMatrix {
            rows: num_constraints,
            cols: self.next_col,
            entries: self.a_entries,
        };
        let b = CcsMatrix {
            rows: num_constraints,
            cols: self.next_col,
            entries: self.b_entries,
        };
        let c = CcsMatrix {
            rows: num_constraints,
            cols: self.next_col,
            entries: self.c_entries,
        };

        let mut ccs = CcsProgram::from_r1cs(
            &program.name,
            program.field,
            num_constraints,
            self.next_col,
            a,
            b,
            c,
        );
        ccs.num_public = self.num_public;
        ccs
    }

    fn allocate_aux(&mut self) -> usize {
        let col = self.next_col;
        self.next_col += 1;
        col
    }

    fn signal_lc(&self, signal: &str) -> ZkfResult<LinearExpr> {
        let Some(&col) = self.signal_index.get(signal) else {
            return Err(ZkfError::UnknownSignal {
                signal: signal.to_string(),
            });
        };
        Ok(lc_var(col))
    }

    fn expr_to_lc(&mut self, expr: &Expr) -> ZkfResult<LinearExpr> {
        match expr {
            Expr::Const(value) => Ok(lc_const(value.normalized_bigint(self.field)?)),
            Expr::Signal(name) => self.signal_lc(name),
            Expr::Add(terms) => {
                let mut acc = LinearExpr::new();
                for term in terms {
                    lc_add_assign(&mut acc, &self.expr_to_lc(term)?);
                }
                Ok(acc)
            }
            Expr::Sub(left, right) => {
                let mut acc = self.expr_to_lc(left)?;
                lc_sub_assign(&mut acc, &self.expr_to_lc(right)?);
                Ok(acc)
            }
            Expr::Mul(left, right) => {
                let left_lc = self.expr_to_lc(left)?;
                let right_lc = self.expr_to_lc(right)?;
                let aux_col = self.allocate_aux();
                self.add_row(left_lc, right_lc, lc_var(aux_col));
                Ok(lc_var(aux_col))
            }
            Expr::Div(left, right) => {
                let numerator = self.expr_to_lc(left)?;
                let denominator = self.expr_to_lc(right)?;
                let quotient_col = self.allocate_aux();
                let inverse_col = self.allocate_aux();

                self.add_row(denominator.clone(), lc_var(inverse_col), lc_one());
                self.add_row(lc_var(quotient_col), denominator, numerator);

                Ok(lc_var(quotient_col))
            }
        }
    }

    fn add_row(&mut self, a: LinearExpr, b: LinearExpr, c: LinearExpr) {
        let row = self.row;
        push_lc_entries(self.field, &mut self.a_entries, row, &a);
        push_lc_entries(self.field, &mut self.b_entries, row, &b);
        push_lc_entries(self.field, &mut self.c_entries, row, &c);
        self.row += 1;
    }
}

#[allow(dead_code)]
fn encode_constraint(
    builder: &mut R1csBuilder,
    constraint: &Constraint,
    index: usize,
) -> ZkfResult<()> {
    match constraint {
        Constraint::Equal { lhs, rhs, .. } => {
            if let Expr::Mul(left, right) = lhs {
                let a = builder.expr_to_lc(left)?;
                let b = builder.expr_to_lc(right)?;
                let c = builder.expr_to_lc(rhs)?;
                builder.add_row(a, b, c);
                return Ok(());
            }

            if let Expr::Mul(left, right) = rhs {
                let a = builder.expr_to_lc(left)?;
                let b = builder.expr_to_lc(right)?;
                let c = builder.expr_to_lc(lhs)?;
                builder.add_row(a, b, c);
                return Ok(());
            }

            let lhs_lc = builder.expr_to_lc(lhs)?;
            let rhs_lc = builder.expr_to_lc(rhs)?;
            let mut diff = lhs_lc;
            lc_sub_assign(&mut diff, &rhs_lc);
            builder.add_row(diff, lc_one(), LinearExpr::new());
            Ok(())
        }
        Constraint::Boolean { signal, .. } => {
            let value = builder.signal_lc(signal)?;
            builder.add_row(
                value,
                lc_one_minus_var(builder.signal_index[signal]),
                LinearExpr::new(),
            );
            Ok(())
        }
        Constraint::Range { signal, bits, .. } => {
            let signal_value = builder.signal_lc(signal)?;
            let mut recomposed = LinearExpr::new();

            for bit in 0..*bits {
                let bit_col = builder.allocate_aux();
                builder.add_row(
                    lc_var(bit_col),
                    lc_one_minus_var(bit_col),
                    LinearExpr::new(),
                );
                lc_add_term(
                    &mut recomposed,
                    bit_col,
                    BigInt::one() << usize::try_from(bit).unwrap_or(0),
                );
            }

            builder.add_row(signal_value, lc_one(), recomposed);
            Ok(())
        }
        Constraint::BlackBox {
            op: BlackBoxOp::RecursiveAggregationMarker,
            ..
        } => Ok(()),
        Constraint::BlackBox { .. } => Err(ZkfError::UnsupportedCcsEncoding {
            index,
            label: constraint.label().cloned(),
            reason: "blackbox constraints must be lowered before CCS synthesis".to_string(),
        }),
        Constraint::Lookup { .. } => Err(ZkfError::UnsupportedCcsEncoding {
            index,
            label: constraint.label().cloned(),
            reason: "lookup constraints must be lowered before CCS synthesis".to_string(),
        }),
    }
}

#[cfg(any(test, kani))]
#[allow(dead_code)]
pub(crate) fn lookup_constraint_fail_closed_for_verification() -> ZkfResult<()> {
    let mut builder = R1csBuilder::new(&Program::default());
    encode_constraint(
        &mut builder,
        &Constraint::Lookup {
            inputs: Vec::new(),
            table: String::new(),
            outputs: None,
            label: None,
        },
        0,
    )
}

#[allow(dead_code)]
fn lc_const(value: BigInt) -> LinearExpr {
    let mut expr = LinearExpr::new();
    lc_add_term(&mut expr, 0, value);
    expr
}

#[allow(dead_code)]
fn lc_var(col: usize) -> LinearExpr {
    let mut expr = LinearExpr::new();
    lc_add_term(&mut expr, col, BigInt::one());
    expr
}

#[allow(dead_code)]
fn lc_one() -> LinearExpr {
    lc_const(BigInt::one())
}

#[allow(dead_code)]
fn lc_one_minus_var(col: usize) -> LinearExpr {
    let mut expr = lc_one();
    lc_add_term(&mut expr, col, -BigInt::one());
    expr
}

#[allow(dead_code)]
fn lc_add_term(target: &mut LinearExpr, col: usize, coeff: BigInt) {
    if coeff.is_zero() {
        return;
    }

    let mut remove = false;
    {
        let entry = target.entry(col).or_insert_with(BigInt::zero);
        *entry += coeff;
        if entry.is_zero() {
            remove = true;
        }
    }

    if remove {
        target.remove(&col);
    }
}

#[allow(dead_code)]
fn lc_add_assign(target: &mut LinearExpr, other: &LinearExpr) {
    for (col, coeff) in other {
        lc_add_term(target, *col, coeff.clone());
    }
}

#[allow(dead_code)]
fn lc_sub_assign(target: &mut LinearExpr, other: &LinearExpr) {
    for (col, coeff) in other {
        lc_add_term(target, *col, -coeff.clone());
    }
}

#[allow(dead_code)]
fn push_lc_entries(
    field: FieldId,
    entries: &mut Vec<(usize, usize, FieldElement)>,
    row: usize,
    lc: &LinearExpr,
) {
    for (col, coeff) in lc {
        let normalized = normalize_mod(coeff.clone(), field.modulus());
        if normalized.is_zero() {
            continue;
        }
        entries.push((
            row,
            *col,
            FieldElement::from_bigint_with_field(normalized, field),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_ccs_program() {
        let prog = CcsProgram::new("test", FieldId::Bn254, 0, 1);
        assert_eq!(prog.num_matrices(), 0);
        assert_eq!(prog.num_terms(), 0);
        assert_eq!(prog.degree(), 0);
    }

    #[test]
    fn r1cs_as_ccs() {
        let n = 3;
        let m = 4;
        let a = CcsMatrix::new(n, m);
        let b = CcsMatrix::new(n, m);
        let c = CcsMatrix::new(n, m);

        let prog = CcsProgram::from_r1cs("r1cs_test", FieldId::Bn254, n, m, a, b, c);
        assert_eq!(prog.num_matrices(), 3);
        assert_eq!(prog.num_terms(), 2);
        assert_eq!(prog.degree(), 2);
    }

    #[test]
    fn try_from_program_multiply() {
        use crate::ir::{Signal, Visibility};

        let program = Program {
            name: "multiply".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "a".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "b".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "c".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Mul(
                    Box::new(Expr::Signal("a".to_string())),
                    Box::new(Expr::Signal("b".to_string())),
                ),
                rhs: Expr::Signal("c".to_string()),
                label: Some("a*b=c".to_string()),
            }],
            ..Default::default()
        };

        let ccs = CcsProgram::try_from_program(&program).expect("exact multiply CCS");
        assert_eq!(ccs.num_matrices(), 3);
        assert_eq!(ccs.num_terms(), 2);
        assert_eq!(ccs.degree(), 2);
        assert_eq!(ccs.num_public, 1);
        assert_eq!(ccs.num_constraints, 1);
        assert_eq!(ccs.num_variables, 4);
    }

    #[test]
    fn try_from_program_boolean() {
        use crate::ir::{Signal, Visibility};

        let program = Program {
            name: "bool_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Boolean {
                signal: "x".to_string(),
                label: None,
            }],
            ..Default::default()
        };

        let ccs = CcsProgram::try_from_program(&program).expect("exact boolean CCS");
        assert_eq!(ccs.num_constraints, 1);
        assert_eq!(ccs.num_variables, 2);
    }

    #[test]
    fn nested_multiplication_allocates_auxiliary_rows() {
        use crate::ir::{Signal, Visibility};

        let program = Program {
            name: "nested_mul".to_string(),
            field: FieldId::Bn254,
            signals: vec![
                Signal {
                    name: "x".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "y".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "z".to_string(),
                    visibility: Visibility::Private,
                    constant: None,
                    ty: None,
                },
                Signal {
                    name: "out".to_string(),
                    visibility: Visibility::Public,
                    constant: None,
                    ty: None,
                },
            ],
            constraints: vec![Constraint::Equal {
                lhs: Expr::Add(vec![
                    Expr::Signal("x".to_string()),
                    Expr::Mul(
                        Box::new(Expr::Signal("y".to_string())),
                        Box::new(Expr::Signal("z".to_string())),
                    ),
                ]),
                rhs: Expr::Signal("out".to_string()),
                label: Some("x+yz=out".to_string()),
            }],
            ..Default::default()
        };

        let ccs = CcsProgram::try_from_program(&program).expect("nested mul should be exact");
        assert!(ccs.num_constraints >= 2);
        assert!(ccs.num_variables >= 6);
    }

    #[test]
    fn try_from_program_handles_large_constraint_lists_without_recursive_stack_growth() {
        use crate::ir::{Signal, Visibility};

        let constraint_count = 50_000usize;
        let program = Program {
            name: "large_boolean_surface".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: std::iter::repeat_with(|| Constraint::Boolean {
                signal: "x".to_string(),
                label: None,
            })
            .take(constraint_count)
            .collect(),
            ..Default::default()
        };

        let ccs = CcsProgram::try_from_program(&program).expect("large boolean CCS");
        assert_eq!(ccs.num_constraints, constraint_count);
        assert_eq!(ccs.num_variables, 2);
        assert_eq!(ccs.num_public, 0);
    }

    #[test]
    fn lookup_requires_explicit_lowering() {
        use crate::ir::{LookupTable, Signal, Visibility, WitnessPlan};

        let program = Program {
            name: "lookup".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "selector".to_string(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Lookup {
                inputs: vec![Expr::Signal("selector".to_string())],
                table: "table".to_string(),
                outputs: None,
                label: Some("lookup".to_string()),
            }],
            witness_plan: WitnessPlan::default(),
            lookup_tables: vec![LookupTable {
                name: "table".to_string(),
                columns: vec!["selector".to_string()],
                values: vec![vec![FieldElement::from_i64(1)]],
            }],
            ..Default::default()
        };

        let err = CcsProgram::try_from_program(&program).expect_err("lookup must fail-closed");
        assert!(matches!(err, ZkfError::UnsupportedCcsEncoding { .. }));
    }

    #[test]
    fn degree_helpers_cover_lookup_and_division() {
        let expr = Expr::Div(
            Box::new(Expr::Mul(
                Box::new(Expr::Signal("a".to_string())),
                Box::new(Expr::Signal("b".to_string())),
            )),
            Box::new(Expr::Signal("c".to_string())),
        );
        assert_eq!(expr_degree(&expr), 2);

        let constraint = Constraint::Lookup {
            inputs: vec![expr],
            table: "table".to_string(),
            outputs: None,
            label: None,
        };
        assert_eq!(constraint_degree(&constraint), 2);
    }

    #[test]
    fn ccs_matrix_operations() {
        let mut matrix = CcsMatrix::new(2, 3);
        assert_eq!(matrix.nnz(), 0);

        matrix.push(0, 1, FieldElement::from_i64(5));
        matrix.push(1, 2, FieldElement::from_i64(7));

        assert_eq!(matrix.nnz(), 2);
        assert_eq!(matrix.entries.len(), 2);
    }
}
