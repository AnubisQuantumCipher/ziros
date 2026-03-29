//! Lookup constraint lowering for R1CS backends.
//!
//! Converts `Constraint::Lookup` into equivalent arithmetic constraints
//! using indicator-variable decomposition:
//!
//! For a table with N rows and K columns:
//! 1. Introduce N boolean selector variables s_0, ..., s_{N-1}
//! 2. Constrain: sum(s_i) = 1 (exactly one row selected)
//! 3. For each input column j: input_j = sum(s_i * table[i][j])
//! 4. For each output column j: output_j = sum(s_i * table[i][j])
//!
//! This is O(N * K) constraints. Efficient for small tables (≤256 rows).
//! For large tables, backends with native lookup support (Plonky3/Halo2)
//! should be used instead.

use super::{AuxCounter, LoweredBlackBox, constraint_instance_suffix};
use zkf_core::ir::LookupTable;
use zkf_core::{Constraint, Expr, FieldElement, Program, ZkfError, ZkfResult};

/// Maximum table size for R1CS lookup decomposition.
/// Tables larger than this should use a native lookup backend.
const MAX_R1CS_LOOKUP_ROWS: usize = 256;

#[cfg_attr(not(feature = "kani-minimal"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LookupLoweringShape {
    pub(crate) selector_count: usize,
    pub(crate) boolean_constraint_count: usize,
    pub(crate) equality_constraint_count: usize,
    pub(crate) output_binding_count: usize,
}

#[cfg_attr(not(feature = "kani-minimal"), allow(dead_code))]
pub(crate) fn summarize_lookup_lowering_shape(
    input_count: usize,
    output_count: usize,
    table: &LookupTable,
) -> ZkfResult<LookupLoweringShape> {
    let n_rows = table.values.len();
    if n_rows == 0 {
        return Err(ZkfError::Backend(format!(
            "lookup table '{}' has no rows",
            table.name
        )));
    }
    if n_rows > MAX_R1CS_LOOKUP_ROWS {
        return Err(ZkfError::Backend(format!(
            "lookup table '{}' has {} rows, exceeding the R1CS decomposition limit of {}. \
             Use a backend with native lookup support (Plonky3, Halo2) for large tables.",
            table.name, n_rows, MAX_R1CS_LOOKUP_ROWS
        )));
    }

    let n_cols = table.columns.len();
    if input_count > n_cols {
        return Err(ZkfError::Backend(format!(
            "lookup into '{}': {} inputs but table has only {} columns",
            table.name, input_count, n_cols
        )));
    }

    let output_binding_count = output_count.min(n_cols.saturating_sub(input_count));
    Ok(LookupLoweringShape {
        selector_count: n_rows,
        boolean_constraint_count: n_rows,
        equality_constraint_count: 1 + input_count + output_binding_count,
        output_binding_count,
    })
}

/// Lower all `Constraint::Lookup` in a program into arithmetic constraints.
///
/// Call this after `lower_blackbox_program()` for R1CS backends that don't
/// support native lookup arguments.
///
/// Returns a new program with Lookup constraints replaced by arithmetic
/// constraints (indicator variables + equality checks).
pub fn lower_lookup_constraints(program: &Program) -> ZkfResult<Program> {
    let mut new_signals = program.signals.clone();
    let mut new_constraints = Vec::with_capacity(program.constraints.len());
    let mut aux = AuxCounter::new("lookup");

    for (idx, constraint) in program.constraints.iter().enumerate() {
        match constraint {
            Constraint::Lookup {
                inputs,
                table: table_name,
                outputs,
                label,
            } => {
                // Find the lookup table
                let table = program
                    .lookup_tables
                    .iter()
                    .find(|t| t.name == *table_name)
                    .ok_or_else(|| {
                        ZkfError::Backend(format!(
                            "lookup constraint {} references unknown table '{}'",
                            idx, table_name
                        ))
                    })?;

                let prefix = format!(
                    "lk_{}_{}",
                    table_name,
                    constraint_instance_suffix(label, idx)
                );

                let lowered =
                    lower_single_lookup(&mut aux, inputs, outputs.as_deref(), table, &prefix)?;

                new_signals.extend(lowered.signals);
                new_constraints.extend(lowered.constraints);
            }
            other => {
                new_constraints.push(other.clone());
            }
        }
    }

    let mut result = program.clone();
    result.signals = new_signals;
    result.constraints = new_constraints;
    Ok(result)
}

fn lower_single_lookup(
    aux: &mut AuxCounter,
    inputs: &[Expr],
    outputs: Option<&[String]>,
    table: &LookupTable,
    prefix: &str,
) -> ZkfResult<LoweredBlackBox> {
    let n_rows = table.values.len();

    if n_rows == 0 {
        return Err(ZkfError::Backend(format!(
            "lookup table '{}' has no rows",
            table.name
        )));
    }
    if n_rows > MAX_R1CS_LOOKUP_ROWS {
        return Err(ZkfError::Backend(format!(
            "lookup table '{}' has {} rows, exceeding the R1CS decomposition limit of {}. \
             Use a backend with native lookup support (Plonky3, Halo2) for large tables.",
            table.name, n_rows, MAX_R1CS_LOOKUP_ROWS
        )));
    }

    let n_cols = table.columns.len();
    if inputs.len() > n_cols {
        return Err(ZkfError::Backend(format!(
            "lookup into '{}': {} inputs but table has only {} columns",
            table.name,
            inputs.len(),
            n_cols
        )));
    }

    let mut lowered = LoweredBlackBox::default();

    // Step 1: Create N boolean selector variables
    let mut selectors = Vec::with_capacity(n_rows);
    for row in 0..n_rows {
        let sel = lowered.add_private_signal(aux.next(&format!("{prefix}_sel{row}")));
        lowered.add_boolean(&sel, format!("{prefix}_sel{row}_bool"));
        selectors.push(sel);
    }

    // Step 2: Constrain sum(s_i) = 1 (exactly one row selected)
    let selector_sum = Expr::Add(selectors.iter().map(|s| Expr::Signal(s.clone())).collect());
    lowered.constraints.push(Constraint::Equal {
        lhs: selector_sum,
        rhs: Expr::Const(FieldElement::from_i64(1)),
        label: Some(format!("{prefix}_one_hot")),
    });

    // Step 3: For each input column j, constrain:
    //   input_j = sum(s_i * table[i][j])
    for (col, input_expr) in inputs.iter().enumerate() {
        let terms: Vec<Expr> = (0..n_rows)
            .map(|row| {
                let table_val = if col < table.values[row].len() {
                    table.values[row][col].clone()
                } else {
                    FieldElement::from_i64(0)
                };
                Expr::Mul(
                    Box::new(Expr::Signal(selectors[row].clone())),
                    Box::new(Expr::Const(table_val)),
                )
            })
            .collect();

        let selected_value = if terms.len() == 1 {
            terms.into_iter().next().unwrap()
        } else {
            Expr::Add(terms)
        };

        lowered.constraints.push(Constraint::Equal {
            lhs: input_expr.clone(),
            rhs: selected_value,
            label: Some(format!("{prefix}_col{col}_match")),
        });
    }

    // Step 4: For each output column, bind the output signal to the selected row
    if let Some(out_names) = outputs {
        for (out_idx, out_name) in out_names.iter().enumerate() {
            let col = inputs.len() + out_idx;
            if col >= n_cols {
                continue;
            }

            let terms: Vec<Expr> = (0..n_rows)
                .map(|row| {
                    let table_val = if col < table.values[row].len() {
                        table.values[row][col].clone()
                    } else {
                        FieldElement::from_i64(0)
                    };
                    Expr::Mul(
                        Box::new(Expr::Signal(selectors[row].clone())),
                        Box::new(Expr::Const(table_val)),
                    )
                })
                .collect();

            let selected_value = if terms.len() == 1 {
                terms.into_iter().next().unwrap()
            } else {
                Expr::Add(terms)
            };

            lowered.constraints.push(Constraint::Equal {
                lhs: Expr::Signal(out_name.clone()),
                rhs: selected_value,
                label: Some(format!("{prefix}_out{out_idx}_bind")),
            });
        }
    }

    Ok(lowered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::{FieldId, Program, Signal, Visibility, WitnessPlan};

    #[test]
    fn lookup_lowering_basic() {
        let program = Program {
            name: "lookup_test".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Lookup {
                inputs: vec![Expr::Signal("x".into())],
                table: "small".into(),
                outputs: None,
                label: Some("test".into()),
            }],
            lookup_tables: vec![LookupTable {
                name: "small".into(),
                columns: vec!["val".into()],
                values: vec![
                    vec![FieldElement::from_i64(0)],
                    vec![FieldElement::from_i64(1)],
                    vec![FieldElement::from_i64(2)],
                    vec![FieldElement::from_i64(3)],
                ],
            }],
            witness_plan: WitnessPlan::default(),
            ..Default::default()
        };

        let lowered = lower_lookup_constraints(&program).unwrap();

        // No Lookup constraints should remain
        assert!(
            !lowered
                .constraints
                .iter()
                .any(|c| matches!(c, Constraint::Lookup { .. })),
            "lowered program should have no Lookup constraints"
        );

        // Should have selector boolean constraints + one-hot + column match
        // 4 selectors * (1 boolean) + 1 one-hot + 1 column match = 6
        let eq_count = lowered
            .constraints
            .iter()
            .filter(|c| matches!(c, Constraint::Equal { .. }))
            .count();
        assert!(
            eq_count >= 2,
            "expected at least 2 Equal constraints, got {eq_count}"
        );

        let bool_count = lowered
            .constraints
            .iter()
            .filter(|c| matches!(c, Constraint::Boolean { .. }))
            .count();
        assert_eq!(
            bool_count, 4,
            "expected 4 boolean constraints for 4 selectors"
        );
    }

    #[test]
    fn lookup_rejects_large_table() {
        let program = Program {
            name: "big_lookup".to_string(),
            field: FieldId::Bn254,
            signals: vec![Signal {
                name: "x".into(),
                visibility: Visibility::Private,
                constant: None,
                ty: None,
            }],
            constraints: vec![Constraint::Lookup {
                inputs: vec![Expr::Signal("x".into())],
                table: "big".into(),
                outputs: None,
                label: None,
            }],
            lookup_tables: vec![LookupTable {
                name: "big".into(),
                columns: vec!["val".into()],
                values: (0..300).map(|i| vec![FieldElement::from_i64(i)]).collect(),
            }],
            witness_plan: WitnessPlan::default(),
            ..Default::default()
        };

        let err = lower_lookup_constraints(&program).unwrap_err();
        assert!(
            err.to_string().contains("256"),
            "should mention the 256-row limit"
        );
    }
}
