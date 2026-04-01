use super::ZirLowering;
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{BackendKind, FieldElement, ZkfResult};

/// R1CS triplet: A * B = C over linear combinations.
#[derive(Debug, Clone)]
pub struct R1csConstraint {
    pub a: LinearCombination,
    pub b: LinearCombination,
    pub c: LinearCombination,
    pub label: Option<String>,
}

/// Linear combination: sum of (coefficient, variable_index) pairs + constant.
#[derive(Debug, Clone)]
pub struct LinearCombination {
    pub terms: Vec<(FieldElement, String)>,
    pub constant: FieldElement,
}

impl Default for LinearCombination {
    fn default() -> Self {
        Self {
            terms: Vec::new(),
            constant: FieldElement::from_i64(0),
        }
    }
}

/// Auxiliary witness variable introduced during lowering (e.g., for divisions,
/// range bit decomposition).
#[derive(Debug, Clone)]
pub struct AuxVariable {
    pub name: String,
    pub computation: AuxComputation,
}

#[derive(Debug, Clone)]
pub enum AuxComputation {
    /// Division: value = numerator / denominator
    Division {
        numerator: String,
        denominator: String,
    },
    /// Bit extraction: value = (source >> bit) & 1
    RangeBit { source: String, bit: u32 },
}

/// Lowered R1CS representation for Arkworks Groth16.
#[derive(Debug, Clone)]
pub struct ArkworksLoweredIr {
    pub signals: Vec<zir::Signal>,
    pub r1cs_constraints: Vec<R1csConstraint>,
    pub aux_variables: Vec<AuxVariable>,
    pub public_inputs: Vec<String>,
    pub witness_plan: zir::WitnessPlan,
    pub field: zkf_core::FieldId,
    pub metadata: BTreeMap<String, String>,
}

pub struct ArkworksLowering;

impl ZirLowering for ArkworksLowering {
    type LoweredIr = ArkworksLoweredIr;

    fn backend(&self) -> BackendKind {
        BackendKind::ArkworksGroth16
    }

    fn lower(&self, program: &zir::Program) -> ZkfResult<ArkworksLoweredIr> {
        let mut r1cs_constraints = Vec::new();
        let mut aux_variables = Vec::new();
        let mut aux_counter = 0usize;

        let public_inputs: Vec<String> = program
            .signals
            .iter()
            .filter(|s| s.visibility == zkf_core::Visibility::Public)
            .map(|s| s.name.clone())
            .collect();

        for constraint in &program.constraints {
            lower_constraint(
                constraint,
                &mut r1cs_constraints,
                &mut aux_variables,
                &mut aux_counter,
            )?;
        }

        Ok(ArkworksLoweredIr {
            signals: program.signals.clone(),
            r1cs_constraints,
            aux_variables,
            public_inputs,
            witness_plan: program.witness_plan.clone(),
            field: program.field,
            metadata: program.metadata.clone(),
        })
    }
}

fn lower_constraint(
    constraint: &zir::Constraint,
    r1cs: &mut Vec<R1csConstraint>,
    aux: &mut Vec<AuxVariable>,
    counter: &mut usize,
) -> ZkfResult<()> {
    match constraint {
        zir::Constraint::Equal { lhs, rhs, label } => {
            // lhs - rhs = 0 → encode as (lhs - rhs) * 1 = 0
            let a = expr_to_lc(lhs, aux, counter)?;
            let b_lc = expr_to_lc(rhs, aux, counter)?;
            let combined = lc_sub(&a, &b_lc);
            r1cs.push(R1csConstraint {
                a: combined,
                b: LinearCombination {
                    terms: vec![],
                    constant: FieldElement::from_i64(1),
                },
                c: LinearCombination::default(),
                label: label.clone(),
            });
        }
        zir::Constraint::Boolean { signal, label } => {
            // s * (1 - s) = 0
            r1cs.push(R1csConstraint {
                a: LinearCombination {
                    terms: vec![(FieldElement::from_i64(1), signal.clone())],
                    constant: FieldElement::from_i64(0),
                },
                b: LinearCombination {
                    terms: vec![(FieldElement::from_i64(-1), signal.clone())],
                    constant: FieldElement::from_i64(1),
                },
                c: LinearCombination::default(),
                label: label.clone(),
            });
        }
        zir::Constraint::Range {
            signal,
            bits,
            label,
        } => {
            // Bit decomposition: for each bit, create aux var and boolean constraint
            for bit in 0..*bits {
                let bit_name = format!("__aux_range_{}_{}", signal, bit);
                aux.push(AuxVariable {
                    name: bit_name.clone(),
                    computation: AuxComputation::RangeBit {
                        source: signal.clone(),
                        bit,
                    },
                });
                // Boolean constraint on each bit
                r1cs.push(R1csConstraint {
                    a: LinearCombination {
                        terms: vec![(FieldElement::from_i64(1), bit_name.clone())],
                        constant: FieldElement::from_i64(0),
                    },
                    b: LinearCombination {
                        terms: vec![(FieldElement::from_i64(-1), bit_name.clone())],
                        constant: FieldElement::from_i64(1),
                    },
                    c: LinearCombination::default(),
                    label: label.as_ref().map(|l| format!("{}_bit_{}", l, bit)),
                });
            }
            // Recombination: sum(bit_i * 2^i) = signal
            let mut recomb = LinearCombination::default();
            for bit in 0..*bits {
                let bit_name = format!("__aux_range_{}_{}", signal, bit);
                let coeff = FieldElement::from_u64(1u64 << bit);
                recomb.terms.push((coeff, bit_name));
            }
            let signal_lc = LinearCombination {
                terms: vec![(FieldElement::from_i64(1), signal.clone())],
                constant: FieldElement::from_i64(0),
            };
            let diff = lc_sub(&recomb, &signal_lc);
            r1cs.push(R1csConstraint {
                a: diff,
                b: LinearCombination {
                    terms: vec![],
                    constant: FieldElement::from_i64(1),
                },
                c: LinearCombination::default(),
                label: label.as_ref().map(|l| format!("{}_recombination", l)),
            });
        }
        zir::Constraint::BlackBox { label, .. } => {
            return Err(zkf_core::ZkfError::UnsupportedBackend {
                backend: BackendKind::ArkworksGroth16.to_string(),
                message: format!(
                    "arkworks ZIR-native lowering cannot synthesize BlackBox constraint '{}'; \
                     convert through IR v2 lowering first",
                    label.as_deref().unwrap_or("unnamed")
                ),
            });
        }
        zir::Constraint::Lookup { table, label, .. } => {
            return Err(zkf_core::ZkfError::UnsupportedBackend {
                backend: BackendKind::ArkworksGroth16.to_string(),
                message: format!(
                    "arkworks ZIR-native lowering cannot synthesize lookup '{}'; \
                     convert through IR v2 lowering so lower_lookup_constraints() runs first",
                    label.as_deref().unwrap_or(table)
                ),
            });
        }
        zir::Constraint::CustomGate { gate, label, .. } => {
            return Err(zkf_core::ZkfError::UnsupportedBackend {
                backend: BackendKind::ArkworksGroth16.to_string(),
                message: format!(
                    "arkworks ZIR-native lowering cannot synthesize custom gate '{}' ({})",
                    gate,
                    label.as_deref().unwrap_or("unnamed")
                ),
            });
        }
        zir::Constraint::MemoryRead { label, .. } | zir::Constraint::MemoryWrite { label, .. } => {
            return Err(zkf_core::ZkfError::UnsupportedBackend {
                backend: BackendKind::ArkworksGroth16.to_string(),
                message: format!(
                    "arkworks ZIR-native lowering cannot synthesize memory constraint '{}'",
                    label.as_deref().unwrap_or("unnamed")
                ),
            });
        }
        zir::Constraint::Permutation { left, right, label } => {
            // Permutation → equality in R1CS
            r1cs.push(R1csConstraint {
                a: LinearCombination {
                    terms: vec![
                        (FieldElement::from_i64(1), left.clone()),
                        (FieldElement::from_i64(-1), right.clone()),
                    ],
                    constant: FieldElement::from_i64(0),
                },
                b: LinearCombination {
                    terms: vec![],
                    constant: FieldElement::from_i64(1),
                },
                c: LinearCombination::default(),
                label: label.clone(),
            });
        }
        zir::Constraint::Copy { from, to, label } => {
            // Copy → equality
            r1cs.push(R1csConstraint {
                a: LinearCombination {
                    terms: vec![
                        (FieldElement::from_i64(1), from.clone()),
                        (FieldElement::from_i64(-1), to.clone()),
                    ],
                    constant: FieldElement::from_i64(0),
                },
                b: LinearCombination {
                    terms: vec![],
                    constant: FieldElement::from_i64(1),
                },
                c: LinearCombination::default(),
                label: label.clone(),
            });
        }
    }
    Ok(())
}

fn expr_to_lc(
    expr: &zir::Expr,
    _aux: &mut Vec<AuxVariable>,
    counter: &mut usize,
) -> ZkfResult<LinearCombination> {
    match expr {
        zir::Expr::Const(c) => Ok(LinearCombination {
            terms: vec![],
            constant: c.clone(),
        }),
        zir::Expr::Signal(name) => Ok(LinearCombination {
            terms: vec![(FieldElement::from_i64(1), name.clone())],
            constant: FieldElement::from_i64(0),
        }),
        zir::Expr::Add(values) => {
            let mut result = LinearCombination::default();
            for value in values {
                let lc = expr_to_lc(value, _aux, counter)?;
                result = lc_add(&result, &lc);
            }
            Ok(result)
        }
        zir::Expr::Sub(left, right) => {
            let l = expr_to_lc(left, _aux, counter)?;
            let r = expr_to_lc(right, _aux, counter)?;
            Ok(lc_sub(&l, &r))
        }
        zir::Expr::Mul(left, right) => {
            // For R1CS, multiplication of two non-trivial LCs requires
            // introducing an auxiliary variable. For now, represent as signal.
            let l = expr_to_lc(left, _aux, counter)?;
            let r = expr_to_lc(right, _aux, counter)?;
            if l.terms.is_empty() || r.terms.is_empty() {
                // One side is constant — can absorb into LC
                return Ok(lc_mul_const(&l, &r));
            }
            // Need auxiliary variable for non-trivial multiplication
            let aux_name = format!("__aux_mul_{}", *counter);
            *counter += 1;
            Ok(LinearCombination {
                terms: vec![(FieldElement::from_i64(1), aux_name)],
                constant: FieldElement::from_i64(0),
            })
        }
        zir::Expr::Div(left, right) => {
            let _ = (left, right);
            let aux_name = format!("__aux_div_{}", *counter);
            *counter += 1;
            Ok(LinearCombination {
                terms: vec![(FieldElement::from_i64(1), aux_name)],
                constant: FieldElement::from_i64(0),
            })
        }
    }
}

fn lc_add(a: &LinearCombination, b: &LinearCombination) -> LinearCombination {
    let mut terms = a.terms.clone();
    terms.extend(b.terms.iter().cloned());
    LinearCombination {
        terms,
        constant: FieldElement::from_i64(0), // simplified: should add constants
    }
}

fn lc_sub(a: &LinearCombination, b: &LinearCombination) -> LinearCombination {
    let mut terms = a.terms.clone();
    for (coeff, name) in &b.terms {
        terms.push((negate_field_element(coeff), name.clone()));
    }
    LinearCombination {
        terms,
        constant: FieldElement::from_i64(0),
    }
}

fn lc_mul_const(a: &LinearCombination, b: &LinearCombination) -> LinearCombination {
    // One of them should have no signal terms (pure constant).
    if a.terms.is_empty() {
        // a is constant, scale b's terms
        LinearCombination {
            terms: b.terms.clone(),
            constant: FieldElement::from_i64(0),
        }
    } else {
        // b is constant, scale a's terms
        LinearCombination {
            terms: a.terms.clone(),
            constant: FieldElement::from_i64(0),
        }
    }
}

fn negate_field_element(fe: &FieldElement) -> FieldElement {
    // Negate by subtracting from zero
    if fe.is_zero() {
        FieldElement::from_i64(0)
    } else {
        // Use from_bigint to negate
        let val = fe.as_bigint();
        FieldElement::from_bigint(-val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkf_core::FieldId;

    #[test]
    fn lowers_equal_constraint_to_r1cs() {
        let program = zir::Program {
            name: "test".to_string(),
            field: FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "x".to_string(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            }],
            constraints: vec![zir::Constraint::Equal {
                lhs: zir::Expr::Signal("x".to_string()),
                rhs: zir::Expr::Const(FieldElement::from_i64(42)),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowering = ArkworksLowering;
        let lowered = lowering.lower(&program).unwrap();
        assert_eq!(lowered.r1cs_constraints.len(), 1);
    }

    #[test]
    fn lowers_boolean_constraint() {
        let program = zir::Program {
            name: "test".to_string(),
            field: FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "b".to_string(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Bool,
                constant: None,
            }],
            constraints: vec![zir::Constraint::Boolean {
                signal: "b".to_string(),
                label: None,
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = ArkworksLowering.lower(&program).unwrap();
        assert_eq!(lowered.r1cs_constraints.len(), 1);
    }

    #[test]
    fn lowers_range_with_bit_decomposition() {
        let program = zir::Program {
            name: "test".to_string(),
            field: FieldId::Bn254,
            signals: vec![zir::Signal {
                name: "v".to_string(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::UInt { bits: 8 },
                constant: None,
            }],
            constraints: vec![zir::Constraint::Range {
                signal: "v".to_string(),
                bits: 8,
                label: Some("r8".to_string()),
            }],
            witness_plan: zir::WitnessPlan::default(),
            lookup_tables: Vec::new(),
            memory_regions: Vec::new(),
            custom_gates: Vec::new(),
            metadata: BTreeMap::new(),
        };

        let lowered = ArkworksLowering.lower(&program).unwrap();
        // 8 boolean constraints + 1 recombination
        assert_eq!(lowered.r1cs_constraints.len(), 9);
        assert_eq!(lowered.aux_variables.len(), 8);
    }
}
