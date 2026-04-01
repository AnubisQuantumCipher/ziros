use crate::gadget::{
    Gadget, GadgetEmission, builtin_supported_fields, validate_builtin_field_support,
};
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{FieldId, ZkfError, ZkfResult};

/// Plonk custom gate gadget.
///
/// Emits the standard 5-selector Plonk gate constraint:
///   q_L * a + q_R * b + q_O * c + q_M * a * b + q_C = 0
///
/// Inputs (in order):
/// 0. `a` — Left wire value
/// 1. `b` — Right wire value
/// 2. `c` — Output wire value
///
/// Parameters (selectors, as string-encoded field elements):
/// - `q_l` — Left selector (default: "0")
/// - `q_r` — Right selector (default: "0")
/// - `q_o` — Output selector (default: "0")
/// - `q_m` — Multiplication selector (default: "0")
/// - `q_c` — Constant selector (default: "0")
///
/// Outputs:
/// 0. `gate_result` — The gate evaluation (should be 0 for valid assignment)
///
/// This is useful for Plonk-compatible circuit compilation where custom
/// gates need to be expressed in the universal format.
pub struct PlonkGateGadget;

impl Gadget for PlonkGateGadget {
    fn name(&self) -> &str {
        "plonk_gate"
    }

    fn supported_fields(&self) -> Vec<FieldId> {
        builtin_supported_fields(self.name()).unwrap_or_default()
    }

    fn emit(
        &self,
        inputs: &[zir::Expr],
        outputs: &[String],
        field: FieldId,
        params: &BTreeMap<String, String>,
    ) -> ZkfResult<GadgetEmission> {
        validate_builtin_field_support(self.name(), field)?;
        if inputs.len() < 3 {
            return Err(ZkfError::InvalidArtifact(
                "plonk_gate requires 3 inputs: a, b, c".into(),
            ));
        }

        let mut emission = GadgetEmission::default();
        let mut aux_idx = 0usize;
        let mut next_aux = |prefix: &str| -> String {
            let name = format!("__plonk_{prefix}_{aux_idx}");
            aux_idx += 1;
            name
        };

        let a = &inputs[0];
        let b = &inputs[1];
        let c = &inputs[2];

        // Parse selectors from params
        let q_l = parse_selector(params, "q_l");
        let q_r = parse_selector(params, "q_r");
        let q_o = parse_selector(params, "q_o");
        let q_m = parse_selector(params, "q_m");
        let q_c = parse_selector(params, "q_c");

        // Build the gate expression: q_L*a + q_R*b + q_O*c + q_M*a*b + q_C = 0
        let mut terms: Vec<zir::Expr> = Vec::new();

        // q_L * a
        if q_l != 0 {
            if q_l == 1 {
                terms.push(a.clone());
            } else {
                terms.push(zir::Expr::Mul(
                    Box::new(zir::Expr::Const(zkf_core::FieldElement::from_i64(q_l))),
                    Box::new(a.clone()),
                ));
            }
        }

        // q_R * b
        if q_r != 0 {
            if q_r == 1 {
                terms.push(b.clone());
            } else {
                terms.push(zir::Expr::Mul(
                    Box::new(zir::Expr::Const(zkf_core::FieldElement::from_i64(q_r))),
                    Box::new(b.clone()),
                ));
            }
        }

        // q_O * c
        if q_o != 0 {
            if q_o == 1 {
                terms.push(c.clone());
            } else {
                terms.push(zir::Expr::Mul(
                    Box::new(zir::Expr::Const(zkf_core::FieldElement::from_i64(q_o))),
                    Box::new(c.clone()),
                ));
            }
        }

        // q_M * a * b
        if q_m != 0 {
            let ab = zir::Expr::Mul(Box::new(a.clone()), Box::new(b.clone()));
            if q_m == 1 {
                terms.push(ab);
            } else {
                terms.push(zir::Expr::Mul(
                    Box::new(zir::Expr::Const(zkf_core::FieldElement::from_i64(q_m))),
                    Box::new(ab),
                ));
            }
        }

        // q_C
        if q_c != 0 {
            terms.push(zir::Expr::Const(zkf_core::FieldElement::from_i64(q_c)));
        }

        // The full gate expression = 0
        let gate_expr = if terms.is_empty() {
            zir::Expr::Const(zkf_core::FieldElement::from_i64(0))
        } else if terms.len() == 1 {
            terms.into_iter().next().unwrap()
        } else {
            zir::Expr::Add(terms)
        };

        // Emit the constraint: gate_expr = 0
        emission.constraints.push(zir::Constraint::Equal {
            lhs: gate_expr,
            rhs: zir::Expr::Const(zkf_core::FieldElement::from_i64(0)),
            label: Some("plonk_gate".to_string()),
        });

        // Emit output signals
        for output in outputs {
            emission.signals.push(zir::Signal {
                name: output.clone(),
                visibility: zkf_core::Visibility::Private,
                ty: zir::SignalType::Field,
                constant: None,
            });
            // gate_result = 0 (the gate is satisfied)
            emission.constraints.push(zir::Constraint::Equal {
                lhs: zir::Expr::Signal(output.clone()),
                rhs: zir::Expr::Const(zkf_core::FieldElement::from_i64(0)),
                label: Some(format!("plonk_gate_output_{output}")),
            });
        }

        // Emit selector signals for backends that need them
        let sel_names = ["q_l", "q_r", "q_o", "q_m", "q_c"];
        let sel_vals = [q_l, q_r, q_o, q_m, q_c];
        for (sel_name, sel_val) in sel_names.iter().zip(sel_vals.iter()) {
            let sig_name = next_aux(sel_name);
            emission.signals.push(zir::Signal {
                name: sig_name.clone(),
                visibility: zkf_core::Visibility::Constant,
                ty: zir::SignalType::Field,
                constant: Some(zkf_core::FieldElement::from_i64(*sel_val)),
            });
        }

        Ok(emission)
    }
}

fn parse_selector(params: &BTreeMap<String, String>, key: &str) -> i64 {
    params
        .get(key)
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plonk_gate_addition() {
        // a + b - c = 0 → q_L=1, q_R=1, q_O=-1
        let gadget = PlonkGateGadget;
        let inputs = vec![
            zir::Expr::Signal("a".into()),
            zir::Expr::Signal("b".into()),
            zir::Expr::Signal("c".into()),
        ];
        let mut params = BTreeMap::new();
        params.insert("q_l".to_string(), "1".to_string());
        params.insert("q_r".to_string(), "1".to_string());
        params.insert("q_o".to_string(), "-1".to_string());

        let emission = gadget
            .emit(&inputs, &["gate_ok".into()], FieldId::Bn254, &params)
            .unwrap();

        // Should have the gate constraint + output constraint
        assert!(emission.constraints.len() >= 2);
        // Should have selector signals + output signal
        assert!(!emission.signals.is_empty());
    }

    #[test]
    fn plonk_gate_multiplication() {
        // a * b - c = 0 → q_M=1, q_O=-1
        let gadget = PlonkGateGadget;
        let inputs = vec![
            zir::Expr::Signal("a".into()),
            zir::Expr::Signal("b".into()),
            zir::Expr::Signal("c".into()),
        ];
        let mut params = BTreeMap::new();
        params.insert("q_m".to_string(), "1".to_string());
        params.insert("q_o".to_string(), "-1".to_string());

        let emission = gadget.emit(&inputs, &[], FieldId::Bn254, &params).unwrap();

        // At least the gate constraint
        assert!(!emission.constraints.is_empty());
    }

    #[test]
    fn plonk_gate_constant() {
        // q_C = 42, everything else 0 → should constrain 42 = 0 (unsatisfiable but valid emission)
        let gadget = PlonkGateGadget;
        let inputs = vec![
            zir::Expr::Signal("a".into()),
            zir::Expr::Signal("b".into()),
            zir::Expr::Signal("c".into()),
        ];
        let mut params = BTreeMap::new();
        params.insert("q_c".to_string(), "42".to_string());

        let emission = gadget.emit(&inputs, &[], FieldId::Bn254, &params).unwrap();
        assert!(!emission.constraints.is_empty());
    }

    #[test]
    fn plonk_gate_all_selectors() {
        // 2a + 3b - c + ab + 5 = 0
        let gadget = PlonkGateGadget;
        let inputs = vec![
            zir::Expr::Signal("a".into()),
            zir::Expr::Signal("b".into()),
            zir::Expr::Signal("c".into()),
        ];
        let mut params = BTreeMap::new();
        params.insert("q_l".to_string(), "2".to_string());
        params.insert("q_r".to_string(), "3".to_string());
        params.insert("q_o".to_string(), "-1".to_string());
        params.insert("q_m".to_string(), "1".to_string());
        params.insert("q_c".to_string(), "5".to_string());

        let emission = gadget
            .emit(&inputs, &["result".into()], FieldId::Bn254, &params)
            .unwrap();
        assert!(emission.constraints.len() >= 2);
        // 5 selector signals + 1 output signal
        assert!(emission.signals.len() >= 6);
    }

    #[test]
    fn plonk_gate_rejects_insufficient_inputs() {
        let gadget = PlonkGateGadget;
        let inputs = vec![zir::Expr::Signal("a".into())];
        let result = gadget.emit(&inputs, &[], FieldId::Bn254, &BTreeMap::new());
        assert!(result.is_err());
    }

    #[test]
    fn plonk_gate_wide_field_support() {
        let gadget = PlonkGateGadget;
        let fields = gadget.supported_fields();
        assert!(fields.len() >= 5);
        assert!(fields.contains(&FieldId::Goldilocks));
        assert!(fields.contains(&FieldId::BabyBear));
    }
}
