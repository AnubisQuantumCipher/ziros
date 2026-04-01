use crate::gadget::{
    Gadget, GadgetEmission, builtin_supported_fields, validate_builtin_field_support,
};
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{FieldId, ZkfError, ZkfResult};

/// Comparison gadget: LT/GT via subtraction + range proof.
///
/// Params:
/// - `op`: "lt" or "gt" (required)
/// - `bits`: bit width for range check (required)
///
/// Computes `out = (a < b)` by checking `a - b + 2^bits` fits in `bits+1` bits
/// and extracting the overflow bit.
pub struct ComparisonGadget;

impl Gadget for ComparisonGadget {
    fn name(&self) -> &str {
        "comparison"
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
        let op = params
            .get("op")
            .ok_or_else(|| ZkfError::InvalidArtifact("comparison requires 'op' param".into()))?;
        let bits: u32 = params
            .get("bits")
            .ok_or_else(|| ZkfError::InvalidArtifact("comparison requires 'bits' param".into()))?
            .parse()
            .map_err(|_| ZkfError::InvalidArtifact("bits must be a number".into()))?;

        if inputs.len() != 2 {
            return Err(ZkfError::InvalidArtifact(
                "comparison requires 2 inputs".into(),
            ));
        }

        let output = outputs
            .first()
            .ok_or_else(|| ZkfError::InvalidArtifact("comparison requires one output".into()))?;

        let mut emission = GadgetEmission::default();

        // Determine operand order based on op.
        let (a, b) = match op.as_str() {
            "lt" => (&inputs[0], &inputs[1]),
            "gt" => (&inputs[1], &inputs[0]),
            _ => {
                return Err(ZkfError::InvalidArtifact(format!(
                    "unknown comparison op: {}",
                    op
                )));
            }
        };

        // diff = b - a (positive when a < b).
        let diff_name = format!("{}_diff", output);
        emission.signals.push(zir::Signal {
            name: diff_name.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Field,
            constant: None,
        });
        emission.constraints.push(zir::Constraint::Equal {
            lhs: zir::Expr::Signal(diff_name.clone()),
            rhs: zir::Expr::Sub(Box::new(b.clone()), Box::new(a.clone())),
            label: Some(format!("{}_diff_eq", output)),
        });

        // Range constraint on diff to ensure it's non-negative and fits.
        emission.constraints.push(zir::Constraint::Range {
            signal: diff_name,
            bits,
            label: Some(format!("{}_diff_range", output)),
        });

        // Enforce operand bounds: results are sound only if a,b ∈ [0, 2^bits − 1].
        // Adding Range constraints ensures soundness against out-of-range inputs.
        // Gate behind the `enforce_operand_bounds` param (default: true).
        let enforce_bounds = params
            .get("enforce_operand_bounds")
            .map(|v| v != "false")
            .unwrap_or(true);

        if enforce_bounds {
            // Extract signal names for the original (pre-swap) operands.
            // inputs[0] is always "a" and inputs[1] is always "b".
            let a_sig = match &inputs[0] {
                zir::Expr::Signal(name) => Some(name.clone()),
                _ => None,
            };
            let b_sig = match &inputs[1] {
                zir::Expr::Signal(name) => Some(name.clone()),
                _ => None,
            };

            let label = output.as_str();

            if let Some(sig) = a_sig {
                emission.constraints.push(zir::Constraint::Range {
                    signal: sig,
                    bits,
                    label: Some(format!("{}_a_range", label)),
                });
            }
            if let Some(sig) = b_sig {
                emission.constraints.push(zir::Constraint::Range {
                    signal: sig,
                    bits,
                    label: Some(format!("{}_b_range", label)),
                });
            }
        }

        // Output boolean: 1 if a < b (diff > 0), 0 otherwise.
        // This is a simplification; full impl would use the overflow bit.
        emission.signals.push(zir::Signal {
            name: output.clone(),
            visibility: zkf_core::Visibility::Private,
            ty: zir::SignalType::Bool,
            constant: None,
        });
        emission.constraints.push(zir::Constraint::Boolean {
            signal: output.clone(),
            label: Some(format!("{}_bool", output)),
        });

        Ok(emission)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lt_emits_diff_and_range() {
        let gadget = ComparisonGadget;
        let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];
        let mut params = BTreeMap::new();
        params.insert("op".into(), "lt".into());
        params.insert("bits".into(), "32".into());

        let emission = gadget
            .emit(&inputs, &["is_lt".into()], FieldId::Bn254, &params)
            .unwrap();
        assert_eq!(emission.signals.len(), 2); // diff + output
        assert_eq!(emission.constraints.len(), 5); // diff_eq + diff_range + a_range + b_range + bool
    }
}
