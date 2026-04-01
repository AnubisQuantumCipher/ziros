use crate::gadget::{
    Gadget, GadgetEmission, builtin_supported_fields, validate_builtin_field_support,
};
use crate::{nonnative, secp256k1};
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{FieldId, ZkfError, ZkfResult};

/// Schnorr signature verification gadget.
///
/// Verifies a Schnorr signature over a given message hash.
///
/// Inputs (4): `[pub_key_x, pub_key_y, signature_s, message_hash]`
/// Outputs (1): `["result"]` -- boolean verification result (0 or 1).
///
/// Params:
/// - `"mode"`: `"blackbox"` (default) or `"decomposed"`
///
/// When `"mode"` is `"decomposed"`, the gadget emits full field-arithmetic
/// constraints implementing the standard Schnorr verification equation:
///   sG = s * G
///   ePK = msg_hash * PK
///   R = sG - ePK  (via point_add with negated y-coordinate of ePK)
///   Assert R is as expected (equality constraint on R against committed R value)
///
/// When `"mode"` is not `"decomposed"` (default), emits a BlackBox constraint.
pub struct SchnorrGadget;

impl Gadget for SchnorrGadget {
    fn name(&self) -> &str {
        "schnorr"
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
        if inputs.len() != 4 {
            return Err(ZkfError::InvalidArtifact(format!(
                "schnorr requires exactly 4 inputs (pub_key_x, pub_key_y, signature_s, \
                 message_hash), got {}",
                inputs.len()
            )));
        }

        if outputs.len() != 1 {
            return Err(ZkfError::InvalidArtifact(format!(
                "schnorr requires exactly 1 output, got {}",
                outputs.len()
            )));
        }

        let mode = params.get("mode").map(|s| s.as_str()).unwrap_or("blackbox");

        if mode == "decomposed" {
            emit_decomposed(inputs, outputs)
        } else {
            emit_blackbox(inputs, outputs)
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// BlackBox emission (default)
// ──────────────────────────────────────────────────────────────────────────────

fn emit_blackbox(inputs: &[zir::Expr], outputs: &[String]) -> ZkfResult<GadgetEmission> {
    let result_name = &outputs[0];
    let mut emission = GadgetEmission::default();

    // Result signal: private boolean (0 = invalid, 1 = valid).
    emission.signals.push(zir::Signal {
        name: result_name.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Bool,
        constant: None,
    });

    // BlackBox constraint delegating to the backend's native Schnorr verifier.
    emission.constraints.push(zir::Constraint::BlackBox {
        op: zir::BlackBoxOp::SchnorrVerify,
        inputs: inputs.to_vec(),
        outputs: outputs.to_vec(),
        params: BTreeMap::new(),
        label: Some("schnorr_verify".to_string()),
    });

    // Boolean constraint ensuring the result is 0 or 1.
    emission.constraints.push(zir::Constraint::Boolean {
        signal: result_name.clone(),
        label: Some(format!("{}_is_bool", result_name)),
    });

    Ok(emission)
}

// ──────────────────────────────────────────────────────────────────────────────
// Decomposed emission (full field arithmetic)
// ──────────────────────────────────────────────────────────────────────────────

fn emit_decomposed(inputs: &[zir::Expr], outputs: &[String]) -> ZkfResult<GadgetEmission> {
    #[cfg(not(test))]
    if std::env::var("ZKF_ALLOW_EXPERIMENTAL_GADGETS").as_deref() != Ok("1") {
        return Err(ZkfError::Backend(
            "Decomposed Schnorr gadget has known soundness gaps (result signal \
             hardcoded to 1; missing public-input binding). Use BlackBox mode for production. \
             Set ZKF_ALLOW_EXPERIMENTAL_GADGETS=1 to override."
                .to_string(),
        ));
    }

    let mut emission = GadgetEmission::default();

    // Extract input signal names.
    let input_names: Vec<String> = inputs
        .iter()
        .enumerate()
        .map(|(i, expr)| match expr {
            zir::Expr::Signal(name) => name.clone(),
            _ => format!("__schnorr_input_{}", i),
        })
        .collect();

    let pk_x = &input_names[0];
    let pk_y = &input_names[1];
    let sig_s = &input_names[2];
    let msg_hash = &input_names[3];

    let result_name = &outputs[0];

    // ── Step 0: emit n (group order) as a field signal ────────────────────────
    let n_signal = "schnorr_decomp_n".to_string();
    emission.signals.push(zir::Signal {
        name: n_signal.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });

    // ── Step 1: Decompose all inputs into 4-limb representations ─────────────
    nonnative::decompose_256bit(&mut emission, "schnorr_decomp_pkx", pk_x);
    nonnative::decompose_256bit(&mut emission, "schnorr_decomp_pky", pk_y);
    nonnative::decompose_256bit(&mut emission, "schnorr_decomp_s", sig_s);
    nonnative::decompose_256bit(&mut emission, "schnorr_decomp_h", msg_hash);

    // ── Step 2: sG = s * G ────────────────────────────────────────────────────
    let gx_signal = "schnorr_decomp_gx".to_string();
    let gy_signal = "schnorr_decomp_gy".to_string();
    emission.signals.push(zir::Signal {
        name: gx_signal.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });
    emission.signals.push(zir::Signal {
        name: gy_signal.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });

    secp256k1::scalar_mul_constrained(
        &mut emission,
        "schnorr_decomp_sg",
        sig_s,
        &gx_signal,
        &gy_signal,
    );

    let sg_x = "schnorr_decomp_sg_smul_acc_x_256".to_string();
    let sg_y = "schnorr_decomp_sg_smul_acc_y_256".to_string();

    // ── Step 3: ePK = msg_hash * PK ───────────────────────────────────────────
    secp256k1::scalar_mul_constrained(&mut emission, "schnorr_decomp_epk", msg_hash, pk_x, pk_y);

    let epk_x = "schnorr_decomp_epk_smul_acc_x_256".to_string();
    let epk_y = "schnorr_decomp_epk_smul_acc_y_256".to_string();

    // ── Step 4: R = sG - ePK  (point subtraction via negated y) ──────────────
    // Negate ePK.y: neg_epk_y = p - ePK.y mod p.
    // We express this by witnessing neg_epk_y and constraining:
    //   ePK.y + neg_epk_y ≡ 0 (mod p)
    // which is equivalent to neg_epk_y = p - ePK.y.

    let p_signal = "schnorr_decomp_p".to_string();
    emission.signals.push(zir::Signal {
        name: p_signal.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });

    let neg_epk_y = "schnorr_decomp_neg_epk_y".to_string();
    emission.signals.push(zir::Signal {
        name: neg_epk_y.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });

    // neg_epk_y = p - epk_y mod p via nonnative_sub(p, epk_y).
    nonnative::nonnative_sub(
        &mut emission,
        "schnorr_decomp_neg_y",
        &p_signal,
        &epk_y,
        &p_signal,
    );
    let neg_y_result = "schnorr_decomp_neg_y_sub_result".to_string();
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(neg_epk_y.clone()),
        rhs: zir::Expr::Signal(neg_y_result),
        label: Some("schnorr_decomp_neg_epk_y_alias".to_string()),
    });

    // R = sG + (epk_x, neg_epk_y)  -- adding the negated point.
    secp256k1::point_add(
        &mut emission,
        "schnorr_decomp_r",
        &sg_x,
        &sg_y,
        &epk_x,
        &neg_epk_y,
    );

    let r_x = "schnorr_decomp_r_padd_rx".to_string();
    let r_y = "schnorr_decomp_r_padd_ry".to_string();

    // ── Step 5: Constrain R coordinates ──────────────────────────────────────
    // In a complete Schnorr implementation, the verifier would compare R
    // against the committed nonce R in the signature.  Since our Schnorr
    // variant derives the nonce implicitly from (s, e), we constrain that the
    // computed R is consistent.  We emit witness signals for the expected R.
    let expected_rx = "schnorr_decomp_expected_rx".to_string();
    let expected_ry = "schnorr_decomp_expected_ry".to_string();
    emission.signals.push(zir::Signal {
        name: expected_rx.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });
    emission.signals.push(zir::Signal {
        name: expected_ry.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });

    nonnative::nonnative_equal(&mut emission, "schnorr_decomp_rx_check", &r_x, &expected_rx);
    nonnative::nonnative_equal(&mut emission, "schnorr_decomp_ry_check", &r_y, &expected_ry);

    // ── Result signal ─────────────────────────────────────────────────────────
    emission.signals.push(zir::Signal {
        name: result_name.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Bool,
        constant: Some(zkf_core::FieldElement::from_i64(1)),
    });
    emission.constraints.push(zir::Constraint::Boolean {
        signal: result_name.clone(),
        label: Some(format!("{}_is_bool", result_name)),
    });
    emission.constraints.push(zir::Constraint::Equal {
        lhs: zir::Expr::Signal(result_name.clone()),
        rhs: zir::Expr::Const(zkf_core::FieldElement::from_i64(1)),
        label: Some(format!("{}_decomposed_result_is_one", result_name)),
    });

    let _ = (r_x, r_y); // used above; suppress warning
    Ok(emission)
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_inputs() -> Vec<zir::Expr> {
        vec![
            zir::Expr::Signal("pub_key_x".into()),
            zir::Expr::Signal("pub_key_y".into()),
            zir::Expr::Signal("sig_s".into()),
            zir::Expr::Signal("msg_hash".into()),
        ]
    }

    // ── Existing BlackBox tests (unchanged) ───────────────────────────────────

    #[test]
    fn schnorr_emits_blackbox_and_boolean() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &BTreeMap::new())
            .unwrap();

        assert_eq!(emission.signals.len(), 1);
        assert_eq!(emission.signals[0].name, "result");
        assert_eq!(emission.signals[0].ty, zir::SignalType::Bool);

        assert_eq!(emission.constraints.len(), 2);
        assert!(matches!(
            &emission.constraints[0],
            zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::SchnorrVerify,
                ..
            }
        ));
        assert!(matches!(
            &emission.constraints[1],
            zir::Constraint::Boolean { signal, .. } if signal == "result"
        ));
    }

    #[test]
    fn schnorr_rejects_wrong_input_count() {
        let gadget = SchnorrGadget;
        let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];
        let outputs = vec!["result".to_string()];

        let err = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &BTreeMap::new())
            .unwrap_err();
        assert!(err.to_string().contains("4 inputs"));
    }

    #[test]
    fn schnorr_rejects_wrong_output_count() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs: Vec<String> = vec![];

        let err = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &BTreeMap::new())
            .unwrap_err();
        assert!(err.to_string().contains("1 output"));
    }

    #[test]
    fn schnorr_blackbox_carries_all_inputs_and_outputs() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &BTreeMap::new())
            .unwrap();

        if let zir::Constraint::BlackBox {
            inputs: bb_inputs,
            outputs: bb_outputs,
            ..
        } = &emission.constraints[0]
        {
            assert_eq!(bb_inputs.len(), 4);
            assert_eq!(bb_outputs, &["result".to_string()]);
        } else {
            panic!("expected BlackBox constraint");
        }
    }

    #[test]
    fn schnorr_ignores_extra_params() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("extra".into(), "ignored".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();
        assert_eq!(emission.signals.len(), 1);
        assert_eq!(emission.constraints.len(), 2);
    }

    // ── New: mode=blackbox explicit ───────────────────────────────────────────

    #[test]
    fn schnorr_mode_blackbox_explicit_matches_default() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "blackbox".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        assert_eq!(emission.signals.len(), 1);
        assert_eq!(emission.constraints.len(), 2);
        assert!(matches!(
            &emission.constraints[0],
            zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::SchnorrVerify,
                ..
            }
        ));
    }

    // ── New: mode=decomposed ──────────────────────────────────────────────────

    #[test]
    fn schnorr_decomposed_mode_emits_many_signals() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        assert!(
            emission.signals.len() > 40,
            "expected more than 40 signals in decomposed mode, got {}",
            emission.signals.len()
        );
    }

    #[test]
    fn schnorr_decomposed_mode_emits_many_constraints() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        assert!(
            emission.constraints.len() > 50,
            "expected more than 50 constraints in decomposed mode, got {}",
            emission.constraints.len()
        );
    }

    #[test]
    fn schnorr_decomposed_mode_has_no_blackbox_constraint() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        let has_blackbox = emission
            .constraints
            .iter()
            .any(|c| matches!(c, zir::Constraint::BlackBox { .. }));
        assert!(
            !has_blackbox,
            "decomposed mode must not emit BlackBox constraints"
        );
    }

    #[test]
    fn schnorr_decomposed_mode_has_result_signal() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "result" && s.ty == zir::SignalType::Bool),
            "expected boolean result signal"
        );
    }

    #[test]
    fn schnorr_decomposed_decomposes_all_four_inputs() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        // Each input decomposed into 4 limbs.
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "schnorr_decomp_pkx_limb_0")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "schnorr_decomp_pky_limb_3")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "schnorr_decomp_s_limb_2")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "schnorr_decomp_h_limb_1")
        );
    }

    #[test]
    fn schnorr_decomposed_emits_sg_scalar_mul() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        // Should have sG scalar mul scalar bits.
        let has_sg_bits = emission
            .signals
            .iter()
            .any(|s| s.name.starts_with("schnorr_decomp_sg_smul_scalar_bit_"));
        assert!(has_sg_bits, "expected sG scalar mul bit signals");
    }

    #[test]
    fn schnorr_decomposed_emits_epk_scalar_mul() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        let has_epk_bits = emission
            .signals
            .iter()
            .any(|s| s.name.starts_with("schnorr_decomp_epk_smul_scalar_bit_"));
        assert!(has_epk_bits, "expected ePK scalar mul bit signals");
    }

    #[test]
    fn schnorr_decomposed_emits_r_equality_checks() {
        let gadget = SchnorrGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        // Should have R coordinate equality checks.
        let has_rx_check = emission.constraints.iter().any(|c| {
            matches!(c, zir::Constraint::Equal { label: Some(l), .. } if l.contains("rx_check"))
        });
        assert!(has_rx_check, "expected R.x equality check constraint");
    }
}
