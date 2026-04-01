use crate::gadget::{
    Gadget, GadgetEmission, builtin_supported_fields, validate_builtin_field_support,
};
use crate::{nonnative, secp256k1};
use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{FieldId, ZkfError, ZkfResult};

/// ECDSA signature verification gadget.
///
/// Verifies an ECDSA signature over secp256k1 (default) or secp256r1.
///
/// Inputs (5): `[pub_key_x, pub_key_y, signature_r, signature_s, message_hash]`
/// Outputs (1): `["result"]` -- boolean verification result (0 or 1).
///
/// Params:
/// - `"curve"`: `"secp256k1"` (default) or `"secp256r1"`
/// - `"mode"`: `"blackbox"` (default) or `"decomposed"`
///
/// When `"mode"` is `"decomposed"`, the gadget emits full field-arithmetic constraints:
///   1. Decompose all 5 inputs into 4-limb representations.
///   2. Constrain pubkey is on curve: py² = px³ + 7 (secp256k1).
///   3. s_inv = s⁻¹ mod n.
///   4. u1 = hash * s_inv mod n,  u2 = r * s_inv mod n.
///   5. R' = u1*G + u2*PK  (2 scalar muls + 1 point add).
///   6. Assert R'.x mod n == r.
///
/// When `"mode"` is not `"decomposed"` (default), emits a BlackBox constraint.
pub struct EcdsaGadget;

impl Gadget for EcdsaGadget {
    fn name(&self) -> &str {
        "ecdsa"
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
        if inputs.len() != 5 {
            return Err(ZkfError::InvalidArtifact(format!(
                "ecdsa requires exactly 5 inputs (pub_key_x, pub_key_y, signature_r, \
                 signature_s, message_hash), got {}",
                inputs.len()
            )));
        }

        if outputs.len() != 1 {
            return Err(ZkfError::InvalidArtifact(format!(
                "ecdsa requires exactly 1 output, got {}",
                outputs.len()
            )));
        }

        let mode = params.get("mode").map(|s| s.as_str()).unwrap_or("blackbox");

        if mode == "decomposed" {
            emit_decomposed(inputs, outputs, params)
        } else {
            emit_blackbox(inputs, outputs, params)
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// BlackBox emission (default)
// ──────────────────────────────────────────────────────────────────────────────

fn emit_blackbox(
    inputs: &[zir::Expr],
    outputs: &[String],
    params: &BTreeMap<String, String>,
) -> ZkfResult<GadgetEmission> {
    let curve = params
        .get("curve")
        .map(|s| s.as_str())
        .unwrap_or("secp256k1");

    let op = match curve {
        "secp256k1" => zir::BlackBoxOp::EcdsaSecp256k1,
        "secp256r1" => zir::BlackBoxOp::EcdsaSecp256r1,
        other => {
            return Err(ZkfError::InvalidArtifact(format!(
                "ecdsa: unsupported curve '{}', expected 'secp256k1' or 'secp256r1'",
                other
            )));
        }
    };

    let result_name = &outputs[0];
    let mut emission = GadgetEmission::default();

    // Result signal: private boolean (0 = invalid, 1 = valid).
    emission.signals.push(zir::Signal {
        name: result_name.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Bool,
        constant: None,
    });

    // BlackBox constraint delegating to the backend's native ECDSA verifier.
    emission.constraints.push(zir::Constraint::BlackBox {
        op,
        inputs: inputs.to_vec(),
        outputs: outputs.to_vec(),
        params: BTreeMap::new(),
        label: Some(format!("ecdsa_{}_verify", curve)),
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

fn emit_decomposed(
    inputs: &[zir::Expr],
    outputs: &[String],
    _params: &BTreeMap<String, String>,
) -> ZkfResult<GadgetEmission> {
    #[cfg(not(test))]
    if std::env::var("ZKF_ALLOW_EXPERIMENTAL_GADGETS").as_deref() != Ok("1") {
        return Err(ZkfError::Backend(
            "Decomposed ECDSA gadget has known soundness gaps (result signal \
             hardcoded to 1; missing public-input binding). Use BlackBox mode for production. \
             Set ZKF_ALLOW_EXPERIMENTAL_GADGETS=1 to override."
                .to_string(),
        ));
    }

    let mut emission = GadgetEmission::default();

    // Extract input signal names (we require Signal expressions for decomposed mode).
    let input_names: Vec<String> = inputs
        .iter()
        .enumerate()
        .map(|(i, expr)| match expr {
            zir::Expr::Signal(name) => name.clone(),
            _ => format!("__ecdsa_input_{}", i),
        })
        .collect();

    let pk_x = &input_names[0];
    let pk_y = &input_names[1];
    let sig_r = &input_names[2];
    let sig_s = &input_names[3];
    let msg_hash = &input_names[4];

    let result_name = &outputs[0];

    // ── Step 0: emit n (group order) as a field signal ────────────────────────
    let n_signal = "ecdsa_decomp_n".to_string();
    emission.signals.push(zir::Signal {
        name: n_signal.clone(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: None,
    });

    // ── Step 1: Decompose all 5 inputs into 4-limb representations ───────────
    nonnative::decompose_256bit(&mut emission, "ecdsa_decomp_pkx", pk_x);
    nonnative::decompose_256bit(&mut emission, "ecdsa_decomp_pky", pk_y);
    nonnative::decompose_256bit(&mut emission, "ecdsa_decomp_r", sig_r);
    nonnative::decompose_256bit(&mut emission, "ecdsa_decomp_s", sig_s);
    nonnative::decompose_256bit(&mut emission, "ecdsa_decomp_h", msg_hash);

    // ── Step 2: Constrain pubkey on curve ─────────────────────────────────────
    secp256k1::constrain_on_curve(&mut emission, "ecdsa_decomp", pk_x, pk_y);

    // ── Step 3: s_inv = s⁻¹ mod n ────────────────────────────────────────────
    nonnative::nonnative_inverse(&mut emission, "ecdsa_decomp_sinv", sig_s, &n_signal);

    let s_inv_signal = "ecdsa_decomp_sinv_inv".to_string();

    // ── Step 4: u1 = hash * s_inv mod n,  u2 = r * s_inv mod n ───────────────
    nonnative::nonnative_mul(
        &mut emission,
        "ecdsa_decomp_u1",
        msg_hash,
        &s_inv_signal,
        &n_signal,
    );
    let u1_signal = "ecdsa_decomp_u1_mul_result".to_string();

    nonnative::nonnative_mul(
        &mut emission,
        "ecdsa_decomp_u2",
        sig_r,
        &s_inv_signal,
        &n_signal,
    );
    let u2_signal = "ecdsa_decomp_u2_mul_result".to_string();

    // ── Step 5: R' = u1*G + u2*PK ────────────────────────────────────────────
    // 5a. u1 * G (secp256k1 generator).
    let gx_signal = "ecdsa_decomp_gx".to_string();
    let gy_signal = "ecdsa_decomp_gy".to_string();
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
        "ecdsa_decomp_u1g",
        &u1_signal,
        &gx_signal,
        &gy_signal,
    );

    // The last accumulator after 256 iterations is the result of u1*G.
    let u1g_x = "ecdsa_decomp_u1g_smul_acc_x_256".to_string();
    let u1g_y = "ecdsa_decomp_u1g_smul_acc_y_256".to_string();

    // 5b. u2 * PK.
    secp256k1::scalar_mul_constrained(&mut emission, "ecdsa_decomp_u2pk", &u2_signal, pk_x, pk_y);

    let u2pk_x = "ecdsa_decomp_u2pk_smul_acc_x_256".to_string();
    let u2pk_y = "ecdsa_decomp_u2pk_smul_acc_y_256".to_string();

    // 5c. R' = u1G + u2PK.
    secp256k1::point_add(
        &mut emission,
        "ecdsa_decomp_rprime",
        &u1g_x,
        &u1g_y,
        &u2pk_x,
        &u2pk_y,
    );

    let r_prime_x = "ecdsa_decomp_rprime_padd_rx".to_string();

    // ── Step 6: r_prime_x mod n == r ─────────────────────────────────────────
    // Reduce r_prime_x mod n (using nonnative_sub with quotient witness).
    nonnative::nonnative_mul(
        &mut emission,
        "ecdsa_decomp_rx_modn",
        &r_prime_x,
        "ecdsa_decomp_n_one", // 1 mod n (constant)
        &n_signal,
    );
    // The result of the above "mul by 1" gives us r_prime_x mod n.
    let r_prime_x_mod_n = "ecdsa_decomp_rx_modn_mul_result".to_string();
    // Emit the constant-1 signal.
    emission.signals.push(zir::Signal {
        name: "ecdsa_decomp_n_one".to_string(),
        visibility: zkf_core::Visibility::Private,
        ty: zir::SignalType::Field,
        constant: Some(zkf_core::FieldElement::from_i64(1)),
    });

    // Assert r_prime_x_mod_n == sig_r.
    nonnative::nonnative_equal(
        &mut emission,
        "ecdsa_decomp_verify",
        &r_prime_x_mod_n,
        sig_r,
    );

    // ── Result signal ─────────────────────────────────────────────────────────
    // In decomposed mode, verification is expressed purely via constraints.
    // If all constraints are satisfied, verification passed.  We emit a
    // result signal that is constrained to 1 (constraints enforce this).
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
            zir::Expr::Signal("sig_r".into()),
            zir::Expr::Signal("sig_s".into()),
            zir::Expr::Signal("msg_hash".into()),
        ]
    }

    // ── Existing BlackBox tests (unchanged) ───────────────────────────────────

    #[test]
    fn ecdsa_secp256k1_default() {
        let gadget = EcdsaGadget;
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
                op: zir::BlackBoxOp::EcdsaSecp256k1,
                ..
            }
        ));
        assert!(matches!(
            &emission.constraints[1],
            zir::Constraint::Boolean { signal, .. } if signal == "result"
        ));
    }

    #[test]
    fn ecdsa_secp256r1_via_param() {
        let gadget = EcdsaGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("curve".into(), "secp256r1".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        assert!(matches!(
            &emission.constraints[0],
            zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::EcdsaSecp256r1,
                ..
            }
        ));
    }

    #[test]
    fn ecdsa_rejects_wrong_input_count() {
        let gadget = EcdsaGadget;
        let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];
        let outputs = vec!["result".to_string()];

        let err = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &BTreeMap::new())
            .unwrap_err();
        assert!(err.to_string().contains("5 inputs"));
    }

    #[test]
    fn ecdsa_rejects_wrong_output_count() {
        let gadget = EcdsaGadget;
        let inputs = make_inputs();
        let outputs = vec!["a".to_string(), "b".to_string()];

        let err = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &BTreeMap::new())
            .unwrap_err();
        assert!(err.to_string().contains("1 output"));
    }

    #[test]
    fn ecdsa_rejects_unknown_curve() {
        let gadget = EcdsaGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("curve".into(), "secp384r1".into());

        let err = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap_err();
        assert!(err.to_string().contains("unsupported curve"));
    }

    #[test]
    fn ecdsa_blackbox_carries_all_inputs_and_outputs() {
        let gadget = EcdsaGadget;
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
            assert_eq!(bb_inputs.len(), 5);
            assert_eq!(bb_outputs, &["result".to_string()]);
        } else {
            panic!("expected BlackBox constraint");
        }
    }

    // ── New: mode=blackbox explicit ───────────────────────────────────────────

    #[test]
    fn ecdsa_mode_blackbox_explicit_is_same_as_default() {
        let gadget = EcdsaGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "blackbox".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        // Should behave identically to default (no mode param).
        assert_eq!(emission.signals.len(), 1);
        assert_eq!(emission.constraints.len(), 2);
        assert!(matches!(
            &emission.constraints[0],
            zir::Constraint::BlackBox {
                op: zir::BlackBoxOp::EcdsaSecp256k1,
                ..
            }
        ));
    }

    // ── New: mode=decomposed ──────────────────────────────────────────────────

    #[test]
    fn ecdsa_decomposed_mode_emits_many_signals() {
        let gadget = EcdsaGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        // Decomposed mode should emit a large number of signals (limbs, intermediates, etc.)
        assert!(
            emission.signals.len() > 50,
            "expected more than 50 signals in decomposed mode, got {}",
            emission.signals.len()
        );
    }

    #[test]
    fn ecdsa_decomposed_mode_emits_many_constraints() {
        let gadget = EcdsaGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        // Should have a substantial number of constraints from full field arithmetic.
        assert!(
            emission.constraints.len() > 100,
            "expected more than 100 constraints in decomposed mode, got {}",
            emission.constraints.len()
        );
    }

    #[test]
    fn ecdsa_decomposed_mode_has_no_blackbox_constraint() {
        let gadget = EcdsaGadget;
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
    fn ecdsa_decomposed_mode_has_result_signal() {
        let gadget = EcdsaGadget;
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
                .any(|s| s.name == "result" && s.ty == zir::SignalType::Bool)
        );
    }

    #[test]
    fn ecdsa_decomposed_decomposes_all_five_inputs() {
        let gadget = EcdsaGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        // Each input is decomposed into 4 limbs; check a few.
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "ecdsa_decomp_pkx_limb_0")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "ecdsa_decomp_pky_limb_3")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "ecdsa_decomp_r_limb_2")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "ecdsa_decomp_s_limb_1")
        );
        assert!(
            emission
                .signals
                .iter()
                .any(|s| s.name == "ecdsa_decomp_h_limb_0")
        );
    }

    #[test]
    fn ecdsa_decomposed_has_on_curve_check() {
        let gadget = EcdsaGadget;
        let inputs = make_inputs();
        let outputs = vec!["result".to_string()];
        let mut params = BTreeMap::new();
        params.insert("mode".into(), "decomposed".into());

        let emission = gadget
            .emit(&inputs, &outputs, FieldId::Bn254, &params)
            .unwrap();

        let has_oncurve = emission.constraints.iter().any(
            |c| matches!(c, zir::Constraint::Equal { label: Some(l), .. } if l.contains("oncurve")),
        );
        assert!(
            has_oncurve,
            "expected on-curve constraints in decomposed mode"
        );
    }
}
