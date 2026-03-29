//! ECDSA signature verification as arithmetic constraints over the shipped
//! BN254-backed `160 -> 1` byte ABI.
//!
//! Inputs are 160 private byte expressions:
//! `[pkx(32), pky(32), sig_r(32), sig_s(32), msg(32)]`
//! and the single output is a boolean result signal.
//!
//! The lowering keeps malformed surfaces fail-closed, but ABI-conformant inputs
//! must remain satisfiable with `result = 0` for invalid signatures. To achieve
//! that, the gadget computes boolean format predicates first, sanitizes invalid
//! inputs onto a fixed safe branch, and then forces the final output to equal
//! the complete verification predicate.

use super::{AuxCounter, LoweredBlackBox, bits, constraint_instance_suffix};
use crate::proof_blackbox_ecdsa_spec::SupportedCriticalEcdsaCurve;
#[cfg(feature = "native-blackbox-solvers")]
use acvm_blackbox_solver::{ecdsa_secp256k1_verify, ecdsa_secp256r1_verify};
use num_bigint::{BigInt, Sign};
use num_traits::{One, Zero};
use std::array;
use std::collections::BTreeMap;
use zkf_core::{
    Expr, FieldElement, FieldId, Signal, Visibility, ZkfError, ZkfResult, mod_inverse_bigint,
    normalize_mod,
};

#[derive(Clone)]
struct CurveConfig {
    name: &'static str,
    p: BigInt,
    n: BigInt,
    half_n: BigInt,
    a: BigInt,
    b: BigInt,
    gx: BigInt,
    gy: BigInt,
}

#[derive(Clone)]
struct CurveConstSignals {
    p: String,
    n: String,
    _half_n: String,
    a: String,
    b: String,
    gx: String,
    gy: String,
    zero: String,
    one: String,
    two: String,
    three: String,
}

#[derive(Clone)]
struct U256Var {
    signal: String,
    _limbs: [String; 4],
}

#[derive(Clone)]
struct PointVar {
    x: U256Var,
    y: U256Var,
    is_identity: String,
}

#[derive(Clone)]
struct RuntimePoint {
    x: BigInt,
    y: BigInt,
    is_identity: bool,
}

#[derive(Clone)]
struct ByteCmpSignals {
    lt: String,
    eq: String,
}

#[derive(Clone)]
struct ByteCmpValues {
    lt: bool,
    eq: bool,
}

pub fn lower_ecdsa(
    inputs: &[Expr],
    outputs: &[String],
    _params: &BTreeMap<String, String>,
    field: FieldId,
    aux: &mut AuxCounter,
    curve: &str,
) -> Result<LoweredBlackBox, String> {
    if !cfg!(feature = "native-blackbox-solvers") {
        return Err(
            "ecdsa lowering requires a build with native-blackbox-solvers enabled".to_string(),
        );
    }
    if field != FieldId::Bn254 {
        return Err(format!(
            "ecdsa {curve} lowering only supports BN254 programs, found {field}"
        ));
    }
    if inputs.len() != 160 {
        return Err(format!(
            "ecdsa {curve}: expected 160 input bytes (pkx[32], pky[32], sig_r[32], sig_s[32], msg[32]), got {}",
            inputs.len()
        ));
    }
    if outputs.len() != 1 {
        return Err(format!(
            "ecdsa {curve}: expected 1 output (boolean result), got {}",
            outputs.len()
        ));
    }

    let curve = curve_config_by_name(curve)?;
    let mut lowered = LoweredBlackBox::default();
    let consts = add_curve_constants(&mut lowered, &curve);
    lowered.add_boolean(outputs[0].clone(), format!("{}_result_bool", curve.name));

    // Range constrain every input expression to a single byte and expose the
    // decomposition bits so witness enrichment can deterministically fill them.
    for (index, input) in inputs.iter().enumerate() {
        let _ = bits::decompose_to_bits(
            &mut lowered,
            aux,
            input.clone(),
            8,
            &format!("{}_byte_{index}", curve.name),
        );
    }

    let pkx = alias_expr_to_u256(
        &mut lowered,
        aux,
        reconstruct_256bit_expr(&inputs[0..32]),
        &format!("{}_pkx", curve.name),
    );
    let pky = alias_expr_to_u256(
        &mut lowered,
        aux,
        reconstruct_256bit_expr(&inputs[32..64]),
        &format!("{}_pky", curve.name),
    );
    let sig_r = alias_expr_to_u256(
        &mut lowered,
        aux,
        reconstruct_256bit_expr(&inputs[64..96]),
        &format!("{}_sig_r", curve.name),
    );
    let sig_s = alias_expr_to_u256(
        &mut lowered,
        aux,
        reconstruct_256bit_expr(&inputs[96..128]),
        &format!("{}_sig_s", curve.name),
    );
    let msg = alias_expr_to_u256(
        &mut lowered,
        aux,
        reconstruct_256bit_expr(&inputs[128..160]),
        &format!("{}_msg", curve.name),
    );

    let r_nonzero = bytes_any_nonzero(
        &mut lowered,
        aux,
        &inputs[64..96],
        &format!("{}_r_nonzero", curve.name),
        &consts,
    );
    let s_nonzero = bytes_any_nonzero(
        &mut lowered,
        aux,
        &inputs[96..128],
        &format!("{}_s_nonzero", curve.name),
        &consts,
    );
    let pk_nonzero = bytes_any_nonzero(
        &mut lowered,
        aux,
        &inputs[0..64],
        &format!("{}_pk_nonzero", curve.name),
        &consts,
    );

    let p_bytes = bigint_to_be_bytes32(&curve.p);
    let n_bytes = bigint_to_be_bytes32(&curve.n);
    let half_n_bytes = bigint_to_be_bytes32(&curve.half_n);

    let pkx_lt_p = bytes_lt_const(
        &mut lowered,
        aux,
        &inputs[0..32],
        &p_bytes,
        &format!("{}_pkx_lt_p", curve.name),
        &consts,
    );
    let pky_lt_p = bytes_lt_const(
        &mut lowered,
        aux,
        &inputs[32..64],
        &p_bytes,
        &format!("{}_pky_lt_p", curve.name),
        &consts,
    );
    let r_lt_n = bytes_lt_const(
        &mut lowered,
        aux,
        &inputs[64..96],
        &n_bytes,
        &format!("{}_r_lt_n", curve.name),
        &consts,
    );
    let s_lt_n = bytes_lt_const(
        &mut lowered,
        aux,
        &inputs[96..128],
        &n_bytes,
        &format!("{}_s_lt_n", curve.name),
        &consts,
    );
    let low_s = bytes_lte_const(
        &mut lowered,
        aux,
        &inputs[96..128],
        &half_n_bytes,
        &format!("{}_low_s", curve.name),
        &consts,
    );
    let msg_lt_n = bytes_lt_const(
        &mut lowered,
        aux,
        &inputs[128..160],
        &n_bytes,
        &format!("{}_msg_lt_n", curve.name),
        &consts,
    );

    let on_curve = curve_on_curve_bit(
        &mut lowered,
        aux,
        &curve,
        &consts,
        &pkx.signal,
        &pky.signal,
        &format!("{}_pk_on_curve", curve.name),
    );

    let sig_ok_0 = and_bit(&mut lowered, aux, &r_nonzero, &r_lt_n, "sig_ok_r");
    let sig_ok_1 = and_bit(&mut lowered, aux, &s_nonzero, &s_lt_n, "sig_ok_s");
    let sig_ok_2 = and_bit(&mut lowered, aux, &sig_ok_0, &sig_ok_1, "sig_ok_pair");
    let sig_ok = and_bit(&mut lowered, aux, &sig_ok_2, &low_s, "sig_ok");

    let pk_ok_0 = and_bit(&mut lowered, aux, &pkx_lt_p, &pky_lt_p, "pk_ok_lt");
    let pk_ok_1 = and_bit(&mut lowered, aux, &pk_nonzero, &on_curve, "pk_ok_curve");
    let pk_ok = and_bit(&mut lowered, aux, &pk_ok_0, &pk_ok_1, "pk_ok");

    let safe_r = select_u256_expr(
        &mut lowered,
        aux,
        &sig_ok,
        Expr::Signal(sig_r.signal.clone()),
        Expr::Signal(consts.one.clone()),
        "safe_r",
    );
    let safe_s = select_u256_expr(
        &mut lowered,
        aux,
        &sig_ok,
        Expr::Signal(sig_s.signal.clone()),
        Expr::Signal(consts.one.clone()),
        "safe_s",
    );
    let safe_msg = select_u256_expr(
        &mut lowered,
        aux,
        &msg_lt_n,
        Expr::Signal(msg.signal.clone()),
        Expr::Signal(consts.zero.clone()),
        "safe_msg",
    );
    let safe_pkx = select_u256_expr(
        &mut lowered,
        aux,
        &pk_ok,
        Expr::Signal(pkx.signal.clone()),
        Expr::Signal(consts.gx.clone()),
        "safe_pkx",
    );
    let safe_pky = select_u256_expr(
        &mut lowered,
        aux,
        &pk_ok,
        Expr::Signal(pky.signal.clone()),
        Expr::Signal(consts.gy.clone()),
        "safe_pky",
    );
    let safe_pk = point_from_xy(
        safe_pkx.clone(),
        safe_pky.clone(),
        select_bool(
            &mut lowered,
            aux,
            &pk_ok,
            Expr::Const(FieldElement::from_i64(0)),
            Expr::Const(FieldElement::from_i64(0)),
            "safe_pk_is_identity",
        ),
    );

    let s_inv = mod_inv_u256(&mut lowered, aux, &safe_s.signal, &consts.n, "s_inv_mod_n");
    let u1 = mod_mul_u256(
        &mut lowered,
        aux,
        &safe_msg.signal,
        &s_inv.signal,
        &consts.n,
        "u1_mod_n",
    );
    let u2 = mod_mul_u256(
        &mut lowered,
        aux,
        &safe_r.signal,
        &s_inv.signal,
        &consts.n,
        "u2_mod_n",
    );

    let generator = point_from_xy(
        alias_expr_to_u256(
            &mut lowered,
            aux,
            Expr::Signal(consts.gx.clone()),
            "generator_x",
        ),
        alias_expr_to_u256(
            &mut lowered,
            aux,
            Expr::Signal(consts.gy.clone()),
            "generator_y",
        ),
        alias_bool_expr(
            &mut lowered,
            aux,
            Expr::Const(FieldElement::from_i64(0)),
            "generator_is_identity",
        ),
    );

    let u1g = scalar_mul(
        &mut lowered,
        aux,
        &curve,
        &consts,
        &u1.signal,
        &generator,
        "u1_generator_mul",
    );
    let u2pk = scalar_mul(
        &mut lowered,
        aux,
        &curve,
        &consts,
        &u2.signal,
        &safe_pk,
        "u2_pk_mul",
    );
    let r_point = point_add(
        &mut lowered,
        aux,
        &curve,
        &consts,
        &u1g,
        &u2pk,
        "ecdsa_r_point",
    );

    let rx_mod_n = mod_reduce_u256(&mut lowered, aux, &r_point.x.signal, &consts.n, "rx_mod_n");
    let rx_matches = eq_signal_expr(
        &mut lowered,
        aux,
        Expr::Signal(rx_mod_n.signal.clone()),
        Expr::Signal(safe_r.signal.clone()),
        "rx_matches_r",
    );
    let r_not_identity = not_bit(&mut lowered, aux, &r_point.is_identity, "r_not_identity");

    let verify_ok_0 = and_bit(&mut lowered, aux, &sig_ok, &pk_ok, "verify_ok_inputs");
    let verify_ok_1 = and_bit(&mut lowered, aux, &verify_ok_0, &msg_lt_n, "verify_ok_msg");
    let verify_ok_2 = and_bit(
        &mut lowered,
        aux,
        &verify_ok_1,
        &r_not_identity,
        "verify_ok_point",
    );
    let verify_ok = and_bit(
        &mut lowered,
        aux,
        &verify_ok_2,
        &rx_matches,
        "verify_ok_final",
    );

    lowered.add_equal(
        Expr::Signal(outputs[0].clone()),
        Expr::Signal(verify_ok),
        format!("{}_result_equals_verify_ok", curve.name),
    );

    Ok(lowered)
}

#[cfg(feature = "native-blackbox-solvers")]
#[allow(clippy::too_many_arguments)]
pub fn compute_ecdsa_witness(
    curve: SupportedCriticalEcdsaCurve,
    input_values: &[BigInt],
    _output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    field: FieldId,
    label: &Option<String>,
    index: usize,
    witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    if field != FieldId::Bn254 {
        return Err(ZkfError::Backend(
            "ecdsa auxiliary witness generation only supports BN254".to_string(),
        ));
    }
    if input_values.len() != 160 {
        return Err(ZkfError::Backend(format!(
            "ecdsa auxiliary witness generation expects 160 input bytes, found {}",
            input_values.len()
        )));
    }

    let curve = curve_config(curve);
    let prefix = format!(
        "ecdsa_{}_{}",
        curve.name,
        constraint_instance_suffix(label, index)
    );
    let mut aux = AuxCounter::new(prefix);

    let input_bytes = input_values
        .iter()
        .map(bigint_to_u8)
        .collect::<ZkfResult<Vec<_>>>()?;

    for (index, byte) in input_bytes.iter().enumerate() {
        insert_byte_bits(
            witness_values,
            &mut aux,
            *byte,
            &format!("{}_byte_{index}", curve.name),
            field,
        );
    }

    let pkx_bytes = slice_to_array_32(&input_bytes[0..32]);
    let pky_bytes = slice_to_array_32(&input_bytes[32..64]);
    let r_bytes = slice_to_array_32(&input_bytes[64..96]);
    let s_bytes = slice_to_array_32(&input_bytes[96..128]);
    let msg_bytes = slice_to_array_32(&input_bytes[128..160]);

    let pkx_value = bytes_to_bigint_be(&pkx_bytes);
    let pky_value = bytes_to_bigint_be(&pky_bytes);
    let r_value = bytes_to_bigint_be(&r_bytes);
    let s_value = bytes_to_bigint_be(&s_bytes);
    let msg_value = bytes_to_bigint_be(&msg_bytes);

    let pkx = insert_u256_value(
        witness_values,
        &mut aux,
        &pkx_value,
        &format!("{}_pkx", curve.name),
        field,
    );
    let pky = insert_u256_value(
        witness_values,
        &mut aux,
        &pky_value,
        &format!("{}_pky", curve.name),
        field,
    );
    let sig_r = insert_u256_value(
        witness_values,
        &mut aux,
        &r_value,
        &format!("{}_sig_r", curve.name),
        field,
    );
    let sig_s = insert_u256_value(
        witness_values,
        &mut aux,
        &s_value,
        &format!("{}_sig_s", curve.name),
        field,
    );
    let msg = insert_u256_value(
        witness_values,
        &mut aux,
        &msg_value,
        &format!("{}_msg", curve.name),
        field,
    );

    let r_nonzero = witness_bytes_any_nonzero(
        witness_values,
        &mut aux,
        &input_bytes[64..96],
        &format!("{}_r_nonzero", curve.name),
        field,
    );
    let s_nonzero = witness_bytes_any_nonzero(
        witness_values,
        &mut aux,
        &input_bytes[96..128],
        &format!("{}_s_nonzero", curve.name),
        field,
    );
    let pk_nonzero = witness_bytes_any_nonzero(
        witness_values,
        &mut aux,
        &input_bytes[0..64],
        &format!("{}_pk_nonzero", curve.name),
        field,
    );

    let p_bytes = bigint_to_be_bytes32(&curve.p);
    let n_bytes = bigint_to_be_bytes32(&curve.n);
    let half_n_bytes = bigint_to_be_bytes32(&curve.half_n);

    let pkx_lt_p = witness_bytes_lt_const(
        witness_values,
        &mut aux,
        &input_bytes[0..32],
        &p_bytes,
        &format!("{}_pkx_lt_p", curve.name),
        field,
    );
    let pky_lt_p = witness_bytes_lt_const(
        witness_values,
        &mut aux,
        &input_bytes[32..64],
        &p_bytes,
        &format!("{}_pky_lt_p", curve.name),
        field,
    );
    let r_lt_n = witness_bytes_lt_const(
        witness_values,
        &mut aux,
        &input_bytes[64..96],
        &n_bytes,
        &format!("{}_r_lt_n", curve.name),
        field,
    );
    let s_lt_n = witness_bytes_lt_const(
        witness_values,
        &mut aux,
        &input_bytes[96..128],
        &n_bytes,
        &format!("{}_s_lt_n", curve.name),
        field,
    );
    let low_s = witness_bytes_lte_const(
        witness_values,
        &mut aux,
        &input_bytes[96..128],
        &half_n_bytes,
        &format!("{}_low_s", curve.name),
        field,
    );
    let msg_lt_n = witness_bytes_lt_const(
        witness_values,
        &mut aux,
        &input_bytes[128..160],
        &n_bytes,
        &format!("{}_msg_lt_n", curve.name),
        field,
    );

    let on_curve = witness_curve_on_curve_bit(
        witness_values,
        &mut aux,
        &curve,
        &pkx_value,
        &pky_value,
        &format!("{}_pk_on_curve", curve.name),
        field,
    );

    let sig_ok_0 = insert_bool_and(
        witness_values,
        &mut aux,
        r_nonzero,
        r_lt_n,
        "sig_ok_r",
        field,
    );
    let sig_ok_1 = insert_bool_and(
        witness_values,
        &mut aux,
        s_nonzero,
        s_lt_n,
        "sig_ok_s",
        field,
    );
    let sig_ok_2 = insert_bool_and(
        witness_values,
        &mut aux,
        sig_ok_0,
        sig_ok_1,
        "sig_ok_pair",
        field,
    );
    let sig_ok = insert_bool_and(witness_values, &mut aux, sig_ok_2, low_s, "sig_ok", field);

    let pk_ok_0 = insert_bool_and(
        witness_values,
        &mut aux,
        pkx_lt_p,
        pky_lt_p,
        "pk_ok_lt",
        field,
    );
    let pk_ok_1 = insert_bool_and(
        witness_values,
        &mut aux,
        pk_nonzero,
        on_curve,
        "pk_ok_curve",
        field,
    );
    let pk_ok = insert_bool_and(witness_values, &mut aux, pk_ok_0, pk_ok_1, "pk_ok", field);

    let safe_r_value = if sig_ok {
        r_value.clone()
    } else {
        BigInt::one()
    };
    let safe_s_value = if sig_ok {
        s_value.clone()
    } else {
        BigInt::one()
    };
    let safe_msg_value = if msg_lt_n {
        msg_value.clone()
    } else {
        BigInt::zero()
    };
    let safe_pkx_value = if pk_ok {
        pkx_value.clone()
    } else {
        curve.gx.clone()
    };
    let safe_pky_value = if pk_ok {
        pky_value.clone()
    } else {
        curve.gy.clone()
    };

    let safe_r = insert_select_u256_value(
        witness_values,
        &mut aux,
        sig_ok,
        &safe_r_value,
        "safe_r",
        field,
    );
    let safe_s = insert_select_u256_value(
        witness_values,
        &mut aux,
        sig_ok,
        &safe_s_value,
        "safe_s",
        field,
    );
    let safe_msg = insert_select_u256_value(
        witness_values,
        &mut aux,
        msg_lt_n,
        &safe_msg_value,
        "safe_msg",
        field,
    );
    let _safe_pkx = insert_select_u256_value(
        witness_values,
        &mut aux,
        pk_ok,
        &safe_pkx_value,
        "safe_pkx",
        field,
    );
    let _safe_pky = insert_select_u256_value(
        witness_values,
        &mut aux,
        pk_ok,
        &safe_pky_value,
        "safe_pky",
        field,
    );
    let _safe_pk_is_identity = insert_select_bool_value(
        witness_values,
        &mut aux,
        pk_ok,
        false,
        false,
        "safe_pk_is_identity",
        field,
    );
    let safe_pk = RuntimePoint {
        x: safe_pkx_value,
        y: safe_pky_value,
        is_identity: false,
    };

    let s_inv_value =
        mod_inverse_bigint(safe_s_value.clone(), &curve.n).unwrap_or_else(BigInt::zero);
    let s_inv = insert_mod_inv_u256_value(
        witness_values,
        &mut aux,
        &safe_s_value,
        &curve.n,
        &s_inv_value,
        "s_inv_mod_n",
        field,
    );
    let u1_value = normalize_mod(safe_msg_value.clone() * s_inv_value.clone(), &curve.n);
    let u1 = insert_mod_mul_u256_value(
        witness_values,
        &mut aux,
        &safe_msg_value,
        &s_inv_value,
        &curve.n,
        &u1_value,
        "u1_mod_n",
        field,
    );
    let u2_value = normalize_mod(safe_r_value.clone() * s_inv_value.clone(), &curve.n);
    let u2 = insert_mod_mul_u256_value(
        witness_values,
        &mut aux,
        &safe_r_value,
        &s_inv_value,
        &curve.n,
        &u2_value,
        "u2_mod_n",
        field,
    );

    let generator = RuntimePoint {
        x: curve.gx.clone(),
        y: curve.gy.clone(),
        is_identity: false,
    };
    insert_u256_value(witness_values, &mut aux, &curve.gx, "generator_x", field);
    insert_u256_value(witness_values, &mut aux, &curve.gy, "generator_y", field);
    insert_bool_value(
        witness_values,
        &mut aux,
        "generator_is_identity",
        false,
        field,
    );

    let u1g = witness_scalar_mul(
        witness_values,
        &mut aux,
        &curve,
        &u1_value,
        &generator,
        "u1_generator_mul",
        field,
    )?;
    let u2pk = witness_scalar_mul(
        witness_values,
        &mut aux,
        &curve,
        &u2_value,
        &safe_pk,
        "u2_pk_mul",
        field,
    )?;
    let r_point = witness_point_add(
        witness_values,
        &mut aux,
        &curve,
        &u1g,
        &u2pk,
        "ecdsa_r_point",
        field,
    )?;

    let rx_mod_n_value = normalize_mod(r_point.x.clone(), &curve.n);
    let rx_mod_n = insert_mod_reduce_u256_value(
        witness_values,
        &mut aux,
        &r_point.x,
        &curve.n,
        &rx_mod_n_value,
        "rx_mod_n",
        field,
    );
    let rx_matches = witness_eq_signal_expr(
        witness_values,
        &mut aux,
        &rx_mod_n_value,
        &safe_r_value,
        "rx_matches_r",
        field,
    );
    let r_not_identity = insert_bool_not(
        witness_values,
        &mut aux,
        r_point.is_identity,
        "r_not_identity",
        field,
    );

    let verify_ok_0 = insert_bool_and(
        witness_values,
        &mut aux,
        sig_ok,
        pk_ok,
        "verify_ok_inputs",
        field,
    );
    let verify_ok_1 = insert_bool_and(
        witness_values,
        &mut aux,
        verify_ok_0,
        msg_lt_n,
        "verify_ok_msg",
        field,
    );
    let verify_ok_2 = insert_bool_and(
        witness_values,
        &mut aux,
        verify_ok_1,
        r_not_identity,
        "verify_ok_point",
        field,
    );
    let verify_ok = insert_bool_and(
        witness_values,
        &mut aux,
        verify_ok_2,
        rx_matches,
        "verify_ok_final",
        field,
    );

    let native_verified = native_verify_signature(
        curve.name, &pkx_bytes, &pky_bytes, &r_bytes, &s_bytes, &msg_bytes,
    );
    if native_verified != verify_ok {
        return Err(ZkfError::Backend(format!(
            "ecdsa {} witness generation disagrees with native curve verification: runtime={} native={}",
            curve.name, verify_ok, native_verified
        )));
    }

    let _ = (
        pkx, pky, sig_r, sig_s, msg, safe_r, safe_s, safe_msg, s_inv, u1, u2, rx_mod_n,
    );
    Ok(())
}

#[cfg(not(feature = "native-blackbox-solvers"))]
pub fn compute_ecdsa_witness(
    _curve: SupportedCriticalEcdsaCurve,
    _input_values: &[BigInt],
    _output_values: &[BigInt],
    _params: &BTreeMap<String, String>,
    _field: FieldId,
    _label: &Option<String>,
    _index: usize,
    _witness_values: &mut BTreeMap<String, FieldElement>,
) -> ZkfResult<()> {
    Err(ZkfError::Backend(
        "ecdsa auxiliary witness generation requires native-blackbox-solvers".to_string(),
    ))
}

fn curve_config(curve: SupportedCriticalEcdsaCurve) -> CurveConfig {
    match curve {
        SupportedCriticalEcdsaCurve::Secp256k1 => CurveConfig {
            name: "secp256k1",
            p: parse_hex_bigint("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
            n: parse_hex_bigint("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
            half_n: parse_hex_bigint(
                "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
            ),
            a: BigInt::zero(),
            b: BigInt::from(7u8),
            gx: parse_hex_bigint(
                "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
            ),
            gy: parse_hex_bigint(
                "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",
            ),
        },
        SupportedCriticalEcdsaCurve::Secp256r1 => {
            let p = parse_hex_bigint(
                "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
            );
            CurveConfig {
                name: "secp256r1",
                p: p.clone(),
                n: parse_hex_bigint(
                    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
                ),
                half_n: parse_hex_bigint(
                    "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8",
                ),
                a: p - BigInt::from(3u8),
                b: parse_hex_bigint(
                    "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                ),
                gx: parse_hex_bigint(
                    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                ),
                gy: parse_hex_bigint(
                    "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                ),
            }
        }
    }
}

fn curve_config_by_name(curve: &str) -> Result<CurveConfig, String> {
    match curve {
        "secp256k1" => Ok(curve_config(SupportedCriticalEcdsaCurve::Secp256k1)),
        "secp256r1" => Ok(curve_config(SupportedCriticalEcdsaCurve::Secp256r1)),
        other => Err(format!("unsupported ecdsa curve '{other}'")),
    }
}

fn parse_hex_bigint(value: &str) -> BigInt {
    BigInt::parse_bytes(value.as_bytes(), 16).expect("valid curve constant")
}

fn bigint_to_be_bytes32(value: &BigInt) -> [u8; 32] {
    let (_, bytes) = value.to_bytes_be();
    let mut out = [0u8; 32];
    let start = 32usize.saturating_sub(bytes.len());
    out[start..start + bytes.len()].copy_from_slice(&bytes);
    out
}

fn bytes_to_bigint_be(bytes: &[u8; 32]) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, bytes)
}

fn slice_to_array_32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    out
}

fn bigint_to_u64_limbs(value: &BigInt) -> [BigInt; 4] {
    let mut bytes = [0u8; 32];
    let (_, src) = value.to_bytes_le();
    let len = src.len().min(32);
    bytes[..len].copy_from_slice(&src[..len]);
    array::from_fn(|index| {
        let start = index * 8;
        BigInt::from(u64::from_le_bytes(
            bytes[start..start + 8].try_into().unwrap(),
        ))
    })
}

fn reconstruct_256bit_expr(bytes: &[Expr]) -> Expr {
    let mut terms = Vec::with_capacity(bytes.len());
    for (index, byte) in bytes.iter().enumerate() {
        let shift = (bytes.len() - 1 - index) * 8;
        let coeff = BigInt::one() << shift;
        terms.push(Expr::Mul(
            Box::new(Expr::Const(FieldElement::from_bigint(coeff))),
            Box::new(byte.clone()),
        ));
    }
    Expr::Add(terms)
}

fn recombine_u64_limbs_expr(limbs: &[String; 4]) -> Expr {
    Expr::Add(
        limbs
            .iter()
            .enumerate()
            .map(|(index, limb)| {
                if index == 0 {
                    Expr::Signal(limb.clone())
                } else {
                    Expr::Mul(
                        Box::new(Expr::Const(FieldElement::from_bigint(
                            BigInt::one() << (64 * index),
                        ))),
                        Box::new(Expr::Signal(limb.clone())),
                    )
                }
            })
            .collect(),
    )
}

fn add_constant_signal(
    lowered: &mut LoweredBlackBox,
    name: impl Into<String>,
    value: BigInt,
) -> String {
    let name = name.into();
    lowered.signals.push(Signal {
        name: name.clone(),
        visibility: Visibility::Private,
        constant: Some(FieldElement::from_bigint(value)),
        ty: None,
    });
    name
}

fn add_curve_constants(lowered: &mut LoweredBlackBox, curve: &CurveConfig) -> CurveConstSignals {
    CurveConstSignals {
        p: add_constant_signal(lowered, format!("{}_const_p", curve.name), curve.p.clone()),
        n: add_constant_signal(lowered, format!("{}_const_n", curve.name), curve.n.clone()),
        _half_n: add_constant_signal(
            lowered,
            format!("{}_const_half_n", curve.name),
            curve.half_n.clone(),
        ),
        a: add_constant_signal(lowered, format!("{}_const_a", curve.name), curve.a.clone()),
        b: add_constant_signal(lowered, format!("{}_const_b", curve.name), curve.b.clone()),
        gx: add_constant_signal(
            lowered,
            format!("{}_const_gx", curve.name),
            curve.gx.clone(),
        ),
        gy: add_constant_signal(
            lowered,
            format!("{}_const_gy", curve.name),
            curve.gy.clone(),
        ),
        zero: add_constant_signal(
            lowered,
            format!("{}_const_zero", curve.name),
            BigInt::zero(),
        ),
        one: add_constant_signal(lowered, format!("{}_const_one", curve.name), BigInt::one()),
        two: add_constant_signal(
            lowered,
            format!("{}_const_two", curve.name),
            BigInt::from(2u8),
        ),
        three: add_constant_signal(
            lowered,
            format!("{}_const_three", curve.name),
            BigInt::from(3u8),
        ),
    }
}

fn add_bool_signal(lowered: &mut LoweredBlackBox, aux: &mut AuxCounter, label: &str) -> String {
    let signal = lowered.add_private_signal(aux.next(label));
    lowered.add_boolean(signal.clone(), format!("{label}_bool"));
    signal
}

fn add_u256_signal(lowered: &mut LoweredBlackBox, aux: &mut AuxCounter, label: &str) -> U256Var {
    let signal = lowered.add_private_signal(aux.next(label));
    let limbs = array::from_fn(|index| {
        let limb = lowered.add_private_signal(aux.next(&format!("{label}_limb_{index}")));
        lowered.add_range(limb.clone(), 64, format!("{label}_limb_{index}_range64"));
        limb
    });
    lowered.add_equal(
        Expr::Signal(signal.clone()),
        recombine_u64_limbs_expr(&limbs),
        format!("{label}_recombine"),
    );
    U256Var {
        signal,
        _limbs: limbs,
    }
}

fn alias_expr_to_u256(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    expr: Expr,
    label: &str,
) -> U256Var {
    let value = add_u256_signal(lowered, aux, label);
    lowered.add_equal(
        Expr::Signal(value.signal.clone()),
        expr,
        format!("{label}_alias"),
    );
    value
}

fn alias_bool_expr(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    expr: Expr,
    label: &str,
) -> String {
    let signal = add_bool_signal(lowered, aux, label);
    lowered.add_equal(Expr::Signal(signal.clone()), expr, format!("{label}_alias"));
    signal
}

fn and_bit(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a: &str,
    b: &str,
    label: &str,
) -> String {
    bits::and_bits(lowered, aux, a, b, label)
}

fn not_bit(lowered: &mut LoweredBlackBox, aux: &mut AuxCounter, a: &str, label: &str) -> String {
    bits::not_bit(lowered, aux, a, label)
}

fn or_bit(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    a: &str,
    b: &str,
    label: &str,
) -> String {
    let result = add_bool_signal(lowered, aux, &format!("{label}_or"));
    lowered.add_equal(
        Expr::Signal(result.clone()),
        Expr::Sub(
            Box::new(Expr::Add(vec![
                Expr::Signal(a.to_string()),
                Expr::Signal(b.to_string()),
            ])),
            Box::new(Expr::Mul(
                Box::new(Expr::Signal(a.to_string())),
                Box::new(Expr::Signal(b.to_string())),
            )),
        ),
        format!("{label}_or_expr"),
    );
    result
}

fn zero_test_expr(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    expr: Expr,
    label: &str,
) -> String {
    let inv = lowered.add_private_signal(aux.next(&format!("{label}_inv")));
    let is_zero = add_bool_signal(lowered, aux, &format!("{label}_is_zero"));
    lowered.add_equal(
        Expr::Mul(Box::new(expr.clone()), Box::new(Expr::Signal(inv.clone()))),
        Expr::Sub(
            Box::new(Expr::Const(FieldElement::from_i64(1))),
            Box::new(Expr::Signal(is_zero.clone())),
        ),
        format!("{label}_zero_test_inv"),
    );
    lowered.add_equal(
        Expr::Mul(Box::new(expr), Box::new(Expr::Signal(is_zero.clone()))),
        Expr::Const(FieldElement::from_i64(0)),
        format!("{label}_zero_test_zero"),
    );
    is_zero
}

fn eq_signal_expr(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    lhs: Expr,
    rhs: Expr,
    label: &str,
) -> String {
    zero_test_expr(lowered, aux, Expr::Sub(Box::new(lhs), Box::new(rhs)), label)
}

fn compare_byte_to_const(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    byte: Expr,
    constant: u8,
    label: &str,
) -> ByteCmpSignals {
    let lt = add_bool_signal(lowered, aux, &format!("{label}_lt"));
    let diff = lowered.add_private_signal(aux.next(&format!("{label}_diff")));
    lowered.add_range(diff.clone(), 8, format!("{label}_diff_range"));
    lowered.add_equal(
        Expr::Add(vec![
            byte,
            Expr::Mul(
                Box::new(Expr::Const(FieldElement::from_i64(256))),
                Box::new(Expr::Signal(lt.clone())),
            ),
        ]),
        Expr::Add(vec![
            Expr::Const(FieldElement::from_i64(i64::from(constant))),
            Expr::Signal(diff.clone()),
        ]),
        format!("{label}_cmp"),
    );
    let eq = zero_test_expr(lowered, aux, Expr::Signal(diff), &format!("{label}_eq"));
    ByteCmpSignals { lt, eq }
}

fn bytes_lt_const(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    inputs: &[Expr],
    constant: &[u8; 32],
    label: &str,
    consts: &CurveConstSignals,
) -> String {
    let mut prefix_eq = consts.one.clone();
    let mut lt_acc = consts.zero.clone();
    for (index, byte) in inputs.iter().enumerate() {
        let cmp = compare_byte_to_const(
            lowered,
            aux,
            byte.clone(),
            constant[index],
            &format!("{label}_byte_{index}"),
        );
        let lt_here = and_bit(
            lowered,
            aux,
            &prefix_eq,
            &cmp.lt,
            &format!("{label}_lt_{index}"),
        );
        lt_acc = or_bit(
            lowered,
            aux,
            &lt_acc,
            &lt_here,
            &format!("{label}_or_{index}"),
        );
        prefix_eq = and_bit(
            lowered,
            aux,
            &prefix_eq,
            &cmp.eq,
            &format!("{label}_eq_{index}"),
        );
    }
    lt_acc
}

fn bytes_lte_const(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    inputs: &[Expr],
    constant: &[u8; 32],
    label: &str,
    consts: &CurveConstSignals,
) -> String {
    let lt = bytes_lt_const(lowered, aux, inputs, constant, label, consts);
    let mut prefix_eq = consts.one.clone();
    for (index, byte) in inputs.iter().enumerate() {
        let cmp = compare_byte_to_const(
            lowered,
            aux,
            byte.clone(),
            constant[index],
            &format!("{label}_lte_byte_{index}"),
        );
        prefix_eq = and_bit(
            lowered,
            aux,
            &prefix_eq,
            &cmp.eq,
            &format!("{label}_lte_eq_{index}"),
        );
    }
    or_bit(lowered, aux, &lt, &prefix_eq, &format!("{label}_lte"))
}

fn bytes_any_nonzero(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    inputs: &[Expr],
    label: &str,
    consts: &CurveConstSignals,
) -> String {
    let mut any = consts.zero.clone();
    for (index, byte) in inputs.iter().enumerate() {
        let is_zero = zero_test_expr(
            lowered,
            aux,
            byte.clone(),
            &format!("{label}_byte_zero_{index}"),
        );
        let nonzero = not_bit(
            lowered,
            aux,
            &is_zero,
            &format!("{label}_byte_nonzero_{index}"),
        );
        any = or_bit(lowered, aux, &any, &nonzero, &format!("{label}_or_{index}"));
    }
    any
}

fn select_bool(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    selector: &str,
    when_true: Expr,
    when_false: Expr,
    label: &str,
) -> String {
    let result = add_bool_signal(lowered, aux, label);
    lowered.add_equal(
        Expr::Signal(result.clone()),
        Expr::Add(vec![
            when_false.clone(),
            Expr::Mul(
                Box::new(Expr::Signal(selector.to_string())),
                Box::new(Expr::Sub(Box::new(when_true), Box::new(when_false))),
            ),
        ]),
        format!("{label}_select"),
    );
    result
}

fn select_u256_expr(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    selector: &str,
    when_true: Expr,
    when_false: Expr,
    label: &str,
) -> U256Var {
    let value = add_u256_signal(lowered, aux, label);
    lowered.add_equal(
        Expr::Signal(value.signal.clone()),
        Expr::Add(vec![
            when_false.clone(),
            Expr::Mul(
                Box::new(Expr::Signal(selector.to_string())),
                Box::new(Expr::Sub(Box::new(when_true), Box::new(when_false))),
            ),
        ]),
        format!("{label}_select"),
    );
    value
}

fn mod_add_u256(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    lhs: &str,
    rhs: &str,
    modulus: &str,
    label: &str,
) -> U256Var {
    let result = add_u256_signal(lowered, aux, label);
    let carry = add_bool_signal(lowered, aux, &format!("{label}_carry"));
    lowered.add_equal(
        Expr::Add(vec![
            Expr::Signal(lhs.to_string()),
            Expr::Signal(rhs.to_string()),
        ]),
        Expr::Add(vec![
            Expr::Signal(result.signal.clone()),
            Expr::Mul(
                Box::new(Expr::Signal(carry)),
                Box::new(Expr::Signal(modulus.to_string())),
            ),
        ]),
        format!("{label}_mod_add"),
    );
    result
}

fn mod_sub_u256(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    lhs: &str,
    rhs: &str,
    modulus: &str,
    label: &str,
) -> U256Var {
    let result = add_u256_signal(lowered, aux, label);
    let borrow = add_bool_signal(lowered, aux, &format!("{label}_borrow"));
    lowered.add_equal(
        Expr::Add(vec![
            Expr::Signal(lhs.to_string()),
            Expr::Mul(
                Box::new(Expr::Signal(borrow)),
                Box::new(Expr::Signal(modulus.to_string())),
            ),
        ]),
        Expr::Add(vec![
            Expr::Signal(rhs.to_string()),
            Expr::Signal(result.signal.clone()),
        ]),
        format!("{label}_mod_sub"),
    );
    result
}

fn mod_mul_u256(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    lhs: &str,
    rhs: &str,
    modulus: &str,
    label: &str,
) -> U256Var {
    let result = add_u256_signal(lowered, aux, label);
    let quotient = add_u256_signal(lowered, aux, &format!("{label}_quot"));
    lowered.add_equal(
        Expr::Mul(
            Box::new(Expr::Signal(lhs.to_string())),
            Box::new(Expr::Signal(rhs.to_string())),
        ),
        Expr::Add(vec![
            Expr::Signal(result.signal.clone()),
            Expr::Mul(
                Box::new(Expr::Signal(quotient.signal)),
                Box::new(Expr::Signal(modulus.to_string())),
            ),
        ]),
        format!("{label}_mod_mul"),
    );
    result
}

fn mod_inv_u256(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    value: &str,
    modulus: &str,
    label: &str,
) -> U256Var {
    let inv = add_u256_signal(lowered, aux, label);
    let quotient = add_u256_signal(lowered, aux, &format!("{label}_quot"));
    lowered.add_equal(
        Expr::Mul(
            Box::new(Expr::Signal(value.to_string())),
            Box::new(Expr::Signal(inv.signal.clone())),
        ),
        Expr::Add(vec![
            Expr::Const(FieldElement::from_i64(1)),
            Expr::Mul(
                Box::new(Expr::Signal(quotient.signal)),
                Box::new(Expr::Signal(modulus.to_string())),
            ),
        ]),
        format!("{label}_mod_inv"),
    );
    inv
}

fn mod_reduce_u256(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    value: &str,
    modulus: &str,
    label: &str,
) -> U256Var {
    let reduced = add_u256_signal(lowered, aux, label);
    let quotient = add_u256_signal(lowered, aux, &format!("{label}_quot"));
    lowered.add_equal(
        Expr::Signal(value.to_string()),
        Expr::Add(vec![
            Expr::Signal(reduced.signal.clone()),
            Expr::Mul(
                Box::new(Expr::Signal(quotient.signal)),
                Box::new(Expr::Signal(modulus.to_string())),
            ),
        ]),
        format!("{label}_mod_reduce"),
    );
    reduced
}

fn point_from_xy(x: U256Var, y: U256Var, is_identity: String) -> PointVar {
    PointVar { x, y, is_identity }
}

fn point_select(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    selector: &str,
    when_true: &PointVar,
    when_false: &PointVar,
    label: &str,
) -> PointVar {
    point_from_xy(
        select_u256_expr(
            lowered,
            aux,
            selector,
            Expr::Signal(when_true.x.signal.clone()),
            Expr::Signal(when_false.x.signal.clone()),
            &format!("{label}_x"),
        ),
        select_u256_expr(
            lowered,
            aux,
            selector,
            Expr::Signal(when_true.y.signal.clone()),
            Expr::Signal(when_false.y.signal.clone()),
            &format!("{label}_y"),
        ),
        select_bool(
            lowered,
            aux,
            selector,
            Expr::Signal(when_true.is_identity.clone()),
            Expr::Signal(when_false.is_identity.clone()),
            &format!("{label}_is_identity"),
        ),
    )
}

fn identity_point(lowered: &mut LoweredBlackBox, aux: &mut AuxCounter, label: &str) -> PointVar {
    point_from_xy(
        alias_expr_to_u256(
            lowered,
            aux,
            Expr::Const(FieldElement::from_i64(0)),
            &format!("{label}_x"),
        ),
        alias_expr_to_u256(
            lowered,
            aux,
            Expr::Const(FieldElement::from_i64(0)),
            &format!("{label}_y"),
        ),
        alias_bool_expr(
            lowered,
            aux,
            Expr::Const(FieldElement::from_i64(1)),
            &format!("{label}_is_identity"),
        ),
    )
}

fn curve_on_curve_bit(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    curve: &CurveConfig,
    consts: &CurveConstSignals,
    x: &str,
    y: &str,
    label: &str,
) -> String {
    let y_sq = mod_mul_u256(lowered, aux, y, y, &consts.p, &format!("{label}_y_sq"));
    let x_sq = mod_mul_u256(lowered, aux, x, x, &consts.p, &format!("{label}_x_sq"));
    let x_cu = mod_mul_u256(
        lowered,
        aux,
        &x_sq.signal,
        x,
        &consts.p,
        &format!("{label}_x_cu"),
    );
    let rhs = if curve.a.is_zero() {
        mod_add_u256(
            lowered,
            aux,
            &x_cu.signal,
            &consts.b,
            &consts.p,
            &format!("{label}_rhs"),
        )
    } else {
        let ax = mod_mul_u256(
            lowered,
            aux,
            x,
            &consts.a,
            &consts.p,
            &format!("{label}_ax"),
        );
        let rhs0 = mod_add_u256(
            lowered,
            aux,
            &x_cu.signal,
            &ax.signal,
            &consts.p,
            &format!("{label}_rhs0"),
        );
        mod_add_u256(
            lowered,
            aux,
            &rhs0.signal,
            &consts.b,
            &consts.p,
            &format!("{label}_rhs"),
        )
    };
    let residual = mod_sub_u256(
        lowered,
        aux,
        &y_sq.signal,
        &rhs.signal,
        &consts.p,
        &format!("{label}_residual"),
    );
    eq_signal_expr(
        lowered,
        aux,
        Expr::Signal(residual.signal),
        Expr::Signal(consts.zero.clone()),
        &format!("{label}_eq"),
    )
}

fn point_double(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    _curve: &CurveConfig,
    consts: &CurveConstSignals,
    point: &PointVar,
    label: &str,
) -> PointVar {
    let y_zero = eq_signal_expr(
        lowered,
        aux,
        Expr::Signal(point.y.signal.clone()),
        Expr::Signal(consts.zero.clone()),
        &format!("{label}_y_zero"),
    );
    let not_id = not_bit(lowered, aux, &point.is_identity, &format!("{label}_not_id"));
    let not_y_zero = not_bit(lowered, aux, &y_zero, &format!("{label}_not_y_zero"));
    let use_regular = and_bit(
        lowered,
        aux,
        &not_id,
        &not_y_zero,
        &format!("{label}_use_regular"),
    );

    let eff_x = select_u256_expr(
        lowered,
        aux,
        &use_regular,
        Expr::Signal(point.x.signal.clone()),
        Expr::Signal(consts.zero.clone()),
        &format!("{label}_eff_x"),
    );
    let eff_y = select_u256_expr(
        lowered,
        aux,
        &use_regular,
        Expr::Signal(point.y.signal.clone()),
        Expr::Signal(consts.one.clone()),
        &format!("{label}_eff_y"),
    );

    let x_sq = mod_mul_u256(
        lowered,
        aux,
        &eff_x.signal,
        &eff_x.signal,
        &consts.p,
        &format!("{label}_x_sq"),
    );
    let three_x_sq = mod_mul_u256(
        lowered,
        aux,
        &x_sq.signal,
        &consts.three,
        &consts.p,
        &format!("{label}_three_x_sq"),
    );
    let numerator = mod_add_u256(
        lowered,
        aux,
        &three_x_sq.signal,
        &consts.a,
        &consts.p,
        &format!("{label}_numerator"),
    );
    let two_y = mod_mul_u256(
        lowered,
        aux,
        &eff_y.signal,
        &consts.two,
        &consts.p,
        &format!("{label}_two_y"),
    );
    let two_y_inv = mod_inv_u256(
        lowered,
        aux,
        &two_y.signal,
        &consts.p,
        &format!("{label}_two_y_inv"),
    );
    let lambda = mod_mul_u256(
        lowered,
        aux,
        &numerator.signal,
        &two_y_inv.signal,
        &consts.p,
        &format!("{label}_lambda"),
    );
    let lambda_sq = mod_mul_u256(
        lowered,
        aux,
        &lambda.signal,
        &lambda.signal,
        &consts.p,
        &format!("{label}_lambda_sq"),
    );
    let two_x = mod_mul_u256(
        lowered,
        aux,
        &eff_x.signal,
        &consts.two,
        &consts.p,
        &format!("{label}_two_x"),
    );
    let rx = mod_sub_u256(
        lowered,
        aux,
        &lambda_sq.signal,
        &two_x.signal,
        &consts.p,
        &format!("{label}_rx"),
    );
    let x_minus_rx = mod_sub_u256(
        lowered,
        aux,
        &eff_x.signal,
        &rx.signal,
        &consts.p,
        &format!("{label}_x_minus_rx"),
    );
    let lambda_times = mod_mul_u256(
        lowered,
        aux,
        &lambda.signal,
        &x_minus_rx.signal,
        &consts.p,
        &format!("{label}_lambda_times"),
    );
    let ry = mod_sub_u256(
        lowered,
        aux,
        &lambda_times.signal,
        &eff_y.signal,
        &consts.p,
        &format!("{label}_ry"),
    );

    let out_x = select_u256_expr(
        lowered,
        aux,
        &use_regular,
        Expr::Signal(rx.signal),
        Expr::Signal(consts.zero.clone()),
        &format!("{label}_out_x"),
    );
    let out_y = select_u256_expr(
        lowered,
        aux,
        &use_regular,
        Expr::Signal(ry.signal),
        Expr::Signal(consts.zero.clone()),
        &format!("{label}_out_y"),
    );
    let out_is_identity = or_bit(
        lowered,
        aux,
        &point.is_identity,
        &y_zero,
        &format!("{label}_out_id"),
    );

    point_from_xy(out_x, out_y, out_is_identity)
}

fn point_add(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    curve: &CurveConfig,
    consts: &CurveConstSignals,
    lhs: &PointVar,
    rhs: &PointVar,
    label: &str,
) -> PointVar {
    let not_lhs_id = not_bit(
        lowered,
        aux,
        &lhs.is_identity,
        &format!("{label}_not_lhs_id"),
    );
    let not_rhs_id = not_bit(
        lowered,
        aux,
        &rhs.is_identity,
        &format!("{label}_not_rhs_id"),
    );
    let both_non_id = and_bit(
        lowered,
        aux,
        &not_lhs_id,
        &not_rhs_id,
        &format!("{label}_both_non_id"),
    );
    let same_x = eq_signal_expr(
        lowered,
        aux,
        Expr::Signal(lhs.x.signal.clone()),
        Expr::Signal(rhs.x.signal.clone()),
        &format!("{label}_same_x"),
    );
    let same_y = eq_signal_expr(
        lowered,
        aux,
        Expr::Signal(lhs.y.signal.clone()),
        Expr::Signal(rhs.y.signal.clone()),
        &format!("{label}_same_y"),
    );
    let not_same_x = not_bit(lowered, aux, &same_x, &format!("{label}_not_same_x"));
    let use_regular = and_bit(
        lowered,
        aux,
        &both_non_id,
        &not_same_x,
        &format!("{label}_use_regular"),
    );
    let same_x_and_y = and_bit(lowered, aux, &same_x, &same_y, &format!("{label}_same_xy"));
    let use_double = and_bit(
        lowered,
        aux,
        &both_non_id,
        &same_x_and_y,
        &format!("{label}_use_double"),
    );
    let active_curve = or_bit(
        lowered,
        aux,
        &use_regular,
        &use_double,
        &format!("{label}_active_curve"),
    );

    let eff_x1 = select_u256_expr(
        lowered,
        aux,
        &use_regular,
        Expr::Signal(lhs.x.signal.clone()),
        Expr::Signal(consts.zero.clone()),
        &format!("{label}_eff_x1"),
    );
    let eff_y1 = select_u256_expr(
        lowered,
        aux,
        &use_regular,
        Expr::Signal(lhs.y.signal.clone()),
        Expr::Signal(consts.zero.clone()),
        &format!("{label}_eff_y1"),
    );
    let eff_x2 = select_u256_expr(
        lowered,
        aux,
        &use_regular,
        Expr::Signal(rhs.x.signal.clone()),
        Expr::Signal(consts.one.clone()),
        &format!("{label}_eff_x2"),
    );
    let eff_y2 = select_u256_expr(
        lowered,
        aux,
        &use_regular,
        Expr::Signal(rhs.y.signal.clone()),
        Expr::Signal(consts.zero.clone()),
        &format!("{label}_eff_y2"),
    );
    let dy = mod_sub_u256(
        lowered,
        aux,
        &eff_y2.signal,
        &eff_y1.signal,
        &consts.p,
        &format!("{label}_dy"),
    );
    let dx = mod_sub_u256(
        lowered,
        aux,
        &eff_x2.signal,
        &eff_x1.signal,
        &consts.p,
        &format!("{label}_dx"),
    );
    let dx_inv = mod_inv_u256(
        lowered,
        aux,
        &dx.signal,
        &consts.p,
        &format!("{label}_dx_inv"),
    );
    let lambda = mod_mul_u256(
        lowered,
        aux,
        &dy.signal,
        &dx_inv.signal,
        &consts.p,
        &format!("{label}_lambda"),
    );
    let lambda_sq = mod_mul_u256(
        lowered,
        aux,
        &lambda.signal,
        &lambda.signal,
        &consts.p,
        &format!("{label}_lambda_sq"),
    );
    let tmp = mod_sub_u256(
        lowered,
        aux,
        &lambda_sq.signal,
        &eff_x1.signal,
        &consts.p,
        &format!("{label}_tmp"),
    );
    let regular_x = mod_sub_u256(
        lowered,
        aux,
        &tmp.signal,
        &eff_x2.signal,
        &consts.p,
        &format!("{label}_regular_x"),
    );
    let x1_minus_rx = mod_sub_u256(
        lowered,
        aux,
        &eff_x1.signal,
        &regular_x.signal,
        &consts.p,
        &format!("{label}_x1_minus_rx"),
    );
    let lambda_times = mod_mul_u256(
        lowered,
        aux,
        &lambda.signal,
        &x1_minus_rx.signal,
        &consts.p,
        &format!("{label}_lambda_times"),
    );
    let regular_y = mod_sub_u256(
        lowered,
        aux,
        &lambda_times.signal,
        &eff_y1.signal,
        &consts.p,
        &format!("{label}_regular_y"),
    );
    let regular_point = point_from_xy(
        select_u256_expr(
            lowered,
            aux,
            &use_regular,
            Expr::Signal(regular_x.signal),
            Expr::Signal(consts.zero.clone()),
            &format!("{label}_regular_out_x"),
        ),
        select_u256_expr(
            lowered,
            aux,
            &use_regular,
            Expr::Signal(regular_y.signal),
            Expr::Signal(consts.zero.clone()),
            &format!("{label}_regular_out_y"),
        ),
        select_bool(
            lowered,
            aux,
            &use_regular,
            Expr::Const(FieldElement::from_i64(0)),
            Expr::Const(FieldElement::from_i64(1)),
            &format!("{label}_regular_out_id"),
        ),
    );

    let doubled = point_double(lowered, aux, curve, consts, lhs, &format!("{label}_double"));
    let curve_branch = point_select(
        lowered,
        aux,
        &use_double,
        &doubled,
        &regular_point,
        &format!("{label}_curve_branch"),
    );
    let identity = identity_point(lowered, aux, &format!("{label}_identity"));
    let curve_or_identity = point_select(
        lowered,
        aux,
        &active_curve,
        &curve_branch,
        &identity,
        &format!("{label}_curve_or_identity"),
    );
    let after_rhs = point_select(
        lowered,
        aux,
        &rhs.is_identity,
        lhs,
        &curve_or_identity,
        &format!("{label}_after_rhs"),
    );
    point_select(
        lowered,
        aux,
        &lhs.is_identity,
        rhs,
        &after_rhs,
        &format!("{label}_after_lhs"),
    )
}

fn scalar_mul(
    lowered: &mut LoweredBlackBox,
    aux: &mut AuxCounter,
    curve: &CurveConfig,
    consts: &CurveConstSignals,
    scalar: &str,
    base: &PointVar,
    label: &str,
) -> PointVar {
    let scalar_bits = bits::decompose_to_bits(
        lowered,
        aux,
        Expr::Signal(scalar.to_string()),
        256,
        &format!("{label}_scalar"),
    );
    let mut acc = identity_point(lowered, aux, &format!("{label}_acc_init"));
    for bit_index in (0..256).rev() {
        let doubled = point_double(
            lowered,
            aux,
            curve,
            consts,
            &acc,
            &format!("{label}_dbl_{bit_index}"),
        );
        let added = point_add(
            lowered,
            aux,
            curve,
            consts,
            &doubled,
            base,
            &format!("{label}_add_{bit_index}"),
        );
        acc = point_select(
            lowered,
            aux,
            &scalar_bits[bit_index],
            &added,
            &doubled,
            &format!("{label}_sel_{bit_index}"),
        );
    }
    acc
}

fn insert_raw_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    name: impl Into<String>,
    value: BigInt,
) -> String {
    let name = name.into();
    witness_values.insert(name.clone(), FieldElement::from_bigint(value));
    name
}

fn insert_u256_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    value: &BigInt,
    label: &str,
    _field: FieldId,
) -> U256Var {
    let signal = insert_raw_value(witness_values, aux.next(label), value.clone());
    let limbs = bigint_to_u64_limbs(value);
    let limb_names = array::from_fn(|index| {
        insert_raw_value(
            witness_values,
            aux.next(&format!("{label}_limb_{index}")),
            limbs[index].clone(),
        )
    });
    U256Var {
        signal,
        _limbs: limb_names,
    }
}

fn insert_bool_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    label: &str,
    value: bool,
    _field: FieldId,
) -> String {
    insert_raw_value(
        witness_values,
        aux.next(label),
        if value { BigInt::one() } else { BigInt::zero() },
    )
}

fn insert_byte_bits(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    byte: u8,
    label: &str,
    field: FieldId,
) {
    for bit in 0..8 {
        let name = aux.next(&format!("{label}_bit{bit}"));
        witness_values.insert(
            name,
            FieldElement::from_bigint_with_field(BigInt::from((byte >> bit) & 1), field),
        );
    }
}

fn insert_bool_and(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    a: bool,
    b: bool,
    label: &str,
    field: FieldId,
) -> bool {
    let value = a && b;
    let _ = insert_bool_value(witness_values, aux, &format!("{label}_and"), value, field);
    value
}

fn insert_bool_not(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    a: bool,
    label: &str,
    field: FieldId,
) -> bool {
    let value = !a;
    let _ = insert_bool_value(witness_values, aux, &format!("{label}_not"), value, field);
    value
}

fn insert_bool_or(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    a: bool,
    b: bool,
    label: &str,
    field: FieldId,
) -> bool {
    let value = a || b;
    let _ = insert_bool_value(witness_values, aux, &format!("{label}_or"), value, field);
    value
}

fn insert_zero_test(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    value: &BigInt,
    label: &str,
    field: FieldId,
) -> bool {
    let normalized = normalize_mod(value.clone(), field.modulus());
    let is_zero = normalized.is_zero();
    let inv = if is_zero {
        BigInt::zero()
    } else {
        mod_inverse_bigint(normalized, field.modulus()).unwrap_or_else(BigInt::zero)
    };
    let _ = insert_raw_value(witness_values, aux.next(&format!("{label}_inv")), inv);
    let _ = insert_bool_value(
        witness_values,
        aux,
        &format!("{label}_is_zero"),
        is_zero,
        field,
    );
    is_zero
}

fn insert_select_bool_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    selector: bool,
    when_true: bool,
    when_false: bool,
    label: &str,
    field: FieldId,
) -> bool {
    let value = if selector { when_true } else { when_false };
    let _ = insert_bool_value(witness_values, aux, label, value, field);
    value
}

fn insert_select_u256_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    _selector: bool,
    value: &BigInt,
    label: &str,
    field: FieldId,
) -> U256Var {
    insert_u256_value(witness_values, aux, value, label, field)
}

#[allow(clippy::too_many_arguments)]
fn insert_mod_mul_u256_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    lhs: &BigInt,
    rhs: &BigInt,
    modulus: &BigInt,
    result: &BigInt,
    label: &str,
    field: FieldId,
) -> U256Var {
    let out = insert_u256_value(witness_values, aux, result, label, field);
    let quotient = normalize_nonnegative((lhs * rhs - result) / modulus);
    let _ = insert_u256_value(
        witness_values,
        aux,
        &quotient,
        &format!("{label}_quot"),
        field,
    );
    out
}

#[allow(clippy::too_many_arguments)]
fn insert_mod_add_u256_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    lhs: &BigInt,
    rhs: &BigInt,
    modulus: &BigInt,
    result: &BigInt,
    label: &str,
    field: FieldId,
) -> U256Var {
    let out = insert_u256_value(witness_values, aux, result, label, field);
    let carry = lhs + rhs >= *modulus;
    let _ = insert_bool_value(witness_values, aux, &format!("{label}_carry"), carry, field);
    out
}

#[allow(clippy::too_many_arguments)]
fn insert_mod_sub_u256_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    lhs: &BigInt,
    rhs: &BigInt,
    modulus: &BigInt,
    result: &BigInt,
    label: &str,
    field: FieldId,
) -> U256Var {
    let out = insert_u256_value(witness_values, aux, result, label, field);
    let borrow = lhs < rhs;
    let _ = insert_bool_value(
        witness_values,
        aux,
        &format!("{label}_borrow"),
        borrow,
        field,
    );
    let _ = modulus;
    out
}

fn insert_mod_inv_u256_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    value: &BigInt,
    modulus: &BigInt,
    inv: &BigInt,
    label: &str,
    field: FieldId,
) -> U256Var {
    let out = insert_u256_value(witness_values, aux, inv, label, field);
    let quotient = normalize_nonnegative((value * inv - BigInt::one()) / modulus);
    let _ = insert_u256_value(
        witness_values,
        aux,
        &quotient,
        &format!("{label}_quot"),
        field,
    );
    out
}

fn insert_mod_reduce_u256_value(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    value: &BigInt,
    modulus: &BigInt,
    reduced: &BigInt,
    label: &str,
    field: FieldId,
) -> U256Var {
    let out = insert_u256_value(witness_values, aux, reduced, label, field);
    let quotient = normalize_nonnegative((value - reduced) / modulus);
    let _ = insert_u256_value(
        witness_values,
        aux,
        &quotient,
        &format!("{label}_quot"),
        field,
    );
    out
}

fn witness_compare_byte_to_const(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    byte: u8,
    constant: u8,
    label: &str,
    field: FieldId,
) -> ByteCmpValues {
    let lt = byte < constant;
    let diff = if lt {
        u16::from(byte) + 256 - u16::from(constant)
    } else {
        u16::from(byte) - u16::from(constant)
    } as u8;
    let _ = insert_bool_value(witness_values, aux, &format!("{label}_lt"), lt, field);
    let _ = insert_raw_value(
        witness_values,
        aux.next(&format!("{label}_diff")),
        BigInt::from(diff),
    );
    let eq = insert_zero_test(
        witness_values,
        aux,
        &BigInt::from(diff),
        &format!("{label}_eq"),
        field,
    );
    ByteCmpValues { lt, eq }
}

fn witness_bytes_lt_const(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    inputs: &[u8],
    constant: &[u8; 32],
    label: &str,
    field: FieldId,
) -> bool {
    let mut prefix_eq = true;
    let mut lt_acc = false;
    for (index, byte) in inputs.iter().enumerate() {
        let cmp = witness_compare_byte_to_const(
            witness_values,
            aux,
            *byte,
            constant[index],
            &format!("{label}_byte_{index}"),
            field,
        );
        let lt_here = insert_bool_and(
            witness_values,
            aux,
            prefix_eq,
            cmp.lt,
            &format!("{label}_lt_{index}"),
            field,
        );
        lt_acc = insert_bool_or(
            witness_values,
            aux,
            lt_acc,
            lt_here,
            &format!("{label}_or_{index}"),
            field,
        );
        prefix_eq = insert_bool_and(
            witness_values,
            aux,
            prefix_eq,
            cmp.eq,
            &format!("{label}_eq_{index}"),
            field,
        );
    }
    lt_acc
}

fn witness_bytes_lte_const(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    inputs: &[u8],
    constant: &[u8; 32],
    label: &str,
    field: FieldId,
) -> bool {
    let lt = witness_bytes_lt_const(witness_values, aux, inputs, constant, label, field);
    let mut prefix_eq = true;
    for (index, byte) in inputs.iter().enumerate() {
        let cmp = witness_compare_byte_to_const(
            witness_values,
            aux,
            *byte,
            constant[index],
            &format!("{label}_lte_byte_{index}"),
            field,
        );
        prefix_eq = insert_bool_and(
            witness_values,
            aux,
            prefix_eq,
            cmp.eq,
            &format!("{label}_lte_eq_{index}"),
            field,
        );
    }
    insert_bool_or(
        witness_values,
        aux,
        lt,
        prefix_eq,
        &format!("{label}_lte"),
        field,
    )
}

fn witness_bytes_any_nonzero(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    inputs: &[u8],
    label: &str,
    field: FieldId,
) -> bool {
    let mut any = false;
    for (index, byte) in inputs.iter().enumerate() {
        let is_zero = insert_zero_test(
            witness_values,
            aux,
            &BigInt::from(*byte),
            &format!("{label}_byte_zero_{index}"),
            field,
        );
        let nonzero = insert_bool_not(
            witness_values,
            aux,
            is_zero,
            &format!("{label}_byte_nonzero_{index}"),
            field,
        );
        any = insert_bool_or(
            witness_values,
            aux,
            any,
            nonzero,
            &format!("{label}_or_{index}"),
            field,
        );
    }
    any
}

fn witness_eq_signal_expr(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    lhs: &BigInt,
    rhs: &BigInt,
    label: &str,
    field: FieldId,
) -> bool {
    insert_zero_test(witness_values, aux, &(lhs - rhs), label, field)
}

fn witness_curve_on_curve_bit(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    curve: &CurveConfig,
    x: &BigInt,
    y: &BigInt,
    label: &str,
    field: FieldId,
) -> bool {
    let y_sq_value = normalize_mod(y * y, &curve.p);
    let _y_sq = insert_mod_mul_u256_value(
        witness_values,
        aux,
        y,
        y,
        &curve.p,
        &y_sq_value,
        &format!("{label}_y_sq"),
        field,
    );
    let x_sq_value = normalize_mod(x * x, &curve.p);
    let _x_sq = insert_mod_mul_u256_value(
        witness_values,
        aux,
        x,
        x,
        &curve.p,
        &x_sq_value,
        &format!("{label}_x_sq"),
        field,
    );
    let x_cu_value = normalize_mod(x_sq_value.clone() * x, &curve.p);
    let _x_cu = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &x_sq_value,
        x,
        &curve.p,
        &x_cu_value,
        &format!("{label}_x_cu"),
        field,
    );
    let rhs_value = if curve.a.is_zero() {
        normalize_mod(x_cu_value.clone() + curve.b.clone(), &curve.p)
    } else {
        normalize_mod(
            x_cu_value.clone() + normalize_mod(curve.a.clone() * x, &curve.p) + curve.b.clone(),
            &curve.p,
        )
    };
    if curve.a.is_zero() {
        let _ = insert_mod_add_u256_value(
            witness_values,
            aux,
            &x_cu_value,
            &curve.b,
            &curve.p,
            &rhs_value,
            &format!("{label}_rhs"),
            field,
        );
    } else {
        let ax_value = normalize_mod(curve.a.clone() * x, &curve.p);
        let _ax = insert_mod_mul_u256_value(
            witness_values,
            aux,
            x,
            &curve.a,
            &curve.p,
            &ax_value,
            &format!("{label}_ax"),
            field,
        );
        let rhs0_value = normalize_mod(x_cu_value.clone() + ax_value.clone(), &curve.p);
        let _rhs0 = insert_mod_add_u256_value(
            witness_values,
            aux,
            &x_cu_value,
            &ax_value,
            &curve.p,
            &rhs0_value,
            &format!("{label}_rhs0"),
            field,
        );
        let _ = insert_mod_add_u256_value(
            witness_values,
            aux,
            &rhs0_value,
            &curve.b,
            &curve.p,
            &rhs_value,
            &format!("{label}_rhs"),
            field,
        );
    }
    let residual_value = normalize_mod(y_sq_value.clone() - rhs_value, &curve.p);
    let _ = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &y_sq_value,
        &normalize_mod(y_sq_value.clone() - residual_value.clone(), &curve.p),
        &curve.p,
        &residual_value,
        &format!("{label}_residual"),
        field,
    );
    witness_eq_signal_expr(
        witness_values,
        aux,
        &residual_value,
        &BigInt::zero(),
        &format!("{label}_eq"),
        field,
    )
}

fn witness_point_add(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    curve: &CurveConfig,
    lhs: &RuntimePoint,
    rhs: &RuntimePoint,
    label: &str,
    field: FieldId,
) -> ZkfResult<RuntimePoint> {
    let not_lhs_id = insert_bool_not(
        witness_values,
        aux,
        lhs.is_identity,
        &format!("{label}_not_lhs_id"),
        field,
    );
    let not_rhs_id = insert_bool_not(
        witness_values,
        aux,
        rhs.is_identity,
        &format!("{label}_not_rhs_id"),
        field,
    );
    let both_non_id = insert_bool_and(
        witness_values,
        aux,
        not_lhs_id,
        not_rhs_id,
        &format!("{label}_both_non_id"),
        field,
    );
    let same_x = witness_eq_signal_expr(
        witness_values,
        aux,
        &lhs.x,
        &rhs.x,
        &format!("{label}_same_x"),
        field,
    );
    let same_y = witness_eq_signal_expr(
        witness_values,
        aux,
        &lhs.y,
        &rhs.y,
        &format!("{label}_same_y"),
        field,
    );
    let not_same_x = insert_bool_not(
        witness_values,
        aux,
        same_x,
        &format!("{label}_not_same_x"),
        field,
    );
    let use_regular = insert_bool_and(
        witness_values,
        aux,
        both_non_id,
        not_same_x,
        &format!("{label}_use_regular"),
        field,
    );
    let same_x_and_y = insert_bool_and(
        witness_values,
        aux,
        same_x,
        same_y,
        &format!("{label}_same_xy"),
        field,
    );
    let use_double = insert_bool_and(
        witness_values,
        aux,
        both_non_id,
        same_x_and_y,
        &format!("{label}_use_double"),
        field,
    );
    let active_curve = insert_bool_or(
        witness_values,
        aux,
        use_regular,
        use_double,
        &format!("{label}_active_curve"),
        field,
    );

    let eff_x1_value = if use_regular {
        lhs.x.clone()
    } else {
        BigInt::zero()
    };
    let eff_y1_value = if use_regular {
        lhs.y.clone()
    } else {
        BigInt::zero()
    };
    let eff_x2_value = if use_regular {
        rhs.x.clone()
    } else {
        BigInt::one()
    };
    let eff_y2_value = if use_regular {
        rhs.y.clone()
    } else {
        BigInt::zero()
    };
    let _eff_x1 = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &eff_x1_value,
        &format!("{label}_eff_x1"),
        field,
    );
    let _eff_y1 = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &eff_y1_value,
        &format!("{label}_eff_y1"),
        field,
    );
    let _eff_x2 = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &eff_x2_value,
        &format!("{label}_eff_x2"),
        field,
    );
    let _eff_y2 = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &eff_y2_value,
        &format!("{label}_eff_y2"),
        field,
    );

    let dy_value = normalize_mod(eff_y2_value.clone() - eff_y1_value.clone(), &curve.p);
    let _dy = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &eff_y2_value,
        &eff_y1_value,
        &curve.p,
        &dy_value,
        &format!("{label}_dy"),
        field,
    );
    let dx_value = normalize_mod(eff_x2_value.clone() - eff_x1_value.clone(), &curve.p);
    let _dx = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &eff_x2_value,
        &eff_x1_value,
        &curve.p,
        &dx_value,
        &format!("{label}_dx"),
        field,
    );
    let dx_inv_value = mod_inverse_bigint(dx_value.clone(), &curve.p).unwrap_or_else(BigInt::zero);
    let _dx_inv = insert_mod_inv_u256_value(
        witness_values,
        aux,
        &dx_value,
        &curve.p,
        &dx_inv_value,
        &format!("{label}_dx_inv"),
        field,
    );
    let lambda_value = normalize_mod(dy_value.clone() * dx_inv_value.clone(), &curve.p);
    let _lambda = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &dy_value,
        &dx_inv_value,
        &curve.p,
        &lambda_value,
        &format!("{label}_lambda"),
        field,
    );
    let lambda_sq_value = normalize_mod(lambda_value.clone() * lambda_value.clone(), &curve.p);
    let _lambda_sq = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &lambda_value,
        &lambda_value,
        &curve.p,
        &lambda_sq_value,
        &format!("{label}_lambda_sq"),
        field,
    );
    let tmp_value = normalize_mod(lambda_sq_value.clone() - eff_x1_value.clone(), &curve.p);
    let _tmp = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &lambda_sq_value,
        &eff_x1_value,
        &curve.p,
        &tmp_value,
        &format!("{label}_tmp"),
        field,
    );
    let regular_x_value = normalize_mod(tmp_value.clone() - eff_x2_value.clone(), &curve.p);
    let _regular_x = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &tmp_value,
        &eff_x2_value,
        &curve.p,
        &regular_x_value,
        &format!("{label}_regular_x"),
        field,
    );
    let x1_minus_rx_value = normalize_mod(eff_x1_value.clone() - regular_x_value.clone(), &curve.p);
    let _x1_minus_rx = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &eff_x1_value,
        &regular_x_value,
        &curve.p,
        &x1_minus_rx_value,
        &format!("{label}_x1_minus_rx"),
        field,
    );
    let lambda_times_value =
        normalize_mod(lambda_value.clone() * x1_minus_rx_value.clone(), &curve.p);
    let _lambda_times = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &lambda_value,
        &x1_minus_rx_value,
        &curve.p,
        &lambda_times_value,
        &format!("{label}_lambda_times"),
        field,
    );
    let regular_y_value =
        normalize_mod(lambda_times_value.clone() - eff_y1_value.clone(), &curve.p);
    let _regular_y = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &lambda_times_value,
        &eff_y1_value,
        &curve.p,
        &regular_y_value,
        &format!("{label}_regular_y"),
        field,
    );
    let regular_point = RuntimePoint {
        x: if use_regular {
            regular_x_value
        } else {
            BigInt::zero()
        },
        y: if use_regular {
            regular_y_value
        } else {
            BigInt::zero()
        },
        is_identity: !use_regular,
    };

    let _regular_out_x = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &regular_point.x,
        &format!("{label}_regular_out_x"),
        field,
    );
    let _regular_out_y = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &regular_point.y,
        &format!("{label}_regular_out_y"),
        field,
    );
    let _regular_out_id = insert_select_bool_value(
        witness_values,
        aux,
        use_regular,
        false,
        true,
        &format!("{label}_regular_out_id"),
        field,
    );

    let doubled = witness_point_double(
        witness_values,
        aux,
        curve,
        lhs,
        &format!("{label}_double"),
        field,
    )?;
    let curve_branch = if use_double {
        doubled.clone()
    } else {
        regular_point.clone()
    };
    let _curve_branch_x = insert_select_u256_value(
        witness_values,
        aux,
        use_double,
        &curve_branch.x,
        &format!("{label}_curve_branch_x"),
        field,
    );
    let _curve_branch_y = insert_select_u256_value(
        witness_values,
        aux,
        use_double,
        &curve_branch.y,
        &format!("{label}_curve_branch_y"),
        field,
    );
    let _curve_branch_id = insert_select_bool_value(
        witness_values,
        aux,
        use_double,
        curve_branch.is_identity,
        regular_point.is_identity,
        &format!("{label}_curve_branch_is_identity"),
        field,
    );
    let identity = RuntimePoint {
        x: BigInt::zero(),
        y: BigInt::zero(),
        is_identity: true,
    };
    let _identity_x = insert_u256_value(
        witness_values,
        aux,
        &identity.x,
        &format!("{label}_identity_x"),
        field,
    );
    let _identity_y = insert_u256_value(
        witness_values,
        aux,
        &identity.y,
        &format!("{label}_identity_y"),
        field,
    );
    let _identity_id = insert_bool_value(
        witness_values,
        aux,
        &format!("{label}_identity_is_identity"),
        true,
        field,
    );

    let curve_or_identity = if active_curve {
        curve_branch.clone()
    } else {
        identity.clone()
    };
    let _curve_or_identity_x = insert_select_u256_value(
        witness_values,
        aux,
        active_curve,
        &curve_or_identity.x,
        &format!("{label}_curve_or_identity_x"),
        field,
    );
    let _curve_or_identity_y = insert_select_u256_value(
        witness_values,
        aux,
        active_curve,
        &curve_or_identity.y,
        &format!("{label}_curve_or_identity_y"),
        field,
    );
    let _curve_or_identity_id = insert_select_bool_value(
        witness_values,
        aux,
        active_curve,
        curve_or_identity.is_identity,
        identity.is_identity,
        &format!("{label}_curve_or_identity_is_identity"),
        field,
    );

    let after_rhs = if rhs.is_identity {
        lhs.clone()
    } else {
        curve_or_identity.clone()
    };
    let _after_rhs_x = insert_select_u256_value(
        witness_values,
        aux,
        rhs.is_identity,
        &after_rhs.x,
        &format!("{label}_after_rhs_x"),
        field,
    );
    let _after_rhs_y = insert_select_u256_value(
        witness_values,
        aux,
        rhs.is_identity,
        &after_rhs.y,
        &format!("{label}_after_rhs_y"),
        field,
    );
    let _after_rhs_id = insert_select_bool_value(
        witness_values,
        aux,
        rhs.is_identity,
        after_rhs.is_identity,
        curve_or_identity.is_identity,
        &format!("{label}_after_rhs_is_identity"),
        field,
    );

    let out = if lhs.is_identity {
        rhs.clone()
    } else {
        after_rhs.clone()
    };
    let _after_lhs_x = insert_select_u256_value(
        witness_values,
        aux,
        lhs.is_identity,
        &out.x,
        &format!("{label}_after_lhs_x"),
        field,
    );
    let _after_lhs_y = insert_select_u256_value(
        witness_values,
        aux,
        lhs.is_identity,
        &out.y,
        &format!("{label}_after_lhs_y"),
        field,
    );
    let _after_lhs_id = insert_select_bool_value(
        witness_values,
        aux,
        lhs.is_identity,
        out.is_identity,
        after_rhs.is_identity,
        &format!("{label}_after_lhs_is_identity"),
        field,
    );

    Ok(out)
}

fn witness_point_double(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    curve: &CurveConfig,
    point: &RuntimePoint,
    label: &str,
    field: FieldId,
) -> ZkfResult<RuntimePoint> {
    let y_zero = witness_eq_signal_expr(
        witness_values,
        aux,
        &point.y,
        &BigInt::zero(),
        &format!("{label}_y_zero"),
        field,
    );
    let not_id = insert_bool_not(
        witness_values,
        aux,
        point.is_identity,
        &format!("{label}_not_id"),
        field,
    );
    let not_y_zero = insert_bool_not(
        witness_values,
        aux,
        y_zero,
        &format!("{label}_not_y_zero"),
        field,
    );
    let use_regular = insert_bool_and(
        witness_values,
        aux,
        not_id,
        not_y_zero,
        &format!("{label}_use_regular"),
        field,
    );

    let eff_x_value = if use_regular {
        point.x.clone()
    } else {
        BigInt::zero()
    };
    let eff_y_value = if use_regular {
        point.y.clone()
    } else {
        BigInt::one()
    };
    let _eff_x = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &eff_x_value,
        &format!("{label}_eff_x"),
        field,
    );
    let _eff_y = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &eff_y_value,
        &format!("{label}_eff_y"),
        field,
    );

    let x_sq_value = normalize_mod(eff_x_value.clone() * eff_x_value.clone(), &curve.p);
    let _x_sq = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &eff_x_value,
        &eff_x_value,
        &curve.p,
        &x_sq_value,
        &format!("{label}_x_sq"),
        field,
    );
    let three_x_sq_value = normalize_mod(x_sq_value.clone() * BigInt::from(3u8), &curve.p);
    let _three_x_sq = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &x_sq_value,
        &BigInt::from(3u8),
        &curve.p,
        &three_x_sq_value,
        &format!("{label}_three_x_sq"),
        field,
    );
    let numerator_value = normalize_mod(three_x_sq_value.clone() + curve.a.clone(), &curve.p);
    let _numerator = insert_mod_add_u256_value(
        witness_values,
        aux,
        &three_x_sq_value,
        &curve.a,
        &curve.p,
        &numerator_value,
        &format!("{label}_numerator"),
        field,
    );
    let two_y_value = normalize_mod(eff_y_value.clone() * BigInt::from(2u8), &curve.p);
    let _two_y = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &eff_y_value,
        &BigInt::from(2u8),
        &curve.p,
        &two_y_value,
        &format!("{label}_two_y"),
        field,
    );
    let two_y_inv_value = mod_inverse_bigint(two_y_value.clone(), &curve.p).ok_or_else(|| {
        ZkfError::Backend("ecdsa point-double denominator not invertible".to_string())
    })?;
    let _two_y_inv = insert_mod_inv_u256_value(
        witness_values,
        aux,
        &two_y_value,
        &curve.p,
        &two_y_inv_value,
        &format!("{label}_two_y_inv"),
        field,
    );
    let lambda_value = normalize_mod(numerator_value.clone() * two_y_inv_value.clone(), &curve.p);
    let _lambda = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &numerator_value,
        &two_y_inv_value,
        &curve.p,
        &lambda_value,
        &format!("{label}_lambda"),
        field,
    );
    let lambda_sq_value = normalize_mod(lambda_value.clone() * lambda_value.clone(), &curve.p);
    let _lambda_sq = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &lambda_value,
        &lambda_value,
        &curve.p,
        &lambda_sq_value,
        &format!("{label}_lambda_sq"),
        field,
    );
    let two_x_value = normalize_mod(eff_x_value.clone() * BigInt::from(2u8), &curve.p);
    let _two_x = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &eff_x_value,
        &BigInt::from(2u8),
        &curve.p,
        &two_x_value,
        &format!("{label}_two_x"),
        field,
    );
    let rx_value = normalize_mod(lambda_sq_value.clone() - two_x_value.clone(), &curve.p);
    let _rx = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &lambda_sq_value,
        &two_x_value,
        &curve.p,
        &rx_value,
        &format!("{label}_rx"),
        field,
    );
    let x_minus_rx_value = normalize_mod(eff_x_value.clone() - rx_value.clone(), &curve.p);
    let _x_minus_rx = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &eff_x_value,
        &rx_value,
        &curve.p,
        &x_minus_rx_value,
        &format!("{label}_x_minus_rx"),
        field,
    );
    let lambda_times_value =
        normalize_mod(lambda_value.clone() * x_minus_rx_value.clone(), &curve.p);
    let _lambda_times = insert_mod_mul_u256_value(
        witness_values,
        aux,
        &lambda_value,
        &x_minus_rx_value,
        &curve.p,
        &lambda_times_value,
        &format!("{label}_lambda_times"),
        field,
    );
    let ry_value = normalize_mod(lambda_times_value.clone() - eff_y_value.clone(), &curve.p);
    let _ry = insert_mod_sub_u256_value(
        witness_values,
        aux,
        &lambda_times_value,
        &eff_y_value,
        &curve.p,
        &ry_value,
        &format!("{label}_ry"),
        field,
    );

    let out = if use_regular {
        RuntimePoint {
            x: rx_value.clone(),
            y: ry_value.clone(),
            is_identity: false,
        }
    } else {
        RuntimePoint {
            x: BigInt::zero(),
            y: BigInt::zero(),
            is_identity: true,
        }
    };
    let _out_x = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &out.x,
        &format!("{label}_out_x"),
        field,
    );
    let _out_y = insert_select_u256_value(
        witness_values,
        aux,
        use_regular,
        &out.y,
        &format!("{label}_out_y"),
        field,
    );
    let _out_id = insert_bool_or(
        witness_values,
        aux,
        point.is_identity,
        y_zero,
        &format!("{label}_out_id"),
        field,
    );
    Ok(out)
}

fn witness_scalar_mul(
    witness_values: &mut BTreeMap<String, FieldElement>,
    aux: &mut AuxCounter,
    curve: &CurveConfig,
    scalar: &BigInt,
    base: &RuntimePoint,
    label: &str,
    field: FieldId,
) -> ZkfResult<RuntimePoint> {
    for bit in 0..256 {
        let name = aux.next(&format!("{label}_scalar_bit{bit}"));
        let bit_value = ((scalar >> bit) & BigInt::one()) == BigInt::one();
        witness_values.insert(
            name,
            FieldElement::from_bigint_with_field(
                if bit_value {
                    BigInt::one()
                } else {
                    BigInt::zero()
                },
                field,
            ),
        );
    }
    let mut acc = RuntimePoint {
        x: BigInt::zero(),
        y: BigInt::zero(),
        is_identity: true,
    };
    let _acc_init_x = insert_u256_value(
        witness_values,
        aux,
        &acc.x,
        &format!("{label}_acc_init_x"),
        field,
    );
    let _acc_init_y = insert_u256_value(
        witness_values,
        aux,
        &acc.y,
        &format!("{label}_acc_init_y"),
        field,
    );
    let _acc_init_id = insert_bool_value(
        witness_values,
        aux,
        &format!("{label}_acc_init_is_identity"),
        true,
        field,
    );

    for bit_index in (0..256).rev() {
        let doubled = witness_point_double(
            witness_values,
            aux,
            curve,
            &acc,
            &format!("{label}_dbl_{bit_index}"),
            field,
        )?;
        let added = witness_point_add(
            witness_values,
            aux,
            curve,
            &doubled,
            base,
            &format!("{label}_add_{bit_index}"),
            field,
        )?;
        let bit_value = ((scalar >> bit_index) & BigInt::one()) == BigInt::one();
        let selected = if bit_value {
            added.clone()
        } else {
            doubled.clone()
        };
        let _sel_x = insert_select_u256_value(
            witness_values,
            aux,
            bit_value,
            &selected.x,
            &format!("{label}_sel_{bit_index}_x"),
            field,
        );
        let _sel_y = insert_select_u256_value(
            witness_values,
            aux,
            bit_value,
            &selected.y,
            &format!("{label}_sel_{bit_index}_y"),
            field,
        );
        let _sel_id = insert_select_bool_value(
            witness_values,
            aux,
            bit_value,
            selected.is_identity,
            doubled.is_identity,
            &format!("{label}_sel_{bit_index}_is_identity"),
            field,
        );
        acc = selected;
    }

    Ok(acc)
}

fn normalize_nonnegative(value: BigInt) -> BigInt {
    if value.sign() == Sign::Minus {
        BigInt::zero()
    } else {
        value
    }
}

fn bigint_to_u8(value: &BigInt) -> ZkfResult<u8> {
    let normalized = normalize_nonnegative(value.clone());
    if normalized > BigInt::from(u8::MAX) {
        return Err(ZkfError::InvalidArtifact(format!(
            "ecdsa byte input {value} exceeds 8 bits"
        )));
    }
    let (_, bytes) = normalized.to_bytes_le();
    Ok(bytes.first().copied().unwrap_or(0))
}

#[cfg(feature = "native-blackbox-solvers")]
fn native_verify_signature(
    curve_name: &str,
    pkx: &[u8; 32],
    pky: &[u8; 32],
    sig_r: &[u8; 32],
    sig_s: &[u8; 32],
    msg: &[u8; 32],
) -> bool {
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(sig_r);
    signature[32..].copy_from_slice(sig_s);
    match curve_name {
        "secp256k1" => ecdsa_secp256k1_verify(msg, pkx, pky, &signature).unwrap_or(false),
        "secp256r1" => ecdsa_secp256r1_verify(msg, pkx, pky, &signature).unwrap_or(false),
        _ => false,
    }
}
