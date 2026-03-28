use std::collections::BTreeMap;
use zkf_core::FieldId;
use zkf_core::zir_v1 as zir;
use zkf_gadgets::GadgetRegistry;

/// Verify all builtin gadgets are registered and emit valid constraints.
#[test]
fn all_builtins_registered() {
    let registry = GadgetRegistry::with_builtins();
    let names = registry.list();

    let expected = [
        "blake3",
        "boolean",
        "comparison",
        "ecdsa",
        "kzg",
        "merkle",
        "plonk_gate",
        "poseidon",
        "range",
        "schnorr",
        "sha256",
    ];
    for name in &expected {
        assert!(
            names.contains(name),
            "missing builtin gadget: {name}, registered: {names:?}"
        );
    }
}

#[test]
fn blake3_gadget_emits_constraints() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("blake3").expect("blake3 must exist");

    // Blake3 requires 16 u32 state words as input
    let inputs: Vec<zir::Expr> = (0..16)
        .map(|i| zir::Expr::Signal(format!("state_{i}")))
        .collect();

    let emission = gadget
        .emit(
            &inputs,
            &["out_0".to_string(), "out_1".to_string()],
            FieldId::Bn254,
            &BTreeMap::new(),
        )
        .expect("blake3 emit should succeed");

    assert!(
        !emission.constraints.is_empty(),
        "blake3 must emit constraints"
    );
    assert!(!emission.signals.is_empty(), "blake3 must emit signals");
}

#[test]
fn blake3_handles_partial_inputs() {
    // Blake3 zero-fills missing state words, so partial inputs are valid.
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("blake3").unwrap();

    let inputs = vec![zir::Expr::Signal("a".into())];
    let result = gadget.emit(&inputs, &["out".into()], FieldId::Bn254, &BTreeMap::new());
    assert!(result.is_ok());
}

#[test]
fn sha256_gadget_emits_full_compression() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("sha256").expect("sha256 must exist");

    // SHA-256 requires 16 u32 message words + 8 H values
    let inputs: Vec<zir::Expr> = (0..24)
        .map(|i| zir::Expr::Signal(format!("in_{i}")))
        .collect();

    let emission = gadget
        .emit(
            &inputs,
            &[
                "h0".into(),
                "h1".into(),
                "h2".into(),
                "h3".into(),
                "h4".into(),
                "h5".into(),
                "h6".into(),
                "h7".into(),
            ],
            FieldId::Bn254,
            &BTreeMap::new(),
        )
        .expect("sha256 emit should succeed");

    // SHA-256 compression has 64 rounds, should produce many constraints
    assert!(
        emission.constraints.len() > 100,
        "sha256 should produce many constraints"
    );
    assert!(!emission.signals.is_empty());
}

#[test]
fn kzg_gadget_emits_pairing_chain() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("kzg").expect("kzg must exist");

    let inputs = vec![
        zir::Expr::Signal("commitment".into()),
        zir::Expr::Signal("evaluation".into()),
        zir::Expr::Signal("point".into()),
        zir::Expr::Signal("proof".into()),
    ];

    let emission = gadget
        .emit(&inputs, &["valid".into()], FieldId::Bn254, &BTreeMap::new())
        .expect("kzg emit should succeed");

    // Should have scalar mul, point sub, srs computation, pairing check, output
    assert!(
        emission.constraints.len() >= 5,
        "kzg must chain multiple operations"
    );
    assert!(!emission.signals.is_empty());
}

#[test]
fn kzg_rejects_insufficient_inputs() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("kzg").unwrap();

    let inputs = vec![zir::Expr::Signal("c".into())];
    let result = gadget.emit(&inputs, &["valid".into()], FieldId::Bn254, &BTreeMap::new());
    assert!(result.is_err());
}

#[test]
fn kzg_supported_fields() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("kzg").unwrap();
    let fields = gadget.supported_fields();
    assert!(fields.contains(&FieldId::Bn254));
    assert!(fields.contains(&FieldId::Bls12_381));
    assert!(!fields.contains(&FieldId::Goldilocks));
}

#[test]
fn plonk_gate_addition() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("plonk_gate").expect("plonk_gate must exist");

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
        .emit(&inputs, &["result".into()], FieldId::Bn254, &params)
        .expect("plonk_gate emit should succeed");

    assert!(
        emission.constraints.len() >= 2,
        "gate constraint + output constraint"
    );
    assert!(!emission.signals.is_empty());
}

#[test]
fn plonk_gate_wide_field_support() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("plonk_gate").unwrap();
    let fields = gadget.supported_fields();
    assert!(fields.contains(&FieldId::Goldilocks));
    assert!(fields.contains(&FieldId::BabyBear));
    assert!(fields.contains(&FieldId::Mersenne31));
    assert!(fields.len() >= 5);
}

#[test]
fn poseidon_gadget_bn254() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("poseidon").unwrap();

    let inputs = vec![zir::Expr::Signal("a".into()), zir::Expr::Signal("b".into())];

    let emission = gadget
        .emit(&inputs, &["hash".into()], FieldId::Bn254, &BTreeMap::new())
        .expect("poseidon emit should succeed");

    assert!(!emission.constraints.is_empty());
    assert!(!emission.signals.is_empty());
}

#[test]
fn merkle_gadget_depth_1() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("merkle").unwrap();

    // Merkle depth=1: leaf + 1 sibling + 1 index = 3 inputs
    let inputs = vec![
        zir::Expr::Signal("leaf".into()),
        zir::Expr::Signal("sibling0".into()),
        zir::Expr::Signal("idx0".into()),
    ];
    let mut params = BTreeMap::new();
    params.insert("depth".to_string(), "1".to_string());

    let emission = gadget
        .emit(&inputs, &["root".into()], FieldId::Bn254, &params)
        .expect("merkle emit should succeed");

    assert!(!emission.constraints.is_empty());
}

#[test]
fn ecdsa_gadget_emits_constraints() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("ecdsa").unwrap();

    let inputs = vec![
        zir::Expr::Signal("msg_hash".into()),
        zir::Expr::Signal("pub_x".into()),
        zir::Expr::Signal("pub_y".into()),
        zir::Expr::Signal("sig_r".into()),
        zir::Expr::Signal("sig_s".into()),
    ];

    let emission = gadget
        .emit(&inputs, &["valid".into()], FieldId::Bn254, &BTreeMap::new())
        .expect("ecdsa emit should succeed");

    assert!(!emission.constraints.is_empty());
}

#[test]
fn schnorr_gadget_emits_constraints() {
    let registry = GadgetRegistry::with_builtins();
    let gadget = registry.get("schnorr").unwrap();

    let inputs = vec![
        zir::Expr::Signal("msg".into()),
        zir::Expr::Signal("pub_x".into()),
        zir::Expr::Signal("pub_y".into()),
        zir::Expr::Signal("sig".into()),
    ];

    let emission = gadget
        .emit(&inputs, &["valid".into()], FieldId::Bn254, &BTreeMap::new())
        .expect("schnorr emit should succeed");

    assert!(!emission.constraints.is_empty());
}
