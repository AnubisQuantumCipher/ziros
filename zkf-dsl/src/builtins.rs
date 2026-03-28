/// Built-in circuit functions recognized by the DSL macro.
///
/// These are lowered to specific ZIR constraints or gadget invocations.
pub fn is_builtin(name: &str) -> bool {
    matches!(
        name,
        // Assertion builtins
        "assert_range"
            | "assert_bool"
            | "assert_eq"
            | "assert_ne"
            | "assert_lt"
            // Hash function builtins
            | "poseidon_hash"
            | "sha256_hash"
            | "keccak256_hash"
            | "blake2s_hash"
            | "blake3_hash"
            | "pedersen_hash"
            // Signature verification builtins
            | "ecdsa_verify"
            | "schnorr_verify"
            // Merkle tree builtins
            | "merkle_verify"
            | "merkle_root"
            // Field arithmetic builtins
            | "field_inverse"
            | "field_sqrt"
            | "field_pow"
            // Non-native arithmetic builtins
            | "nonnative_mul"
            | "nonnative_add"
            // Curve builtins
            | "secp256k1_mul"
            | "kzg_verify"
            // Comparison builtins
            | "comparison_lt"
            | "comparison_gt"
    )
}

/// Returns the ZIR BlackBox operation name for a builtin, if it maps to one.
///
/// Only builtins that currently lower directly to `zir::Constraint::BlackBox`
/// are included here.
pub fn builtin_to_blackbox_op(name: &str) -> Option<&'static str> {
    match name {
        "poseidon_hash" => Some("Poseidon"),
        "sha256_hash" => Some("SHA256"),
        "keccak256_hash" => Some("Keccak256"),
        "blake2s_hash" => Some("Blake2s"),
        "pedersen_hash" => Some("Pedersen"),
        "ecdsa_verify" => Some("EcdsaSecp256k1"),
        "schnorr_verify" => Some("SchnorrVerify"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::builtin_to_blackbox_op;

    #[test]
    fn builtin_blackbox_mapping_matches_supported_lowering() {
        assert_eq!(builtin_to_blackbox_op("poseidon_hash"), Some("Poseidon"));
        assert_eq!(builtin_to_blackbox_op("sha256_hash"), Some("SHA256"));
        assert_eq!(builtin_to_blackbox_op("keccak256_hash"), Some("Keccak256"));
        assert_eq!(builtin_to_blackbox_op("blake2s_hash"), Some("Blake2s"));
        assert_eq!(builtin_to_blackbox_op("pedersen_hash"), Some("Pedersen"));
        assert_eq!(
            builtin_to_blackbox_op("ecdsa_verify"),
            Some("EcdsaSecp256k1")
        );
        assert_eq!(
            builtin_to_blackbox_op("schnorr_verify"),
            Some("SchnorrVerify")
        );

        assert_eq!(builtin_to_blackbox_op("blake3_hash"), None);
        assert_eq!(builtin_to_blackbox_op("merkle_verify"), None);
    }
}
