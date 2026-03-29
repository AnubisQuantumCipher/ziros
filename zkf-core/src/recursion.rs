//! Recursion and proof composition planning.
//!
//! Models same-field and cross-field recursive verification via [`RecursionPlan`],
//! including field adapter selection and known recursion-capable backend pairs.

use crate::artifact::BackendKind;
use crate::field::FieldId;
use serde::{Deserialize, Serialize};

/// How field elements from the inner proof system are represented in the outer system.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldAdapter {
    /// Both systems use the same native field — no adaptation needed.
    NativeCompatible,
    /// Inner field elements are emulated using non-native arithmetic in the outer field.
    NonNativeArithmetic,
}

/// A plan for recursive proof composition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecursionPlan {
    /// The backend that generates the inner proof.
    pub inner_backend: BackendKind,
    /// The backend that verifies the inner proof inside a circuit.
    pub outer_backend: BackendKind,
    /// The field used by the inner proof.
    pub inner_field: FieldId,
    /// The field used by the outer verifier circuit.
    pub outer_field: FieldId,
    /// How inner field elements are adapted to the outer field.
    pub field_adapter: FieldAdapter,
    /// Optional path to a pre-compiled wrapping circuit.
    pub wrapping_circuit: Option<String>,
    /// Estimated constraint overhead of the recursive verifier.
    pub estimated_verifier_constraints: Option<usize>,
}

impl RecursionPlan {
    /// Create a same-field recursion plan (no adaptation needed).
    pub fn same_field(inner: BackendKind, outer: BackendKind, field: FieldId) -> Self {
        Self {
            inner_backend: inner,
            outer_backend: outer,
            inner_field: field,
            outer_field: field,
            field_adapter: FieldAdapter::NativeCompatible,
            wrapping_circuit: None,
            estimated_verifier_constraints: None,
        }
    }

    /// Create a cross-field recursion plan (requires non-native arithmetic).
    pub fn cross_field(
        inner: BackendKind,
        outer: BackendKind,
        inner_field: FieldId,
        outer_field: FieldId,
    ) -> Self {
        Self {
            inner_backend: inner,
            outer_backend: outer,
            inner_field,
            outer_field,
            field_adapter: FieldAdapter::NonNativeArithmetic,
            wrapping_circuit: None,
            estimated_verifier_constraints: None,
        }
    }

    /// Whether this plan requires non-native field arithmetic.
    pub fn requires_non_native(&self) -> bool {
        self.field_adapter == FieldAdapter::NonNativeArithmetic
    }

    /// Set the wrapping circuit path.
    pub fn with_wrapping_circuit(mut self, path: impl Into<String>) -> Self {
        self.wrapping_circuit = Some(path.into());
        self
    }

    /// Set estimated constraint overhead.
    pub fn with_estimated_constraints(mut self, count: usize) -> Self {
        self.estimated_verifier_constraints = Some(count);
        self
    }
}

/// Known recursion-capable combinations.
pub fn available_recursion_paths() -> Vec<RecursionPlan> {
    vec![
        // STARK -> Groth16 wrapping (Plonky3 Goldilocks -> Arkworks BN254)
        RecursionPlan::cross_field(
            BackendKind::Plonky3,
            BackendKind::ArkworksGroth16,
            FieldId::Goldilocks,
            FieldId::Bn254,
        )
        .with_estimated_constraints(2_000_000),
        // Nova folding (same field)
        RecursionPlan::same_field(BackendKind::Nova, BackendKind::Nova, FieldId::PastaFp)
            .with_estimated_constraints(10_000),
        // HyperNova folding
        RecursionPlan::same_field(
            BackendKind::HyperNova,
            BackendKind::HyperNova,
            FieldId::PastaFp,
        )
        .with_estimated_constraints(15_000),
    ]
}

/// Check if a recursion path is available for given inner/outer backends.
pub fn find_recursion_path(inner: BackendKind, outer: BackendKind) -> Option<RecursionPlan> {
    available_recursion_paths()
        .into_iter()
        .find(|p| p.inner_backend == inner && p.outer_backend == outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_field_plan() {
        let plan =
            RecursionPlan::same_field(BackendKind::Nova, BackendKind::Nova, FieldId::PastaFp);
        assert_eq!(plan.inner_backend, BackendKind::Nova);
        assert_eq!(plan.outer_backend, BackendKind::Nova);
        assert_eq!(plan.inner_field, FieldId::PastaFp);
        assert_eq!(plan.outer_field, FieldId::PastaFp);
        assert_eq!(plan.field_adapter, FieldAdapter::NativeCompatible);
        assert!(!plan.requires_non_native());
        assert!(plan.wrapping_circuit.is_none());
        assert!(plan.estimated_verifier_constraints.is_none());
    }

    #[test]
    fn cross_field_plan() {
        let plan = RecursionPlan::cross_field(
            BackendKind::Plonky3,
            BackendKind::ArkworksGroth16,
            FieldId::Goldilocks,
            FieldId::Bn254,
        );
        assert_eq!(plan.inner_field, FieldId::Goldilocks);
        assert_eq!(plan.outer_field, FieldId::Bn254);
        assert_eq!(plan.field_adapter, FieldAdapter::NonNativeArithmetic);
        assert!(plan.requires_non_native());
    }

    #[test]
    fn builder_methods() {
        let plan =
            RecursionPlan::same_field(BackendKind::Nova, BackendKind::Nova, FieldId::PastaFp)
                .with_wrapping_circuit("/path/to/circuit.r1cs")
                .with_estimated_constraints(50_000);
        assert_eq!(
            plan.wrapping_circuit.as_deref(),
            Some("/path/to/circuit.r1cs")
        );
        assert_eq!(plan.estimated_verifier_constraints, Some(50_000));
    }

    #[test]
    fn available_paths_non_empty() {
        let paths = available_recursion_paths();
        assert!(!paths.is_empty());
        // Expect at least the three known paths
        assert!(paths.len() >= 3);
    }

    #[test]
    fn find_stark_to_groth16() {
        let plan = find_recursion_path(BackendKind::Plonky3, BackendKind::ArkworksGroth16);
        assert!(plan.is_some());
        let plan = plan.unwrap();
        assert_eq!(plan.inner_field, FieldId::Goldilocks);
        assert_eq!(plan.outer_field, FieldId::Bn254);
        assert!(plan.requires_non_native());
        assert_eq!(plan.estimated_verifier_constraints, Some(2_000_000));
    }

    #[test]
    fn find_nova_folding() {
        let plan = find_recursion_path(BackendKind::Nova, BackendKind::Nova);
        assert!(plan.is_some());
        let plan = plan.unwrap();
        assert_eq!(plan.inner_field, FieldId::PastaFp);
        assert!(!plan.requires_non_native());
    }

    #[test]
    fn find_hypernova_folding() {
        let plan = find_recursion_path(BackendKind::HyperNova, BackendKind::HyperNova);
        assert!(plan.is_some());
        let plan = plan.unwrap();
        assert_eq!(plan.field_adapter, FieldAdapter::NativeCompatible);
    }

    #[test]
    fn find_nonexistent_path_returns_none() {
        let plan = find_recursion_path(BackendKind::Halo2, BackendKind::Sp1);
        assert!(plan.is_none());
    }

    #[test]
    fn field_adapter_serde_roundtrip() {
        for adapter in [
            FieldAdapter::NativeCompatible,
            FieldAdapter::NonNativeArithmetic,
        ] {
            let json = serde_json::to_string(&adapter).unwrap();
            let parsed: FieldAdapter = serde_json::from_str(&json).unwrap();
            assert_eq!(adapter, parsed);
        }
    }

    #[test]
    fn field_adapter_serde_names() {
        assert_eq!(
            serde_json::to_string(&FieldAdapter::NativeCompatible).unwrap(),
            "\"native_compatible\""
        );
        assert_eq!(
            serde_json::to_string(&FieldAdapter::NonNativeArithmetic).unwrap(),
            "\"non_native_arithmetic\""
        );
    }

    #[test]
    fn recursion_plan_serde_roundtrip() {
        let plan = RecursionPlan::cross_field(
            BackendKind::Plonky3,
            BackendKind::ArkworksGroth16,
            FieldId::Goldilocks,
            FieldId::Bn254,
        )
        .with_wrapping_circuit("test.r1cs")
        .with_estimated_constraints(1_000_000);

        let json = serde_json::to_string_pretty(&plan).unwrap();
        let parsed: RecursionPlan = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.inner_backend, plan.inner_backend);
        assert_eq!(parsed.outer_backend, plan.outer_backend);
        assert_eq!(parsed.inner_field, plan.inner_field);
        assert_eq!(parsed.outer_field, plan.outer_field);
        assert_eq!(parsed.field_adapter, plan.field_adapter);
        assert_eq!(parsed.wrapping_circuit, plan.wrapping_circuit);
        assert_eq!(
            parsed.estimated_verifier_constraints,
            plan.estimated_verifier_constraints
        );
    }
}
