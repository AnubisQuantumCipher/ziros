use zkf_core::{FieldElement, FieldId, ZkfResult};

/// Trait for converting between the generic `FieldElement` representation and
/// backend-native field types. Each backend implements this for its native type
/// to avoid string parsing on every field operation.
pub trait NativeField: Sized {
    /// Convert from a generic `FieldElement` to this native representation.
    fn from_field_element(fe: &FieldElement, field: FieldId) -> ZkfResult<Self>;

    /// Convert from this native representation back to a generic `FieldElement`.
    fn to_field_element(&self) -> FieldElement;

    /// The field this native type belongs to.
    fn field_id() -> FieldId;
}

// Backend-specific NativeField implementations are provided alongside each backend
// module (arkworks.rs, halo2.rs, plonky3.rs) since they depend on the backend's
// native field crate imports.
