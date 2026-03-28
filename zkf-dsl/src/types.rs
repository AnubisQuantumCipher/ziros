use std::collections::BTreeMap;

/// Maps Rust types to ZIR SignalType names for code generation.
pub fn rust_type_to_signal_type(ty: &str) -> &'static str {
    match ty.trim() {
        "bool" => "Bool",
        "u8" => "UInt8",
        "u16" => "UInt16",
        "u32" => "UInt32",
        "u64" => "UInt64",
        "Field" => "Field",
        _ => "Field",
    }
}

/// Parse an array type like `[Field; 4]` into (element_type, length).
pub fn parse_array_type(ty: &str) -> Option<(&str, u32)> {
    let trimmed = ty.trim();
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?;
    let mut parts = inner.splitn(2, ';');
    let elem = parts.next()?.trim();
    let len_str = parts.next()?.trim();
    let len: u32 = len_str.parse().ok()?;
    Some((elem, len))
}

// ---------------------------------------------------------------------------
// 7C: Type Inference
// ---------------------------------------------------------------------------

/// The set of types the DSL can infer for circuit signals and bindings.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum InferredType {
    /// A prime-field element (default).
    Field,
    /// A boolean value.
    Bool,
    /// An unsigned integer of the given bit-width.
    UInt(u32),
    /// A fixed-length array of a homogeneous type.
    Array(Box<InferredType>, u32),
    /// A named struct type.
    Struct(String),
    /// Type not yet determined.
    Unknown,
}

#[allow(dead_code)]
impl InferredType {
    /// Infer the result type of an addition or subtraction of two operands.
    ///
    /// `UInt(n) op UInt(m) → UInt(max(n, m))`
    /// `Field op Field → Field`
    /// `Unknown op T → T`, `T op Unknown → T`
    /// Everything else → Field (conservative widening).
    pub fn infer_add_sub(lhs: &InferredType, rhs: &InferredType) -> InferredType {
        match (lhs, rhs) {
            (InferredType::UInt(n), InferredType::UInt(m)) => InferredType::UInt(*n.max(m)),
            (InferredType::Field, InferredType::Field) => InferredType::Field,
            (InferredType::Unknown, other) | (other, InferredType::Unknown) => other.clone(),
            _ => InferredType::Field,
        }
    }

    /// Infer the result type of a multiplication.
    ///
    /// `UInt(n) * UInt(m) → UInt(n + m)` (product may need more bits).
    /// `Field * Field → Field`.
    pub fn infer_mul(lhs: &InferredType, rhs: &InferredType) -> InferredType {
        match (lhs, rhs) {
            (InferredType::UInt(n), InferredType::UInt(m)) => {
                InferredType::UInt(n.saturating_add(*m))
            }
            (InferredType::Field, InferredType::Field) => InferredType::Field,
            (InferredType::Unknown, other) | (other, InferredType::Unknown) => other.clone(),
            _ => InferredType::Field,
        }
    }

    /// Infer the result type of a boolean AND/OR operation.
    ///
    /// `Bool && Bool → Bool`, `Bool || Bool → Bool`.
    pub fn infer_bool_op(lhs: &InferredType, rhs: &InferredType) -> InferredType {
        match (lhs, rhs) {
            (InferredType::Bool, InferredType::Bool) => InferredType::Bool,
            _ => InferredType::Unknown,
        }
    }

    /// Convert an `InferredType` into the corresponding ZIR `SignalType` name
    /// used by the code generator.
    pub fn to_signal_type_str(&self) -> &'static str {
        match self {
            InferredType::Bool => "Bool",
            InferredType::UInt(8) => "UInt8",
            InferredType::UInt(16) => "UInt16",
            InferredType::UInt(32) => "UInt32",
            InferredType::UInt(64) => "UInt64",
            _ => "Field",
        }
    }
}

/// A typing environment that maps binding names to their inferred types.
pub struct TypeEnv {
    pub bindings: BTreeMap<String, InferredType>,
}

impl TypeEnv {
    /// Create an empty typing environment.
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
        }
    }

    /// Record (or overwrite) the type of a binding.
    pub fn insert(&mut self, name: String, ty: InferredType) {
        self.bindings.insert(name, ty);
    }

    /// Look up the inferred type of a binding.
    pub fn get(&self, name: &str) -> Option<&InferredType> {
        self.bindings.get(name)
    }
}

impl Default for TypeEnv {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_type_to_signal_type_known_types() {
        assert_eq!(rust_type_to_signal_type("bool"), "Bool");
        assert_eq!(rust_type_to_signal_type("u8"), "UInt8");
        assert_eq!(rust_type_to_signal_type("u16"), "UInt16");
        assert_eq!(rust_type_to_signal_type("u32"), "UInt32");
        assert_eq!(rust_type_to_signal_type("u64"), "UInt64");
        assert_eq!(rust_type_to_signal_type("Field"), "Field");
        assert_eq!(rust_type_to_signal_type("Unknown"), "Field");
    }

    #[test]
    fn parse_array_type_basic() {
        assert_eq!(parse_array_type("[Field; 4]"), Some(("Field", 4)));
        assert_eq!(parse_array_type("[u32; 8]"), Some(("u32", 8)));
        assert_eq!(parse_array_type("Field"), None);
    }

    #[test]
    fn inferred_type_add_sub_uint() {
        let a = InferredType::UInt(16);
        let b = InferredType::UInt(32);
        assert_eq!(InferredType::infer_add_sub(&a, &b), InferredType::UInt(32));
    }

    #[test]
    fn inferred_type_add_sub_field() {
        let a = InferredType::Field;
        let b = InferredType::Field;
        assert_eq!(InferredType::infer_add_sub(&a, &b), InferredType::Field);
    }

    #[test]
    fn inferred_type_add_sub_unknown_widens_to_known() {
        let a = InferredType::Unknown;
        let b = InferredType::UInt(8);
        assert_eq!(InferredType::infer_add_sub(&a, &b), InferredType::UInt(8));
    }

    #[test]
    fn inferred_type_mul_uint_sums_bits() {
        let a = InferredType::UInt(16);
        let b = InferredType::UInt(16);
        assert_eq!(InferredType::infer_mul(&a, &b), InferredType::UInt(32));
    }

    #[test]
    fn inferred_type_mul_field() {
        assert_eq!(
            InferredType::infer_mul(&InferredType::Field, &InferredType::Field),
            InferredType::Field
        );
    }

    #[test]
    fn inferred_type_bool_op() {
        assert_eq!(
            InferredType::infer_bool_op(&InferredType::Bool, &InferredType::Bool),
            InferredType::Bool
        );
        assert_eq!(
            InferredType::infer_bool_op(&InferredType::Bool, &InferredType::Field),
            InferredType::Unknown
        );
    }

    #[test]
    fn inferred_type_to_signal_type_str() {
        assert_eq!(InferredType::Bool.to_signal_type_str(), "Bool");
        assert_eq!(InferredType::UInt(8).to_signal_type_str(), "UInt8");
        assert_eq!(InferredType::UInt(32).to_signal_type_str(), "UInt32");
        assert_eq!(InferredType::UInt(64).to_signal_type_str(), "UInt64");
        assert_eq!(InferredType::Field.to_signal_type_str(), "Field");
        assert_eq!(InferredType::Unknown.to_signal_type_str(), "Field");
        assert_eq!(InferredType::UInt(7).to_signal_type_str(), "Field"); // non-standard width
    }

    #[test]
    fn type_env_insert_and_get() {
        let mut env = TypeEnv::new();
        env.insert("x".to_string(), InferredType::UInt(32));
        assert_eq!(env.get("x"), Some(&InferredType::UInt(32)));
        assert_eq!(env.get("y"), None);
    }

    #[test]
    fn type_env_overwrite() {
        let mut env = TypeEnv::new();
        env.insert("x".to_string(), InferredType::Field);
        env.insert("x".to_string(), InferredType::Bool);
        assert_eq!(env.get("x"), Some(&InferredType::Bool));
    }

    #[test]
    fn type_env_default_is_empty() {
        let env = TypeEnv::default();
        assert!(env.bindings.is_empty());
    }
}
