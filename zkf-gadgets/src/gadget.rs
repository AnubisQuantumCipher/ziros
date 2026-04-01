use std::collections::BTreeMap;
use zkf_core::zir;
use zkf_core::{BackendCapabilityMatrix, FieldId, ZkfError, ZkfResult};

pub const BUILTIN_GADGET_NAMES: [&str; 11] = [
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

const ALL_FRAMEWORK_FIELDS: [FieldId; 7] = [
    FieldId::Bn254,
    FieldId::Bls12_381,
    FieldId::PastaFp,
    FieldId::PastaFq,
    FieldId::Goldilocks,
    FieldId::BabyBear,
    FieldId::Mersenne31,
];

fn capability_backed_fields(op: &str) -> Vec<FieldId> {
    let mut discovered = Vec::new();
    for entry in BackendCapabilityMatrix::current().entries {
        if entry
            .supported_blackbox_ops
            .iter()
            .any(|supported| supported == op)
        {
            for field in entry.supported_fields {
                if !discovered.contains(&field) {
                    discovered.push(field);
                }
            }
        }
    }
    ALL_FRAMEWORK_FIELDS
        .iter()
        .copied()
        .filter(|field| discovered.contains(field))
        .collect()
}

pub fn builtin_supported_fields(name: &str) -> Option<Vec<FieldId>> {
    match name {
        "poseidon" | "merkle" => Some(capability_backed_fields("poseidon")),
        "sha256" => Some(capability_backed_fields("sha256")),
        "boolean" | "comparison" | "range" | "plonk_gate" => Some(ALL_FRAMEWORK_FIELDS.to_vec()),
        "ecdsa" | "schnorr" => Some(vec![FieldId::Bn254]),
        "kzg" => Some(vec![FieldId::Bn254, FieldId::Bls12_381]),
        "blake3" => Some(vec![
            FieldId::Bn254,
            FieldId::Bls12_381,
            FieldId::PastaFp,
            FieldId::PastaFq,
            FieldId::Goldilocks,
        ]),
        _ => None,
    }
}

pub fn builtin_supported_field_names(name: &str) -> Option<Vec<String>> {
    builtin_supported_fields(name).map(|fields| {
        fields
            .into_iter()
            .map(|field| field.as_str().to_string())
            .collect()
    })
}

pub fn validate_builtin_field_support(name: &str, field: FieldId) -> ZkfResult<()> {
    let Some(supported_fields) = builtin_supported_fields(name) else {
        return Err(ZkfError::InvalidArtifact(format!(
            "unknown builtin gadget '{name}'"
        )));
    };

    if supported_fields.contains(&field) {
        return Ok(());
    }

    let supported = supported_fields
        .into_iter()
        .map(|supported| supported.as_str().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(ZkfError::InvalidArtifact(format!(
        "gadget '{name}' does not support field '{field}'. Supported fields: {supported}"
    )))
}

/// A reusable, backend-optimized circuit component.
pub trait Gadget: Send + Sync {
    /// Human-readable gadget name (e.g., "poseidon", "merkle_membership").
    fn name(&self) -> &str;

    /// Which fields this gadget supports.
    fn supported_fields(&self) -> Vec<FieldId>;

    /// Emit ZIR signals, constraints, and witness assignments for this gadget.
    fn emit(
        &self,
        inputs: &[zir::Expr],
        outputs: &[String],
        field: FieldId,
        params: &BTreeMap<String, String>,
    ) -> ZkfResult<GadgetEmission>;
}

/// The output of a gadget emission: new signals, constraints, assignments,
/// and optionally lookup tables.
#[derive(Debug, Clone, Default)]
pub struct GadgetEmission {
    pub signals: Vec<zir::Signal>,
    pub constraints: Vec<zir::Constraint>,
    pub assignments: Vec<zir::WitnessAssignment>,
    pub lookup_tables: Vec<zir::LookupTable>,
}

/// Registry of available gadgets, indexed by name.
pub struct GadgetRegistry {
    gadgets: BTreeMap<String, Box<dyn Gadget>>,
}

impl GadgetRegistry {
    pub fn new() -> Self {
        Self {
            gadgets: BTreeMap::new(),
        }
    }

    /// Create a registry pre-loaded with all built-in gadgets.
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        registry.register(Box::new(crate::blake3::Blake3Gadget));
        registry.register(Box::new(crate::boolean::BooleanGadget));
        registry.register(Box::new(crate::comparison::ComparisonGadget));
        registry.register(Box::new(crate::ecdsa::EcdsaGadget));
        registry.register(Box::new(crate::kzg::KzgGadget));
        registry.register(Box::new(crate::merkle::MerkleGadget));
        registry.register(Box::new(crate::plonk_gate::PlonkGateGadget));
        registry.register(Box::new(crate::poseidon::PoseidonGadget));
        registry.register(Box::new(crate::range::RangeGadget));
        registry.register(Box::new(crate::schnorr::SchnorrGadget));
        registry.register(Box::new(crate::sha256::Sha256Gadget));
        registry
    }

    pub fn register(&mut self, gadget: Box<dyn Gadget>) {
        self.gadgets.insert(gadget.name().to_string(), gadget);
    }

    pub fn get(&self, name: &str) -> Option<&dyn Gadget> {
        self.gadgets.get(name).map(|g| g.as_ref())
    }

    pub fn list(&self) -> Vec<&str> {
        self.gadgets.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for GadgetRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}
