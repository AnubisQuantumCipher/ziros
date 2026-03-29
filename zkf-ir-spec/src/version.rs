//! IR version negotiation.
//!
//! Provides [`IrVersion`] with major/minor fields and semver-style compatibility checks.

use serde::{Deserialize, Serialize};

/// Semantic version of the IR specification.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct IrVersion {
    pub major: u32,
    pub minor: u32,
}

impl IrVersion {
    pub fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Check if this version is compatible with another (same major, >= minor).
    pub fn is_compatible_with(&self, other: &IrVersion) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

impl std::fmt::Display for IrVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compatibility() {
        let v2_0 = IrVersion::new(2, 0);
        let v2_1 = IrVersion::new(2, 1);
        let v3_0 = IrVersion::new(3, 0);

        assert!(v2_1.is_compatible_with(&v2_0));
        assert!(!v2_0.is_compatible_with(&v2_1));
        assert!(!v3_0.is_compatible_with(&v2_0));
    }
}
