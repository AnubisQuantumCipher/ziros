//! Metal 4-style barrier helpers backed by the current compute-encoder API.

use objc2::runtime::ProtocolObject;
use objc2_metal::{MTLBarrierScope, MTLComputeCommandEncoder};

/// Barrier scope for Metal synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierScope {
    Threadgroup,
    Device,
    Buffers,
}

impl BarrierScope {
    pub(crate) fn as_metal(self) -> MTLBarrierScope {
        match self {
            Self::Threadgroup => MTLBarrierScope::Buffers,
            Self::Device => MTLBarrierScope::Buffers,
            Self::Buffers => MTLBarrierScope::Buffers,
        }
    }
}

/// Apply a memory barrier to the active compute encoder.
pub fn apply_barrier(encoder: &ProtocolObject<dyn MTLComputeCommandEncoder>, scope: BarrierScope) {
    encoder.memoryBarrierWithScope(scope.as_metal());
}

/// Small helper for batching multiple barrier applications into a single call site.
#[derive(Debug, Default, Clone)]
pub struct BarrierGroup {
    scopes: Vec<BarrierScope>,
}

impl BarrierGroup {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_scope(mut self, scope: BarrierScope) -> Self {
        self.scopes.push(scope);
        self
    }

    pub fn push(&mut self, scope: BarrierScope) {
        self.scopes.push(scope);
    }

    pub fn apply(&self, encoder: &ProtocolObject<dyn MTLComputeCommandEncoder>) {
        for scope in &self.scopes {
            apply_barrier(encoder, *scope);
        }
    }

    pub fn is_empty(&self) -> bool {
        self.scopes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn barrier_group_tracks_scopes() {
        let mut group = BarrierGroup::new();
        assert!(group.is_empty());
        group.push(BarrierScope::Buffers);
        group.push(BarrierScope::Device);
        assert!(!group.is_empty());
    }
}
