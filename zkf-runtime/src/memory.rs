//! Unified memory buffer management.

use crate::slot_map::SlotMap;
use std::sync::atomic::{AtomicU64, Ordering};

// ─── Node identity ─────────────────────────────────────────────────────────

/// Unique identifier for a node in the proving graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(u64);

static NEXT_NODE_ID: AtomicU64 = AtomicU64::new(1);

impl NodeId {
    pub fn new() -> Self {
        Self(NEXT_NODE_ID.fetch_add(1, Ordering::Relaxed))
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Buffer management ─────────────────────────────────────────────────────

/// A handle into the `UnifiedBufferPool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BufferHandle {
    pub slot: u32,
    /// Expected size in bytes; used for memory-pressure estimates.
    pub size_bytes: usize,
    pub class: MemoryClass,
}

/// Physical backing status of a buffer slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PhysicalBacking {
    /// No physical memory has been bound yet.
    Unbound,
    /// Backed by CPU-only (host) memory.
    CpuBound,
    /// Backed by GPU-shared (unified/managed) memory.
    GpuSharedBound,
    /// Evicted to persistent storage (SSD/disk).
    Spilled,
}

/// Public summary of a slot's metadata, suitable for external inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotSummary {
    pub slot: u32,
    pub size_bytes: usize,
    pub class: MemoryClass,
    pub backing: PhysicalBacking,
    pub live: bool,
    pub content_digest: Option<[u8; 8]>,
}

/// Lifetime class of a buffer in the unified arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemoryClass {
    /// Proving keys, twiddle tables, MSM bases.
    /// Allocated once, kept resident across many proof invocations.
    HotResident,
    /// Intermediate NTT stages, partial buckets, batched hash outputs.
    /// Valid only for the duration of a single graph execution.
    EphemeralScratch,
    /// Large traces, old Merkle layers, archived polynomial chunks.
    /// May be evicted to SSD when memory pressure is high.
    Spillable,
}

/// A slot-indexed pool of buffers living in unified (CPU+GPU) memory.
pub struct UnifiedBufferPool {
    /// Total bytes currently allocated across all slots.
    allocated_bytes: usize,
    /// Configurable ceiling before spill kicks in.
    pub capacity_limit: usize,
    /// Monotonically increasing slot counter.
    next_slot: u32,
    /// Per-slot metadata.
    slots: SlotMap<u32, SlotMeta>,
}

#[derive(Debug)]
struct SlotMeta {
    size_bytes: usize,
    class: MemoryClass,
    last_writer: Option<NodeId>,
    live: bool,
    backing: PhysicalBacking,
    content_digest: Option<[u8; 8]>,
}

impl UnifiedBufferPool {
    pub fn new(capacity_limit: usize) -> Self {
        Self {
            allocated_bytes: 0,
            capacity_limit,
            next_slot: 1,
            slots: SlotMap::new(),
        }
    }

    pub fn alloc(&mut self, size_bytes: usize, class: MemoryClass) -> Option<BufferHandle> {
        if self.allocated_bytes + size_bytes > self.capacity_limit {
            self.evict_spillable(size_bytes);
            if self.allocated_bytes + size_bytes > self.capacity_limit {
                return None;
            }
        }
        let slot = self.next_slot;
        self.next_slot += 1;
        self.allocated_bytes += size_bytes;
        self.slots.insert(
            slot,
            SlotMeta {
                size_bytes,
                class,
                last_writer: None,
                live: true,
                backing: PhysicalBacking::Unbound,
                content_digest: None,
            },
        );
        Some(BufferHandle {
            slot,
            size_bytes,
            class,
        })
    }

    pub fn track_handle(&mut self, handle: BufferHandle) {
        if self.slots.contains_key(&handle.slot) {
            return;
        }
        self.allocated_bytes += handle.size_bytes;
        self.next_slot = self.next_slot.max(handle.slot.saturating_add(1));
        self.slots.insert(
            handle.slot,
            SlotMeta {
                size_bytes: handle.size_bytes,
                class: handle.class,
                last_writer: None,
                live: true,
                backing: PhysicalBacking::Unbound,
                content_digest: None,
            },
        );
    }

    pub fn free(&mut self, handle: BufferHandle) {
        if let Some(meta) = self.slots.get_mut(&handle.slot)
            && meta.live
        {
            self.allocated_bytes = self.allocated_bytes.saturating_sub(meta.size_bytes);
            meta.live = false;
        }
    }

    pub fn mark_written(&mut self, handle: BufferHandle, writer: NodeId) {
        if let Some(meta) = self.slots.get_mut(&handle.slot) {
            meta.last_writer = Some(writer);
        }
    }

    pub fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    /// Query the physical backing status of a slot.
    pub fn slot_backing(&self, slot: u32) -> Option<PhysicalBacking> {
        self.slots.get(&slot).map(|m| m.backing)
    }

    /// Update the physical backing status of a slot.
    pub fn set_backing(&mut self, slot: u32, backing: PhysicalBacking) {
        if let Some(meta) = self.slots.get_mut(&slot) {
            meta.backing = backing;
        }
    }

    /// Query the content digest of a slot.
    pub fn slot_digest(&self, slot: u32) -> Option<[u8; 8]> {
        self.slots.get(&slot).and_then(|m| m.content_digest)
    }

    /// Set the content digest of a slot after execution.
    pub fn set_digest(&mut self, slot: u32, digest: [u8; 8]) {
        if let Some(meta) = self.slots.get_mut(&slot) {
            meta.content_digest = Some(digest);
        }
    }

    /// Return a public summary of a slot's metadata.
    pub fn slot_meta_summary(&self, slot: u32) -> Option<SlotSummary> {
        self.slots.get(&slot).map(|m| SlotSummary {
            slot,
            size_bytes: m.size_bytes,
            class: m.class,
            backing: m.backing,
            live: m.live,
            content_digest: m.content_digest,
        })
    }

    /// Return the slot ids of all live (non-freed) slots.
    pub fn live_slots(&self) -> Vec<u32> {
        let mut ids: Vec<u32> = self
            .slots
            .iter()
            .filter(|(_, m)| m.live)
            .map(|(slot, _)| *slot)
            .collect();
        ids.sort_unstable();
        ids
    }

    fn evict_spillable(&mut self, needed: usize) {
        let mut recovered = 0usize;
        let spillable: Vec<u32> = self
            .slots
            .iter()
            .filter(|(_, m)| m.live && m.class == MemoryClass::Spillable)
            .map(|(slot, _)| *slot)
            .collect();
        for slot in spillable {
            if recovered >= needed {
                break;
            }
            if let Some(meta) = self.slots.get_mut(&slot) {
                recovered += meta.size_bytes;
                self.allocated_bytes = self.allocated_bytes.saturating_sub(meta.size_bytes);
                meta.live = false;
            }
        }
    }
}

/// Compute a short deterministic digest of a slice of buffer handles.
pub fn digest_handles(handles: &[BufferHandle]) -> [u8; 8] {
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis
    for h in handles {
        let bytes = h.slot.to_le_bytes();
        for b in bytes {
            acc ^= b as u64;
            acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    acc.to_le_bytes()
}
