#![allow(dead_code)]

//! Kani-friendly pure buffer bridge core.
//!
//! This module models the proof-relevant buffer semantics without filesystem,
//! GPU allocation, or the runtime slot-map implementation. The current Kani
//! harnesses use this core directly so the bounded checks stay focused on
//! typed-view alignment and spill/reload behavior.

use crate::error::RuntimeError;
use crate::memory::{BufferHandle, MemoryClass, NodeId};

const MAX_CORE_SLOTS: usize = 16;
const MAX_SLOT_BYTES: usize = 256;

#[derive(Debug, Clone)]
struct CoreSlot {
    occupied: bool,
    slot: u32,
    class: MemoryClass,
    len: usize,
    bytes: [u8; MAX_SLOT_BYTES],
    resident: bool,
    last_writer: Option<NodeId>,
    digest: Option<[u8; 8]>,
}

impl CoreSlot {
    fn empty() -> Self {
        Self {
            occupied: false,
            slot: 0,
            class: MemoryClass::Spillable,
            len: 0,
            bytes: [0u8; MAX_SLOT_BYTES],
            resident: false,
            last_writer: None,
            digest: None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BufferBridgeCore {
    slots: [CoreSlot; MAX_CORE_SLOTS],
    slot_count: usize,
    current_resident_bytes: usize,
    peak_resident_bytes: usize,
}

impl Default for BufferBridgeCore {
    fn default() -> Self {
        Self {
            slots: std::array::from_fn(|_| CoreSlot::empty()),
            slot_count: 0,
            current_resident_bytes: 0,
            peak_resident_bytes: 0,
        }
    }
}

impl BufferBridgeCore {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn allocate(&mut self, handle: BufferHandle) -> Result<(), RuntimeError> {
        if self.find_slot_index(handle.slot).is_some() {
            return Ok(());
        }
        if handle.size_bytes > MAX_SLOT_BYTES {
            return Err(RuntimeError::Allocation(
                "proof core slot exceeds maximum byte capacity".to_string(),
            ));
        }

        let index = self
            .find_empty_slot_index()
            .ok_or(RuntimeError::BufferExhausted {
                needed_bytes: handle.size_bytes,
            })?;

        self.slots[index] = CoreSlot {
            occupied: true,
            slot: handle.slot,
            class: handle.class,
            len: handle.size_bytes,
            bytes: [0u8; MAX_SLOT_BYTES],
            resident: true,
            last_writer: None,
            digest: None,
        };
        self.slot_count += 1;
        self.current_resident_bytes += handle.size_bytes;
        if self.current_resident_bytes > self.peak_resident_bytes {
            self.peak_resident_bytes = self.current_resident_bytes;
        }
        Ok(())
    }

    pub(crate) fn write_slot(&mut self, slot: u32, data: &[u8]) -> Result<(), RuntimeError> {
        if data.len() > MAX_SLOT_BYTES {
            return Err(RuntimeError::Allocation(
                "proof core slot write exceeds maximum byte capacity".to_string(),
            ));
        }

        let index = self
            .find_slot_index(slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;
        if !self.slots[index].resident {
            return Err(RuntimeError::BufferNotResident { slot });
        }

        let old_len = self.slots[index].len;
        let new_len = data.len();
        self.slots[index].len = new_len;
        self.slots[index].bytes[..new_len].copy_from_slice(data);
        if new_len > old_len {
            self.current_resident_bytes += new_len - old_len;
            if self.current_resident_bytes > self.peak_resident_bytes {
                self.peak_resident_bytes = self.current_resident_bytes;
            }
        }
        Ok(())
    }

    pub(crate) fn view(&self, slot: u32) -> Result<&[u8], RuntimeError> {
        let index = self
            .find_slot_index(slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;
        let meta = &self.slots[index];
        if !meta.resident {
            return Err(RuntimeError::BufferNotResident { slot });
        }
        if meta.len > MAX_SLOT_BYTES {
            return Err(RuntimeError::Allocation(
                "proof core length invariant violated".to_string(),
            ));
        }
        Ok(&meta.bytes[..meta.len])
    }

    pub(crate) fn view_mut(&mut self, slot: u32) -> Result<&mut [u8], RuntimeError> {
        let index = self
            .find_slot_index(slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;
        if !self.slots[index].resident {
            return Err(RuntimeError::BufferNotResident { slot });
        }
        let len = self.slots[index].len;
        if len > MAX_SLOT_BYTES {
            return Err(RuntimeError::Allocation(
                "proof core length invariant violated".to_string(),
            ));
        }
        Ok(&mut self.slots[index].bytes[..len])
    }

    pub(crate) fn copy_resident_prefix<const N: usize>(
        &self,
        slot: u32,
    ) -> Result<[u8; N], RuntimeError> {
        let index = self
            .find_slot_index(slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;
        let meta = &self.slots[index];
        if !meta.resident {
            return Err(RuntimeError::BufferNotResident { slot });
        }
        if meta.len > MAX_SLOT_BYTES {
            return Err(RuntimeError::Allocation(
                "proof core length invariant violated".to_string(),
            ));
        }
        if meta.len < N {
            return Err(RuntimeError::Allocation(
                "proof core resident prefix shorter than requested".to_string(),
            ));
        }

        let mut out = [0u8; N];
        let mut index = 0usize;
        while index < N {
            out[index] = meta.bytes[index];
            index += 1;
        }
        Ok(out)
    }

    pub(crate) fn evict_spillable(&mut self, slot: u32) -> Result<(), RuntimeError> {
        let index = self
            .find_slot_index(slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;
        let meta = &mut self.slots[index];
        if meta.class != MemoryClass::Spillable || !meta.resident {
            return Ok(());
        }

        meta.resident = false;
        self.current_resident_bytes = self.current_resident_bytes.saturating_sub(meta.len);
        Ok(())
    }

    pub(crate) fn ensure_resident(&mut self, slot: u32) -> Result<(), RuntimeError> {
        let index = self
            .find_slot_index(slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;
        let meta = &mut self.slots[index];
        if meta.resident {
            return Ok(());
        }

        meta.resident = true;
        self.current_resident_bytes += meta.len;
        if self.current_resident_bytes > self.peak_resident_bytes {
            self.peak_resident_bytes = self.current_resident_bytes;
        }
        Ok(())
    }

    pub(crate) fn mark_written(&mut self, slot: u32, writer: NodeId) {
        let digest = self.compute_digest(slot);
        if let Some(index) = self.find_slot_index(slot) {
            self.slots[index].last_writer = Some(writer);
            self.slots[index].digest = digest;
        }
    }

    pub(crate) fn slot_digest(&self, slot: u32) -> Option<[u8; 8]> {
        self.find_slot_index(slot)
            .and_then(|index| self.slots[index].digest)
    }

    pub(crate) fn free(&mut self, slot: u32) {
        if let Some(index) = self.find_slot_index(slot) {
            let removed_len = self.slots[index].len;
            let was_resident = self.slots[index].resident;
            self.slots[index] = CoreSlot::empty();
            self.slot_count = self.slot_count.saturating_sub(1);
            if was_resident {
                self.current_resident_bytes =
                    self.current_resident_bytes.saturating_sub(removed_len);
            }
        }
    }

    pub(crate) fn is_resident(&self, slot: u32) -> bool {
        if let Some(index) = self.find_slot_index(slot) {
            self.slots[index].resident
        } else {
            false
        }
    }

    pub(crate) fn current_resident_bytes(&self) -> usize {
        self.current_resident_bytes
    }

    pub(crate) fn peak_resident_bytes(&self) -> usize {
        self.peak_resident_bytes
    }

    pub(crate) fn slot_count(&self) -> usize {
        self.slot_count
    }

    fn find_slot_index(&self, slot: u32) -> Option<usize> {
        let mut index = 0usize;
        while index < MAX_CORE_SLOTS {
            let entry = &self.slots[index];
            if entry.occupied && entry.slot == slot {
                return Some(index);
            }
            index += 1;
        }
        None
    }

    fn find_empty_slot_index(&self) -> Option<usize> {
        let mut index = 0usize;
        while index < MAX_CORE_SLOTS {
            if !self.slots[index].occupied {
                return Some(index);
            }
            index += 1;
        }
        None
    }

    fn compute_digest(&self, slot: u32) -> Option<[u8; 8]> {
        let index = self.find_slot_index(slot)?;
        let meta = &self.slots[index];
        if !meta.resident {
            return None;
        }

        let sample_len = meta.len.min(64);
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        let mut i = 0usize;
        while i < sample_len {
            acc ^= meta.bytes[i] as u64;
            acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
            i += 1;
        }
        Some(acc.to_le_bytes())
    }
}
