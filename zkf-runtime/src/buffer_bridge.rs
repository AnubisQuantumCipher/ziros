// Copyright (c) 2026 AnubisQuantumCipher. All rights reserved.
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// Change Date: April 1, 2030
// Change License: Apache License 2.0

//! Physical buffer bridge: turns logical `BufferHandle` slots into real
//! shared CPU/GPU allocations with spill/reload.
//!
//! On Apple Silicon the bridge can be extended by `zkf-metal` to allocate
//! `storageModeShared` Metal buffers.  The runtime itself only manages
//! CPU-owned and spilled buffers.  GPU buffer management is injected via
//! the `GpuBufferAllocator` trait.

use crate::error::RuntimeError;
use crate::memory::{BufferHandle, MemoryClass, NodeId, UnifiedBufferPool};
use crate::slot_map::SlotMap;
use serde::Serialize;
#[cfg(not(feature = "kani-minimal"))]
use std::io::{Read, Write};
#[cfg(not(feature = "kani-minimal"))]
use std::path::Path;
use std::path::PathBuf;
#[cfg(not(feature = "kani-minimal"))]
use std::sync::atomic::{AtomicU64, Ordering};

// ─── Physical Buffer ──────────────────────────────────────────────────────

/// Backing store for a live buffer slot.
#[derive(Debug)]
pub enum PhysicalBuffer {
    /// CPU-only heap allocation.
    CpuOwned { bytes: Vec<u8> },
    /// GPU shared allocation managed by the external GPU allocator.
    /// The runtime treats this as an opaque CPU-visible pointer + length.
    GpuShared {
        /// CPU-visible pointer to the shared allocation.
        ptr: *mut u8,
        len_bytes: usize,
        /// Opaque token for the GPU allocator to free/manage this buffer.
        gpu_token: u64,
    },
    /// Evicted to disk; must be reloaded before use.
    Spilled { path: PathBuf, len_bytes: usize },
}

// SAFETY: GpuShared ptr is only used via BufferView/BufferViewMut which
// borrow the bridge, ensuring no concurrent mutation.
unsafe impl Send for PhysicalBuffer {}
unsafe impl Sync for PhysicalBuffer {}

impl PhysicalBuffer {
    pub fn len_bytes(&self) -> usize {
        match self {
            PhysicalBuffer::CpuOwned { bytes } => bytes.len(),
            PhysicalBuffer::GpuShared { len_bytes, .. } => *len_bytes,
            PhysicalBuffer::Spilled { len_bytes, .. } => *len_bytes,
        }
    }

    pub fn is_spilled(&self) -> bool {
        matches!(self, PhysicalBuffer::Spilled { .. })
    }

    pub fn is_resident(&self) -> bool {
        !self.is_spilled()
    }
}

// ─── Residency class ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidencyClass {
    Cpu,
    MetalShared,
    Spilled,
}

// ─── GPU Buffer Allocator Trait ───────────────────────────────────────────

/// Trait for GPU-side buffer allocation.  Implemented by `zkf-metal`.
/// The runtime calls through this trait to allocate shared Metal buffers.
pub trait GpuBufferAllocator: Send + Sync {
    /// Allocate a shared buffer of `size_bytes`.
    /// Returns (cpu_ptr, gpu_token) or None if allocation fails.
    fn alloc_shared(&self, size_bytes: usize) -> Option<(*mut u8, u64)>;

    /// Free a previously allocated shared buffer.
    fn free_shared(&self, gpu_token: u64);

    /// Whether GPU allocation is available.
    fn is_available(&self) -> bool;
}

// ─── Buffer View ──────────────────────────────────────────────────────────

/// Immutable typed view over a resident buffer.
pub struct BufferView<'a> {
    bytes: &'a [u8],
}

impl<'a> BufferView<'a> {
    #[allow(dead_code)]
    pub(crate) fn from_bytes(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn as_u64_slice(&self) -> &[u64] {
        let ptr = self.bytes.as_ptr();
        let align = ptr.align_offset(std::mem::align_of::<u64>());
        if align != 0 || !self.bytes.len().is_multiple_of(8) {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(ptr as *const u64, self.bytes.len() / 8) }
        }
    }

    pub fn as_u32_slice(&self) -> &[u32] {
        let ptr = self.bytes.as_ptr();
        let align = ptr.align_offset(std::mem::align_of::<u32>());
        if align != 0 || !self.bytes.len().is_multiple_of(4) {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(ptr as *const u32, self.bytes.len() / 4) }
        }
    }

    pub fn as_field_elements(&self) -> &[u64] {
        self.as_u64_slice()
    }

    pub fn as_bn254_scalars(&self) -> &[[u64; 4]] {
        let u64s = self.as_u64_slice();
        if !u64s.len().is_multiple_of(4) {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(u64s.as_ptr() as *const [u64; 4], u64s.len() / 4) }
        }
    }

    pub fn as_bn254_points(&self) -> &[[u64; 8]] {
        let u64s = self.as_u64_slice();
        if !u64s.len().is_multiple_of(8) {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(u64s.as_ptr() as *const [u64; 8], u64s.len() / 8) }
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Mutable typed view over a resident buffer.
pub struct BufferViewMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> BufferViewMut<'a> {
    #[allow(dead_code)]
    pub(crate) fn from_bytes(bytes: &'a mut [u8]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    pub fn as_u64_slice_mut(&mut self) -> &mut [u64] {
        let ptr = self.bytes.as_mut_ptr();
        let len = self.bytes.len();
        let align = ptr.align_offset(std::mem::align_of::<u64>());
        if align != 0 || !len.is_multiple_of(8) {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(ptr as *mut u64, len / 8) }
        }
    }

    pub fn as_u32_slice_mut(&mut self) -> &mut [u32] {
        let ptr = self.bytes.as_mut_ptr();
        let len = self.bytes.len();
        let align = ptr.align_offset(std::mem::align_of::<u32>());
        if align != 0 || !len.is_multiple_of(4) {
            &mut []
        } else {
            unsafe { std::slice::from_raw_parts_mut(ptr as *mut u32, len / 4) }
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// ─── Per-slot metadata ────────────────────────────────────────────────────

#[derive(Debug)]
struct BridgeSlotMeta {
    physical: PhysicalBuffer,
    class: MemoryClass,
    last_writer: Option<NodeId>,
    digest: Option<[u8; 8]>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BufferBridgeStats {
    pub resident_limit_bytes: Option<usize>,
    pub current_resident_bytes: usize,
    pub peak_resident_bytes: usize,
    pub spill_events: usize,
    pub spilled_bytes: usize,
    pub reload_events: usize,
    pub reloaded_bytes: usize,
}

// ─── Buffer Bridge ────────────────────────────────────────────────────────

/// Manages the mapping from logical `BufferHandle.slot` to physical storage.
pub struct BufferBridge {
    slots: SlotMap<u32, BridgeSlotMeta>,
    spill_root: PathBuf,
    #[cfg(feature = "kani-minimal")]
    spill_cache: SlotMap<u32, Vec<u8>>,
    peak_resident_bytes: usize,
    current_resident_bytes: usize,
    resident_limit_bytes: Option<usize>,
    spill_events: usize,
    spilled_bytes: usize,
    reload_events: usize,
    reloaded_bytes: usize,
    gpu_allocator: Option<Box<dyn GpuBufferAllocator>>,
}

#[cfg(not(feature = "kani-minimal"))]
static NEXT_SPILL_SESSION: AtomicU64 = AtomicU64::new(1);

impl BufferBridge {
    #[cfg(not(feature = "kani-minimal"))]
    pub fn new(spill_root: impl Into<PathBuf>) -> Self {
        let spill_root = spill_root.into();
        let _ = create_private_spill_dir(&spill_root);
        Self {
            slots: SlotMap::new(),
            spill_root,
            peak_resident_bytes: 0,
            current_resident_bytes: 0,
            resident_limit_bytes: None,
            spill_events: 0,
            spilled_bytes: 0,
            reload_events: 0,
            reloaded_bytes: 0,
            gpu_allocator: None,
        }
    }

    #[cfg(feature = "kani-minimal")]
    pub fn new(spill_root: impl Into<PathBuf>) -> Self {
        Self {
            slots: SlotMap::new(),
            spill_root: spill_root.into(),
            spill_cache: SlotMap::new(),
            peak_resident_bytes: 0,
            current_resident_bytes: 0,
            resident_limit_bytes: None,
            spill_events: 0,
            spilled_bytes: 0,
            reload_events: 0,
            reloaded_bytes: 0,
            gpu_allocator: None,
        }
    }

    #[cfg(not(feature = "kani-minimal"))]
    pub fn with_temp_spill() -> Self {
        let base_dir = std::env::temp_dir().join("zkf-runtime-spill");
        let _ = create_private_spill_dir(&base_dir);
        cleanup_orphaned_spill_entries(&base_dir);
        let session_dir = base_dir.join(spill_session_name());
        let _ = create_private_spill_dir(&session_dir);
        Self::new(session_dir)
    }

    #[cfg(feature = "kani-minimal")]
    pub fn with_temp_spill() -> Self {
        Self::new(PathBuf::from(".zkf-kani-spill"))
    }

    /// Attach a GPU buffer allocator (provided by zkf-metal).
    pub fn with_gpu_allocator(mut self, allocator: Box<dyn GpuBufferAllocator>) -> Self {
        self.gpu_allocator = Some(allocator);
        self
    }

    /// Set the GPU allocator after construction.
    pub fn set_gpu_allocator(&mut self, allocator: Box<dyn GpuBufferAllocator>) {
        self.gpu_allocator = Some(allocator);
    }

    pub fn set_resident_limit_bytes(&mut self, resident_limit_bytes: Option<usize>) {
        self.resident_limit_bytes = resident_limit_bytes.filter(|value| *value > 0);
    }

    pub fn stats(&self) -> BufferBridgeStats {
        BufferBridgeStats {
            resident_limit_bytes: self.resident_limit_bytes,
            current_resident_bytes: self.current_resident_bytes,
            peak_resident_bytes: self.peak_resident_bytes,
            spill_events: self.spill_events,
            spilled_bytes: self.spilled_bytes,
            reload_events: self.reload_events,
            reloaded_bytes: self.reloaded_bytes,
        }
    }

    pub fn allocate(&mut self, handle: BufferHandle) -> Result<(), RuntimeError> {
        if self.slots.contains_key(&handle.slot) {
            return Ok(());
        }

        self.ensure_capacity_for_resident_bytes(handle.size_bytes, &[])?;

        let physical = self.allocate_physical(handle.size_bytes)?;
        let resident_size = if physical.is_resident() {
            physical.len_bytes()
        } else {
            0
        };

        self.slots.insert(
            handle.slot,
            BridgeSlotMeta {
                physical,
                class: handle.class,
                last_writer: None,
                digest: None,
            },
        );

        self.current_resident_bytes += resident_size;
        if self.current_resident_bytes > self.peak_resident_bytes {
            self.peak_resident_bytes = self.current_resident_bytes;
        }

        Ok(())
    }

    fn allocate_physical(&self, size_bytes: usize) -> Result<PhysicalBuffer, RuntimeError> {
        // Try GPU shared allocation first
        if let Some(ref alloc) = self.gpu_allocator
            && alloc.is_available()
            && let Some((ptr, token)) = alloc.alloc_shared(size_bytes)
        {
            return Ok(PhysicalBuffer::GpuShared {
                ptr,
                len_bytes: size_bytes,
                gpu_token: token,
            });
        }

        // CPU heap allocation
        let bytes = vec![0u8; size_bytes];
        Ok(PhysicalBuffer::CpuOwned { bytes })
    }

    pub fn write_slot(&mut self, slot: u32, data: &[u8]) -> Result<(), RuntimeError> {
        let meta = self
            .slots
            .get_mut(&slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;

        match &mut meta.physical {
            PhysicalBuffer::CpuOwned { bytes } => {
                if data.len() > bytes.len() {
                    *bytes = data.to_vec();
                } else {
                    bytes[..data.len()].copy_from_slice(data);
                }
                Ok(())
            }
            PhysicalBuffer::GpuShared { ptr, len_bytes, .. } => {
                if data.len() > *len_bytes {
                    return Err(RuntimeError::BufferAlignment {
                        slot,
                        required_align: data.len(),
                    });
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), *ptr, data.len());
                }
                Ok(())
            }
            PhysicalBuffer::Spilled { .. } => Err(RuntimeError::BufferNotResident { slot }),
        }
    }

    pub fn view(&self, slot: u32) -> Result<BufferView<'_>, RuntimeError> {
        let meta = self
            .slots
            .get(&slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;

        match &meta.physical {
            PhysicalBuffer::CpuOwned { bytes } => Ok(BufferView { bytes }),
            PhysicalBuffer::GpuShared { ptr, len_bytes, .. } => {
                let bytes = unsafe { std::slice::from_raw_parts(*ptr as *const u8, *len_bytes) };
                Ok(BufferView { bytes })
            }
            PhysicalBuffer::Spilled { .. } => Err(RuntimeError::BufferNotResident { slot }),
        }
    }

    pub fn view_mut(&mut self, slot: u32) -> Result<BufferViewMut<'_>, RuntimeError> {
        let meta = self
            .slots
            .get_mut(&slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?;

        match &mut meta.physical {
            PhysicalBuffer::CpuOwned { bytes } => Ok(BufferViewMut { bytes }),
            PhysicalBuffer::GpuShared { ptr, len_bytes, .. } => {
                let bytes = unsafe { std::slice::from_raw_parts_mut(*ptr, *len_bytes) };
                Ok(BufferViewMut { bytes })
            }
            PhysicalBuffer::Spilled { .. } => Err(RuntimeError::BufferNotResident { slot }),
        }
    }

    pub fn evict_spillable(&mut self, slot: u32) -> Result<(), RuntimeError> {
        let (data, len_bytes, gpu_token) = {
            let meta = self
                .slots
                .get(&slot)
                .ok_or(RuntimeError::BufferNotResident { slot })?;

            if meta.class != MemoryClass::Spillable {
                return Ok(());
            }

            match &meta.physical {
                PhysicalBuffer::CpuOwned { bytes } => (bytes.clone(), bytes.len(), None),
                PhysicalBuffer::GpuShared {
                    ptr,
                    len_bytes,
                    gpu_token,
                } => (
                    unsafe { std::slice::from_raw_parts(*ptr as *const u8, *len_bytes) }.to_vec(),
                    *len_bytes,
                    Some(*gpu_token),
                ),
                PhysicalBuffer::Spilled { .. } => return Ok(()),
            }
        };

        if let Some(gpu_token) = gpu_token
            && let Some(ref alloc) = self.gpu_allocator
        {
            alloc.free_shared(gpu_token);
        }

        self.current_resident_bytes = self.current_resident_bytes.saturating_sub(len_bytes);
        self.spill_events = self.spill_events.saturating_add(1);
        self.spilled_bytes = self.spilled_bytes.saturating_add(len_bytes);

        #[cfg(feature = "kani-minimal")]
        {
            let spill_path = self.spill_root.join(format!("slot_{slot}.spill"));
            self.spill_cache.insert(slot, data);
            let meta = self
                .slots
                .get_mut(&slot)
                .ok_or(RuntimeError::BufferNotResident { slot })?;
            meta.physical = PhysicalBuffer::Spilled {
                path: spill_path,
                len_bytes,
            };
            Ok(())
        }

        #[cfg(not(feature = "kani-minimal"))]
        {
            let spill_path = self.spill_root.join(format!("slot_{slot}.spill"));
            let mut file =
                std::fs::File::create(&spill_path).map_err(|e| RuntimeError::SpillWrite {
                    slot,
                    reason: e.to_string(),
                })?;
            file.write_all(&data)
                .map_err(|e| RuntimeError::SpillWrite {
                    slot,
                    reason: e.to_string(),
                })?;
            file.sync_all().map_err(|e| RuntimeError::SpillWrite {
                slot,
                reason: e.to_string(),
            })?;
            let meta = self
                .slots
                .get_mut(&slot)
                .ok_or(RuntimeError::BufferNotResident { slot })?;
            meta.physical = PhysicalBuffer::Spilled {
                path: spill_path,
                len_bytes,
            };
            Ok(())
        }
    }

    pub fn ensure_resident(&mut self, slot: u32) -> Result<(), RuntimeError> {
        self.ensure_resident_with_exempt(slot, &[slot])
    }

    fn ensure_resident_with_exempt(
        &mut self,
        slot: u32,
        exempt_slots: &[u32],
    ) -> Result<(), RuntimeError> {
        let (path, len_bytes) = match &self
            .slots
            .get(&slot)
            .ok_or(RuntimeError::BufferNotResident { slot })?
            .physical
        {
            PhysicalBuffer::Spilled { path, len_bytes } => (path.clone(), *len_bytes),
            _ => return Ok(()),
        };

        self.ensure_capacity_for_resident_bytes(len_bytes, exempt_slots)?;

        #[cfg(feature = "kani-minimal")]
        {
            let data = self
                .spill_cache
                .remove(&slot)
                .ok_or(RuntimeError::SpillRead {
                    slot,
                    reason: "missing in-memory spill payload".to_string(),
                })?;
            let meta = self
                .slots
                .get_mut(&slot)
                .ok_or(RuntimeError::BufferNotResident { slot })?;
            meta.physical = PhysicalBuffer::CpuOwned { bytes: data };
            self.current_resident_bytes += len_bytes;
            if self.current_resident_bytes > self.peak_resident_bytes {
                self.peak_resident_bytes = self.current_resident_bytes;
            }
            self.reload_events = self.reload_events.saturating_add(1);
            self.reloaded_bytes = self.reloaded_bytes.saturating_add(len_bytes);
            let _ = path;
            Ok(())
        }

        #[cfg(not(feature = "kani-minimal"))]
        {
            let mut file = std::fs::File::open(&path).map_err(|e| RuntimeError::SpillRead {
                slot,
                reason: e.to_string(),
            })?;
            let mut data = Vec::with_capacity(len_bytes);
            file.read_to_end(&mut data)
                .map_err(|e| RuntimeError::SpillRead {
                    slot,
                    reason: e.to_string(),
                })?;

            if let Some(ref alloc) = self.gpu_allocator
                && alloc.is_available()
                && let Some((ptr, token)) = alloc.alloc_shared(data.len())
            {
                let meta = self
                    .slots
                    .get_mut(&slot)
                    .ok_or(RuntimeError::BufferNotResident { slot })?;
                unsafe {
                    std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
                }
                meta.physical = PhysicalBuffer::GpuShared {
                    ptr,
                    len_bytes: data.len(),
                    gpu_token: token,
                };
                self.current_resident_bytes += data.len();
                if self.current_resident_bytes > self.peak_resident_bytes {
                    self.peak_resident_bytes = self.current_resident_bytes;
                }
                self.reload_events = self.reload_events.saturating_add(1);
                self.reloaded_bytes = self.reloaded_bytes.saturating_add(data.len());
                let _ = std::fs::remove_file(&path);
                return Ok(());
            }

            let meta = self
                .slots
                .get_mut(&slot)
                .ok_or(RuntimeError::BufferNotResident { slot })?;
            meta.physical = PhysicalBuffer::CpuOwned { bytes: data };
            self.current_resident_bytes += len_bytes;
            if self.current_resident_bytes > self.peak_resident_bytes {
                self.peak_resident_bytes = self.current_resident_bytes;
            }
            self.reload_events = self.reload_events.saturating_add(1);
            self.reloaded_bytes = self.reloaded_bytes.saturating_add(len_bytes);
            let _ = std::fs::remove_file(&path);
            Ok(())
        }
    }

    pub fn mark_written(&mut self, slot: u32, writer: NodeId) {
        let digest = self.compute_digest_inner(slot);
        if let Some(meta) = self.slots.get_mut(&slot) {
            meta.last_writer = Some(writer);
            meta.digest = digest;
        }
    }

    fn compute_digest_inner(&self, slot: u32) -> Option<[u8; 8]> {
        let meta = self.slots.get(&slot)?;
        let sample: &[u8] = match &meta.physical {
            PhysicalBuffer::CpuOwned { bytes } => {
                let sample_len = bytes.len().min(64);
                &bytes[..sample_len]
            }
            PhysicalBuffer::GpuShared { ptr, len_bytes, .. } => {
                let sample_len = (*len_bytes).min(64);
                unsafe { std::slice::from_raw_parts(*ptr as *const u8, sample_len) }
            }
            PhysicalBuffer::Spilled { .. } => return None,
        };

        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in sample {
            acc ^= b as u64;
            acc = acc.wrapping_mul(0x0000_0100_0000_01b3);
        }
        Some(acc.to_le_bytes())
    }

    pub fn slot_digest(&self, slot: u32) -> Option<[u8; 8]> {
        self.slots.get(&slot).and_then(|m| m.digest)
    }

    pub fn free(&mut self, slot: u32) {
        if let Some(meta) = self.slots.remove(&slot) {
            if meta.physical.is_resident() {
                self.current_resident_bytes = self
                    .current_resident_bytes
                    .saturating_sub(meta.physical.len_bytes());
            }
            if let PhysicalBuffer::GpuShared { gpu_token, .. } = &meta.physical
                && let Some(ref alloc) = self.gpu_allocator
            {
                alloc.free_shared(*gpu_token);
            }
            if let PhysicalBuffer::Spilled { path, .. } = &meta.physical {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    pub fn residency(&self, slot: u32) -> Option<ResidencyClass> {
        self.slots.get(&slot).map(|meta| match &meta.physical {
            PhysicalBuffer::CpuOwned { .. } => ResidencyClass::Cpu,
            PhysicalBuffer::GpuShared { .. } => ResidencyClass::MetalShared,
            PhysicalBuffer::Spilled { .. } => ResidencyClass::Spilled,
        })
    }

    pub fn is_resident(&self, slot: u32) -> bool {
        self.slots
            .get(&slot)
            .map(|m| m.physical.is_resident())
            .unwrap_or(false)
    }

    pub fn peak_resident_bytes(&self) -> usize {
        self.peak_resident_bytes
    }

    pub fn current_resident_bytes(&self) -> usize {
        self.current_resident_bytes
    }

    pub fn allocate_from_pool(
        &mut self,
        _pool: &UnifiedBufferPool,
        handles: &[BufferHandle],
    ) -> Result<(), RuntimeError> {
        for handle in handles {
            self.allocate(*handle)?;
        }
        Ok(())
    }

    pub fn ensure_inputs_resident(&mut self, input_slots: &[u32]) -> Result<(), RuntimeError> {
        for &slot in input_slots {
            if self.slots.contains_key(&slot) {
                self.ensure_resident_with_exempt(slot, input_slots)?;
            }
        }
        Ok(())
    }

    fn ensure_capacity_for_resident_bytes(
        &mut self,
        additional_bytes: usize,
        exempt_slots: &[u32],
    ) -> Result<(), RuntimeError> {
        let Some(limit) = self.resident_limit_bytes else {
            return Ok(());
        };
        if additional_bytes > limit {
            return Err(RuntimeError::Execution(format!(
                "insufficient runtime memory: requested resident allocation of {additional_bytes} bytes exceeds configured resident limit {limit}"
            )));
        }
        while self.current_resident_bytes.saturating_add(additional_bytes) > limit {
            let mut candidates = self
                .slots
                .iter()
                .filter_map(|(slot, meta)| {
                    (meta.class == MemoryClass::Spillable
                        && meta.physical.is_resident()
                        && !exempt_slots.contains(slot))
                    .then_some((*slot, meta.physical.len_bytes()))
                })
                .collect::<Vec<_>>();
            candidates.sort_by(|left, right| right.1.cmp(&left.1));
            let Some((slot, _)) = candidates.first().copied() else {
                return Err(RuntimeError::Execution(format!(
                    "insufficient runtime memory: resident working set {} bytes plus request {additional_bytes} bytes exceeds limit {limit} and no spillable buffers remain",
                    self.current_resident_bytes
                )));
            };
            self.evict_spillable(slot)?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for BufferBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferBridge")
            .field("slot_count", &self.slots.len())
            .field("current_resident_bytes", &self.current_resident_bytes)
            .field("peak_resident_bytes", &self.peak_resident_bytes)
            .field("spill_root", &self.spill_root)
            .field("has_gpu_allocator", &self.gpu_allocator.is_some())
            .finish()
    }
}

impl Drop for BufferBridge {
    fn drop(&mut self) {
        for meta in self.slots.values() {
            if let PhysicalBuffer::Spilled { path, .. } = &meta.physical {
                let _ = std::fs::remove_file(path);
            }
        }
        let _ = std::fs::remove_dir_all(&self.spill_root);
    }
}

#[cfg(not(feature = "kani-minimal"))]
fn spill_session_name() -> String {
    let pid = std::process::id();
    let session = NEXT_SPILL_SESSION.fetch_add(1, Ordering::Relaxed);
    format!("session-{pid}-{session}")
}

#[cfg(not(feature = "kani-minimal"))]
fn cleanup_orphaned_spill_entries(base_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(base_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with(".spill") {
            let _ = std::fs::remove_file(&path);
        }
    }
}

#[cfg(not(feature = "kani-minimal"))]
fn create_private_spill_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    set_private_dir_permissions(path)
}

#[cfg(unix)]
#[cfg(not(feature = "kani-minimal"))]
fn set_private_dir_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
