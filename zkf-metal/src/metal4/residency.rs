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

//! Host-gated residency budgeting for large Metal allocations.

use objc2::rc::Retained;
use objc2::runtime::ProtocolObject;
use objc2_metal::MTLBuffer;
use std::collections::BTreeMap;

/// Configuration for residency management.
#[derive(Debug, Clone, Copy)]
pub struct ResidencyConfig {
    /// Maximum resident memory budget in bytes.
    pub max_resident_bytes: u64,
    /// Whether new buffers are marked resident immediately.
    pub lazy_residency: bool,
}

impl Default for ResidencyConfig {
    fn default() -> Self {
        let resources = zkf_core::SystemResources::detect();
        let total = resources.total_ram_bytes.max(1);
        let available = resources.available_ram_bytes.min(total);
        let os_headroom = if resources.unified_memory {
            (total / 5).max(8 * 1024 * 1024 * 1024)
        } else {
            (total.saturating_mul(15) / 100).max(4 * 1024 * 1024 * 1024)
        };
        let execution_budget = available
            .saturating_sub(os_headroom)
            .min(total.saturating_mul(70) / 100)
            .max(1024 * 1024 * 1024);
        Self {
            max_resident_bytes: execution_budget
                .saturating_mul(40)
                .saturating_div(100)
                .min(12 * 1024 * 1024 * 1024)
                .max(64 * 1024 * 1024),
            lazy_residency: true,
        }
    }
}

#[derive(Clone)]
struct ResidencyEntry {
    buffer: Retained<ProtocolObject<dyn MTLBuffer>>,
    bytes: u64,
    resident: bool,
    generation: u64,
}

/// Tracks a working set of Metal buffers and keeps the resident subset within budget.
pub struct ResidencySet {
    config: ResidencyConfig,
    entries: BTreeMap<String, ResidencyEntry>,
    generation: u64,
}

impl ResidencySet {
    pub fn new(config: ResidencyConfig) -> Self {
        Self {
            config,
            entries: BTreeMap::new(),
            generation: 0,
        }
    }

    pub fn config(&self) -> ResidencyConfig {
        self.config
    }

    pub fn tracked_bytes(&self) -> u64 {
        self.entries.values().map(|entry| entry.bytes).sum()
    }

    pub fn resident_bytes(&self) -> u64 {
        self.entries
            .values()
            .filter(|entry| entry.resident)
            .map(|entry| entry.bytes)
            .sum()
    }

    pub fn contains(&self, label: &str) -> bool {
        self.entries.contains_key(label)
    }

    pub fn labels(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }

    pub fn add_buffer(
        &mut self,
        label: impl Into<String>,
        buffer: Retained<ProtocolObject<dyn MTLBuffer>>,
    ) -> Result<(), String> {
        let label = label.into();
        let resident = !self.config.lazy_residency;
        self.generation = self.generation.saturating_add(1);
        self.entries.insert(
            label,
            ResidencyEntry {
                bytes: buffer.length() as u64,
                buffer,
                resident,
                generation: self.generation,
            },
        );
        self.enforce_budget();
        Ok(())
    }

    pub fn make_resident(&mut self, label: &str) -> Result<(), String> {
        let entry = self
            .entries
            .get_mut(label)
            .ok_or_else(|| format!("unknown residency buffer '{label}'"))?;
        self.generation = self.generation.saturating_add(1);
        entry.resident = true;
        entry.generation = self.generation;
        self.enforce_budget();
        Ok(())
    }

    pub fn evict(&mut self, label: &str) -> bool {
        if let Some(entry) = self.entries.get_mut(label) {
            entry.resident = false;
            return true;
        }
        false
    }

    pub fn remove(&mut self, label: &str) -> bool {
        self.entries.remove(label).is_some()
    }

    pub fn resident_handles(&self) -> Vec<Retained<ProtocolObject<dyn MTLBuffer>>> {
        self.entries
            .values()
            .filter(|entry| entry.resident)
            .map(|entry| entry.buffer.clone())
            .collect()
    }

    fn enforce_budget(&mut self) {
        while self.resident_bytes() > self.config.max_resident_bytes {
            let Some(label) = self
                .entries
                .iter()
                .filter(|(_, entry)| entry.resident)
                .min_by_key(|(_, entry)| entry.generation)
                .map(|(label, _)| label.clone())
            else {
                break;
            };
            if let Some(entry) = self.entries.get_mut(&label) {
                entry.resident = false;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn residency_config_defaults_to_positive_budget() {
        let config = ResidencyConfig::default();
        assert!(config.max_resident_bytes > 0);
    }
}
