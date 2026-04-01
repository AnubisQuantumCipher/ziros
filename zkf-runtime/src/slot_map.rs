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

#[cfg(not(feature = "kani-minimal"))]
pub(crate) type SlotMap<K, V> = std::collections::HashMap<K, V>;

#[cfg(feature = "kani-minimal")]
#[derive(Debug, Default)]
pub(crate) struct SlotMap<K, V> {
    entries: Vec<(K, V)>,
}

#[cfg(feature = "kani-minimal")]
impl<K: PartialEq + Copy, V> SlotMap<K, V> {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn contains_key(&self, key: &K) -> bool {
        self.entries.iter().any(|(candidate, _)| candidate == key)
    }

    pub(crate) fn get(&self, key: &K) -> Option<&V> {
        self.entries
            .iter()
            .find_map(|(candidate, value)| (candidate == key).then_some(value))
    }

    pub(crate) fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.entries
            .iter_mut()
            .find_map(|(candidate, value)| (*candidate == *key).then_some(value))
    }

    pub(crate) fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Some((_, existing)) = self
            .entries
            .iter_mut()
            .find(|(candidate, _)| *candidate == key)
        {
            return Some(std::mem::replace(existing, value));
        }
        self.entries.push((key, value));
        None
    }

    pub(crate) fn remove(&mut self, key: &K) -> Option<V> {
        let index = self
            .entries
            .iter()
            .position(|(candidate, _)| candidate == key)?;
        Some(self.entries.swap_remove(index).1)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&K, &V)> + '_ {
        self.entries.iter().map(|(key, value)| (key, value))
    }

    pub(crate) fn values(&self) -> impl Iterator<Item = &V> + '_ {
        self.entries.iter().map(|(_, value)| value)
    }
}
