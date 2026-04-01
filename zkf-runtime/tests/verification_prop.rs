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

use proptest::prelude::*;
use zkf_runtime::{BufferBridge, BufferHandle, MemoryClass};

fn allocate_slot(
    bridge: &mut BufferBridge,
    slot: u32,
    size_bytes: usize,
    class: MemoryClass,
) -> BufferHandle {
    let handle = BufferHandle {
        slot,
        size_bytes,
        class,
    };
    bridge.allocate(handle).expect("allocate slot");
    handle
}

proptest! {
    #[test]
    fn aligned_u64_typed_views_roundtrip(words in prop::collection::vec(any::<u64>(), 1..5)) {
        let mut bridge = BufferBridge::with_temp_spill();
        let handle = allocate_slot(&mut bridge, 1, words.len() * 8, MemoryClass::EphemeralScratch);
        bridge
            .write_slot(handle.slot, &vec![0u8; words.len() * 8])
            .expect("seed aligned bytes");

        {
            let mut view = bridge.view_mut(handle.slot).expect("mutable aligned view");
            let typed = view.as_u64_slice_mut();
            prop_assert_eq!(typed.len(), words.len());
            typed.copy_from_slice(&words);
        }

        let view = bridge.view(handle.slot).expect("immutable aligned view");
        prop_assert_eq!(view.as_u64_slice(), words.as_slice());
        prop_assert_eq!(view.as_u32_slice().len(), words.len() * 2);
    }

    #[test]
    fn misaligned_u64_views_are_empty(
        payload in prop::collection::vec(any::<u8>(), 1..33)
            .prop_filter("length must not be u64-aligned", |bytes| !bytes.len().is_multiple_of(8))
    ) {
        let mut bridge = BufferBridge::with_temp_spill();
        let handle = allocate_slot(&mut bridge, 2, payload.len(), MemoryClass::EphemeralScratch);
        bridge.write_slot(handle.slot, &payload).expect("write payload");

        let view = bridge.view(handle.slot).expect("misaligned immutable view");
        prop_assert!(view.as_u64_slice().is_empty());
    }

    #[test]
    fn misaligned_u32_views_are_empty(
        payload in prop::collection::vec(any::<u8>(), 1..33)
            .prop_filter("length must not be u32-aligned", |bytes| !bytes.len().is_multiple_of(4))
    ) {
        let mut bridge = BufferBridge::with_temp_spill();
        let handle = allocate_slot(&mut bridge, 3, payload.len(), MemoryClass::EphemeralScratch);
        bridge.write_slot(handle.slot, &payload).expect("write payload");

        let view = bridge.view(handle.slot).expect("misaligned immutable view");
        prop_assert!(view.as_u32_slice().is_empty());
    }

    #[test]
    fn spill_and_reload_roundtrips_small_payloads(payload in prop::collection::vec(any::<u8>(), 0..64)) {
        let mut bridge = BufferBridge::with_temp_spill();
        let handle = allocate_slot(&mut bridge, 4, payload.len(), MemoryClass::Spillable);
        bridge.write_slot(handle.slot, &payload).expect("write spillable payload");

        bridge.evict_spillable(handle.slot).expect("evict spillable");
        prop_assert!(!bridge.is_resident(handle.slot));

        bridge.ensure_resident(handle.slot).expect("reload spillable");
        prop_assert!(bridge.is_resident(handle.slot));

        let view = bridge.view(handle.slot).expect("reloaded view");
        prop_assert_eq!(view.as_bytes(), payload.as_slice());
    }
}
