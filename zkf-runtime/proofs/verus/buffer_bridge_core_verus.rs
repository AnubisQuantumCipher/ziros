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

use vstd::prelude::*;
use vstd::seq::*;

verus! {

pub open spec fn max_core_slots() -> nat {
    16
}

pub open spec fn max_slot_bytes() -> int {
    256
}

pub struct SlotModel {
    pub occupied: bool,
    pub slot_id: int,
    pub len: int,
    pub spillable: bool,
    pub resident: bool,
    pub payload_tag: int,
}

pub struct BufferBridgeCoreModel {
    pub slots: Seq<SlotModel>,
    pub slot_count: int,
    pub current_resident_bytes: int,
    pub peak_resident_bytes: int,
}

pub open spec fn empty_slot() -> SlotModel {
    SlotModel {
        occupied: false,
        slot_id: 0,
        len: 0,
        spillable: true,
        resident: false,
        payload_tag: 0,
    }
}

pub open spec fn slot_valid(slot: SlotModel) -> bool {
    &&& slot.len <= max_slot_bytes()
    &&& slot.len >= 0
    &&& slot.slot_id >= 0
    &&& slot.payload_tag >= 0
    &&& (!slot.occupied ==> !slot.resident && slot.len == 0)
}

pub open spec fn slot_id_present(state: BufferBridgeCoreModel, slot_id: int) -> bool {
    exists|i: int|
        0 <= i < state.slots.len() && state.slots[i].occupied && state.slots[i].slot_id == slot_id
}

pub open spec fn slot_index_for_id(state: BufferBridgeCoreModel, slot_id: int) -> int
    recommends slot_id_present(state, slot_id)
{
    choose|i: int|
        0 <= i < state.slots.len() && state.slots[i].occupied && state.slots[i].slot_id == slot_id
}

pub open spec fn slot_for_id(state: BufferBridgeCoreModel, slot_id: int) -> SlotModel
    recommends slot_id_present(state, slot_id)
{
    state.slots[slot_index_for_id(state, slot_id)]
}

pub open spec fn can_view_by_id(state: BufferBridgeCoreModel, slot_id: int) -> bool {
    slot_id_present(state, slot_id) && slot_for_id(state, slot_id).resident
}

pub open spec fn can_write_by_id(
    state: BufferBridgeCoreModel,
    slot_id: int,
    requested_len: int,
) -> bool {
    requested_len >= 0 && requested_len <= max_slot_bytes() && can_view_by_id(state, slot_id)
}

pub open spec fn state_valid(state: BufferBridgeCoreModel) -> bool {
    &&& state.slots.len() == max_core_slots()
    &&& forall|i: int| 0 <= i < state.slots.len() ==> slot_valid(state.slots[i])
    &&& forall|i: int, j: int|
        0 <= i < state.slots.len() && 0 <= j < state.slots.len()
        && i != j
        && state.slots[i].occupied
        && state.slots[j].occupied
            ==> state.slots[i].slot_id != state.slots[j].slot_id
    &&& state.slot_count >= 0
    &&& state.current_resident_bytes >= 0
    &&& state.peak_resident_bytes >= 0
    &&& state.peak_resident_bytes >= state.current_resident_bytes
}

pub open spec fn empty_index(state: BufferBridgeCoreModel, idx: int) -> bool {
    0 <= idx < state.slots.len() && !state.slots[idx].occupied
}

pub open spec fn replace_slot(
    slots: Seq<SlotModel>,
    idx: int,
    new_slot: SlotModel,
) -> Seq<SlotModel>
    recommends 0 <= idx < slots.len()
{
    Seq::new(slots.len(), |i: int| if i == idx { new_slot } else { slots[i] })
}

pub open spec fn max_int(left: int, right: int) -> int {
    if left <= right {
        right
    } else {
        left
    }
}

pub open spec fn allocate_at(
    state: BufferBridgeCoreModel,
    idx: int,
    slot_id: int,
    size_bytes: int,
    spillable: bool,
) -> BufferBridgeCoreModel
    recommends state_valid(state), empty_index(state, idx), slot_id >= 0, size_bytes >= 0, size_bytes <= max_slot_bytes()
{
    let new_slot = SlotModel {
        occupied: true,
        slot_id,
        len: size_bytes,
        spillable,
        resident: true,
        payload_tag: 0,
    };
    let new_current = state.current_resident_bytes + size_bytes;
    BufferBridgeCoreModel {
        slots: replace_slot(state.slots, idx, new_slot),
        slot_count: state.slot_count + 1,
        current_resident_bytes: new_current,
        peak_resident_bytes: max_int(state.peak_resident_bytes, new_current),
    }
}

pub open spec fn write_at(
    state: BufferBridgeCoreModel,
    idx: int,
    requested_len: int,
    payload_tag: int,
) -> BufferBridgeCoreModel
    recommends state_valid(state), 0 <= idx < state.slots.len(), state.slots[idx].occupied, state.slots[idx].resident, requested_len >= 0, requested_len <= max_slot_bytes(), payload_tag >= 0
{
    let old_slot = state.slots[idx];
    let new_slot = SlotModel {
        occupied: true,
        slot_id: old_slot.slot_id,
        len: requested_len,
        spillable: old_slot.spillable,
        resident: true,
        payload_tag,
    };
    let growth = if requested_len <= old_slot.len {
        0
    } else {
        requested_len - old_slot.len
    };
    let new_current = state.current_resident_bytes + growth;
    BufferBridgeCoreModel {
        slots: replace_slot(state.slots, idx, new_slot),
        slot_count: state.slot_count,
        current_resident_bytes: new_current,
        peak_resident_bytes: max_int(state.peak_resident_bytes, new_current),
    }
}

pub open spec fn write_at_id(
    state: BufferBridgeCoreModel,
    slot_id: int,
    requested_len: int,
    payload_tag: int,
) -> BufferBridgeCoreModel
    recommends can_write_by_id(state, slot_id, requested_len)
{
    write_at(state, slot_index_for_id(state, slot_id), requested_len, payload_tag)
}

pub open spec fn evict_at(
    state: BufferBridgeCoreModel,
    idx: int,
) -> BufferBridgeCoreModel
    recommends state_valid(state), 0 <= idx < state.slots.len(), state.slots[idx].occupied, state.slots[idx].resident, state.slots[idx].spillable, state.current_resident_bytes >= state.slots[idx].len
{
    let old_slot = state.slots[idx];
    let new_slot = SlotModel {
        occupied: true,
        slot_id: old_slot.slot_id,
        len: old_slot.len,
        spillable: old_slot.spillable,
        resident: false,
        payload_tag: old_slot.payload_tag,
    };
    BufferBridgeCoreModel {
        slots: replace_slot(state.slots, idx, new_slot),
        slot_count: state.slot_count,
        current_resident_bytes: state.current_resident_bytes - old_slot.len,
        peak_resident_bytes: state.peak_resident_bytes,
    }
}

pub open spec fn ensure_resident_at(
    state: BufferBridgeCoreModel,
    idx: int,
) -> BufferBridgeCoreModel
    recommends state_valid(state), 0 <= idx < state.slots.len(), state.slots[idx].occupied, !state.slots[idx].resident
{
    let old_slot = state.slots[idx];
    let new_slot = SlotModel {
        occupied: true,
        slot_id: old_slot.slot_id,
        len: old_slot.len,
        spillable: old_slot.spillable,
        resident: true,
        payload_tag: old_slot.payload_tag,
    };
    let new_current = state.current_resident_bytes + old_slot.len;
    BufferBridgeCoreModel {
        slots: replace_slot(state.slots, idx, new_slot),
        slot_count: state.slot_count,
        current_resident_bytes: new_current,
        peak_resident_bytes: max_int(state.peak_resident_bytes, new_current),
    }
}

pub open spec fn free_at(
    state: BufferBridgeCoreModel,
    idx: int,
) -> BufferBridgeCoreModel
    recommends state_valid(state), 0 <= idx < state.slots.len(), state.slots[idx].occupied, state.slot_count > 0, state.current_resident_bytes >= if state.slots[idx].resident { state.slots[idx].len } else { 0 }
{
    let removed = state.slots[idx];
    let resident_drop = if removed.resident { removed.len } else { 0 };
    BufferBridgeCoreModel {
        slots: replace_slot(state.slots, idx, empty_slot()),
        slot_count: state.slot_count - 1,
        current_resident_bytes: state.current_resident_bytes - resident_drop,
        peak_resident_bytes: state.peak_resident_bytes,
    }
}

pub open spec fn free_at_id(
    state: BufferBridgeCoreModel,
    slot_id: int,
) -> BufferBridgeCoreModel
    recommends slot_id_present(state, slot_id), state_valid(state), state.slot_count > 0, state.current_resident_bytes >= if slot_for_id(state, slot_id).resident { slot_for_id(state, slot_id).len } else { 0 }
{
    free_at(state, slot_index_for_id(state, slot_id))
}

pub open spec fn typed_u64_lane_count(len: int, aligned: bool) -> int {
    if aligned && len % 8 == 0 {
        len / 8
    } else {
        0
    }
}

pub open spec fn typed_u32_lane_count(len: int, aligned: bool) -> int {
    if aligned && len % 4 == 0 {
        len / 4
    } else {
        0
    }
}

pub proof fn empty_state_is_valid()
    ensures state_valid(BufferBridgeCoreModel {
        slots: Seq::new(max_core_slots(), |i: int| empty_slot()),
        slot_count: 0,
        current_resident_bytes: 0,
        peak_resident_bytes: 0,
    })
{
}

pub proof fn buffer_read_write_layout_validity_ok(
    state: BufferBridgeCoreModel,
    idx: int,
    fresh_slot_id: int,
    missing_slot_id: int,
    requested_len: int,
    payload_tag: int,
)
    requires
        state_valid(state),
        empty_index(state, idx),
        fresh_slot_id >= 0,
        missing_slot_id >= 0,
        payload_tag >= 0,
        requested_len >= 0,
        requested_len <= max_slot_bytes(),
        fresh_slot_id != missing_slot_id,
        !slot_id_present(state, fresh_slot_id),
        !slot_id_present(state, missing_slot_id),
    ensures
        state_valid(allocate_at(state, idx, fresh_slot_id, requested_len, true)),
        state_valid(write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag)),
        write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag).slots[idx].occupied,
        write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag).slots[idx].slot_id == fresh_slot_id,
        write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag).slots[idx].resident,
        write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag).slots[idx].len == requested_len,
        write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag).slots[idx].payload_tag == payload_tag,
        !slot_id_present(write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag), missing_slot_id),
{
}

pub proof fn buffer_typed_view_surface_ok(
    state: BufferBridgeCoreModel,
    idx: int,
    fresh_slot_id: int,
    requested_len: int,
    payload_tag: int,
    u64_aligned: bool,
    u32_aligned: bool,
)
    requires
        state_valid(state),
        empty_index(state, idx),
        fresh_slot_id >= 0,
        payload_tag >= 0,
        requested_len >= 0,
        requested_len <= max_slot_bytes(),
        !slot_id_present(state, fresh_slot_id),
    ensures
        typed_u64_lane_count(
            write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag).slots[idx].len,
            u64_aligned,
        ) == if u64_aligned && requested_len % 8 == 0 { requested_len / 8 } else { 0 },
        typed_u32_lane_count(
            write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag).slots[idx].len,
            u32_aligned,
        ) == if u32_aligned && requested_len % 4 == 0 { requested_len / 4 } else { 0 },
        write_at(allocate_at(state, idx, fresh_slot_id, requested_len, true), idx, requested_len, payload_tag).slots[idx].payload_tag == payload_tag,
{
}

pub proof fn buffer_residency_transition_sound_ok(
    state: BufferBridgeCoreModel,
    idx: int,
)
    requires
        state_valid(state),
        0 <= idx < state.slots.len(),
        state.slots[idx].occupied,
        state.slots[idx].spillable,
        state.slots[idx].resident,
        state.current_resident_bytes >= state.slots[idx].len,
    ensures
        state_valid(evict_at(state, idx)),
        !evict_at(state, idx).slots[idx].resident,
        evict_at(state, idx).slots[idx].payload_tag == state.slots[idx].payload_tag,
        evict_at(state, idx).current_resident_bytes + state.slots[idx].len == state.current_resident_bytes,
        state_valid(ensure_resident_at(evict_at(state, idx), idx)),
        ensure_resident_at(evict_at(state, idx), idx).slots[idx].resident,
        ensure_resident_at(evict_at(state, idx), idx).slots[idx].payload_tag == state.slots[idx].payload_tag,
{
}

pub proof fn buffer_spill_reload_roundtrip_surface_ok(
    state: BufferBridgeCoreModel,
    idx: int,
)
    requires
        state_valid(state),
        0 <= idx < state.slots.len(),
        state.slots[idx].occupied,
        state.slots[idx].spillable,
        state.slots[idx].resident,
        state.current_resident_bytes >= state.slots[idx].len,
    ensures
        state_valid(ensure_resident_at(evict_at(state, idx), idx)),
        ensure_resident_at(evict_at(state, idx), idx).slots[idx].slot_id == state.slots[idx].slot_id,
        ensure_resident_at(evict_at(state, idx), idx).slots[idx].len == state.slots[idx].len,
        ensure_resident_at(evict_at(state, idx), idx).slots[idx].payload_tag == state.slots[idx].payload_tag,
        ensure_resident_at(evict_at(state, idx), idx).slots[idx].resident,
{
}

pub proof fn buffer_alias_separation_sound_ok(
    state: BufferBridgeCoreModel,
    left_idx: int,
    right_idx: int,
    new_len: int,
    new_payload_tag: int,
)
    requires
        state_valid(state),
        0 <= left_idx < state.slots.len(),
        0 <= right_idx < state.slots.len(),
        left_idx != right_idx,
        new_len >= 0,
        new_payload_tag >= 0,
        state.slots[left_idx].occupied,
        state.slots[right_idx].occupied,
        state.slots[left_idx].resident,
        state.slots[right_idx].resident,
        new_len <= max_slot_bytes(),
        state.slot_count > 0,
        state.current_resident_bytes >= if write_at(state, left_idx, new_len, new_payload_tag).slots[left_idx].resident { write_at(state, left_idx, new_len, new_payload_tag).slots[left_idx].len } else { 0 },
    ensures
        state_valid(write_at(state, left_idx, new_len, new_payload_tag)),
        write_at(state, left_idx, new_len, new_payload_tag).slots[right_idx].payload_tag == state.slots[right_idx].payload_tag,
        write_at(state, left_idx, new_len, new_payload_tag).slots[right_idx].len == state.slots[right_idx].len,
        state_valid(free_at(write_at(state, left_idx, new_len, new_payload_tag), left_idx)),
        !free_at(write_at(state, left_idx, new_len, new_payload_tag), left_idx).slots[left_idx].occupied,
        !free_at(write_at(state, left_idx, new_len, new_payload_tag), left_idx).slots[left_idx].resident,
        free_at(write_at(state, left_idx, new_len, new_payload_tag), left_idx).slots[right_idx].resident,
        free_at(write_at(state, left_idx, new_len, new_payload_tag), left_idx).slots[right_idx].payload_tag == state.slots[right_idx].payload_tag,
{
}

} // verus!
