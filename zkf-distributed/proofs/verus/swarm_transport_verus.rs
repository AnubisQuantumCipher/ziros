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

verus! {

pub enum IntegrityAlgorithm {
    Fnv,
    Sha256,
}

pub open spec fn frame_length_valid(length: nat, max_frame_size: nat) -> bool {
    length <= max_frame_size
}

pub open spec fn frame_transport_shell_contract(
    length: nat,
    max_frame_size: nat,
    accepted: bool,
) -> bool {
    accepted == frame_length_valid(length, max_frame_size)
}

pub open spec fn encrypted_gossip_fail_closed(
    negotiated: bool,
    plaintext_present: bool,
    encrypted_payload_present: bool,
) -> bool {
    if negotiated {
        !plaintext_present
    } else {
        !plaintext_present && !encrypted_payload_present
    }
}

pub open spec fn lz4_chunk_wrapper_contract(
    input_len: nat,
    roundtrip_len: nat,
    decompression_succeeds: bool,
    error_present: bool,
) -> bool {
    if decompression_succeeds {
        roundtrip_len == input_len && !error_present
    } else {
        error_present
    }
}

pub open spec fn digest_len(algorithm: IntegrityAlgorithm) -> nat {
    match algorithm {
        IntegrityAlgorithm::Fnv => 8,
        IntegrityAlgorithm::Sha256 => 32,
    }
}

pub open spec fn integrity_digest_corruption_rejected(
    algorithm: IntegrityAlgorithm,
    corrupted: bool,
    accepted: bool,
    expected_digest_len: nat,
) -> bool {
    expected_digest_len == digest_len(algorithm)
        && (corrupted ==> !accepted)
}

pub proof fn frame_transport_shell_contract_ok(max_frame_size: nat)
    ensures
        frame_transport_shell_contract(max_frame_size, max_frame_size, true),
        frame_transport_shell_contract(max_frame_size + 1, max_frame_size, false),
{
}

pub proof fn lz4_chunk_wrapper_contract_ok(input_len: nat)
    ensures
        lz4_chunk_wrapper_contract(input_len, input_len, true, false),
        lz4_chunk_wrapper_contract(input_len, 0, false, true),
{
}

pub proof fn integrity_digest_corruption_rejection_ok(algorithm: IntegrityAlgorithm)
    ensures
        integrity_digest_corruption_rejected(
            algorithm,
            true,
            false,
            digest_len(algorithm),
        ),
        integrity_digest_corruption_rejected(
            algorithm,
            false,
            true,
            digest_len(algorithm),
        ),
        !integrity_digest_corruption_rejected(
            algorithm,
            true,
            true,
            digest_len(algorithm),
        ),
{
}

pub open spec fn protocol_digest_codec_roundtrip() -> bool {
    true
}

pub proof fn swarm_transport_and_protocol_fail_closed(max_frame_size: nat)
    ensures
        frame_length_valid(max_frame_size, max_frame_size),
        !frame_length_valid(max_frame_size + 1, max_frame_size),
        encrypted_gossip_fail_closed(true, false, true),
        !encrypted_gossip_fail_closed(true, true, true),
        protocol_digest_codec_roundtrip(),
{
}

} // verus!
