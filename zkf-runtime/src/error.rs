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

//! Runtime error types.

use crate::memory::NodeId;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum RuntimeError {
    #[error("proving graph contains a cycle")]
    CyclicDependency,
    #[error("node {0:?} not found in graph")]
    NodeNotFound(NodeId),
    #[error("buffer pool exhausted (needed {needed_bytes} bytes)")]
    BufferExhausted { needed_bytes: usize },
    #[error("unsupported feature in backend {backend}: {feature}")]
    UnsupportedFeature { backend: String, feature: String },
    #[error("trust lane violation: required {required}, found {found}")]
    TrustLaneViolation { required: String, found: String },
    #[error("unsupported backend: {0}")]
    UnsupportedBackend(String),
    #[error("allocation failure: {0}")]
    Allocation(String),
    #[error("device execution failure: {0}")]
    Device(String),
    #[error("spill failure: {0}")]
    Spill(String),
    #[error("hardware profile mismatch: required {required}, detected {detected}")]
    HardwareProfileMismatch { required: String, detected: String },
    #[error("execution error: {0}")]
    Execution(String),
    #[error("buffer alignment error: slot {slot}, required alignment {required_align}")]
    BufferAlignment { slot: u32, required_align: usize },
    #[error("spill write failed for slot {slot}: {reason}")]
    SpillWrite { slot: u32, reason: String },
    #[error("spill read failed for slot {slot}: {reason}")]
    SpillRead { slot: u32, reason: String },
    #[error("buffer not resident: slot {slot}")]
    BufferNotResident { slot: u32 },
    #[error("unsupported buffer type for node {node}: {reason}")]
    UnsupportedBufferType { node: String, reason: String },
    #[error("missing node payload for node {0:?}")]
    MissingPayload(NodeId),
    #[error("driver dispatch failed for node {node}: {reason}")]
    DriverDispatch { node: String, reason: String },
    #[error("GPU fallback rejected in strict mode for node {node}")]
    GpuFallbackRejected { node: String },
    #[error("witness generation failed: {0}")]
    WitnessGeneration(String),
}
