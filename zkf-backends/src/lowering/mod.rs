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

pub mod arkworks_lowering;
pub mod halo2_lowering;
pub mod midnight_lowering;
pub mod nova_lowering;
pub mod plonky3_lowering;
pub mod sp1_lowering;

use zkf_core::zir;
use zkf_core::{BackendKind, ZkfResult};

/// Backend-specific lowering pass: transforms a ZIR program into an optimized
/// form tailored for a particular proof system. Each backend implements this to
/// exploit features like lookup tables, custom gates, and memory operations.
pub trait ZirLowering {
    /// The backend-specific intermediate representation produced by lowering.
    type LoweredIr;

    /// Which backend this lowering targets.
    fn backend(&self) -> BackendKind;

    /// Transform a ZIR program into a backend-optimized intermediate form.
    fn lower(&self, program: &zir::Program) -> ZkfResult<Self::LoweredIr>;
}
