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

#![allow(dead_code)]

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum SpecNoirRecheckStatus {
    Accepted,
    Rejected,
}

#[cfg_attr(hax, hax_lib::include)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct SpecNoirRecheckBoundary {
    pub(crate) translated_constraints_valid: bool,
    pub(crate) acvm_witness_present: bool,
}

#[cfg_attr(hax, hax_lib::include)]
pub(crate) fn noir_acir_recheck_wrapper_surface(
    boundary: SpecNoirRecheckBoundary,
) -> SpecNoirRecheckStatus {
    if boundary.translated_constraints_valid && boundary.acvm_witness_present {
        SpecNoirRecheckStatus::Accepted
    } else {
        SpecNoirRecheckStatus::Rejected
    }
}
