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

pub mod aerospace;
pub mod aerospace_qualification;
pub mod api;
#[cfg(feature = "full")]
pub mod audit;
pub mod builder;
pub mod combustion;
pub mod descent;
pub mod edl_monte_carlo;
#[cfg(not(target_arch = "wasm32"))]
pub mod evidence;
pub mod falcon_heavy_certification;
pub mod inputs;
pub mod mission_ops;
pub mod multi_satellite;
pub mod navier_stokes;
pub mod orbital;
pub mod private_identity;
pub mod progress;
pub mod real_gas;
pub mod reentry;
pub mod reentry_ops;
pub mod satellite;
pub mod science;
pub mod sovereign_economic_defense;
pub mod spec;
pub mod subsystem;
pub mod subsystem_support;
pub mod templates;
pub mod thermochemical;
#[cfg(not(target_arch = "wasm32"))]
pub mod verifier;
