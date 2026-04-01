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

pub mod blake3;
pub mod boolean;
pub mod comparison;
pub mod ecdsa;
pub mod gadget;
pub mod kzg;
pub mod merkle;
pub mod nonnative;
pub mod plonk_gate;
pub mod poseidon;
pub mod range;
pub mod registry;
pub mod schnorr;
pub mod secp256k1;
pub mod sha256;

pub use gadget::{
    BUILTIN_GADGET_NAMES, Gadget, GadgetEmission, GadgetRegistry, builtin_supported_field_names,
    builtin_supported_fields, validate_builtin_field_support,
};
pub use registry::{AuditStatus as GadgetAuditStatus, GadgetSpec, all_gadget_specs, gadget_spec};
