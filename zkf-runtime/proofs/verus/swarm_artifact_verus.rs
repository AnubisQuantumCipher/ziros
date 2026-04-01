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

pub open spec fn controller_artifact_path(enabled: bool, reject: bool) -> Option<bool> {
    if enabled && reject {
        None
    } else {
        Some(true)
    }
}

pub proof fn swarm_artifact_non_mutation_surface(enabled: bool)
    ensures
        controller_artifact_path(enabled, false) == Some(true),
        controller_artifact_path(false, true) == Some(true),
        controller_artifact_path(true, true).is_None(),
{
}

} // verus!
