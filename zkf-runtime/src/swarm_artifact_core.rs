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

use zkf_core::artifact::ProofArtifact;

pub(crate) fn preserve_successful_proof_artifact(artifact: ProofArtifact) -> ProofArtifact {
    artifact
}

pub(crate) fn preserve_successful_artifact<T>(artifact: T) -> T {
    artifact
}

#[allow(dead_code)]
pub(crate) fn controller_artifact_path<T>(
    enabled: bool,
    artifact: T,
    reject: bool,
) -> Result<T, ()> {
    if enabled && reject {
        Err(())
    } else {
        Ok(artifact)
    }
}

#[cfg(test)]
mod tests {
    use super::controller_artifact_path;

    #[test]
    fn accepted_artifacts_pass_through_unchanged() {
        assert_eq!(
            controller_artifact_path(true, [1u8, 2, 3, 4], false),
            Ok([1u8, 2, 3, 4])
        );
    }

    #[test]
    fn rejected_enabled_artifacts_fail_closed() {
        assert_eq!(
            controller_artifact_path(true, [1u8, 2, 3, 4], true),
            Err(())
        );
        assert_eq!(
            controller_artifact_path(false, [1u8, 2, 3, 4], true),
            Ok([1u8, 2, 3, 4])
        );
    }
}
