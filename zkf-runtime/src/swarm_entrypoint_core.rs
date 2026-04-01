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

use crate::security::RuntimeSecurityContext;

pub(crate) fn context_has_security_signal(context: &RuntimeSecurityContext) -> bool {
    context.rate_limit_violation_count > 0
        || context.auth_failure_count > 0
        || context.malformed_request_count > 0
        || context.backend_incompatibility_attempt_count > 0
        || context.anonymous_burst
        || context.telemetry_replay_detected
        || context.integrity_mismatch_detected
}

pub(crate) fn sanitize_file_component(value: &str) -> String {
    let mut sanitized = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            sanitized.push(ch.to_ascii_lowercase());
        } else if !sanitized.ends_with('-') {
            sanitized.push('-');
        }
    }
    sanitized.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::{context_has_security_signal, sanitize_file_component};
    use crate::security::RuntimeSecurityContext;

    #[test]
    fn detects_security_context_activity() {
        assert!(!context_has_security_signal(
            &RuntimeSecurityContext::default()
        ));
        assert!(context_has_security_signal(&RuntimeSecurityContext {
            malformed_request_count: 1,
            ..RuntimeSecurityContext::default()
        }));
    }

    #[test]
    fn sanitizes_names_for_filesystem_use() {
        assert_eq!(sanitize_file_component("GET /health"), "get-health");
        assert_eq!(sanitize_file_component(" prove:v1 "), "prove-v1");
    }
}
