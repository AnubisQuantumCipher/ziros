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
        assert!(!context_has_security_signal(&RuntimeSecurityContext::default()));
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
