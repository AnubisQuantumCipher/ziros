use axum::http::{HeaderMap, StatusCode};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::types::ApiTier;

/// Extract API key from `Authorization: Bearer <key>` header.
pub fn extract_api_key_from_headers(headers: &HeaderMap) -> Option<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
}

pub fn generate_api_key() -> String {
    format!("zkf_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

pub fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn api_key_prefix(api_key: &str) -> String {
    api_key.chars().take(12).collect()
}

/// Build a stable rate-limit identity from authenticated API key hash or client IP hints.
pub fn rate_limit_key(headers: &HeaderMap, api_key_hash: Option<&str>) -> String {
    if let Some(api_key_hash) = api_key_hash
        && !api_key_hash.is_empty()
    {
        return format!("api-key:{api_key_hash}");
    }

    for header in ["x-forwarded-for", "x-real-ip"] {
        if let Some(value) = headers.get(header).and_then(|value| value.to_str().ok()) {
            let candidate = value.split(',').next().unwrap_or("").trim();
            if !candidate.is_empty() {
                return format!("ip:{candidate}");
            }
        }
    }

    "anonymous".to_string()
}

/// Validate API key and return its stable hash plus tier.
pub fn validate_key(
    db: &crate::db::Database,
    api_key: Option<&str>,
) -> Result<(String, ApiTier), StatusCode> {
    match api_key {
        Some(key) if !key.is_empty() => {
            let tier = db.get_tier(key).map_err(|_| StatusCode::UNAUTHORIZED)?;
            Ok((hash_api_key(key), tier))
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
