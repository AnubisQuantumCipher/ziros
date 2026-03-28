use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::db::Database;
use crate::types::ApiTier;

const DEFAULT_REQUESTS_PER_MINUTE: u32 = 100;
const DEFAULT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, BucketState>>,
    capacity: f64,
    refill_per_second: f64,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_RATE_LIMIT_WINDOW)
    }

    pub fn with_capacity(capacity: u32, window: Duration) -> Self {
        let capacity = capacity.max(1) as f64;
        let window_seconds = window.as_secs_f64().max(0.001);
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity,
            refill_per_second: capacity / window_seconds,
        }
    }

    pub fn check(&self, key: &str) -> Result<(), String> {
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .map_err(|err| format!("rate limiter lock: {err}"))?;
        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| BucketState {
                tokens: self.capacity,
                last_refill: now,
            });

        let elapsed = now
            .saturating_duration_since(bucket.last_refill)
            .as_secs_f64();
        if elapsed > 0.0 {
            bucket.tokens = (bucket.tokens + elapsed * self.refill_per_second).min(self.capacity);
            bucket.last_refill = now;
        }

        if bucket.tokens < 1.0 {
            return Err(format!(
                "rate limit exceeded (max {} requests/minute)",
                self.capacity as u32
            ));
        }

        bucket.tokens -= 1.0;
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if the API key has remaining quota for the given operation kind.
pub fn check_quota(db: &Database, api_key: &str, tier: ApiTier, kind: &str) -> Result<(), String> {
    let usage = db.get_usage(api_key)?;

    match kind {
        "prove" => {
            if usage.proofs >= tier.proofs_per_month() {
                return Err(format!(
                    "monthly proof quota exceeded ({}/{})",
                    usage.proofs,
                    tier.proofs_per_month()
                ));
            }
        }
        "wrap" => {
            if usage.wraps >= tier.wraps_per_month() {
                return Err(format!(
                    "monthly wrap quota exceeded ({}/{})",
                    usage.wraps,
                    tier.wraps_per_month()
                ));
            }
            if !tier.gpu_enabled() {
                return Err("wrapping requires Developer tier or above".to_string());
            }
        }
        "deploy" => {
            if usage.deploys >= tier.deploys_per_month() {
                return Err(format!(
                    "monthly deploy quota exceeded ({}/{})",
                    usage.deploys,
                    tier.deploys_per_month()
                ));
            }
            if !tier.gpu_enabled() {
                return Err("Solidity generation requires Developer tier or above".to_string());
            }
        }
        "benchmark" => {
            if usage.benchmarks >= tier.benchmarks_per_month() {
                return Err(format!(
                    "monthly benchmark quota exceeded ({}/{})",
                    usage.benchmarks,
                    tier.benchmarks_per_month()
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

/// Check if the API key can start another concurrent job.
pub fn check_concurrency(db: &Database, api_key: &str, tier: ApiTier) -> Result<(), String> {
    let running = db.count_running_jobs(api_key)?;
    let limit = tier.concurrent_jobs();
    if running >= limit {
        return Err(format!(
            "concurrent job limit reached ({}/{})",
            running, limit
        ));
    }
    Ok(())
}

pub fn check_rate_limit(rate_limiter: &RateLimiter, key: &str) -> Result<(), String> {
    rate_limiter.check(key)
}

/// Record usage after a successful operation.
pub fn record_usage(db: &Database, api_key: &str, kind: &str) -> Result<(), String> {
    db.increment_usage(api_key, kind)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn token_bucket_blocks_after_capacity_is_spent() {
        let limiter = RateLimiter::with_capacity(2, Duration::from_secs(60));
        assert!(limiter.check("test-client").is_ok());
        assert!(limiter.check("test-client").is_ok());
        assert!(limiter.check("test-client").is_err());
    }

    #[test]
    fn token_bucket_refills_over_time() {
        let limiter = RateLimiter::with_capacity(1, Duration::from_millis(20));
        assert!(limiter.check("test-client").is_ok());
        assert!(limiter.check("test-client").is_err());
        thread::sleep(Duration::from_millis(25));
        assert!(limiter.check("test-client").is_ok());
    }
}
