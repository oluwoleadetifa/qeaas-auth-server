use std::time::Duration;

use crate::entropy::EntropyMode;

pub fn auth_addr() -> String {
    std::env::var("AUTH_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string())
}

pub fn qrng_base_url() -> String {
    std::env::var("QRNG_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string())
}

pub fn nonce_ttl_secs() -> u64 {
    // e.g., 60 seconds replay window
    60
}

pub fn nonce_per_device_cap() -> usize {
    // how many nonces per device to retain (within TTL)
    2048
}

pub fn nonce_cleanup_interval_secs() -> u64 {
    30
}

pub fn entropy_mode() -> anyhow::Result<EntropyMode> {
    let value = std::env::var("ENTROPY_MODE").unwrap_or_else(|_| "direct_qrng".to_string());
    value.parse()
}

pub fn hybrid_reseed_after_bytes() -> usize {
    std::env::var("HYBRID_RESEED_AFTER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024 * 1024)
}

pub fn hybrid_qrng_seed_size() -> usize {
    std::env::var("HYBRID_QRNG_SEED_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(32)
}

pub fn http_timeout() -> Duration {
    Duration::from_secs(5)
}
