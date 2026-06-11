use std::time::Duration;

use crate::entropy::EntropyMode;

fn env_any(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| std::env::var(name).ok())
}

pub fn auth_addr() -> String {
    std::env::var("AUTH_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".to_string())
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
    let value = env_any(&["ENTROPY_MODE", "QEaaS_ENTROPY_MODE", "QEAAS_ENTROPY_MODE"])
        .unwrap_or_else(|| "direct_qrng".to_string());
    value.parse()
}

pub fn hybrid_reseed_after_bytes() -> usize {
    env_any(&[
        "HYBRID_RESEED_AFTER_BYTES",
        "QEAAAS_RESEED_BYTES",
        "QEAAS_RESEED_BYTES",
        "QEaaS_RESEED_BYTES",
    ])
    .and_then(|v| v.parse().ok())
    .unwrap_or(1024 * 1024)
}

pub fn hybrid_qrng_seed_size() -> usize {
    env_any(&[
        "HYBRID_QRNG_SEED_SIZE",
        "QEAAAS_QRNG_SEED_SIZE",
        "QEAAS_QRNG_SEED_SIZE",
    ])
    .and_then(|v| v.parse().ok())
    .unwrap_or(32)
}

pub fn hybrid_pool_size() -> anyhow::Result<usize> {
    let value = env_any(&[
        "HYBRID_POOL_SIZE",
        "QEAAAS_HYBRID_POOL_SIZE",
        "QEAAS_HYBRID_POOL_SIZE",
        "QEaaS_HYBRID_POOL_SIZE",
    ])
    .and_then(|v| v.parse().ok())
    .unwrap_or(8);

    if value == 0 {
        anyhow::bail!("HYBRID_POOL_SIZE must be greater than zero");
    }

    Ok(value)
}

pub fn enable_stage_timing() -> bool {
    env_any(&[
        "ENABLE_STAGE_TIMING",
        "QEAAAS_ENABLE_STAGE_TIMING",
        "QEAAS_ENABLE_STAGE_TIMING",
        "QEaaS_ENABLE_STAGE_TIMING",
    ])
    .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
    .unwrap_or(false)
}

pub fn max_entropy_request_bytes() -> usize {
    env_any(&[
        "QEAAAS_MAX_ENTROPY_BYTES",
        "QEAAS_MAX_ENTROPY_BYTES",
        "QEaaS_MAX_ENTROPY_BYTES",
        "MAX_ENTROPY_REQUEST_BYTES",
    ])
    .and_then(|v| v.parse().ok())
    .unwrap_or(1024 * 1024)
}

pub fn http_timeout() -> Duration {
    Duration::from_secs(5)
}
