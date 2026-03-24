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