use serde::{Deserialize, Serialize};
use std::sync::Arc;

use client_iot::pq::DevicePq;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub device_id: String,
    pub kem_pk_b64: String,
    pub sig_pk_b64: String,
    pub sig_sk_b64: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyRequest {
    pub device_id: String,
    pub n: u32,
    pub nonce_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub base_url: String,
    pub entropy_mode: String,
    pub n: u32,
    pub concurrency: usize,
    pub duration_secs: u64,
    pub users_file: String,
    pub label: String,
    pub csv_out: Option<String>,
    pub jsonl_out: Option<String>,
    pub md_out: Option<String>,
}

#[derive(Clone)]
pub struct SigningContext {
    pub device_id: String,
    pub pq: Arc<DevicePq>,
}
