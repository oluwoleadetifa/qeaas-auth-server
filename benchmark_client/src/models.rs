use serde::{Deserialize, Serialize};
use std::sync::Arc;

use client_iot::client::IotClient;

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

#[derive(Debug, Deserialize)]
pub struct EntropyResponse {
    pub length: Option<usize>,
    pub data_hex: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BenchmarkConfig {
    pub base_url: String,
    pub n: u32,
    pub concurrency: usize,
    pub duration_secs: u64,
    pub users_file: String,
}

#[derive(Debug, Clone)]
pub struct DeviceContext {
    pub device_id: String,
    pub sig_sk_b64: String,
}

#[derive(Clone)]
pub struct SigningContext {
    pub device_id: String,
    pub pq: DevicePq,
}
