pub mod client;
pub mod config;
pub mod crypto;
pub mod models;
pub mod pq;
pub mod storage;

use anyhow::Context;
use oqs::{kem, sig};
use sha2::{Digest, Sha256};

use crate::{
    client::IotClient,
    config::ClientConfig,
    pq::DevicePq,
    storage::{save_device_credentials, save_enrollment_response},
};

pub struct RunOutput {
    pub device_id: String,
    pub entropy_len: usize,
    pub entropy_sha256_hex: String,
}

/// End-to-end flow:
/// 1) generate PQ keys
/// 2) enroll device
/// 3) signed entropy request
/// 4) verify server signature
pub async fn run_once(cfg: ClientConfig, device_id: &str) -> anyhow::Result<RunOutput> {
    let kem_alg = kem::Algorithm::Kyber1024;
    let sig_alg = sig::Algorithm::Dilithium5;

    let pq = DevicePq::new(kem_alg, sig_alg).context("DevicePq::new failed")?;
    let credentials_path = save_device_credentials(device_id, &pq)
        .context("failed to save generated device credentials")?;
    println!("Saved device credentials to {}", credentials_path.display());

    let client = IotClient::new(cfg.auth_base.clone());

    let enroll_resp = client.enroll(device_id, &pq).await?;
    println!("Enrolled device {}", &device_id);
    println!("Server KEM alg: {}", enroll_resp.server_kem_alg);
    println!("Server SIG alg: {}", enroll_resp.server_sig_alg);
    save_enrollment_response(device_id, &enroll_resp)
        .context("failed to save enrollment response")?;

    let (_resp, entropy) = client
        .request_entropy(device_id, cfg.n, &pq, &enroll_resp.server_sig_pk_b64)
        .await?;

    let h = Sha256::digest(&entropy);
    Ok(RunOutput {
        device_id: device_id.to_string(),
        entropy_len: entropy.len(),
        entropy_sha256_hex: format!("{:x}", h),
    })
}
