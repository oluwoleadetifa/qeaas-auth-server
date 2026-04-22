// benchmark_client/src/enroll.rs
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use oqs::{kem, sig};


use crate::models::StoredUser;
use crate::storage::append_user;

use client_iot::{
    client::IotClient,
    config::ClientConfig,
    pq::DevicePq,
};

pub async fn enroll_many(base_url: &str, count: usize, out_file: &str) -> Result<()> {
    for i in 0..count {
        let device_id = format!("iot-device-{i:04}");

        let stored = enroll_one(base_url, &device_id)
            .await
            .with_context(|| format!("failed to enroll device {device_id}"))?;

        append_user(out_file, &stored)
            .with_context(|| format!("failed to persist device {device_id}"))?;

        println!("enrolled {}", stored.device_id);
    }

    Ok(())
}

async fn enroll_one(base_url: &str, device_id: &str) -> anyhow::Result<StoredUser> {
    // 1. Create PQ device (YOU MUST PICK ALGORITHMS)
    let pq = DevicePq::new(
        kem::Algorithm::Kyber1024,
        sig::Algorithm::Dilithium5,
    )?;

    // 2. Create client (only needs base URL)
    let client = IotClient::new(base_url.to_string());

    // 3. Call enroll
    // (adjust this if your actual method name differs)
    let resp = client
        .enroll(device_id, &pq)
        .await
        .context("enrollment failed")?;

    // 4. Save credentials
    let user = StoredUser {
        device_id: device_id.to_string(),
        kem_pk_b64: resp.kem_pk_b64,
        sig_pk_b64: resp.sig_pk_b64,

        // THIS is critical — extract secret key from pq
        sig_sk_b64: base64::encode(pq.sig_sk_bytes()?),
    };

    Ok(user)
}

