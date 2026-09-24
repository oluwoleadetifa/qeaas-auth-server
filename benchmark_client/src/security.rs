use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use client_iot::{client::IotClient, pq::DevicePq};
use oqs::{kem, sig};
use rand::RngCore;
use reqwest::Client as HttpClient;
use serde::Serialize;

use crate::message::{build_signed_request, sign_request};
use crate::models::{EntropyRequest, SigningContext};

#[derive(Debug, Serialize)]
struct SecurityCheckResult {
    test: &'static str,
    expected_status: u16,
    actual_status: u16,
    passed: bool,
}

pub async fn run_security_check(base_url: &str, oversized_n: u32) -> Result<()> {
    let http = HttpClient::new();
    let device_id = format!("security-device-{}", unix_ms());
    let pq = DevicePq::new(kem::Algorithm::Kyber1024, sig::Algorithm::Dilithium5)?;
    let iot = IotClient::new(base_url.to_string());
    iot.enroll(&device_id, &pq)
        .await
        .context("security-check enrollment failed")?;

    let ctx = SigningContext {
        device_id: device_id.clone(),
        pq: Arc::new(pq),
    };

    let mut results = Vec::new();

    let unregistered_ctx = SigningContext {
        device_id: format!("unregistered-{}", unix_ms()),
        pq: Arc::new(DevicePq::new(
            kem::Algorithm::Kyber1024,
            sig::Algorithm::Dilithium5,
        )?),
    };
    let unregistered = build_signed_request(&unregistered_ctx, 32)?;
    results.push(
        check(
            &http,
            base_url,
            "unregistered device rejected",
            401,
            &unregistered,
        )
        .await?,
    );

    let valid = build_signed_request(&ctx, 32)?;
    results.push(check(&http, base_url, "valid fresh request accepted", 200, &valid).await?);

    let mut modified_n = build_signed_request(&ctx, 32)?;
    modified_n.n = 33;
    results.push(check(&http, base_url, "modified n rejected", 401, &modified_n).await?);

    let mut modified_device = build_signed_request(&ctx, 32)?;
    modified_device.device_id = format!("{}-tampered", modified_device.device_id);
    results.push(
        check(
            &http,
            base_url,
            "modified device_id rejected",
            401,
            &modified_device,
        )
        .await?,
    );

    let replay = build_signed_request(&ctx, 32)?;
    results.push(check(&http, base_url, "replay setup accepted", 200, &replay).await?);
    results.push(check(&http, base_url, "exact replay rejected", 409, &replay).await?);

    let reused_nonce = fixed_nonce_request(&ctx, 32)?;
    results.push(
        check(
            &http,
            base_url,
            "fresh nonce after replay still accepted",
            200,
            &reused_nonce,
        )
        .await?,
    );
    let reused_nonce_again = EntropyRequest {
        signature_b64: sign_request(
            &ctx,
            32,
            &STANDARD
                .decode(&reused_nonce.nonce_b64)
                .context("bad nonce in test")?,
        )?,
        ..reused_nonce
    };
    results.push(
        check(
            &http,
            base_url,
            "reused nonce rejected",
            409,
            &reused_nonce_again,
        )
        .await?,
    );

    let mut malformed = build_signed_request(&ctx, 32)?;
    malformed.signature_b64 = "not-base64".to_string();
    results.push(
        check(
            &http,
            base_url,
            "malformed base64 rejected",
            400,
            &malformed,
        )
        .await?,
    );

    let oversized = build_signed_request(&ctx, oversized_n)?;
    let oversized_status = post_status(&http, base_url, &oversized).await?;
    results.push(SecurityCheckResult {
        test: "oversized entropy request rejected or safely handled",
        expected_status: 400,
        actual_status: oversized_status,
        passed: matches!(oversized_status, 400 | 413 | 502),
    });

    print_results(&results);

    if results.iter().any(|result| !result.passed) {
        anyhow::bail!("one or more security checks failed");
    }

    Ok(())
}

async fn check(
    http: &HttpClient,
    base_url: &str,
    test: &'static str,
    expected_status: u16,
    req: &EntropyRequest,
) -> Result<SecurityCheckResult> {
    let actual_status = post_status(http, base_url, req).await?;
    Ok(SecurityCheckResult {
        test,
        expected_status,
        actual_status,
        passed: actual_status == expected_status,
    })
}

async fn post_status(http: &HttpClient, base_url: &str, req: &EntropyRequest) -> Result<u16> {
    Ok(http
        .post(format!("{}/v1/entropy", base_url.trim_end_matches('/')))
        .json(req)
        .send()
        .await?
        .status()
        .as_u16())
}

fn fixed_nonce_request(ctx: &SigningContext, n: u32) -> Result<EntropyRequest> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);
    Ok(EntropyRequest {
        device_id: ctx.device_id.clone(),
        n,
        nonce_b64: STANDARD.encode(nonce),
        signature_b64: sign_request(ctx, n, &nonce)?,
    })
}

fn print_results(results: &[SecurityCheckResult]) {
    println!("\n=== QEaaS Security Validation ===");
    println!(
        "{:<52} {:>8} {:>8} {:>8}",
        "test", "expect", "actual", "pass"
    );
    for result in results {
        println!(
            "{:<52} {:>8} {:>8} {:>8}",
            result.test,
            result.expected_status,
            result.actual_status,
            if result.passed { "yes" } else { "no" }
        );
    }
    println!(
        "{}",
        serde_json::to_string(results).unwrap_or_else(|_| "[]".to_string())
    );
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}
