// benchmark_client/src/message.rs
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rand::RngCore;

use crate::models::{EntropyRequest, SigningContext};

/// Canonical message client signs:
/// msg = device_id || 0x00 || n(u64 LE) || 0x00 || nonce
pub fn build_client_signed_message(device_id: &str, n: usize, nonce: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(device_id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(&(n as u64).to_le_bytes());
    msg.push(0);
    msg.extend_from_slice(nonce);
    msg
}

pub fn build_signed_request(signing_ctx: &SigningContext, n: u32) -> Result<EntropyRequest> {
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    let nonce_b64 = STANDARD.encode(nonce);
    let signature_b64 = sign_request(signing_ctx, n, &nonce)?;

    Ok(EntropyRequest {
        device_id: signing_ctx.device_id.clone(),
        n,
        nonce_b64,
        signature_b64,
    })
}

pub fn sign_request(signing_ctx: &SigningContext, n: u32, nonce: &[u8]) -> Result<String> {
    let msg = build_client_signed_message(&signing_ctx.device_id, n as usize, nonce);

    let sig = signing_ctx
        .pq
        .sign(&msg)
        .context("failed to sign entropy request")?;

    Ok(STANDARD.encode(sig))
}

#[cfg(test)]
mod tests {
    use super::build_client_signed_message;

    #[test]
    fn canonical_message_matches_qeaas_format() {
        let nonce = [0xabu8; 32];
        let msg = build_client_signed_message("device-1", 1024, &nonce);

        let mut expected = Vec::new();
        expected.extend_from_slice(b"device-1");
        expected.push(0);
        expected.extend_from_slice(&(1024u64).to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&nonce);

        assert_eq!(msg, expected);
    }
}
