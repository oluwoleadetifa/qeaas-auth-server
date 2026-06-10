use crate::crypto;
use crate::{
    models::{EnrollRequest, EnrollResponse, EntropyRequest, EntropyResponse},
    pq::{build_client_signed_message, DevicePq},
};
use anyhow::Context;
use base64::{engine::general_purpose, Engine as _};
use reqwest::Client;

pub struct IotClient {
    http: Client,
    pub auth_base: String,
}

impl IotClient {
    pub fn new(auth_base: String) -> Self {
        Self {
            http: Client::new(),
            auth_base,
        }
    }

    pub async fn enroll(&self, device_id: &str, pq: &DevicePq) -> anyhow::Result<EnrollResponse> {
        self.enroll_with_public_keys(
            device_id,
            &general_purpose::STANDARD.encode(pq.kem_pk.as_ref()),
            &general_purpose::STANDARD.encode(pq.sig_pk.as_ref()),
        )
        .await
    }

    pub async fn enroll_with_public_keys(
        &self,
        device_id: &str,
        kem_pk_b64: &str,
        sig_pk_b64: &str,
    ) -> anyhow::Result<EnrollResponse> {
        let req = EnrollRequest {
            device_id: device_id.to_string(),
            kem_pk_b64: kem_pk_b64.to_string(),
            sig_pk_b64: sig_pk_b64.to_string(),
        };

        println!(
            "ENTROPY_REQUEST_JSON={}",
            serde_json::to_string(&req).unwrap()
        );

        let url = format!("{}/v1/devices/enroll", self.auth_base);
        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await
            .context("enroll request failed")?
            .error_for_status()
            .context("enroll non-200")?
            .json::<EnrollResponse>()
            .await
            .context("enroll json decode failed")?;

        Ok(resp)
    }

    pub async fn request_entropy(
        &self,
        device_id: &str,
        n: usize,
        pq: &DevicePq,
        server_sig_pk_b64: &str,
    ) -> anyhow::Result<(EntropyResponse, Vec<u8>)> {
        let nonce = pq.make_nonce_32();
        let msg = build_client_signed_message(device_id, n, &nonce);
        let client_sig = pq.sign(&msg)?;

        let req = EntropyRequest {
            device_id: device_id.to_string(),
            n,
            nonce_b64: general_purpose::STANDARD.encode(&nonce),
            signature_b64: general_purpose::STANDARD.encode(&client_sig),
        };

        println!(
            "ENTROPY_REQUEST_JSON={}",
            serde_json::to_string(&req).unwrap()
        );

        let url = format!("{}/v1/entropy", self.auth_base);
        let resp = self
            .http
            .post(&url)
            .json(&req)
            .send()
            .await
            .context("entropy request failed")?
            .error_for_status()
            .context("entropy non-200")?
            .json::<EntropyResponse>()
            .await
            .context("entropy json decode failed")?;

        // Decode response parts
        if resp.nonce_b64 != req.nonce_b64 {
            anyhow::bail!("server nonce mismatch (possible replay/mixup)");
        }
        if resp.device_id != device_id || resp.n != n {
            anyhow::bail!("response parameters mismatch (device_id/n)");
        }

        let ct = general_purpose::STANDARD
            .decode(&resp.kem_ct_b64)
            .context("bad kem_ct_b64")?;
        let aead_nonce_vec = general_purpose::STANDARD
            .decode(&resp.aead_nonce_b64)
            .context("bad aead_nonce_b64")?;
        let entropy_ct = general_purpose::STANDARD
            .decode(&resp.entropy_ct_b64)
            .context("bad entropy_ct_b64")?;
        let server_sig = general_purpose::STANDARD
            .decode(&resp.server_signature_b64)
            .context("bad server_signature_b64")?;

        if aead_nonce_vec.len() != 12 {
            anyhow::bail!("aead nonce must be 12 bytes");
        }
        let mut aead_nonce12 = [0u8; 12];
        aead_nonce12.copy_from_slice(&aead_nonce_vec);

        // decapsulate to get ss
        let ss_client = pq.decapsulate(&ct)?;

        // derive AEAD key
        let key32 = crypto::derive_aead_key(&ss_client, &nonce)?;

        // build same AAD as server
        let mut aad = Vec::new();
        aad.extend_from_slice(device_id.as_bytes());
        aad.push(0);
        aad.extend_from_slice(&(n as u64).to_le_bytes());
        aad.push(0);
        aad.extend_from_slice(&nonce);
        aad.push(0);
        aad.extend_from_slice(&ct);

        // decrypt entropy
        let entropy = crypto::aead_decrypt(&key32, &aead_nonce12, &aad, &entropy_ct)?;

        // verify server signature over response transcript (ciphertext)
        let server_sig_pk_bytes = general_purpose::STANDARD
            .decode(server_sig_pk_b64)
            .context("bad server_sig_pk_b64")?;
        let tbs =
            crate::pq::build_server_tbs(device_id, n, &nonce, &ct, &aead_nonce12, &entropy_ct);
        pq.verify_server_signature(&server_sig_pk_bytes, &tbs, &server_sig)?;

        Ok((resp, entropy))
    }
}
