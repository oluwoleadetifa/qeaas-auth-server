use anyhow::{anyhow, Context};
use base64::{engine::general_purpose, Engine as _};

use oqs::{
    kem,
    sig,
};

/// Centralizes the PQ algorithms and server keys.
///
/// IMPORTANT:
/// - This struct is meant to live behind an Arc in AppState.
/// - You do NOT need PqContext: Clone; use Arc<PqContext>.
pub struct PqContext {
    pub kem_alg: kem::Algorithm,
    pub sig_alg: sig::Algorithm,

    kem: kem::Kem,
    sig: sig::Sig,

    // Server long-term keys
    kem_pk: kem::PublicKey,
    kem_sk: kem::SecretKey,
    sig_pk: sig::PublicKey,
    sig_sk: sig::SecretKey,
}

impl PqContext {
    pub fn new() -> anyhow::Result<Self> {
        // Must be called once per process before using oqs.
        // Safe to call multiple times, but do it once in main.rs ideally.
        oqs::init();

        // Pick algorithms. (Kyber + Dilithium)
        // NOTE: In newer oqs versions, Kyber may be deprecated in favor of ML-KEM.
        // But on oqs 0.10.1 this should exist if enabled.
        let kem_alg = kem::Algorithm::Kyber1024;
        let sig_alg = sig::Algorithm::Dilithium5;

        let kem = kem::Kem::new(kem_alg).context("failed to create KEM")?;
        let sig = sig::Sig::new(sig_alg).context("failed to create SIG")?;

        let (kem_pk, kem_sk) = kem.keypair().context("kem.keypair failed")?;
        let (sig_pk, sig_sk) = sig.keypair().context("sig.keypair failed")?;

        Ok(Self {
            kem_alg,
            sig_alg,
            kem,
            sig,
            kem_pk,
            kem_sk,
            sig_pk,
            sig_sk,
        })
    }

    pub fn server_kem_pk_b64(&self) -> String {
        general_purpose::STANDARD.encode(self.kem_pk.as_ref())
    }

    pub fn server_sig_pk_b64(&self) -> String {
        general_purpose::STANDARD.encode(self.sig_pk.as_ref())
    }

    /// Sign bytes with server SIG secret key. Returns raw signature bytes.
    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let signature = self.sig.sign(msg, &self.sig_sk).context("sig.sign failed")?;
        Ok(signature.as_ref().to_vec())
    }

    /// Verify signature using a *client* sig pk provided as raw bytes.
    ///
    /// We convert pk bytes -> PublicKeyRef via sig.public_key_from_bytes(...)
    /// and signature bytes -> SignatureRef via sig.signature_from_bytes(...)
    pub fn verify_with_client_pk_bytes(
        &self,
        client_sig_pk_bytes: &[u8],
        msg: &[u8],
        signature_bytes: &[u8],
    ) -> anyhow::Result<bool> {
        let pk_ref = self
            .sig
            .public_key_from_bytes(client_sig_pk_bytes)
            .ok_or_else(|| anyhow!("client sig pk wrong length"))?;

        let sig_ref = self
            .sig
            .signature_from_bytes(signature_bytes)
            .ok_or_else(|| anyhow!("signature wrong length"))?;

        // verify() returns Result<()> on success in oqs. If it errors, it's invalid.
        match self.sig.verify(msg, sig_ref, pk_ref) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Encapsulate to a client's KEM pk bytes.
    /// Returns (ciphertext_bytes, shared_secret_bytes).
    pub fn encapsulate_to_client_kem_pk_bytes(
        &self,
        client_kem_pk_bytes: &[u8],
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let pk_ref = self
            .kem
            .public_key_from_bytes(client_kem_pk_bytes)
            .ok_or_else(|| anyhow!("client kem pk wrong length"))?;

        let (ct, ss) = self.kem.encapsulate(pk_ref).context("kem.encapsulate failed")?;
        Ok((ct.as_ref().to_vec(), ss.as_ref().to_vec()))
    }

    /// Decapsulate ciphertext bytes using server KEM secret key.
    pub fn decapsulate_ct_bytes(&self, ct_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ct_ref = self
            .kem
            .ciphertext_from_bytes(ct_bytes)
            .ok_or_else(|| anyhow!("ciphertext wrong length"))?;

        let ss = self.kem.decapsulate(&self.kem_sk, ct_ref).context("kem.decapsulate failed")?;
        Ok(ss.as_ref().to_vec())
    }
}
