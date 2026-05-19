use anyhow::{anyhow, Context};
use oqs::{kem, sig};
use sha2::{Digest, Sha256};

pub struct DevicePq {
    pub kem_alg: kem::Algorithm,
    pub sig_alg: sig::Algorithm,

    pub kem_obj: kem::Kem,
    pub sig_obj: sig::Sig,

    pub kem_pk: kem::PublicKey,
    pub kem_sk: kem::SecretKey,

    pub sig_pk: sig::PublicKey,
    pub sig_sk: sig::SecretKey,
    sig_sk_override: Option<Vec<u8>>,
}

impl DevicePq {
    pub fn new(kem_alg: kem::Algorithm, sig_alg: sig::Algorithm) -> anyhow::Result<Self> {
        oqs::init();

        let kem_obj = kem::Kem::new(kem_alg).context("Kem::new failed")?;
        let (kem_pk, kem_sk) = kem_obj.keypair().context("kem keypair failed")?;

        let sig_obj = sig::Sig::new(sig_alg).context("Sig::new failed")?;
        let (sig_pk, sig_sk) = sig_obj.keypair().context("sig keypair failed")?;

        Ok(Self {
            kem_alg,
            sig_alg,
            kem_obj,
            sig_obj,
            kem_pk,
            kem_sk,
            sig_pk,
            sig_sk,
            sig_sk_override: None,
        })
    }

    /// Deterministic test nonce: hash(pk || pk || time_nanos) -> 32 bytes
    pub fn make_nonce_32(&self) -> Vec<u8> {
        let mut nonce = Vec::new();
        nonce.extend_from_slice(self.sig_pk.as_ref());
        nonce.extend_from_slice(self.kem_pk.as_ref());
        nonce.extend_from_slice(
            &(std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos())
            .to_le_bytes(),
        );

        Sha256::digest(&nonce).to_vec()
    }

    pub fn sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let s = match &self.sig_sk_override {
            Some(sig_sk) => {
                let sig_sk_ref = self
                    .sig_obj
                    .secret_key_from_bytes(sig_sk)
                    .ok_or_else(|| anyhow!("client sig sk wrong length"))?;
                self.sig_obj.sign(msg, sig_sk_ref)
            }
            None => self.sig_obj.sign(msg, &self.sig_sk),
        }
        .context("client sign failed")?;
        Ok(s.as_ref().to_vec())
    }

    pub fn sig_sk_bytes(&self) -> anyhow::Result<Vec<u8>> {
        Ok(self.sig_sk.as_ref().to_vec())
    }

    pub fn set_sig_sk(&mut self, sig_sk: Vec<u8>) -> anyhow::Result<()> {
        self.sig_obj
            .secret_key_from_bytes(&sig_sk)
            .ok_or_else(|| anyhow!("client sig sk wrong length"))?;
        self.sig_sk_override = Some(sig_sk);
        Ok(())
    }

    pub fn decapsulate(&self, ct_bytes: &[u8]) -> anyhow::Result<Vec<u8>> {
        let ct_ref = self
            .kem_obj
            .ciphertext_from_bytes(ct_bytes)
            .ok_or_else(|| anyhow!("ciphertext wrong length"))?;

        let ss = self
            .kem_obj
            .decapsulate(&self.kem_sk, ct_ref)
            .context("client decapsulate failed")?;

        Ok(ss.as_ref().to_vec())
    }

    pub fn verify_server_signature(
        &self,
        server_sig_pk_bytes: &[u8],
        tbs: &[u8],
        server_sig_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let verifier = sig::Sig::new(self.sig_alg).context("Sig::new(server) failed")?;

        let pk_ref = verifier
            .public_key_from_bytes(server_sig_pk_bytes)
            .ok_or_else(|| anyhow!("server sig pk wrong length"))?;

        let sig_ref = verifier
            .signature_from_bytes(server_sig_bytes)
            .ok_or_else(|| anyhow!("server signature wrong length"))?;

        verifier
            .verify(tbs, sig_ref, pk_ref)
            .context("server signature verify FAILED")?;
        Ok(())
    }
}

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

/// Transcript that server signs (must match server code):
/// device_id || 0x00 || n(u64 LE) || 0x00 || nonce || 0x00 || ct || 0x00 || entropy
pub fn build_server_tbs(
    device_id: &str,
    n: usize,
    nonce: &[u8],
    ct: &[u8],
    aead_nonce12: &[u8; 12],
    entropy_ct: &[u8],
) -> Vec<u8> {
    let mut tbs = Vec::new();
    tbs.extend_from_slice(device_id.as_bytes());
    tbs.push(0);
    tbs.extend_from_slice(&(n as u64).to_le_bytes());
    tbs.push(0);
    tbs.extend_from_slice(nonce);
    tbs.push(0);
    tbs.extend_from_slice(ct);
    tbs.push(0);
    tbs.extend_from_slice(aead_nonce12);
    tbs.push(0);
    tbs.extend_from_slice(entropy_ct);
    tbs
}
