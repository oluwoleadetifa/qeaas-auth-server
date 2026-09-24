use anyhow::anyhow;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

pub fn derive_aead_key(ss: &[u8], salt_nonce32: &[u8]) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<sha2::Sha256>::new(Some(salt_nonce32), ss);
    let mut okm = [0u8; 32];

    hk.expand(b"qeaas entropy v1", &mut okm)
        .map_err(|_e| anyhow!("hkdf expand failed"))?;

    Ok(okm)
}

pub fn derive_aead_nonce12(client_nonce32: &[u8]) -> [u8; 12] {
    let mut h = Sha256::new();
    h.update(b"qeaas-aead-nonce");
    h.update(client_nonce32);
    let out = h.finalize();
    let mut nonce12 = [0u8; 12];
    nonce12.copy_from_slice(&out[..12]);
    nonce12
}

pub fn aead_encrypt(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key32));
    let nonce = Nonce::from_slice(nonce12);

    let ct = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_e| anyhow!("aead encrypt failed"))?;

    Ok(ct)
}
