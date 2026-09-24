use anyhow::anyhow;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

pub fn derive_aead_key(ss: &[u8], salt_nonce32: &[u8]) -> anyhow::Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt_nonce32), ss);
    let mut okm = [0u8; 32];

    hk.expand(b"qeaas entropy v1", &mut okm)
        .map_err(|_| anyhow!("hkdf expand failed"))?;

    Ok(okm)
}

pub fn aead_decrypt(
    key32: &[u8; 32],
    nonce12: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key32));
    let nonce = Nonce::from_slice(nonce12);

    let pt = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| anyhow!("aead decrypt failed"))?;

    Ok(pt)
}
