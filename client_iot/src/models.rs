use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct EnrollRequest {
    pub device_id: String,
    pub kem_pk_b64: String,
    pub sig_pk_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct EnrollResponse {
    pub server_kem_alg: String,
    pub server_sig_alg: String,
    pub server_kem_pk_b64: String,
    pub server_sig_pk_b64: String,
}

#[derive(Debug, Serialize)]
pub struct EntropyRequest {
    pub device_id: String,
    pub n: usize,
    pub nonce_b64: String,
    pub signature_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct EntropyResponse {
    pub device_id: String,
    pub n: usize,
    pub nonce_b64: String,

    pub kem_ct_b64: String,
    pub aead_nonce_b64: String,
    pub entropy_ct_b64: String,

    pub server_signature_b64: String,
}

