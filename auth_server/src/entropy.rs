use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct QrngResponse {
    pub length: usize,
    pub data_hex: String,
}

pub async fn fetch_entropy_bytes(
    http: &reqwest::Client,
    base_url: &str,
    n: usize,
) -> Result<Vec<u8>, EntropyError> {
    let url = format!("{}/random/{}", base_url.trim_end_matches('/'), n);

    let resp = http.get(url).send().await.map_err(EntropyError::Http)?;
    if !resp.status().is_success() {
        return Err(EntropyError::BadStatus(resp.status().as_u16()));
    }

    let body: QrngResponse = resp.json().await.map_err(EntropyError::BadJson)?;

    let bytes = hex::decode(&body.data_hex).map_err(EntropyError::BadHex)?;
    if bytes.len() != n {
        // Your QRNG server might return fewer bytes if it’s returning hex length incorrectly.
        // We keep this strict for now so you catch bugs early.
        return Err(EntropyError::LengthMismatch { expected: n, got: bytes.len() });
    }

    Ok(bytes)
}

#[derive(thiserror::Error, Debug)]
pub enum EntropyError {
    #[error("http error: {0}")]
    Http(reqwest::Error),
    #[error("qrng returned non-200 status: {0}")]
    BadStatus(u16),
    #[error("failed to parse qrng json: {0}")]
    BadJson(reqwest::Error),
    #[error("invalid hex in qrng response: {0}")]
    BadHex(hex::FromHexError),
    #[error("length mismatch expected={expected} got={got}")]
    LengthMismatch { expected: usize, got: usize },
}