use crate::config;
use thiserror::Error;
use rand::rngs::OsRng;
use rand::RngCore;

const MAX_ENTROPY_BYTES: usize = 64;

#[derive(Error, Debug)]
pub enum EntropyError {
    #[error("QRNG request failed")]
    QrngFailed,
}

#[derive(Clone)]
pub enum EntropyBackend {
    Mock,
    Qrng,
}

impl EntropyBackend {
    pub async fn get_entropy(&self, bytes: usize) -> Result<Vec<u8>, EntropyError> {
        let bounded = bytes.min(MAX_ENTROPY_BYTES);

        match self {
            EntropyBackend::Mock => {
                let mut buf = vec![0u8; bounded];
                OsRng.fill_bytes(&mut buf);
                Ok(buf)
            }

            EntropyBackend::Qrng => {
                let url = format!("{}/random/{}", config::qrng_url(), bounded);

                let res = reqwest::get(url)
                    .await
                    .map_err(|_| EntropyError::QrngFailed)?
                    .error_for_status()
                    .map_err(|_| EntropyError::QrngFailed)?;

                let data = res
                    .json::<Vec<u8>>()
                    .await
                    .map_err(|_| EntropyError::QrngFailed)?;

                Ok(data)
            }
        }
    }
}