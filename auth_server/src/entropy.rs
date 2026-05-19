use std::{str::FromStr, sync::Arc};

use anyhow::anyhow;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;
use sha2::Digest;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyMode {
    DirectQrng,
    HybridCsprng,
}

impl EntropyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectQrng => "direct_qrng",
            Self::HybridCsprng => "hybrid_csprng",
        }
    }
}

impl FromStr for EntropyMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct_qrng" => Ok(Self::DirectQrng),
            "hybrid_csprng" => Ok(Self::HybridCsprng),
            other => Err(anyhow!(
                "invalid ENTROPY_MODE={other}; expected direct_qrng or hybrid_csprng"
            )),
        }
    }
}

#[derive(Clone)]
pub struct EntropySource {
    inner: Arc<EntropySourceInner>,
}

enum EntropySourceInner {
    DirectQrng {
        http: reqwest::Client,
        base_url: String,
    },
    HybridCsprng {
        http: reqwest::Client,
        base_url: String,
        seed_size: usize,
        reseed_after_bytes: usize,
        state: Mutex<HybridState>,
    },
}

struct HybridState {
    rng: ChaCha20Rng,
    reseed_count: u64,
    bytes_served_since_reseed: usize,
    reseed_failures: u64,
}

#[derive(Debug, Clone)]
pub struct EntropyStats {
    pub entropy_mode: &'static str,
    pub reseed_count: u64,
    pub bytes_served_since_reseed: usize,
    pub reseed_failures: u64,
    pub qrng_seed_size: usize,
}

impl EntropySource {
    pub async fn direct_qrng(http: reqwest::Client, base_url: String) -> Self {
        tracing::info!(
            entropy_mode = EntropyMode::DirectQrng.as_str(),
            qrng_seed_size = 0usize,
            "entropy source initialized"
        );

        Self {
            inner: Arc::new(EntropySourceInner::DirectQrng { http, base_url }),
        }
    }

    pub async fn hybrid_csprng(
        http: reqwest::Client,
        base_url: String,
        seed_size: usize,
        reseed_after_bytes: usize,
    ) -> Result<Self, EntropyError> {
        let seed = fetch_qrng_seed(&http, &base_url, seed_size).await?;
        let rng = rng_from_seed(&seed);

        tracing::info!(
            entropy_mode = EntropyMode::HybridCsprng.as_str(),
            qrng_seed_size = seed_size,
            reseed_after_bytes,
            "entropy source initialized"
        );

        Ok(Self {
            inner: Arc::new(EntropySourceInner::HybridCsprng {
                http,
                base_url,
                seed_size,
                reseed_after_bytes,
                state: Mutex::new(HybridState {
                    rng,
                    reseed_count: 0,
                    bytes_served_since_reseed: 0,
                    reseed_failures: 0,
                }),
            }),
        })
    }

    pub async fn bytes(&self, n: usize) -> Result<Vec<u8>, EntropyError> {
        match self.inner.as_ref() {
            EntropySourceInner::DirectQrng { http, base_url } => {
                fetch_entropy_bytes(http, base_url, n).await
            }
            EntropySourceInner::HybridCsprng {
                http,
                base_url,
                seed_size,
                reseed_after_bytes,
                state,
            } => {
                let should_reseed = {
                    let guard = state.lock().await;
                    guard.bytes_served_since_reseed >= *reseed_after_bytes
                };

                if should_reseed {
                    let seed = match fetch_qrng_seed(http, base_url, *seed_size).await {
                        Ok(seed) => seed,
                        Err(err) => {
                            let mut guard = state.lock().await;
                            guard.reseed_failures += 1;
                            tracing::error!(
                                entropy_mode = EntropyMode::HybridCsprng.as_str(),
                                reseed_failures = guard.reseed_failures,
                                qrng_seed_size = *seed_size,
                                error = %err,
                                "hybrid CSPRNG reseed failed"
                            );
                            return Err(err);
                        }
                    };

                    let mut guard = state.lock().await;
                    guard.rng = rng_from_seed(&seed);
                    guard.reseed_count += 1;
                    guard.bytes_served_since_reseed = 0;
                    tracing::info!(
                        entropy_mode = EntropyMode::HybridCsprng.as_str(),
                        reseed_count = guard.reseed_count,
                        bytes_served_since_reseed = guard.bytes_served_since_reseed,
                        qrng_seed_size = *seed_size,
                        "hybrid CSPRNG reseeded"
                    );
                }

                let mut guard = state.lock().await;
                let mut out = vec![0u8; n];
                guard.rng.fill_bytes(&mut out);
                guard.bytes_served_since_reseed += n;
                Ok(out)
            }
        }
    }

    pub async fn stats(&self) -> EntropyStats {
        match self.inner.as_ref() {
            EntropySourceInner::DirectQrng { .. } => EntropyStats {
                entropy_mode: EntropyMode::DirectQrng.as_str(),
                reseed_count: 0,
                bytes_served_since_reseed: 0,
                reseed_failures: 0,
                qrng_seed_size: 0,
            },
            EntropySourceInner::HybridCsprng {
                seed_size, state, ..
            } => {
                let guard = state.lock().await;
                EntropyStats {
                    entropy_mode: EntropyMode::HybridCsprng.as_str(),
                    reseed_count: guard.reseed_count,
                    bytes_served_since_reseed: guard.bytes_served_since_reseed,
                    reseed_failures: guard.reseed_failures,
                    qrng_seed_size: *seed_size,
                }
            }
        }
    }
}

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
        return Err(EntropyError::LengthMismatch {
            expected: n,
            got: bytes.len(),
        });
    }

    Ok(bytes)
}

async fn fetch_qrng_seed(
    http: &reqwest::Client,
    base_url: &str,
    seed_size: usize,
) -> Result<Vec<u8>, EntropyError> {
    if seed_size == 0 {
        return Err(EntropyError::InvalidSeedSize);
    }

    fetch_entropy_bytes(http, base_url, seed_size).await
}

fn rng_from_seed(seed: &[u8]) -> ChaCha20Rng {
    let digest = sha2::Sha256::digest(seed);
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(&digest[..32]);
    ChaCha20Rng::from_seed(seed32)
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
    #[error("HYBRID_QRNG_SEED_SIZE must be greater than zero")]
    InvalidSeedSize,
}
