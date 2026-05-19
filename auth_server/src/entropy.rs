use std::{
    str::FromStr,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};

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
    ParallelHybrid,
}

impl EntropyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DirectQrng => "direct_qrng",
            Self::HybridCsprng => "hybrid_csprng",
            Self::ParallelHybrid => "parallel_hybrid",
        }
    }
}

impl FromStr for EntropyMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "direct_qrng" => Ok(Self::DirectQrng),
            "hybrid_csprng" => Ok(Self::HybridCsprng),
            "parallel_hybrid" | "hybrid_pool" => Ok(Self::ParallelHybrid),
            other => Err(anyhow!(
                "invalid ENTROPY_MODE={other}; expected direct_qrng, hybrid_csprng, parallel_hybrid, or hybrid_pool"
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
    ParallelHybrid {
        http: reqwest::Client,
        base_url: String,
        seed_size: usize,
        reseed_after_bytes: u64,
        shards: Vec<HybridShard>,
        next_shard: AtomicUsize,
        total_bytes_served: AtomicU64,
        total_reseed_count: AtomicU64,
        total_reseed_failures: AtomicU64,
        total_entropy_wait_us: AtomicU64,
    },
}

struct HybridState {
    rng: ChaCha20Rng,
    reseed_count: u64,
    bytes_served_since_reseed: usize,
    reseed_failures: u64,
}

struct HybridShard {
    id: usize,
    state: Mutex<ShardState>,
    bytes_served: AtomicU64,
    bytes_since_reseed: AtomicU64,
    reseed_count: AtomicU64,
    reseed_failures: AtomicU64,
    reseed_in_progress: AtomicBool,
}

struct ShardState {
    rng: ChaCha20Rng,
}

#[derive(Debug)]
pub struct EntropyOutput {
    pub bytes: Vec<u8>,
    pub stats: EntropyStats,
}

#[derive(Debug, Clone)]
pub struct EntropyStats {
    pub entropy_mode: &'static str,
    pub pool_size: usize,
    pub shard_id: Option<usize>,
    pub reseed_count: u64,
    pub bytes_served_since_reseed: usize,
    pub bytes_served: u64,
    pub reseed_failures: u64,
    pub qrng_seed_size: usize,
    pub lock_wait_us: u64,
    pub total_entropy_wait_us: u64,
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

    pub async fn parallel_hybrid(
        http: reqwest::Client,
        base_url: String,
        seed_size: usize,
        reseed_after_bytes: usize,
        pool_size: usize,
    ) -> Result<Self, EntropyError> {
        if pool_size == 0 {
            return Err(EntropyError::InvalidPoolSize);
        }

        let mut shards = Vec::with_capacity(pool_size);
        for shard_id in 0..pool_size {
            let seed = fetch_qrng_seed(&http, &base_url, seed_size).await?;
            shards.push(HybridShard {
                id: shard_id,
                state: Mutex::new(ShardState {
                    rng: rng_from_seed_for_shard(&seed, shard_id),
                }),
                bytes_served: AtomicU64::new(0),
                bytes_since_reseed: AtomicU64::new(0),
                reseed_count: AtomicU64::new(0),
                reseed_failures: AtomicU64::new(0),
                reseed_in_progress: AtomicBool::new(false),
            });
        }

        tracing::info!(
            entropy_mode = EntropyMode::ParallelHybrid.as_str(),
            pool_size,
            qrng_seed_size = seed_size,
            reseed_after_bytes,
            "entropy source initialized"
        );

        Ok(Self {
            inner: Arc::new(EntropySourceInner::ParallelHybrid {
                http,
                base_url,
                seed_size,
                reseed_after_bytes: reseed_after_bytes as u64,
                shards,
                next_shard: AtomicUsize::new(0),
                total_bytes_served: AtomicU64::new(0),
                total_reseed_count: AtomicU64::new(0),
                total_reseed_failures: AtomicU64::new(0),
                total_entropy_wait_us: AtomicU64::new(0),
            }),
        })
    }

    pub async fn bytes(&self, n: usize) -> Result<Vec<u8>, EntropyError> {
        Ok(self.bytes_with_stats(n).await?.bytes)
    }

    pub async fn bytes_with_stats(&self, n: usize) -> Result<EntropyOutput, EntropyError> {
        match self.inner.as_ref() {
            EntropySourceInner::DirectQrng { http, base_url } => {
                let bytes = fetch_entropy_bytes(http, base_url, n).await?;
                Ok(EntropyOutput {
                    bytes,
                    stats: EntropyStats {
                        entropy_mode: EntropyMode::DirectQrng.as_str(),
                        pool_size: 0,
                        shard_id: None,
                        reseed_count: 0,
                        bytes_served_since_reseed: 0,
                        bytes_served: 0,
                        reseed_failures: 0,
                        qrng_seed_size: 0,
                        lock_wait_us: 0,
                        total_entropy_wait_us: 0,
                    },
                })
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
                let stats = EntropyStats {
                    entropy_mode: EntropyMode::HybridCsprng.as_str(),
                    pool_size: 1,
                    shard_id: Some(0),
                    reseed_count: guard.reseed_count,
                    bytes_served_since_reseed: guard.bytes_served_since_reseed,
                    bytes_served: guard.bytes_served_since_reseed as u64,
                    reseed_failures: guard.reseed_failures,
                    qrng_seed_size: *seed_size,
                    lock_wait_us: 0,
                    total_entropy_wait_us: 0,
                };
                Ok(EntropyOutput { bytes: out, stats })
            }
            EntropySourceInner::ParallelHybrid {
                http,
                base_url,
                seed_size,
                reseed_after_bytes,
                shards,
                next_shard,
                total_bytes_served,
                total_reseed_count,
                total_reseed_failures,
                total_entropy_wait_us,
            } => {
                let shard_index = next_shard.fetch_add(1, Ordering::Relaxed) % shards.len();
                let shard = &shards[shard_index];

                if shard.bytes_since_reseed.load(Ordering::Relaxed) >= *reseed_after_bytes {
                    self.try_reseed_parallel_shard(
                        http,
                        base_url,
                        *seed_size,
                        shards.len(),
                        shard,
                        total_reseed_count,
                        total_reseed_failures,
                    )
                    .await;
                }

                let wait_start = Instant::now();
                let mut guard = shard.state.lock().await;
                let lock_wait_us = wait_start.elapsed().as_micros() as u64;
                let mut out = vec![0u8; n];
                guard.rng.fill_bytes(&mut out);
                drop(guard);

                let n_u64 = n as u64;
                let bytes_since_reseed =
                    shard.bytes_since_reseed.fetch_add(n_u64, Ordering::Relaxed) + n_u64;
                shard.bytes_served.fetch_add(n_u64, Ordering::Relaxed);
                let bytes_served = total_bytes_served.fetch_add(n_u64, Ordering::Relaxed) + n_u64;
                let total_wait =
                    total_entropy_wait_us.fetch_add(lock_wait_us, Ordering::Relaxed) + lock_wait_us;

                Ok(EntropyOutput {
                    bytes: out,
                    stats: EntropyStats {
                        entropy_mode: EntropyMode::ParallelHybrid.as_str(),
                        pool_size: shards.len(),
                        shard_id: Some(shard.id),
                        reseed_count: total_reseed_count.load(Ordering::Relaxed),
                        bytes_served_since_reseed: bytes_since_reseed as usize,
                        bytes_served,
                        reseed_failures: total_reseed_failures.load(Ordering::Relaxed),
                        qrng_seed_size: *seed_size,
                        lock_wait_us,
                        total_entropy_wait_us: total_wait,
                    },
                })
            }
        }
    }

    async fn try_reseed_parallel_shard(
        &self,
        http: &reqwest::Client,
        base_url: &str,
        seed_size: usize,
        pool_size: usize,
        shard: &HybridShard,
        total_reseed_count: &AtomicU64,
        total_reseed_failures: &AtomicU64,
    ) {
        if shard
            .reseed_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let seed = match fetch_qrng_seed(http, base_url, seed_size).await {
            Ok(seed) => seed,
            Err(err) => {
                let shard_failures = shard.reseed_failures.fetch_add(1, Ordering::Relaxed) + 1;
                let total_failures = total_reseed_failures.fetch_add(1, Ordering::Relaxed) + 1;
                shard.reseed_in_progress.store(false, Ordering::Release);
                tracing::error!(
                    entropy_mode = EntropyMode::ParallelHybrid.as_str(),
                    pool_size,
                    shard_id = shard.id,
                    reseed_failures = total_failures,
                    shard_reseed_failures = shard_failures,
                    qrng_seed_size = seed_size,
                    error = %err,
                    "parallel hybrid CSPRNG reseed failed"
                );
                return;
            }
        };

        {
            let mut guard = shard.state.lock().await;
            guard.rng = rng_from_seed_for_shard(&seed, shard.id);
        }

        shard.bytes_since_reseed.store(0, Ordering::Relaxed);
        let shard_reseed_count = shard.reseed_count.fetch_add(1, Ordering::Relaxed) + 1;
        let total_reseeds = total_reseed_count.fetch_add(1, Ordering::Relaxed) + 1;
        shard.reseed_in_progress.store(false, Ordering::Release);

        tracing::info!(
            entropy_mode = EntropyMode::ParallelHybrid.as_str(),
            pool_size,
            shard_id = shard.id,
            reseed_count = total_reseeds,
            shard_reseed_count,
            bytes_served = shard.bytes_served.load(Ordering::Relaxed),
            bytes_since_reseed = shard.bytes_since_reseed.load(Ordering::Relaxed),
            qrng_seed_size = seed_size,
            "parallel hybrid CSPRNG shard reseeded"
        );
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

fn rng_from_seed_for_shard(seed: &[u8], shard_id: usize) -> ChaCha20Rng {
    let mut h = sha2::Sha256::new();
    h.update(seed);
    h.update((shard_id as u64).to_le_bytes());
    let digest = h.finalize();
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
    #[error("HYBRID_POOL_SIZE must be greater than zero")]
    InvalidPoolSize,
}
