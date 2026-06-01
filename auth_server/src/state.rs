use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::{
    config,
    entropy::{EntropyMode, EntropySource},
    pq::PqContext,
};

#[derive(Clone)]
pub struct AppState {
    pub pq: Arc<PqContext>,
    pub entropy: EntropySource,

    // device_id -> (kem_pk_bytes, sig_pk_bytes)
    pub devices: Arc<RwLock<HashMap<String, DeviceKeys>>>,

    // replay protection
    pub nonce_cache: NonceCache,
}

#[derive(Clone)]
pub struct DeviceKeys {
    pub kem_pk: Vec<u8>,
    pub sig_pk: Vec<u8>,
}

/// device_id -> (nonce_b64 -> expires_at)
#[derive(Clone)]
pub struct NonceCache {
    inner: Arc<RwLock<HashMap<String, HashMap<String, Instant>>>>,
    ttl: Duration,
    per_device_cap: usize,
}

impl NonceCache {
    pub fn new(ttl: Duration, per_device_cap: usize) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            ttl,
            per_device_cap,
        }
    }

    /// true = accepted (new nonce); false = replay
    pub async fn check_and_insert(&self, device_id: &str, nonce_b64: &str) -> bool {
        let now = Instant::now();
        let exp = now + self.ttl;

        let mut guard = self.inner.write().await;
        let device_map = guard.entry(device_id.to_string()).or_default();

        // replay check (within TTL)
        if let Some(&expires_at) = device_map.get(nonce_b64) {
            if expires_at > now {
                return false;
            }
        }

        // best-effort cleanup + cap enforcement
        if device_map.len() >= self.per_device_cap {
            device_map.retain(|_, &mut t| t > now);

            while device_map.len() >= self.per_device_cap {
                if let Some(k) = device_map.keys().next().cloned() {
                    device_map.remove(&k);
                } else {
                    break;
                }
            }
        }

        device_map.insert(nonce_b64.to_string(), exp);
        true
    }

    /// remove expired entries
    pub async fn cleanup(&self) {
        let now = Instant::now();
        let mut guard = self.inner.write().await;

        guard.retain(|_, nonces| {
            nonces.retain(|_, &mut t| t > now);
            !nonces.is_empty()
        });
    }
}

impl AppState {
    pub async fn new() -> anyhow::Result<Self> {
        let pq = Arc::new(PqContext::new()?);

        let http = reqwest::Client::builder()
            .timeout(config::http_timeout())
            .build()?;

        let qrng_base_url = config::qrng_base_url();
        let entropy_mode = config::entropy_mode()?;
        let qrng_seed_size = config::hybrid_qrng_seed_size();
        let reseed_after_bytes = config::hybrid_reseed_after_bytes();
        let hybrid_pool_size = if matches!(entropy_mode, EntropyMode::ParallelHybrid) {
            Some(config::hybrid_pool_size()?)
        } else {
            None
        };

        tracing::info!(
            entropy_mode = entropy_mode.as_str(),
            qrng_base_url = %qrng_base_url,
            qrng_seed_size,
            reseed_after_bytes,
            hybrid_pool_size = ?hybrid_pool_size,
            max_entropy_request_bytes = config::max_entropy_request_bytes(),
            stage_timing_enabled = config::enable_stage_timing(),
            "QEaaS auth server configuration"
        );

        let entropy = match entropy_mode {
            EntropyMode::DirectQrng => {
                EntropySource::direct_qrng(http.clone(), qrng_base_url.clone()).await
            }
            EntropyMode::HybridCsprng => {
                EntropySource::hybrid_csprng(
                    http.clone(),
                    qrng_base_url.clone(),
                    qrng_seed_size,
                    reseed_after_bytes,
                )
                .await?
            }
            EntropyMode::ParallelHybrid => {
                EntropySource::parallel_hybrid(
                    http.clone(),
                    qrng_base_url.clone(),
                    qrng_seed_size,
                    reseed_after_bytes,
                    hybrid_pool_size.unwrap_or(8),
                )
                .await?
            }
        };

        // You can wire these from config.rs; for now use defaults if you don’t have them yet.
        let nonce_ttl = Duration::from_secs(config::nonce_ttl_secs()); // implement in config
        let per_device_cap = config::nonce_per_device_cap(); // implement in config
        let nonce_cache = NonceCache::new(nonce_ttl, per_device_cap);

        Ok(Self {
            pq,
            entropy,
            devices: Arc::new(RwLock::new(HashMap::new())),
            nonce_cache,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::NonceCache;
    use std::time::Duration;

    #[tokio::test]
    async fn nonce_cache_rejects_reuse_within_ttl() {
        let cache = NonceCache::new(Duration::from_secs(60), 16);

        assert!(cache.check_and_insert("device-1", "nonce-a").await);
        assert!(!cache.check_and_insert("device-1", "nonce-a").await);
        assert!(cache.check_and_insert("device-1", "nonce-b").await);
        assert!(cache.check_and_insert("device-2", "nonce-a").await);
    }
}
