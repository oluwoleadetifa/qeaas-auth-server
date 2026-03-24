use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

use crate::{config, pq::PqContext};

#[derive(Clone)]
pub struct AppState {
    pub pq: Arc<PqContext>,
    pub http: reqwest::Client,
    pub qrng_base_url: String,

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
            .timeout(std::time::Duration::from_secs(5))
            .build()?;

        let qrng_base_url = config::qrng_base_url();

        // You can wire these from config.rs; for now use defaults if you don’t have them yet.
        let nonce_ttl = Duration::from_secs(config::nonce_ttl_secs()); // implement in config
        let per_device_cap = config::nonce_per_device_cap();          // implement in config
        let nonce_cache = NonceCache::new(nonce_ttl, per_device_cap);

        Ok(Self {
            pq,
            http,
            qrng_base_url,
            devices: Arc::new(RwLock::new(HashMap::new())),
            nonce_cache,
        })
    }
}