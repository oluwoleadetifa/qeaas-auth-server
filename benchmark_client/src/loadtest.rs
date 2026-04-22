// benchmark_client/src/loadtest.rs
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use anyhow::{Context, Result};
use futures::future::join_all;
use reqwest::Client as HttpClient;
use tokio::sync::Mutex;

use crate::message::build_signed_request;
use crate::models::{BenchmarkConfig, SigningContext, StoredUser};

use client_iot::{
    client::IotClient,
    config::ClientConfig,
    pq::DevicePq,
};
use oqs::{kem, sig};

#[derive(Default, Debug)]
pub struct Metrics {
    pub success: AtomicU64,
    pub failures: AtomicU64,
    pub replay_409: AtomicU64,
    pub invalid_401: AtomicU64,
    pub other_status: AtomicU64,
    pub latencies_micros: Mutex<Vec<u128>>,
}

pub async fn run_loadtest(cfg: BenchmarkConfig, users: Vec<StoredUser>) -> Result<()> {
    if users.is_empty() {
        anyhow::bail!("no users loaded from {}", cfg.users_file);
    }

    let http_client = HttpClient::builder()
        .pool_idle_timeout(Duration::from_secs(30))
        .build()
        .context("failed to build reqwest client")?;

    let signing_contexts = build_signing_contexts(&cfg.base_url, &users)
        .context("failed to initialize signing contexts")?;

    let metrics = Arc::new(Metrics::default());
    let deadline = Instant::now() + Duration::from_secs(cfg.duration_secs);
    let mut tasks = Vec::with_capacity(cfg.concurrency);

    for worker_id in 0..cfg.concurrency {
        let http_client = http_client.clone();
        let cfg = cfg.clone();
        let metrics = Arc::clone(&metrics);
        let signing_ctx = signing_contexts[worker_id % signing_contexts.len()].clone();

        tasks.push(tokio::spawn(async move {
            worker_loop(http_client, signing_ctx, cfg, deadline, metrics).await;
        }));
    }

    let _ = join_all(tasks).await;
    print_report(&cfg, &metrics).await;

    Ok(())
}

async fn worker_loop(
    http_client: HttpClient,
    signing_ctx: SigningContext,
    cfg: BenchmarkConfig,
    deadline: Instant,
    metrics: Arc<Metrics>,
) {
    while Instant::now() < deadline {
        let req = match build_signed_request(&signing_ctx, cfg.n) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("request build failed: {e:#}");
                metrics.failures.fetch_add(1, Ordering::Relaxed);
                continue;
            }
        };

        let start = Instant::now();

        let response = http_client
            .post(format!("{}/v1/entropy", cfg.base_url))
            .json(&req)
            .send()
            .await;

        let elapsed = start.elapsed().as_micros();

        {
            let mut latencies = metrics.latencies_micros.lock().await;
            latencies.push(elapsed);
        }

        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();

                if status == 200 {
                    metrics.success.fetch_add(1, Ordering::Relaxed);
                } else {
                    metrics.failures.fetch_add(1, Ordering::Relaxed);
                    match status {
                        409 => {
                            metrics.replay_409.fetch_add(1, Ordering::Relaxed);
                        }
                        401 => {
                            metrics.invalid_401.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => {
                            metrics.other_status.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }

                let _ = resp.text().await;
            }
            Err(err) => {
                eprintln!("request failed: {err}");
                metrics.failures.fetch_add(1, Ordering::Relaxed);
                metrics.other_status.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn build_signing_contexts(_base_url: &str, users: &[StoredUser]) -> Result<Vec<SigningContext>> {
    let mut out = Vec::with_capacity(users.len());

    for user in users {
        let ctx = rebuild_device_context(user)
            .with_context(|| format!("failed to rebuild device for {}", user.device_id))?;

        out.push(SigningContext {
            device_id: ctx.device_id,
            pq: ctx.pq,
        });
    }

    Ok(out)
}


fn rebuild_device_context(user: &StoredUser) -> Result<SigningContext> {
    let sig_sk = STANDARD
        .decode(&user.sig_sk_b64)
        .context("failed to decode sig_sk_b64")?;

    let mut pq = DevicePq::new(
        kem::Algorithm::Kyber1024,
        sig::Algorithm::Dilithium5,
    )?;

    // ⚠️ This method MUST exist or be added
    pq.set_sig_sk(sig_sk)?;

    Ok(SigningContext {
        device_id: user.device_id.clone(),
        pq,
    })
}


async fn print_report(cfg: &BenchmarkConfig, metrics: &Metrics) {
    let success = metrics.success.load(Ordering::Relaxed);
    let failures = metrics.failures.load(Ordering::Relaxed);
    let total = success + failures;

    let mut latencies = metrics.latencies_micros.lock().await.clone();
    latencies.sort_unstable();

    let mean = if latencies.is_empty() {
        0.0
    } else {
        latencies.iter().sum::<u128>() as f64 / latencies.len() as f64
    };

    let p95 = percentile(&latencies, 95);
    let p99 = percentile(&latencies, 99);
    let throughput = success as f64 / cfg.duration_secs as f64;

    println!("\n=== Benchmark Report ===");
    println!("Concurrency      : {}", cfg.concurrency);
    println!("Duration (s)     : {}", cfg.duration_secs);
    println!("Request size (n) : {}", cfg.n);
    println!("Total requests   : {}", total);
    println!("Success (200)    : {}", success);
    println!("Failures         : {}", failures);
    println!("Replay 409       : {}", metrics.replay_409.load(Ordering::Relaxed));
    println!("Invalid 401      : {}", metrics.invalid_401.load(Ordering::Relaxed));
    println!("Other failures   : {}", metrics.other_status.load(Ordering::Relaxed));
    println!("Throughput req/s : {:.2}", throughput);
    println!("Mean latency us  : {:.2}", mean);
    println!("P95 latency us   : {}", p95);
    println!("P99 latency us   : {}", p99);
}

fn percentile(values: &[u128], p: usize) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let idx = ((p as f64 / 100.0) * (values.len().saturating_sub(1) as f64)).round() as usize;
    values[idx]
}


