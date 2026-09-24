// benchmark_client/src/loadtest.rs
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::process::Command;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use futures::future::join_all;
use reqwest::Client as HttpClient;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::message::build_signed_request;
use crate::models::{BenchmarkConfig, SigningContext, StoredUser};

use client_iot::pq::DevicePq;
use oqs::{kem, sig};
use std::io::Write;

#[derive(Default, Debug)]
pub struct Metrics {
    pub success: AtomicU64,
    pub failures: AtomicU64,
    pub replay_409: AtomicU64,
    pub invalid_401: AtomicU64,
    pub other_status: AtomicU64,
    pub latencies_micros: Mutex<Vec<u128>>,
}

#[derive(Debug, Serialize)]
struct BenchmarkSummary {
    timestamp: u128,
    git_commit: Option<String>,
    label: String,
    base_url: String,
    entropy_mode: String,
    payload_size_n: u32,
    concurrency: usize,
    duration_seconds: u64,
    total_requests: u64,
    successful_responses: u64,
    failed_responses: u64,
    http_401_count: u64,
    http_409_count: u64,
    other_error_count: u64,
    throughput_req_s: f64,
    mean_latency_us: f64,
    p50_latency_us: u128,
    p95_latency_us: u128,
    p99_latency_us: u128,
    max_latency_us: u128,
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
    let summary = summarize(&cfg, &metrics).await;
    print_report(&summary);
    write_reports(&cfg, &summary)?;

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
            pq: Arc::clone(&ctx.pq),
        });
    }

    Ok(out)
}

fn rebuild_device_context(user: &StoredUser) -> Result<SigningContext> {
    let sig_sk = STANDARD
        .decode(&user.sig_sk_b64)
        .context("failed to decode sig_sk_b64")?;

    let mut pq = DevicePq::new(kem::Algorithm::Kyber1024, sig::Algorithm::Dilithium5)?;

    // ⚠️ This method MUST exist or be added
    pq.set_sig_sk(sig_sk)?;

    Ok(SigningContext {
        device_id: user.device_id.clone(),
        pq: Arc::new(pq),
    })
}

async fn summarize(cfg: &BenchmarkConfig, metrics: &Metrics) -> BenchmarkSummary {
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

    let p50 = percentile(&latencies, 50);
    let p95 = percentile(&latencies, 95);
    let p99 = percentile(&latencies, 99);
    let max = latencies.last().copied().unwrap_or(0);
    let throughput = success as f64 / cfg.duration_secs as f64;

    BenchmarkSummary {
        timestamp: unix_ms(),
        git_commit: git_commit(),
        label: cfg.label.clone(),
        base_url: cfg.base_url.clone(),
        entropy_mode: cfg.entropy_mode.clone(),
        payload_size_n: cfg.n,
        concurrency: cfg.concurrency,
        duration_seconds: cfg.duration_secs,
        total_requests: total,
        successful_responses: success,
        failed_responses: failures,
        http_401_count: metrics.invalid_401.load(Ordering::Relaxed),
        http_409_count: metrics.replay_409.load(Ordering::Relaxed),
        other_error_count: metrics.other_status.load(Ordering::Relaxed),
        throughput_req_s: throughput,
        mean_latency_us: mean,
        p50_latency_us: p50,
        p95_latency_us: p95,
        p99_latency_us: p99,
        max_latency_us: max,
    }
}

fn print_report(summary: &BenchmarkSummary) {
    println!("\n=== Benchmark Report ===");
    println!("Label            : {}", summary.label);
    println!("Entropy mode     : {}", summary.entropy_mode);
    println!("Concurrency      : {}", summary.concurrency);
    println!("Duration (s)     : {}", summary.duration_seconds);
    println!("Request size (n) : {}", summary.payload_size_n);
    println!("Total requests   : {}", summary.total_requests);
    println!("Success (200)    : {}", summary.successful_responses);
    println!("Failures         : {}", summary.failed_responses);
    println!("Replay 409       : {}", summary.http_409_count);
    println!("Invalid 401      : {}", summary.http_401_count);
    println!("Other failures   : {}", summary.other_error_count);
    println!("Throughput req/s : {:.2}", summary.throughput_req_s);
    println!("Mean latency us  : {:.2}", summary.mean_latency_us);
    println!("P50 latency us   : {}", summary.p50_latency_us);
    println!("P95 latency us   : {}", summary.p95_latency_us);
    println!("P99 latency us   : {}", summary.p99_latency_us);
    println!("Max latency us   : {}", summary.max_latency_us);
}

fn write_reports(cfg: &BenchmarkConfig, summary: &BenchmarkSummary) -> Result<()> {
    if let Some(path) = &cfg.csv_out {
        write_csv_report(path, summary)?;
    }

    if let Some(path) = &cfg.jsonl_out {
        write_jsonl_report(path, summary)?;
    }

    if let Some(path) = &cfg.md_out {
        write_markdown_report(path, summary)?;
    }

    Ok(())
}

fn write_csv_report(path: &str, summary: &BenchmarkSummary) -> Result<()> {
    let exists = std::path::Path::new(path).exists();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open CSV report: {path}"))?;

    if !exists {
        writeln!(
            f,
            "timestamp,git_commit,base_url,entropy_mode,label,payload_size_n,concurrency,duration_seconds,total_requests,successful_responses,failed_responses,http_401_count,http_409_count,other_error_count,throughput_req_s,mean_latency_us,p50_latency_us,p95_latency_us,p99_latency_us,max_latency_us"
        )?;
    }

    writeln!(
        f,
        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.2},{:.2},{},{},{},{}",
        summary.timestamp,
        csv_escape(summary.git_commit.as_deref().unwrap_or("")),
        csv_escape(&summary.base_url),
        csv_escape(&summary.entropy_mode),
        csv_escape(&summary.label),
        summary.payload_size_n,
        summary.concurrency,
        summary.duration_seconds,
        summary.total_requests,
        summary.successful_responses,
        summary.failed_responses,
        summary.http_401_count,
        summary.http_409_count,
        summary.other_error_count,
        summary.throughput_req_s,
        summary.mean_latency_us,
        summary.p50_latency_us,
        summary.p95_latency_us,
        summary.p99_latency_us,
        summary.max_latency_us
    )?;

    Ok(())
}

fn write_jsonl_report(path: &str, summary: &BenchmarkSummary) -> Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open JSONL report: {path}"))?;

    writeln!(f, "{}", serde_json::to_string(summary)?)?;

    Ok(())
}

fn write_markdown_report(path: &str, summary: &BenchmarkSummary) -> Result<()> {
    let exists = std::path::Path::new(path).exists();
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open Markdown report: {path}"))?;

    if !exists {
        writeln!(f, "# QEaaS Benchmark Summary\n")?;
        writeln!(
            f,
            "| label | mode | n | concurrency | duration_s | total | success | failures | 409 | 401 | other | req/s | mean_us | p50_us | p95_us | p99_us | max_us |"
        )?;
        writeln!(
            f,
            "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
        )?;
    }

    writeln!(
        f,
        "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} | {} | {} | {} | {} |",
        md_escape(&summary.label),
        md_escape(&summary.entropy_mode),
        summary.payload_size_n,
        summary.concurrency,
        summary.duration_seconds,
        summary.total_requests,
        summary.successful_responses,
        summary.failed_responses,
        summary.http_409_count,
        summary.http_401_count,
        summary.other_error_count,
        summary.throughput_req_s,
        summary.mean_latency_us,
        summary.p50_latency_us,
        summary.p95_latency_us,
        summary.p99_latency_us,
        summary.max_latency_us
    )?;

    Ok(())
}

fn csv_escape(value: &str) -> String {
    if value.contains([',', '"', '\n']) {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

fn md_escape(value: &str) -> String {
    value.replace('|', "\\|")
}

fn percentile(values: &[u128], p: usize) -> u128 {
    if values.is_empty() {
        return 0;
    }
    let idx = ((p as f64 / 100.0) * (values.len().saturating_sub(1) as f64)).round() as usize;
    values[idx]
}

fn unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let commit = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!commit.is_empty()).then_some(commit)
}

#[cfg(test)]
mod tests {
    use super::{percentile, BenchmarkSummary};

    #[test]
    fn percentile_handles_empty_values() {
        assert_eq!(percentile(&[], 50), 0);
    }

    #[test]
    fn percentile_reports_expected_positions() {
        let values = vec![10, 20, 30, 40, 50];
        assert_eq!(percentile(&values, 50), 30);
        assert_eq!(percentile(&values, 95), 50);
        assert_eq!(percentile(&values, 99), 50);
    }

    #[test]
    fn benchmark_summary_serializes_publication_fields() {
        let summary = BenchmarkSummary {
            timestamp: 1,
            git_commit: Some("abc123".to_string()),
            label: "smoke".to_string(),
            base_url: "http://127.0.0.1:3000".to_string(),
            entropy_mode: "direct_qrng".to_string(),
            payload_size_n: 32,
            concurrency: 1,
            duration_seconds: 30,
            total_requests: 10,
            successful_responses: 10,
            failed_responses: 0,
            http_401_count: 0,
            http_409_count: 0,
            other_error_count: 0,
            throughput_req_s: 0.33,
            mean_latency_us: 100.0,
            p50_latency_us: 90,
            p95_latency_us: 120,
            p99_latency_us: 130,
            max_latency_us: 140,
        };

        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"entropy_mode\":\"direct_qrng\""));
        assert!(json.contains("\"payload_size_n\":32"));
        assert!(json.contains("\"p50_latency_us\":90"));
        assert!(json.contains("\"max_latency_us\":140"));
    }
}
