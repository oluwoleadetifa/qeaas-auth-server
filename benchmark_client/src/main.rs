// benchmark_client/src/main.rs
mod enroll;
mod loadtest;
mod message;
mod models;
mod security;
mod storage;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::enroll::enroll_many;
use crate::loadtest::run_loadtest;
use crate::models::BenchmarkConfig;
use crate::security::run_security_check;
use crate::storage::load_users;

#[derive(Parser, Debug)]
#[command(name = "benchmark_client")]
#[command(about = "Enrollment + load testing for QEaaS auth server", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Enroll {
        #[arg(long)]
        base_url: String,
        #[arg(long)]
        count: usize,
        #[arg(long, default_value = "users.jsonl")]
        out: String,
    },
    Loadtest {
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value = "unknown")]
        entropy_mode: String,
        #[arg(long, default_value_t = 32)]
        n: u32,
        #[arg(long, default_value_t = 10)]
        concurrency: usize,
        #[arg(long, default_value_t = 30)]
        duration: u64,
        #[arg(long, default_value = "users.jsonl")]
        users: String,
        #[arg(long, default_value = "benchmark")]
        label: String,
        #[arg(long = "csv-out", alias = "out-csv")]
        csv_out: Option<String>,
        #[arg(long = "jsonl-out", alias = "out-jsonl")]
        jsonl_out: Option<String>,
        #[arg(long)]
        md_out: Option<String>,
    },
    Matrix {
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value = "unknown")]
        entropy_mode: String,
        #[arg(long, default_value = "users.jsonl")]
        users: String,
        #[arg(long, default_value = "32,256,1024,4096")]
        payloads: String,
        #[arg(long = "concurrency-levels", default_value = "1,5,10,25")]
        concurrency_levels: String,
        #[arg(long, default_value_t = 30)]
        duration: u64,
        #[arg(long = "csv-out", alias = "out-csv")]
        csv_out: Option<String>,
        #[arg(long = "jsonl-out", alias = "out-jsonl")]
        jsonl_out: Option<String>,
        #[arg(long)]
        md_out: Option<String>,
        #[arg(long, default_value = "matrix")]
        label: String,
    },
    SecurityCheck {
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        oversized_n: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Enroll {
            base_url,
            count,
            out,
        } => {
            enroll_many(&base_url, count, &out).await?;
        }
        Commands::Loadtest {
            base_url,
            entropy_mode,
            n,
            concurrency,
            duration,
            users,
            label,
            csv_out,
            jsonl_out,
            md_out,
        } => {
            let stored_users = load_users(&users)?;
            let entropy_mode = effective_entropy_mode(entropy_mode, &label);
            let cfg = BenchmarkConfig {
                base_url,
                entropy_mode,
                n,
                concurrency,
                duration_secs: duration,
                users_file: users,
                label,
                csv_out,
                jsonl_out,
                md_out,
            };
            run_loadtest(cfg, stored_users).await?;
        }
        Commands::Matrix {
            base_url,
            entropy_mode,
            users,
            payloads,
            concurrency_levels,
            duration,
            csv_out,
            jsonl_out,
            md_out,
            label,
        } => {
            let stored_users = load_users(&users)?;
            let payloads = parse_csv_u32(&payloads)?;
            let concurrency_levels = parse_csv_usize(&concurrency_levels)?;

            let entropy_mode = effective_entropy_mode(entropy_mode, &label);

            for n in payloads {
                for concurrency in &concurrency_levels {
                    let cfg = BenchmarkConfig {
                        base_url: base_url.clone(),
                        entropy_mode: entropy_mode.clone(),
                        n,
                        concurrency: *concurrency,
                        duration_secs: duration,
                        users_file: users.clone(),
                        label: format!("{label}-{}-n{n}-c{concurrency}", entropy_mode),
                        csv_out: csv_out.clone(),
                        jsonl_out: jsonl_out.clone(),
                        md_out: md_out.clone(),
                    };
                    run_loadtest(cfg, stored_users.clone()).await?;
                }
            }
        }
        Commands::SecurityCheck {
            base_url,
            oversized_n,
        } => {
            run_security_check(&base_url, oversized_n).await?;
        }
    }

    Ok(())
}

fn parse_csv_u32(value: &str) -> Result<Vec<u32>> {
    value
        .split(',')
        .map(|part| {
            part.trim()
                .parse::<u32>()
                .map_err(|e| anyhow::anyhow!("invalid payload size {part:?}: {e}"))
        })
        .collect()
}

fn parse_csv_usize(value: &str) -> Result<Vec<usize>> {
    value
        .split(',')
        .map(|part| {
            part.trim()
                .parse::<usize>()
                .map_err(|e| anyhow::anyhow!("invalid concurrency level {part:?}: {e}"))
        })
        .collect()
}

fn effective_entropy_mode(entropy_mode: String, label: &str) -> String {
    if entropy_mode == "unknown"
        && matches!(
            label,
            "direct_qrng" | "hybrid_csprng" | "parallel_hybrid" | "hybrid_pool"
        )
    {
        label.to_string()
    } else {
        entropy_mode
    }
}
