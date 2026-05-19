// benchmark_client/src/main.rs
mod enroll;
mod loadtest;
mod message;
mod models;
mod storage;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::enroll::enroll_many;
use crate::loadtest::run_loadtest;
use crate::models::BenchmarkConfig;
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
        #[arg(long)]
        csv_out: Option<String>,
        #[arg(long)]
        md_out: Option<String>,
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
            n,
            concurrency,
            duration,
            users,
            label,
            csv_out,
            md_out,
        } => {
            let stored_users = load_users(&users)?;
            let cfg = BenchmarkConfig {
                base_url,
                n,
                concurrency,
                duration_secs: duration,
                users_file: users,
                label,
                csv_out,
                md_out,
            };
            run_loadtest(cfg, stored_users).await?;
        }
    }

    Ok(())
}
