use anyhow::{anyhow, Context};
use client_iot::{
    client::IotClient,
    config::ClientConfig,
    pq::DevicePq,
    storage::{
        credentials_exist, credentials_path, device_pq_from_credentials, ensure_state_dir,
        load_device_credentials, public_keys, save_device_credentials, save_enrollment_response,
    },
};
use oqs::{kem, sig};
use sha2::{Digest, Sha256};
use std::time::Instant;

const DEFAULT_DEVICE_ID: &str = "iot-device-mac";
const DEFAULT_N: usize = 32;

#[derive(Debug)]
enum Command {
    Enroll(CommandOptions),
    Request(CommandOptions),
    ReEnroll(CommandOptions),
}

#[derive(Debug)]
struct CommandOptions {
    server: String,
    device_id: String,
    n: usize,
    dry_run: bool,
    verbose: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = parse_args(std::env::args().skip(1))?;

    match command {
        Command::Enroll(opts) => enroll(opts).await?,
        Command::Request(opts) => request(opts).await?,
        Command::ReEnroll(opts) => re_enroll(opts).await?,
    }

    Ok(())
}

async fn enroll(opts: CommandOptions) -> anyhow::Result<()> {
    let state_dir = ensure_state_dir()?;
    let state_path = credentials_path(&opts.device_id);

    if opts.dry_run {
        println!("DRY RUN enroll");
        println!("Server: {}", opts.server);
        println!("Device ID: {}", opts.device_id);
        println!("State dir: {}", state_dir.display());
        println!("State file: {}", state_path.display());
        println!(
            "Action: would {} credentials and call /v1/devices/enroll",
            if state_path.exists() {
                "load existing"
            } else {
                "generate new"
            }
        );
        return Ok(());
    }

    let client = IotClient::with_verbose(opts.server, opts.verbose);
    let enroll_resp = if credentials_exist(&opts.device_id) {
        let credentials = load_device_credentials(&opts.device_id)?;
        let (kem_pk_b64, sig_pk_b64) = public_keys(&credentials);
        client
            .enroll_with_public_keys(&opts.device_id, kem_pk_b64, sig_pk_b64)
            .await?
    } else {
        let pq = new_device_pq()?;
        save_device_credentials(&opts.device_id, &pq)
            .context("failed to save generated device credentials")?;
        client.enroll(&opts.device_id, &pq).await?
    };

    save_enrollment_response(&opts.device_id, &enroll_resp)
        .context("failed to save enrollment response")?;
    println!("Status: enrolled");
    println!("Device ID: {}", opts.device_id);
    Ok(())
}

async fn request(opts: CommandOptions) -> anyhow::Result<()> {
    let state_dir = ensure_state_dir()?;
    let state_path = credentials_path(&opts.device_id);

    if opts.dry_run {
        println!("DRY RUN request");
        println!("Server: {}", opts.server);
        println!("Device ID: {}", opts.device_id);
        println!("n: {}", opts.n);
        println!("State dir: {}", state_dir.display());
        println!("State file: {}", state_path.display());
        println!(
            "Action: would load existing state and call /v1/entropy{}",
            if state_path.exists() {
                ""
            } else {
                " (state is currently missing)"
            }
        );
        return Ok(());
    }

    let credentials = load_device_credentials(&opts.device_id)?;
    let server_sig_pk_b64 = credentials
        .server_sig_pk_b64
        .as_deref()
        .ok_or_else(|| anyhow!("device state is missing server_sig_pk_b64; run enroll first"))?;
    let pq = device_pq_from_credentials(&credentials)?;
    let client = IotClient::with_verbose(opts.server, opts.verbose);
    let mut timed = client
        .request_entropy_timed(&opts.device_id, opts.n, &pq, server_sig_pk_b64)
        .await?;

    let postprocess_start = Instant::now();
    let entropy_len = timed.entropy.len();
    let h = Sha256::digest(&timed.entropy);
    timed.timing.client_postprocess_us = postprocess_start.elapsed().as_micros();

    println!("Status: ok");
    println!("Device ID: {}", opts.device_id);
    println!("Entropy length: {}", entropy_len);
    println!("SHA256(entropy): {:x}", h);
    println!("client_prepare_us: {}", timed.timing.client_prepare_us);
    println!("client_decap_us: {}", timed.timing.client_decap_us);
    println!("client_decrypt_us: {}", timed.timing.client_decrypt_us);
    println!(
        "client_response_verify_us: {}",
        timed.timing.client_response_verify_us
    );
    println!(
        "client_postprocess_us: {}",
        timed.timing.client_postprocess_us
    );
    println!(
        "end_to_end_usable_entropy_us: {}",
        timed.timing.end_to_end_usable_entropy_us
    );
    Ok(())
}

async fn re_enroll(opts: CommandOptions) -> anyhow::Result<()> {
    let state_dir = ensure_state_dir()?;
    let state_path = credentials_path(&opts.device_id);

    if opts.dry_run {
        println!("DRY RUN re-enroll");
        println!("Server: {}", opts.server);
        println!("Device ID: {}", opts.device_id);
        println!("State dir: {}", state_dir.display());
        println!("State file: {}", state_path.display());
        println!("Action: would replace credentials and call /v1/devices/enroll");
        return Ok(());
    }

    let pq = new_device_pq()?;
    save_device_credentials(&opts.device_id, &pq)
        .context("failed to save replacement device credentials")?;
    let client = IotClient::with_verbose(opts.server, opts.verbose);
    let enroll_resp = client.enroll(&opts.device_id, &pq).await?;
    save_enrollment_response(&opts.device_id, &enroll_resp)
        .context("failed to save enrollment response")?;

    println!("Status: re-enrolled");
    println!("Device ID: {}", opts.device_id);
    Ok(())
}

fn new_device_pq() -> anyhow::Result<DevicePq> {
    DevicePq::new(kem::Algorithm::Kyber1024, sig::Algorithm::Dilithium5)
}

fn parse_args<I>(args: I) -> anyhow::Result<Command>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        print_help();
        return Err(anyhow!("missing command"));
    };

    if matches!(command.as_str(), "--help" | "-h" | "help") {
        print_help();
        std::process::exit(0);
    }

    let mut opts = CommandOptions {
        server: ClientConfig::from_env().auth_base,
        device_id: std::env::var("DEVICE_ID").unwrap_or_else(|_| DEFAULT_DEVICE_ID.to_string()),
        n: DEFAULT_N,
        dry_run: false,
        verbose: false,
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server" => {
                opts.server = args
                    .next()
                    .ok_or_else(|| anyhow!("--server requires a URL"))?;
            }
            "--device-id" => {
                opts.device_id = args
                    .next()
                    .ok_or_else(|| anyhow!("--device-id requires an ID"))?;
            }
            "--n" => {
                opts.n = args
                    .next()
                    .ok_or_else(|| anyhow!("--n requires a byte count"))?
                    .parse()
                    .context("--n must be a positive integer")?;
            }
            "--dry-run" => opts.dry_run = true,
            "--verbose" => opts.verbose = true,
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => return Err(anyhow!("unknown argument: {other}")),
        }
    }

    match command.as_str() {
        "enroll" => Ok(Command::Enroll(opts)),
        "request" => Ok(Command::Request(opts)),
        "re-enroll" => Ok(Command::ReEnroll(opts)),
        other => Err(anyhow!("unknown command: {other}")),
    }
}

fn print_help() {
    println!(
        r#"QEaaS IoT client

USAGE:
    cargo run -- enroll [--server <URL>] [--device-id <ID>] [--dry-run] [--verbose]
    cargo run -- request [--server <URL>] [--device-id <ID>] [--n <BYTES>] [--dry-run] [--verbose]
    cargo run -- re-enroll [--server <URL>] [--device-id <ID>] [--dry-run] [--verbose]

COMMANDS:
    enroll      Create state if missing, then enroll the device
    request     Load existing state and request entropy
    re-enroll   Replace state and enroll the new credentials

DEFAULTS:
    device id:  iot-device-mac
    server URL: QEAAAS_SERVER_URL, then AUTH_BASE, then http://127.0.0.1:3000
    n:          32

FLAGS:
    --verbose   Print detailed enrollment/request JSON
"#
    );
}
