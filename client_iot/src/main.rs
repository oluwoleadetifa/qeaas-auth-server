use client_iot::{config::ClientConfig, run_once};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = ClientConfig::from_env();
    let device_id = std::env::var("DEVICE_ID").unwrap_or_else(|_| "iot-device-002".to_string());

    let out = run_once(cfg, &device_id).await?;

    println!("OK ✅");
    println!("Device: {}", out.device_id);
    println!("Entropy bytes: {}", out.entropy_len);
    println!("SHA256(entropy): {}", out.entropy_sha256_hex);

    Ok(())
}
