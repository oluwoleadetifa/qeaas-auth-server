use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use oqs::{kem, sig};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::models::EnrollResponse;
use crate::pq::DevicePq;

pub fn state_dir() -> PathBuf {
    PathBuf::from("device_state")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceCredentials {
    pub device_id: String,
    kem_alg: String,
    sig_alg: String,
    kem_pk_b64: String,
    kem_sk_b64: String,
    sig_pk_b64: String,
    sig_sk_b64: String,
    pub server_kem_alg: Option<String>,
    pub server_sig_alg: Option<String>,
    pub server_kem_pk_b64: Option<String>,
    pub server_sig_pk_b64: Option<String>,
}

pub fn save_device_credentials(device_id: &str, pq: &DevicePq) -> Result<PathBuf> {
    let credentials = DeviceCredentials {
        device_id: device_id.to_string(),
        kem_alg: format!("{:?}", pq.kem_alg),
        sig_alg: format!("{:?}", pq.sig_alg),
        kem_pk_b64: STANDARD.encode(pq.kem_pk.as_ref()),
        kem_sk_b64: STANDARD.encode(pq.kem_sk.as_ref()),
        sig_pk_b64: STANDARD.encode(pq.sig_pk.as_ref()),
        sig_sk_b64: STANDARD.encode(pq.sig_sk_bytes()?),
        server_kem_alg: None,
        server_sig_alg: None,
        server_kem_pk_b64: None,
        server_sig_pk_b64: None,
    };

    save_device_credentials_record(&credentials)
}

pub fn save_device_credentials_record(credentials: &DeviceCredentials) -> Result<PathBuf> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    let path = credentials_path(&credentials.device_id);
    fs::write(&path, serde_json::to_string_pretty(credentials)?)?;
    Ok(path)
}

pub fn credentials_path(device_id: &str) -> PathBuf {
    state_dir().join(format!("{}.json", safe_state_name(device_id)))
}

pub fn ensure_state_dir() -> Result<PathBuf> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

pub fn credentials_exist(device_id: &str) -> bool {
    credentials_path(device_id).exists()
}

pub fn load_device_credentials(device_id: &str) -> Result<DeviceCredentials> {
    let path = credentials_path(device_id);
    let value =
        fs::read_to_string(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_str(&value).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn save_enrollment_response(device_id: &str, enroll: &EnrollResponse) -> Result<PathBuf> {
    let mut credentials = load_device_credentials(device_id)?;
    credentials.server_kem_alg = Some(enroll.server_kem_alg.clone());
    credentials.server_sig_alg = Some(enroll.server_sig_alg.clone());
    credentials.server_kem_pk_b64 = Some(enroll.server_kem_pk_b64.clone());
    credentials.server_sig_pk_b64 = Some(enroll.server_sig_pk_b64.clone());
    save_device_credentials_record(&credentials)
}

pub fn device_pq_from_credentials(credentials: &DeviceCredentials) -> Result<DevicePq> {
    let kem_alg = parse_kem_algorithm(&credentials.kem_alg)?;
    let sig_alg = parse_sig_algorithm(&credentials.sig_alg)?;
    let mut pq = DevicePq::new(kem_alg, sig_alg).context("DevicePq::new failed")?;
    pq.set_kem_sk(
        STANDARD
            .decode(&credentials.kem_sk_b64)
            .context("failed to decode kem_sk_b64")?,
    )?;
    pq.set_sig_sk(
        STANDARD
            .decode(&credentials.sig_sk_b64)
            .context("failed to decode sig_sk_b64")?,
    )?;
    Ok(pq)
}

pub fn public_keys(credentials: &DeviceCredentials) -> (&str, &str) {
    (&credentials.kem_pk_b64, &credentials.sig_pk_b64)
}

pub fn write_state_file(name: &str, value: &str) -> Result<()> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    fs::write(dir.join(name), value)?;
    Ok(())
}

pub fn read_state_file(name: &str) -> Result<String> {
    let value = fs::read_to_string(state_dir().join(name))?;
    Ok(value.trim().to_string())
}

fn safe_state_name(device_id: &str) -> String {
    device_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn parse_kem_algorithm(value: &str) -> Result<kem::Algorithm> {
    match value {
        "Kyber1024" => Ok(kem::Algorithm::Kyber1024),
        other => Err(anyhow!("unsupported saved KEM algorithm: {other}")),
    }
}

fn parse_sig_algorithm(value: &str) -> Result<sig::Algorithm> {
    match value {
        "Dilithium5" => Ok(sig::Algorithm::Dilithium5),
        other => Err(anyhow!("unsupported saved signature algorithm: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::safe_state_name;

    #[test]
    fn safe_state_name_removes_path_separators() {
        assert_eq!(safe_state_name("../device/one"), ".._device_one");
    }
}
