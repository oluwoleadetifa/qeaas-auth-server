use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose, Engine as _};

use crate::{
    crypto,
    entropy,
    model::*,
    state::{AppState, DeviceKeys},
};

/// ----- Transcript builders (canonical encoding) -----

fn build_client_msg(device_id: &str, n: usize, nonce: &[u8]) -> Vec<u8> {
    // msg = device_id || 0x00 || n(u64 LE) || 0x00 || nonce
    let mut msg = Vec::with_capacity(device_id.len() + 1 + 8 + 1 + nonce.len());
    msg.extend_from_slice(device_id.as_bytes());
    msg.push(0);
    msg.extend_from_slice(&(n as u64).to_le_bytes());
    msg.push(0);
    msg.extend_from_slice(nonce);
    msg
}

fn build_aad(device_id: &str, n: usize, nonce: &[u8], ct_bytes: &[u8]) -> Vec<u8> {
    // aad = device_id || 0x00 || n(u64 LE) || 0x00 || nonce || 0x00 || kem_ct
    let mut aad = Vec::with_capacity(device_id.len() + 1 + 8 + 1 + nonce.len() + 1 + ct_bytes.len());
    aad.extend_from_slice(device_id.as_bytes());
    aad.push(0);
    aad.extend_from_slice(&(n as u64).to_le_bytes());
    aad.push(0);
    aad.extend_from_slice(nonce);
    aad.push(0);
    aad.extend_from_slice(ct_bytes);
    aad
}

fn build_resp_tbs(
    device_id: &str,
    n: usize,
    nonce: &[u8],
    ct_bytes: &[u8],
    aead_nonce12: &[u8; 12],
    entropy_ct: &[u8],
) -> Vec<u8> {
    // resp_tbs = device_id || 0x00 || n(u64 LE) || 0x00 || nonce || 0x00 || kem_ct || 0x00 || aead_nonce12 || 0x00 || entropy_ct
    let mut tbs = Vec::with_capacity(
        device_id.len() + 1 + 8 + 1 + nonce.len() + 1 + ct_bytes.len() + 1 + 12 + 1 + entropy_ct.len(),
    );
    tbs.extend_from_slice(device_id.as_bytes());
    tbs.push(0);
    tbs.extend_from_slice(&(n as u64).to_le_bytes());
    tbs.push(0);
    tbs.extend_from_slice(nonce);
    tbs.push(0);
    tbs.extend_from_slice(ct_bytes);
    tbs.push(0);
    tbs.extend_from_slice(aead_nonce12);
    tbs.push(0);
    tbs.extend_from_slice(entropy_ct);
    tbs
}

/// ----- Small helpers -----

fn b64_decode(field: &'static str, s: &str) -> Result<Vec<u8>, Response> {
    general_purpose::STANDARD
        .decode(s)
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("invalid {field}")).into_response())
}

fn unauthorized(msg: &'static str) -> axum::response::Response {
    (StatusCode::UNAUTHORIZED, msg).into_response()
}

fn conflict(msg: &'static str) -> axum::response::Response {
    (StatusCode::CONFLICT, msg).into_response()
}

fn bad_gateway(msg: String) -> axum::response::Response {
    (StatusCode::BAD_GATEWAY, msg).into_response()
}

/// ----- Handlers -----

pub async fn enroll(
    State(state): State<AppState>,
    Json(payload): Json<EnrollRequest>,
) -> Response {
    let kem_pk = match b64_decode("kem_pk_b64", &payload.kem_pk_b64) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let sig_pk = match b64_decode("sig_pk_b64", &payload.sig_pk_b64) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    {
        let mut devices = state.devices.write().await;
        devices.insert(payload.device_id.clone(), DeviceKeys { kem_pk, sig_pk });
    }

    let resp = EnrollResponse {
        server_kem_alg: format!("{:?}", state.pq.kem_alg),
        server_sig_alg: format!("{:?}", state.pq.sig_alg),
        server_kem_pk_b64: state.pq.server_kem_pk_b64(),
        server_sig_pk_b64: state.pq.server_sig_pk_b64(),
    };

    (StatusCode::OK, Json(resp)).into_response()
}

pub async fn request_entropy(
    State(state): State<AppState>,
    Json(req): Json<EntropyRequest>,
) -> impl IntoResponse {
    // 1) Lookup device keys
    let device = {
        let devices = state.devices.read().await;
        match devices.get(&req.device_id) {
            Some(d) => d.clone(),
            None => return unauthorized("device not enrolled"),
        }
    };

    // 2) Decode inputs
    let nonce = match b64_decode("nonce_b64", &req.nonce_b64) {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    let signature = match b64_decode("signature_b64", &req.signature_b64) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // 3) Verify client signature FIRST (prevents nonce-cache DoS)
    let msg = build_client_msg(&req.device_id, req.n, &nonce);
    let verified = match state
        .pq
        .verify_with_client_pk_bytes(&device.sig_pk, &msg, &signature)
    {
        Ok(v) => v,
        Err(_) => return unauthorized("signature verification error"),
    };

    if !verified {
        return unauthorized("invalid signature");
    }

    // 4) Replay protection (nonce cache) AFTER signature is valid
    //    If nonce already used (within TTL), reject replay.
    let fresh = state
        .nonce_cache
        .check_and_insert(&req.device_id, &req.nonce_b64)
        .await;

    if !fresh {
        // 409 makes it explicit to clients this was a replay
        return conflict("replay detected");
    }

    // 5) Fetch entropy from QRNG server
    let entropy_bytes =
        match entropy::fetch_entropy_bytes(&state.http, &state.qrng_base_url, req.n).await {
            Ok(b) => b,
            Err(e) => return bad_gateway(format!("qrng fetch failed: {e}")),
        };

    // 6) Encapsulate to client KEM pk (Kyber)
    let (ct_bytes, ss_bytes) = match state.pq.encapsulate_to_client_kem_pk_bytes(&device.kem_pk) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad client kem pk length").into_response(),
    };

    // 7) HKDF(ss, salt=client_nonce) -> AEAD key
    let key32 = match crypto::derive_aead_key(&ss_bytes, &nonce) {
        Ok(k) => k,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "key derivation failed").into_response(),
    };

    // 8) AEAD nonce (12 bytes) derived from client nonce (baseline)
    let aead_nonce12 = crypto::derive_aead_nonce12(&nonce);

    // 9) AAD binds encryption to request transcript
    let aad = build_aad(&req.device_id, req.n, &nonce, &ct_bytes);

    // 10) Encrypt entropy -> ciphertext+tag
    let entropy_ct = match crypto::aead_encrypt(&key32, &aead_nonce12, &aad, &entropy_bytes) {
        Ok(v) => v,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "aead encrypt failed").into_response(),
    };

    // 11) Sign response transcript over ciphertext
    let resp_tbs = build_resp_tbs(
        &req.device_id,
        req.n,
        &nonce,
        &ct_bytes,
        &aead_nonce12,
        &entropy_ct,
    );

    let server_sig = match state.pq.sign(&resp_tbs) {
        Ok(s) => s,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "server signing failed").into_response(),
    };

    // 12) Build response
    let resp = EntropyResponse {
        device_id: req.device_id,
        n: req.n,
        nonce_b64: req.nonce_b64,
        kem_ct_b64: general_purpose::STANDARD.encode(&ct_bytes),
        aead_nonce_b64: general_purpose::STANDARD.encode(&aead_nonce12),
        entropy_ct_b64: general_purpose::STANDARD.encode(&entropy_ct),
        server_signature_b64: general_purpose::STANDARD.encode(&server_sig),
    };

    (StatusCode::OK, Json(resp)).into_response()
}

/// Debug endpoint: fetch entropy from QRNG server via auth server.
/// Returns raw bytes as application/octet-stream.
pub async fn entropy_raw(
    State(state): State<AppState>,
    Path(n): Path<usize>,
) -> impl IntoResponse {
    match entropy::fetch_entropy_bytes(&state.http, &state.qrng_base_url, n).await {
        Ok(bytes) => {
            let mut headers = HeaderMap::new();
            headers.insert("content-type", "application/octet-stream".parse().unwrap());
            (StatusCode::OK, headers, bytes).into_response()
        }
        Err(e) => {
            tracing::error!("entropy fetch failed: {}", e);
            (StatusCode::BAD_GATEWAY, e.to_string()).into_response()
        }
    }
}

fn is_admin(headers: &HeaderMap) -> bool {
    let expected = std::env::var("ADMIN_TOKEN").ok();
    match expected {
        None => false, // if not set, disable endpoint by default
        Some(tok) => headers
            .get("x-admin-token")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == tok)
            .unwrap_or(false),
    }
}

pub async fn list_devices(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !is_admin(&headers) {
        return unauthorized("admin token required");
    }

    let devices = state.devices.read().await;

    let mut out: Vec<DeviceInfo> = Vec::with_capacity(devices.len());
    for (device_id, keys) in devices.iter() {
        out.push(DeviceInfo {
            device_id: device_id.clone(),
            kem_pk_b64: general_purpose::STANDARD.encode(&keys.kem_pk),
            sig_pk_b64: general_purpose::STANDARD.encode(&keys.sig_pk),
        });
    }

    out.sort_by(|a, b| a.device_id.cmp(&b.device_id));

    let resp = ListDevicesResponse {
        count: out.len(),
        devices: out,
    };

    (StatusCode::OK, Json(resp)).into_response()
}