use axum::{Json, extract::State};
use crate::{state::AppState, model::*};
use crate::pq::generate_kyber_keypair;

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Json<RegisterResponse> {

    let entropy = state.entropy.get_entropy(32).await.unwrap();
    let (pk, _sk) = generate_kyber_keypair(&entropy);

    println!("Registered device {}", req.device_id);

    Json(RegisterResponse {
        public_key: pk,
    })
}