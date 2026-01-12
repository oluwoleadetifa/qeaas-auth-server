use serde::{Serialize, Deserialize};

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub device_id: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub public_key: Vec<u8>,
}