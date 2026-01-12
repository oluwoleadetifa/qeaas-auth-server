use crate::entropy::EntropyBackend;
use crate::config;

#[derive(Clone)]
pub struct AppState {
    pub entropy: EntropyBackend,
}

impl AppState {
    pub async fn new() -> Self {
        let entropy = match config::entropy_mode().as_str() {
            "qrng" => EntropyBackend::Qrng,
            _ => EntropyBackend::Mock,
        };

        Self { entropy }
    }
}
