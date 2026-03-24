pub struct ClientConfig {
    pub auth_base: String,
    pub n: usize,
}

impl ClientConfig {
    pub fn from_env() -> Self {
        let auth_base = std::env::var("AUTH_BASE").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
        let n = std::env::var("ENTROPY_N")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(32);

        Self {auth_base, n }
    }
}
