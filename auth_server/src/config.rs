use std::net::SocketAddr;

pub fn auth_addr() -> SocketAddr {
    std::env::var("AUTH_SERVER_ADDR")
        .unwrap_or("127.0.0.1:8090".into())
        .parse()
        .unwrap()
}

pub fn qrng_url() -> String {
    std::env::var("QRNG_SERVER_URL")
        .unwrap_or("http://127.0.0.1:8080".into())
}

pub fn entropy_mode() -> String {
    std::env::var("ENTROPY_MODE")
        .unwrap_or("mock".into())
}