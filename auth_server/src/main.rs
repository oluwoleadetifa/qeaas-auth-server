use axum::{Router, routing::post};
use dotenvy::dotenv;
use tracing_subscriber;
use tower_http::limit::RequestBodyLimitLayer;
use tower::limit::RateLimitLayer;
use std::time::Duration;
use tokio::net::TcpListener;

mod api;
mod config;
mod state;
mod entropy;
mod pq;
mod model;

use state::AppState;

#[tokio::main]
async fn main() {
    dotenv().ok();
    tracing_subscriber::fmt::init();

    let state = AppState::new().await;

    let app = Router::new()
    .route("/auth/register", post(api::register))
    .with_state(state)
    .layer(RequestBodyLimitLayer::new(8 * 1024))
    .layer(RateLimitLayer::new(30, Duration::from_secs(60)));


    let addr = config::auth_addr();
    println!("Auth server running on {}", addr);

    let listener = TcpListener::bind(addr).await.unwrap();

    axum::serve(listener, app)
    .await
    .unwrap();
}