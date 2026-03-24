use axum::{
    routing::{get, post},
    Router,
};
use dotenvy::dotenv;
use tokio::net::TcpListener;
use tower_http::{limit::RequestBodyLimitLayer, trace::TraceLayer};

mod api;
mod config;
mod crypto;
mod entropy;
mod model;
mod pq;
mod state;

use state::AppState;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // basic logging
    tracing_subscriber::fmt::init();

    // build shared application state
    let state = AppState::new().await?;

    // spawn nonce cache cleanup task (best-effort)
    {
        let cache = state.nonce_cache.clone();
        let interval = Duration::from_secs(config::nonce_cleanup_interval_secs());

        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                cache.cleanup().await;
            }
        });
    }

    // router
    let app = Router::new()
        .route("/v1/devices/enroll", post(api::enroll))
        .route("/v1/entropy", post(api::request_entropy))
        .route("/v1/devices", get(api::list_devices))
        .route("/entropy/raw/:n", get(api::entropy_raw))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        // request size cap (8 MiB)
        .layer(RequestBodyLimitLayer::new(8 * 1024 * 1024));

    // bind + serve
    let addr = config::auth_addr();
    tracing::info!(%addr, "Auth server running");

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}