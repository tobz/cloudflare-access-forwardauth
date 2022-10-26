use std::{net::SocketAddr, sync::Arc};

use openidconnect::IssuerUrl;
use tracing::error;
use tracing_subscriber::{filter::LevelFilter, EnvFilter};

pub mod validation;
pub mod web;
use self::validation::{manage_jwks_refreshing, SignatureState};
use self::web::run_api_endpoint;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // Initialize the tracing/logging layer.
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    // Run the application, logging any unrecoverable errors.
    if let Err(e) = run().await {
        error!(error = e, "Failed with unrecoverable error. Exiting.");
    }
}

async fn run() -> Result<(), String> {
    // Read all the relevant configuration variables.
    let listen_address: SocketAddr = std::env::var("LISTEN_ADDR")
        .map_err(|_| {
            "Listen address must be specified via `LISTEN_ADDR` (example: 127.0.0.1:9000)".into()
        })
        .and_then(|s| {
            s.parse()
                .map_err(|e| format!("Listen address was invalid: {}", e))
        })?;

    let issuer_url = std::env::var("CF_AUTH_DOMAIN")
        .map_err(|_| "Cloudflare Access team domain must be specified via `CF_AUTH_DOMAIN` (example: https://your-team-name.cloudflareaccess.com)".to_string())
        .and_then(|s| IssuerUrl::new(s).map_err(|e| format!("Authentication domain was invalid: {}", e)))?;

    // Ensure that the root certificate trust store is already present/configured, and if not, try
    // finding it and configuring the environment to allow OpenSSL to locate it.
    if !openssl_probe::has_ssl_cert_env_vars() && !openssl_probe::try_init_ssl_cert_env_vars() {
        return Err(String::from("Failed to locate system root certificates. TLS cannot verify certificates without this."));
    }

    // Create all the application configuration and shared state.
    let signature_state = SignatureState::from_issuer_url(issuer_url).map(Arc::new)?;

    // Run a background task that refreshes the signatures used for the given authentication domain,
    // including the initial load that establishes readiness for this server.
    tokio::spawn(manage_jwks_refreshing(Arc::clone(&signature_state)));

    // Run the API endpoint.
    run_api_endpoint(&listen_address, signature_state).await
}
