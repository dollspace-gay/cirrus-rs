//! PDS server command.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use cirrus_pds::lexicon::LexiconStore;
use cirrus_pds::routes::{AppState, create_router};
use cirrus_pds::sequencer::Firehose;
use cirrus_pds::storage::SqliteStorage;

/// Configuration for the PDS server.
pub struct ServerConfig {
    /// Address to bind to.
    pub bind_addr: SocketAddr,
    /// Path to the `SQLite` database.
    pub db_path: String,
    /// JWT secret for session tokens.
    pub jwt_secret: String,
    /// Hostname for this PDS.
    pub hostname: String,
    /// DID of the account.
    pub did: String,
    /// Handle of the account.
    pub handle: String,
    /// Public key in multibase format.
    pub public_key_multibase: String,
}

impl Default for ServerConfig {
    #[allow(clippy::expect_used)]
    fn default() -> Self {
        Self {
            bind_addr: "127.0.0.1:2583".parse().expect("valid default address"),
            db_path: "pds.db".to_string(),
            jwt_secret: String::new(),
            hostname: "localhost:2583".to_string(),
            did: String::new(),
            handle: String::new(),
            public_key_multibase: String::new(),
        }
    }
}

/// Runs the PDS server.
///
/// # Errors
/// Returns an error if the server fails to start.
pub async fn run(config: ServerConfig) -> Result<()> {
    // Initialize storage
    let storage = SqliteStorage::open(&config.db_path)?;

    // Create app state
    let state = Arc::new(AppState {
        storage,
        lexicons: LexiconStore::new(),
        jwt_secret: config.jwt_secret.into_bytes(),
        hostname: config.hostname,
        did: config.did,
        handle: config.handle,
        public_key_multibase: config.public_key_multibase,
        firehose: Firehose::new(),
    });

    // Create router with middleware
    let app = create_router(state)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // Bind and serve
    let listener = TcpListener::bind(config.bind_addr).await?;
    tracing::info!("PDS listening on {}", config.bind_addr);

    axum::serve(listener, app).await?;

    Ok(())
}
